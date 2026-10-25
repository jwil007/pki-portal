package web

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/jwil007/pki-portal/internal/formats"
	"github.com/jwil007/pki-portal/internal/hooks"
)

// pullAPI serves GET /api/v1/certs/{id}/{format} to holders of a pull-hook token.
// Password formats take the password in the X-PKI-Password header (not the URL,
// so it doesn't end up in access logs). ?root=1 appends the root for internal certs.
func (s *Server) pullAPI(w http.ResponseWriter, r *http.Request) {
	token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	id := r.PathValue("id")
	if !ok || token == "" {
		apiError(w, http.StatusUnauthorized, "missing bearer token")
		return
	}
	h, err := s.store.HookByToken(id, hooks.HashToken(token))
	if err != nil {
		apiError(w, http.StatusUnauthorized, "invalid token for this certificate")
		return
	}
	c, err := s.kube.Get(r.Context(), id)
	if err != nil || c.Leaf == nil {
		apiError(w, http.StatusNotFound, "certificate not available")
		return
	}
	f, ok := formats.Lookup(r.PathValue("format"))
	if !ok {
		ids := []string{}
		for _, f := range formats.All {
			ids = append(ids, f.ID)
		}
		apiError(w, http.StatusBadRequest, "unknown format; use one of: "+strings.Join(ids, ", "))
		return
	}
	b := formats.Bundle{Leaf: c.Leaf, Chain: c.Chain, Name: strings.ReplaceAll(firstName(c), "*", "wildcard")}
	if f.Key {
		key, err := s.keyFor(r, c)
		if err != nil {
			apiError(w, http.StatusConflict, err.Error())
			return
		}
		b.Key = key
	}
	if r.URL.Query().Get("root") == "1" && !c.Public {
		if root, _, err := s.kube.CA(r.Context(), s.cfg.CAConfigMap); err == nil {
			b.Root = root
		}
	}
	out, err := formats.Render(f.ID, b, r.Header.Get("X-PKI-Password"))
	if err != nil {
		apiError(w, http.StatusBadRequest, err.Error())
		return
	}
	s.store.Log("api-download", c.ID, fmt.Sprintf("%s via pull hook #%d", f.ID, h.ID), remote(r))
	w.Header().Set("Content-Type", out.ContentType)
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", out.Filename))
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-PKI-Serial", c.Serial())
	w.Write(out.Data)
}

func apiError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(status)
	w.Write([]byte(msg + "\n"))
}
