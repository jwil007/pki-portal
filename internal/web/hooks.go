package web

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/jwil007/pki-portal/internal/formats"
	"github.com/jwil007/pki-portal/internal/hooks"
	"github.com/jwil007/pki-portal/internal/kube"
	"github.com/jwil007/pki-portal/internal/store"
)

// hookView pairs a stored hook with its driver for templates.
type hookView struct {
	*store.Hook
	Driver hooks.Driver
}

func (s *Server) hookViews(certID string) []hookView {
	hs, _ := s.store.HooksFor(certID)
	var out []hookView
	for _, h := range hs {
		d, _ := hooks.Get(h.Type)
		out = append(out, hookView{h, d})
	}
	return out
}

// hasKey reports whether the portal can hand out this certificate's private key.
func (s *Server) hasKey(c *kube.Cert) bool {
	switch c.Mode {
	case kube.Managed:
		return true
	case kube.Unmanaged:
		_, _, ok := s.stash.Get(c.ID)
		return ok
	}
	return false
}

func (s *Server) hookFields(w http.ResponseWriter, r *http.Request) {
	d, ok := hooks.Get(r.FormValue("type"))
	if !ok {
		w.Write(nil)
		return
	}
	s.partial(w, "hookfields", map[string]any{"Driver": d, "SSHPublicKey": s.hooks.Env.SSHPublicKey})
}

func (s *Server) hookCreate(w http.ResponseWriter, r *http.Request) {
	c, ok := s.getCert(w, r)
	if !ok {
		return
	}
	d, ok := hooks.Get(r.FormValue("type"))
	if !ok {
		s.fail(w, r, http.StatusBadRequest, errors.New("choose a hook type"))
		return
	}
	if d.NeedsKey() && c.Mode != kube.Managed {
		s.fail(w, r, http.StatusBadRequest, fmt.Errorf("%s needs a managed certificate (the portal must keep the key)", d.Label()))
		return
	}
	cfg := map[string]string{}
	for _, f := range d.Fields() {
		if v := strings.TrimSpace(r.FormValue("cfg_" + f.Name)); v != "" {
			cfg[f.Name] = v
		}
	}
	notes, err := d.Prepare(r.Context(), s.hooks.Env, cfg)
	if err != nil {
		s.fail(w, r, http.StatusBadRequest, err)
		return
	}
	h := &store.Hook{CertID: c.ID, Type: d.Type(), Name: strings.TrimSpace(r.FormValue("name")), Config: cfg}
	// Don't fire for the certificate that exists now; fire on the next issuance.
	h.LastSerial = c.Serial()
	var token string
	if hooks.IsPassive(d) {
		token, h.TokenHash = hooks.NewToken()
	}
	if err := s.store.AddHook(h); err != nil {
		s.fail(w, r, http.StatusInternalServerError, err)
		return
	}
	s.record(r, "hook-create", c.ID, fmt.Sprintf("%s #%d", d.Type(), h.ID))
	s.render(w, r, "hookcreated", map[string]any{
		"Cert": c, "Hook": h, "Driver": d, "Notes": notes, "Token": token,
		"BaseURL": s.cfg.BaseURL, "HasKey": s.hasKey(c), "SSHPublicKey": s.hooks.Env.SSHPublicKey, "Formats": formats.All,
		"Slug": strings.ReplaceAll(strings.TrimPrefix(firstName(c), "*."), "*", "wildcard"),
	})
}

func firstName(c *kube.Cert) string {
	if len(c.Names) > 0 {
		return c.Names[0]
	}
	return c.ID
}

func (s *Server) hookFromPath(w http.ResponseWriter, r *http.Request) (*store.Hook, bool) {
	id, err := strconv.ParseInt(r.PathValue("hid"), 10, 64)
	if err == nil {
		var h *store.Hook
		if h, err = s.store.Hook(id); err == nil {
			return h, true
		}
	}
	s.fail(w, r, http.StatusNotFound, errors.New("hook not found"))
	return nil, false
}

func (s *Server) hookRun(w http.ResponseWriter, r *http.Request) {
	h, ok := s.hookFromPath(w, r)
	if !ok {
		return
	}
	if err := s.hooks.RunNow(r.Context(), h.ID); err != nil {
		s.log.Warn("hook run failed", "hook", h.ID, "err", err)
	}
	http.Redirect(w, r, "/certs/"+h.CertID+"#hooks", http.StatusSeeOther)
}

func (s *Server) hookDelete(w http.ResponseWriter, r *http.Request) {
	h, ok := s.hookFromPath(w, r)
	if !ok {
		return
	}
	if err := s.store.DeleteHook(h.ID); err != nil {
		s.fail(w, r, http.StatusInternalServerError, err)
		return
	}
	s.record(r, "hook-delete", h.CertID, fmt.Sprintf("%s #%d", h.Type, h.ID))
	http.Redirect(w, r, "/certs/"+h.CertID+"#hooks", http.StatusSeeOther)
}
