package web

import (
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/jwil007/pki-portal/internal/kube"
)

// gitopsCard adds download tracking to a Git-managed certificate.
type gitopsCard struct {
	*kube.GitOpsCert
	LastSerial     string
	LastDownloaded time.Time
	RenewedSince   bool // the certificate changed after the last download
}

func (s *Server) gitopsPage(w http.ResponseWriter, r *http.Request) {
	if s.cfg.GitOpsNamespace == "" {
		s.fail(w, r, http.StatusNotFound, errors.New("the GitOps view is disabled (PORTAL_GITOPS_NAMESPACE)"))
		return
	}
	certs, err := s.kube.GitOpsCerts(r.Context(), s.cfg.GitOpsNamespace)
	if err != nil {
		s.fail(w, r, http.StatusBadGateway, err)
		return
	}
	var cards []gitopsCard
	for _, g := range certs {
		card := gitopsCard{GitOpsCert: g}
		card.LastSerial, card.LastDownloaded = s.store.LastGitOpsDownload(g.Namespace + "/" + g.Name)
		card.RenewedSince = card.LastSerial != "" && g.Leaf != nil && card.LastSerial != g.Serial()
		cards = append(cards, card)
	}
	s.render(w, r, "gitops", map[string]any{"Cards": cards, "Namespace": s.cfg.GitOpsNamespace})
}

func (s *Server) gitopsCert(w http.ResponseWriter, r *http.Request) (*kube.GitOpsCert, bool) {
	g, err := s.kube.GitOpsCert(r.Context(), s.cfg.GitOpsNamespace, r.PathValue("name"))
	if err != nil {
		s.fail(w, r, http.StatusNotFound, err)
		return nil, false
	}
	return g, true
}

// gitopsDownload serves the cert-manager-built keystore.p12 as-is, or the PEM chain.
func (s *Server) gitopsDownload(w http.ResponseWriter, r *http.Request) {
	g, ok := s.gitopsCert(w, r)
	if !ok {
		return
	}
	data, err := s.kube.GitOpsSecret(r.Context(), g.Namespace, g.SecretName)
	if err != nil {
		s.fail(w, r, http.StatusBadGateway, err)
		return
	}
	var name, ctype string
	var body []byte
	switch r.FormValue("what") {
	case "p12":
		name, ctype, body = g.Name+".p12", "application/x-pkcs12", data["keystore.p12"]
	case "fullchain":
		name, ctype, body = g.Name+".fullchain.pem", "application/x-pem-file", data["tls.crt"]
	default:
		s.fail(w, r, http.StatusBadRequest, errors.New("unknown download"))
		return
	}
	if len(body) == 0 {
		s.fail(w, r, http.StatusNotFound, fmt.Errorf("%s has no %s", g.SecretName, r.FormValue("what")))
		return
	}
	s.store.RecordGitOpsDownload(g.Namespace+"/"+g.Name, g.Serial())
	s.record(r, "gitops-download", g.Namespace+"/"+g.Name, r.FormValue("what"))
	w.Header().Set("Content-Type", ctype)
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", name))
	w.Header().Set("Cache-Control", "no-store")
	w.Write(body)
}

// gitopsPassphrase shows the p12 password from the Secret cert-manager uses.
func (s *Server) gitopsPassphrase(w http.ResponseWriter, r *http.Request) {
	g, ok := s.gitopsCert(w, r)
	if !ok {
		return
	}
	if g.P12Password == nil {
		s.fail(w, r, http.StatusNotFound, errors.New("this certificate has no PKCS#12 keystore"))
		return
	}
	data, err := s.kube.GitOpsSecret(r.Context(), g.Namespace, g.P12Password.Name)
	if err != nil {
		s.fail(w, r, http.StatusBadGateway, err)
		return
	}
	s.record(r, "gitops-passphrase", g.Namespace+"/"+g.Name, "revealed")
	w.Header().Set("Cache-Control", "no-store")
	s.render(w, r, "passphrase", map[string]any{"Cert": g, "Passphrase": string(data[g.P12Password.Key])})
}
