package web

import (
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"github.com/jwil007/pki-portal/internal/csrutil"
	"github.com/jwil007/pki-portal/internal/internalca"
	"github.com/jwil007/pki-portal/internal/kube"
	"github.com/jwil007/pki-portal/internal/stepca"
)

// --- EAP-TLS client certificates ---

type clientForm struct {
	Profile  string // user | device
	Username string
	Email    string
	Device   string
	Managed  bool
	KeyType  string
	Error    string
}

var usernameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

func (s *Server) clientsPage(w http.ResponseWriter, r *http.Request) {
	s.render(w, r, "clients", map[string]any{
		"Form":    clientForm{Profile: "user", Managed: true, KeyType: "rsa2048"},
		"Domain":  s.cfg.ClientEmailDomain,
		"Enabled": s.internal != nil && s.internal.ClientsEnabled(),
	})
}

func (s *Server) clientsCreate(w http.ResponseWriter, r *http.Request) {
	f := clientForm{
		Profile:  r.FormValue("profile"),
		Username: strings.TrimSpace(r.FormValue("username")),
		Email:    strings.ToLower(strings.TrimSpace(r.FormValue("email"))),
		Device:   strings.ToLower(strings.TrimSuffix(strings.TrimSpace(r.FormValue("device")), ".")),
		Managed:  r.FormValue("lifecycle") != "unmanaged",
		KeyType:  r.FormValue("key"),
	}
	if f.KeyType != string(csrutil.ECDSA256) {
		f.KeyType = string(csrutil.RSA2048)
	}
	req := internalca.Request{Profile: f.Profile, KeyType: f.KeyType, Mode: kube.Managed}
	if !f.Managed {
		req.Mode = kube.Unmanaged
	}
	switch {
	case s.internal == nil || !s.internal.ClientsEnabled():
		f.Error = "Client certificates aren't enabled (PORTAL_STEPCA_CLIENT_PROVISIONER)."
	case f.Profile == "user":
		if f.Email == "" && f.Username != "" {
			f.Email = strings.ToLower(f.Username) + "@" + s.cfg.ClientEmailDomain
		}
		switch {
		case !usernameRe.MatchString(f.Username):
			f.Error = "Username: letters, digits, '.', '_' or '-' (the AD sAMAccountName, e.g. testuser)."
		case s.policy.CheckEmail(f.Email) != nil:
			f.Error = s.policy.CheckEmail(f.Email).Error()
		}
		req.Subject, req.SANs = f.Username, []string{f.Email}
	case f.Profile == "device":
		if f.Device != "" && !strings.Contains(f.Device, ".") && len(s.cfg.Domains) > 0 {
			f.Device += "." + s.cfg.Domains[0]
		}
		if err := s.policy.CheckDNS(f.Device, false); err != nil {
			f.Error = err.Error()
		}
		req.Subject, req.SANs = f.Device, []string{f.Device}
	default:
		f.Error = "Choose User or Device."
	}
	if f.Error != "" {
		w.WriteHeader(http.StatusUnprocessableEntity)
		s.render(w, r, "clients", map[string]any{"Form": f, "Domain": s.cfg.ClientEmailDomain, "Enabled": s.internal != nil && s.internal.ClientsEnabled()})
		return
	}
	req.ID = kube.NewID(f.Profile + "-" + req.Subject)
	key, err := s.internal.Issue(r.Context(), req)
	if err != nil {
		s.fail(w, r, http.StatusBadGateway, fmt.Errorf("issuing client certificate: %w", err))
		return
	}
	if req.Mode == kube.Unmanaged {
		s.stash.Put(req.ID, key)
	}
	s.record(r, "issue", req.ID, fmt.Sprintf("%s %s client cert: CN=%s %s", req.Mode, f.Profile, req.Subject, strings.Join(req.SANs, ", ")))
	s.counters.issue(kube.StepCAIssuer, req.Mode)
	http.Redirect(w, r, "/certs/"+req.ID, http.StatusSeeOther)
}

// --- revocation ---

func (s *Server) revoke(w http.ResponseWriter, r *http.Request) {
	c, ok := s.getCert(w, r)
	if !ok {
		return
	}
	if s.internal == nil {
		s.fail(w, r, http.StatusBadRequest, errInternalDisabled)
		return
	}
	code, _ := strconv.Atoi(r.FormValue("reason"))
	if err := s.internal.Revoke(r.Context(), c, code, r.FormValue("note")); err != nil {
		s.fail(w, r, http.StatusBadGateway, err)
		return
	}
	s.stash.Delete(c.ID)
	s.record(r, "revoke", c.ID, fmt.Sprintf("serial %s, reason %d %s", c.Serial(), code, r.FormValue("note")))
	http.Redirect(w, r, "/certs/"+c.ID, http.StatusSeeOther)
}

// crlInfo summarizes step-ca's CRL for the CA page.
type crlInfo struct {
	Enabled    bool
	Error      string
	ThisUpdate string
	NextUpdate string
	Revoked    int
}

func (s *Server) crlInfo(r *http.Request) crlInfo {
	if s.internal == nil {
		return crlInfo{Error: errInternalDisabled.Error()}
	}
	der, err := s.internal.CRL(r.Context())
	if errors.Is(err, stepca.ErrNoCRL) {
		return crlInfo{}
	}
	if err != nil {
		return crlInfo{Error: err.Error()}
	}
	crl, err := x509.ParseRevocationList(der)
	if err != nil {
		return crlInfo{Enabled: true, Error: err.Error()}
	}
	return crlInfo{Enabled: true, Revoked: len(crl.RevokedCertificateEntries),
		ThisUpdate: crl.ThisUpdate.Local().Format("2006-01-02 15:04"), NextUpdate: crl.NextUpdate.Local().Format("2006-01-02 15:04")}
}

func (s *Server) crlFile(w http.ResponseWriter, r *http.Request) {
	if s.internal == nil {
		http.NotFound(w, r)
		return
	}
	der, err := s.internal.CRL(r.Context())
	if err != nil {
		s.fail(w, r, http.StatusBadGateway, err)
		return
	}
	w.Header().Set("Content-Type", "application/pkix-crl")
	w.Header().Set("Content-Disposition", `attachment; filename="wilsonfi-intermediate-ca.crl"`)
	w.Write(der)
}
