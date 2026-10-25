package web

import (
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"

	"github.com/jwil007/pki-portal/internal/csrutil"
	"github.com/jwil007/pki-portal/internal/formats"
	"github.com/jwil007/pki-portal/internal/hooks"
	"github.com/jwil007/pki-portal/internal/internalca"
	"github.com/jwil007/pki-portal/internal/kube"
	"github.com/jwil007/pki-portal/internal/policy"
)

var errInternalDisabled = errors.New("internal certificates are disabled: no step-ca provisioner password is configured (PORTAL_STEPCA_PASSWORD)")

// --- dashboard & inventory ---

func (s *Server) dashboard(w http.ResponseWriter, r *http.Request) {
	certs, err := s.kube.List(r.Context())
	if err != nil {
		s.fail(w, r, http.StatusBadGateway, err)
		return
	}
	counts := map[string]int{}
	byIssuer := map[string]int{}
	var expiring, failed, renewed []*kube.Cert
	for _, c := range certs {
		counts[string(c.State)]++
		byIssuer[c.Issuer]++
		switch {
		case c.State == kube.Failed:
			failed = append(failed, c)
		case c.Leaf != nil && c.State != kube.Expired && time.Until(c.Leaf.NotAfter) < 30*24*time.Hour:
			expiring = append(expiring, c)
		}
		if c.Mode == kube.Managed && c.Revision > 1 && c.Leaf != nil && time.Since(c.Leaf.NotBefore) < 14*24*time.Hour {
			renewed = append(renewed, c)
		}
	}
	issuers := s.kube.Issuers(r.Context(), s.cfg.PublicIssuer)
	st := kube.IssuerStatus{Name: kube.StepCAIssuer, Ready: true}
	if s.internal == nil {
		st.Ready, st.Message = false, errInternalDisabled.Error()
	} else if err := s.internal.Health(r.Context()); err != nil {
		st.Ready, st.Message = false, err.Error()
	}
	issuers = append(issuers, st)
	s.render(w, r, "dashboard", map[string]any{
		"Total":    len(certs),
		"Counts":   counts,
		"ByIssuer": byIssuer,
		"Expiring": expiring,
		"Failed":   failed,
		"Renewed":  renewed,
		"Issuers":  issuers,
	})
}

func (s *Server) inventory(w http.ResponseWriter, r *http.Request) {
	certs, err := s.kube.List(r.Context())
	if err != nil {
		s.fail(w, r, http.StatusBadGateway, err)
		return
	}
	q := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("q")))
	state := r.URL.Query().Get("state")
	var out []*kube.Cert
	for _, c := range certs {
		if state != "" && string(c.State) != state {
			continue
		}
		if q != "" && !strings.Contains(strings.ToLower(c.ID+" "+strings.Join(c.Names, " ")+" "+c.Issuer+" "+c.Serial()), q) {
			continue
		}
		out = append(out, c)
	}
	s.render(w, r, "inventory", map[string]any{"Certs": out, "Q": q, "State": state})
}

// --- new certificate ---

type issueForm struct {
	Public  bool
	Names   []string
	Raw     string
	Managed bool
	KeyType string
	Confirm bool
}

func readIssueForm(r *http.Request) issueForm {
	f := issueForm{
		Public:  r.FormValue("type") != "internal",
		Raw:     r.FormValue("names"),
		Names:   policy.SplitNames(r.FormValue("names")),
		Managed: r.FormValue("lifecycle") != "unmanaged",
		KeyType: r.FormValue("key"),
		Confirm: r.FormValue("confirm") == "on",
	}
	if f.KeyType != string(csrutil.ECDSA256) {
		f.KeyType = string(csrutil.RSA2048)
	}
	return f
}

func (s *Server) issuerFor(public bool) string {
	if public {
		return s.cfg.PublicIssuer
	}
	return kube.StepCAIssuer
}

func (s *Server) checkNames(names []string, public bool) error {
	if public {
		return s.policy.CheckACME(names, true)
	}
	if s.internal == nil {
		return errInternalDisabled
	}
	return s.policy.CheckInternal(names)
}

// checkResult is shown live under the names box and again on submit errors.
type checkResult struct {
	Names     []string
	Error     string
	Duplicate *kube.Cert
	Issuer    string
	Public    bool
	Prod      bool
}

func (s *Server) runCheck(r *http.Request, f issueForm) checkResult {
	res := checkResult{Names: f.Names, Issuer: s.issuerFor(f.Public), Public: f.Public}
	res.Prod = f.Public && !strings.Contains(res.Issuer, "staging")
	if len(f.Names) == 0 {
		return res
	}
	if err := s.checkNames(f.Names, f.Public); err != nil {
		res.Error = err.Error()
		return res
	}
	if certs, err := s.kube.List(r.Context()); err == nil {
		res.Duplicate = kube.FindDuplicate(certs, res.Issuer, f.Names)
	}
	return res
}

func (s *Server) newPage(w http.ResponseWriter, r *http.Request) {
	s.render(w, r, "new", map[string]any{"Form": issueForm{Public: true, Managed: true, KeyType: "rsa2048"}})
}

func (s *Server) check(w http.ResponseWriter, r *http.Request) {
	s.partial(w, "check", s.runCheck(r, readIssueForm(r)))
}

func (s *Server) create(w http.ResponseWriter, r *http.Request) {
	f := readIssueForm(r)
	res := s.runCheck(r, f)
	switch {
	case len(f.Names) == 0:
		res.Error = "Enter at least one name."
	case res.Error == "" && res.Duplicate != nil && !f.Confirm:
		res.Error = "A certificate for exactly these names already exists. Tick the box to issue another one anyway."
	}
	if res.Error != "" {
		w.WriteHeader(http.StatusUnprocessableEntity)
		s.render(w, r, "new", map[string]any{"Form": f, "Check": res})
		return
	}
	id := kube.NewID(f.Names[0])
	mode := kube.Managed
	if !f.Managed {
		mode = kube.Unmanaged
	}
	if err := s.issue(r, id, f, mode, res.Issuer); err != nil {
		s.fail(w, r, http.StatusBadGateway, fmt.Errorf("issuing certificate: %w", err))
		return
	}
	s.record(r, "issue", id, fmt.Sprintf("%s via %s: %s", mode, res.Issuer, strings.Join(f.Names, ", ")))
	s.counters.issue(res.Issuer, mode)
	http.Redirect(w, r, "/certs/"+id, http.StatusSeeOther)
}

func (s *Server) issue(r *http.Request, id string, f issueForm, mode kube.Mode, issuer string) error {
	ctx := r.Context()
	if !f.Public {
		// Internal: step-ca signs immediately, no ACME or DNS involved.
		key, err := s.internal.IssueServer(ctx, id, f.Names, f.KeyType, mode)
		if err == nil && mode == kube.Unmanaged {
			s.stash.Put(id, key)
		}
		return err
	}
	if mode == kube.Managed {
		return s.kube.CreateManaged(ctx, id, f.Names, issuer, true, f.KeyType)
	}
	var key crypto.Signer
	key, csrPEM, err := csrutil.Generate(csrutil.KeyType(f.KeyType), f.Names)
	if err != nil {
		return err
	}
	s.stash.Put(id, key)
	if err := s.kube.CreateRequest(ctx, id, csrPEM, issuer, true, kube.Unmanaged, f.KeyType); err != nil {
		s.stash.Delete(id)
		return err
	}
	return nil
}

// --- CSR upload ---

type csrResult struct {
	Info   *csrutil.Info
	Names  []string
	Error  string
	Public bool
	Issuer string
}

func (s *Server) readCSR(r *http.Request) ([]byte, error) {
	r.ParseMultipartForm(64 << 10)
	if text := strings.TrimSpace(r.FormValue("csr")); text != "" {
		return []byte(text), nil
	}
	if file, _, err := r.FormFile("file"); err == nil {
		defer file.Close()
		return io.ReadAll(io.LimitReader(file, 64<<10))
	}
	return nil, errors.New("paste a CSR or choose a file")
}

func (s *Server) evalCSR(r *http.Request) csrResult {
	res := csrResult{Public: r.FormValue("type") != "internal"}
	res.Issuer = s.issuerFor(res.Public)
	data, err := s.readCSR(r)
	if err != nil {
		res.Error = err.Error()
		return res
	}
	info, _, err := csrutil.Parse(data)
	if err != nil {
		res.Error = err.Error()
		return res
	}
	res.Info = info
	if res.Public {
		res.Names, err = info.ACMENames()
		if err == nil {
			err = s.checkNames(res.Names, true)
		}
	} else {
		res.Names = info.SANs()
		if len(res.Names) == 0 && info.CN != "" {
			res.Names = []string{info.CN}
		}
		switch {
		case len(info.Emails) > 0 || len(info.URIs) > 0:
			err = errors.New("email and URI SANs aren't supported yet")
		default:
			err = s.checkNames(res.Names, false)
		}
	}
	if err != nil {
		res.Error = err.Error()
	}
	return res
}

func (s *Server) csrPage(w http.ResponseWriter, r *http.Request) {
	s.render(w, r, "csr", map[string]any{"Public": true})
}

func (s *Server) csrParse(w http.ResponseWriter, r *http.Request) {
	s.partial(w, "csrpreview", s.evalCSR(r))
}

func (s *Server) csrSubmit(w http.ResponseWriter, r *http.Request) {
	res := s.evalCSR(r)
	if res.Error != "" || res.Info == nil {
		w.WriteHeader(http.StatusUnprocessableEntity)
		s.render(w, r, "csr", map[string]any{"Public": res.Public, "Result": res, "CSR": r.FormValue("csr")})
		return
	}
	id := kube.NewID(res.Names[0])
	keyDesc := strings.ToLower(strings.ReplaceAll(res.Info.Key, " ", ""))
	var err error
	if res.Public {
		err = s.kube.CreateRequest(r.Context(), id, res.Info.PEM, res.Issuer, true, kube.FromCSR, keyDesc)
	} else {
		err = s.internal.SignCSR(r.Context(), id, res.Info, keyDesc)
	}
	if err != nil {
		s.fail(w, r, http.StatusBadGateway, fmt.Errorf("issuing from CSR: %w", err))
		return
	}
	s.record(r, "issue", id, fmt.Sprintf("csr via %s: %s", res.Issuer, strings.Join(res.Names, ", ")))
	s.counters.issue(res.Issuer, kube.FromCSR)
	http.Redirect(w, r, "/certs/"+id, http.StatusSeeOther)
}

// --- detail & progress ---

func (s *Server) getCert(w http.ResponseWriter, r *http.Request) (*kube.Cert, bool) {
	c, err := s.kube.Get(r.Context(), r.PathValue("id"))
	if err != nil {
		status := http.StatusBadGateway
		if apierrors.IsNotFound(err) {
			status, err = http.StatusNotFound, errors.New("certificate not found")
		}
		s.fail(w, r, status, err)
		return nil, false
	}
	return c, true
}

func (s *Server) detail(w http.ResponseWriter, r *http.Request) {
	c, ok := s.getCert(w, r)
	if !ok {
		return
	}
	data := map[string]any{"Cert": c, "Formats": formats.All, "Internal": c.Backend == kube.BackendStepCA || !c.Public,
		"Hooks": s.hookViews(c.ID), "Drivers": hooks.All(), "BaseURL": s.cfg.BaseURL,
		"CanRevoke": c.Backend == kube.BackendStepCA && c.Leaf != nil && c.State != kube.Revoked && s.internal != nil,
		"Reasons":   internalca.Reasons}
	switch c.Mode {
	case kube.Managed:
		data["HasKey"] = c.Leaf != nil
		if c.Backend != kube.BackendStepCA {
			data["History"], _ = s.kube.History(r.Context(), c.ID)
		}
	case kube.Unmanaged:
		_, until, ok := s.stash.Get(c.ID)
		data["HasKey"] = ok && c.Leaf != nil
		data["KeyAvailable"] = ok
		data["KeyUntil"] = until
	}
	if c.Backend != kube.BackendStepCA && c.State != kube.Ready && c.State != kube.Expired {
		data["Steps"], _ = s.kube.Progress(r.Context(), c)
	}
	s.render(w, r, "cert", data)
}

func (s *Server) progress(w http.ResponseWriter, r *http.Request) {
	c, err := s.kube.Get(r.Context(), r.PathValue("id"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	if c.State == kube.Ready {
		w.Header().Set("HX-Refresh", "true")
		return
	}
	steps, err := s.kube.Progress(r.Context(), c)
	if err != nil {
		steps = append(steps, kube.Step{Name: "Status", State: "failed", Detail: err.Error()})
	}
	s.partial(w, "progress", map[string]any{"Cert": c, "Steps": steps})
}

// --- downloads ---

// keyFor returns the private key: from the Secret (managed) or memory (unmanaged).
func (s *Server) keyFor(r *http.Request, c *kube.Cert) (crypto.Signer, error) {
	if c.State == kube.Revoked {
		return nil, errors.New("this certificate is revoked; its key was discarded")
	}
	switch c.Mode {
	case kube.Managed:
		return s.kube.Key(r.Context(), c)
	case kube.Unmanaged:
		if k, _, ok := s.stash.Get(c.ID); ok {
			return k, nil
		}
		return nil, errors.New("the private key is gone: unmanaged keys are only kept in memory for a limited time (or until the portal restarts). Delete this one and issue again")
	}
	return nil, errors.New("this certificate was issued from your CSR; the private key never left your device")
}

func (s *Server) download(w http.ResponseWriter, r *http.Request) {
	c, ok := s.getCert(w, r)
	if !ok {
		return
	}
	f, ok := formats.Lookup(r.FormValue("format"))
	if !ok {
		s.fail(w, r, http.StatusBadRequest, errors.New("choose a file format"))
		return
	}
	b := formats.Bundle{Leaf: c.Leaf, Chain: c.Chain, Name: c.ID}
	if len(c.Names) > 0 {
		b.Name = strings.ReplaceAll(c.Names[0], "*", "wildcard")
	}
	if f.Key {
		key, err := s.keyFor(r, c)
		if err != nil {
			s.fail(w, r, http.StatusConflict, err)
			return
		}
		b.Key = key
	}
	if r.FormValue("root") == "on" && !c.Public {
		root, _, err := s.kube.CA(r.Context(), s.cfg.CAConfigMap)
		if err != nil {
			s.fail(w, r, http.StatusBadGateway, err)
			return
		}
		b.Root = root
	}
	out, err := formats.Render(f.ID, b, r.FormValue("password"))
	if err != nil {
		s.fail(w, r, http.StatusBadRequest, err)
		return
	}
	if f.Key {
		s.record(r, "download-key", c.ID, f.ID)
	} else {
		s.record(r, "download", c.ID, f.ID)
	}
	w.Header().Set("Content-Type", out.ContentType)
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", out.Filename))
	w.Header().Set("Cache-Control", "no-store")
	w.Write(out.Data)
}

// --- actions ---

func (s *Server) renew(w http.ResponseWriter, r *http.Request) {
	c, ok := s.getCert(w, r)
	if !ok {
		return
	}
	if c.Mode != kube.Managed {
		s.fail(w, r, http.StatusBadRequest, errors.New("only managed certificates can be renewed; issue a new one instead"))
		return
	}
	var err error
	if c.Backend == kube.BackendStepCA {
		if s.internal == nil {
			err = errInternalDisabled
		} else {
			err = s.internal.Renew(r.Context(), c)
		}
	} else {
		err = s.kube.Renew(r.Context(), c.ID)
	}
	if err != nil {
		s.fail(w, r, http.StatusConflict, err)
		return
	}
	s.record(r, "renew", c.ID, "manual")
	s.hooks.Kick()
	http.Redirect(w, r, "/certs/"+c.ID, http.StatusSeeOther)
}

func (s *Server) delete(w http.ResponseWriter, r *http.Request) {
	c, ok := s.getCert(w, r)
	if !ok {
		return
	}
	if err := s.kube.Delete(r.Context(), c); err != nil {
		s.fail(w, r, http.StatusBadGateway, err)
		return
	}
	s.stash.Delete(c.ID)
	s.store.DeleteHooksFor(c.ID)
	s.record(r, "delete", c.ID, strings.Join(c.Names, ", "))
	http.Redirect(w, r, "/certs", http.StatusSeeOther)
}

// --- CA chain ---

func (s *Server) caPage(w http.ResponseWriter, r *http.Request) {
	root, inter, err := s.kube.CA(r.Context(), s.cfg.CAConfigMap)
	if err != nil {
		s.fail(w, r, http.StatusBadGateway, err)
		return
	}
	s.render(w, r, "ca", map[string]any{"CRL": s.crlInfo(r), "CAs": []map[string]any{
		{"Label": "Root CA", "File": "root", "Cert": root, "FP": (&kube.Cert{Leaf: root}).Fingerprint()},
		{"Label": "Intermediate (issuing) CA", "File": "intermediate", "Cert": inter, "FP": (&kube.Cert{Leaf: inter}).Fingerprint()},
	}})
}

func (s *Server) caFile(w http.ResponseWriter, r *http.Request) {
	root, inter, err := s.kube.CA(r.Context(), s.cfg.CAConfigMap)
	if err != nil {
		s.fail(w, r, http.StatusBadGateway, err)
		return
	}
	var name string
	var data []byte
	switch r.PathValue("file") {
	case "root.crt":
		name, data = "wilsonfi-root-ca.crt", pemCert(root)
	case "root.der":
		name, data = "wilsonfi-root-ca.der", root.Raw
	case "intermediate.crt":
		name, data = "wilsonfi-intermediate-ca.crt", pemCert(inter)
	case "intermediate.der":
		name, data = "wilsonfi-intermediate-ca.der", inter.Raw
	case "bundle.crt":
		name, data = "wilsonfi-ca-bundle.crt", append(pemCert(inter), pemCert(root)...)
	default:
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/x-x509-ca-cert")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", name))
	w.Write(data)
}

func (s *Server) audit(w http.ResponseWriter, r *http.Request) {
	q := strings.TrimSpace(r.URL.Query().Get("q"))
	events, err := s.store.Events(q, 500)
	if err != nil {
		s.fail(w, r, http.StatusInternalServerError, err)
		return
	}
	s.render(w, r, "audit", map[string]any{"Events": events, "Q": q})
}

func pemCert(c *x509.Certificate) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})
}
