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
	"github.com/jwil007/pki-portal/internal/kube"
	"github.com/jwil007/pki-portal/internal/p12"
	"github.com/jwil007/pki-portal/internal/policy"
)

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
	s.render(w, r, "dashboard", map[string]any{
		"Total":    len(certs),
		"Counts":   counts,
		"ByIssuer": byIssuer,
		"Expiring": expiring,
		"Failed":   failed,
		"Renewed":  renewed,
		"Issuers":  s.kube.Issuers(r.Context(), s.cfg.PublicIssuer, s.cfg.InternalIssuer),
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
	return s.cfg.InternalIssuer
}

// checkResult is shown live under the names box and again on submit errors.
type checkResult struct {
	Names     []string
	Error     string
	Duplicate *kube.Cert
	Issuer    string
	Prod      bool
}

func (s *Server) runCheck(r *http.Request, f issueForm) checkResult {
	res := checkResult{Names: f.Names, Issuer: s.issuerFor(f.Public)}
	res.Prod = f.Public && !strings.Contains(res.Issuer, "staging")
	if len(f.Names) == 0 {
		return res
	}
	if err := s.policy.CheckACME(f.Names, f.Public); err != nil {
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
		res.Error = "Enter at least one DNS name."
	case res.Duplicate != nil && !f.Confirm:
		res.Error = "A certificate for exactly these names already exists. Tick the box to issue another one anyway."
	}
	if res.Error != "" {
		w.WriteHeader(http.StatusUnprocessableEntity)
		s.render(w, r, "new", map[string]any{"Form": f, "Check": res})
		return
	}
	id := kube.NewID(f.Names[0])
	ctx := r.Context()
	var err error
	if f.Managed {
		err = s.kube.CreateManaged(ctx, id, f.Names, res.Issuer, f.Public, f.KeyType)
	} else {
		var key crypto.Signer
		var csrPEM []byte
		key, csrPEM, err = csrutil.Generate(csrutil.KeyType(f.KeyType), f.Names)
		if err == nil {
			s.stash.Put(id, key)
			err = s.kube.CreateRequest(ctx, id, csrPEM, res.Issuer, f.Public, kube.Unmanaged, f.KeyType)
			if err != nil {
				s.stash.Delete(id)
			}
		}
	}
	if err != nil {
		s.fail(w, r, http.StatusBadGateway, fmt.Errorf("creating certificate: %w", err))
		return
	}
	mode := "managed"
	if !f.Managed {
		mode = "unmanaged"
	}
	s.record(r, "issue", id, fmt.Sprintf("%s via %s: %s", mode, res.Issuer, strings.Join(f.Names, ", ")))
	http.Redirect(w, r, "/certs/"+id, http.StatusSeeOther)
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
	names, err := info.ACMENames()
	if err == nil {
		err = s.policy.CheckACME(names, res.Public)
	}
	if err != nil {
		res.Error = err.Error()
	}
	res.Names = names
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
	if err := s.kube.CreateRequest(r.Context(), id, res.Info.PEM, res.Issuer, res.Public, kube.FromCSR, keyDesc); err != nil {
		s.fail(w, r, http.StatusBadGateway, fmt.Errorf("creating certificate request: %w", err))
		return
	}
	s.record(r, "issue", id, fmt.Sprintf("csr via %s: %s", res.Issuer, strings.Join(res.Names, ", ")))
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
	data := map[string]any{"Cert": c}
	if c.Mode == kube.Managed {
		data["History"], _ = s.kube.History(r.Context(), c.ID)
		data["HasKey"] = c.Leaf != nil
	}
	if c.Mode == kube.Unmanaged {
		_, until, ok := s.stash.Get(c.ID)
		data["HasKey"] = ok && c.Leaf != nil
		data["KeyAvailable"] = ok
		data["KeyUntil"] = until
	}
	if c.State != kube.Ready && c.State != kube.Expired {
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

func filename(c *kube.Cert, ext string) string {
	base := c.ID
	if len(c.Names) > 0 {
		base = strings.ReplaceAll(c.Names[0], "*", "wildcard")
	}
	return base + ext
}

func attach(w http.ResponseWriter, name, ctype string, body []byte) {
	w.Header().Set("Content-Type", ctype)
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", name))
	w.Header().Set("Cache-Control", "no-store")
	w.Write(body)
}

func pemCerts(certs ...*x509.Certificate) []byte {
	var out []byte
	for _, c := range certs {
		out = append(out, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})...)
	}
	return out
}

func (s *Server) downloadCert(w http.ResponseWriter, r *http.Request) {
	c, ok := s.getCert(w, r)
	if !ok {
		return
	}
	if c.Leaf == nil {
		s.fail(w, r, http.StatusConflict, errors.New("certificate not issued yet"))
		return
	}
	if strings.HasSuffix(r.URL.Path, "/fullchain.pem") {
		attach(w, filename(c, ".fullchain.pem"), "application/x-pem-file", pemCerts(append([]*x509.Certificate{c.Leaf}, c.Chain...)...))
		return
	}
	attach(w, filename(c, ".crt"), "application/x-pem-file", pemCerts(c.Leaf))
}

// keyFor returns the private key: from the Secret (managed) or memory (unmanaged).
func (s *Server) keyFor(r *http.Request, c *kube.Cert) (crypto.Signer, error) {
	switch c.Mode {
	case kube.Managed:
		return s.kube.Key(r.Context(), c.ID)
	case kube.Unmanaged:
		if k, _, ok := s.stash.Get(c.ID); ok {
			return k, nil
		}
		return nil, errors.New("the private key is gone: unmanaged keys are only kept in memory for a limited time (or until the portal restarts). Delete this one and issue again")
	}
	return nil, errors.New("this certificate was issued from your CSR; the private key never left your device")
}

func (s *Server) downloadKey(w http.ResponseWriter, r *http.Request) {
	c, ok := s.getCert(w, r)
	if !ok {
		return
	}
	key, err := s.keyFor(r, c)
	if err != nil {
		s.fail(w, r, http.StatusConflict, err)
		return
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		s.fail(w, r, http.StatusInternalServerError, err)
		return
	}
	s.record(r, "download-key", c.ID, "")
	attach(w, filename(c, ".key"), "application/x-pem-file", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
}

func (s *Server) downloadP12(w http.ResponseWriter, r *http.Request) {
	c, ok := s.getCert(w, r)
	if !ok {
		return
	}
	if c.Leaf == nil {
		s.fail(w, r, http.StatusConflict, errors.New("certificate not issued yet"))
		return
	}
	key, err := s.keyFor(r, c)
	if err != nil {
		s.fail(w, r, http.StatusConflict, err)
		return
	}
	password := r.FormValue("password")
	if len(password) < 4 {
		s.fail(w, r, http.StatusBadRequest, errors.New("p12 password must be at least 4 characters (use Generate for a random one)"))
		return
	}
	chain := c.Chain
	if r.FormValue("root") == "on" && !c.Public {
		if root, _, err := s.kube.CA(r.Context(), s.cfg.CAConfigMap); err == nil {
			chain = append(chain, root)
		}
	}
	legacy := r.FormValue("encoding") != "modern"
	data, err := p12.Encode(key, c.Leaf, chain, password, legacy)
	if err != nil {
		s.fail(w, r, http.StatusInternalServerError, err)
		return
	}
	enc := "legacy"
	if !legacy {
		enc = "modern"
	}
	s.record(r, "download-p12", c.ID, enc)
	attach(w, filename(c, ".p12"), "application/x-pkcs12", data)
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
	if err := s.kube.Renew(r.Context(), c.ID); err != nil {
		s.fail(w, r, http.StatusConflict, err)
		return
	}
	s.record(r, "renew", c.ID, "manual")
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
	s.render(w, r, "ca", map[string]any{"CAs": []map[string]any{
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
	switch f := r.PathValue("file"); f {
	case "root.crt":
		attach(w, "wilsonfi-root-ca.crt", "application/x-x509-ca-cert", pemCerts(root))
	case "root.der":
		attach(w, "wilsonfi-root-ca.der", "application/x-x509-ca-cert", root.Raw)
	case "intermediate.crt":
		attach(w, "wilsonfi-intermediate-ca.crt", "application/x-x509-ca-cert", pemCerts(inter))
	case "intermediate.der":
		attach(w, "wilsonfi-intermediate-ca.der", "application/x-x509-ca-cert", inter.Raw)
	case "bundle.crt":
		attach(w, "wilsonfi-ca-bundle.crt", "application/x-x509-ca-cert", pemCerts(inter, root))
	default:
		http.NotFound(w, r)
	}
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
