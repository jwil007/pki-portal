package web

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	cmfake "github.com/cert-manager/cert-manager/pkg/client/clientset/versioned/fake"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/jwil007/pki-portal/internal/config"
	"github.com/jwil007/pki-portal/internal/hooks"
	"github.com/jwil007/pki-portal/internal/keystash"
	"github.com/jwil007/pki-portal/internal/kube"
	"github.com/jwil007/pki-portal/internal/store"
)

func newTestServer(t *testing.T) (*httptest.Server, *http.Client) {
	ts, c, _, _ := newTestServerFull(t)
	return ts, c
}

func newTestServerFull(t *testing.T) (*httptest.Server, *http.Client, *kube.Kube, *config.Config) {
	t.Helper()
	dir := t.TempDir()
	cfg := &config.Config{
		Password: "hunter22", DataDir: dir, Namespace: "pki-managed",
		PublicIssuer: "letsencrypt-staging",
		Domains:      []string{"wilsonfi.dev"}, PublicDomains: []string{"wilsonfi.dev"},
		CAConfigMap: "pki/step-certificates-certs", InsecureCookie: true,
	}
	st, err := store.Open(filepath.Join(dir, "portal.db"))
	if err != nil {
		t.Fatal(err)
	}
	core := fake.NewClientset(&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: "pki", Name: "step-certificates-certs"}})
	k := kube.NewWithClients("pki-managed", core, cmfake.NewClientset())
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	hm := hooks.NewManager(st, k, &hooks.Env{HTTP: http.DefaultClient}, "http://portal", log)
	srv, err := New(cfg, k, st, keystash.New(time.Minute), nil, hm, log)
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	jar, _ := cookiejar.New(nil)
	return ts, &http.Client{Jar: jar}, k, cfg
}

func body(t *testing.T, resp *http.Response) string {
	t.Helper()
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return string(b)
}

func TestLoginAndPages(t *testing.T) {
	ts, c := newTestServer(t)

	resp, _ := c.Get(ts.URL + "/certs")
	if !strings.Contains(body(t, resp), `name="password"`) {
		t.Fatal("unauthenticated request not redirected to login")
	}
	resp, _ = c.PostForm(ts.URL+"/login", url.Values{"password": {"nope"}})
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("bad password status = %d", resp.StatusCode)
	}
	resp, _ = c.PostForm(ts.URL+"/login", url.Values{"password": {"hunter22"}})
	if b := body(t, resp); !strings.Contains(b, "Dashboard") {
		t.Fatalf("login didn't land on dashboard: %s", b[:min(300, len(b))])
	}
	for _, p := range []string{"/", "/certs", "/certs/new", "/csr", "/audit"} {
		resp, _ := c.Get(ts.URL + p)
		if resp.StatusCode != 200 {
			t.Errorf("%s: status %d: %s", p, resp.StatusCode, body(t, resp))
		}
		resp.Body.Close()
	}

	// Live policy check fragment.
	resp, _ = c.PostForm(ts.URL+"/certs/check", url.Values{"type": {"public"}, "names": {"evil.example.com"}})
	if b := body(t, resp); !strings.Contains(b, "not under an allowed domain") {
		t.Errorf("check fragment = %s", b)
	}

	// Issue a managed cert and land on its detail page.
	resp, _ = c.PostForm(ts.URL+"/certs/new", url.Values{"type": {"public"}, "names": {"fw.wilsonfi.dev"}, "lifecycle": {"managed"}, "key": {"rsa2048"}})
	if b := body(t, resp); !strings.Contains(b, "fw.wilsonfi.dev") || !strings.Contains(b, "Issuance progress") {
		t.Errorf("detail page after issue: %s", b)
	}
	// Second identical request must ask for confirmation.
	resp, _ = c.PostForm(ts.URL+"/certs/new", url.Values{"type": {"public"}, "names": {"fw.wilsonfi.dev"}, "lifecycle": {"managed"}})
	if resp.StatusCode != http.StatusUnprocessableEntity {
		t.Errorf("duplicate issue status = %d", resp.StatusCode)
	}
	resp.Body.Close()
	resp, _ = c.Get(ts.URL + "/audit")
	if b := body(t, resp); !strings.Contains(b, "managed via letsencrypt-staging") {
		t.Errorf("issue not audited")
	}
}

func TestCrossOriginPostRejected(t *testing.T) {
	ts, c := newTestServer(t)
	c.PostForm(ts.URL+"/login", url.Values{"password": {"hunter22"}})
	req, _ := http.NewRequest("POST", ts.URL+"/logout", nil)
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("cross-site POST status = %d, want 403", resp.StatusCode)
	}
}

func TestInternalDisabledWithoutProvisioner(t *testing.T) {
	ts, c := newTestServer(t)
	c.PostForm(ts.URL+"/login", url.Values{"password": {"hunter22"}})
	resp, _ := c.PostForm(ts.URL+"/certs/check", url.Values{"type": {"internal"}, "names": {"nas.wilsonfi.dev"}})
	if b := body(t, resp); !strings.Contains(b, "internal certificates are disabled") {
		t.Errorf("check = %s", b)
	}
}

func TestPullAPI(t *testing.T) {
	ts, c, k, _ := newTestServerFull(t)
	c.PostForm(ts.URL+"/login", url.Values{"password": {"hunter22"}})
	root, chain := testChain(t)
	if err := k.SaveSigned(context.Background(), kube.Signed{ID: "nas-x", Mode: kube.FromCSR, ChainPEM: chain, Root: root, KeyType: "rsa2048", Revision: 1}); err != nil {
		t.Fatal(err)
	}
	resp, _ := c.PostForm(ts.URL+"/certs/nas-x/hooks", url.Values{"type": {"pull"}})
	page := body(t, resp)
	token := regexp.MustCompile(`pkp_[A-Za-z0-9_-]+`).FindString(page)
	if token == "" || !strings.Contains(page, "pki-fetch-nas.wilsonfi.dev.timer") {
		t.Fatalf("no token/snippet in page: %s", page)
	}
	get := func(path, tok string) (int, string) {
		req, _ := http.NewRequest("GET", ts.URL+path, nil)
		if tok != "" {
			req.Header.Set("Authorization", "Bearer "+tok)
		}
		resp, err := http.DefaultClient.Do(req) // no session cookie
		if err != nil {
			t.Fatal(err)
		}
		return resp.StatusCode, body(t, resp)
	}
	if code, b := get("/api/v1/certs/nas-x/fullchain", token); code != 200 || !strings.Contains(b, "BEGIN CERTIFICATE") {
		t.Fatalf("fullchain: %d %s", code, b)
	}
	if code, _ := get("/api/v1/certs/nas-x/key", token); code != http.StatusConflict {
		t.Errorf("key for CSR cert: %d", code)
	}
	if code, _ := get("/api/v1/certs/other/fullchain", token); code != http.StatusUnauthorized {
		t.Errorf("token used on another cert: %d", code)
	}
	if code, _ := get("/api/v1/certs/nas-x/fullchain", ""); code != http.StatusUnauthorized {
		t.Errorf("no token: %d", code)
	}
	// Revoke by deleting the hook.
	resp, _ = c.PostForm(ts.URL+"/hooks/1/delete", nil)
	resp.Body.Close()
	if code, _ := get("/api/v1/certs/nas-x/fullchain", token); code != http.StatusUnauthorized {
		t.Errorf("after delete: %d", code)
	}
}

func TestPasswordFileRotation(t *testing.T) {
	ts, c, _, cfg := newTestServerFull(t)
	pwFile := filepath.Join(t.TempDir(), "pw")
	os.WriteFile(pwFile, []byte("first-pass\n"), 0o600)
	cfg.PasswordFile = pwFile
	if resp, _ := c.PostForm(ts.URL+"/login", url.Values{"password": {"first-pass"}}); resp.StatusCode != 200 || resp.Request.URL.Path != "/" {
		t.Fatalf("login with file password failed: %d %s", resp.StatusCode, resp.Request.URL.Path)
	}
	os.WriteFile(pwFile, []byte("second-pass"), 0o600)
	jar, _ := cookiejar.New(nil)
	c2 := &http.Client{Jar: jar}
	if resp, _ := c2.PostForm(ts.URL+"/login", url.Values{"password": {"first-pass"}}); resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("old password still works: %d", resp.StatusCode)
	}
	if resp, _ := c2.PostForm(ts.URL+"/login", url.Values{"password": {"second-pass"}}); resp.Request.URL.Path != "/" {
		t.Errorf("new password rejected")
	}
}

func testChain(t *testing.T) (*x509.Certificate, []byte) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(9), DNSNames: []string{"nas.wilsonfi.dev"}, IsCA: true, BasicConstraintsValid: true,
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour)}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	c, _ := x509.ParseCertificate(der)
	return c, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func TestGitOpsView(t *testing.T) {
	// The GitOps data logic is covered in kube; this checks the pages render.
	ts, c, _, cfg := newTestServerFull(t)
	cfg.GitOpsNamespace = "pki"
	c.PostForm(ts.URL+"/login", url.Values{"password": {"hunter22"}})
	resp, _ := c.Get(ts.URL + "/gitops")
	if b := body(t, resp); resp.StatusCode != 200 || !strings.Contains(b, "Managed by GitOps") {
		t.Fatalf("gitops page: %d %s", resp.StatusCode, b)
	}
	resp, _ = c.Get(ts.URL + "/clients")
	if b := body(t, resp); resp.StatusCode != 200 || !strings.Contains(b, "aren't enabled") {
		t.Errorf("clients page: %d", resp.StatusCode)
	}
}
