package web

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	cmfake "github.com/cert-manager/cert-manager/pkg/client/clientset/versioned/fake"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/jwil007/pki-portal/internal/config"
	"github.com/jwil007/pki-portal/internal/keystash"
	"github.com/jwil007/pki-portal/internal/kube"
	"github.com/jwil007/pki-portal/internal/store"
)

func newTestServer(t *testing.T) (*httptest.Server, *http.Client) {
	t.Helper()
	dir := t.TempDir()
	cfg := &config.Config{
		Password: "hunter22", DataDir: dir, Namespace: "pki-managed",
		PublicIssuer: "letsencrypt-staging", InternalIssuer: "step-ca-acme",
		Domains: []string{"wilsonfi.dev"}, PublicDomains: []string{"wilsonfi.dev"},
		CAConfigMap: "pki/step-certificates-certs", InsecureCookie: true,
	}
	st, err := store.Open(filepath.Join(dir, "portal.db"))
	if err != nil {
		t.Fatal(err)
	}
	core := fake.NewClientset(&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: "pki", Name: "step-certificates-certs"}})
	k := kube.NewWithClients("pki-managed", core, cmfake.NewClientset())
	srv, err := New(cfg, k, st, keystash.New(time.Minute), slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	jar, _ := cookiejar.New(nil)
	return ts, &http.Client{Jar: jar}
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
