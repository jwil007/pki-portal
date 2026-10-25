package hooks

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	cmfake "github.com/cert-manager/cert-manager/pkg/client/clientset/versioned/fake"
	"golang.org/x/crypto/ssh"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/jwil007/pki-portal/internal/kube"
	"github.com/jwil007/pki-portal/internal/store"
)

func testEvent() Event {
	return Event{Event: "renewed", CertID: "fw-x", Names: []string{"fw.wilsonfi.dev"}, Serial: "AB", NotAfter: time.Now().Add(time.Hour), URL: "https://pki.wilsonfi.dev/certs/fw-x"}
}

func testEnv() *Env { return &Env{HTTP: http.DefaultClient} }

func TestWebhookSigned(t *testing.T) {
	var got []byte
	var sig string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got, _ = io.ReadAll(r.Body)
		sig = r.Header.Get("X-PKI-Signature")
	}))
	defer srv.Close()
	d, _ := Get("webhook")
	cfg := map[string]string{"url": srv.URL}
	notes, err := d.Prepare(context.Background(), testEnv(), cfg)
	if err != nil || notes["Signing secret"] == "" || cfg["secret"] == "" {
		t.Fatalf("prepare: %v %v", notes, err)
	}
	if err := d.Deliver(context.Background(), testEnv(), cfg, testEvent(), Material{}); err != nil {
		t.Fatal(err)
	}
	if sig != Sign(cfg["secret"], got) {
		t.Error("signature mismatch")
	}
	var ev Event
	json.Unmarshal(got, &ev)
	if ev.CertID != "fw-x" || strings.Contains(string(got), "PRIVATE") {
		t.Errorf("body = %s", got)
	}
}

func TestNtfy(t *testing.T) {
	var title, body string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		title = r.Header.Get("Title")
		b, _ := io.ReadAll(r.Body)
		body = string(b)
	}))
	defer srv.Close()
	d, _ := Get("ntfy")
	env := testEnv()
	if _, err := d.Prepare(context.Background(), env, map[string]string{}); err == nil {
		t.Error("ntfy without any URL accepted")
	}
	env.DefaultNtfyURL = srv.URL
	if err := d.Deliver(context.Background(), env, map[string]string{}, testEvent(), Material{}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(title, "renewed") || !strings.Contains(body, "fw.wilsonfi.dev") {
		t.Errorf("title=%q body=%q", title, body)
	}
}

func TestSemaphore(t *testing.T) {
	var path, auth string
	var req map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path, auth = r.URL.Path, r.Header.Get("Authorization")
		json.NewDecoder(r.Body).Decode(&req)
		w.WriteHeader(201)
	}))
	defer srv.Close()
	d, _ := Get("semaphore")
	env := testEnv()
	cfg := map[string]string{"project_id": "1", "template_id": "7"}
	if _, err := d.Prepare(context.Background(), env, cfg); err == nil {
		t.Error("accepted without Semaphore configured")
	}
	env.SemaphoreURL, env.SemaphoreToken = srv.URL, "tok"
	if _, err := d.Prepare(context.Background(), env, cfg); err != nil {
		t.Fatal(err)
	}
	if err := d.Deliver(context.Background(), env, cfg, testEvent(), Material{}); err != nil {
		t.Fatal(err)
	}
	if path != "/api/project/1/tasks" || auth != "Bearer tok" || req["template_id"].(float64) != 7 ||
		!strings.Contains(req["environment"].(string), `"pki_cert_id":"fw-x"`) {
		t.Errorf("path=%s auth=%s req=%v", path, auth, req)
	}
}

// --- SSH: a tiny in-process server that records exec commands and stdin ---

type sshRecorder struct {
	mu    sync.Mutex
	cmds  []string
	stdin map[string]string
}

func startSSH(t *testing.T, clientKey ssh.PublicKey) (string, ssh.PublicKey, *sshRecorder) {
	t.Helper()
	_, hostPriv, _ := ed25519.GenerateKey(rand.Reader)
	hostSigner, _ := ssh.NewSignerFromKey(hostPriv)
	conf := &ssh.ServerConfig{PublicKeyCallback: func(_ ssh.ConnMetadata, k ssh.PublicKey) (*ssh.Permissions, error) {
		if string(k.Marshal()) == string(clientKey.Marshal()) {
			return nil, nil
		}
		return nil, io.EOF
	}}
	conf.AddHostKey(hostSigner)
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	t.Cleanup(func() { ln.Close() })
	rec := &sshRecorder{stdin: map[string]string{}}
	go func() {
		for {
			nc, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				_, chans, reqs, err := ssh.NewServerConn(nc, conf)
				if err != nil {
					return
				}
				go ssh.DiscardRequests(reqs)
				for nch := range chans {
					ch, creqs, _ := nch.Accept()
					go func() {
						for r := range creqs {
							if r.Type != "exec" {
								r.Reply(false, nil)
								continue
							}
							cmd := string(r.Payload[4:])
							r.Reply(true, nil)
							in, _ := io.ReadAll(ch)
							rec.mu.Lock()
							rec.cmds = append(rec.cmds, cmd)
							rec.stdin[cmd] = string(in)
							rec.mu.Unlock()
							status := make([]byte, 4)
							binary.BigEndian.PutUint32(status, 0)
							ch.SendRequest("exit-status", false, status)
							ch.Close()
						}
					}()
				}
			}()
		}
	}()
	return ln.Addr().String(), hostSigner.PublicKey(), rec
}

func TestSSHPush(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer, _ := ssh.NewSignerFromKey(priv)
	addrStr, hostKey, rec := startSSH(t, signer.PublicKey())
	host, port, _ := net.SplitHostPort(addrStr)

	env := &Env{SSHSigner: signer}
	d, _ := Get("ssh")
	cfg := map[string]string{"host": host, "port": port, "user": "root", "cert_path": "/etc/ssl/a.pem", "key_path": "/etc/ssl/a.key", "reload": "systemctl reload nginx"}
	notes, err := d.Prepare(context.Background(), env, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if notes["Login test"] != "ok" || cfg["host_key"] != strings.TrimSpace(string(ssh.MarshalAuthorizedKey(hostKey))) {
		t.Fatalf("notes=%v host_key=%q", notes, cfg["host_key"])
	}

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(5), Subject: pkix.Name{CommonName: "a"}, NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour)}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	leaf, _ := x509.ParseCertificate(der)
	mat := Material{Leaf: leaf, Key: func(context.Context) (any, error) { return key, nil }}
	if err := d.Deliver(context.Background(), env, cfg, testEvent(), mat); err != nil {
		t.Fatal(err)
	}
	if len(rec.cmds) != 3 || rec.cmds[2] != "systemctl reload nginx" {
		t.Fatalf("cmds = %q", rec.cmds)
	}
	if !strings.Contains(rec.stdin[rec.cmds[0]], "BEGIN PRIVATE KEY") || !strings.Contains(rec.cmds[0], "'/etc/ssl/a.key'") {
		t.Errorf("key write: %q", rec.cmds[0])
	}
	if !strings.Contains(rec.stdin[rec.cmds[1]], "BEGIN CERTIFICATE") {
		t.Error("cert not written")
	}

	// A different host key must be refused.
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	otherSigner, _ := ssh.NewSignerFromKey(other)
	cfg["host_key"] = string(ssh.MarshalAuthorizedKey(otherSigner.PublicKey()))
	if err := d.Deliver(context.Background(), env, cfg, testEvent(), mat); err == nil {
		t.Error("delivered to a host with the wrong key")
	}
}

// --- Manager ---

func certPEM(t *testing.T, serial int64) (*x509.Certificate, []byte) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(serial), DNSNames: []string{"nas.wilsonfi.dev"},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	c, _ := x509.ParseCertificate(der)
	return c, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func TestManagerDeliversOncePerSerial(t *testing.T) {
	ctx := context.Background()
	st, _ := store.Open(filepath.Join(t.TempDir(), "p.db"))
	k := kube.NewWithClients("pki-managed", fake.NewClientset(), cmfake.NewClientset())
	root, chain := certPEM(t, 1)
	k.SaveSigned(ctx, "nas", kube.FromCSR, chain, nil, root, "rsa2048", 1)

	var events []string
	fail := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if fail {
			w.WriteHeader(500)
			return
		}
		events = append(events, r.Header.Get("X-PKI-Event"))
	}))
	defer srv.Close()

	m := NewManager(st, k, testEnv(), "https://pki", slog.New(slog.NewTextHandler(io.Discard, nil)))
	st.AddHook(&store.Hook{CertID: "nas", Type: "webhook", Config: map[string]string{"url": srv.URL, "secret": "s"}})
	m.Reconcile(ctx)
	m.Reconcile(ctx)
	if len(events) != 1 || events[0] != "issued" {
		t.Fatalf("events = %v", events)
	}

	_, chain2 := certPEM(t, 2)
	k.SaveSigned(ctx, "nas", kube.FromCSR, chain2, nil, root, "rsa2048", 2)
	fail = true
	m.Reconcile(ctx)
	h, _ := st.Hook(1)
	if h.LastOK || h.Failures != 1 || h.NextAttempt.Before(time.Now()) {
		t.Fatalf("after failure: %+v", h)
	}
	fail = false
	m.Reconcile(ctx) // still backing off
	if len(events) != 1 {
		t.Fatalf("delivered during backoff: %v", events)
	}
	if err := m.RunNow(ctx, 1); err != nil {
		t.Fatal(err)
	}
	m.Reconcile(ctx) // RunNow marked the current serial delivered
	if len(events) != 2 || events[1] != "test" {
		t.Fatalf("events = %v", events)
	}
	if c := m.Counts(); c[[2]string{"webhook", "ok"}] != 2 || c[[2]string{"webhook", "failed"}] != 1 {
		t.Errorf("counts = %v", c)
	}
}
