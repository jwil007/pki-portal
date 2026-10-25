package stepca

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
	"time"

	"go.step.sm/crypto/jose"
)

// fakeCA is a minimal step-ca: /provisioners, /1.0/sign and /health.
func fakeCA(t *testing.T, password string) (*httptest.Server, *x509.Certificate) {
	t.Helper()
	jwk, err := jose.GenerateJWK("EC", "P-256", "ES256", "sig", "", 0)
	if err != nil {
		t.Fatal(err)
	}
	pub := jwk.Public()
	jwe, err := jose.EncryptJWK(jwk, []byte(password))
	if err != nil {
		t.Fatal(err)
	}
	enc, _ := jwe.CompactSerialize()

	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Test Intermediate"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign}
	caDER, _ := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	ca, _ := x509.ParseCertificate(caDER)

	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(`{"status":"ok"}`)) })
	mux.HandleFunc("GET /provisioners", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"provisioners": []map[string]any{
			{"type": "ACME", "name": "acme"},
			{"type": "JWK", "name": "pki-portal", "key": pub, "encryptedKey": enc},
		}})
	})
	var srvURL string
	mux.HandleFunc("POST /1.0/sign", func(w http.ResponseWriter, r *http.Request) {
		var req struct{ CSR, OTT string }
		json.NewDecoder(r.Body).Decode(&req)
		tok, err := jose.ParseSigned(req.OTT)
		if err != nil {
			http.Error(w, `{"message":"bad token"}`, 401)
			return
		}
		var claims tokenClaims
		if err := tok.Claims(pub.Key, &claims); err != nil {
			http.Error(w, `{"message":"bad signature"}`, 401)
			return
		}
		if claims.Issuer != "pki-portal" || !slices.Contains(claims.Audience, srvURL+"/1.0/sign") {
			http.Error(w, `{"message":"bad iss/aud"}`, 401)
			return
		}
		block, _ := pem.Decode([]byte(req.CSR))
		csr, err := x509.ParseCertificateRequest(block.Bytes)
		if err != nil {
			http.Error(w, `{"message":"bad csr"}`, 400)
			return
		}
		leafTmpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: claims.Subject},
			DNSNames: claims.SANs, NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour)}
		der, _ := x509.CreateCertificate(rand.Reader, leafTmpl, ca, csr.PublicKey, caKey)
		leafPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
		caPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Raw}))
		json.NewEncoder(w).Encode(map[string]any{"crt": leafPEM, "ca": caPEM, "certChain": []string{leafPEM, caPEM}})
	})
	mux.HandleFunc("POST /1.0/revoke", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Serial, OTT string
			Passive     bool
		}
		json.NewDecoder(r.Body).Decode(&req)
		tok, _ := jose.ParseSigned(req.OTT)
		var claims tokenClaims
		if tok == nil || tok.Claims(pub.Key, &claims) != nil || claims.Subject != req.Serial || !req.Passive ||
			!slices.Contains(claims.Audience, srvURL+"/1.0/revoke") {
			http.Error(w, `{"message":"bad revoke"}`, 401)
			return
		}
		w.Write([]byte(`{"status":"ok"}`))
	})
	srv := httptest.NewTLSServer(mux)
	srvURL = srv.URL
	t.Cleanup(srv.Close)
	return srv, srv.Certificate()
}

func csr(t *testing.T, names ...string) []byte {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{DNSNames: names}, key)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
}

func TestSign(t *testing.T) {
	srv, tlsRoot := fakeCA(t, "s3cret")
	c, err := New(srv.URL, "pki-portal", "s3cret", "", tlsRoot)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := c.Health(ctx); err != nil {
		t.Fatal(err)
	}
	chainPEM, err := c.Sign(ctx, csr(t, "nas.wilsonfi.dev"), "nas.wilsonfi.dev", []string{"nas.wilsonfi.dev"}, 0)
	if err != nil {
		t.Fatal(err)
	}
	var certs []*x509.Certificate
	for rest := chainPEM; ; {
		var b *pem.Block
		if b, rest = pem.Decode(rest); b == nil {
			break
		}
		c, _ := x509.ParseCertificate(b.Bytes)
		certs = append(certs, c)
	}
	if len(certs) != 2 || certs[0].Subject.CommonName != "nas.wilsonfi.dev" {
		t.Fatalf("chain = %d certs", len(certs))
	}
}

func TestWrongPassword(t *testing.T) {
	srv, tlsRoot := fakeCA(t, "s3cret")
	c, _ := New(srv.URL, "pki-portal", "nope", "", tlsRoot)
	if _, err := c.Sign(context.Background(), csr(t, "a.wilsonfi.dev"), "a.wilsonfi.dev", []string{"a.wilsonfi.dev"}, 0); err == nil {
		t.Fatal("signed with wrong provisioner password")
	}
	c2, _ := New(srv.URL, "missing", "s3cret", "", tlsRoot)
	if _, err := c2.Sign(context.Background(), csr(t, "a.wilsonfi.dev"), "a.wilsonfi.dev", []string{"a.wilsonfi.dev"}, 0); err == nil {
		t.Fatal("signed with unknown provisioner")
	}
}

func TestRevoke(t *testing.T) {
	srv, tlsRoot := fakeCA(t, "s3cret")
	c, _ := New(srv.URL, "pki-portal", "s3cret", "", tlsRoot)
	if err := c.Revoke(context.Background(), big.NewInt(123456789), 1, "key compromise"); err != nil {
		t.Fatal(err)
	}
	if _, err := c.CRL(context.Background()); err != ErrNoCRL {
		t.Errorf("CRL on a CA without CRLs: %v", err)
	}
}
