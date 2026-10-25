package formats

import (
	"archive/zip"
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"

	"go.step.sm/crypto/pemutil"
	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

func testBundle(t *testing.T) Bundle {
	t.Helper()
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caT := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "CA"}, IsCA: true, BasicConstraintsValid: true,
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageCertSign}
	caDER, _ := x509.CreateCertificate(rand.Reader, caT, caT, &caKey.PublicKey, caKey)
	ca, _ := x509.ParseCertificate(caDER)
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	leafT := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "fw.wilsonfi.dev"},
		NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour)}
	der, _ := x509.CreateCertificate(rand.Reader, leafT, ca, &key.PublicKey, caKey)
	leaf, _ := x509.ParseCertificate(der)
	return Bundle{Leaf: leaf, Chain: []*x509.Certificate{ca}, Key: key, Name: "fw.wilsonfi.dev"}
}

func TestAllFormatsRender(t *testing.T) {
	b := testBundle(t)
	for _, f := range All {
		out, err := Render(f.ID, b, "password1")
		if err != nil {
			t.Errorf("%s: %v", f.ID, err)
			continue
		}
		if len(out.Data) == 0 || !strings.HasPrefix(out.Filename, "fw.wilsonfi.dev") {
			t.Errorf("%s: empty or misnamed output %q", f.ID, out.Filename)
		}
	}
}

func TestFormatContents(t *testing.T) {
	b := testBundle(t)
	out, _ := Render("key-traditional", b, "")
	if !bytes.Contains(out.Data, []byte("BEGIN RSA PRIVATE KEY")) {
		t.Error("traditional key not PKCS#1")
	}
	out, _ = Render("key-encrypted", b, "password1")
	if !bytes.Contains(out.Data, []byte("BEGIN ENCRYPTED PRIVATE KEY")) {
		t.Errorf("encrypted key header: %s", out.Data[:40])
	}
	if _, err := pemutil.Parse(out.Data, pemutil.WithPassword([]byte("password1"))); err != nil {
		t.Errorf("encrypted key doesn't decrypt: %v", err)
	}
	out, _ = Render("cer", b, "")
	if _, err := x509.ParseCertificate(out.Data); err != nil {
		t.Error("cer is not DER")
	}
	out, _ = Render("combined", b, "")
	if n := strings.Count(string(out.Data), "-----BEGIN"); n != 3 {
		t.Errorf("combined has %d blocks, want key + leaf + intermediate", n)
	}
	out, _ = Render("p12-modern", b, "password1")
	if _, _, _, err := pkcs12.DecodeChain(out.Data, "password1"); err != nil {
		t.Error(err)
	}
	b.Root = b.Chain[0]
	out, _ = Render("zip", b, "")
	zr, err := zip.NewReader(bytes.NewReader(out.Data), int64(len(out.Data)))
	if err != nil || len(zr.File) != 5 {
		t.Errorf("zip: %v, %d files", err, len(zr.File))
	}
	out, _ = Render("crt", b, "")
	if blk, _ := pem.Decode(out.Data); blk == nil || blk.Type != "CERTIFICATE" {
		t.Error("crt not PEM")
	}
}

func TestNeedsKeyAndPassword(t *testing.T) {
	b := testBundle(t)
	if _, err := Render("p12-legacy", b, ""); err == nil {
		t.Error("p12 without password allowed")
	}
	b.Key = nil
	if _, err := Render("key", b, ""); err == nil {
		t.Error("key format without key allowed")
	}
	if _, err := Render("fullchain", b, ""); err != nil {
		t.Error(err)
	}
}
