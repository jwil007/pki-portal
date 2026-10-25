package p12

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

func selfSigned(t *testing.T, cn string, isCA bool, parent *x509.Certificate, parentKey any) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  isCA,
		BasicConstraintsValid: true,
	}
	if parent == nil {
		parent, parentKey = tmpl, key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, &key.PublicKey, parentKey)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return c, key
}

func TestRoundTrip(t *testing.T) {
	ca, caKey := selfSigned(t, "Test CA", true, nil, nil)
	leaf, key := selfSigned(t, "fw.wilsonfi.dev", false, ca, caKey)
	for _, legacy := range []bool{true, false} {
		pw := GeneratePassword()
		data, err := Encode(key, leaf, []*x509.Certificate{ca}, pw, legacy)
		if err != nil {
			t.Fatal(err)
		}
		gotKey, gotLeaf, gotChain, err := pkcs12.DecodeChain(data, pw)
		if err != nil {
			t.Fatalf("legacy=%v decode: %v", legacy, err)
		}
		if gotLeaf.Subject.CommonName != "fw.wilsonfi.dev" || len(gotChain) != 1 || gotKey == nil {
			t.Errorf("legacy=%v: unexpected contents", legacy)
		}
		if _, _, _, err := pkcs12.DecodeChain(data, "wrong"); err == nil {
			t.Errorf("legacy=%v: wrong password accepted", legacy)
		}
	}
}
