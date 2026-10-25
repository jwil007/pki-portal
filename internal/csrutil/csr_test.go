package csrutil

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"net"
	"strings"
	"testing"
)

func mkCSR(t *testing.T, key any, tmpl *x509.CertificateRequest) []byte {
	t.Helper()
	der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
}

func TestParseValid(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	data := mkCSR(t, key, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: "FW.wilsonfi.dev"},
		DNSNames: []string{"vpn.wilsonfi.dev"},
	})
	info, _, err := Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	if info.Key != "ECDSA P-256" {
		t.Errorf("key = %s", info.Key)
	}
	names, err := info.ACMENames()
	if err != nil || len(names) != 2 || names[0] != "fw.wilsonfi.dev" {
		t.Errorf("names = %v, err = %v", names, err)
	}
}

func TestParseRejects(t *testing.T) {
	small, _ := rsa.GenerateKey(rand.Reader, 1024)
	p224, _ := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	ok, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	if _, _, err := Parse(mkCSR(t, small, &x509.CertificateRequest{DNSNames: []string{"a.wilsonfi.dev"}})); err == nil || !strings.Contains(err.Error(), "2048") {
		t.Errorf("RSA 1024 accepted: %v", err)
	}
	if _, _, err := Parse(mkCSR(t, p224, &x509.CertificateRequest{DNSNames: []string{"a.wilsonfi.dev"}})); err == nil {
		t.Error("P-224 accepted")
	}
	if _, _, err := Parse([]byte("garbage")); err == nil {
		t.Error("garbage accepted")
	}

	// Tamper with the signature.
	good := mkCSR(t, ok, &x509.CertificateRequest{DNSNames: []string{"a.wilsonfi.dev"}})
	block, _ := pem.Decode(good)
	block.Bytes[len(block.Bytes)-2] ^= 0xff
	if _, _, err := Parse(pem.EncodeToMemory(block)); err == nil {
		t.Error("bad signature accepted")
	}

	info, _, err := Parse(mkCSR(t, ok, &x509.CertificateRequest{DNSNames: []string{"a.wilsonfi.dev"}, IPAddresses: []net.IP{net.ParseIP("10.0.0.1")}}))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := info.ACMENames(); err == nil {
		t.Error("IP SAN accepted for ACME")
	}
}

func TestGenerate(t *testing.T) {
	for _, kt := range []KeyType{RSA2048, ECDSA256} {
		key, csrPEM, err := Generate(kt, []string{"fw.wilsonfi.dev"})
		if err != nil {
			t.Fatal(err)
		}
		info, csr, err := Parse(csrPEM)
		if err != nil {
			t.Fatal(err)
		}
		if info.CN != "fw.wilsonfi.dev" || csr.PublicKey == nil || key == nil {
			t.Errorf("%s: bad CSR %+v", kt, info)
		}
	}
}
