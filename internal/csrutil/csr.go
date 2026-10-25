// Package csrutil parses and validates PEM certificate signing requests,
// and generates keys + CSRs for portal-generated (unmanaged) certificates.
package csrutil

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"slices"
	"strings"
)

// Info is what the UI shows about a CSR.
type Info struct {
	Subject  string
	CN       string
	DNSNames []string
	IPs      []string
	Emails   []string
	URIs     []string
	Key      string
	PEM      []byte
}

// Parse decodes one PEM CSR, checks its signature and key strength.
func Parse(data []byte) (*Info, *x509.CertificateRequest, error) {
	block, _ := pem.Decode([]byte(strings.TrimSpace(string(data))))
	if block == nil {
		return nil, nil, fmt.Errorf("no PEM block found; paste the whole CSR including the BEGIN/END lines")
	}
	if block.Type != "CERTIFICATE REQUEST" && block.Type != "NEW CERTIFICATE REQUEST" {
		return nil, nil, fmt.Errorf("PEM block is %q, expected CERTIFICATE REQUEST", block.Type)
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("can't parse CSR: %w", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, nil, fmt.Errorf("CSR signature is invalid: %w", err)
	}
	keyDesc, err := CheckKey(csr.PublicKey)
	if err != nil {
		return nil, nil, err
	}
	info := &Info{
		Subject:  csr.Subject.String(),
		CN:       strings.ToLower(csr.Subject.CommonName),
		DNSNames: csr.DNSNames,
		Emails:   csr.EmailAddresses,
		Key:      keyDesc,
		PEM:      pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: block.Bytes}),
	}
	for _, ip := range csr.IPAddresses {
		info.IPs = append(info.IPs, ip.String())
	}
	for _, u := range csr.URIs {
		info.URIs = append(info.URIs, u.String())
	}
	return info, csr, nil
}

// ACMENames returns the DNS names an ACME issuer would certify, or an error if
// the CSR carries anything ACME can't validate.
func (i *Info) ACMENames() ([]string, error) {
	if len(i.IPs) > 0 || len(i.Emails) > 0 || len(i.URIs) > 0 {
		return nil, fmt.Errorf("CSR contains IP, email or URI SANs; ACME issuers only accept DNS names")
	}
	names := slices.Clone(i.DNSNames)
	for k := range names {
		names[k] = strings.ToLower(names[k])
	}
	if i.CN != "" && !slices.Contains(names, i.CN) {
		// cert-manager adds the CN to the order, so treat it as a name to validate.
		names = append([]string{i.CN}, names...)
	}
	if len(names) == 0 {
		return nil, fmt.Errorf("CSR has no DNS names")
	}
	return names, nil
}

// CheckKey enforces RSA >= 2048 or ECDSA P-256/P-384.
func CheckKey(pub any) (string, error) {
	switch k := pub.(type) {
	case *rsa.PublicKey:
		if k.N.BitLen() < 2048 {
			return "", fmt.Errorf("RSA key is %d bits; minimum is 2048", k.N.BitLen())
		}
		return fmt.Sprintf("RSA %d", k.N.BitLen()), nil
	case *ecdsa.PublicKey:
		switch k.Curve {
		case elliptic.P256():
			return "ECDSA P-256", nil
		case elliptic.P384():
			return "ECDSA P-384", nil
		}
		return "", fmt.Errorf("ECDSA curve %s not allowed (P-256 or P-384 only)", k.Curve.Params().Name)
	}
	return "", fmt.Errorf("unsupported key type %T (RSA or ECDSA only)", pub)
}

// KeyType is a key choice offered in the UI.
type KeyType string

const (
	RSA2048  KeyType = "rsa2048"
	ECDSA256 KeyType = "ecdsa256"
)

// Generate creates a key and a CSR for the given names. The key stays in memory.
func Generate(kt KeyType, names []string) (crypto.Signer, []byte, error) {
	var key crypto.Signer
	var err error
	switch kt {
	case ECDSA256:
		key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	default:
		key, err = rsa.GenerateKey(rand.Reader, 2048)
	}
	if err != nil {
		return nil, nil, err
	}
	tmpl := &x509.CertificateRequest{DNSNames: names}
	if len(names) > 0 && len(names[0]) <= 64 {
		tmpl.Subject = pkix.Name{CommonName: names[0]}
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	if err != nil {
		return nil, nil, err
	}
	return key, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}), nil
}
