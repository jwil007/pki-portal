// Package p12 builds PKCS#12 bundles on the fly at download time.
package p12

import (
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"

	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

// Encode bundles key + leaf + chain. Legacy (3DES/SHA-1) is what ClearPass and
// most appliances accept; modern uses AES-256 + PBKDF2.
func Encode(key any, leaf *x509.Certificate, chain []*x509.Certificate, password string, legacy bool) ([]byte, error) {
	enc := pkcs12.Modern2023
	if legacy {
		enc = pkcs12.LegacyDES
	}
	return enc.Encode(key, leaf, chain, password)
}

// GeneratePassword returns a random password that's easy to copy (no symbols).
func GeneratePassword() string {
	b := make([]byte, 15)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}
