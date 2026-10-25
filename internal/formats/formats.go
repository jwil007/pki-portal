// Package formats renders a certificate (and optionally its key) into the
// file formats devices commonly ask for.
package formats

import (
	"archive/zip"
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"

	"go.step.sm/crypto/pemutil"

	"github.com/jwil007/pki-portal/internal/p12"
)

// Bundle is everything a format may need. Root is only set for internal certs.
type Bundle struct {
	Leaf  *x509.Certificate
	Chain []*x509.Certificate // intermediates
	Root  *x509.Certificate
	Key   crypto.Signer // nil when the portal doesn't have the key
	Name  string        // base filename, e.g. fw.wilsonfi.dev
}

type Format struct {
	ID       string
	Label    string
	Help     string
	Group    string
	Key      bool // needs the private key
	Password bool // needs a password
}

// All lists the formats in the order the UI shows them.
var All = []Format{
	{ID: "crt", Group: "Certificate", Label: "Certificate, PEM (.crt)", Help: "Leaf certificate only. Most Linux services and appliances"},
	{ID: "fullchain", Group: "Certificate", Label: "Full chain, PEM (.pem)", Help: "Leaf followed by intermediates. nginx, Traefik, HAProxy cert files"},
	{ID: "chain", Group: "Certificate", Label: "CA chain, PEM (.pem)", Help: "Intermediates (and root if included), without the leaf"},
	{ID: "cer", Group: "Certificate", Label: "Certificate, DER (.cer)", Help: "Binary leaf certificate. Windows, Java and some appliances"},
	{ID: "p12-legacy", Group: "Certificate + key", Label: "PKCS#12 legacy (.p12)", Help: "3DES/SHA-1. ClearPass, FortiGate, older Windows and most appliances", Key: true, Password: true},
	{ID: "p12-modern", Group: "Certificate + key", Label: "PKCS#12 modern (.p12)", Help: "AES-256/PBKDF2. Current Windows/macOS, OpenSSL 3, Java", Key: true, Password: true},
	{ID: "pfx", Group: "Certificate + key", Label: "PFX, legacy encoding (.pfx)", Help: "Same as legacy PKCS#12 with a .pfx name, for Windows/IIS", Key: true, Password: true},
	{ID: "combined", Group: "Certificate + key", Label: "Combined PEM: key + full chain (.pem)", Help: "One file. HAProxy, Proxmox, some appliances", Key: true},
	{ID: "zip", Group: "Certificate + key", Label: "ZIP of PEM files (.zip)", Help: "cert.crt, chain.pem, fullchain.pem, key.pem (and root.crt)", Key: true},
	{ID: "key", Group: "Private key", Label: "Private key, PKCS#8 PEM (.key)", Help: `"BEGIN PRIVATE KEY". The modern default`, Key: true},
	{ID: "key-traditional", Group: "Private key", Label: "Private key, traditional PEM (.key)", Help: `"BEGIN RSA/EC PRIVATE KEY". Older appliances that reject PKCS#8`, Key: true},
	{ID: "key-encrypted", Group: "Private key", Label: "Private key, encrypted PKCS#8 (.key)", Help: "AES-256 with your password. For devices that want a key passphrase", Key: true, Password: true},
}

func Lookup(id string) (Format, bool) {
	for _, f := range All {
		if f.ID == id {
			return f, true
		}
	}
	return Format{}, false
}

// Output is a rendered file.
type Output struct {
	Filename    string
	ContentType string
	Data        []byte
}

func pemCerts(certs ...*x509.Certificate) []byte {
	var out []byte
	for _, c := range certs {
		if c != nil {
			out = append(out, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})...)
		}
	}
	return out
}

func (b Bundle) caCerts() []*x509.Certificate {
	out := append([]*x509.Certificate{}, b.Chain...)
	if b.Root != nil {
		out = append(out, b.Root)
	}
	return out
}

func pkcs8PEM(key crypto.Signer) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

func traditionalPEM(key crypto.Signer) ([]byte, error) {
	switch k := key.(type) {
	case *rsa.PrivateKey:
		return pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)}), nil
	case *ecdsa.PrivateKey:
		der, err := x509.MarshalECPrivateKey(k)
		if err != nil {
			return nil, err
		}
		return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), nil
	}
	return nil, fmt.Errorf("unsupported key type %T", key)
}

// Render produces the file for format id. Root is included where it makes sense
// (chain, p12, zip) only when b.Root is set.
func Render(id string, b Bundle, password string) (*Output, error) {
	f, ok := Lookup(id)
	if !ok {
		return nil, fmt.Errorf("unknown format %q", id)
	}
	if b.Leaf == nil {
		return nil, errors.New("certificate not issued yet")
	}
	if f.Key && b.Key == nil {
		return nil, errors.New("this format includes the private key, which the portal doesn't have for this certificate")
	}
	if f.Password && len(password) < 4 {
		return nil, errors.New("this format needs a password of at least 4 characters")
	}
	full := append([]*x509.Certificate{b.Leaf}, b.Chain...)
	pemType, derType, p12Type := "application/x-pem-file", "application/pkix-cert", "application/x-pkcs12"

	switch id {
	case "crt":
		return &Output{b.Name + ".crt", pemType, pemCerts(b.Leaf)}, nil
	case "fullchain":
		return &Output{b.Name + ".fullchain.pem", pemType, pemCerts(full...)}, nil
	case "chain":
		return &Output{b.Name + ".chain.pem", pemType, pemCerts(b.caCerts()...)}, nil
	case "cer":
		return &Output{b.Name + ".cer", derType, b.Leaf.Raw}, nil
	case "p12-legacy", "p12-modern", "pfx":
		data, err := p12.Encode(b.Key, b.Leaf, b.caCerts(), password, id != "p12-modern")
		if err != nil {
			return nil, err
		}
		ext := ".p12"
		if id == "pfx" {
			ext = ".pfx"
		}
		return &Output{b.Name + ext, p12Type, data}, nil
	case "combined":
		k, err := pkcs8PEM(b.Key)
		if err != nil {
			return nil, err
		}
		return &Output{b.Name + ".combined.pem", pemType, append(k, pemCerts(full...)...)}, nil
	case "key":
		k, err := pkcs8PEM(b.Key)
		return &Output{b.Name + ".key", pemType, k}, err
	case "key-traditional":
		k, err := traditionalPEM(b.Key)
		return &Output{b.Name + ".key", pemType, k}, err
	case "key-encrypted":
		block, err := pemutil.Serialize(b.Key, pemutil.WithPKCS8(true), pemutil.WithPassword([]byte(password)))
		if err != nil {
			return nil, err
		}
		return &Output{b.Name + ".encrypted.key", pemType, pem.EncodeToMemory(block)}, nil
	case "zip":
		k, err := pkcs8PEM(b.Key)
		if err != nil {
			return nil, err
		}
		var buf bytes.Buffer
		zw := zip.NewWriter(&buf)
		files := []struct {
			name string
			data []byte
		}{
			{"cert.crt", pemCerts(b.Leaf)},
			{"chain.pem", pemCerts(b.Chain...)},
			{"fullchain.pem", pemCerts(full...)},
			{"key.pem", k},
		}
		if b.Root != nil {
			files = append(files, struct {
				name string
				data []byte
			}{"root.crt", pemCerts(b.Root)})
		}
		for _, f := range files {
			w, err := zw.Create(b.Name + "/" + f.name)
			if err != nil {
				return nil, err
			}
			w.Write(f.data)
		}
		if err := zw.Close(); err != nil {
			return nil, err
		}
		return &Output{b.Name + ".zip", "application/zip", buf.Bytes()}, nil
	}
	return nil, fmt.Errorf("format %q not implemented", id)
}
