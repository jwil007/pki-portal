// Package internalca issues and renews internal certificates signed directly by
// step-ca (no ACME, no DNS records), storing them as Secrets in the portal namespace.
package internalca

import (
	"context"
	"crypto"
	"fmt"
	"time"

	"github.com/jwil007/pki-portal/internal/csrutil"
	"github.com/jwil007/pki-portal/internal/kube"
	"github.com/jwil007/pki-portal/internal/stepca"
)

type Issuer struct {
	kube     *kube.Kube
	ca       *stepca.Client
	lifetime time.Duration // 0 = provisioner default
}

func New(k *kube.Kube, ca *stepca.Client, lifetime time.Duration) *Issuer {
	return &Issuer{kube: k, ca: ca, lifetime: lifetime}
}

func (i *Issuer) Health(ctx context.Context) error { return i.ca.Health(ctx) }

func (i *Issuer) sign(ctx context.Context, keyType string, names []string) (crypto.Signer, []byte, error) {
	key, csrPEM, err := csrutil.Generate(csrutil.KeyType(keyType), names)
	if err != nil {
		return nil, nil, err
	}
	chain, err := i.ca.Sign(ctx, csrPEM, names[0], names, i.lifetime)
	if err != nil {
		return nil, nil, err
	}
	return key, chain, nil
}

// Issue generates a key, has step-ca sign it, and records the cert. Managed certs
// keep the key in their Secret; for unmanaged ones the caller holds the returned key.
func (i *Issuer) Issue(ctx context.Context, id string, names []string, keyType string, mode kube.Mode) (crypto.Signer, error) {
	key, chain, err := i.sign(ctx, keyType, names)
	if err != nil {
		return nil, err
	}
	var keyPEM []byte
	if mode == kube.Managed {
		if keyPEM, err = csrutil.KeyPEM(key); err != nil {
			return nil, err
		}
	}
	if err := i.kube.SaveSigned(ctx, id, mode, chain, keyPEM, i.ca.Root(), keyType, 1); err != nil {
		return nil, fmt.Errorf("saving certificate: %w", err)
	}
	return key, nil
}

// SignCSR signs an uploaded CSR; the key never reaches the portal.
func (i *Issuer) SignCSR(ctx context.Context, id string, info *csrutil.Info, keyType string) error {
	sans := info.SANs()
	subject := info.CN
	if subject == "" && len(sans) > 0 {
		subject = sans[0]
	}
	if len(sans) == 0 {
		sans = []string{subject}
	}
	chain, err := i.ca.Sign(ctx, info.PEM, subject, sans, i.lifetime)
	if err != nil {
		return err
	}
	return i.kube.SaveSigned(ctx, id, kube.FromCSR, chain, nil, i.ca.Root(), keyType, 1)
}

// Renew re-issues a managed internal cert with a fresh key and the same names.
func (i *Issuer) Renew(ctx context.Context, c *kube.Cert) error {
	if c.Backend != kube.BackendStepCA || c.Mode != kube.Managed {
		return fmt.Errorf("%s is not a managed internal certificate", c.ID)
	}
	keyType := c.KeyType
	if keyType == "" {
		keyType = string(csrutil.RSA2048)
	}
	key, chain, err := i.sign(ctx, keyType, c.Names)
	if err != nil {
		if rerr := i.kube.RecordError(ctx, c.ID, err.Error()); rerr != nil {
			return fmt.Errorf("%w (and recording the error failed: %v)", err, rerr)
		}
		return err
	}
	keyPEM, err := csrutil.KeyPEM(key)
	if err != nil {
		return err
	}
	return i.kube.SaveSigned(ctx, c.ID, kube.Managed, chain, keyPEM, i.ca.Root(), keyType, max(c.Revision, 1)+1)
}

// Result reports one renewal attempt from RenewDue.
type Result struct {
	ID  string
	Err error
}

// RenewDue renews every managed internal cert past two-thirds of its lifetime.
func (i *Issuer) RenewDue(ctx context.Context) ([]Result, error) {
	certs, err := i.kube.List(ctx)
	if err != nil {
		return nil, err
	}
	var out []Result
	for _, c := range certs {
		if c.Backend != kube.BackendStepCA || c.Mode != kube.Managed || c.Leaf == nil {
			continue
		}
		if time.Now().Before(kube.RenewAt(c.Leaf)) {
			continue
		}
		out = append(out, Result{ID: c.ID, Err: i.Renew(ctx, c)})
	}
	return out, nil
}
