// Package internalca issues, renews and revokes internal certificates signed
// directly by step-ca (no ACME, no DNS records), storing them as Secrets in the
// portal namespace.
package internalca

import (
	"context"
	"crypto"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jwil007/pki-portal/internal/csrutil"
	"github.com/jwil007/pki-portal/internal/kube"
	"github.com/jwil007/pki-portal/internal/stepca"
)

type Issuer struct {
	kube     *kube.Kube
	ca       *stepca.Client // server provisioner (name policy enforced by step-ca)
	clients  *stepca.Client // client provisioner for EAP-TLS user/device certs; may be nil
	lifetime time.Duration  // 0 = provisioner default
}

func New(k *kube.Kube, ca, clients *stepca.Client, lifetime time.Duration) *Issuer {
	return &Issuer{kube: k, ca: ca, clients: clients, lifetime: lifetime}
}

func (i *Issuer) Health(ctx context.Context) error { return i.ca.Health(ctx) }

// ClientsEnabled reports whether EAP-TLS client certificates can be issued.
func (i *Issuer) ClientsEnabled() bool { return i.clients != nil }

// Request describes a certificate to issue. SANs may mix DNS names, IPs and emails.
type Request struct {
	ID      string
	Profile string // server | user | device
	Subject string // CN
	SANs    []string
	KeyType string
	Mode    kube.Mode
}

func (i *Issuer) client(profile string) (*stepca.Client, error) {
	if profile == "user" || profile == "device" {
		if i.clients == nil {
			return nil, errors.New("client certificates aren't enabled (no client provisioner configured)")
		}
		return i.clients, nil
	}
	return i.ca, nil
}

func (i *Issuer) sign(ctx context.Context, r Request) (crypto.Signer, []byte, error) {
	ca, err := i.client(r.Profile)
	if err != nil {
		return nil, nil, err
	}
	key, csrPEM, err := csrutil.GenerateFor(csrutil.KeyType(r.KeyType), r.Subject, r.SANs)
	if err != nil {
		return nil, nil, err
	}
	chain, err := ca.Sign(ctx, csrPEM, r.Subject, r.SANs, i.lifetime)
	if err != nil {
		return nil, nil, err
	}
	return key, chain, nil
}

// Issue generates a key, has step-ca sign it, and records the cert. Managed certs
// keep the key in their Secret; for unmanaged ones the caller holds the returned key.
func (i *Issuer) Issue(ctx context.Context, r Request) (crypto.Signer, error) {
	key, chain, err := i.sign(ctx, r)
	if err != nil {
		return nil, err
	}
	var keyPEM []byte
	if r.Mode == kube.Managed {
		if keyPEM, err = csrutil.KeyPEM(key); err != nil {
			return nil, err
		}
	}
	err = i.kube.SaveSigned(ctx, kube.Signed{ID: r.ID, Mode: r.Mode, Profile: r.Profile, ChainPEM: chain,
		KeyPEM: keyPEM, Root: i.ca.Root(), KeyType: r.KeyType, Revision: 1})
	if err != nil {
		return nil, fmt.Errorf("saving certificate: %w", err)
	}
	return key, nil
}

// IssueServer is the common case: DNS names and IPs, first name as CN.
func (i *Issuer) IssueServer(ctx context.Context, id string, names []string, keyType string, mode kube.Mode) (crypto.Signer, error) {
	return i.Issue(ctx, Request{ID: id, Profile: "server", Subject: names[0], SANs: names, KeyType: keyType, Mode: mode})
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
	return i.kube.SaveSigned(ctx, kube.Signed{ID: id, Mode: kube.FromCSR, ChainPEM: chain, Root: i.ca.Root(), KeyType: keyType, Revision: 1})
}

// Renew re-issues a managed internal cert with a fresh key, the same subject and SANs.
func (i *Issuer) Renew(ctx context.Context, c *kube.Cert) error {
	if c.Backend != kube.BackendStepCA || c.Mode != kube.Managed || c.Leaf == nil {
		return fmt.Errorf("%s is not a managed internal certificate", c.ID)
	}
	if c.State == kube.Revoked {
		return fmt.Errorf("%s is revoked", c.ID)
	}
	keyType := c.KeyType
	if keyType == "" {
		keyType = string(csrutil.RSA2048)
	}
	r := Request{ID: c.ID, Profile: c.Profile, Subject: c.Leaf.Subject.CommonName, SANs: leafSANs(c), KeyType: keyType, Mode: kube.Managed}
	key, chain, err := i.sign(ctx, r)
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
	return i.kube.SaveSigned(ctx, kube.Signed{ID: c.ID, Mode: kube.Managed, Profile: c.Profile, ChainPEM: chain,
		KeyPEM: keyPEM, Root: i.ca.Root(), KeyType: keyType, Revision: max(c.Revision, 1) + 1})
}

func leafSANs(c *kube.Cert) []string {
	var out []string
	out = append(out, c.Leaf.DNSNames...)
	for _, ip := range c.Leaf.IPAddresses {
		out = append(out, ip.String())
	}
	out = append(out, c.Leaf.EmailAddresses...)
	return out
}

// Revocation reasons offered in the UI (RFC 5280 codes).
var Reasons = []struct {
	Code  int
	Label string
}{
	{0, "Unspecified"},
	{1, "Key compromise"},
	{3, "Affiliation changed (user left, device reassigned)"},
	{4, "Superseded (replaced by a new certificate)"},
	{5, "Cessation of operation (device retired)"},
}

func reasonLabel(code int) string {
	for _, r := range Reasons {
		if r.Code == code {
			return r.Label
		}
	}
	return "Unspecified"
}

// Revoke revokes a step-ca certificate (it appears on step-ca's CRL), stops
// renewal and drops the stored key.
func (i *Issuer) Revoke(ctx context.Context, c *kube.Cert, code int, note string) error {
	if c.Backend != kube.BackendStepCA || c.Leaf == nil {
		return errors.New("only certificates signed directly by step-ca can be revoked here")
	}
	if c.State == kube.Revoked {
		return errors.New("already revoked")
	}
	reason := reasonLabel(code)
	if note = strings.TrimSpace(note); note != "" {
		reason += ": " + note
	}
	if err := i.ca.Revoke(ctx, c.Leaf.SerialNumber, code, reason); err != nil {
		return err
	}
	return i.kube.MarkRevoked(ctx, c.ID, reason)
}

// CRL returns step-ca's current CRL (DER) or stepca.ErrNoCRL.
func (i *Issuer) CRL(ctx context.Context) ([]byte, error) { return i.ca.CRL(ctx) }

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
		if c.Backend != kube.BackendStepCA || c.Mode != kube.Managed || c.Leaf == nil || c.State == kube.Revoked {
			continue
		}
		if time.Now().Before(kube.RenewAt(c.Leaf)) {
			continue
		}
		out = append(out, Result{ID: c.ID, Err: i.Renew(ctx, c)})
	}
	return out, nil
}
