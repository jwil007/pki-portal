package kube

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"strconv"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Certificates signed directly by step-ca (no cert-manager object) are stored as
// one Secret each, in the same shape cert-manager uses: tls.crt, tls.key, ca.crt.
// Unmanaged and CSR certs get a Secret without tls.key, so the inventory has a record.

const (
	LabelBackend   = "pki.wilsonfi.dev/backend"
	BackendStepCA  = "step-ca"
	AnnRevision    = "pki.wilsonfi.dev/revision"
	AnnRenewedAt   = "pki.wilsonfi.dev/renewed-at"
	AnnLastError   = "pki.wilsonfi.dev/last-error"
	AnnProfile     = "pki.wilsonfi.dev/profile" // server | user | device
	AnnRevokedAt   = "pki.wilsonfi.dev/revoked-at"
	AnnRevokedWhy  = "pki.wilsonfi.dev/revoked-reason"
	StepCAIssuer   = "step-ca"
	backendCertMgr = "cert-manager"
)

// Signed is a step-ca signed certificate to store.
type Signed struct {
	ID       string
	Mode     Mode
	Profile  string // server | user | device; empty means server
	ChainPEM []byte
	KeyPEM   []byte // nil for unmanaged and CSR certs
	Root     *x509.Certificate
	KeyType  string
	Revision int
}

// SaveSigned creates or replaces the Secret for a step-ca signed certificate.
func (k *Kube) SaveSigned(ctx context.Context, sc Signed) error {
	id, mode, chainPEM, keyPEM, root, keyType, revision := sc.ID, sc.Mode, sc.ChainPEM, sc.KeyPEM, sc.Root, sc.KeyType, sc.Revision
	if sc.Profile == "" {
		sc.Profile = "server"
	}
	lbl := labels(id, mode)
	lbl[LabelBackend] = BackendStepCA
	s := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      id,
			Namespace: k.ns,
			Labels:    lbl,
			Annotations: map[string]string{
				AnnClass:    "internal",
				AnnKeyType:  keyType,
				AnnRevision: strconv.Itoa(revision),
				AnnProfile:  sc.Profile,
			},
		},
		Type: corev1.SecretTypeOpaque,
		Data: map[string][]byte{
			"tls.crt": chainPEM,
			"ca.crt":  pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: root.Raw}),
		},
	}
	if keyPEM != nil {
		s.Type = corev1.SecretTypeTLS
		s.Data["tls.key"] = keyPEM
	}
	if revision > 1 {
		s.Annotations[AnnRenewedAt] = time.Now().UTC().Format(time.RFC3339)
	}
	if revision == 1 {
		_, err := k.core.CoreV1().Secrets(k.ns).Create(ctx, s, metav1.CreateOptions{})
		return err
	}
	_, err := k.core.CoreV1().Secrets(k.ns).Update(ctx, s, metav1.UpdateOptions{})
	return err
}

// MarkRevoked records a revocation on the Secret and drops the private key,
// which is useless once the certificate is revoked.
func (k *Kube) MarkRevoked(ctx context.Context, id, reason string) error {
	s, err := k.core.CoreV1().Secrets(k.ns).Get(ctx, id, metav1.GetOptions{})
	if err != nil {
		return err
	}
	if s.Annotations == nil {
		s.Annotations = map[string]string{}
	}
	s.Annotations[AnnRevokedAt] = time.Now().UTC().Format(time.RFC3339)
	s.Annotations[AnnRevokedWhy] = reason
	if _, ok := s.Data["tls.key"]; ok {
		s.Data["tls.key"] = []byte{} // kubernetes.io/tls Secrets must keep the key, so empty it
	}
	_, err = k.core.CoreV1().Secrets(k.ns).Update(ctx, s, metav1.UpdateOptions{})
	return err
}

// RecordError notes a failed renewal on the Secret so the UI can show it.
func (k *Kube) RecordError(ctx context.Context, id string, msg string) error {
	s, err := k.core.CoreV1().Secrets(k.ns).Get(ctx, id, metav1.GetOptions{})
	if err != nil {
		return err
	}
	if s.Annotations == nil {
		s.Annotations = map[string]string{}
	}
	s.Annotations[AnnLastError] = msg
	_, err = k.core.CoreV1().Secrets(k.ns).Update(ctx, s, metav1.UpdateOptions{})
	return err
}

func (k *Kube) getSigned(ctx context.Context, id string) (*Cert, *corev1.Secret, error) {
	s, err := k.core.CoreV1().Secrets(k.ns).Get(ctx, id, metav1.GetOptions{})
	if err != nil {
		return nil, nil, err
	}
	if s.Labels[LabelManagedBy] != managedBy || s.Labels[LabelBackend] != BackendStepCA {
		return nil, nil, apierrors.NewNotFound(corev1.Resource("secret"), id)
	}
	return fromSecret(s), s, nil
}

func fromSecret(s *corev1.Secret) *Cert {
	c := &Cert{
		ID:      s.Name,
		Mode:    Mode(s.Labels[LabelMode]),
		Backend: BackendStepCA,
		Issuer:  StepCAIssuer,
		KeyType: s.Annotations[AnnKeyType],
		Created: s.CreationTimestamp.Time,
		State:   Ready,
		Message: s.Annotations[AnnLastError],
		Profile: s.Annotations[AnnProfile],
	}
	if c.Profile == "" {
		c.Profile = "server"
	}
	c.Revision, _ = strconv.Atoi(s.Annotations[AnnRevision])
	if t, err := time.Parse(time.RFC3339, s.Annotations[AnnRenewedAt]); err == nil {
		c.RenewedAt = t
	}
	if chain := ParseChain(s.Data["tls.crt"]); len(chain) > 0 {
		c.Leaf, c.Chain = chain[0], chain[1:]
		if c.Profile == "user" {
			c.Names = append(c.Names, c.Leaf.Subject.CommonName)
		}
		c.Names = append(c.Names, c.Leaf.DNSNames...)
		for _, ip := range c.Leaf.IPAddresses {
			c.Names = append(c.Names, ip.String())
		}
		c.Names = append(c.Names, c.Leaf.EmailAddresses...)
		if len(c.Names) == 0 {
			c.Names = []string{c.Leaf.Subject.CommonName}
		}
		if c.Mode == Managed {
			c.RenewalTime = RenewAt(c.Leaf)
		}
	}
	if c.Message != "" {
		c.State = Failed
	}
	if t, err := time.Parse(time.RFC3339, s.Annotations[AnnRevokedAt]); err == nil {
		c.RevokedAt, c.RevokedReason = t, s.Annotations[AnnRevokedWhy]
	}
	if c.Leaf == nil {
		c.State = Failed
	} else if time.Now().After(c.Leaf.NotAfter) {
		c.State = Expired
	}
	if !c.RevokedAt.IsZero() {
		c.State = Revoked
	}
	return c
}

// RenewAt is two-thirds of the way through the certificate's lifetime.
func RenewAt(leaf *x509.Certificate) time.Time {
	life := leaf.NotAfter.Sub(leaf.NotBefore)
	return leaf.NotBefore.Add(life * 2 / 3)
}
