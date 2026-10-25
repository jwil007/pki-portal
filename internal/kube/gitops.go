package kube

import (
	"context"
	"crypto/x509"
	"errors"
	"sort"
	"time"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// GitOpsCert is a read-only view of a cert-manager Certificate the portal
// doesn't own (e.g. the ClearPass certs in namespace pki, managed in Git).
type GitOpsCert struct {
	Name        string
	Namespace   string
	Issuer      string
	DNSNames    []string
	Ready       bool
	Message     string
	RenewalTime time.Time
	Revision    int
	SecretName  string
	Leaf        *x509.Certificate
	Chain       []*x509.Certificate
	HasKey      bool
	HasP12      bool
	P12Password *cmmeta.SecretKeySelector // where cert-manager reads the keystore password
	SecretError string                    // set when the Secret isn't readable (RBAC)
}

func (c *GitOpsCert) Serial() string {
	return (&Cert{Leaf: c.Leaf}).Serial()
}

func (c *GitOpsCert) DaysLeft() int { return (&Cert{Leaf: c.Leaf}).DaysLeft() }

// GitOpsCerts lists every Certificate in namespace ns, with what the portal can
// read of each Secret. It never modifies anything there.
func (k *Kube) GitOpsCerts(ctx context.Context, ns string) ([]*GitOpsCert, error) {
	crts, err := k.cm.CertmanagerV1().Certificates(ns).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	var out []*GitOpsCert
	for i := range crts.Items {
		crt := &crts.Items[i]
		g := &GitOpsCert{
			Name: crt.Name, Namespace: ns, Issuer: crt.Spec.IssuerRef.Name,
			DNSNames: crt.Spec.DNSNames, SecretName: crt.Spec.SecretName,
		}
		if r := condition(crt.Status.Conditions, cmapi.CertificateConditionReady); r != nil {
			g.Ready, g.Message = r.Status == cmmeta.ConditionTrue, r.Message
		}
		if crt.Status.RenewalTime != nil {
			g.RenewalTime = crt.Status.RenewalTime.Time
		}
		if crt.Status.Revision != nil {
			g.Revision = *crt.Status.Revision
		}
		if ks := crt.Spec.Keystores; ks != nil && ks.PKCS12 != nil && ks.PKCS12.Create {
			g.P12Password = ks.PKCS12.PasswordSecretRef.DeepCopy()
		}
		data, err := k.GitOpsSecret(ctx, ns, crt.Spec.SecretName)
		if err != nil {
			g.SecretError = err.Error()
		} else {
			if chain := ParseChain(data["tls.crt"]); len(chain) > 0 {
				g.Leaf, g.Chain = chain[0], chain[1:]
			}
			g.HasKey = len(data["tls.key"]) > 0
			g.HasP12 = len(data["keystore.p12"]) > 0
		}
		out = append(out, g)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// GitOpsCert returns one Certificate by name.
func (k *Kube) GitOpsCert(ctx context.Context, ns, name string) (*GitOpsCert, error) {
	all, err := k.GitOpsCerts(ctx, ns)
	if err != nil {
		return nil, err
	}
	for _, g := range all {
		if g.Name == name {
			return g, nil
		}
	}
	return nil, errors.New("certificate not found")
}

// GitOpsSecret reads one Secret in a namespace the portal only has get access to.
func (k *Kube) GitOpsSecret(ctx context.Context, ns, name string) (map[string][]byte, error) {
	s, err := k.core.CoreV1().Secrets(ns).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}
	return s.Data, nil
}
