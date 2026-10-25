package kube

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	cmfake "github.com/cert-manager/cert-manager/pkg/client/clientset/versioned/fake"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/jwil007/pki-portal/internal/csrutil"
)

func newFake() (*Kube, *cmfake.Clientset) {
	cm := cmfake.NewClientset()
	return NewWithClients("pki-managed", fake.NewClientset(), cm), cm
}

func TestCreateManagedAndList(t *testing.T) {
	ctx := context.Background()
	k, cm := newFake()
	id := NewID("fw.wilsonfi.dev")
	if err := k.CreateManaged(ctx, id, []string{"fw.wilsonfi.dev"}, "letsencrypt-staging", true, "rsa2048"); err != nil {
		t.Fatal(err)
	}
	crt, err := cm.CertmanagerV1().Certificates("pki-managed").Get(ctx, id, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if crt.Labels[LabelManagedBy] != "pki-portal" || crt.Labels[LabelCertID] != id || crt.Spec.SecretTemplate.Labels[LabelCertID] != id {
		t.Errorf("labels not set: %v", crt.Labels)
	}
	if crt.Spec.PrivateKey.Algorithm != cmapi.RSAKeyAlgorithm || crt.Spec.PrivateKey.Size != 2048 || crt.Spec.CommonName != "fw.wilsonfi.dev" {
		t.Errorf("bad spec %+v", crt.Spec)
	}

	// An unmanaged request plus a cert-manager-created CR for the managed cert (must not be listed twice).
	_, csrPEM, _ := csrutil.Generate(csrutil.ECDSA256, []string{"vpn.wilsonfi.dev"})
	if err := k.CreateRequest(ctx, "vpn-x", csrPEM, "step-ca-acme", false, Unmanaged, "ecdsa256"); err != nil {
		t.Fatal(err)
	}
	cm.CertmanagerV1().CertificateRequests("pki-managed").Create(ctx, &cmapi.CertificateRequest{
		ObjectMeta: metav1.ObjectMeta{Name: id + "-1", Labels: labels(id, Managed)},
	}, metav1.CreateOptions{})

	certs, err := k.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(certs) != 2 {
		t.Fatalf("got %d certs, want 2", len(certs))
	}
	if d := FindDuplicate(certs, "letsencrypt-staging", []string{"fw.wilsonfi.dev"}); d == nil || d.ID != id {
		t.Errorf("duplicate not found")
	}
	if d := FindDuplicate(certs, "letsencrypt-prod", []string{"fw.wilsonfi.dev"}); d != nil {
		t.Errorf("duplicate across issuers")
	}
	got, err := k.Get(ctx, "vpn-x")
	if err != nil || got.Mode != Unmanaged || got.Names[0] != "vpn.wilsonfi.dev" || got.State != Issuing {
		t.Errorf("Get unmanaged = %+v, %v", got, err)
	}
	if _, err := k.Get(ctx, id+"-1"); err == nil {
		t.Error("managed CR should not be addressable as its own cert")
	}
}

func TestRenewAndState(t *testing.T) {
	ctx := context.Background()
	k, cm := newFake()
	k.CreateManaged(ctx, "a", []string{"a.wilsonfi.dev"}, "step-ca-acme", false, "ecdsa256")
	crt, _ := cm.CertmanagerV1().Certificates("pki-managed").Get(ctx, "a", metav1.GetOptions{})
	crt.Status.Conditions = []cmapi.CertificateCondition{{Type: cmapi.CertificateConditionReady, Status: cmmeta.ConditionTrue}}
	cm.CertmanagerV1().Certificates("pki-managed").UpdateStatus(ctx, crt, metav1.UpdateOptions{})

	c, _ := k.Get(ctx, "a")
	if c.State != Ready {
		t.Fatalf("state = %s", c.State)
	}
	if err := k.Renew(ctx, "a"); err != nil {
		t.Fatal(err)
	}
	c, _ = k.Get(ctx, "a")
	if c.State != Issuing {
		t.Errorf("after renew state = %s", c.State)
	}
	if err := k.Renew(ctx, "a"); err == nil {
		t.Error("double renew allowed")
	}
}

func TestExplain(t *testing.T) {
	got := Explain(`Waiting for DNS-01 challenge propagation: DNS record for "fw.wilsonfi.dev" not yet propagated`)
	if got == "" || got[:12] != "DNS-01 pendi" {
		t.Errorf("got %q", got)
	}
}

func TestSignedSecrets(t *testing.T) {
	ctx := context.Background()
	k, _ := newFake()
	root, chain := testChain(t, "nas.wilsonfi.dev")
	if err := k.SaveSigned(ctx, "nas-x", Managed, chain, []byte("key"), root, "rsa2048", 1); err != nil {
		t.Fatal(err)
	}
	if err := k.SaveSigned(ctx, "dev-y", FromCSR, chain, nil, root, "ecdsap-256", 1); err != nil {
		t.Fatal(err)
	}
	certs, _ := k.List(ctx)
	if len(certs) != 2 {
		t.Fatalf("listed %d", len(certs))
	}
	c, err := k.Get(ctx, "nas-x")
	if err != nil || c.Backend != BackendStepCA || c.State != Ready || c.Names[0] != "nas.wilsonfi.dev" || c.RenewalTime.IsZero() {
		t.Fatalf("Get = %+v, %v", c, err)
	}
	k.RecordError(ctx, "nas-x", "step-ca down")
	c, _ = k.Get(ctx, "nas-x")
	if c.State != Failed {
		t.Errorf("state after error = %s", c.State)
	}
	if err := k.SaveSigned(ctx, "nas-x", Managed, chain, []byte("key"), root, "rsa2048", 2); err != nil {
		t.Fatal(err)
	}
	c, _ = k.Get(ctx, "nas-x")
	if c.State != Ready || c.Revision != 2 {
		t.Errorf("after renewal state=%s rev=%d", c.State, c.Revision)
	}
	if err := k.Delete(ctx, c); err != nil {
		t.Fatal(err)
	}
	if _, err := k.Get(ctx, "nas-x"); err == nil {
		t.Error("still there after delete")
	}
}

func testChain(t *testing.T, name string) (*x509.Certificate, []byte) {
	t.Helper()
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caT := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Root"}, IsCA: true, BasicConstraintsValid: true,
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour), KeyUsage: x509.KeyUsageCertSign}
	caDER, _ := x509.CreateCertificate(rand.Reader, caT, caT, &caKey.PublicKey, caKey)
	ca, _ := x509.ParseCertificate(caDER)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	lT := &x509.Certificate{SerialNumber: big.NewInt(2), DNSNames: []string{name}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour)}
	der, _ := x509.CreateCertificate(rand.Reader, lT, ca, &key.PublicKey, caKey)
	return ca, append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})...)
}
