// Package kube talks to Kubernetes and cert-manager. Certificates and keys live
// in the portal namespace (pki-managed); nothing here caches key material.
package kube

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	cmclient "github.com/cert-manager/cert-manager/pkg/client/clientset/versioned"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

const (
	LabelManagedBy = "app.kubernetes.io/managed-by"
	LabelCertID    = "pki.wilsonfi.dev/cert-id"
	LabelMode      = "pki.wilsonfi.dev/mode"
	AnnClass       = "pki.wilsonfi.dev/class" // public | internal
	AnnKeyType     = "pki.wilsonfi.dev/key-type"
	managedBy      = "pki-portal"
)

type Mode string

const (
	Managed   Mode = "managed"   // cert-manager Certificate, key in a Secret, auto-renews
	Unmanaged Mode = "unmanaged" // portal-generated key held in memory, issue-and-forget
	FromCSR   Mode = "csr"       // uploaded CSR, key never seen
)

type State string

const (
	Ready   State = "ready"
	Issuing State = "issuing"
	Failed  State = "failed"
	Expired State = "expired"
)

// Cert is the portal's view of one certificate, whatever object backs it.
type Cert struct {
	ID          string
	Mode        Mode
	Backend     string // cert-manager | step-ca
	Issuer      string
	Public      bool
	Names       []string
	KeyType     string
	State       State
	Message     string
	Created     time.Time
	Revision    int
	RenewalTime time.Time
	RenewedAt   time.Time
	Leaf        *x509.Certificate
	Chain       []*x509.Certificate // intermediates, as returned by the issuer
}

func (c *Cert) Fingerprint() string {
	if c.Leaf == nil {
		return ""
	}
	sum := sha256.Sum256(c.Leaf.Raw)
	return strings.ToUpper(hex.EncodeToString(sum[:]))
}

func (c *Cert) Serial() string {
	if c.Leaf == nil {
		return ""
	}
	return strings.ToUpper(c.Leaf.SerialNumber.Text(16))
}

func (c *Cert) Class() string {
	if c.Public {
		return "public"
	}
	return "internal"
}

// DaysLeft is negative once expired; 0 with no cert yet.
func (c *Cert) DaysLeft() int {
	if c.Leaf == nil {
		return 0
	}
	return int(time.Until(c.Leaf.NotAfter).Hours() / 24)
}

type Kube struct {
	ns   string
	core kubernetes.Interface
	cm   cmclient.Interface
}

// New uses in-cluster config when running in a pod, otherwise $KUBECONFIG or ~/.kube/config.
func New(namespace string) (*Kube, error) {
	cfg, err := rest.InClusterConfig()
	if err != nil {
		path := os.Getenv("KUBECONFIG")
		if path == "" {
			home, _ := os.UserHomeDir()
			path = filepath.Join(home, ".kube", "config")
		}
		cfg, err = clientcmd.BuildConfigFromFlags("", path)
		if err != nil {
			return nil, fmt.Errorf("no in-cluster config and can't load kubeconfig: %w", err)
		}
	}
	core, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return nil, err
	}
	cm, err := cmclient.NewForConfig(cfg)
	if err != nil {
		return nil, err
	}
	return NewWithClients(namespace, core, cm), nil
}

func NewWithClients(ns string, core kubernetes.Interface, cm cmclient.Interface) *Kube {
	return &Kube{ns: ns, core: core, cm: cm}
}

func (k *Kube) Namespace() string { return k.ns }

var slugRe = regexp.MustCompile(`[^a-z0-9]+`)

// NewID builds a readable, unique object name from the first DNS name.
func NewID(firstName string) string {
	s := strings.Replace(strings.ToLower(firstName), "*.", "wildcard.", 1)
	s = strings.Trim(slugRe.ReplaceAllString(s, "-"), "-")
	if len(s) > 40 {
		s = strings.Trim(s[:40], "-")
	}
	const alphabet = "abcdefghijkmnpqrstuvwxyz23456789"
	b := make([]byte, 5)
	for i := range b {
		n, _ := rand.Int(rand.Reader, big.NewInt(int64(len(alphabet))))
		b[i] = alphabet[n.Int64()]
	}
	return s + "-" + string(b)
}

func labels(id string, mode Mode) map[string]string {
	return map[string]string{LabelManagedBy: managedBy, LabelCertID: id, LabelMode: string(mode)}
}

func class(public bool) string {
	if public {
		return "public"
	}
	return "internal"
}

func issuerRef(name string) cmmeta.IssuerReference {
	return cmmeta.IssuerReference{Name: name, Kind: "ClusterIssuer", Group: "cert-manager.io"}
}

// CreateManaged creates a cert-manager Certificate; cert-manager owns issuance and renewal.
func (k *Kube) CreateManaged(ctx context.Context, id string, names []string, issuer string, public bool, keyType string) error {
	pk := &cmapi.CertificatePrivateKey{RotationPolicy: cmapi.RotationPolicyAlways}
	if keyType == "ecdsa256" {
		pk.Algorithm, pk.Size = cmapi.ECDSAKeyAlgorithm, 256
	} else {
		pk.Algorithm, pk.Size = cmapi.RSAKeyAlgorithm, 2048
	}
	history := int32(10)
	crt := &cmapi.Certificate{
		ObjectMeta: metav1.ObjectMeta{
			Name:        id,
			Namespace:   k.ns,
			Labels:      labels(id, Managed),
			Annotations: map[string]string{AnnClass: class(public), AnnKeyType: keyType},
		},
		Spec: cmapi.CertificateSpec{
			SecretName:           id + "-tls",
			DNSNames:             names,
			IssuerRef:            issuerRef(issuer),
			PrivateKey:           pk,
			RevisionHistoryLimit: &history,
			SecretTemplate:       &cmapi.CertificateSecretTemplate{Labels: labels(id, Managed)},
		},
	}
	// Appliances often still look at the CN; ACME requires it to fit in 64 bytes.
	if len(names[0]) <= 64 {
		crt.Spec.CommonName = names[0]
	}
	_, err := k.cm.CertmanagerV1().Certificates(k.ns).Create(ctx, crt, metav1.CreateOptions{})
	return err
}

// CreateRequest submits a CSR as a CertificateRequest (unmanaged or uploaded CSR).
func (k *Kube) CreateRequest(ctx context.Context, id string, csrPEM []byte, issuer string, public bool, mode Mode, keyType string) error {
	cr := &cmapi.CertificateRequest{
		ObjectMeta: metav1.ObjectMeta{
			Name:        id,
			Namespace:   k.ns,
			Labels:      labels(id, mode),
			Annotations: map[string]string{AnnClass: class(public), AnnKeyType: keyType},
		},
		Spec: cmapi.CertificateRequestSpec{
			Request:   csrPEM,
			IssuerRef: issuerRef(issuer),
			Usages:    []cmapi.KeyUsage{cmapi.UsageDigitalSignature, cmapi.UsageKeyEncipherment, cmapi.UsageServerAuth},
		},
	}
	_, err := k.cm.CertmanagerV1().CertificateRequests(k.ns).Create(ctx, cr, metav1.CreateOptions{})
	return err
}

func selector(extra string) string {
	s := LabelManagedBy + "=" + managedBy
	if extra != "" {
		s += "," + extra
	}
	return s
}

// List returns every portal certificate, newest first.
func (k *Kube) List(ctx context.Context) ([]*Cert, error) {
	crts, err := k.cm.CertmanagerV1().Certificates(k.ns).List(ctx, metav1.ListOptions{LabelSelector: selector(LabelMode + "=managed")})
	if err != nil {
		return nil, err
	}
	secrets, err := k.core.CoreV1().Secrets(k.ns).List(ctx, metav1.ListOptions{LabelSelector: selector("")})
	if err != nil {
		return nil, err
	}
	tlsBySecret := map[string][]byte{}
	for _, s := range secrets.Items {
		tlsBySecret[s.Name] = s.Data["tls.crt"]
	}
	crs, err := k.cm.CertmanagerV1().CertificateRequests(k.ns).List(ctx, metav1.ListOptions{LabelSelector: selector(LabelMode + " in (unmanaged,csr)")})
	if err != nil {
		return nil, err
	}
	var out []*Cert
	for i := range crts.Items {
		out = append(out, fromCertificate(&crts.Items[i], tlsBySecret[crts.Items[i].Spec.SecretName]))
	}
	for i := range secrets.Items {
		if secrets.Items[i].Labels[LabelBackend] == BackendStepCA {
			out = append(out, fromSecret(&secrets.Items[i]))
		}
	}
	for i := range crs.Items {
		out = append(out, fromRequest(&crs.Items[i]))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Created.After(out[j].Created) })
	return out, nil
}

// Get finds a certificate by ID, as either a Certificate or a CertificateRequest.
func (k *Kube) Get(ctx context.Context, id string) (*Cert, error) {
	crt, err := k.cm.CertmanagerV1().Certificates(k.ns).Get(ctx, id, metav1.GetOptions{})
	if err == nil && crt.Labels[LabelManagedBy] == managedBy {
		var tls []byte
		if s, err := k.core.CoreV1().Secrets(k.ns).Get(ctx, crt.Spec.SecretName, metav1.GetOptions{}); err == nil {
			tls = s.Data["tls.crt"]
		}
		return fromCertificate(crt, tls), nil
	}
	if err != nil && !apierrors.IsNotFound(err) {
		return nil, err
	}
	if c, _, err := k.getSigned(ctx, id); err == nil {
		return c, nil
	} else if !apierrors.IsNotFound(err) {
		return nil, err
	}
	cr, err := k.cm.CertmanagerV1().CertificateRequests(k.ns).Get(ctx, id, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}
	if cr.Labels[LabelManagedBy] != managedBy || Mode(cr.Labels[LabelMode]) == Managed {
		return nil, apierrors.NewNotFound(cmapi.Resource("certificaterequest"), id)
	}
	return fromRequest(cr), nil
}

func fromCertificate(crt *cmapi.Certificate, tlsCrt []byte) *Cert {
	c := &Cert{
		ID:      crt.Name,
		Mode:    Managed,
		Backend: backendCertMgr,
		Issuer:  crt.Spec.IssuerRef.Name,
		Public:  crt.Annotations[AnnClass] == "public",
		Names:   crt.Spec.DNSNames,
		KeyType: crt.Annotations[AnnKeyType],
		Created: crt.CreationTimestamp.Time,
	}
	if crt.Status.Revision != nil {
		c.Revision = *crt.Status.Revision
	}
	if crt.Status.RenewalTime != nil {
		c.RenewalTime = crt.Status.RenewalTime.Time
	}
	if chain := ParseChain(tlsCrt); len(chain) > 0 {
		c.Leaf, c.Chain = chain[0], chain[1:]
	}
	ready := condition(crt.Status.Conditions, cmapi.CertificateConditionReady)
	issuing := condition(crt.Status.Conditions, cmapi.CertificateConditionIssuing)
	switch {
	case issuing != nil && issuing.Status == cmmeta.ConditionTrue:
		c.State, c.Message = Issuing, issuing.Message
	case ready != nil && ready.Status == cmmeta.ConditionTrue:
		c.State = Ready
	case crt.Status.LastFailureTime != nil:
		c.State = Failed
		if ready != nil {
			c.Message = ready.Message
		}
	default:
		c.State = Issuing
	}
	if issuing != nil && crt.Status.LastFailureTime != nil && c.State == Issuing {
		// cert-manager keeps Issuing=True between retries; surface it as a failure.
		c.State = Failed
	}
	if c.Leaf != nil && time.Now().After(c.Leaf.NotAfter) {
		c.State = Expired
	}
	return c
}

func condition(conds []cmapi.CertificateCondition, t cmapi.CertificateConditionType) *cmapi.CertificateCondition {
	for i := range conds {
		if conds[i].Type == t {
			return &conds[i]
		}
	}
	return nil
}

func requestCondition(cr *cmapi.CertificateRequest, t cmapi.CertificateRequestConditionType) *cmapi.CertificateRequestCondition {
	for i := range cr.Status.Conditions {
		if cr.Status.Conditions[i].Type == t {
			return &cr.Status.Conditions[i]
		}
	}
	return nil
}

func fromRequest(cr *cmapi.CertificateRequest) *Cert {
	c := &Cert{
		ID:      cr.Name,
		Mode:    Mode(cr.Labels[LabelMode]),
		Backend: backendCertMgr,
		Issuer:  cr.Spec.IssuerRef.Name,
		Public:  cr.Annotations[AnnClass] == "public",
		KeyType: cr.Annotations[AnnKeyType],
		Created: cr.CreationTimestamp.Time,
		State:   Issuing,
	}
	if block, _ := pem.Decode(cr.Spec.Request); block != nil {
		if csr, err := x509.ParseCertificateRequest(block.Bytes); err == nil {
			c.Names = csr.DNSNames
			if cn := strings.ToLower(csr.Subject.CommonName); cn != "" && !slices.Contains(c.Names, cn) {
				c.Names = append([]string{cn}, c.Names...)
			}
		}
	}
	if chain := ParseChain(cr.Status.Certificate); len(chain) > 0 {
		c.Leaf, c.Chain = chain[0], chain[1:]
	}
	if r := requestCondition(cr, cmapi.CertificateRequestConditionReady); r != nil {
		switch {
		case r.Status == cmmeta.ConditionTrue:
			c.State = Ready
		case r.Reason == cmapi.CertificateRequestReasonFailed || r.Reason == cmapi.CertificateRequestReasonDenied:
			c.State, c.Message = Failed, r.Message
		default:
			c.Message = r.Message
		}
	}
	if d := requestCondition(cr, cmapi.CertificateRequestConditionDenied); d != nil && d.Status == cmmeta.ConditionTrue {
		c.State, c.Message = Failed, "Request denied: "+d.Message
	}
	if c.Leaf != nil && time.Now().After(c.Leaf.NotAfter) {
		c.State = Expired
	}
	return c
}

// ParseChain decodes every CERTIFICATE block in a PEM bundle.
func ParseChain(data []byte) []*x509.Certificate {
	var out []*x509.Certificate
	for {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			return out
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		if c, err := x509.ParseCertificate(block.Bytes); err == nil {
			out = append(out, c)
		}
	}
}

// Key loads the private key of a managed certificate from its Secret.
func (k *Kube) Key(ctx context.Context, c *Cert) (crypto.Signer, error) {
	if c.Backend == BackendStepCA {
		_, s, err := k.getSigned(ctx, c.ID)
		if err != nil {
			return nil, err
		}
		return ParseKey(s.Data["tls.key"])
	}
	crt, err := k.cm.CertmanagerV1().Certificates(k.ns).Get(ctx, c.ID, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}
	if crt.Labels[LabelManagedBy] != managedBy {
		return nil, errors.New("not a portal certificate")
	}
	s, err := k.core.CoreV1().Secrets(k.ns).Get(ctx, crt.Spec.SecretName, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}
	return ParseKey(s.Data["tls.key"])
}

// ParseKey accepts PKCS#1, SEC1 and PKCS#8 PEM keys.
func ParseKey(data []byte) (crypto.Signer, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("no key in secret")
	}
	if k, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return k, nil
	}
	if k, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		return k, nil
	}
	k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	s, ok := k.(crypto.Signer)
	if !ok {
		return nil, errors.New("unsupported key type")
	}
	return s, nil
}

// Delete removes the Certificate (and its Secret) or the CertificateRequest.
func (k *Kube) Delete(ctx context.Context, c *Cert) error {
	if c.Backend == BackendStepCA {
		return k.core.CoreV1().Secrets(k.ns).Delete(ctx, c.ID, metav1.DeleteOptions{})
	}
	if c.Mode == Managed {
		crt, err := k.cm.CertmanagerV1().Certificates(k.ns).Get(ctx, c.ID, metav1.GetOptions{})
		if err != nil {
			return err
		}
		if err := k.cm.CertmanagerV1().Certificates(k.ns).Delete(ctx, c.ID, metav1.DeleteOptions{}); err != nil {
			return err
		}
		err = k.core.CoreV1().Secrets(k.ns).Delete(ctx, crt.Spec.SecretName, metav1.DeleteOptions{})
		if err != nil && !apierrors.IsNotFound(err) {
			return err
		}
		return nil
	}
	return k.cm.CertmanagerV1().CertificateRequests(k.ns).Delete(ctx, c.ID, metav1.DeleteOptions{})
}

// Renew asks cert-manager to re-issue now, the same way `cmctl renew` does.
func (k *Kube) Renew(ctx context.Context, id string) error {
	crt, err := k.cm.CertmanagerV1().Certificates(k.ns).Get(ctx, id, metav1.GetOptions{})
	if err != nil {
		return err
	}
	if c := condition(crt.Status.Conditions, cmapi.CertificateConditionIssuing); c != nil && c.Status == cmmeta.ConditionTrue {
		return errors.New("already issuing")
	}
	now := metav1.Now()
	crt.Status.Conditions = append(slices.DeleteFunc(crt.Status.Conditions, func(c cmapi.CertificateCondition) bool {
		return c.Type == cmapi.CertificateConditionIssuing
	}), cmapi.CertificateCondition{
		Type:               cmapi.CertificateConditionIssuing,
		Status:             cmmeta.ConditionTrue,
		Reason:             "ManuallyTriggered",
		Message:            "Certificate re-issuance requested from the PKI portal",
		LastTransitionTime: &now,
		ObservedGeneration: crt.Generation,
	})
	_, err = k.cm.CertmanagerV1().Certificates(k.ns).UpdateStatus(ctx, crt, metav1.UpdateOptions{})
	return err
}

// History lists the CertificateRequests behind a managed certificate (one per issuance).
type Issuance struct {
	Revision int
	Created  time.Time
	State    State
	Message  string
	NotAfter time.Time
}

func (k *Kube) History(ctx context.Context, id string) ([]Issuance, error) {
	crs, err := k.cm.CertmanagerV1().CertificateRequests(k.ns).List(ctx, metav1.ListOptions{LabelSelector: selector(LabelCertID + "=" + id + "," + LabelMode + "=managed")})
	if err != nil {
		return nil, err
	}
	var out []Issuance
	for i := range crs.Items {
		cr := &crs.Items[i]
		c := fromRequest(cr)
		rev, _ := strconv.Atoi(cr.Annotations["cert-manager.io/certificate-revision"])
		is := Issuance{Revision: rev, Created: cr.CreationTimestamp.Time, State: c.State, Message: c.Message}
		if c.Leaf != nil {
			is.NotAfter = c.Leaf.NotAfter
		}
		out = append(out, is)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Revision > out[j].Revision })
	return out, nil
}

// CA returns step-ca's root and intermediate from its certs ConfigMap ("namespace/name").
func (k *Kube) CA(ctx context.Context, ref string) (root, intermediate *x509.Certificate, err error) {
	ns, name, ok := strings.Cut(ref, "/")
	if !ok {
		return nil, nil, fmt.Errorf("CA ConfigMap must be namespace/name, got %q", ref)
	}
	cm, err := k.core.CoreV1().ConfigMaps(ns).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return nil, nil, err
	}
	if c := ParseChain([]byte(cm.Data["root_ca.crt"])); len(c) > 0 {
		root = c[0]
	}
	if c := ParseChain([]byte(cm.Data["intermediate_ca.crt"])); len(c) > 0 {
		intermediate = c[0]
	}
	if root == nil || intermediate == nil {
		return nil, nil, fmt.Errorf("ConfigMap %s is missing root_ca.crt or intermediate_ca.crt", ref)
	}
	return root, intermediate, nil
}

type IssuerStatus struct {
	Name    string
	Ready   bool
	Message string
}

func (k *Kube) Issuers(ctx context.Context, names ...string) []IssuerStatus {
	var out []IssuerStatus
	for _, n := range names {
		st := IssuerStatus{Name: n}
		ci, err := k.cm.CertmanagerV1().ClusterIssuers().Get(ctx, n, metav1.GetOptions{})
		if err != nil {
			st.Message = err.Error()
		} else {
			for _, c := range ci.Status.Conditions {
				if c.Type == cmapi.IssuerConditionReady {
					st.Ready = c.Status == cmmeta.ConditionTrue
					st.Message = c.Message
				}
			}
		}
		out = append(out, st)
	}
	return out
}

// FindDuplicate returns a live managed cert with the same issuer and names, if any.
func FindDuplicate(certs []*Cert, issuer string, names []string) *Cert {
	want := slices.Sorted(slices.Values(names))
	for _, c := range certs {
		if c.Issuer != issuer || c.State == Expired || c.State == Failed {
			continue
		}
		if slices.Equal(slices.Sorted(slices.Values(c.Names)), want) {
			return c
		}
	}
	return nil
}
