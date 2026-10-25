package kube

import (
	"context"
	"sort"
	"strings"

	acmev1 "github.com/cert-manager/cert-manager/pkg/apis/acme/v1"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

// Step is one line of the issuance timeline shown while a cert is being issued.
type Step struct {
	Name   string
	State  string // done | active | failed | waiting
	Detail string
}

// Progress walks CertificateRequest → Order → Challenges for the latest issuance.
func (k *Kube) Progress(ctx context.Context, c *Cert) ([]Step, error) {
	cr, err := k.latestRequest(ctx, c)
	if err != nil {
		return nil, err
	}
	if cr == nil {
		return []Step{{Name: "Request", State: "active", Detail: "cert-manager is generating the key and CSR"}}, nil
	}
	steps := []Step{requestStep(cr)}

	orders, err := k.cm.AcmeV1().Orders(k.ns).List(ctx, metav1.ListOptions{})
	if err != nil {
		return steps, err
	}
	var order *acmev1.Order
	for i := range orders.Items {
		if ownedBy(orders.Items[i].OwnerReferences, cr.UID) {
			order = &orders.Items[i]
		}
	}
	if order == nil {
		if r := requestCondition(cr, cmapi.CertificateRequestConditionReady); r == nil || r.Status != cmmeta.ConditionTrue {
			steps = append(steps, Step{Name: "ACME order", State: "waiting", Detail: "Not created yet"})
		}
		return steps, nil
	}
	steps = append(steps, orderStep(order))

	chs, err := k.cm.AcmeV1().Challenges(k.ns).List(ctx, metav1.ListOptions{})
	if err != nil {
		return steps, err
	}
	var mine []acmev1.Challenge
	for _, ch := range chs.Items {
		if ownedBy(ch.OwnerReferences, order.UID) {
			mine = append(mine, ch)
		}
	}
	sort.Slice(mine, func(i, j int) bool { return mine[i].Spec.DNSName < mine[j].Spec.DNSName })
	for _, ch := range mine {
		steps = append(steps, challengeStep(&ch, c.Public))
	}
	if len(mine) == 0 && order.Status.State == acmev1.Pending {
		steps = append(steps, Step{Name: "DNS-01 challenges", State: "waiting", Detail: "Waiting for cert-manager to create the challenges"})
	}
	return steps, nil
}

func (k *Kube) latestRequest(ctx context.Context, c *Cert) (*cmapi.CertificateRequest, error) {
	if c.Mode != Managed {
		return k.cm.CertmanagerV1().CertificateRequests(k.ns).Get(ctx, c.ID, metav1.GetOptions{})
	}
	crs, err := k.cm.CertmanagerV1().CertificateRequests(k.ns).List(ctx, metav1.ListOptions{LabelSelector: selector(LabelCertID + "=" + c.ID + "," + LabelMode + "=managed")})
	if err != nil || len(crs.Items) == 0 {
		return nil, err
	}
	latest := &crs.Items[0]
	for i := range crs.Items {
		if crs.Items[i].CreationTimestamp.After(latest.CreationTimestamp.Time) {
			latest = &crs.Items[i]
		}
	}
	return latest, nil
}

func ownedBy(refs []metav1.OwnerReference, uid types.UID) bool {
	for _, r := range refs {
		if r.UID == uid {
			return true
		}
	}
	return false
}

func requestStep(cr *cmapi.CertificateRequest) Step {
	s := Step{Name: "Certificate request", State: "active", Detail: "Waiting for approval"}
	if a := requestCondition(cr, cmapi.CertificateRequestConditionApproved); a != nil && a.Status == cmmeta.ConditionTrue {
		s.Detail = "Approved, waiting for the issuer"
	}
	if d := requestCondition(cr, cmapi.CertificateRequestConditionDenied); d != nil && d.Status == cmmeta.ConditionTrue {
		return Step{Name: s.Name, State: "failed", Detail: "Denied: " + d.Message}
	}
	if r := requestCondition(cr, cmapi.CertificateRequestConditionReady); r != nil {
		switch {
		case r.Status == cmmeta.ConditionTrue:
			s.State, s.Detail = "done", "Certificate issued"
		case r.Reason == cmapi.CertificateRequestReasonFailed:
			s.State, s.Detail = "failed", Explain(r.Message)
		case r.Message != "":
			s.Detail = Explain(r.Message)
		}
	}
	return s
}

func orderStep(o *acmev1.Order) Step {
	s := Step{Name: "ACME order"}
	switch o.Status.State {
	case acmev1.Valid:
		s.State, s.Detail = "done", "Order complete"
	case acmev1.Invalid, acmev1.Errored, acmev1.Expired:
		s.State = "failed"
		s.Detail = "The CA marked the order " + string(o.Status.State) + ". "
		if o.Status.Reason != "" {
			s.Detail += Explain(o.Status.Reason)
		} else {
			s.Detail += "Usually the CA couldn't see the DNS-01 TXT record before the order expired."
		}
	case acmev1.Ready, acmev1.Processing:
		s.State, s.Detail = "active", "Challenges passed, CA is signing"
	default:
		s.State, s.Detail = "active", "Waiting for challenges"
	}
	return s
}

func challengeStep(ch *acmev1.Challenge, public bool) Step {
	s := Step{Name: "DNS-01 " + ch.Spec.DNSName}
	switch ch.Status.State {
	case acmev1.Valid:
		s.State, s.Detail = "done", "Validated"
		return s
	case acmev1.Invalid, acmev1.Errored, acmev1.Expired:
		s.State = "failed"
	default:
		s.State = "active"
	}
	switch {
	case ch.Status.Reason != "":
		s.Detail = Explain(ch.Status.Reason)
	case !ch.Status.Presented:
		s.Detail = "Creating the TXT record in Cloudflare"
	default:
		s.Detail = "TXT record created; waiting for the CA to validate it"
	}
	if s.State == "failed" && !public {
		s.Detail += " For step-ca, check that it can resolve _acme-challenge." + strings.TrimPrefix(ch.Spec.DNSName, "*.") + " (internal DNS forwarding for the zone)."
	}
	return s
}

// Explain turns common cert-manager / ACME errors into plain English.
func Explain(msg string) string {
	m := strings.ToLower(msg)
	switch {
	case strings.Contains(m, "propagation check failed"), strings.Contains(m, "waiting for dns-01 challenge propagation"):
		return "DNS-01 pending: the TXT record isn't visible yet (cert-manager's self-check). This normally clears within 1–3 minutes."
	case strings.Contains(m, "ratelimited"), strings.Contains(m, "too many certificates"), strings.Contains(m, "rate limit"):
		return "Let's Encrypt rate limit hit. Wait before retrying, or use the staging issuer for testing. (" + msg + ")"
	case strings.Contains(m, "cloudflare") && (strings.Contains(m, "auth") || strings.Contains(m, "permission") || strings.Contains(m, "10000")):
		return "Cloudflare rejected the TXT record change; check the API token's zone permissions. (" + msg + ")"
	case strings.Contains(m, "no such host"), strings.Contains(m, "servfail"), strings.Contains(m, "i/o timeout"):
		return "DNS lookup failed while checking the challenge; check cluster DNS / forwarding. (" + msg + ")"
	case strings.Contains(m, "incorrect txt record"), strings.Contains(m, "no txt record"), strings.Contains(m, "unauthorized"):
		return "The CA looked up the TXT record and didn't find the right value. (" + msg + ")"
	case strings.Contains(m, "rejectedidentifier"), strings.Contains(m, "policy forbids"):
		return "The CA's policy refuses this name. (" + msg + ")"
	}
	return msg
}
