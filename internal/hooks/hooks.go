// Package hooks delivers certificates (or news about them) after issuance and
// renewal. Each delivery mechanism is a Driver; adding one is a single file that
// implements the interface and calls Register in an init function.
package hooks

import (
	"context"
	"crypto/x509"
	"fmt"
	"net/http"
	"sort"
	"time"

	"golang.org/x/crypto/ssh"
)

// Event describes what happened to a certificate. It never carries key material.
type Event struct {
	Event       string    `json:"event"` // issued | renewed | test
	CertID      string    `json:"cert_id"`
	Names       []string  `json:"names"`
	Serial      string    `json:"serial"`
	Fingerprint string    `json:"sha256_fingerprint"`
	NotBefore   time.Time `json:"not_before"`
	NotAfter    time.Time `json:"not_after"`
	Issuer      string    `json:"issuer"`
	Mode        string    `json:"mode"`
	URL         string    `json:"url"` // the certificate's page in the portal
}

// Material is what drivers that install certificates (e.g. SSH) can ask for.
// Fetching the key is lazy so drivers that don't need it never touch it.
type Material struct {
	Leaf  *x509.Certificate
	Chain []*x509.Certificate
	Key   func(ctx context.Context) (any, error) // nil when the portal has no key
}

// Field describes one setting in a driver's config form.
type Field struct {
	Name        string
	Label       string
	Help        string
	Kind        string // text | password | textarea | number
	Required    bool
	Placeholder string
}

// Env is shared, deploy-time configuration drivers may use (from env/Secrets).
type Env struct {
	HTTP           *http.Client
	DefaultNtfyURL string
	SemaphoreURL   string
	SemaphoreToken string
	SSHSigner      ssh.Signer
	SSHPublicKey   string // authorized_keys line for the portal's SSH key
}

// Driver is one delivery mechanism.
type Driver interface {
	Type() string
	Label() string
	Help() string
	Fields() []Field
	// NeedsKey drivers can only be attached to certificates whose key the portal holds.
	NeedsKey() bool
	// Prepare validates and completes a new hook's config (e.g. generating a
	// secret or pinning a host key). Returned notes are shown to the user once.
	Prepare(ctx context.Context, env *Env, cfg map[string]string) (notes map[string]string, err error)
	// Deliver runs the hook. Pull hooks (passive) return nil without doing anything.
	Deliver(ctx context.Context, env *Env, cfg map[string]string, ev Event, m Material) error
}

var registry = map[string]Driver{}

func Register(d Driver) { registry[d.Type()] = d }

func Get(t string) (Driver, bool) {
	d, ok := registry[t]
	return d, ok
}

// All returns the drivers in a stable order for the UI.
func All() []Driver {
	order := map[string]int{"ntfy": 0, "pull": 1, "webhook": 2, "semaphore": 3, "ssh": 4}
	var out []Driver
	for _, d := range registry {
		out = append(out, d)
	}
	sort.Slice(out, func(i, j int) bool {
		oi, ok := order[out[i].Type()]
		if !ok {
			oi = 100
		}
		oj, ok := order[out[j].Type()]
		if !ok {
			oj = 100
		}
		if oi != oj {
			return oi < oj
		}
		return out[i].Type() < out[j].Type()
	})
	return out
}

// Passive drivers are never run by the delivery loop (the pull API).
type Passive interface{ Passive() bool }

func IsPassive(d Driver) bool {
	p, ok := d.(Passive)
	return ok && p.Passive()
}

func required(cfg map[string]string, fields []Field) error {
	for _, f := range fields {
		if f.Required && cfg[f.Name] == "" {
			return fmt.Errorf("%s is required", f.Label)
		}
	}
	return nil
}
