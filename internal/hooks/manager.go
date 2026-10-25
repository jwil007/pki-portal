package hooks

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/jwil007/pki-portal/internal/kube"
	"github.com/jwil007/pki-portal/internal/store"
)

// Manager runs hooks whenever a certificate's serial differs from the serial a
// hook last delivered. Comparing serials (instead of reacting to watch events)
// means renewals that happened while the portal was down are still delivered.
type Manager struct {
	Store   *store.Store
	Kube    *kube.Kube
	Env     *Env
	BaseURL string
	Log     *slog.Logger

	trigger chan struct{}
	mu      sync.Mutex
	counts  map[[2]string]int // {type, ok|failed} -> deliveries
}

func NewManager(st *store.Store, k *kube.Kube, env *Env, baseURL string, log *slog.Logger) *Manager {
	return &Manager{Store: st, Kube: k, Env: env, BaseURL: baseURL, Log: log,
		trigger: make(chan struct{}, 1), counts: map[[2]string]int{}}
}

// Kick asks the loop to check now (after an issuance or renewal).
func (m *Manager) Kick() {
	select {
	case m.trigger <- struct{}{}:
	default:
	}
}

func (m *Manager) Run(ctx context.Context) {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		m.Reconcile(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		case <-m.trigger:
		}
	}
}

// EventFor describes a certificate for drivers.
func (m *Manager) EventFor(c *kube.Cert, kind string) Event {
	ev := Event{Event: kind, CertID: c.ID, Names: c.Names, Issuer: c.Issuer, Mode: string(c.Mode),
		URL: m.BaseURL + "/certs/" + c.ID, Serial: c.Serial(), Fingerprint: c.Fingerprint()}
	if c.Leaf != nil {
		ev.NotBefore, ev.NotAfter = c.Leaf.NotBefore, c.Leaf.NotAfter
	}
	return ev
}

func (m *Manager) material(c *kube.Cert) Material {
	mat := Material{Leaf: c.Leaf, Chain: c.Chain}
	if c.Mode == kube.Managed {
		mat.Key = func(ctx context.Context) (any, error) { return m.Kube.Key(ctx, c) }
	}
	return mat
}

// Reconcile delivers every hook whose certificate has a new serial.
func (m *Manager) Reconcile(ctx context.Context) {
	hs, err := m.Store.AllHooks()
	if err != nil || len(hs) == 0 {
		return
	}
	certs, err := m.Kube.List(ctx)
	if err != nil {
		m.Log.Warn("hooks: listing certificates failed", "err", err)
		return
	}
	byID := map[string]*kube.Cert{}
	for _, c := range certs {
		byID[c.ID] = c
	}
	now := time.Now()
	for _, h := range hs {
		d, ok := Get(h.Type)
		c := byID[h.CertID]
		if !ok || !h.Enabled || IsPassive(d) || c == nil || c.Leaf == nil || c.State == kube.Revoked {
			continue
		}
		if c.Serial() == h.LastSerial || now.Before(h.NextAttempt) {
			continue
		}
		kind := "renewed"
		if h.LastSerial == "" {
			kind = "issued"
		}
		m.deliver(ctx, d, h, c, kind)
	}
}

// RunNow delivers one hook immediately, regardless of serials.
func (m *Manager) RunNow(ctx context.Context, id int64) error {
	h, err := m.Store.Hook(id)
	if err != nil {
		return err
	}
	d, ok := Get(h.Type)
	if !ok {
		return fmt.Errorf("unknown hook type %q", h.Type)
	}
	c, err := m.Kube.Get(ctx, h.CertID)
	if err != nil {
		return err
	}
	if c.Leaf == nil {
		return fmt.Errorf("certificate not issued yet")
	}
	return m.deliver(ctx, d, h, c, "test")
}

func (m *Manager) deliver(ctx context.Context, d Driver, h *store.Hook, c *kube.Cert, kind string) error {
	dctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	err := d.Deliver(dctx, m.Env, h.Config, m.EventFor(c, kind), m.material(c))
	if rerr := m.Store.RecordRun(h, c.Serial(), err); rerr != nil {
		m.Log.Error("hooks: recording run failed", "hook", h.ID, "err", rerr)
	}
	result := "ok"
	detail := fmt.Sprintf("%s #%d (%s): ok", h.Type, h.ID, kind)
	if err != nil {
		result = "failed"
		detail = fmt.Sprintf("%s #%d (%s): %v", h.Type, h.ID, kind, err)
		m.Log.Warn("hook failed", "hook", h.ID, "type", h.Type, "cert", c.ID, "err", err)
	}
	m.Store.Log("hook-run", c.ID, detail, "hooks")
	m.mu.Lock()
	m.counts[[2]string{h.Type, result}]++
	m.mu.Unlock()
	return err
}

// Counts returns delivery counters for /metrics.
func (m *Manager) Counts() map[[2]string]int {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make(map[[2]string]int, len(m.counts))
	for k, v := range m.counts {
		out[k] = v
	}
	return out
}
