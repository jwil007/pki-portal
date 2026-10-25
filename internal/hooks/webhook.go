package hooks

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// webhook POSTs the event as JSON, signed with HMAC-SHA256.
type webhook struct{}

func init() { Register(webhook{}) }

func (webhook) Type() string   { return "webhook" }
func (webhook) Label() string  { return "Webhook" }
func (webhook) NeedsKey() bool { return false }
func (webhook) Help() string {
	return "POSTs a JSON event (cert ID, names, serial, expiry, portal link; never key material) to a URL. The body is signed: X-PKI-Signature: sha256=<hex HMAC of the body with the hook secret>."
}

func (webhook) Fields() []Field {
	return []Field{
		{Name: "url", Label: "URL", Kind: "text", Required: true, Placeholder: "https://automation.wilsonfi.dev/hooks/certs"},
		{Name: "secret", Label: "Signing secret", Kind: "password", Help: "Leave empty to generate one (shown once)."},
	}
}

func (w webhook) Prepare(_ context.Context, _ *Env, cfg map[string]string) (map[string]string, error) {
	if err := required(cfg, w.Fields()); err != nil {
		return nil, err
	}
	if !strings.HasPrefix(cfg["url"], "https://") && !strings.HasPrefix(cfg["url"], "http://") {
		return nil, fmt.Errorf("URL must start with https://")
	}
	if cfg["secret"] == "" {
		b := make([]byte, 24)
		rand.Read(b)
		cfg["secret"] = hex.EncodeToString(b)
		return map[string]string{"Signing secret": cfg["secret"]}, nil
	}
	return nil, nil
}

// Sign returns the X-PKI-Signature header value for a body.
func Sign(secret string, body []byte) string {
	m := hmac.New(sha256.New, []byte(secret))
	m.Write(body)
	return "sha256=" + hex.EncodeToString(m.Sum(nil))
}

func (webhook) Deliver(ctx context.Context, env *Env, cfg map[string]string, ev Event, _ Material) error {
	body, _ := json.Marshal(ev)
	req, err := http.NewRequestWithContext(ctx, "POST", cfg["url"], bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "pki-portal")
	req.Header.Set("X-PKI-Event", ev.Event)
	req.Header.Set("X-PKI-Signature", Sign(cfg["secret"], body))
	resp, err := env.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 300))
		return fmt.Errorf("webhook returned %s: %s", resp.Status, strings.TrimSpace(string(msg)))
	}
	return nil
}
