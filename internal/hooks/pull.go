package hooks

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
)

// pull is passive: it issues a per-certificate API token that a device or
// script uses to fetch the latest certificate from /api/v1/certs/{id}/{format}.
type pull struct{}

func init() { Register(pull{}) }

func (pull) Type() string   { return "pull" }
func (pull) Label() string  { return "Pull API token" }
func (pull) Passive() bool  { return true }
func (pull) NeedsKey() bool { return false }
func (pull) Help() string {
	return "A revocable token scoped to this one certificate, so a device or script can download the latest version itself (curl + systemd timer). Delete the hook to revoke the token."
}
func (pull) Fields() []Field { return nil }

func (pull) Prepare(context.Context, *Env, map[string]string) (map[string]string, error) {
	return nil, nil
}

func (pull) Deliver(context.Context, *Env, map[string]string, Event, Material) error { return nil }

// NewToken returns a token and the hash to store.
func NewToken() (token, hash string) {
	b := make([]byte, 32)
	rand.Read(b)
	token = "pkp_" + base64.RawURLEncoding.EncodeToString(b)
	return token, HashToken(token)
}

func HashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}
