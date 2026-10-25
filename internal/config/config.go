// Package config reads deploy-time settings from environment variables.
package config

import (
	"fmt"
	"os"
	"strings"
	"time"
)

type Config struct {
	Listen         string
	Password       string
	DataDir        string
	Namespace      string
	PublicIssuer   string
	Domains        []string
	PublicDomains  []string
	IPRanges       []string
	CAConfigMap    string // namespace/name of step-ca's certs ConfigMap
	InsecureCookie bool   // allow login over plain http (local dev only)
	KeyTTL         time.Duration

	// Internal certs are signed directly by step-ca with a JWK provisioner.
	StepCAURL         string
	StepCAProvisioner string
	StepCAPassword    string // empty disables internal certificates
	StepCADial        string // optional host:port to connect to instead of the URL's host
	InternalLifetime  time.Duration
	NtfyURL           string // e.g. https://ntfy.sh/my-topic; empty disables notifications
	BaseURL           string // used in notification links
}

func Load() (*Config, error) {
	c := &Config{
		Listen:         env("PORTAL_LISTEN", ":8080"),
		Password:       os.Getenv("PORTAL_PASSWORD"),
		DataDir:        env("PORTAL_DATA_DIR", "./data"),
		Namespace:      env("PORTAL_NAMESPACE", "pki-managed"),
		PublicIssuer:   env("PORTAL_PUBLIC_ISSUER", "letsencrypt-staging"),
		Domains:        list(env("PORTAL_DOMAINS", "wilsonfi.dev,wilsonfi.com")),
		PublicDomains:  list(env("PORTAL_PUBLIC_DOMAINS", "wilsonfi.dev")),
		IPRanges:       list(env("PORTAL_IP_RANGES", "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16")),
		CAConfigMap:    env("PORTAL_CA_CONFIGMAP", "pki/step-certificates-certs"),
		InsecureCookie: os.Getenv("PORTAL_INSECURE_COOKIE") == "true",
		NtfyURL:        os.Getenv("PORTAL_NTFY_URL"),
		BaseURL:        strings.TrimSuffix(env("PORTAL_BASE_URL", "http://localhost:8080"), "/"),

		StepCAURL:         env("PORTAL_STEPCA_URL", "https://step-certificates.pki.svc.cluster.local"),
		StepCAProvisioner: env("PORTAL_STEPCA_PROVISIONER", "pki-portal"),
		StepCAPassword:    os.Getenv("PORTAL_STEPCA_PASSWORD"),
		StepCADial:        os.Getenv("PORTAL_STEPCA_DIAL"),
	}
	ttl, err := time.ParseDuration(env("PORTAL_KEY_TTL", "30m"))
	if err != nil {
		return nil, fmt.Errorf("PORTAL_KEY_TTL: %w", err)
	}
	c.KeyTTL = ttl
	if v := os.Getenv("PORTAL_INTERNAL_LIFETIME"); v != "" {
		if c.InternalLifetime, err = time.ParseDuration(v); err != nil {
			return nil, fmt.Errorf("PORTAL_INTERNAL_LIFETIME: %w", err)
		}
	}
	if c.Password == "" {
		return nil, fmt.Errorf("PORTAL_PASSWORD must be set")
	}
	return c, nil
}

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func list(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.ToLower(strings.TrimSpace(p)); p != "" {
			out = append(out, p)
		}
	}
	return out
}
