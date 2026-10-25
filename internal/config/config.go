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
	PasswordFile   string // when set, re-read on every login so a rotated Secret applies without a restart
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
	NtfyURL           string // default ntfy topic URL for notify hooks
	BaseURL           string // used in notification links

	SemaphoreURL   string
	SemaphoreToken string
	SSHKeyFile     string // portal's SSH key for SSH push hooks; generated in DataDir if unset
	MetricsListen  string // separate listener for /metrics (not exposed through the ingress)
}

func Load() (*Config, error) {
	c := &Config{
		Listen:         env("PORTAL_LISTEN", ":8080"),
		Password:       os.Getenv("PORTAL_PASSWORD"),
		PasswordFile:   os.Getenv("PORTAL_PASSWORD_FILE"),
		DataDir:        env("PORTAL_DATA_DIR", "./data"),
		Namespace:      env("PORTAL_NAMESPACE", "pki-managed"),
		PublicIssuer:   env("PORTAL_PUBLIC_ISSUER", "letsencrypt-staging"),
		Domains:        list(env("PORTAL_DOMAINS", "wilsonfi.dev,wilsonfi.com")),
		PublicDomains:  list(env("PORTAL_PUBLIC_DOMAINS", "wilsonfi.dev")),
		IPRanges:       list(env("PORTAL_IP_RANGES", "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16")),
		CAConfigMap:    env("PORTAL_CA_CONFIGMAP", "pki/step-certificates-certs"),
		InsecureCookie: os.Getenv("PORTAL_INSECURE_COOKIE") == "true",
		NtfyURL:        secret("PORTAL_NTFY_URL"),
		BaseURL:        strings.TrimSuffix(env("PORTAL_BASE_URL", "http://localhost:8080"), "/"),

		StepCAURL:         env("PORTAL_STEPCA_URL", "https://step-certificates.pki.svc.cluster.local"),
		StepCAProvisioner: env("PORTAL_STEPCA_PROVISIONER", "pki-portal"),
		StepCAPassword:    secret("PORTAL_STEPCA_PASSWORD"),
		StepCADial:        os.Getenv("PORTAL_STEPCA_DIAL"),

		SemaphoreURL:   os.Getenv("PORTAL_SEMAPHORE_URL"),
		SemaphoreToken: secret("PORTAL_SEMAPHORE_TOKEN"),
		SSHKeyFile:     os.Getenv("PORTAL_SSH_KEY_FILE"),
		MetricsListen:  env("PORTAL_METRICS_LISTEN", ":9090"),
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
	if c.Password == "" && c.PasswordFile == "" {
		return nil, fmt.Errorf("PORTAL_PASSWORD or PORTAL_PASSWORD_FILE must be set")
	}
	if c.PasswordFile != "" {
		if _, err := os.ReadFile(c.PasswordFile); err != nil {
			return nil, fmt.Errorf("PORTAL_PASSWORD_FILE: %w", err)
		}
	}
	return c, nil
}

// CurrentPassword returns the login password, re-reading the file if one is configured.
func (c *Config) CurrentPassword() string {
	if c.PasswordFile != "" {
		if b, err := os.ReadFile(c.PasswordFile); err == nil {
			return strings.TrimSpace(string(b))
		}
	}
	return c.Password
}

// secret reads NAME, or the file named by NAME_FILE (how Kubernetes Secrets are mounted).
func secret(name string) string {
	if f := os.Getenv(name + "_FILE"); f != "" {
		if b, err := os.ReadFile(f); err == nil {
			return strings.TrimSpace(string(b))
		}
	}
	return os.Getenv(name)
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
