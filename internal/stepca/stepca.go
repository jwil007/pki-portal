// Package stepca signs CSRs directly with step-ca through a JWK provisioner,
// the same way `step ca sign` does: a short-lived one-time token plus POST /1.0/sign.
package stepca

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"go.step.sm/crypto/jose"
)

type Client struct {
	base        *url.URL
	provisioner string
	password    []byte
	root        *x509.Certificate
	http        *http.Client

	mu  sync.Mutex
	jwk *jose.JSONWebKey
}

// New creates a client. dial optionally overrides the address connected to
// (e.g. the LoadBalancer IP when running outside the cluster).
func New(caURL, provisioner, password, dial string, root *x509.Certificate) (*Client, error) {
	u, err := url.Parse(strings.TrimSuffix(caURL, "/"))
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	pool.AddCert(root)
	tr := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}}
	if dial != "" {
		d := &net.Dialer{Timeout: 10 * time.Second}
		tr.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
			return d.DialContext(ctx, network, dial)
		}
	}
	return &Client{
		base:        u,
		provisioner: provisioner,
		password:    []byte(password),
		root:        root,
		http:        &http.Client{Transport: tr, Timeout: 30 * time.Second},
	}, nil
}

func (c *Client) Root() *x509.Certificate { return c.root }

// Health returns nil when step-ca answers /health.
func (c *Client) Health(ctx context.Context) error {
	req, _ := http.NewRequestWithContext(ctx, "GET", c.base.String()+"/health", nil)
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("step-ca /health returned %s", resp.Status)
	}
	return nil
}

// key fetches and decrypts the provisioner's private key once.
func (c *Client) key(ctx context.Context) (*jose.JSONWebKey, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.jwk != nil {
		return c.jwk, nil
	}
	cursor := ""
	for {
		req, _ := http.NewRequestWithContext(ctx, "GET", c.base.String()+"/provisioners?limit=100&cursor="+url.QueryEscape(cursor), nil)
		resp, err := c.http.Do(req)
		if err != nil {
			return nil, fmt.Errorf("listing step-ca provisioners: %w", err)
		}
		var body struct {
			Provisioners []struct {
				Type         string `json:"type"`
				Name         string `json:"name"`
				EncryptedKey string `json:"encryptedKey"`
			} `json:"provisioners"`
			NextCursor string `json:"nextCursor"`
		}
		err = json.NewDecoder(resp.Body).Decode(&body)
		resp.Body.Close()
		if err != nil {
			return nil, fmt.Errorf("decoding provisioners: %w", err)
		}
		for _, p := range body.Provisioners {
			if p.Name != c.provisioner {
				continue
			}
			if p.Type != "JWK" || p.EncryptedKey == "" {
				return nil, fmt.Errorf("provisioner %q is %s, not a JWK provisioner with an encrypted key", p.Name, p.Type)
			}
			raw, err := jose.Decrypt([]byte(p.EncryptedKey), jose.WithPassword(c.password))
			if err != nil {
				return nil, fmt.Errorf("decrypting provisioner %q key (wrong password?): %w", p.Name, err)
			}
			jwk := new(jose.JSONWebKey)
			if err := json.Unmarshal(raw, jwk); err != nil {
				return nil, err
			}
			c.jwk = jwk
			return jwk, nil
		}
		if body.NextCursor == "" {
			return nil, fmt.Errorf("step-ca has no provisioner named %q", c.provisioner)
		}
		cursor = body.NextCursor
	}
}

type tokenClaims struct {
	jose.Claims
	SANs []string `json:"sans"`
	SHA  string   `json:"sha"`
}

func (c *Client) token(ctx context.Context, subject string, sans []string, path string) (string, error) {
	jwk, err := c.key(ctx)
	if err != nil {
		return "", err
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.SignatureAlgorithm(jwk.Algorithm), Key: jwk.Key},
		new(jose.SignerOptions).WithType("JWT").WithHeader("kid", jwk.KeyID))
	if err != nil {
		return "", err
	}
	id := make([]byte, 16)
	rand.Read(id)
	now := time.Now()
	sum := sha256.Sum256(c.root.Raw)
	claims := tokenClaims{
		Claims: jose.Claims{
			Issuer:    c.provisioner,
			Subject:   subject,
			Audience:  jose.Audience{c.base.String() + path},
			IssuedAt:  jose.NewNumericDate(now),
			NotBefore: jose.NewNumericDate(now),
			Expiry:    jose.NewNumericDate(now.Add(5 * time.Minute)),
			ID:        hex.EncodeToString(id),
		},
		SANs: sans,
		SHA:  hex.EncodeToString(sum[:]),
	}
	return jose.Signed(signer).Claims(claims).CompactSerialize()
}

// Sign submits a PEM CSR. subject becomes the CN; sans must match the CSR's SANs.
// It returns the PEM leaf followed by the intermediate(s).
func (c *Client) Sign(ctx context.Context, csrPEM []byte, subject string, sans []string, lifetime time.Duration) ([]byte, error) {
	ott, err := c.token(ctx, subject, sans, "/1.0/sign")
	if err != nil {
		return nil, err
	}
	req := map[string]string{"csr": string(csrPEM), "ott": ott}
	if lifetime > 0 {
		req["notAfter"] = lifetime.String()
	}
	body, _ := json.Marshal(req)
	hreq, _ := http.NewRequestWithContext(ctx, "POST", c.base.String()+"/1.0/sign", bytes.NewReader(body))
	hreq.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(hreq)
	if err != nil {
		return nil, fmt.Errorf("step-ca sign: %w", err)
	}
	defer resp.Body.Close()
	var out struct {
		CertChain []string `json:"certChain"`
		Crt       string   `json:"crt"`
		CA        string   `json:"ca"`
		Message   string   `json:"message"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("step-ca sign: %s (unreadable response)", resp.Status)
	}
	if resp.StatusCode/100 != 2 {
		if out.Message == "" {
			out.Message = resp.Status
		}
		return nil, errors.New("step-ca refused to sign: " + out.Message)
	}
	if len(out.CertChain) > 0 {
		return []byte(strings.Join(out.CertChain, "\n")), nil
	}
	return []byte(out.Crt + "\n" + out.CA), nil
}

// Revoke marks a certificate revoked in step-ca's database (passive revocation:
// it shows up in the CRL; step-ca has no OCSP). Any JWK provisioner may revoke.
func (c *Client) Revoke(ctx context.Context, serial *big.Int, reasonCode int, reason string) error {
	ott, err := c.token(ctx, serial.String(), nil, "/1.0/revoke")
	if err != nil {
		return err
	}
	body, _ := json.Marshal(map[string]any{
		"serial": serial.String(), "ott": ott, "reasonCode": reasonCode, "reason": reason, "passive": true,
	})
	req, _ := http.NewRequestWithContext(ctx, "POST", c.base.String()+"/1.0/revoke", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("step-ca revoke: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		var e struct {
			Message string `json:"message"`
		}
		json.NewDecoder(resp.Body).Decode(&e)
		if e.Message == "" {
			e.Message = resp.Status
		}
		return errors.New("step-ca refused to revoke: " + e.Message)
	}
	return nil
}

// CRL fetches step-ca's current CRL (DER). It returns ErrNoCRL when CRLs aren't enabled.
func (c *Client) CRL(ctx context.Context) ([]byte, error) {
	req, _ := http.NewRequestWithContext(ctx, "GET", c.base.String()+"/1.0/crl", nil)
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusNotImplemented {
		return nil, ErrNoCRL
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("step-ca /1.0/crl returned %s", resp.Status)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 16<<20))
}

var ErrNoCRL = errors.New("CRL generation isn't enabled on step-ca")

// WithProvisioner returns a client for another JWK provisioner on the same CA.
func (c *Client) WithProvisioner(name string) *Client {
	return &Client{base: c.base, provisioner: name, password: c.password, root: c.root, http: c.http}
}
