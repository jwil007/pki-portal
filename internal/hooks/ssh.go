package hooks

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// sshPush copies the full chain and key to a Linux host over SSH, then runs a
// reload command. The host key is pinned when the hook is created.
type sshPush struct{}

func init() { Register(sshPush{}) }

func (sshPush) Type() string   { return "ssh" }
func (sshPush) Label() string  { return "SSH push" }
func (sshPush) NeedsKey() bool { return true }
func (sshPush) Help() string {
	return "Copies the full chain and private key to a host over SSH and runs a reload command. Add the portal's public key (shown below) to the user's authorized_keys first. The host key is pinned on first connect."
}

func (sshPush) Fields() []Field {
	return []Field{
		{Name: "host", Label: "Host", Kind: "text", Required: true, Placeholder: "10.0.10.22"},
		{Name: "port", Label: "Port", Kind: "number", Placeholder: "22"},
		{Name: "user", Label: "User", Kind: "text", Required: true, Placeholder: "root"},
		{Name: "cert_path", Label: "Full chain path", Kind: "text", Required: true, Placeholder: "/etc/ssl/certs/host.pem"},
		{Name: "key_path", Label: "Private key path", Kind: "text", Required: true, Placeholder: "/etc/ssl/private/host.key", Help: "Written with mode 0600."},
		{Name: "key_format", Label: "Key format", Kind: "text", Placeholder: "pkcs8", Help: "pkcs8 (BEGIN PRIVATE KEY) or traditional (BEGIN RSA/EC PRIVATE KEY)."},
		{Name: "reload", Label: "Reload command", Kind: "text", Placeholder: "systemctl reload nginx", Help: "Run after the files are written. Optional."},
		{Name: "host_key", Label: "Host key", Kind: "textarea", Help: "Leave empty to pin the key the host presents on first connect."},
	}
}

func addr(cfg map[string]string) string {
	port := cfg["port"]
	if port == "" {
		port = "22"
	}
	return net.JoinHostPort(cfg["host"], port)
}

func (s sshPush) Prepare(ctx context.Context, env *Env, cfg map[string]string) (map[string]string, error) {
	if env.SSHSigner == nil {
		return nil, errors.New("the portal has no SSH key configured")
	}
	if err := required(cfg, s.Fields()); err != nil {
		return nil, err
	}
	if f := cfg["key_format"]; f != "" && f != "pkcs8" && f != "traditional" {
		return nil, errors.New("key format must be pkcs8 or traditional")
	}
	if hk := strings.TrimSpace(cfg["host_key"]); hk != "" {
		if _, _, _, _, err := ssh.ParseAuthorizedKey([]byte(hk)); err != nil {
			return nil, fmt.Errorf("host key: %w (expected e.g. \"ssh-ed25519 AAAA…\")", err)
		}
		return nil, nil
	}
	// Trust on first use: record whatever key the host presents.
	var seen ssh.PublicKey
	conf := &ssh.ClientConfig{
		User:            cfg["user"],
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(env.SSHSigner)},
		HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error { seen = key; return nil },
		Timeout:         10 * time.Second,
	}
	c, err := ssh.Dial("tcp", addr(cfg), conf)
	if seen == nil {
		return nil, fmt.Errorf("couldn't reach %s to read its host key: %w", addr(cfg), err)
	}
	if c != nil {
		c.Close()
	}
	cfg["host_key"] = strings.TrimSpace(string(ssh.MarshalAuthorizedKey(seen)))
	notes := map[string]string{"Pinned host key": ssh.FingerprintSHA256(seen)}
	if err != nil {
		notes["Login test"] = "failed: " + err.Error() + ". Add the portal's public key to authorized_keys, then use Run now."
	} else {
		notes["Login test"] = "ok"
	}
	return notes, nil
}

func shellQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

func keyPEM(key any, format string) ([]byte, error) {
	if format == "traditional" {
		switch k := key.(type) {
		case *rsa.PrivateKey:
			return pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)}), nil
		case *ecdsa.PrivateKey:
			der, err := x509.MarshalECPrivateKey(k)
			return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), err
		}
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), err
}

func (sshPush) Deliver(ctx context.Context, env *Env, cfg map[string]string, _ Event, m Material) error {
	if env.SSHSigner == nil {
		return errors.New("the portal has no SSH key configured")
	}
	if m.Key == nil || m.Leaf == nil {
		return errors.New("the portal doesn't hold this certificate's key")
	}
	key, err := m.Key(ctx)
	if err != nil {
		return err
	}
	keyData, err := keyPEM(key, cfg["key_format"])
	if err != nil {
		return err
	}
	var chain []byte
	for _, c := range append([]*x509.Certificate{m.Leaf}, m.Chain...) {
		chain = append(chain, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})...)
	}
	hostKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(cfg["host_key"]))
	if err != nil {
		return fmt.Errorf("pinned host key: %w", err)
	}
	client, err := ssh.Dial("tcp", addr(cfg), &ssh.ClientConfig{
		User:            cfg["user"],
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(env.SSHSigner)},
		HostKeyCallback: ssh.FixedHostKey(hostKey),
		Timeout:         15 * time.Second,
	})
	if err != nil {
		return fmt.Errorf("ssh %s: %w", addr(cfg), err)
	}
	defer client.Close()

	run := func(cmd string, stdin []byte) error {
		sess, err := client.NewSession()
		if err != nil {
			return err
		}
		defer sess.Close()
		if stdin != nil {
			sess.Stdin = bytes.NewReader(stdin)
		}
		out, err := sess.CombinedOutput(cmd)
		if err != nil {
			return fmt.Errorf("%s: %w: %s", cmd, err, strings.TrimSpace(string(out)))
		}
		return nil
	}
	// Write to a temp file and rename, so a half-written file is never live.
	put := func(path string, data []byte) error {
		tmp := shellQuote(path + ".pki-portal.tmp")
		return run(fmt.Sprintf("umask 077 && cat > %s && mv -f %s %s", tmp, tmp, shellQuote(path)), data)
	}
	if err := put(cfg["key_path"], keyData); err != nil {
		return err
	}
	if err := put(cfg["cert_path"], chain); err != nil {
		return err
	}
	if r := strings.TrimSpace(cfg["reload"]); r != "" {
		return run(r, nil)
	}
	return nil
}
