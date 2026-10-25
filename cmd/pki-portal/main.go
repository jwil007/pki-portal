// Command pki-portal serves the PKI self-service web UI.
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/jwil007/pki-portal/internal/config"
	"github.com/jwil007/pki-portal/internal/hooks"
	"github.com/jwil007/pki-portal/internal/internalca"
	"github.com/jwil007/pki-portal/internal/keystash"
	"github.com/jwil007/pki-portal/internal/kube"
	"github.com/jwil007/pki-portal/internal/stepca"
	"github.com/jwil007/pki-portal/internal/store"
	"github.com/jwil007/pki-portal/internal/web"

	"golang.org/x/crypto/ssh"
)

var version = "dev"

func main() {
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	if err := run(log); err != nil {
		log.Error("fatal", "err", err)
		os.Exit(1)
	}
}

func run(log *slog.Logger) error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(cfg.DataDir, 0o700); err != nil {
		return err
	}
	st, err := store.Open(filepath.Join(cfg.DataDir, "portal.db"))
	if err != nil {
		return err
	}
	defer st.Close()
	k, err := kube.New(cfg.Namespace)
	if err != nil {
		return err
	}
	stash := keystash.New(cfg.KeyTTL)

	var internal *internalca.Issuer
	if cfg.StepCAPassword != "" {
		root, _, err := k.CA(context.Background(), cfg.CAConfigMap)
		if err != nil {
			return fmt.Errorf("loading step-ca root for internal certs: %w", err)
		}
		ca, err := stepca.New(cfg.StepCAURL, cfg.StepCAProvisioner, cfg.StepCAPassword, cfg.StepCADial, root)
		if err != nil {
			return err
		}
		var clients *stepca.Client
		if cfg.ClientProvisioner != "" {
			clients = ca.WithProvisioner(cfg.ClientProvisioner)
		}
		internal = internalca.New(k, ca, clients, cfg.InternalLifetime)
	} else {
		log.Warn("PORTAL_STEPCA_PASSWORD not set: internal certificates are disabled")
	}
	env, err := hookEnv(cfg)
	if err != nil {
		return err
	}
	hm := hooks.NewManager(st, k, env, cfg.BaseURL, log)
	srv, err := web.New(cfg, k, st, stash, internal, hm, log)
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		t := time.NewTicker(time.Minute)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				stash.Sweep()
				if internal != nil && time.Now().Minute()%10 == 0 {
					renewInternal(ctx, internal, st, log)
					hm.Kick()
				}
			}
		}
	}()

	if internal != nil {
		go renewInternal(ctx, internal, st, log)
	}
	go hm.Run(ctx)
	if cfg.MetricsListen != "" {
		ms := &http.Server{Addr: cfg.MetricsListen, Handler: srv.Metrics(), ReadHeaderTimeout: 10 * time.Second}
		go func() {
			if err := ms.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Error("metrics listener", "err", err)
			}
		}()
		go func() { <-ctx.Done(); ms.Close() }()
	}
	hs := &http.Server{Addr: cfg.Listen, Handler: srv.Handler(), ReadHeaderTimeout: 10 * time.Second}
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		hs.Shutdown(shutdown)
	}()
	log.Info("listening", "version", version, "addr", cfg.Listen, "namespace", cfg.Namespace, "public_issuer", cfg.PublicIssuer, "internal", internal != nil)
	if err := hs.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// renewInternal renews managed step-ca certs past two-thirds of their lifetime.
func renewInternal(ctx context.Context, issuer *internalca.Issuer, st *store.Store, log *slog.Logger) {
	results, err := issuer.RenewDue(ctx)
	if err != nil {
		log.Error("renewal check failed", "err", err)
		return
	}
	for _, r := range results {
		if r.Err != nil {
			log.Error("renewal failed", "cert", r.ID, "err", r.Err)
			st.Log("renew-failed", r.ID, r.Err.Error(), "scheduler")
			continue
		}
		log.Info("renewed", "cert", r.ID)
		st.Log("renew", r.ID, "automatic", "scheduler")
	}
}

// hookEnv builds the shared settings for hook drivers, including the portal's
// SSH key (from PORTAL_SSH_KEY_FILE, or generated once into the data dir).
func hookEnv(cfg *config.Config) (*hooks.Env, error) {
	env := &hooks.Env{
		HTTP:           &http.Client{Timeout: 20 * time.Second},
		DefaultNtfyURL: cfg.NtfyURL,
		SemaphoreURL:   cfg.SemaphoreURL,
		SemaphoreToken: cfg.SemaphoreToken,
	}
	path := cfg.SSHKeyFile
	if path == "" {
		path = filepath.Join(cfg.DataDir, "ssh_ed25519")
		if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
			_, priv, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				return nil, err
			}
			block, err := ssh.MarshalPrivateKey(priv, "pki-portal")
			if err != nil {
				return nil, err
			}
			if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o600); err != nil {
				return nil, err
			}
		}
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading SSH key: %w", err)
	}
	signer, err := ssh.ParsePrivateKey(data)
	if err != nil {
		return nil, fmt.Errorf("parsing SSH key %s: %w", path, err)
	}
	env.SSHSigner = signer
	env.SSHPublicKey = strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey()))) + " pki-portal"
	return env, nil
}
