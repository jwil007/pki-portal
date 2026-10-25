// Command pki-portal serves the PKI self-service web UI.
package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/jwil007/pki-portal/internal/config"
	"github.com/jwil007/pki-portal/internal/keystash"
	"github.com/jwil007/pki-portal/internal/kube"
	"github.com/jwil007/pki-portal/internal/store"
	"github.com/jwil007/pki-portal/internal/web"
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
	srv, err := web.New(cfg, k, st, stash, log)
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
			}
		}
	}()

	hs := &http.Server{Addr: cfg.Listen, Handler: srv.Handler(), ReadHeaderTimeout: 10 * time.Second}
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		hs.Shutdown(shutdown)
	}()
	log.Info("listening", "version", version, "addr", cfg.Listen, "namespace", cfg.Namespace, "public_issuer", cfg.PublicIssuer, "internal_issuer", cfg.InternalIssuer)
	if err := hs.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}
