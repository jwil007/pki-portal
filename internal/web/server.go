// Package web is the portal's HTTP UI: server-rendered templates plus htmx.
package web

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"embed"
	"encoding/base64"
	"fmt"
	"html/template"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/jwil007/pki-portal/internal/config"
	"github.com/jwil007/pki-portal/internal/hooks"
	"github.com/jwil007/pki-portal/internal/internalca"
	"github.com/jwil007/pki-portal/internal/keystash"
	"github.com/jwil007/pki-portal/internal/kube"
	"github.com/jwil007/pki-portal/internal/policy"
	"github.com/jwil007/pki-portal/internal/store"
)

//go:embed templates static
var assets embed.FS

const sessionCookie = "pki_session"
const sessionTTL = 7 * 24 * time.Hour

type Server struct {
	cfg        *config.Config
	kube       *kube.Kube
	store      *store.Store
	stash      *keystash.Stash
	internal   *internalca.Issuer // nil when no step-ca provisioner is configured
	hooks      *hooks.Manager
	counters   counters
	policy     policy.Policy
	sessionKey []byte
	pages      map[string]*template.Template
	log        *slog.Logger
}

func New(cfg *config.Config, k *kube.Kube, st *store.Store, stash *keystash.Stash, internal *internalca.Issuer, hm *hooks.Manager, log *slog.Logger) (*Server, error) {
	key, err := loadSessionKey(filepath.Join(cfg.DataDir, "session.key"))
	if err != nil {
		return nil, err
	}
	ranges, err := policy.ParseRanges(cfg.IPRanges)
	if err != nil {
		return nil, err
	}
	s := &Server{
		cfg:        cfg,
		kube:       k,
		store:      st,
		stash:      stash,
		internal:   internal,
		hooks:      hm,
		policy:     policy.Policy{Domains: cfg.Domains, PublicDomains: cfg.PublicDomains, IPRanges: ranges},
		sessionKey: key,
		log:        log,
	}
	if err := s.parseTemplates(); err != nil {
		return nil, err
	}
	return s, nil
}

// loadSessionKey keeps sessions valid across restarts when the data dir persists.
func loadSessionKey(path string) ([]byte, error) {
	if b, err := os.ReadFile(path); err == nil && len(b) == 32 {
		return b, nil
	}
	b := make([]byte, 32)
	rand.Read(b)
	if err := os.WriteFile(path, b, 0o600); err != nil {
		return nil, fmt.Errorf("write session key: %w", err)
	}
	return b, nil
}

var funcs = template.FuncMap{
	"date": func(t time.Time) string {
		if t.IsZero() {
			return "—"
		}
		return t.Local().Format("2006-01-02 15:04")
	},
	"day": func(t time.Time) string {
		if t.IsZero() {
			return "—"
		}
		return t.Local().Format("2006-01-02")
	},
	"join": strings.Join,
	"short": func(s string) string {
		if len(s) > 80 {
			return s[:77] + "…"
		}
		return s
	},
	"explain": kube.Explain,
	"fp": func(s string) string { // colon-separate a hex fingerprint
		var b strings.Builder
		for i := 0; i < len(s); i += 2 {
			if i > 0 {
				b.WriteByte(':')
			}
			b.WriteString(s[i:min(i+2, len(s))])
		}
		return b.String()
	},
}

func (s *Server) parseTemplates() error {
	s.pages = map[string]*template.Template{}
	pages, err := fs.Glob(assets, "templates/pages/*.html")
	if err != nil {
		return err
	}
	for _, p := range pages {
		t, err := template.New(filepath.Base(p)).Funcs(funcs).ParseFS(assets, "templates/layout.html", "templates/partials.html", p)
		if err != nil {
			return err
		}
		s.pages[strings.TrimSuffix(filepath.Base(p), ".html")] = t
	}
	// Partials rendered on their own for htmx swaps.
	t, err := template.New("partials").Funcs(funcs).ParseFS(assets, "templates/partials.html")
	if err != nil {
		return err
	}
	s.pages["_partials"] = t
	return nil
}

// Handler wires routes, auth and cross-origin (CSRF) protection.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	static, _ := fs.Sub(assets, "static")
	mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServerFS(static)))
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) })
	mux.HandleFunc("GET /login", s.loginPage)
	mux.HandleFunc("POST /login", s.login)
	mux.HandleFunc("GET /api/v1/certs/{id}/{format}", s.pullAPI)

	auth := http.NewServeMux()
	auth.HandleFunc("POST /logout", s.logout)
	auth.HandleFunc("GET /{$}", s.dashboard)
	auth.HandleFunc("GET /certs", s.inventory)
	auth.HandleFunc("GET /certs/new", s.newPage)
	auth.HandleFunc("POST /certs/new", s.create)
	auth.HandleFunc("POST /certs/check", s.check)
	auth.HandleFunc("GET /csr", s.csrPage)
	auth.HandleFunc("POST /csr/parse", s.csrParse)
	auth.HandleFunc("POST /csr", s.csrSubmit)
	auth.HandleFunc("GET /certs/{id}", s.detail)
	auth.HandleFunc("GET /certs/{id}/progress", s.progress)
	auth.HandleFunc("POST /certs/{id}/download", s.download)
	auth.HandleFunc("POST /certs/{id}/renew", s.renew)
	auth.HandleFunc("POST /certs/{id}/delete", s.delete)
	auth.HandleFunc("POST /certs/{id}/hooks", s.hookCreate)
	auth.HandleFunc("POST /hooks/fields", s.hookFields)
	auth.HandleFunc("POST /hooks/{hid}/run", s.hookRun)
	auth.HandleFunc("POST /hooks/{hid}/delete", s.hookDelete)
	auth.HandleFunc("GET /ca", s.caPage)
	auth.HandleFunc("GET /ca/{file}", s.caFile)
	auth.HandleFunc("GET /audit", s.audit)
	mux.Handle("/", s.requireLogin(auth))

	return http.NewCrossOriginProtection().Handler(securityHeaders(mux))
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "same-origin")
		h.Set("Content-Security-Policy", "default-src 'self'; style-src 'self'; script-src 'self'; img-src 'self' data:")
		next.ServeHTTP(w, r)
	})
}

// --- sessions ---

func (s *Server) sign(exp int64) string {
	m := hmac.New(sha256.New, s.sessionKey)
	m.Write([]byte(strconv.FormatInt(exp, 10)))
	return strconv.FormatInt(exp, 10) + "." + base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}

func (s *Server) validSession(r *http.Request) bool {
	c, err := r.Cookie(sessionCookie)
	if err != nil {
		return false
	}
	expStr, _, ok := strings.Cut(c.Value, ".")
	exp, err := strconv.ParseInt(expStr, 10, 64)
	if !ok || err != nil || time.Now().Unix() > exp {
		return false
	}
	return hmac.Equal([]byte(c.Value), []byte(s.sign(exp)))
}

func (s *Server) requireLogin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.validSession(r) {
			if r.Header.Get("HX-Request") != "" {
				w.Header().Set("HX-Redirect", "/login")
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) setCookie(w http.ResponseWriter, value string, maxAge int) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    value,
		Path:     "/",
		MaxAge:   maxAge,
		HttpOnly: true,
		Secure:   !s.cfg.InsecureCookie,
		SameSite: http.SameSiteLaxMode,
	})
}

func (s *Server) loginPage(w http.ResponseWriter, r *http.Request) {
	if s.validSession(r) {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	s.render(w, r, "login", map[string]any{})
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	pw := r.FormValue("password")
	want := s.cfg.CurrentPassword()
	if want == "" || subtle.ConstantTimeCompare([]byte(pw), []byte(want)) != 1 {
		s.record(r, "login-failed", "", "")
		time.Sleep(time.Second) // slow down guessing
		w.WriteHeader(http.StatusUnauthorized)
		s.render(w, r, "login", map[string]any{"Error": "Wrong password"})
		return
	}
	s.setCookie(w, s.sign(time.Now().Add(sessionTTL).Unix()), int(sessionTTL.Seconds()))
	s.record(r, "login", "", "")
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	s.setCookie(w, "", -1)
	s.record(r, "logout", "", "")
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// --- helpers ---

func remote(r *http.Request) string {
	if f := r.Header.Get("X-Forwarded-For"); f != "" {
		return strings.TrimSpace(strings.Split(f, ",")[0])
	}
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	return host
}

func (s *Server) record(r *http.Request, action, target, detail string) {
	if err := s.store.Log(action, target, detail, remote(r)); err != nil {
		s.log.Error("audit log write failed", "err", err)
	}
	s.log.Info("audit", "action", action, "target", target, "detail", detail, "remote", remote(r))
}

func (s *Server) render(w http.ResponseWriter, r *http.Request, page string, data map[string]any) {
	t, ok := s.pages[page]
	if !ok {
		http.Error(w, "unknown page "+page, http.StatusInternalServerError)
		return
	}
	data["Authed"] = s.validSession(r)
	data["Path"] = r.URL.Path
	data["PublicIssuer"] = s.cfg.PublicIssuer
	data["Staging"] = strings.Contains(s.cfg.PublicIssuer, "staging")
	data["InternalEnabled"] = s.internal != nil
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := t.ExecuteTemplate(w, "layout", data); err != nil {
		s.log.Error("render", "page", page, "err", err)
	}
}

func (s *Server) partial(w http.ResponseWriter, name string, data any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.pages["_partials"].ExecuteTemplate(w, name, data); err != nil {
		s.log.Error("render partial", "name", name, "err", err)
	}
}

func (s *Server) fail(w http.ResponseWriter, r *http.Request, status int, err error) {
	s.log.Warn("request failed", "path", r.URL.Path, "err", err)
	w.WriteHeader(status)
	s.render(w, r, "error", map[string]any{"Status": status, "Error": err.Error()})
}
