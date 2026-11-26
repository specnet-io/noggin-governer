// Package web serves the approver UI (Listen) and the noggin hook (HookListen).
package web

import (
	"crypto/tls"
	"crypto/x509"
	"embed"
	"fmt"
	"html/template"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/specnet-io/noggin-governer/internal/config"
	"github.com/specnet-io/noggin-governer/internal/ipa"
	"github.com/specnet-io/noggin-governer/internal/mail"
	"github.com/specnet-io/noggin-governer/internal/store"
)

//go:embed templates/*.html static/*
var assets embed.FS

type Server struct {
	cfg     *config.Config
	ipa     *ipa.Client
	store   *store.Store
	mail    *mail.Mailer
	http    *http.Client // noggin callback
	pages   map[string]*template.Template
	limit   *limiter
	Version string

	approverMu    sync.Mutex
	approverCache map[string]approverEntry
}

type approverEntry struct {
	ok bool
	at time.Time
}

func New(cfg *config.Config, ic *ipa.Client, st *store.Store, m *mail.Mailer, version string) (*Server, error) {
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}
	if cfg.IPACACert != "" {
		if pem, err := os.ReadFile(cfg.IPACACert); err == nil {
			pool.AppendCertsFromPEM(pem)
		}
	}
	s := &Server{
		cfg:   cfg,
		ipa:   ic,
		store: st,
		mail:  m,
		http: &http.Client{
			Timeout: 30 * time.Second,
			Transport: &http.Transport{
				Proxy:           http.ProxyFromEnvironment,
				TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
			},
		},
		limit:         newLimiter(5, 10*time.Minute),
		Version:       version,
		approverCache: map[string]approverEntry{},
	}
	if err := s.loadTemplates(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Server) loadTemplates() error {
	funcs := template.FuncMap{
		"ts": func(t time.Time) string {
			if t.IsZero() {
				return "—"
			}
			return t.UTC().Format("2006-01-02 15:04 UTC")
		},
		"join": strings.Join,
	}
	s.pages = map[string]*template.Template{}
	for _, p := range []string{"login", "users", "group_requests", "groups", "blocklist", "activity", "request_group", "error"} {
		t, err := template.New("").Funcs(funcs).ParseFS(assets, "templates/layout.html", "templates/"+p+".html")
		if err != nil {
			return fmt.Errorf("template %s: %w", p, err)
		}
		s.pages[p] = t
	}
	return nil
}

// UIHandler is the approver/user website.
func (s *Server) UIHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.healthz)
	mux.Handle("GET /static/", http.FileServerFS(assets))

	mux.HandleFunc("GET /login", s.loginForm)
	mux.HandleFunc("POST /login", s.loginSubmit)
	mux.HandleFunc("POST /logout", s.logout)

	mux.HandleFunc("GET /{$}", s.authed(false, s.home))
	mux.HandleFunc("GET /request-group", s.authed(false, s.requestGroupForm))
	mux.HandleFunc("POST /request-group", s.authed(false, s.requestGroupSubmit))

	mux.HandleFunc("GET /users", s.authed(true, s.usersPage))
	mux.HandleFunc("POST /users/{uid}/approve", s.authed(true, s.userApprove))
	mux.HandleFunc("POST /users/{uid}/deny", s.authed(true, s.userDeny))

	mux.HandleFunc("GET /group-requests", s.authed(true, s.groupRequestsPage))
	mux.HandleFunc("POST /group-requests/{id}/approve", s.authed(true, s.groupRequestApprove))
	mux.HandleFunc("POST /group-requests/{id}/deny", s.authed(true, s.groupRequestDeny))

	mux.HandleFunc("GET /groups", s.authed(true, s.groupsPage))
	mux.HandleFunc("POST /groups/{name}/owner", s.authed(true, s.groupOwner))
	mux.HandleFunc("POST /groups/{name}/rename", s.authed(true, s.groupRename))
	mux.HandleFunc("POST /groups/{name}/delete", s.authed(true, s.groupDelete))

	mux.HandleFunc("GET /blocklist", s.authed(true, s.blocklistPage))
	mux.HandleFunc("POST /blocklist/add", s.authed(true, s.blocklistAdd))
	mux.HandleFunc("POST /blocklist/remove", s.authed(true, s.blocklistRemove))

	mux.HandleFunc("GET /activity", s.authed(true, s.activityPage))
	return securityHeaders(mux)
}

// HookHandler is the endpoint noggin calls (BASSET_URL). Do not publish it.
func (s *Server) HookHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.healthz)
	mux.HandleFunc("POST /basset", s.bassetHook)
	return mux
}

func (s *Server) healthz(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	w.Write([]byte("ok\n"))
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", "default-src 'none'; style-src 'self'; img-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "same-origin")
		h.Set("X-Frame-Options", "DENY")
		if !strings.HasPrefix(r.URL.Path, "/static/") {
			h.Set("Cache-Control", "no-store")
		}
		next.ServeHTTP(w, r)
	})
}

// clientIP honours X-Forwarded-For only from GOVERNER_TRUSTED_PROXIES.
func (s *Server) clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	addr, err := netip.ParseAddr(host)
	if err != nil || !s.trusted(addr) {
		return host
	}
	parts := strings.Split(r.Header.Get("X-Forwarded-For"), ",")
	for i := len(parts) - 1; i >= 0; i-- {
		p := strings.TrimSpace(parts[i])
		a, err := netip.ParseAddr(p)
		if err != nil {
			continue
		}
		if !s.trusted(a) {
			return p
		}
	}
	return host
}

func (s *Server) trusted(a netip.Addr) bool {
	for _, p := range s.cfg.TrustedProxies {
		if p.Contains(a.Unmap()) {
			return true
		}
	}
	return false
}

func (s *Server) render(w http.ResponseWriter, status int, page string, data *view) {
	t := s.pages[page]
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	if err := t.ExecuteTemplate(w, "layout", data); err != nil {
		slog.Error("render", "page", page, "err", err)
	}
}

// view is passed to every template.
type view struct {
	Title     string
	Tab       string
	User      string
	Approver  bool
	CSRF      string
	Flash     string
	FlashKind string
	Warnings  []string
	Version   string
	Data      any
}
