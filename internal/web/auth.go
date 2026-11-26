package web

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/specnet-io/noggin-governer/internal/ipa"
)

const (
	sessionCookie = "governer_session"
	flashCookie   = "governer_flash"
	sessionTTL    = 8 * time.Hour
	approverTTL   = time.Minute
)

var usernameRe = regexp.MustCompile(`^[a-z_][a-z0-9_.-]{0,31}$`)

type session struct {
	User string `json:"u"`
	Exp  int64  `json:"e"`
	CSRF string `json:"c"`
}

type reqCtx struct {
	User     string
	Approver bool
	CSRF     string
}

func (s *Server) sign(payload string) string {
	m := hmac.New(sha256.New, s.cfg.SessionKey)
	m.Write([]byte(payload))
	return base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}

func (s *Server) setSession(w http.ResponseWriter, sess session) {
	raw, _ := json.Marshal(sess)
	payload := base64.RawURLEncoding.EncodeToString(raw)
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookie, Value: payload + "." + s.sign(payload), Path: "/",
		HttpOnly: true, Secure: !s.cfg.InsecureCookies, SameSite: http.SameSiteLaxMode,
		Expires: time.Unix(sess.Exp, 0),
	})
}

func (s *Server) readSession(r *http.Request) (session, bool) {
	c, err := r.Cookie(sessionCookie)
	if err != nil {
		return session{}, false
	}
	payload, sig, ok := strings.Cut(c.Value, ".")
	if !ok || !hmac.Equal([]byte(sig), []byte(s.sign(payload))) {
		return session{}, false
	}
	raw, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil {
		return session{}, false
	}
	var sess session
	if json.Unmarshal(raw, &sess) != nil || sess.User == "" || time.Now().Unix() > sess.Exp {
		return session{}, false
	}
	return sess, true
}

func clearCookie(w http.ResponseWriter, name string, secure bool) {
	http.SetCookie(w, &http.Cookie{Name: name, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, Secure: secure, SameSite: http.SameSiteLaxMode})
}

func randToken() string {
	b := make([]byte, 24)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// isApprover checks IPA group membership (direct or nested), cached briefly.
func (s *Server) isApprover(ctx context.Context, user string) (bool, error) {
	s.approverMu.Lock()
	if e, ok := s.approverCache[user]; ok && time.Since(e.at) < approverTTL {
		s.approverMu.Unlock()
		return e.ok, nil
	}
	s.approverMu.Unlock()
	u, err := s.ipa.User(ctx, user)
	if err != nil {
		return false, err
	}
	ok := false
	for _, g := range u.Groups {
		if g == s.cfg.ApproverGroup {
			ok = true
		}
	}
	s.approverMu.Lock()
	s.approverCache[user] = approverEntry{ok: ok, at: time.Now()}
	s.approverMu.Unlock()
	return ok, nil
}

// authed wraps a handler: valid session required, CSRF on POST, approver role if asked.
func (s *Server) authed(approverOnly bool, h func(http.ResponseWriter, *http.Request, *reqCtx)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sess, ok := s.readSession(r)
		if !ok {
			next := r.URL.Path
			if r.Method != http.MethodGet {
				next = "/"
			}
			http.Redirect(w, r, "/login?next="+next, http.StatusSeeOther)
			return
		}
		if r.Method == http.MethodPost {
			if subtle.ConstantTimeCompare([]byte(r.PostFormValue("csrf")), []byte(sess.CSRF)) != 1 {
				s.fail(w, r, &reqCtx{User: sess.User, CSRF: sess.CSRF}, http.StatusForbidden, "The form expired. Go back, reload the page and try again.")
				return
			}
		}
		approver, err := s.isApprover(r.Context(), sess.User)
		if err != nil {
			if ipa.IsNotFound(err) { // user deleted or still staged
				clearCookie(w, sessionCookie, !s.cfg.InsecureCookies)
				http.Redirect(w, r, "/login", http.StatusSeeOther)
				return
			}
			slog.Error("approver check", "user", sess.User, "err", err)
			s.fail(w, r, &reqCtx{User: sess.User, CSRF: sess.CSRF}, http.StatusBadGateway, "Could not reach FreeIPA. Try again shortly.")
			return
		}
		rc := &reqCtx{User: sess.User, Approver: approver, CSRF: sess.CSRF}
		if approverOnly && !approver {
			s.fail(w, r, rc, http.StatusForbidden, "This page is for members of the "+s.cfg.ApproverGroup+" group.")
			return
		}
		h(w, r, rc)
	}
}

func (s *Server) loginForm(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.readSession(r); ok {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	s.render(w, http.StatusOK, "login", &view{Title: "Sign in", Version: s.Version, Data: map[string]string{"Next": safeNext(r.URL.Query().Get("next"))}})
}

func safeNext(n string) string {
	if !strings.HasPrefix(n, "/") || strings.HasPrefix(n, "//") || strings.Contains(n, "\\") {
		return "/"
	}
	return n
}

func (s *Server) loginSubmit(w http.ResponseWriter, r *http.Request) {
	user := strings.ToLower(strings.TrimSpace(r.PostFormValue("username")))
	pass := r.PostFormValue("password")
	next := safeNext(r.PostFormValue("next"))
	ip := s.clientIP(r)
	fail := func(status int, msg string) {
		s.render(w, status, "login", &view{Title: "Sign in", Version: s.Version, Flash: msg, FlashKind: "error",
			Data: map[string]string{"Next": next, "Username": user}})
	}
	if !usernameRe.MatchString(user) || pass == "" {
		fail(http.StatusBadRequest, "Enter your username and password.")
		return
	}
	if !s.limit.allow("ip:"+ip) || !s.limit.allow("user:"+user) {
		fail(http.StatusTooManyRequests, "Too many failed sign-ins. Wait a few minutes and try again.")
		return
	}
	if err := s.ipa.CheckPassword(r.Context(), user, pass); err != nil {
		switch {
		case errors.Is(err, ipa.ErrInvalidCredentials):
			s.limit.fail("ip:" + ip)
			s.limit.fail("user:" + user)
			slog.Info("login failed", "user", user, "ip", ip)
			fail(http.StatusUnauthorized, "Wrong username or password. Accounts with a one-time code: append the code to the password.")
		case errors.Is(err, ipa.ErrPasswordExpired):
			fail(http.StatusUnauthorized, "Your password has expired. Change it in noggin, then sign in here.")
		default:
			slog.Error("login check", "user", user, "err", err)
			fail(http.StatusBadGateway, "Could not reach FreeIPA. Try again shortly.")
		}
		return
	}
	s.limit.reset("user:" + user)
	s.setSession(w, session{User: user, Exp: time.Now().Add(sessionTTL).Unix(), CSRF: randToken()})
	slog.Info("login", "user", user, "ip", ip)
	http.Redirect(w, r, next, http.StatusSeeOther)
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	sess, ok := s.readSession(r)
	if ok && subtle.ConstantTimeCompare([]byte(r.PostFormValue("csrf")), []byte(sess.CSRF)) != 1 {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	clearCookie(w, sessionCookie, !s.cfg.InsecureCookies)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// ---- flash messages (one-shot cookie) ----

func (s *Server) flash(w http.ResponseWriter, kind, msg string) {
	http.SetCookie(w, &http.Cookie{Name: flashCookie, Value: base64.RawURLEncoding.EncodeToString([]byte(kind + "|" + msg)),
		Path: "/", HttpOnly: true, Secure: !s.cfg.InsecureCookies, SameSite: http.SameSiteLaxMode, MaxAge: 60})
}

func (s *Server) takeFlash(w http.ResponseWriter, r *http.Request) (string, string) {
	c, err := r.Cookie(flashCookie)
	if err != nil {
		return "", ""
	}
	clearCookie(w, flashCookie, !s.cfg.InsecureCookies)
	raw, err := base64.RawURLEncoding.DecodeString(c.Value)
	if err != nil {
		return "", ""
	}
	kind, msg, _ := strings.Cut(string(raw), "|")
	if kind != "ok" && kind != "error" {
		kind = "error"
	}
	return kind, msg
}

// ---- login rate limiter ----

type limiter struct {
	mu     sync.Mutex
	max    int
	window time.Duration
	hits   map[string][]time.Time
}

func newLimiter(max int, window time.Duration) *limiter {
	return &limiter{max: max, window: window, hits: map[string][]time.Time{}}
}

func (l *limiter) prune(key string) []time.Time {
	cut := time.Now().Add(-l.window)
	h := l.hits[key]
	i := 0
	for i < len(h) && h[i].Before(cut) {
		i++
	}
	h = h[i:]
	if len(h) == 0 {
		delete(l.hits, key)
	} else {
		l.hits[key] = h
	}
	return h
}

func (l *limiter) allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.prune(key)) < l.max
}

func (l *limiter) fail(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.hits[key] = append(l.prune(key), time.Now())
}

func (l *limiter) reset(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.hits, key)
}
