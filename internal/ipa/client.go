// Package ipa is a minimal FreeIPA JSON-RPC client: service-account calls with
// session cookies and server failover, plus user password checks.
package ipa

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

// Error is an error returned by the IPA API itself (as opposed to transport errors).
type Error struct {
	Code    int    `json:"code"`
	Name    string `json:"name"`
	Message string `json:"message"`
}

func (e *Error) Error() string { return fmt.Sprintf("IPA %s (%d): %s", e.Name, e.Code, e.Message) }

func code(err error) int {
	var e *Error
	if errors.As(err, &e) {
		return e.Code
	}
	return 0
}

func IsNotFound(err error) bool     { return code(err) == 4001 }
func IsDuplicate(err error) bool    { return code(err) == 4002 }
func IsEmptyModlist(err error) bool { return code(err) == 4202 }

var (
	ErrInvalidCredentials = errors.New("invalid username or password")
	ErrPasswordExpired    = errors.New("password expired; change it in noggin first")
)

type Options struct {
	Servers    []string // host or host:port
	CACertFile string   // added to the system roots; empty = system roots only
	RootCAs    *x509.CertPool
	User       string
	Password   string
	Timeout    time.Duration
}

type Client struct {
	servers  []string
	user     string
	password string
	api      *http.Client // with cookie jar (service account session)
	plain    *http.Client // no jar (user password checks)

	mu        sync.Mutex
	preferred int
}

func New(o Options) (*Client, error) {
	if len(o.Servers) == 0 {
		return nil, errors.New("ipa: no servers")
	}
	pool := o.RootCAs
	if pool == nil {
		var err error
		if pool, err = x509.SystemCertPool(); err != nil || pool == nil {
			pool = x509.NewCertPool()
		}
		if o.CACertFile != "" {
			pem, err := os.ReadFile(o.CACertFile)
			if err != nil {
				return nil, fmt.Errorf("ipa: CA file: %w", err)
			}
			if !pool.AppendCertsFromPEM(pem) {
				return nil, fmt.Errorf("ipa: no certificates in %s", o.CACertFile)
			}
		}
	}
	if o.Timeout == 0 {
		o.Timeout = 20 * time.Second
	}
	tr := &http.Transport{
		Proxy:               nil, // IPA is always reached directly
		TLSClientConfig:     &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
		MaxIdleConnsPerHost: 4,
		IdleConnTimeout:     90 * time.Second,
	}
	jar, _ := cookiejar.New(nil)
	return &Client{
		servers:  o.Servers,
		user:     o.User,
		password: o.Password,
		api:      &http.Client{Transport: tr, Jar: jar, Timeout: o.Timeout},
		plain:    &http.Client{Transport: tr, Timeout: o.Timeout},
	}, nil
}

// order returns servers starting with the last one that worked.
func (c *Client) order() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	n := len(c.servers)
	out := make([]string, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, c.servers[(c.preferred+i)%n])
	}
	return out
}

func (c *Client) prefer(server string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for i, s := range c.servers {
		if s == server {
			c.preferred = i
		}
	}
}

func base(server string) string { return "https://" + server + "/ipa" }

// Call runs one API command as the service account and returns its "result" object.
func (c *Client) Call(ctx context.Context, method string, args []any, opts map[string]any) (map[string]any, error) {
	if args == nil {
		args = []any{}
	}
	if opts == nil {
		opts = map[string]any{}
	}
	body, err := json.Marshal(map[string]any{"method": method, "params": []any{args, opts}, "id": 0})
	if err != nil {
		return nil, err
	}
	var lastErr error
	for _, s := range c.order() {
		res, err := c.callServer(ctx, s, method, body)
		var apiErr *Error
		if err == nil || errors.As(err, &apiErr) {
			c.prefer(s)
			return res, err
		}
		lastErr = err
	}
	return nil, lastErr
}

func (c *Client) callServer(ctx context.Context, server, method string, body []byte) (map[string]any, error) {
	for attempt := 0; attempt < 2; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, base(server)+"/session/json", bytes.NewReader(body))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json")
		req.Header.Set("Referer", base(server))
		resp, err := c.api.Do(req)
		if err != nil {
			return nil, err
		}
		data, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
		resp.Body.Close()
		if err != nil {
			return nil, err
		}
		if resp.StatusCode == http.StatusUnauthorized && attempt == 0 {
			if err := c.login(ctx, server); err != nil {
				return nil, err
			}
			continue
		}
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("ipa %s: %s: HTTP %d", server, method, resp.StatusCode)
		}
		var out struct {
			Result map[string]any `json:"result"`
			Error  *Error         `json:"error"`
		}
		if err := json.Unmarshal(data, &out); err != nil {
			return nil, fmt.Errorf("ipa %s: %s: %w", server, method, err)
		}
		if out.Error != nil {
			return nil, out.Error
		}
		return out.Result, nil
	}
	return nil, fmt.Errorf("ipa %s: service account session rejected", server)
}

func (c *Client) login(ctx context.Context, server string) error {
	status, reason, err := c.postLogin(ctx, c.api, server, c.user, c.password)
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		return fmt.Errorf("ipa %s: service account %s login failed: HTTP %d %s", server, c.user, status, reason)
	}
	return nil
}

func (c *Client) postLogin(ctx context.Context, hc *http.Client, server, user, password string) (int, string, error) {
	form := url.Values{"user": {user}, "password": {password}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base(server)+"/session/login_password", strings.NewReader(form.Encode()))
	if err != nil {
		return 0, "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "text/plain")
	req.Header.Set("Referer", base(server))
	resp, err := hc.Do(req)
	if err != nil {
		return 0, "", err
	}
	io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
	resp.Body.Close()
	return resp.StatusCode, resp.Header.Get("X-IPA-Rejection-Reason"), nil
}

// CheckPassword verifies a user's password (password+OTP for OTP users) against IPA.
func (c *Client) CheckPassword(ctx context.Context, user, password string) error {
	var lastErr error
	for _, s := range c.order() {
		status, reason, err := c.postLogin(ctx, c.plain, s, user, password)
		if err != nil {
			lastErr = err
			continue
		}
		switch {
		case status == http.StatusOK:
			return nil
		case status == http.StatusUnauthorized && reason == "password-expired":
			return ErrPasswordExpired
		case status == http.StatusUnauthorized:
			return ErrInvalidCredentials
		default:
			return fmt.Errorf("ipa %s: login check: HTTP %d %s", s, status, reason)
		}
	}
	return lastErr
}
