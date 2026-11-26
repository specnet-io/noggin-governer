// Package config builds the runtime settings. Precedence, highest first:
//  1. environment variable GOVERNER_<NAME>
//  2. GOVERNER_<NAME> in noggin's config file
//  3. the matching noggin setting (FREEIPA_*, MAIL_*, SECRET_KEY)
//  4. built-in default
package config

import (
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"fmt"
	"net/mail"
	"net/netip"
	"net/url"
	"os"
	"strconv"
	"strings"
)

type Config struct {
	NogginConfigPath string
	NogginFound      bool

	Listen     string // web UI (behind the reverse proxy)
	HookListen string // noggin -> governer (BASSET_URL); keep it off the proxy
	DataDir    string

	IPAServers  []string
	IPACACert   string
	IPAUser     string
	IPAPassword string

	SessionKey []byte // derived from GOVERNER_SECRET_KEY or noggin's SECRET_KEY

	MailServer  string
	MailPort    int
	MailFrom    string // RFC 5322 From header, e.g. "Noggin <no-reply@example.org>"
	MailEnabled bool

	ApproverGroup  string
	ManagerGroup   string
	ContainerGroup string

	PublicURL   string // this site, for links in emails
	NogginURL   string // noggin's public URL; derived from the callback when empty
	CallbackURL string // override for noggin's /register/spamcheck-hook

	TrustedProxies  []netip.Prefix
	InsecureCookies bool

	// Problems found in noggin's config that weaken the approval workflow.
	Warnings []string
}

const (
	DefaultApproverGroup  = "self-service-managers"
	DefaultContainerGroup = "self-service-managed-groups"
)

type loader struct {
	getenv func(string) string
	noggin map[string]any
}

func (l loader) str(name, nogginKey, def string) string {
	if v := strings.TrimSpace(l.getenv("GOVERNER_" + name)); v != "" {
		return v
	}
	if v := toString(l.noggin["GOVERNER_"+name]); v != "" {
		return v
	}
	if nogginKey != "" {
		if v := toString(l.noggin[nogginKey]); v != "" {
			return v
		}
	}
	return def
}

func (l loader) list(name, nogginKey string) []string {
	if v := strings.TrimSpace(l.getenv("GOVERNER_" + name)); v != "" {
		return splitList(v)
	}
	for _, k := range []string{"GOVERNER_" + name, nogginKey} {
		switch v := l.noggin[k].(type) {
		case []any:
			var out []string
			for _, x := range v {
				if s := toString(x); s != "" {
					out = append(out, s)
				}
			}
			if len(out) > 0 {
				return out
			}
		case string:
			if v != "" {
				return splitList(v)
			}
		}
	}
	return nil
}

func (l loader) boolean(name string, def bool) (bool, error) {
	s := l.str(name, "", "")
	if s == "" {
		return def, nil
	}
	b, err := strconv.ParseBool(s)
	if err != nil {
		return false, fmt.Errorf("GOVERNER_%s: %w", name, err)
	}
	return b, nil
}

func toString(v any) string {
	switch x := v.(type) {
	case nil:
		return ""
	case string:
		return strings.TrimSpace(x)
	case bool:
		return strconv.FormatBool(x)
	default:
		return fmt.Sprint(x)
	}
}

func splitList(s string) []string {
	var out []string
	for _, f := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' || r == '\n' }) {
		if f = strings.TrimSpace(f); f != "" {
			out = append(out, f)
		}
	}
	return out
}

// Load reads noggin's config file (if present) and the environment.
func Load(getenv func(string) string) (*Config, error) {
	path := strings.TrimSpace(getenv("GOVERNER_NOGGIN_CONFIG"))
	if path == "" {
		path = "/etc/noggin/noggin.cfg"
	}
	cfg := &Config{NogginConfigPath: path}
	noggin := map[string]any{}
	if raw, err := os.ReadFile(path); err == nil {
		noggin = ParsePyConfig(string(raw))
		cfg.NogginFound = true
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("reading noggin config %s: %w", path, err)
	}
	l := loader{getenv: getenv, noggin: noggin}

	cfg.Listen = l.str("LISTEN", "", ":8080")
	cfg.HookListen = l.str("HOOK_LISTEN", "", ":8081")
	cfg.DataDir = l.str("DATA_DIR", "", "/data")

	cfg.IPAServers = l.list("IPA_SERVERS", "FREEIPA_SERVERS")
	cfg.IPACACert = l.str("IPA_CACERT", "FREEIPA_CACERT", "")
	cfg.IPAUser = l.str("IPA_USER", "FREEIPA_ADMIN_USER", "")
	cfg.IPAPassword = l.str("IPA_PASSWORD", "FREEIPA_ADMIN_PASSWORD", "")

	secret := l.str("SECRET_KEY", "SECRET_KEY", "")
	if len(secret) < 32 {
		return nil, errors.New("a secret of at least 32 characters is required: GOVERNER_SECRET_KEY, or SECRET_KEY in noggin's config")
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte("noggin-governer session key v1"))
	cfg.SessionKey = mac.Sum(nil)

	cfg.MailServer = l.str("MAIL_SERVER", "MAIL_SERVER", "")
	port, err := strconv.Atoi(l.str("MAIL_PORT", "MAIL_PORT", "25"))
	if err != nil {
		return nil, fmt.Errorf("mail port: %w", err)
	}
	cfg.MailPort = port
	cfg.MailFrom = l.str("MAIL_SENDER", "MAIL_DEFAULT_SENDER", "")
	if cfg.MailEnabled, err = l.boolean("MAIL_ENABLED", cfg.MailServer != ""); err != nil {
		return nil, err
	}

	cfg.ApproverGroup = l.str("APPROVER_GROUP", "", DefaultApproverGroup)
	cfg.ManagerGroup = l.str("GROUP_MANAGER_GROUP", "", cfg.ApproverGroup)
	cfg.ContainerGroup = l.str("MANAGED_GROUPS_GROUP", "", DefaultContainerGroup)

	cfg.PublicURL = strings.TrimRight(l.str("PUBLIC_URL", "", ""), "/")
	cfg.NogginURL = strings.TrimRight(l.str("NOGGIN_URL", "", ""), "/")
	cfg.CallbackURL = l.str("NOGGIN_CALLBACK_URL", "", "")

	for _, p := range l.list("TRUSTED_PROXIES", "") {
		pfx, err := netip.ParsePrefix(p)
		if err != nil {
			addr, aerr := netip.ParseAddr(p)
			if aerr != nil {
				return nil, fmt.Errorf("GOVERNER_TRUSTED_PROXIES: %q: %w", p, err)
			}
			pfx = netip.PrefixFrom(addr, addr.BitLen())
		}
		cfg.TrustedProxies = append(cfg.TrustedProxies, pfx)
	}
	if cfg.InsecureCookies, err = l.boolean("INSECURE_COOKIES", false); err != nil {
		return nil, err
	}

	if err := cfg.validate(); err != nil {
		return nil, err
	}
	cfg.Warnings = nogginWarnings(cfg.NogginFound, noggin)
	return cfg, nil
}

func (c *Config) validate() error {
	var errs []string
	if len(c.IPAServers) == 0 {
		errs = append(errs, "IPA servers: set FREEIPA_SERVERS in noggin's config or GOVERNER_IPA_SERVERS")
	}
	if c.IPAUser == "" || c.IPAPassword == "" {
		errs = append(errs, "IPA service account: set FREEIPA_ADMIN_USER/PASSWORD in noggin's config or GOVERNER_IPA_USER/PASSWORD")
	}
	if c.MailEnabled {
		if c.MailServer == "" {
			errs = append(errs, "mail is enabled but no server is set (MAIL_SERVER / GOVERNER_MAIL_SERVER)")
		}
		if _, err := mail.ParseAddress(c.MailFrom); err != nil {
			errs = append(errs, fmt.Sprintf("mail sender %q: %v (MAIL_DEFAULT_SENDER / GOVERNER_MAIL_SENDER)", c.MailFrom, err))
		}
	}
	for name, u := range map[string]string{"GOVERNER_PUBLIC_URL": c.PublicURL, "GOVERNER_NOGGIN_URL": c.NogginURL, "GOVERNER_NOGGIN_CALLBACK_URL": c.CallbackURL} {
		if u == "" {
			continue
		}
		if p, err := url.Parse(u); err != nil || (p.Scheme != "https" && p.Scheme != "http") || p.Host == "" {
			errs = append(errs, name+" must be an absolute http(s) URL")
		}
	}
	for _, g := range []string{c.ApproverGroup, c.ManagerGroup, c.ContainerGroup} {
		if !ValidGroupName(g) {
			errs = append(errs, fmt.Sprintf("invalid group name %q", g))
		}
	}
	if len(errs) > 0 {
		return errors.New(strings.Join(errs, "; "))
	}
	return nil
}

// ValidGroupName is deliberately stricter than IPA: lowercase, starts with a letter or digit.
func ValidGroupName(s string) bool {
	if len(s) < 2 || len(s) > 64 {
		return false
	}
	for i, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
		case i > 0 && (r == '-' || r == '_' || r == '.'):
		default:
			return false
		}
	}
	return true
}

func nogginWarnings(found bool, n map[string]any) []string {
	if !found {
		return []string{"noggin's config file was not found, so its settings could not be checked"}
	}
	var w []string
	if toString(n["BASSET_URL"]) == "" {
		w = append(w, "noggin: BASSET_URL is not set, so new registrations skip approval")
	}
	status := ""
	if d, ok := n["USER_DEFAULTS"].(map[string]any); ok {
		status = toString(d["status_note"])
	}
	if status == "" || status == "active" {
		w = append(w, `noggin: USER_DEFAULTS["status_note"] must be "spamcheck_awaiting"; with "active" a registrant can request the validation email before approval`)
	}
	if v, ok := n["SPAMCHECK_TOKEN_EXPIRATION"].(int64); !ok || v < 1440 {
		w = append(w, "noggin: SPAMCHECK_TOKEN_EXPIRATION is under a day; approvals after it expires fall back to emailing the registrant a link to finish")
	}
	return w
}
