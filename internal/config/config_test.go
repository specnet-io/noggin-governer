package config

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

const sampleNoggin = `# noggin config
FREEIPA_DOMAIN = "idm.example.org"
FREEIPA_SERVERS = ["ipa1.idm.example.org", 'ipa2.idm.example.org',]  # two servers
FREEIPA_CACERT = "/etc/ipa/ca.crt"
FREEIPA_ADMIN_USER = "svc-noggin"
FREEIPA_ADMIN_PASSWORD = "p\"ss\\word"
SECRET_KEY = "0123456789abcdef0123456789abcdef-long"
MAIL_SERVER = "10.0.0.5"
MAIL_PORT = 2525
MAIL_DEFAULT_SENDER = "Noggin <no-reply@example.org>"
REGISTRATION_OPEN = True
BASSET_URL = "http://10.0.0.5:8081/basset"
SPAMCHECK_TOKEN_EXPIRATION = 20160
USER_DEFAULTS = {
    "locale": "en-US",   # comment inside a dict
    "timezone": "UTC",
    "status_note": "spamcheck_awaiting",
}
PASSWORD_POLICY = {"min": 12, "max": 122}
COMPUTED = 1 + 2
GOVERNER_APPROVER_GROUP = "account-approvers"
GOVERNER_PUBLIC_URL = "https://acctman.example.org/"
`

func TestParsePyConfig(t *testing.T) {
	got := ParsePyConfig(sampleNoggin)
	if !reflect.DeepEqual(got["FREEIPA_SERVERS"], []any{"ipa1.idm.example.org", "ipa2.idm.example.org"}) {
		t.Errorf("servers: %#v", got["FREEIPA_SERVERS"])
	}
	if got["FREEIPA_ADMIN_PASSWORD"] != `p"ss\word` {
		t.Errorf("escapes: %#v", got["FREEIPA_ADMIN_PASSWORD"])
	}
	if got["MAIL_PORT"] != int64(2525) || got["REGISTRATION_OPEN"] != true {
		t.Errorf("scalars: %#v %#v", got["MAIL_PORT"], got["REGISTRATION_OPEN"])
	}
	if d, _ := got["USER_DEFAULTS"].(map[string]any); d["status_note"] != "spamcheck_awaiting" {
		t.Errorf("multi-line dict: %#v", got["USER_DEFAULTS"])
	}
	if _, ok := got["COMPUTED"]; ok {
		t.Error("expressions must be skipped")
	}
}

func TestLoadPrecedence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "noggin.cfg")
	if err := os.WriteFile(path, []byte(sampleNoggin), 0o600); err != nil {
		t.Fatal(err)
	}
	env := map[string]string{
		"GOVERNER_NOGGIN_CONFIG":        path,
		"GOVERNER_MANAGED_GROUPS_GROUP": "custom-managed",
	}
	cfg, err := Load(func(k string) string { return env[k] })
	if err != nil {
		t.Fatal(err)
	}
	if cfg.IPAUser != "svc-noggin" || len(cfg.IPAServers) != 2 || cfg.MailPort != 2525 {
		t.Errorf("noggin settings not reused: %+v", cfg)
	}
	if cfg.ApproverGroup != "account-approvers" || cfg.ManagerGroup != "account-approvers" {
		t.Errorf("GOVERNER_ key from noggin.cfg: %q %q", cfg.ApproverGroup, cfg.ManagerGroup)
	}
	if cfg.ContainerGroup != "custom-managed" {
		t.Errorf("env must win: %q", cfg.ContainerGroup)
	}
	if cfg.PublicURL != "https://acctman.example.org" {
		t.Errorf("public url: %q", cfg.PublicURL)
	}
	if !cfg.MailEnabled || len(cfg.Warnings) != 0 {
		t.Errorf("mail=%v warnings=%v", cfg.MailEnabled, cfg.Warnings)
	}
}

func TestWarnings(t *testing.T) {
	path := filepath.Join(t.TempDir(), "noggin.cfg")
	os.WriteFile(path, []byte(`FREEIPA_SERVERS = ["ipa"]
FREEIPA_ADMIN_USER = "u"
FREEIPA_ADMIN_PASSWORD = "p"
SECRET_KEY = "0123456789abcdef0123456789abcdef"
`), 0o600)
	cfg, err := Load(func(k string) string {
		if k == "GOVERNER_NOGGIN_CONFIG" {
			return path
		}
		return ""
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Warnings) != 3 || !strings.Contains(cfg.Warnings[0], "BASSET_URL") {
		t.Errorf("warnings: %v", cfg.Warnings)
	}
}

func TestValidGroupName(t *testing.T) {
	for name, want := range map[string]bool{"dev-team": true, "a": false, "Dev": false, "-x": false, "web.ops_1": true} {
		if ValidGroupName(name) != want {
			t.Errorf("%q: want %v", name, want)
		}
	}
}
