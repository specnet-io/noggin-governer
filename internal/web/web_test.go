package web

import (
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"

	"github.com/specnet-io/noggin-governer/internal/config"
	"github.com/specnet-io/noggin-governer/internal/ipa"
	"github.com/specnet-io/noggin-governer/internal/mail"
	"github.com/specnet-io/noggin-governer/internal/store"
)

// fakeIPA implements the IPA JSON-RPC commands noggin-governer uses, in memory.
type fakeIPA struct {
	mu        sync.Mutex
	passwords map[string]string
	users     map[string]map[string]any // uid -> attrs
	stage     map[string]map[string]any
	groups    map[string]*fakeGroup
	calls     []string
}

type fakeGroup struct {
	desc                     string
	fas, posix               bool
	users, groups            []string
	managerUsers, managerGrp []string
}

func newFakeIPA() *fakeIPA {
	f := &fakeIPA{
		passwords: map[string]string{"svc": "svcpw", "alice": "alicepw", "bob": "bobpw"},
		users: map[string]map[string]any{
			"svc":   {"uid": []any{"svc"}},
			"alice": {"uid": []any{"alice"}, "cn": []any{"Alice"}, "mail": []any{"alice@example.org"}},
			"bob":   {"uid": []any{"bob"}, "cn": []any{"Bob"}, "mail": []any{"bob@example.org"}},
		},
		stage:  map[string]map[string]any{},
		groups: map[string]*fakeGroup{"self-service-managers": {users: []string{"alice"}}},
	}
	return f
}

func list(xs []string) []any {
	out := make([]any, len(xs))
	for i, x := range xs {
		out[i] = x
	}
	return out
}

func strsOf(v any) []string {
	var out []string
	switch t := v.(type) {
	case []any:
		for _, x := range t {
			out = append(out, fmt.Sprint(x))
		}
	case string:
		out = []string{t}
	}
	return out
}

func remove(xs []string, drop []string) []string {
	var out []string
outer:
	for _, x := range xs {
		for _, d := range drop {
			if x == d {
				continue outer
			}
		}
		out = append(out, x)
	}
	return out
}

func (f *fakeIPA) groupsOf(uid string) []any {
	var out []string
	for name, g := range f.groups {
		for _, u := range g.users {
			if u == uid {
				out = append(out, name)
			}
		}
	}
	return list(out)
}

func (f *fakeIPA) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	switch r.URL.Path {
	case "/ipa/session/login_password":
		r.ParseForm()
		u, p := r.PostForm.Get("user"), r.PostForm.Get("password")
		if f.passwords[u] == "" || f.passwords[u] != p {
			w.Header().Set("X-IPA-Rejection-Reason", "invalid-password")
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if u == "svc" {
			http.SetCookie(w, &http.Cookie{Name: "ipa_session", Value: "ok", Path: "/ipa"})
		}
		return
	case "/ipa/session/json":
	default:
		http.NotFound(w, r)
		return
	}
	if c, err := r.Cookie("ipa_session"); err != nil || c.Value != "ok" {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	var req struct {
		Method string `json:"method"`
		Params []json.RawMessage
	}
	json.NewDecoder(r.Body).Decode(&req)
	var args []any
	opts := map[string]any{}
	json.Unmarshal(req.Params[0], &args)
	json.Unmarshal(req.Params[1], &opts)
	f.calls = append(f.calls, req.Method)
	name := ""
	if len(args) > 0 {
		name = fmt.Sprint(args[0])
	}
	res, ipaErr := f.call(req.Method, name, opts)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"result": res, "error": ipaErr, "id": 0})
}

func notFound(what string) map[string]any {
	return map[string]any{"code": 4001, "name": "NotFound", "message": what + " not found"}
}

func (f *fakeIPA) call(method, name string, opts map[string]any) (map[string]any, map[string]any) {
	switch method {
	case "user_show":
		u, ok := f.users[name]
		if !ok {
			return nil, notFound(name)
		}
		m := map[string]any{}
		for k, v := range u {
			m[k] = v
		}
		m["memberof_group"] = f.groupsOf(name)
		return map[string]any{"result": m}, nil
	case "stageuser_show":
		su, ok := f.stage[name]
		if !ok {
			return nil, notFound(name)
		}
		return map[string]any{"result": su}, nil
	case "stageuser_find":
		var out []any
		for _, su := range f.stage {
			out = append(out, su)
		}
		return map[string]any{"result": out}, nil
	case "stageuser_mod":
		su, ok := f.stage[name]
		if !ok {
			return nil, notFound(name)
		}
		if strsOf(su["fasstatusnote"])[0] == opts["fasstatusnote"] {
			return nil, map[string]any{"code": 4202, "name": "EmptyModlist", "message": "no modifications to be performed"}
		}
		su["fasstatusnote"] = []any{opts["fasstatusnote"]}
		return map[string]any{"result": su}, nil
	case "stageuser_del":
		if _, ok := f.stage[name]; !ok {
			return nil, notFound(name)
		}
		delete(f.stage, name)
		return map[string]any{}, nil
	case "group_show":
		g, ok := f.groups[name]
		if !ok {
			return nil, notFound(name)
		}
		m := map[string]any{"cn": []any{name}, "description": []any{g.desc}, "member_user": list(g.users), "member_group": list(g.groups),
			"membermanager_user": list(g.managerUsers), "membermanager_group": list(g.managerGrp), "objectclass": []any{"top", "groupofnames"}}
		if g.fas {
			m["objectclass"] = []any{"top", "groupofnames", "fasgroup"}
		}
		return map[string]any{"result": m}, nil
	case "group_add":
		if _, ok := f.groups[name]; ok {
			return nil, map[string]any{"code": 4002, "name": "DuplicateEntry", "message": "group already exists"}
		}
		f.groups[name] = &fakeGroup{desc: fmt.Sprint(opts["description"]), fas: opts["fasgroup"] == true, posix: opts["nonposix"] != true}
		return map[string]any{"result": map[string]any{}}, nil
	case "group_mod":
		g, ok := f.groups[name]
		if !ok {
			return nil, notFound(name)
		}
		if nn, ok := opts["rename"].(string); ok {
			delete(f.groups, name)
			f.groups[nn] = g
			for _, other := range f.groups { // IPA's referential integrity
				for i, m := range other.groups {
					if m == name {
						other.groups[i] = nn
					}
				}
			}
		}
		return map[string]any{"result": map[string]any{}}, nil
	case "group_del":
		if _, ok := f.groups[name]; !ok {
			return nil, notFound(name)
		}
		delete(f.groups, name)
		for _, other := range f.groups {
			other.groups = remove(other.groups, []string{name})
		}
		return map[string]any{}, nil
	case "group_add_member", "group_remove_member", "group_add_member_manager", "group_remove_member_manager":
		g, ok := f.groups[name]
		if !ok {
			return nil, notFound(name)
		}
		users, groups := strsOf(opts["user"]), strsOf(opts["group"])
		switch method {
		case "group_add_member":
			g.users, g.groups = append(g.users, users...), append(g.groups, groups...)
		case "group_remove_member":
			g.users, g.groups = remove(g.users, users), remove(g.groups, groups)
		case "group_add_member_manager":
			g.managerUsers, g.managerGrp = append(g.managerUsers, users...), append(g.managerGrp, groups...)
		case "group_remove_member_manager":
			g.managerUsers, g.managerGrp = remove(g.managerUsers, users), remove(g.managerGrp, groups)
		}
		return map[string]any{"failed": map[string]any{"member": map[string]any{"user": []any{}, "group": []any{}}}}, nil
	}
	return nil, map[string]any{"code": 900, "name": "CommandError", "message": "unknown command " + method}
}

type harness struct {
	t        *testing.T
	ipa      *fakeIPA
	ui, hook *httptest.Server
	store    *store.Store
	callback []map[string]string
	noggin   *httptest.Server
	mu       sync.Mutex
}

func newHarness(t *testing.T) *harness {
	h := &harness{t: t, ipa: newFakeIPA()}
	ipaSrv := httptest.NewTLSServer(h.ipa)
	t.Cleanup(ipaSrv.Close)
	h.noggin = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]string
		json.NewDecoder(r.Body).Decode(&body)
		h.mu.Lock()
		h.callback = append(h.callback, body)
		h.mu.Unlock()
		if body["token"] != "tok-carol" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		// noggin's hook sets the status itself.
		h.ipa.mu.Lock()
		h.ipa.stage["carol"]["fasstatusnote"] = []any{body["status"]}
		h.ipa.mu.Unlock()
		w.Write([]byte(`{"status":"success"}`))
	}))
	t.Cleanup(h.noggin.Close)

	pool := x509.NewCertPool()
	pool.AddCert(ipaSrv.Certificate())
	host := strings.TrimPrefix(ipaSrv.URL, "https://")
	ic, err := ipa.New(ipa.Options{Servers: []string{host}, RootCAs: pool, User: "svc", Password: "svcpw"})
	if err != nil {
		t.Fatal(err)
	}
	h.store, err = store.Open(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{
		SessionKey: []byte("0123456789abcdef0123456789abcdef"), ApproverGroup: config.DefaultApproverGroup,
		ManagerGroup: config.DefaultApproverGroup, ContainerGroup: config.DefaultContainerGroup, InsecureCookies: true,
	}
	srv, err := New(cfg, ic, h.store, &mail.Mailer{}, "test")
	if err != nil {
		t.Fatal(err)
	}
	h.ui = httptest.NewServer(srv.UIHandler())
	h.hook = httptest.NewServer(srv.HookHandler())
	t.Cleanup(h.ui.Close)
	t.Cleanup(h.hook.Close)
	return h
}

type browser struct {
	h    *harness
	c    *http.Client
	csrf string
}

var csrfRe = regexp.MustCompile(`name="csrf" value="([^"]+)"`)

func (h *harness) login(user, pass string) *browser {
	jar, _ := cookiejar.New(nil)
	b := &browser{h: h, c: &http.Client{Jar: jar}}
	resp, err := b.c.PostForm(h.ui.URL+"/login", url.Values{"username": {user}, "password": {pass}, "next": {"/"}})
	if err != nil {
		h.t.Fatal(err)
	}
	body := readBody(resp)
	if m := csrfRe.FindStringSubmatch(body); m != nil {
		b.csrf = m[1]
	}
	return b
}

func readBody(resp *http.Response) string {
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return string(b)
}

func (b *browser) get(path string) (int, string) {
	resp, err := b.c.Get(b.h.ui.URL + path)
	if err != nil {
		b.h.t.Fatal(err)
	}
	body := readBody(resp)
	if m := csrfRe.FindStringSubmatch(body); m != nil {
		b.csrf = m[1]
	}
	return resp.StatusCode, body
}

func (b *browser) post(path string, form url.Values) (int, string) {
	if form == nil {
		form = url.Values{}
	}
	form.Set("csrf", b.csrf)
	resp, err := b.c.PostForm(b.h.ui.URL+path, form)
	if err != nil {
		b.h.t.Fatal(err)
	}
	return resp.StatusCode, readBody(resp)
}

func (h *harness) register(uid, mail, token string) int {
	h.ipa.mu.Lock()
	h.ipa.stage[uid] = map[string]any{"uid": []any{uid}, "cn": []any{"Carol C"}, "mail": []any{mail},
		"fasstatusnote": []any{"spamcheck_awaiting"}, "fascreationtime": []any{"20261126120000Z"}}
	h.ipa.mu.Unlock()
	payload := fmt.Sprintf(`{"action":"fedora.noggin.registration","data":{"user":{"username":%q,"mail":%q},
		"request_headers":{"X-Forwarded-For":"203.0.113.9, 10.0.0.1"},"request_ip":"10.0.0.1","token":%q,"callback":%q}}`,
		uid, mail, token, h.noggin.URL+"/register/spamcheck-hook")
	resp, err := http.Post(h.hook.URL+"/basset", "application/json", strings.NewReader(payload))
	if err != nil {
		h.t.Fatal(err)
	}
	resp.Body.Close()
	return resp.StatusCode
}

func (h *harness) stageStatus(uid string) string {
	h.ipa.mu.Lock()
	defer h.ipa.mu.Unlock()
	su, ok := h.ipa.stage[uid]
	if !ok {
		return "<deleted>"
	}
	return strsOf(su["fasstatusnote"])[0]
}

func TestRegistrationApproval(t *testing.T) {
	h := newHarness(t)
	if code := h.register("carol", "carol@example.net", "tok-carol"); code != 200 {
		t.Fatalf("hook: %d", code)
	}
	if s := h.stageStatus("carol"); s != "spamcheck_manual" {
		t.Fatalf("held status = %q", s)
	}
	if code := h.register("ghost", "x@example.net", "t"); code != 200 { // creates stage user first, so valid
		t.Fatalf("hook ghost: %d", code)
	}

	bob := h.login("bob", "bobpw")
	if code, _ := bob.get("/users"); code != http.StatusForbidden {
		t.Fatalf("non-approver saw /users: %d", code)
	}
	alice := h.login("alice", "alicepw")
	code, body := alice.get("/users")
	if code != 200 || !strings.Contains(body, "carol@example.net") || !strings.Contains(body, "203.0.113.9") {
		t.Fatalf("users page: %d %s", code, body)
	}
	if _, body := alice.post("/users/carol/approve", nil); !strings.Contains(body, "noggin emailed them") {
		t.Fatalf("approve: %s", body)
	}
	if s := h.stageStatus("carol"); s != "active" {
		t.Fatalf("after approve: %q", s)
	}
	if len(h.callback) != 1 || h.callback[0]["status"] != "active" {
		t.Fatalf("callback: %v", h.callback)
	}
	// Deny + block domain; later registrations from it are auto-denied.
	if _, body := alice.post("/users/ghost/deny", url.Values{"block": {"domain"}}); !strings.Contains(body, "Blocked example.net") {
		t.Fatalf("deny: %s", body)
	}
	if s := h.stageStatus("ghost"); s != "<deleted>" {
		t.Fatalf("ghost not deleted: %s", s)
	}
	h.register("dave", "dave@mail.example.net", "t2")
	if s := h.stageStatus("dave"); s != "<deleted>" {
		t.Fatalf("blocklisted registration kept: %s", s)
	}
}

func TestCSRFRequired(t *testing.T) {
	h := newHarness(t)
	alice := h.login("alice", "alicepw")
	alice.csrf = "forged"
	if code, _ := alice.post("/blocklist/add", url.Values{"entry": {"example.com"}}); code != http.StatusForbidden {
		t.Fatalf("forged csrf accepted: %d", code)
	}
	if len(h.store.Blocklist()) != 0 {
		t.Fatal("blocklist changed")
	}
}

func TestBadLogin(t *testing.T) {
	h := newHarness(t)
	b := h.login("alice", "wrong")
	if _, body := b.get("/users"); !strings.Contains(body, `action="/login"`) {
		t.Fatal("bad password got a session")
	}
}

func TestGroupLifecycle(t *testing.T) {
	h := newHarness(t)
	bob := h.login("bob", "bobpw")
	bob.get("/request-group")
	_, body := bob.post("/request-group", url.Values{"name": {"web-team"}, "description": {"Web people"}, "justification": {"we build sites"}})
	if !strings.Contains(body, "Request #1 for web-team sent") {
		t.Fatalf("request: %s", body)
	}
	if _, body := bob.post("/request-group", url.Values{"name": {"self-service-managers"}, "description": {"x"}}); !strings.Contains(body, "reserved") {
		t.Fatalf("reserved name accepted: %s", body)
	}

	alice := h.login("alice", "alicepw")
	alice.get("/group-requests")
	if _, body := alice.post("/group-requests/1/approve", nil); !strings.Contains(body, "Created web-team") {
		t.Fatalf("approve: %s", body)
	}
	g := h.ipa.groups["web-team"]
	if g == nil || !g.fas || fmt.Sprint(g.managerUsers) != "[bob]" || fmt.Sprint(g.managerGrp) != "[self-service-managers]" || fmt.Sprint(g.users) != "[bob]" {
		t.Fatalf("group not set up: %+v", g)
	}
	if c := h.ipa.groups["self-service-managed-groups"]; c == nil || fmt.Sprint(c.groups) != "[web-team]" || c.posix {
		t.Fatalf("container: %+v", c)
	}

	if _, body := alice.get("/groups"); !strings.Contains(body, "web-team") {
		t.Fatalf("groups page: %s", body)
	}
	alice.post("/groups/web-team/owner", url.Values{"owner": {"alice"}})
	if fmt.Sprint(h.ipa.groups["web-team"].managerUsers) != "[alice]" {
		t.Fatalf("owner: %+v", h.ipa.groups["web-team"])
	}
	alice.post("/groups/web-team/rename", url.Values{"new_name": {"web-ops"}})
	if h.ipa.groups["web-ops"] == nil || h.ipa.groups["web-team"] != nil {
		t.Fatal("rename failed")
	}
	// Groups outside the container are off limits.
	if _, body := alice.post("/groups/self-service-managers/delete", url.Values{"confirm": {"self-service-managers"}}); !strings.Contains(body, "not a managed group") {
		t.Fatalf("unmanaged delete: %s", body)
	}
	if _, body := alice.post("/groups/web-ops/delete", url.Values{"confirm": {"wrong"}}); !strings.Contains(body, "type the group name") {
		t.Fatalf("unconfirmed delete: %s", body)
	}
	alice.post("/groups/web-ops/delete", url.Values{"confirm": {"web-ops"}})
	if h.ipa.groups["web-ops"] != nil {
		t.Fatal("delete failed")
	}
	if ev := h.store.Events(10); len(ev) < 4 {
		t.Fatalf("activity log: %v", ev)
	}
}
