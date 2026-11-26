package web

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/specnet-io/noggin-governer/internal/config"
	"github.com/specnet-io/noggin-governer/internal/ipa"
	"github.com/specnet-io/noggin-governer/internal/store"
)

// ---- noggin hook (BASSET_URL) ----

// bassetPayload is what noggin posts for each new stage user (noggin/signals.py).
type bassetPayload struct {
	Action string `json:"action"`
	Data   struct {
		User struct {
			Username  string `json:"username"`
			Mail      string `json:"mail"`
			HumanName string `json:"human_name"`
		} `json:"user"`
		RequestHeaders map[string]string `json:"request_headers"`
		RequestIP      string            `json:"request_ip"`
		Token          string            `json:"token"`
		Callback       string            `json:"callback"`
	} `json:"data"`
}

func (s *Server) bassetHook(w http.ResponseWriter, r *http.Request) {
	var p bassetPayload
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&p); err != nil {
		jsonResp(w, http.StatusBadRequest, "bad payload")
		return
	}
	uid := p.Data.User.Username
	if !usernameRe.MatchString(uid) || p.Data.Token == "" {
		jsonResp(w, http.StatusBadRequest, "missing username or token")
		return
	}
	// Only act on real stage users; the payload itself is not trusted for anything else.
	su, err := s.ipa.StageUser(r.Context(), uid)
	if ipa.IsNotFound(err) {
		jsonResp(w, http.StatusNotFound, "no such stage user")
		return
	}
	if err != nil {
		slog.Error("hook: stage user lookup", "user", uid, "err", err)
		jsonResp(w, http.StatusBadGateway, "ipa unavailable")
		return
	}
	if su.Status == "active" {
		slog.Warn("hook: stage user already active; noggin USER_DEFAULTS status_note should be spamcheck_awaiting", "user", uid)
	}
	ip := p.Data.RequestIP
	if xff := headerValue(p.Data.RequestHeaders, "X-Forwarded-For"); xff != "" {
		ip = strings.TrimSpace(strings.Split(xff, ",")[0])
	}

	if entry, blocked := s.store.Blocked(su.Mail); blocked {
		if err := s.ipa.DeleteStageUser(r.Context(), uid); err != nil {
			slog.Error("hook: delete blocked stage user", "user", uid, "err", err)
			jsonResp(w, http.StatusBadGateway, "ipa error")
			return
		}
		s.store.Log("blocklist", "registration auto-denied", uid, fmt.Sprintf("%s matched %s (ip %s)", su.Mail, entry, ip))
		slog.Info("registration blocked", "user", uid, "entry", entry)
		jsonResp(w, http.StatusOK, "blocked")
		return
	}

	// Hold the stage user until an approver decides (noggin keeps the "please wait" page).
	if err := s.ipa.SetStageStatus(r.Context(), uid, "spamcheck_manual"); err != nil {
		slog.Error("hook: set status", "user", uid, "err", err)
		jsonResp(w, http.StatusBadGateway, "ipa error")
		return
	}
	reg := store.Registration{
		Username: uid, Email: su.Mail, Name: su.Name, Token: p.Data.Token,
		Callback: p.Data.Callback, IP: ip, Received: time.Now().UTC(),
	}
	if err := s.store.PutRegistration(reg); err != nil {
		slog.Error("hook: store", "err", err)
		jsonResp(w, http.StatusInternalServerError, "store error")
		return
	}
	s.store.Log("noggin", "registration received", uid, su.Mail)
	slog.Info("registration queued", "user", uid, "ip", ip)
	s.notifyApprovers("New account request: "+uid,
		fmt.Sprintf("%s (%s, %s) asked for an account.\n\nReview it: %s\n", su.Name, uid, su.Mail, s.link("/users")))
	jsonResp(w, http.StatusOK, "queued")
}

func headerValue(h map[string]string, name string) string {
	for k, v := range h {
		if strings.EqualFold(k, name) {
			return v
		}
	}
	return ""
}

func jsonResp(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{"status": msg})
}

// ---- registration decisions ----

// approveRegistration lets noggin continue: through its spam-check callback (noggin then
// emails the validation link), or, without a usable token, by marking the stage user
// active and emailing the registrant a link to noggin's "resend validation email" page.
func (s *Server) approveRegistration(ctx context.Context, uid, actor string) (string, error) {
	su, err := s.ipa.StageUser(ctx, uid)
	if err != nil {
		return "", err
	}
	reg, hasReg := s.store.Registration(uid)
	if hasReg && reg.Token != "" && reg.Callback != "" {
		err := s.callback(ctx, reg.Callback, reg.Token, "active")
		if err == nil {
			s.store.Log(actor, "registration approved", uid, "noggin sent the validation email")
			return "Approved " + uid + ". noggin emailed them the link to set a password.", nil
		}
		slog.Warn("noggin callback failed; falling back", "user", uid, "err", err)
	}
	if err := s.ipa.SetStageStatus(ctx, uid, "active"); err != nil {
		return "", err
	}
	base := s.cfg.NogginURL
	if base == "" && hasReg {
		base = origin(reg.Callback)
	}
	if base == "" {
		s.store.Log(actor, "registration approved", uid, "no noggin URL known; registrant not emailed")
		return "Approved " + uid + ", but the registrant could not be emailed (set GOVERNER_NOGGIN_URL). They can finish at noggin's confirmation page.", nil
	}
	link := base + "/register/confirm?username=" + url.QueryEscape(uid)
	s.mail.SendAsync([]string{su.Mail}, "Your account request was approved",
		fmt.Sprintf("Hello %s,\n\nYour account request (%s) was approved.\n\nTo finish, open %s and choose \"Resend\" to receive the email that lets you set your password.\n", su.Name, uid, link))
	s.store.Log(actor, "registration approved", uid, "token unavailable; registrant emailed "+link)
	return "Approved " + uid + ". They were emailed a link to finish registration.", nil
}

func (s *Server) callback(ctx context.Context, cb, token, status string) error {
	if s.cfg.CallbackURL != "" {
		cb = s.cfg.CallbackURL
	}
	body, _ := json.Marshal(map[string]string{"token": token, "status": status})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cb, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("noggin callback: HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(data)))
	}
	return nil
}

func origin(u string) string {
	p, err := url.Parse(u)
	if err != nil || p.Scheme == "" || p.Host == "" {
		return ""
	}
	return p.Scheme + "://" + p.Host
}

func (s *Server) denyRegistration(ctx context.Context, uid, actor, block string) (string, error) {
	su, err := s.ipa.StageUser(ctx, uid)
	if err != nil && !ipa.IsNotFound(err) {
		return "", err
	}
	msg := "Denied " + uid + "."
	if su != nil && block != "" && su.Mail != "" {
		entry := strings.ToLower(su.Mail)
		if block == "domain" {
			entry = entry[strings.LastIndexByte(entry, '@')+1:]
		}
		if entry, err = store.NormalizeBlock(entry); err == nil {
			if err := s.store.AddBlock(entry); err != nil {
				return "", err
			}
			s.store.Log(actor, "blocklist add", entry, "while denying "+uid)
			msg += " Blocked " + entry + "."
		}
	}
	if err := s.ipa.DeleteStageUser(ctx, uid); err != nil {
		return "", err
	}
	s.store.DeleteRegistration(uid)
	s.store.Log(actor, "registration denied", uid, "")
	return msg, nil
}

// ---- group requests ----

var errGroupExists = errors.New("a group with that name already exists")

func (s *Server) groupExists(ctx context.Context, name string) (bool, error) {
	_, err := s.ipa.Group(ctx, name)
	if ipa.IsNotFound(err) {
		return false, nil
	}
	return err == nil, err
}

func (s *Server) reservedGroup(name string) bool {
	return name == s.cfg.ApproverGroup || name == s.cfg.ManagerGroup || name == s.cfg.ContainerGroup
}

// ensureContainer creates the group that holds every group made here, if missing.
func (s *Server) ensureContainer(ctx context.Context) error {
	ok, err := s.groupExists(ctx, s.cfg.ContainerGroup)
	if err != nil || ok {
		return err
	}
	err = s.ipa.CreatePlainGroup(ctx, s.cfg.ContainerGroup, "Groups created through noggin-governer (managed membership container)")
	if ipa.IsDuplicate(err) {
		return nil
	}
	return err
}

// createRequestedGroup turns an approved request into a FAS group in IPA.
func (s *Server) createRequestedGroup(ctx context.Context, req store.GroupRequest) error {
	if ok, err := s.groupExists(ctx, s.cfg.ManagerGroup); err != nil {
		return err
	} else if !ok {
		return fmt.Errorf("manager group %q does not exist in IPA; create it first", s.cfg.ManagerGroup)
	}
	if err := s.ensureContainer(ctx); err != nil {
		return fmt.Errorf("container group: %w", err)
	}
	if ok, err := s.groupExists(ctx, req.Name); err != nil {
		return err
	} else if ok {
		return errGroupExists
	}
	if err := s.ipa.CreateGroup(ctx, req.Name, req.Description); err != nil {
		return fmt.Errorf("create: %w", err)
	}
	if err := s.ipa.AddManagers(ctx, req.Name, []string{req.Requester}, []string{s.cfg.ManagerGroup}); err != nil {
		return fmt.Errorf("group created, but setting managers failed: %w", err)
	}
	if err := s.ipa.AddMembers(ctx, req.Name, []string{req.Requester}, nil); err != nil {
		return fmt.Errorf("group created, but adding the owner as a member failed: %w", err)
	}
	if err := s.ipa.AddMembers(ctx, s.cfg.ContainerGroup, nil, []string{req.Name}); err != nil {
		return fmt.Errorf("group created, but adding it to %s failed: %w", s.cfg.ContainerGroup, err)
	}
	return nil
}

// managedGroup returns the group if (and only if) it belongs to the container.
func (s *Server) managedGroup(ctx context.Context, name string) (*ipa.Group, error) {
	if !config.ValidGroupName(name) {
		return nil, errors.New("not a managed group")
	}
	c, err := s.ipa.Group(ctx, s.cfg.ContainerGroup)
	if err != nil {
		return nil, err
	}
	for _, g := range c.MemberGroups {
		if g == name {
			return s.ipa.Group(ctx, name)
		}
	}
	return nil, errors.New("not a managed group")
}

// ---- notifications ----

func (s *Server) link(path string) string {
	if s.cfg.PublicURL == "" {
		return path
	}
	return s.cfg.PublicURL + path
}

func (s *Server) notifyApprovers(subject, body string) {
	if !s.mail.Enabled {
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		users, err := s.ipa.GroupUsers(ctx, s.cfg.ApproverGroup)
		if err != nil {
			slog.Warn("notify approvers: list group", "err", err)
			return
		}
		var rcpts []string
		for _, u := range users {
			if len(rcpts) >= 100 {
				break
			}
			if info, err := s.ipa.User(ctx, u); err == nil && info.Mail != "" {
				rcpts = append(rcpts, info.Mail)
			}
		}
		if err := s.mail.Send(rcpts, subject, body); err != nil {
			slog.Warn("notify approvers", "err", err)
		}
	}()
}

func (s *Server) notifyUser(uid, subject, body string) {
	if !s.mail.Enabled {
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		u, err := s.ipa.User(ctx, uid)
		if err != nil || u.Mail == "" {
			return
		}
		if err := s.mail.Send([]string{u.Mail}, subject, body); err != nil {
			slog.Warn("notify user", "user", uid, "err", err)
		}
	}()
}
