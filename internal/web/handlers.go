package web

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/specnet-io/noggin-governer/internal/config"
	"github.com/specnet-io/noggin-governer/internal/ipa"
	"github.com/specnet-io/noggin-governer/internal/store"
)

func (s *Server) view(w http.ResponseWriter, r *http.Request, rc *reqCtx, title, tab string, data any) *view {
	kind, msg := s.takeFlash(w, r)
	v := &view{Title: title, Tab: tab, User: rc.User, Approver: rc.Approver, CSRF: rc.CSRF,
		Flash: msg, FlashKind: kind, Version: s.Version, Data: data}
	if rc.Approver {
		v.Warnings = s.cfg.Warnings
	}
	return v
}

func (s *Server) fail(w http.ResponseWriter, r *http.Request, rc *reqCtx, status int, msg string) {
	s.render(w, status, "error", &view{Title: "Error", User: rc.User, Approver: rc.Approver, CSRF: rc.CSRF,
		Version: s.Version, Flash: msg, FlashKind: "error"})
}

// done flashes a result and redirects (POST/redirect/GET).
func (s *Server) done(w http.ResponseWriter, r *http.Request, to, msg string, err error) {
	if err != nil {
		slog.Error("action failed", "path", r.URL.Path, "err", err)
		s.flash(w, "error", msg+": "+err.Error())
	} else {
		s.flash(w, "ok", msg)
	}
	http.Redirect(w, r, to, http.StatusSeeOther)
}

func (s *Server) home(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	if rc.Approver {
		http.Redirect(w, r, "/users", http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/request-group", http.StatusSeeOther)
}

// ---- user requests ----

type userRow struct {
	ipa.StageUser
	IP       string
	Received time.Time
	Blocked  string
	HasToken bool
}

func (s *Server) usersPage(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	stage, err := s.ipa.StageUsers(r.Context())
	if err != nil {
		slog.Error("stage users", "err", err)
		s.fail(w, r, rc, http.StatusBadGateway, "Could not list stage users from FreeIPA.")
		return
	}
	var pending, approved, denied []userRow
	existing := map[string]bool{}
	for _, su := range stage {
		existing[su.UID] = true
		row := userRow{StageUser: su}
		if reg, ok := s.store.Registration(su.UID); ok {
			row.IP, row.Received, row.HasToken = reg.IP, reg.Received, reg.Token != ""
		}
		if entry, ok := s.store.Blocked(su.Mail); ok {
			row.Blocked = entry
		}
		switch su.Status {
		case "active":
			approved = append(approved, row)
		case "spamcheck_denied":
			denied = append(denied, row)
		default:
			pending = append(pending, row)
		}
	}
	s.store.PruneRegistrations(existing)
	s.render(w, http.StatusOK, "users", s.view(w, r, rc, "User requests", "users",
		map[string]any{"Pending": pending, "Approved": approved, "Denied": denied}))
}

func (s *Server) userApprove(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	uid := r.PathValue("uid")
	if !usernameRe.MatchString(uid) {
		s.done(w, r, "/users", "Approve failed", errors.New("bad username"))
		return
	}
	msg, err := s.approveRegistration(r.Context(), uid, rc.User)
	if err != nil {
		s.done(w, r, "/users", "Approving "+uid+" failed", err)
		return
	}
	s.done(w, r, "/users", msg, nil)
}

func (s *Server) userDeny(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	uid := r.PathValue("uid")
	if !usernameRe.MatchString(uid) {
		s.done(w, r, "/users", "Deny failed", errors.New("bad username"))
		return
	}
	block := r.PostFormValue("block")
	if block != "email" && block != "domain" {
		block = ""
	}
	msg, err := s.denyRegistration(r.Context(), uid, rc.User, block)
	if err != nil {
		s.done(w, r, "/users", "Denying "+uid+" failed", err)
		return
	}
	s.done(w, r, "/users", msg, nil)
}

// ---- group requests ----

func (s *Server) requestGroupForm(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	s.render(w, http.StatusOK, "request_group", s.view(w, r, rc, "Request a group", "request",
		map[string]any{"Mine": s.store.GroupRequests(rc.User, "")}))
}

func (s *Server) requestGroupSubmit(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	name := strings.ToLower(strings.TrimSpace(r.PostFormValue("name")))
	desc := strings.TrimSpace(r.PostFormValue("description"))
	why := strings.TrimSpace(r.PostFormValue("justification"))
	fail := func(msg string) { s.done(w, r, "/request-group", "Request not sent", errors.New(msg)) }
	switch {
	case !config.ValidGroupName(name):
		fail("group names are 2-64 characters: lowercase letters, digits, '-', '_' or '.', starting with a letter or digit")
		return
	case s.reservedGroup(name):
		fail("that name is reserved")
		return
	case len(desc) > 200 || len(why) > 2000:
		fail("description (200) or justification (2000) is too long")
		return
	case desc == "":
		fail("add a short description")
		return
	case s.store.PendingGroupRequestFor(name):
		fail("a request for that group is already waiting for approval")
		return
	}
	if len(s.store.GroupRequests(rc.User, store.StatusPending)) >= 5 {
		fail("you already have 5 requests waiting; wait for a decision first")
		return
	}
	exists, err := s.groupExists(r.Context(), name)
	if err != nil {
		s.done(w, r, "/request-group", "Request not sent", err)
		return
	}
	if exists {
		fail("a group with that name already exists")
		return
	}
	req, err := s.store.AddGroupRequest(store.GroupRequest{Name: name, Description: desc, Justification: why,
		Requester: rc.User, Created: time.Now().UTC()})
	if err != nil {
		s.done(w, r, "/request-group", "Request not sent", err)
		return
	}
	s.store.Log(rc.User, "group requested", name, desc)
	s.notifyApprovers("New group request: "+name,
		fmt.Sprintf("%s asked for the group %q.\n\nDescription: %s\nWhy: %s\n\nReview it: %s\n", rc.User, name, desc, why, s.link("/group-requests")))
	s.done(w, r, "/request-group", fmt.Sprintf("Request #%d for %s sent. You'll get an email when it's decided.", req.ID, name), nil)
}

func (s *Server) groupRequestsPage(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	pending := s.store.GroupRequests("", store.StatusPending)
	pending = append(pending, s.store.GroupRequests("", store.StatusFailed)...)
	var recent []store.GroupRequest
	for _, g := range s.store.GroupRequests("", "") {
		if (g.Status == store.StatusApproved || g.Status == store.StatusDenied) && len(recent) < 50 {
			recent = append(recent, g)
		}
	}
	s.render(w, http.StatusOK, "group_requests", s.view(w, r, rc, "Group requests", "group-requests",
		map[string]any{"Pending": pending, "Recent": recent, "ManagerGroup": s.cfg.ManagerGroup, "Container": s.cfg.ContainerGroup}))
}

func (s *Server) requestFromPath(r *http.Request) (store.GroupRequest, bool) {
	id, err := strconv.Atoi(r.PathValue("id"))
	if err != nil {
		return store.GroupRequest{}, false
	}
	req, ok := s.store.GroupRequest(id)
	return req, ok && (req.Status == store.StatusPending || req.Status == store.StatusFailed)
}

func (s *Server) groupRequestApprove(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	req, ok := s.requestFromPath(r)
	if !ok {
		s.done(w, r, "/group-requests", "Approve failed", errors.New("request not found or already decided"))
		return
	}
	err := s.createRequestedGroup(r.Context(), req)
	now := time.Now().UTC()
	if err != nil {
		s.store.UpdateGroupRequest(req.ID, func(g *store.GroupRequest) {
			g.Status, g.Note, g.DecidedBy, g.DecidedAt = store.StatusFailed, err.Error(), rc.User, now
		})
		s.store.Log(rc.User, "group creation failed", req.Name, err.Error())
		s.done(w, r, "/group-requests", "Creating "+req.Name+" failed", err)
		return
	}
	s.store.UpdateGroupRequest(req.ID, func(g *store.GroupRequest) {
		g.Status, g.Note, g.DecidedBy, g.DecidedAt = store.StatusApproved, "", rc.User, now
	})
	s.store.Log(rc.User, "group request approved", req.Name, "owner "+req.Requester)
	s.notifyUser(req.Requester, "Group approved: "+req.Name,
		fmt.Sprintf("Your request for the group %q was approved. You manage its members in noggin.\n", req.Name))
	s.done(w, r, "/group-requests", fmt.Sprintf("Created %s; %s manages it (with %s).", req.Name, req.Requester, s.cfg.ManagerGroup), nil)
}

func (s *Server) groupRequestDeny(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	req, ok := s.requestFromPath(r)
	if !ok {
		s.done(w, r, "/group-requests", "Deny failed", errors.New("request not found or already decided"))
		return
	}
	note := strings.TrimSpace(r.PostFormValue("note"))
	if len(note) > 500 {
		note = note[:500]
	}
	s.store.UpdateGroupRequest(req.ID, func(g *store.GroupRequest) {
		g.Status, g.Note, g.DecidedBy, g.DecidedAt = store.StatusDenied, note, rc.User, time.Now().UTC()
	})
	s.store.Log(rc.User, "group request denied", req.Name, note)
	body := fmt.Sprintf("Your request for the group %q was declined.\n", req.Name)
	if note != "" {
		body += "\nReason: " + note + "\n"
	}
	s.notifyUser(req.Requester, "Group request declined: "+req.Name, body)
	s.done(w, r, "/group-requests", "Denied the request for "+req.Name+".", nil)
}

// ---- group management ----

func (s *Server) groupsPage(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	var groups []*ipa.Group
	missing := false
	c, err := s.ipa.Group(r.Context(), s.cfg.ContainerGroup)
	switch {
	case ipa.IsNotFound(err):
		missing = true
	case err != nil:
		slog.Error("container group", "err", err)
		s.fail(w, r, rc, http.StatusBadGateway, "Could not read groups from FreeIPA.")
		return
	default:
		names := append([]string(nil), c.MemberGroups...)
		sort.Strings(names)
		for _, n := range names {
			g, err := s.ipa.Group(r.Context(), n)
			if err != nil {
				slog.Warn("group show", "group", n, "err", err)
				continue
			}
			groups = append(groups, g)
		}
	}
	s.render(w, http.StatusOK, "groups", s.view(w, r, rc, "Group management", "groups",
		map[string]any{"Groups": groups, "Container": s.cfg.ContainerGroup, "Missing": missing, "ManagerGroup": s.cfg.ManagerGroup}))
}

func (s *Server) groupOwner(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	name := r.PathValue("name")
	owner := strings.ToLower(strings.TrimSpace(r.PostFormValue("owner")))
	g, err := s.managedGroup(r.Context(), name)
	if err != nil {
		s.done(w, r, "/groups", "Owner change failed", err)
		return
	}
	if !usernameRe.MatchString(owner) {
		s.done(w, r, "/groups", "Owner change failed", errors.New("enter a username"))
		return
	}
	if _, err := s.ipa.User(r.Context(), owner); err != nil {
		if ipa.IsNotFound(err) {
			err = fmt.Errorf("no active user %q", owner)
		}
		s.done(w, r, "/groups", "Owner change failed", err)
		return
	}
	var old []string
	for _, u := range g.ManagerUsers {
		if u != owner {
			old = append(old, u)
		}
	}
	if err := s.ipa.AddManagers(r.Context(), name, []string{owner}, nil); err != nil {
		s.done(w, r, "/groups", "Owner change failed", err)
		return
	}
	if err := s.ipa.AddMembers(r.Context(), name, []string{owner}, nil); err != nil {
		s.done(w, r, "/groups", "Owner set, but adding them as a member failed", err)
		return
	}
	if err := s.ipa.RemoveManagers(r.Context(), name, old, nil); err != nil {
		s.done(w, r, "/groups", "New owner added, but removing the old owner failed", err)
		return
	}
	s.store.Log(rc.User, "group owner changed", name, fmt.Sprintf("%s -> %s", strings.Join(old, ","), owner))
	s.notifyUser(owner, "You now manage the group "+name, fmt.Sprintf("You are now the owner of the group %q and manage its members in noggin.\n", name))
	s.done(w, r, "/groups", fmt.Sprintf("%s now owns %s.", owner, name), nil)
}

func (s *Server) groupRename(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	name := r.PathValue("name")
	newName := strings.ToLower(strings.TrimSpace(r.PostFormValue("new_name")))
	if _, err := s.managedGroup(r.Context(), name); err != nil {
		s.done(w, r, "/groups", "Rename failed", err)
		return
	}
	if !config.ValidGroupName(newName) || s.reservedGroup(newName) {
		s.done(w, r, "/groups", "Rename failed", errors.New("invalid or reserved group name"))
		return
	}
	if exists, err := s.groupExists(r.Context(), newName); err != nil || exists {
		if err == nil {
			err = errGroupExists
		}
		s.done(w, r, "/groups", "Rename failed", err)
		return
	}
	if err := s.ipa.RenameGroup(r.Context(), name, newName); err != nil {
		s.done(w, r, "/groups", "Rename failed", err)
		return
	}
	s.store.Log(rc.User, "group renamed", name, "-> "+newName)
	s.done(w, r, "/groups", fmt.Sprintf("Renamed %s to %s.", name, newName), nil)
}

func (s *Server) groupDelete(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	name := r.PathValue("name")
	if r.PostFormValue("confirm") != name {
		s.done(w, r, "/groups", "Delete failed", errors.New("type the group name exactly to confirm"))
		return
	}
	g, err := s.managedGroup(r.Context(), name)
	if err != nil {
		s.done(w, r, "/groups", "Delete failed", err)
		return
	}
	if err := s.ipa.DeleteGroup(r.Context(), name); err != nil {
		s.done(w, r, "/groups", "Delete failed", err)
		return
	}
	s.store.Log(rc.User, "group deleted", name, fmt.Sprintf("%d members, owners %s", len(g.MemberUsers), strings.Join(g.ManagerUsers, ",")))
	s.done(w, r, "/groups", "Deleted "+name+".", nil)
}

// ---- blocklist ----

func (s *Server) blocklistPage(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	s.render(w, http.StatusOK, "blocklist", s.view(w, r, rc, "Blocklist", "blocklist",
		map[string]any{"Entries": s.store.Blocklist()}))
}

func (s *Server) blocklistAdd(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	entry, err := store.NormalizeBlock(r.PostFormValue("entry"))
	if err == nil {
		err = s.store.AddBlock(entry)
	}
	if err != nil {
		s.done(w, r, "/blocklist", "Not added", err)
		return
	}
	s.store.Log(rc.User, "blocklist add", entry, "")
	s.done(w, r, "/blocklist", "Blocked "+entry+". New registrations from it are denied automatically.", nil)
}

func (s *Server) blocklistRemove(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	entry := r.PostFormValue("entry")
	if err := s.store.RemoveBlock(entry); err != nil {
		s.done(w, r, "/blocklist", "Not removed", err)
		return
	}
	s.store.Log(rc.User, "blocklist remove", entry, "")
	s.done(w, r, "/blocklist", "Removed "+entry+".", nil)
}

func (s *Server) activityPage(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	s.render(w, http.StatusOK, "activity", s.view(w, r, rc, "Activity", "activity",
		map[string]any{"Events": s.store.Events(200)}))
}
