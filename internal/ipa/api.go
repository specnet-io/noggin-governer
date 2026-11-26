package ipa

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"
)

// Typed wrappers for the handful of IPA commands noggin-governer uses.

type User struct {
	UID    string
	Name   string
	Mail   string
	Groups []string // direct and indirect
}

type StageUser struct {
	UID     string
	Name    string
	Mail    string
	Status  string // fasstatusnote (noggin): spamcheck_awaiting, spamcheck_manual, spamcheck_denied, active
	Created time.Time
}

type Group struct {
	Name          string
	Description   string
	GID           string
	FAS           bool
	MemberUsers   []string
	MemberGroups  []string
	ManagerUsers  []string
	ManagerGroups []string
}

func strs(m map[string]any, key string) []string {
	switch v := m[key].(type) {
	case []any:
		out := make([]string, 0, len(v))
		for _, x := range v {
			if s, ok := x.(string); ok {
				out = append(out, s)
			} else if mm, ok := x.(map[string]any); ok { // {"__datetime__": ...} and similar
				for _, y := range mm {
					out = append(out, fmt.Sprint(y))
				}
			} else {
				out = append(out, fmt.Sprint(x))
			}
		}
		return out
	case string:
		return []string{v}
	case nil:
		return nil
	default:
		return []string{fmt.Sprint(v)}
	}
}

func str1(m map[string]any, key string) string {
	if v := strs(m, key); len(v) > 0 {
		return v[0]
	}
	return ""
}

func inner(res map[string]any) map[string]any {
	m, _ := res["result"].(map[string]any)
	if m == nil {
		m = map[string]any{}
	}
	return m
}

func (c *Client) User(ctx context.Context, uid string) (*User, error) {
	res, err := c.Call(ctx, "user_show", []any{uid}, nil)
	if err != nil {
		return nil, err
	}
	m := inner(res)
	return &User{
		UID:    str1(m, "uid"),
		Name:   str1(m, "cn"),
		Mail:   str1(m, "mail"),
		Groups: append(strs(m, "memberof_group"), strs(m, "memberofindirect_group")...),
	}, nil
}

func parseStage(m map[string]any) StageUser {
	su := StageUser{UID: str1(m, "uid"), Name: str1(m, "cn"), Mail: str1(m, "mail"), Status: str1(m, "fasstatusnote")}
	if ts := str1(m, "fascreationtime"); ts != "" {
		for _, layout := range []string{"20060102150405Z", time.RFC3339, "2006-01-02T15:04:05Z"} {
			if t, err := time.Parse(layout, ts); err == nil {
				su.Created = t
				break
			}
		}
	}
	return su
}

func (c *Client) StageUser(ctx context.Context, uid string) (*StageUser, error) {
	res, err := c.Call(ctx, "stageuser_show", []any{uid}, map[string]any{"all": true})
	if err != nil {
		return nil, err
	}
	su := parseStage(inner(res))
	return &su, nil
}

func (c *Client) StageUsers(ctx context.Context) ([]StageUser, error) {
	res, err := c.Call(ctx, "stageuser_find", nil, map[string]any{"all": true, "sizelimit": 0})
	if err != nil {
		return nil, err
	}
	list, _ := res["result"].([]any)
	out := make([]StageUser, 0, len(list))
	for _, x := range list {
		if m, ok := x.(map[string]any); ok {
			out = append(out, parseStage(m))
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Created.Before(out[j].Created) })
	return out, nil
}

// SetStageStatus sets noggin's fasstatusnote on a stage user. No-op if unchanged.
func (c *Client) SetStageStatus(ctx context.Context, uid, status string) error {
	_, err := c.Call(ctx, "stageuser_mod", []any{uid}, map[string]any{"fasstatusnote": status})
	if IsEmptyModlist(err) {
		return nil
	}
	return err
}

func (c *Client) DeleteStageUser(ctx context.Context, uid string) error {
	_, err := c.Call(ctx, "stageuser_del", []any{uid}, nil)
	if IsNotFound(err) {
		return nil
	}
	return err
}

func (c *Client) Group(ctx context.Context, name string) (*Group, error) {
	res, err := c.Call(ctx, "group_show", []any{name}, map[string]any{"all": true})
	if err != nil {
		return nil, err
	}
	m := inner(res)
	g := &Group{
		Name:          str1(m, "cn"),
		Description:   str1(m, "description"),
		GID:           str1(m, "gidnumber"),
		MemberUsers:   strs(m, "member_user"),
		MemberGroups:  strs(m, "member_group"),
		ManagerUsers:  strs(m, "membermanager_user"),
		ManagerGroups: strs(m, "membermanager_group"),
	}
	for _, oc := range strs(m, "objectclass") {
		if strings.EqualFold(oc, "fasgroup") {
			g.FAS = true
		}
	}
	if b, ok := m["fasgroup"].(bool); ok && b {
		g.FAS = true
	}
	return g, nil
}

// GroupUsers returns direct and indirect user members.
func (c *Client) GroupUsers(ctx context.Context, name string) ([]string, error) {
	res, err := c.Call(ctx, "group_show", []any{name}, nil)
	if err != nil {
		return nil, err
	}
	m := inner(res)
	return append(strs(m, "member_user"), strs(m, "memberindirect_user")...), nil
}

// CreateGroup creates a FAS-enabled (noggin-visible) group.
func (c *Client) CreateGroup(ctx context.Context, name, description string) error {
	opts := map[string]any{"fasgroup": true}
	if description != "" {
		opts["description"] = description
	}
	_, err := c.Call(ctx, "group_add", []any{name}, opts)
	if err == nil || IsDuplicate(err) {
		return err
	}
	// Older freeipa-fas without the group_add flag: create, then add the objectclass.
	if !strings.Contains(strings.ToLower(err.Error()), "fasgroup") && !strings.Contains(err.Error(), "Unknown option") {
		return err
	}
	delete(opts, "fasgroup")
	if _, err := c.Call(ctx, "group_add", []any{name}, opts); err != nil {
		return err
	}
	_, err = c.Call(ctx, "group_mod", []any{name}, map[string]any{"addattr": "objectclass=fasgroup"})
	if IsEmptyModlist(err) {
		return nil
	}
	return err
}

// CreatePlainGroup creates a non-POSIX, non-FAS group (used for the container group).
func (c *Client) CreatePlainGroup(ctx context.Context, name, description string) error {
	_, err := c.Call(ctx, "group_add", []any{name}, map[string]any{"description": description, "nonposix": true})
	return err
}

func (c *Client) RenameGroup(ctx context.Context, name, newName string) error {
	_, err := c.Call(ctx, "group_mod", []any{name}, map[string]any{"rename": newName})
	return err
}

func (c *Client) DeleteGroup(ctx context.Context, name string) error {
	_, err := c.Call(ctx, "group_del", []any{name}, nil)
	return err
}

func memberOpts(users, groups []string) map[string]any {
	o := map[string]any{}
	if len(users) > 0 {
		o["user"] = users
	}
	if len(groups) > 0 {
		o["group"] = groups
	}
	return o
}

func (c *Client) memberCall(ctx context.Context, method, group string, users, groups []string, ignore string) error {
	if len(users) == 0 && len(groups) == 0 {
		return nil
	}
	res, err := c.Call(ctx, method, []any{group}, memberOpts(users, groups))
	if err != nil {
		return err
	}
	return failed(res["failed"], ignore)
}

// failed walks IPA's nested "failed" structure ({"member": {"user": [[name, reason]]}}).
func failed(v any, ignore string) error {
	var msgs []string
	var walk func(any)
	walk = func(x any) {
		switch t := x.(type) {
		case map[string]any:
			for _, y := range t {
				walk(y)
			}
		case []any:
			if len(t) == 2 {
				name, ok1 := t[0].(string)
				reason, ok2 := t[1].(string)
				if ok1 && ok2 {
					if !strings.Contains(reason, ignore) {
						msgs = append(msgs, name+": "+reason)
					}
					return
				}
			}
			for _, y := range t {
				walk(y)
			}
		}
	}
	walk(v)
	if len(msgs) > 0 {
		return fmt.Errorf("IPA refused: %s", strings.Join(msgs, "; "))
	}
	return nil
}

func (c *Client) AddMembers(ctx context.Context, group string, users, groups []string) error {
	return c.memberCall(ctx, "group_add_member", group, users, groups, "already a member")
}

func (c *Client) RemoveMembers(ctx context.Context, group string, users, groups []string) error {
	return c.memberCall(ctx, "group_remove_member", group, users, groups, "not a member")
}

func (c *Client) AddManagers(ctx context.Context, group string, users, groups []string) error {
	return c.memberCall(ctx, "group_add_member_manager", group, users, groups, "already a member")
}

func (c *Client) RemoveManagers(ctx context.Context, group string, users, groups []string) error {
	return c.memberCall(ctx, "group_remove_member_manager", group, users, groups, "not a member")
}
