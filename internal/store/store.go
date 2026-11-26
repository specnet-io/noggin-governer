// Package store keeps noggin-governer's own state in one JSON file: pending
// registration tokens, group requests, the blocklist and an activity log.
// IPA stays the source of truth for users and groups.
package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

type Registration struct {
	Username string    `json:"username"`
	Email    string    `json:"email"`
	Name     string    `json:"name"`
	Token    string    `json:"token"`    // noggin's spam-check token (callback auth)
	Callback string    `json:"callback"` // noggin's /register/spamcheck-hook URL
	IP       string    `json:"ip"`
	Received time.Time `json:"received"`
}

type GroupRequestStatus string

const (
	StatusPending  GroupRequestStatus = "pending"
	StatusApproved GroupRequestStatus = "approved"
	StatusDenied   GroupRequestStatus = "denied"
	StatusFailed   GroupRequestStatus = "failed"
)

type GroupRequest struct {
	ID            int                `json:"id"`
	Name          string             `json:"name"`
	Description   string             `json:"description"`
	Justification string             `json:"justification"`
	Requester     string             `json:"requester"`
	Created       time.Time          `json:"created"`
	Status        GroupRequestStatus `json:"status"`
	DecidedBy     string             `json:"decided_by,omitempty"`
	DecidedAt     time.Time          `json:"decided_at,omitempty"`
	Note          string             `json:"note,omitempty"`
}

type Event struct {
	Time   time.Time `json:"time"`
	Actor  string    `json:"actor"`
	Action string    `json:"action"`
	Target string    `json:"target"`
	Detail string    `json:"detail,omitempty"`
}

type state struct {
	Registrations map[string]*Registration `json:"registrations"`
	GroupRequests []*GroupRequest          `json:"group_requests"`
	Blocklist     []string                 `json:"blocklist"`
	Events        []Event                  `json:"events"`
	NextID        int                      `json:"next_id"`
}

const maxEvents = 1000

type Store struct {
	path string
	mu   sync.Mutex
	s    state
}

func Open(path string) (*Store, error) {
	st := &Store{path: path, s: state{Registrations: map[string]*Registration{}, NextID: 1}}
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return st, st.saveLocked()
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(raw, &st.s); err != nil {
		return nil, fmt.Errorf("store %s: %w", path, err)
	}
	if st.s.Registrations == nil {
		st.s.Registrations = map[string]*Registration{}
	}
	if st.s.NextID < 1 {
		st.s.NextID = 1
	}
	return st, nil
}

func (st *Store) saveLocked() error {
	data, err := json.MarshalIndent(st.s, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(st.path), ".state-*")
	if err != nil {
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return err
	}
	tmp.Close()
	return os.Rename(tmp.Name(), st.path)
}

func (st *Store) update(fn func(*state)) error {
	st.mu.Lock()
	defer st.mu.Unlock()
	fn(&st.s)
	return st.saveLocked()
}

// ---- registrations ----

func (st *Store) PutRegistration(r Registration) error {
	return st.update(func(s *state) { s.Registrations[r.Username] = &r })
}

func (st *Store) Registration(uid string) (Registration, bool) {
	st.mu.Lock()
	defer st.mu.Unlock()
	r, ok := st.s.Registrations[uid]
	if !ok {
		return Registration{}, false
	}
	return *r, true
}

func (st *Store) DeleteRegistration(uid string) error {
	return st.update(func(s *state) { delete(s.Registrations, uid) })
}

// PruneRegistrations drops records whose stage user no longer exists.
func (st *Store) PruneRegistrations(existing map[string]bool) error {
	st.mu.Lock()
	stale := false
	for uid := range st.s.Registrations {
		if !existing[uid] {
			stale = true
		}
	}
	st.mu.Unlock()
	if !stale {
		return nil
	}
	return st.update(func(s *state) {
		for uid := range s.Registrations {
			if !existing[uid] {
				delete(s.Registrations, uid)
			}
		}
	})
}

// ---- group requests ----

func (st *Store) AddGroupRequest(r GroupRequest) (GroupRequest, error) {
	err := st.update(func(s *state) {
		r.ID = s.NextID
		s.NextID++
		r.Status = StatusPending
		s.GroupRequests = append(s.GroupRequests, &r)
	})
	return r, err
}

func (st *Store) GroupRequest(id int) (GroupRequest, bool) {
	st.mu.Lock()
	defer st.mu.Unlock()
	for _, r := range st.s.GroupRequests {
		if r.ID == id {
			return *r, true
		}
	}
	return GroupRequest{}, false
}

func (st *Store) UpdateGroupRequest(id int, fn func(*GroupRequest)) error {
	return st.update(func(s *state) {
		for _, r := range s.GroupRequests {
			if r.ID == id {
				fn(r)
			}
		}
	})
}

// GroupRequests returns requests, newest first, optionally filtered by requester and/or status.
func (st *Store) GroupRequests(requester string, status GroupRequestStatus) []GroupRequest {
	st.mu.Lock()
	defer st.mu.Unlock()
	var out []GroupRequest
	for i := len(st.s.GroupRequests) - 1; i >= 0; i-- {
		r := st.s.GroupRequests[i]
		if (requester == "" || r.Requester == requester) && (status == "" || r.Status == status) {
			out = append(out, *r)
		}
	}
	return out
}

// PendingGroupRequestFor reports whether a pending request for that group name exists.
func (st *Store) PendingGroupRequestFor(name string) bool {
	return len(st.filter(func(r *GroupRequest) bool { return r.Status == StatusPending && r.Name == name })) > 0
}

func (st *Store) filter(fn func(*GroupRequest) bool) []GroupRequest {
	st.mu.Lock()
	defer st.mu.Unlock()
	var out []GroupRequest
	for _, r := range st.s.GroupRequests {
		if fn(r) {
			out = append(out, *r)
		}
	}
	return out
}

// ---- blocklist ----

// NormalizeBlock lowercases an entry; "@example.com" and "example.com" both mean the domain.
func NormalizeBlock(entry string) (string, error) {
	e := strings.ToLower(strings.TrimSpace(entry))
	e = strings.TrimPrefix(e, "@")
	if e == "" || strings.ContainsAny(e, " \t,;<>") || strings.Count(e, "@") > 1 {
		return "", fmt.Errorf("%q is not an email address or domain", entry)
	}
	if at := strings.IndexByte(e, '@'); at == 0 || at == len(e)-1 {
		return "", fmt.Errorf("%q is not an email address", entry)
	}
	if !strings.Contains(e[strings.IndexByte(e, '@')+1:], ".") {
		return "", fmt.Errorf("%q has no domain", entry)
	}
	return e, nil
}

func (st *Store) Blocklist() []string {
	st.mu.Lock()
	defer st.mu.Unlock()
	out := append([]string(nil), st.s.Blocklist...)
	sort.Strings(out)
	return out
}

func (st *Store) AddBlock(entry string) error {
	return st.update(func(s *state) {
		for _, b := range s.Blocklist {
			if b == entry {
				return
			}
		}
		s.Blocklist = append(s.Blocklist, entry)
	})
}

func (st *Store) RemoveBlock(entry string) error {
	return st.update(func(s *state) {
		out := s.Blocklist[:0]
		for _, b := range s.Blocklist {
			if b != entry {
				out = append(out, b)
			}
		}
		s.Blocklist = out
	})
}

// Blocked returns the blocklist entry matching an email (exact address, domain or parent domain).
func (st *Store) Blocked(email string) (string, bool) {
	email = strings.ToLower(strings.TrimSpace(email))
	at := strings.LastIndexByte(email, '@')
	if at < 0 {
		return "", false
	}
	domain := email[at+1:]
	st.mu.Lock()
	defer st.mu.Unlock()
	for _, b := range st.s.Blocklist {
		if strings.Contains(b, "@") {
			if b == email {
				return b, true
			}
			continue
		}
		if domain == b || strings.HasSuffix(domain, "."+b) {
			return b, true
		}
	}
	return "", false
}

// ---- activity ----

func (st *Store) Log(actor, action, target, detail string) {
	_ = st.update(func(s *state) {
		s.Events = append(s.Events, Event{Time: time.Now().UTC(), Actor: actor, Action: action, Target: target, Detail: detail})
		if len(s.Events) > maxEvents {
			s.Events = s.Events[len(s.Events)-maxEvents:]
		}
	})
}

// Events returns the newest n events, newest first.
func (st *Store) Events(n int) []Event {
	st.mu.Lock()
	defer st.mu.Unlock()
	var out []Event
	for i := len(st.s.Events) - 1; i >= 0 && len(out) < n; i-- {
		out = append(out, st.s.Events[i])
	}
	return out
}
