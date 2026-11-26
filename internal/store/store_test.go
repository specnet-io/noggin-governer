package store

import (
	"path/filepath"
	"testing"
)

func TestBlocklistMatching(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "s.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range []string{"@Spam.example", "bad@good.example"} {
		n, err := NormalizeBlock(e)
		if err != nil {
			t.Fatal(err)
		}
		st.AddBlock(n)
	}
	cases := map[string]bool{
		"x@spam.example":     true,
		"x@sub.spam.example": true,
		"x@notspam.example":  false,
		"BAD@good.example":   true,
		"other@good.example": false,
	}
	for email, want := range cases {
		if _, got := st.Blocked(email); got != want {
			t.Errorf("%s: got %v want %v", email, got, want)
		}
	}
	for _, bad := range []string{"", "a b", "@", "x@", "nodot", "a@b@c.d"} {
		if _, err := NormalizeBlock(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestPersistence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "s.json")
	st, _ := Open(path)
	st.PutRegistration(Registration{Username: "carol", Token: "t"})
	r, _ := st.AddGroupRequest(GroupRequest{Name: "g", Requester: "bob"})
	st.AddBlock("example.com")

	st2, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if reg, ok := st2.Registration("carol"); !ok || reg.Token != "t" {
		t.Error("registration lost")
	}
	if g, ok := st2.GroupRequest(r.ID); !ok || g.Status != StatusPending {
		t.Error("group request lost")
	}
	if n, _ := st2.AddGroupRequest(GroupRequest{Name: "h"}); n.ID != r.ID+1 {
		t.Errorf("ids not persisted: %d", n.ID)
	}
	if len(st2.Blocklist()) != 1 {
		t.Error("blocklist lost")
	}
}
