package store

import (
	"path/filepath"
	"testing"
)

func TestAudit(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "portal.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	s.Log("login", "", "", "127.0.0.1")
	s.Log("issue", "fw-wilsonfi-dev-abcde", "managed, public", "127.0.0.1")
	all, _ := s.Events("", 10)
	if len(all) != 2 || all[0].Action != "issue" {
		t.Fatalf("events = %+v", all)
	}
	got, _ := s.Events("fw-wilsonfi", 10)
	if len(got) != 1 {
		t.Fatalf("filtered = %+v", got)
	}
}
