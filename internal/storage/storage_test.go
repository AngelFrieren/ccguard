package storage

import (
	"path/filepath"
	"testing"
)

func newTestStore(t *testing.T) *Store {
	t.Helper()
	dir := t.TempDir()
	s, err := Open(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	if err := s.Migrate(); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	return s
}

func TestApproveAndCheck(t *testing.T) {
	s := newTestStore(t)

	const path = "/home/u/.claude/settings.json"
	const goodHash = "abc123"
	const badHash = "def456"

	ok, err := s.IsApproved(path, goodHash)
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("hash should not be approved before approval")
	}

	if err := s.Approve(path, goodHash, "test"); err != nil {
		t.Fatalf("Approve: %v", err)
	}

	ok, err = s.IsApproved(path, goodHash)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Error("approved hash should be recognised")
	}

	ok, err = s.IsApproved(path, badHash)
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Error("non-approved hash should not be recognised")
	}
}

func TestApproveIsIdempotent(t *testing.T) {
	s := newTestStore(t)
	if err := s.Approve("/p", "h", "first"); err != nil {
		t.Fatal(err)
	}
	if err := s.Approve("/p", "h", "second"); err != nil {
		t.Fatal(err)
	}
	n, err := s.CountApproved()
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Errorf("expected 1 approved row, got %d", n)
	}
}

func TestClearApproved(t *testing.T) {
	s := newTestStore(t)
	_ = s.Approve("/a", "h1", "")
	_ = s.Approve("/b", "h2", "")
	if err := s.ClearApproved(); err != nil {
		t.Fatal(err)
	}
	n, _ := s.CountApproved()
	if n != 0 {
		t.Errorf("expected 0 after clear, got %d", n)
	}
}

func TestRecordEvent(t *testing.T) {
	s := newTestStore(t)
	if err := s.RecordEvent("/p", "h", "unapproved-change", "WRITE"); err != nil {
		t.Fatalf("RecordEvent: %v", err)
	}
}

func TestRecordIOCEvent(t *testing.T) {
	s := newTestStore(t)
	if err := s.RecordIOCEvent("/p", "h", "WRITE", "CCG-IOC-0001"); err != nil {
		t.Fatalf("RecordIOCEvent: %v", err)
	}
}

func TestMigrateIdempotent(t *testing.T) {
	s := newTestStore(t)
	// Second Migrate call must not return an error (covers addColumnIfMissing).
	if err := s.Migrate(); err != nil {
		t.Fatalf("second Migrate: %v", err)
	}
}
