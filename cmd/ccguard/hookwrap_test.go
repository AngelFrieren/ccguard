package main

import (
	"bytes"
	"path/filepath"
	"testing"

	"github.com/AngelFrieren/ccguard/internal/alert"
	"github.com/AngelFrieren/ccguard/internal/baseline"
	"github.com/AngelFrieren/ccguard/internal/storage"
)

func newWrapTestDet(t *testing.T) (*baseline.Detector, *bytes.Buffer, *storage.Store) {
	t.Helper()
	dir := t.TempDir()
	store, err := storage.Open(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("storage.Open: %v", err)
	}
	if err := store.Migrate(); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	t.Cleanup(func() { store.Close() })

	var buf bytes.Buffer
	sink := alert.NewSink(&buf, alert.Options{})
	cfg := baseline.DefaultConfig()
	return baseline.NewDetector(store, sink, cfg), &buf, store
}

func TestRunWrap_SuccessfulCommand(t *testing.T) {
	det, _, store := newWrapTestDet(t)

	code := runWrap(det, "TestHook", "/bin/true", nil)
	if code != 0 {
		t.Errorf("expected exit 0, got %d", code)
	}

	execs, err := store.RecentExecutions("TestHook", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(execs) != 1 {
		t.Fatalf("expected 1 execution recorded, got %d", len(execs))
	}
	if execs[0].ExitCode != 0 {
		t.Errorf("expected exit_code=0 in record, got %d", execs[0].ExitCode)
	}
	if execs[0].HookName != "TestHook" {
		t.Errorf("expected hook_name=TestHook, got %q", execs[0].HookName)
	}
	if execs[0].Source != "wrap" {
		t.Errorf("expected source=wrap, got %q", execs[0].Source)
	}
}

func TestRunWrap_FailingCommand(t *testing.T) {
	det, _, store := newWrapTestDet(t)

	code := runWrap(det, "TestHook", "/bin/false", nil)
	if code != 1 {
		t.Errorf("expected exit 1, got %d", code)
	}

	execs, _ := store.RecentExecutions("TestHook", 10)
	if len(execs) != 1 {
		t.Fatalf("expected 1 execution recorded, got %d", len(execs))
	}
	if execs[0].ExitCode != 1 {
		t.Errorf("expected exit_code=1 in record, got %d", execs[0].ExitCode)
	}
}

func TestRunWrap_ExitCodePropagated(t *testing.T) {
	det, _, _ := newWrapTestDet(t)

	// /bin/sh -c "exit N" exits with exactly N.
	code := runWrap(det, "TestHook", "/bin/sh", []string{"-c", "exit 42"})
	if code != 42 {
		t.Errorf("expected exit 42, got %d", code)
	}
}

func TestRunWrap_DurationRecorded(t *testing.T) {
	det, _, store := newWrapTestDet(t)

	// Use a tiny sleep to ensure non-zero duration is measurable.
	runWrap(det, "TestHook", "/bin/sh", []string{"-c", "sleep 0.01"})

	execs, _ := store.RecentExecutions("TestHook", 10)
	if len(execs) != 1 {
		t.Fatalf("expected 1 execution, got %d", len(execs))
	}
	if execs[0].DurationMs < 0 {
		t.Errorf("duration_ms should be non-negative, got %d", execs[0].DurationMs)
	}
}
