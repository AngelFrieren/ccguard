package main

import (
	"bytes"
	"path/filepath"
	"testing"

	"github.com/AngelFrieren/ccguard/internal/alert"
	"github.com/AngelFrieren/ccguard/internal/baseline"
	"github.com/AngelFrieren/ccguard/internal/storage"
)

// TestWatchStartup_ModeBCatchup verifies the Mode B catch-up flow: executions
// recorded by hook-wrap while the watch daemon is stopped are incorporated
// into the baseline the first time RefreshAllStats() is called on restart.
func TestWatchStartup_ModeBCatchup(t *testing.T) {
	dir := t.TempDir()
	store, err := storage.Open(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("storage.Open: %v", err)
	}
	if err := store.Migrate(); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	defer store.Close()

	// Simulate hook-wrap recording executions while watch was stopped.
	for i := 0; i < 5; i++ {
		if err := store.RecordExecution("PreCommit", 100, 0, "wrap"); err != nil {
			t.Fatalf("RecordExecution: %v", err)
		}
	}

	// Simulate watch startup: create detector and refresh stats.
	var buf bytes.Buffer
	sink := alert.NewSink(&buf, alert.Options{})
	det := baseline.NewDetector(store, sink, baseline.DefaultConfig())

	if err := det.RefreshAllStats(); err != nil {
		t.Fatalf("RefreshAllStats: %v", err)
	}

	bs, err := det.Stats("PreCommit")
	if err != nil {
		t.Fatalf("Stats: %v", err)
	}
	if bs == nil {
		t.Fatal("expected non-nil baseline stats after Mode B catch-up")
	}
	if bs.SampleCount != 5 {
		t.Errorf("expected SampleCount=5, got %d", bs.SampleCount)
	}
	if bs.MeanMs != 100 {
		t.Errorf("expected MeanMs=100, got %f", bs.MeanMs)
	}
}
