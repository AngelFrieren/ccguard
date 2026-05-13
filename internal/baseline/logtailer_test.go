package baseline

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/AngelFrieren/ccguard/internal/alert"
	"github.com/AngelFrieren/ccguard/internal/storage"
)

// fixedParser is a LineParser that matches every non-empty line, assigning a
// fixed hook name and the line's byte length as the duration.
type fixedParser struct{ hook string }

func (p fixedParser) Parse(line string) (string, int64, bool) {
	if line == "" {
		return "", 0, false
	}
	return p.hook, int64(len(line)), true
}

func newTailerTestDetector(t *testing.T) (*Detector, *bytes.Buffer, *storage.Store) {
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
	cfg := DefaultConfig()
	cfg.MinSamples = 1 // activate detection immediately for testing
	return NewDetector(store, sink, cfg), &buf, store
}

func TestLogTailer_MissingDir(t *testing.T) {
	det, buf, _ := newTailerTestDetector(t)

	var sinkBuf bytes.Buffer
	sink := alert.NewSink(&sinkBuf, alert.Options{})
	lt := NewLogTailer("/nonexistent-dir-ccguard-test", det, sink, nil)

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	lt.Run(ctx) // should return immediately

	if !strings.Contains(sinkBuf.String(), "not found") {
		t.Errorf("expected 'not found' warning; got: %s", sinkBuf.String())
	}
	_ = buf // silence unused
}

func TestLogTailer_NoOpParserSkipsLines(t *testing.T) {
	det, _, store := newTailerTestDetector(t)
	logDir := t.TempDir()

	var sinkBuf bytes.Buffer
	sink := alert.NewSink(&sinkBuf, alert.Options{})
	lt := NewLogTailer(logDir, det, sink, nil) // nil → NoOpParser

	// Write a log file before tailer starts (tailer seeks to end, so these
	// lines are ignored). Then write new lines after.
	logPath := filepath.Join(logDir, "hooks.log")
	f, err := os.Create(logPath)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		lt.Run(ctx)
		close(done)
	}()

	// Give the tailer time to start and discover the file.
	time.Sleep(100 * time.Millisecond)

	// Write a line — NoOpParser should skip it.
	if _, err := f.WriteString("some hook line\n"); err != nil {
		t.Fatal(err)
	}
	f.Close()

	time.Sleep(700 * time.Millisecond) // wait for one poll cycle
	cancel()
	<-done

	execs, err := store.RecentExecutions("", 10)
	if err != nil {
		// RecentExecutions with empty hookName is fine — returns nothing.
	}
	// Confirm no executions recorded (NoOpParser skips everything).
	all, _ := store.DistinctHookNames()
	if len(all) != 0 || len(execs) != 0 {
		t.Errorf("NoOpParser should record nothing; got hooks=%v", all)
	}
}

func TestLogTailer_CustomParserRecordsLines(t *testing.T) {
	det, _, store := newTailerTestDetector(t)
	logDir := t.TempDir()

	var sinkBuf bytes.Buffer
	sink := alert.NewSink(&sinkBuf, alert.Options{})
	lt := NewLogTailer(logDir, det, sink, fixedParser{hook: "MyHook"})

	logPath := filepath.Join(logDir, "hooks.log")
	f, err := os.Create(logPath)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		lt.Run(ctx)
		close(done)
	}()

	// Wait for tailer to start and discover the file (seek to end of empty file).
	time.Sleep(100 * time.Millisecond)

	// Append two complete lines.
	if _, err := f.WriteString("line one\nline two\n"); err != nil {
		t.Fatal(err)
	}
	f.Close()

	time.Sleep(700 * time.Millisecond) // wait for one poll cycle
	cancel()
	<-done

	execs, err := store.RecentExecutions("MyHook", 10)
	if err != nil {
		t.Fatalf("RecentExecutions: %v", err)
	}
	if len(execs) != 2 {
		t.Errorf("expected 2 executions recorded, got %d", len(execs))
	}
	for _, e := range execs {
		if e.Source != "log" {
			t.Errorf("expected source=log, got %q", e.Source)
		}
	}
}

func TestLogTailer_CancelStopsRun(t *testing.T) {
	det, _, _ := newTailerTestDetector(t)
	logDir := t.TempDir()

	var sinkBuf bytes.Buffer
	sink := alert.NewSink(&sinkBuf, alert.Options{})
	lt := NewLogTailer(logDir, det, sink, nil)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		lt.Run(ctx)
		close(done)
	}()

	time.Sleep(50 * time.Millisecond)
	cancel()

	select {
	case <-done:
		// good
	case <-time.After(2 * time.Second):
		t.Error("Run() did not stop after context cancel")
	}
}
