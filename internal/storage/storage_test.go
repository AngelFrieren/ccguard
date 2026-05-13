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

// --- Phase 3 tests ---

func TestRecordAndRecentExecutions(t *testing.T) {
	s := newTestStore(t)
	for i := 0; i < 5; i++ {
		if err := s.RecordExecution("MyHook", int64(100+i), 0, "wrap"); err != nil {
			t.Fatalf("RecordExecution: %v", err)
		}
	}
	execs, err := s.RecentExecutions("MyHook", 3)
	if err != nil {
		t.Fatalf("RecentExecutions: %v", err)
	}
	if len(execs) != 3 {
		t.Errorf("want 3 results, got %d", len(execs))
	}
	// Results are ordered newest first.
	if execs[0].DurationMs <= execs[len(execs)-1].DurationMs {
		t.Errorf("expected descending order by id")
	}
}

func TestMaxExecutionID(t *testing.T) {
	s := newTestStore(t)
	id, err := s.MaxExecutionID()
	if err != nil {
		t.Fatal(err)
	}
	if id != 0 {
		t.Errorf("want 0 for empty table, got %d", id)
	}
	_ = s.RecordExecution("h", 100, 0, "wrap")
	id, _ = s.MaxExecutionID()
	if id == 0 {
		t.Error("expected non-zero id after insert")
	}
}

func TestExecutionsSince(t *testing.T) {
	s := newTestStore(t)
	_ = s.RecordExecution("h", 100, 0, "wrap") // id=1
	_ = s.RecordExecution("h", 200, 0, "wrap") // id=2
	_ = s.RecordExecution("h", 300, 0, "wrap") // id=3

	execs, err := s.ExecutionsSince(1)
	if err != nil {
		t.Fatal(err)
	}
	if len(execs) != 2 {
		t.Errorf("want 2 results after id=1, got %d", len(execs))
	}
}

func TestDistinctHookNames(t *testing.T) {
	s := newTestStore(t)
	_ = s.RecordExecution("Alpha", 100, 0, "wrap")
	_ = s.RecordExecution("Beta", 200, 0, "wrap")
	_ = s.RecordExecution("Alpha", 150, 0, "wrap")

	names, err := s.DistinctHookNames()
	if err != nil {
		t.Fatal(err)
	}
	if len(names) != 2 {
		t.Errorf("want 2 distinct names, got %d: %v", len(names), names)
	}
}

func TestUpsertAndGetBaselineStats(t *testing.T) {
	s := newTestStore(t)
	if err := s.UpsertBaselineStats("MyHook", 30, 100.0, 10.0); err != nil {
		t.Fatalf("UpsertBaselineStats: %v", err)
	}
	bs, err := s.GetBaselineStats("MyHook")
	if err != nil {
		t.Fatal(err)
	}
	if bs == nil {
		t.Fatal("expected non-nil stats")
	}
	if bs.SampleCount != 30 || bs.MeanMs != 100.0 || bs.StddevMs != 10.0 {
		t.Errorf("stats mismatch: %+v", bs)
	}
	// Non-existent hook returns nil.
	absent, err := s.GetBaselineStats("NonExistent")
	if err != nil || absent != nil {
		t.Errorf("expected nil, nil for unknown hook; got %v, %v", absent, err)
	}
}

// --- Phase 4 tests ---

func TestBehaviorEventRoundtrip(t *testing.T) {
	s := newTestStore(t)
	ev := BehaviorEvent{
		Ts:       1700000000,
		Backend:  "procfs",
		Pid:      1234,
		Ppid:     1000,
		Syscall:  "execve",
		ArgsJSON: `["/usr/bin/curl","https://example.com"]`,
		PolicyID: "CCG-POLICY-0001",
		Severity: "high",
	}
	if err := s.RecordBehaviorEvent(ev); err != nil {
		t.Fatalf("RecordBehaviorEvent: %v", err)
	}
	rows, err := s.RecentBehaviorEvents(1)
	if err != nil {
		t.Fatalf("RecentBehaviorEvents: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("expected 1 row, got %d", len(rows))
	}
	r := rows[0]
	if r.Backend != "procfs" || r.Pid != 1234 || r.PolicyID != "CCG-POLICY-0001" {
		t.Errorf("roundtrip mismatch: %+v", r)
	}
}

func TestBatchRecordBehaviorEvents(t *testing.T) {
	s := newTestStore(t)
	evs := make([]BehaviorEvent, 10)
	for i := range evs {
		evs[i] = BehaviorEvent{
			Ts:       int64(1700000000 + i),
			Backend:  "procfs",
			Pid:      1000 + i,
			Ppid:     999,
			Syscall:  "execve",
			ArgsJSON: `[]`,
		}
	}
	if err := s.BatchRecordBehaviorEvents(evs); err != nil {
		t.Fatalf("BatchRecordBehaviorEvents: %v", err)
	}
	n, err := s.CountBehaviorEventsSince(1700000000)
	if err != nil {
		t.Fatalf("CountBehaviorEventsSince: %v", err)
	}
	if n != 10 {
		t.Errorf("expected 10 events, got %d", n)
	}
}

func TestCountBehaviorEventsSince(t *testing.T) {
	s := newTestStore(t)
	_ = s.RecordBehaviorEvent(BehaviorEvent{Ts: 100, Backend: "procfs", Syscall: "execve", ArgsJSON: "[]"})
	_ = s.RecordBehaviorEvent(BehaviorEvent{Ts: 200, Backend: "procfs", Syscall: "execve", ArgsJSON: "[]"})
	_ = s.RecordBehaviorEvent(BehaviorEvent{Ts: 300, Backend: "procfs", Syscall: "execve", ArgsJSON: "[]"})

	n, err := s.CountBehaviorEventsSince(200)
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Errorf("expected 2 events since ts=200, got %d", n)
	}
}

func TestDeleteBaselineAndExecutions(t *testing.T) {
	s := newTestStore(t)
	_ = s.UpsertBaselineStats("A", 10, 50.0, 5.0)
	_ = s.UpsertBaselineStats("B", 20, 80.0, 8.0)
	_ = s.RecordExecution("A", 50, 0, "wrap")

	if err := s.DeleteBaselineStats("A"); err != nil {
		t.Fatal(err)
	}
	bs, _ := s.GetBaselineStats("A")
	if bs != nil {
		t.Error("expected nil after delete")
	}
	bsB, _ := s.GetBaselineStats("B")
	if bsB == nil {
		t.Error("B should still exist")
	}

	if err := s.DeleteExecutions("A"); err != nil {
		t.Fatal(err)
	}
	execs, _ := s.RecentExecutions("A", 10)
	if len(execs) != 0 {
		t.Errorf("expected 0 after delete, got %d", len(execs))
	}
}
