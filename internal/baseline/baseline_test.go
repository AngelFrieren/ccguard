package baseline

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/AngelFrieren/ccguard/internal/alert"
	"github.com/AngelFrieren/ccguard/internal/storage"
)

// --- test helpers ---

func newTestDetector(t *testing.T, cfg Config) (*Detector, *bytes.Buffer, *storage.Store) {
	t.Helper()
	dir := t.TempDir()
	store, err := storage.Open(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("storage.Open: %v", err)
	}
	if err := store.Migrate(); err != nil {
		t.Fatalf("store.Migrate: %v", err)
	}
	t.Cleanup(func() { store.Close() })

	var buf bytes.Buffer
	sink := alert.NewSink(&buf, alert.Options{})
	return NewDetector(store, sink, cfg), &buf, store
}

// seedStats populates baseline_stats AND inserts sampleCount execution records
// at meanMs so that subsequent recomputations stay close to the seeded values.
func seedStats(t *testing.T, store *storage.Store, hookName string, sampleCount int, meanMs, stddevMs float64) {
	t.Helper()
	if err := store.UpsertBaselineStats(hookName, sampleCount, meanMs, stddevMs); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < sampleCount; i++ {
		_ = store.RecordExecution(hookName, int64(meanMs), 0, "test")
	}
}

// --- calcMeanStddev unit tests ---

func TestCalcMeanStddev_Empty(t *testing.T) {
	mean, stddev := calcMeanStddev(nil)
	if mean != 0 || stddev != 0 {
		t.Errorf("empty: got mean=%v stddev=%v", mean, stddev)
	}
}

func TestCalcMeanStddev_Single(t *testing.T) {
	mean, stddev := calcMeanStddev([]float64{42})
	if mean != 42 || stddev != 0 {
		t.Errorf("single: got mean=%v stddev=%v", mean, stddev)
	}
}

func TestCalcMeanStddev_Known(t *testing.T) {
	// 90, 110, 90, 110, ... (alternating) → mean=100
	// variance = (10^2 + 10^2) / (2-1) for pair = 200 (Bessel)
	// For n values of alternating 90/110:
	// mean = 100 always
	// stddev = sqrt(sum((d-100)^2)/(n-1))
	// Each element contributes 100; total = 100*n; divides by n-1.
	// For n=2: sum=200, div by 1 → stddev=sqrt(200)≈14.14
	// For n=4: sum=400, div by 3 → stddev=sqrt(133.3)≈11.55
	xs := []float64{90, 110, 90, 110}
	mean, stddev := calcMeanStddev(xs)
	if mean != 100 {
		t.Errorf("mean: got %v want 100", mean)
	}
	// stddev = sqrt(400/3) ≈ 11.547
	if stddev < 11 || stddev > 12 {
		t.Errorf("stddev: got %v want ~11.55", stddev)
	}
}

// --- Detector tests ---

func TestDetector_ColdStart(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MinSamples = 30
	det, buf, _ := newTestDetector(t, cfg)

	// Only 5 executions — below MinSamples; no alert expected.
	for i := 0; i < 5; i++ {
		_ = det.RecordAndCheck("TestHook", 100, 0, "wrap")
	}
	// Trigger a "slow" execution — should still not alert.
	_ = det.RecordAndCheck("TestHook", 99999, 0, "wrap")

	out := buf.String()
	if strings.Contains(out, "ALERT") || strings.Contains(out, "WARN ") {
		t.Errorf("cold start should not emit ALERT or WARN; got:\n%s", out)
	}
}

func TestDetector_WarnZ(t *testing.T) {
	cfg := DefaultConfig()
	cfg.WarnZ = 3.0
	cfg.AlertZ = 5.0
	det, buf, store := newTestDetector(t, cfg)

	// mean=100, stddev=10, samples=30 → z = (130-100)/10 = 3.0 → WARN
	seedStats(t, store, "TestHook", 30, 100.0, 10.0)

	_ = det.RecordAndCheck("TestHook", 131, 0, "wrap") // z=3.1 → WARN
	out := buf.String()
	if !strings.Contains(out, "WARN") {
		t.Errorf("expected WARN at z>3.0; got:\n%s", out)
	}
	if strings.Contains(out, "ALERT") {
		t.Errorf("should not ALERT at z<5.0; got:\n%s", out)
	}
}

func TestDetector_AlertZ(t *testing.T) {
	cfg := DefaultConfig()
	cfg.WarnZ = 3.0
	cfg.AlertZ = 5.0
	det, buf, store := newTestDetector(t, cfg)

	// mean=100, stddev=10 → z = (155-100)/10 = 5.5 → ALERT
	seedStats(t, store, "TestHook", 30, 100.0, 10.0)

	_ = det.RecordAndCheck("TestHook", 155, 0, "wrap")
	out := buf.String()
	if !strings.Contains(out, "ALERT") {
		t.Errorf("expected ALERT at z>5.0; got:\n%s", out)
	}
}

func TestDetector_StddevZero(t *testing.T) {
	cfg := DefaultConfig()
	det, buf, store := newTestDetector(t, cfg)

	// stddev=0 means constant execution time — skip check even for huge deviation.
	seedStats(t, store, "TestHook", 30, 100.0, 0.0)

	_ = det.RecordAndCheck("TestHook", 9999, 0, "wrap")
	out := buf.String()
	if strings.Contains(out, "ALERT") || strings.Contains(out, "WARN ") {
		t.Errorf("stddev=0 should skip anomaly check; got:\n%s", out)
	}
}

func TestDetector_NormalExecution(t *testing.T) {
	cfg := DefaultConfig()
	det, buf, store := newTestDetector(t, cfg)

	// mean=100, stddev=10 → z = (105-100)/10 = 0.5 → no alert
	seedStats(t, store, "TestHook", 30, 100.0, 10.0)
	_ = det.RecordAndCheck("TestHook", 105, 0, "wrap")

	out := buf.String()
	if strings.Contains(out, "ALERT") || strings.Contains(out, "WARN ") {
		t.Errorf("normal execution should not alert; got:\n%s", out)
	}
}

func TestDetector_RateLimit(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Cooldown = 10 * time.Minute // long cooldown
	cfg.WarnZ = 3.0
	cfg.AlertZ = 5.0
	det, buf, store := newTestDetector(t, cfg)

	seedStats(t, store, "TestHook", 30, 100.0, 10.0)

	// Two anomalous executions in quick succession.
	_ = det.RecordAndCheck("TestHook", 200, 0, "wrap") // z=10 → ALERT
	_ = det.RecordAndCheck("TestHook", 200, 0, "wrap") // cooldown → suppressed

	// Count occurrences of "ALERT" in output.
	count := strings.Count(buf.String(), "ALERT")
	if count != 1 {
		t.Errorf("expected exactly 1 ALERT due to rate limit; got %d in:\n%s", count, buf.String())
	}
}

func TestDetector_RateLimitExpiry(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Cooldown = 1 * time.Millisecond // very short for testing
	cfg.WarnZ = 3.0
	cfg.AlertZ = 5.0
	det, buf, store := newTestDetector(t, cfg)

	seedStats(t, store, "TestHook", 30, 100.0, 10.0)

	_ = det.RecordAndCheck("TestHook", 200, 0, "wrap") // ALERT
	time.Sleep(5 * time.Millisecond)                   // let cooldown expire
	_ = det.RecordAndCheck("TestHook", 200, 0, "wrap") // should ALERT again

	count := strings.Count(buf.String(), "ALERT")
	if count != 2 {
		t.Errorf("expected 2 ALERTs after cooldown; got %d", count)
	}
}

func TestDetector_RefreshAllStats(t *testing.T) {
	cfg := DefaultConfig()
	det, _, store := newTestDetector(t, cfg)

	// Insert executions for two hooks without computing stats.
	for i := 0; i < 5; i++ {
		_ = store.RecordExecution("HookA", 100, 0, "wrap")
		_ = store.RecordExecution("HookB", 200, 0, "wrap")
	}

	if err := det.RefreshAllStats(); err != nil {
		t.Fatalf("RefreshAllStats: %v", err)
	}

	for _, hook := range []string{"HookA", "HookB"} {
		bs, err := det.Stats(hook)
		if err != nil {
			t.Fatalf("Stats(%s): %v", hook, err)
		}
		if bs == nil {
			t.Errorf("expected stats for %s after RefreshAllStats", hook)
		}
	}
}

func TestDetector_ResetHook(t *testing.T) {
	cfg := DefaultConfig()
	det, _, store := newTestDetector(t, cfg)

	seedStats(t, store, "TestHook", 30, 100.0, 10.0)
	_ = store.RecordExecution("TestHook", 100, 0, "wrap")

	if err := det.ResetHook("TestHook"); err != nil {
		t.Fatalf("ResetHook: %v", err)
	}

	bs, _ := det.Stats("TestHook")
	if bs != nil {
		t.Error("expected nil stats after reset")
	}
	execs, _ := store.RecentExecutions("TestHook", 10)
	if len(execs) != 0 {
		t.Error("expected 0 executions after reset")
	}
}

func TestDetector_SampleCountBoundary(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MinSamples = 3
	cfg.WarnZ = 3.0
	cfg.AlertZ = 5.0
	det, buf, store := newTestDetector(t, cfg)

	// Seed stats at exactly MinSamples — should activate detection.
	seedStats(t, store, "TestHook", 3, 100.0, 10.0)
	_ = det.RecordAndCheck("TestHook", 200, 0, "wrap") // z=10 → ALERT

	if !strings.Contains(buf.String(), "ALERT") {
		t.Errorf("expected ALERT at exactly MinSamples; got:\n%s", buf.String())
	}
}
