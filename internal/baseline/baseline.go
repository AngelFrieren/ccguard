// Package baseline implements Layer 2 of ccguard's 4-layer detection
// architecture: statistical baseline anomaly detection for Claude Code hook
// execution times.
//
// Hook execution durations are recorded over time and compared to a rolling
// baseline (mean ± stddev). When a new execution's duration deviates by more
// than a configurable z-score threshold, a warning or alert is emitted.
//
// This layer is designed to catch T5 threats: malicious hooks that do not
// modify settings.json but instead add heavy background work (encryption,
// large network transfers) each time a hook fires, making them invisible to
// hash-based detection.
package baseline

import (
	"fmt"
	"math"
	"sync"
	"time"

	"github.com/AngelFrieren/ccguard/internal/alert"
	"github.com/AngelFrieren/ccguard/internal/storage"
)

// Config holds anomaly detection parameters. All fields have defaults via
// DefaultConfig(); zero values are not valid — always start from DefaultConfig
// and override specific fields.
type Config struct {
	// MinSamples is the minimum number of executions before anomaly detection
	// activates. During the learning phase, no alerts are emitted.
	MinSamples int

	// Window is the maximum number of recent executions used to compute the
	// baseline. Older executions are ignored.
	Window int

	// WarnZ is the z-score threshold for a Warn-level anomaly (>= WarnZ).
	WarnZ float64

	// AlertZ is the z-score threshold for an Alert-level anomaly (>= AlertZ).
	AlertZ float64

	// Cooldown is the minimum interval between anomaly alerts for the same
	// hook. Prevents alert storms when a hook consistently misbehaves.
	Cooldown time.Duration
}

// DefaultConfig returns production-ready default values.
func DefaultConfig() Config {
	return Config{
		MinSamples: 30,
		Window:     100,
		WarnZ:      3.0,
		AlertZ:     5.0,
		Cooldown:   5 * time.Minute,
	}
}

// Detector records hook executions, maintains a rolling baseline, and emits
// anomaly alerts via an alert.Sink.
type Detector struct {
	store *storage.Store
	sink  *alert.Sink
	cfg   Config

	mu        sync.Mutex
	lastAlert map[string]time.Time // per-hook rate limiting
}

// NewDetector creates a Detector. cfg must be initialised from DefaultConfig().
func NewDetector(store *storage.Store, sink *alert.Sink, cfg Config) *Detector {
	return &Detector{
		store:     store,
		sink:      sink,
		cfg:       cfg,
		lastAlert: make(map[string]time.Time),
	}
}

// RecordAndCheck records one hook execution and checks it against the current
// baseline. If the duration is anomalous and the cooldown has elapsed, an
// alert is emitted via the Sink and recorded in the audit log.
//
// Errors are returned but are non-fatal at the call site: hook-wrap should log
// them and continue so the wrapped command's exit code is always propagated.
func (d *Detector) RecordAndCheck(hookName string, durationMs int64, exitCode int, source string) error {
	// 1. Load pre-existing baseline stats for the anomaly check.
	stats, err := d.store.GetBaselineStats(hookName)
	if err != nil {
		return fmt.Errorf("get baseline stats: %w", err)
	}

	// 2. Determine anomaly level against stored stats (before this execution).
	anomaly := d.checkAnomaly(stats, durationMs)

	// 3. Record the execution.
	if err := d.store.RecordExecution(hookName, durationMs, exitCode, source); err != nil {
		return fmt.Errorf("record execution: %w", err)
	}

	// 4. Recompute and save updated baseline (now includes this execution).
	if err := d.recomputeStats(hookName); err != nil {
		d.sink.Warn("baseline stats update failed", map[string]any{
			"hook":  hookName,
			"error": err.Error(),
		})
	}

	// 5. Emit alert, subject to rate limiting.
	if anomaly.level != "" && d.consumeAlertBudget(hookName) {
		fields := map[string]any{
			"hook":        hookName,
			"duration_ms": durationMs,
			"z_score":     fmt.Sprintf("%.2f", anomaly.z),
			"mean_ms":     fmt.Sprintf("%.1f", stats.MeanMs),
			"stddev_ms":   fmt.Sprintf("%.1f", stats.StddevMs),
			"source":      source,
		}
		msg := "hook execution time anomaly detected (T5)"
		switch anomaly.level {
		case alert.LevelAlert:
			d.sink.Alert(msg, fields)
			_ = d.store.RecordEvent(hookName, "", "baseline-anomaly", source)
		case alert.LevelWarn:
			d.sink.Warn(msg, fields)
		}
	}

	return nil
}

// RefreshAllStats recomputes and saves baseline statistics for every hook that
// has execution records. Called by the watch daemon on startup to sync stats
// for executions that occurred while watch was not running.
func (d *Detector) RefreshAllStats() error {
	hooks, err := d.store.DistinctHookNames()
	if err != nil {
		return fmt.Errorf("distinct hook names: %w", err)
	}
	for _, h := range hooks {
		if err := d.recomputeStats(h); err != nil {
			return fmt.Errorf("refresh stats for %s: %w", h, err)
		}
	}
	return nil
}

// Stats returns current baseline statistics for hookName, or nil if no stats
// have been computed yet.
func (d *Detector) Stats(hookName string) (*storage.BaselineStats, error) {
	return d.store.GetBaselineStats(hookName)
}

// ListStats returns baseline statistics for all hooks.
func (d *Detector) ListStats() ([]storage.BaselineStats, error) {
	return d.store.ListBaselineStats()
}

// ResetHook deletes baseline statistics and execution history for hookName,
// returning that hook to the learning phase.
func (d *Detector) ResetHook(hookName string) error {
	if err := d.store.DeleteBaselineStats(hookName); err != nil {
		return err
	}
	return d.store.DeleteExecutions(hookName)
}

// ResetAll deletes baseline statistics and execution history for all hooks.
func (d *Detector) ResetAll() error {
	if err := d.store.DeleteAllBaselineStats(); err != nil {
		return err
	}
	return d.store.DeleteAllExecutions()
}

// --- internal helpers ---

type anomalyResult struct {
	level alert.Level
	z     float64
}

func (d *Detector) checkAnomaly(stats *storage.BaselineStats, durationMs int64) anomalyResult {
	if stats == nil || stats.SampleCount < d.cfg.MinSamples {
		return anomalyResult{} // still learning
	}
	if stats.StddevMs == 0 {
		return anomalyResult{} // constant execution time — no variance to compare against
	}
	z := (float64(durationMs) - stats.MeanMs) / stats.StddevMs
	switch {
	case z >= d.cfg.AlertZ:
		return anomalyResult{level: alert.LevelAlert, z: z}
	case z >= d.cfg.WarnZ:
		return anomalyResult{level: alert.LevelWarn, z: z}
	default:
		return anomalyResult{}
	}
}

func (d *Detector) consumeAlertBudget(hookName string) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	if last, ok := d.lastAlert[hookName]; ok && time.Since(last) < d.cfg.Cooldown {
		return false
	}
	d.lastAlert[hookName] = time.Now()
	return true
}

func (d *Detector) recomputeStats(hookName string) error {
	execs, err := d.store.RecentExecutions(hookName, d.cfg.Window)
	if err != nil {
		return err
	}
	if len(execs) == 0 {
		return nil
	}
	xs := make([]float64, len(execs))
	for i, e := range execs {
		xs[i] = float64(e.DurationMs)
	}
	mean, stddev := calcMeanStddev(xs)
	return d.store.UpsertBaselineStats(hookName, len(execs), mean, stddev)
}

// calcMeanStddev computes the mean and sample standard deviation (Bessel's
// correction: divides by n−1) of xs. Returns zero stddev for n < 2.
func calcMeanStddev(xs []float64) (mean, stddev float64) {
	n := len(xs)
	if n == 0 {
		return
	}
	sum := 0.0
	for _, x := range xs {
		sum += x
	}
	mean = sum / float64(n)
	if n < 2 {
		return
	}
	sqsum := 0.0
	for _, x := range xs {
		d := x - mean
		sqsum += d * d
	}
	stddev = math.Sqrt(sqsum / float64(n-1))
	return
}
