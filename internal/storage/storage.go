// Package storage persists ccguard's approved-hash baseline and audit log
// in a local SQLite database.
//
// The CGO-free modernc.org/sqlite driver is used so that ccguard builds and
// runs as a pure-Go static binary, which simplifies distribution.
package storage

import (
	"database/sql"
	"errors"
	"fmt"
	"time"

	_ "modernc.org/sqlite"
)

// Store wraps the SQLite handle with ccguard-specific operations.
type Store struct {
	db *sql.DB
}

// Open opens (or creates) the SQLite database at the given path.
func Open(path string) (*Store, error) {
	dsn := fmt.Sprintf("file:%s?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=foreign_keys(on)", path)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	db.SetMaxOpenConns(1) // SQLite + WAL: single writer is simplest and safest here.
	if err := db.Ping(); err != nil {
		_ = db.Close()
		return nil, err
	}
	return &Store{db: db}, nil
}

// Close releases the database handle.
func (s *Store) Close() error {
	return s.db.Close()
}

// Execution is a single hook execution record collected by hook-wrap (Mode B)
// or the log tailer (Mode A).
type Execution struct {
	ID         int64
	Ts         int64 // unix seconds
	HookName   string
	DurationMs int64
	ExitCode   int
	Source     string // "wrap" | "log"
}

// BaselineStats holds computed mean/stddev statistics for a single hook,
// derived from its recent execution history.
type BaselineStats struct {
	HookName    string
	SampleCount int
	MeanMs      float64
	StddevMs    float64
	UpdatedAt   int64 // unix seconds
}

// Migrate creates the schema if missing. Safe to call repeatedly.
func (s *Store) Migrate() error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS approved_hashes (
			path       TEXT NOT NULL,
			sha256     TEXT NOT NULL,
			reason     TEXT NOT NULL DEFAULT '',
			approved_at INTEGER NOT NULL,
			PRIMARY KEY (path, sha256)
		)`,
		`CREATE INDEX IF NOT EXISTS approved_hashes_path_idx ON approved_hashes(path)`,
		`CREATE TABLE IF NOT EXISTS events (
			id        INTEGER PRIMARY KEY AUTOINCREMENT,
			ts        INTEGER NOT NULL,
			path      TEXT NOT NULL,
			sha256    TEXT NOT NULL DEFAULT '',
			kind      TEXT NOT NULL,
			fs_op     TEXT NOT NULL DEFAULT ''
		)`,
		`CREATE INDEX IF NOT EXISTS events_ts_idx ON events(ts)`,
		`CREATE INDEX IF NOT EXISTS events_path_idx ON events(path)`,
	}
	for _, q := range stmts {
		if _, err := s.db.Exec(q); err != nil {
			return fmt.Errorf("migrate (%s...): %w", q[:40], err)
		}
	}
	// Phase 2 additive migration: ioc_id column on events.
	if err := s.addColumnIfMissing("events", "ioc_id", "TEXT NOT NULL DEFAULT ''"); err != nil {
		return fmt.Errorf("migrate events.ioc_id: %w", err)
	}

	// Phase 3: hook execution timing and baseline statistics tables.
	phase3 := []string{
		`CREATE TABLE IF NOT EXISTS hook_executions (
			id          INTEGER PRIMARY KEY AUTOINCREMENT,
			ts          INTEGER NOT NULL,
			hook_name   TEXT NOT NULL,
			duration_ms INTEGER NOT NULL,
			exit_code   INTEGER NOT NULL,
			source      TEXT NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS hook_executions_name_ts_idx ON hook_executions(hook_name, ts)`,
		`CREATE TABLE IF NOT EXISTS baseline_stats (
			hook_name    TEXT PRIMARY KEY,
			sample_count INTEGER NOT NULL,
			mean_ms      REAL NOT NULL,
			stddev_ms    REAL NOT NULL,
			updated_at   INTEGER NOT NULL
		)`,
	}
	for _, q := range phase3 {
		if _, err := s.db.Exec(q); err != nil {
			return fmt.Errorf("migrate phase3 (%s...): %w", q[:min(len(q), 40)], err)
		}
	}

	// Phase 4: behavioral monitoring tables.
	phase4 := []string{
		`CREATE TABLE IF NOT EXISTS behavior_events (
			id        INTEGER PRIMARY KEY AUTOINCREMENT,
			ts        INTEGER NOT NULL,
			backend   TEXT NOT NULL,
			pid       INTEGER NOT NULL,
			ppid      INTEGER NOT NULL,
			syscall   TEXT NOT NULL,
			args_json TEXT NOT NULL,
			policy_id TEXT NOT NULL DEFAULT '',
			severity  TEXT NOT NULL DEFAULT ''
		)`,
		`CREATE INDEX IF NOT EXISTS behavior_events_ts_idx ON behavior_events(ts)`,
		`CREATE INDEX IF NOT EXISTS behavior_events_pid_idx ON behavior_events(pid)`,
	}
	for _, q := range phase4 {
		if _, err := s.db.Exec(q); err != nil {
			return fmt.Errorf("migrate phase4 (%s...): %w", q[:min(len(q), 40)], err)
		}
	}
	return nil
}

// addColumnIfMissing adds a column to a table only if it is not present.
// This makes column-level migrations idempotent without requiring a schema
// version table.
func (s *Store) addColumnIfMissing(table, column, definition string) error {
	rows, err := s.db.Query(fmt.Sprintf(`PRAGMA table_info("%s")`, table))
	if err != nil {
		return fmt.Errorf("table_info %s: %w", table, err)
	}
	defer rows.Close()
	for rows.Next() {
		var cid, notNull, pk int
		var name, colType string
		var dflt interface{}
		if err := rows.Scan(&cid, &name, &colType, &notNull, &dflt, &pk); err != nil {
			return err
		}
		if name == column {
			return nil // already present
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	_, err = s.db.Exec(fmt.Sprintf(`ALTER TABLE "%s" ADD COLUMN %s %s`, table, column, definition))
	return err
}

// Approve records (path, sha256) as an approved combination.
func (s *Store) Approve(path, sha256, reason string) error {
	_, err := s.db.Exec(
		`INSERT OR REPLACE INTO approved_hashes(path, sha256, reason, approved_at) VALUES(?, ?, ?, ?)`,
		path, sha256, reason, time.Now().Unix(),
	)
	if err != nil {
		return err
	}
	return s.RecordEvent(path, sha256, "approved", "manual")
}

// IsApproved reports whether the (path, sha256) pair has been approved.
func (s *Store) IsApproved(path, sha256 string) (bool, error) {
	var n int
	err := s.db.QueryRow(
		`SELECT COUNT(1) FROM approved_hashes WHERE path = ? AND sha256 = ?`,
		path, sha256,
	).Scan(&n)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return false, err
	}
	return n > 0, nil
}

// CountApproved returns the total number of approved entries.
func (s *Store) CountApproved() (int, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(1) FROM approved_hashes`).Scan(&n)
	if err != nil {
		return 0, err
	}
	return n, nil
}

// ClearApproved removes all approval entries (used by `init --force`).
func (s *Store) ClearApproved() error {
	_, err := s.db.Exec(`DELETE FROM approved_hashes`)
	return err
}

// RecordEvent appends an entry to the audit log. Errors are returned but
// non-fatal at the call site.
func (s *Store) RecordEvent(path, sha256, kind, fsOp string) error {
	_, err := s.db.Exec(
		`INSERT INTO events(ts, path, sha256, kind, fs_op) VALUES(?, ?, ?, ?, ?)`,
		time.Now().Unix(), path, sha256, kind, fsOp,
	)
	return err
}

// RecordIOCEvent appends an IOC-match event to the audit log, including the
// matched indicator ID so that the event can be correlated with the IOC
// database after the fact.
func (s *Store) RecordIOCEvent(path, sha256, fsOp, iocID string) error {
	_, err := s.db.Exec(
		`INSERT INTO events(ts, path, sha256, kind, fs_op, ioc_id) VALUES(?, ?, ?, 'ioc-match', ?, ?)`,
		time.Now().Unix(), path, sha256, fsOp, iocID,
	)
	return err
}

// --- Phase 3: hook execution timing ---

// RecordExecution appends a hook execution record.
func (s *Store) RecordExecution(hookName string, durationMs int64, exitCode int, source string) error {
	_, err := s.db.Exec(
		`INSERT INTO hook_executions(ts, hook_name, duration_ms, exit_code, source) VALUES(?, ?, ?, ?, ?)`,
		time.Now().Unix(), hookName, durationMs, exitCode, source,
	)
	return err
}

// RecentExecutions returns the most recent limit executions for hookName,
// ordered newest first.
func (s *Store) RecentExecutions(hookName string, limit int) ([]Execution, error) {
	rows, err := s.db.Query(
		`SELECT id, ts, hook_name, duration_ms, exit_code, source
		 FROM hook_executions
		 WHERE hook_name = ?
		 ORDER BY id DESC LIMIT ?`,
		hookName, limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanExecutions(rows)
}

// ExecutionsSince returns executions with id > afterID, ordered oldest first.
// Used by the watch daemon to process new hook-wrap records on startup.
func (s *Store) ExecutionsSince(afterID int64) ([]Execution, error) {
	rows, err := s.db.Query(
		`SELECT id, ts, hook_name, duration_ms, exit_code, source
		 FROM hook_executions WHERE id > ? ORDER BY id ASC`,
		afterID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanExecutions(rows)
}

// MaxExecutionID returns the highest execution ID currently in the table, or 0
// if the table is empty. Used by the watch daemon to set a watermark.
func (s *Store) MaxExecutionID() (int64, error) {
	var id int64
	err := s.db.QueryRow(`SELECT COALESCE(MAX(id), 0) FROM hook_executions`).Scan(&id)
	return id, err
}

// DistinctHookNames returns all hook names that have at least one execution.
func (s *Store) DistinctHookNames() ([]string, error) {
	rows, err := s.db.Query(`SELECT DISTINCT hook_name FROM hook_executions ORDER BY hook_name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var names []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			return nil, err
		}
		names = append(names, n)
	}
	return names, rows.Err()
}

func scanExecutions(rows *sql.Rows) ([]Execution, error) {
	var out []Execution
	for rows.Next() {
		var e Execution
		if err := rows.Scan(&e.ID, &e.Ts, &e.HookName, &e.DurationMs, &e.ExitCode, &e.Source); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// --- Phase 3: baseline statistics ---

// UpsertBaselineStats saves computed statistics for a hook.
func (s *Store) UpsertBaselineStats(hookName string, sampleCount int, meanMs, stddevMs float64) error {
	_, err := s.db.Exec(
		`INSERT OR REPLACE INTO baseline_stats(hook_name, sample_count, mean_ms, stddev_ms, updated_at)
		 VALUES(?, ?, ?, ?, ?)`,
		hookName, sampleCount, meanMs, stddevMs, time.Now().Unix(),
	)
	return err
}

// GetBaselineStats returns stored statistics for hookName, or nil if none exist.
func (s *Store) GetBaselineStats(hookName string) (*BaselineStats, error) {
	var b BaselineStats
	err := s.db.QueryRow(
		`SELECT hook_name, sample_count, mean_ms, stddev_ms, updated_at
		 FROM baseline_stats WHERE hook_name = ?`,
		hookName,
	).Scan(&b.HookName, &b.SampleCount, &b.MeanMs, &b.StddevMs, &b.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &b, nil
}

// ListBaselineStats returns statistics for all hooks, ordered by hook name.
func (s *Store) ListBaselineStats() ([]BaselineStats, error) {
	rows, err := s.db.Query(
		`SELECT hook_name, sample_count, mean_ms, stddev_ms, updated_at
		 FROM baseline_stats ORDER BY hook_name`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []BaselineStats
	for rows.Next() {
		var b BaselineStats
		if err := rows.Scan(&b.HookName, &b.SampleCount, &b.MeanMs, &b.StddevMs, &b.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, rows.Err()
}

// DeleteBaselineStats removes statistics for hookName.
func (s *Store) DeleteBaselineStats(hookName string) error {
	_, err := s.db.Exec(`DELETE FROM baseline_stats WHERE hook_name = ?`, hookName)
	return err
}

// DeleteAllBaselineStats removes statistics for every hook.
func (s *Store) DeleteAllBaselineStats() error {
	_, err := s.db.Exec(`DELETE FROM baseline_stats`)
	return err
}

// DeleteExecutions removes execution records for hookName.
func (s *Store) DeleteExecutions(hookName string) error {
	_, err := s.db.Exec(`DELETE FROM hook_executions WHERE hook_name = ?`, hookName)
	return err
}

// DeleteAllExecutions removes all execution records.
func (s *Store) DeleteAllExecutions() error {
	_, err := s.db.Exec(`DELETE FROM hook_executions`)
	return err
}

// --- Phase 4: behavioral monitoring ---

// BehaviorEvent is a single behavioral observation from a Phase 4 backend.
type BehaviorEvent struct {
	ID       int64
	Ts       int64  // unix seconds
	Backend  string // procfs | auditd | ebpf
	Pid      int
	Ppid     int
	Syscall  string
	ArgsJSON string // JSON array of argument strings
	PolicyID string
	Severity string
}

// RecordBehaviorEvent appends one behavioral observation to the audit log.
func (s *Store) RecordBehaviorEvent(ev BehaviorEvent) error {
	_, err := s.db.Exec(
		`INSERT INTO behavior_events(ts,backend,pid,ppid,syscall,args_json,policy_id,severity)
		 VALUES(?,?,?,?,?,?,?,?)`,
		ev.Ts, ev.Backend, ev.Pid, ev.Ppid, ev.Syscall, ev.ArgsJSON, ev.PolicyID, ev.Severity,
	)
	return err
}

// BatchRecordBehaviorEvents writes multiple events in a single transaction.
// Callers should batch 100 ms worth of events (or 100 events) before calling
// this to reduce write amplification on the SQLite database.
func (s *Store) BatchRecordBehaviorEvents(evs []BehaviorEvent) error {
	if len(evs) == 0 {
		return nil
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	stmt, err := tx.Prepare(
		`INSERT INTO behavior_events(ts,backend,pid,ppid,syscall,args_json,policy_id,severity)
		 VALUES(?,?,?,?,?,?,?,?)`,
	)
	if err != nil {
		_ = tx.Rollback()
		return err
	}
	defer stmt.Close()
	for _, ev := range evs {
		if _, err := stmt.Exec(ev.Ts, ev.Backend, ev.Pid, ev.Ppid, ev.Syscall,
			ev.ArgsJSON, ev.PolicyID, ev.Severity); err != nil {
			_ = tx.Rollback()
			return err
		}
	}
	return tx.Commit()
}

// RecentBehaviorEvents returns the most recent limit behavioral events, newest first.
func (s *Store) RecentBehaviorEvents(limit int) ([]BehaviorEvent, error) {
	rows, err := s.db.Query(
		`SELECT id,ts,backend,pid,ppid,syscall,args_json,policy_id,severity
		 FROM behavior_events ORDER BY id DESC LIMIT ?`, limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanBehaviorEvents(rows)
}

// CountBehaviorEventsSince returns the count of behavior events with ts >= since.
func (s *Store) CountBehaviorEventsSince(since int64) (int, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(1) FROM behavior_events WHERE ts >= ?`, since).Scan(&n)
	return n, err
}

func scanBehaviorEvents(rows *sql.Rows) ([]BehaviorEvent, error) {
	var out []BehaviorEvent
	for rows.Next() {
		var e BehaviorEvent
		if err := rows.Scan(&e.ID, &e.Ts, &e.Backend, &e.Pid, &e.Ppid,
			&e.Syscall, &e.ArgsJSON, &e.PolicyID, &e.Severity); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
