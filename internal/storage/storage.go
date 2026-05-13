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
		db.Close()
		return nil, err
	}
	return &Store{db: db}, nil
}

// Close releases the database handle.
func (s *Store) Close() error {
	return s.db.Close()
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
