// Package policy implements Phase 4's behavioral policy DSL.
// Policies are YAML files that describe which process behaviors should trigger
// alerts. The package mirrors internal/ioc: LoadDir walks a directory, and
// DB.Eval matches a behavior.Event against loaded policies.
//
// Unknown policy fields and unsupported syscall kinds are logged and skipped
// rather than returning errors, ensuring forward compatibility with future
// policy schema versions.
package policy

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// Severity describes how serious a policy violation is.
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
)

// Action defines the response when a policy matches.
type Action string

const (
	ActionAlert Action = "alert"
	ActionWarn  Action = "warn"
	// ActionBlock is only meaningful with -tags active-enforcement.
)

// When holds the match conditions for a policy rule.
type When struct {
	Syscall                   string   `yaml:"syscall"`                      // execve | openat | connect
	PathGlob                  string   `yaml:"path_glob"`                    // openat: glob on file path
	CommandBasenameIn         []string `yaml:"command_basename_in"`          // execve: command basename list
	DestinationNotInAllowlist []string `yaml:"destination_not_in_allowlist"` // connect: deny-by-default allowlist
}

// Policy is a single behavioral policy entry.
type Policy struct {
	ID          string   `yaml:"id"`
	Severity    Severity `yaml:"severity"`
	Description string   `yaml:"description"`
	When        When     `yaml:"when"`
	Action      Action   `yaml:"action"`
}

type policyFile struct {
	Version  int      `yaml:"version"`
	Policies []Policy `yaml:"policies"`
}

// Event is the behavioral observation presented to DB.Eval.
// The watch integration code populates it from a behavior.Event.
type Event struct {
	Syscall     string // execve | openat | connect
	CmdBasename string // filepath.Base(args[0]) for execve
	Path        string // file path for openat
	Destination string // host:port for connect
}

// Match holds a policy that matched a given event.
type Match struct {
	Policy Policy
	Event  Event
}

// Source describes where a DB's policies were loaded from.
type Source string

const (
	// SourceUser indicates policies were loaded from the user's config directory.
	SourceUser Source = "user"
	// SourceBuiltin indicates the built-in default policies were used as a
	// fallback because the user config directory contained no *.yaml files.
	SourceBuiltin Source = "built-in"
)

// DB holds all loaded policies.
type DB struct {
	policies []Policy
	// Source records whether policies came from the user's directory or the
	// built-in defaults. Set by LoadWithFallback; empty for other loaders.
	Source Source
}

// Len returns the number of loaded policies.
func (db *DB) Len() int { return len(db.policies) }

// All returns all loaded policies.
func (db *DB) All() []Policy {
	out := make([]Policy, len(db.policies))
	copy(out, db.policies)
	return out
}

// LoadDir loads all *.yaml / *.yml files from dir recursively.
// Files that fail to parse or contain invalid policy entries are logged and
// skipped. Returns an empty DB without error when dir does not exist.
func LoadDir(dir string) (*DB, error) {
	db := &DB{}
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		return db, nil
	}
	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		ext := strings.ToLower(filepath.Ext(path))
		if ext != ".yaml" && ext != ".yml" {
			return nil
		}
		data, readErr := os.ReadFile(path)
		if readErr != nil {
			log.Printf("ccguard policy: read %s: %v (skipping)", path, readErr)
			return nil
		}
		var f policyFile
		if parseErr := yaml.Unmarshal(data, &f); parseErr != nil {
			log.Printf("ccguard policy: parse %s: %v (skipping)", path, parseErr)
			return nil
		}
		for _, p := range f.Policies {
			if err := validatePolicy(p); err != nil {
				log.Printf("ccguard policy: %s: policy %s: %v (skipping)", path, p.ID, err)
				continue
			}
			db.policies = append(db.policies, p)
		}
		return nil
	})
	return db, err
}

// LoadFile loads policies from a single YAML file.
// Used by `ccguard policy check`.
func LoadFile(path string) (*DB, []error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return &DB{}, []error{fmt.Errorf("read: %w", err)}
	}
	return parseBytes(data)
}

// LoadWithFallback loads policies from dir. If dir does not exist or contains
// no *.yaml / *.yml files, it falls back to the built-in default policies
// embedded in the binary and sets DB.Source = SourceBuiltin. When user
// policies are found, DB.Source = SourceUser.
func LoadWithFallback(dir string) (*DB, error) {
	db, err := LoadDir(dir)
	if err != nil {
		return db, err
	}
	if db.Len() > 0 {
		db.Source = SourceUser
		return db, nil
	}
	// No user policies — use built-in defaults.
	db, _ = parseBytes(DefaultPoliciesYAML())
	db.Source = SourceBuiltin
	return db, nil
}

// parseBytes parses a policyFile from raw YAML bytes and validates each entry.
// Invalid policies are collected as errors; valid ones are added to the returned DB.
func parseBytes(data []byte) (*DB, []error) {
	db := &DB{}
	var errs []error
	var f policyFile
	if err := yaml.Unmarshal(data, &f); err != nil {
		return db, []error{fmt.Errorf("parse: %w", err)}
	}
	for _, p := range f.Policies {
		if err := validatePolicy(p); err != nil {
			errs = append(errs, fmt.Errorf("policy %s: %w", p.ID, err))
			continue
		}
		db.policies = append(db.policies, p)
	}
	return db, errs
}

func validatePolicy(p Policy) error {
	switch p.When.Syscall {
	case "execve", "openat", "connect":
		// valid
	case "":
		return fmt.Errorf("when.syscall is required")
	default:
		return fmt.Errorf("unknown when.syscall %q", p.When.Syscall)
	}
	switch p.Action {
	case ActionAlert, ActionWarn:
		// valid
	case "block":
		return fmt.Errorf("action %q requires -tags active-enforcement build", p.Action)
	default:
		return fmt.Errorf("unknown action %q", p.Action)
	}
	return nil
}

// Eval evaluates ev against all loaded policies and returns all matches.
func (db *DB) Eval(ev Event) []Match {
	var out []Match
	for _, p := range db.policies {
		if matchPolicy(p, ev) {
			out = append(out, Match{Policy: p, Event: ev})
		}
	}
	return out
}

func matchPolicy(p Policy, ev Event) bool {
	w := p.When
	if w.Syscall != ev.Syscall {
		return false
	}
	switch ev.Syscall {
	case "execve":
		if len(w.CommandBasenameIn) > 0 {
			// Normalize to basename here so that backends passing a full path
			// (e.g. "/tmp/secret-tool") still match a policy that lists the
			// basename ("secret-tool"). filepath.Base is idempotent when the
			// value is already a basename.
			cmdBase := filepath.Base(ev.CmdBasename)
			found := false
			for _, name := range w.CommandBasenameIn {
				if cmdBase == name {
					found = true
					break
				}
			}
			if !found {
				return false
			}
		}
	case "openat":
		if w.PathGlob != "" {
			ok, err := filepath.Match(w.PathGlob, ev.Path)
			if err != nil || !ok {
				return false
			}
		}
	case "connect":
		if len(w.DestinationNotInAllowlist) > 0 {
			for _, allowed := range w.DestinationNotInAllowlist {
				if ev.Destination == allowed {
					return false // destination is in the allowlist — no match
				}
			}
			// destination not in allowlist → match
		}
	}
	return true
}
