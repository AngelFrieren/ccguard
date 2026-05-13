package policy

import (
	"os"
	"path/filepath"
	"testing"
)

// writeYAML writes content to a *.yaml file in dir and returns the path.
func writeYAML(t *testing.T, dir, name, content string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("writeYAML: %v", err)
	}
	return path
}

const validYAML = `
version: 1
policies:
  - id: CCG-POLICY-0001
    severity: high
    description: detect curl invocation
    when:
      syscall: execve
      command_basename_in: [curl, wget]
    action: alert
  - id: CCG-POLICY-0002
    severity: medium
    description: detect /proc/mem access
    when:
      syscall: openat
      path_glob: "/proc/*/mem"
    action: warn
  - id: CCG-POLICY-0003
    severity: low
    description: detect non-allowlisted connections
    when:
      syscall: connect
      destination_not_in_allowlist:
        - "127.0.0.1:443"
        - "localhost:443"
    action: warn
`

func TestLoadDir_Valid(t *testing.T) {
	dir := t.TempDir()
	writeYAML(t, dir, "test.yaml", validYAML)

	db, err := LoadDir(dir)
	if err != nil {
		t.Fatalf("LoadDir: %v", err)
	}
	if db.Len() != 3 {
		t.Errorf("expected 3 policies, got %d", db.Len())
	}
}

func TestLoadDir_NonExistent(t *testing.T) {
	db, err := LoadDir("/nonexistent-ccguard-test-dir")
	if err != nil {
		t.Fatalf("expected no error for missing dir, got %v", err)
	}
	if db.Len() != 0 {
		t.Errorf("expected 0 policies for missing dir")
	}
}

func TestLoadDir_InvalidYAMLSkipped(t *testing.T) {
	dir := t.TempDir()
	writeYAML(t, dir, "bad.yaml", "}{invalid yaml")
	writeYAML(t, dir, "good.yaml", validYAML)

	db, err := LoadDir(dir)
	if err != nil {
		t.Fatalf("LoadDir: %v", err)
	}
	// bad.yaml skipped, good.yaml loaded with 3 policies
	if db.Len() != 3 {
		t.Errorf("expected 3 policies from good.yaml, got %d", db.Len())
	}
}

func TestLoadDir_UnknownSyscallSkipped(t *testing.T) {
	dir := t.TempDir()
	writeYAML(t, dir, "test.yaml", `
version: 1
policies:
  - id: CCG-POLICY-UNKNOWN
    severity: high
    description: uses unknown syscall
    when:
      syscall: mmap
    action: alert
  - id: CCG-POLICY-VALID
    severity: low
    description: valid policy
    when:
      syscall: execve
    action: warn
`)
	db, err := LoadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if db.Len() != 1 {
		t.Errorf("expected 1 valid policy (unknown skipped), got %d", db.Len())
	}
	if db.All()[0].ID != "CCG-POLICY-VALID" {
		t.Errorf("wrong policy loaded: %s", db.All()[0].ID)
	}
}

func TestLoadDir_BlockActionSkipped(t *testing.T) {
	dir := t.TempDir()
	writeYAML(t, dir, "test.yaml", `
version: 1
policies:
  - id: CCG-POLICY-BLOCK
    severity: critical
    description: block action (not supported without build tag)
    when:
      syscall: execve
    action: block
`)
	db, err := LoadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if db.Len() != 0 {
		t.Errorf("expected 0 policies (block skipped), got %d", db.Len())
	}
}

func TestLoadFile_Errors(t *testing.T) {
	dir := t.TempDir()
	path := writeYAML(t, dir, "mixed.yaml", `
version: 1
policies:
  - id: CCG-POLICY-VALID
    severity: low
    when:
      syscall: execve
    action: warn
  - id: CCG-POLICY-INVALID
    severity: high
    when:
      syscall: unknown_syscall
    action: alert
`)
	db, errs := LoadFile(path)
	if len(errs) != 1 {
		t.Errorf("expected 1 error, got %d: %v", len(errs), errs)
	}
	if db.Len() != 1 {
		t.Errorf("expected 1 valid policy, got %d", db.Len())
	}
}

// --- Eval tests ---

func newDB(t *testing.T, yaml string) *DB {
	t.Helper()
	dir := t.TempDir()
	writeYAML(t, dir, "test.yaml", yaml)
	db, err := LoadDir(dir)
	if err != nil {
		t.Fatalf("LoadDir: %v", err)
	}
	return db
}

func TestEval_ExecveMatch(t *testing.T) {
	db := newDB(t, validYAML)
	matches := db.Eval(Event{Syscall: "execve", CmdBasename: "curl"})
	if len(matches) != 1 || matches[0].Policy.ID != "CCG-POLICY-0001" {
		t.Errorf("expected match on CCG-POLICY-0001; got %+v", matches)
	}
}

func TestEval_ExecveNoMatch(t *testing.T) {
	db := newDB(t, validYAML)
	matches := db.Eval(Event{Syscall: "execve", CmdBasename: "git"})
	if len(matches) != 0 {
		t.Errorf("expected no match for 'git'; got %d", len(matches))
	}
}

func TestEval_OpenatMatch(t *testing.T) {
	db := newDB(t, validYAML)
	matches := db.Eval(Event{Syscall: "openat", Path: "/proc/1234/mem"})
	if len(matches) != 1 || matches[0].Policy.ID != "CCG-POLICY-0002" {
		t.Errorf("expected match on CCG-POLICY-0002; got %+v", matches)
	}
}

func TestEval_OpenatNoMatch(t *testing.T) {
	db := newDB(t, validYAML)
	matches := db.Eval(Event{Syscall: "openat", Path: "/etc/passwd"})
	if len(matches) != 0 {
		t.Errorf("expected no match for /etc/passwd; got %d", len(matches))
	}
}

func TestEval_ConnectNotInAllowlist(t *testing.T) {
	db := newDB(t, validYAML)
	// Destination not in allowlist → should match
	matches := db.Eval(Event{Syscall: "connect", Destination: "8.8.8.8:53"})
	if len(matches) != 1 || matches[0].Policy.ID != "CCG-POLICY-0003" {
		t.Errorf("expected match for non-allowlisted destination; got %+v", matches)
	}
}

func TestEval_ConnectInAllowlist(t *testing.T) {
	db := newDB(t, validYAML)
	// Destination in allowlist → should NOT match
	matches := db.Eval(Event{Syscall: "connect", Destination: "localhost:443"})
	if len(matches) != 0 {
		t.Errorf("expected no match for allowlisted destination; got %d", len(matches))
	}
}

func TestEval_ConnectEmptyAllowlist(t *testing.T) {
	db := newDB(t, `
version: 1
policies:
  - id: CCG-POLICY-CONN-ALL
    severity: low
    description: monitor all connections
    when:
      syscall: connect
    action: warn
`)
	// No allowlist → any connection matches
	matches := db.Eval(Event{Syscall: "connect", Destination: "10.0.0.1:80"})
	if len(matches) != 1 {
		t.Errorf("expected match for connection with no allowlist; got %d", len(matches))
	}
}

func TestEval_ExecveNoCondition(t *testing.T) {
	db := newDB(t, `
version: 1
policies:
  - id: CCG-POLICY-ALL-EXEC
    severity: low
    description: monitor all execve
    when:
      syscall: execve
    action: warn
`)
	// No command_basename_in → matches any execve
	matches := db.Eval(Event{Syscall: "execve", CmdBasename: "anything"})
	if len(matches) != 1 {
		t.Errorf("expected match for unconstrained execve policy; got %d", len(matches))
	}
}

func TestLoadDir_Recursive(t *testing.T) {
	dir := t.TempDir()
	sub := filepath.Join(dir, "subdir")
	if err := os.MkdirAll(sub, 0755); err != nil {
		t.Fatal(err)
	}
	writeYAML(t, dir, "top.yaml", `
version: 1
policies:
  - id: CCG-TOP
    severity: low
    when:
      syscall: execve
    action: warn
`)
	writeYAML(t, sub, "nested.yaml", `
version: 1
policies:
  - id: CCG-NESTED
    severity: low
    when:
      syscall: openat
    action: warn
`)
	db, err := LoadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if db.Len() != 2 {
		t.Errorf("expected 2 policies (top + nested), got %d", db.Len())
	}
}
