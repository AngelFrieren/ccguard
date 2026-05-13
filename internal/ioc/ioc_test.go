package ioc

import (
	"os"
	"path/filepath"
	"testing"
)

const validYAML = `
version: 1
indicators:
  - id: CCG-TEST-0001
    severity: critical
    description: "Known-bad SHA-256"
    references:
      - "https://example.com/advisory"
    match:
      kind: file_sha256
      values:
        - "0000000000000000000000000000000000000000000000000000000000000000"
  - id: CCG-TEST-0002
    severity: high
    description: "Suspicious hook script"
    match:
      kind: file_path_glob
      values:
        - "**/.claude/hooks/*.sh"
`

// --- Loader tests ---

func TestLoadDir(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "test.yaml"), validYAML)

	db, err := LoadDir(dir)
	if err != nil {
		t.Fatalf("LoadDir: %v", err)
	}
	if db.Len() != 2 {
		t.Errorf("want 2 indicators, got %d", db.Len())
	}
}

func TestLoadDirNonExistent(t *testing.T) {
	db, err := LoadDir("/nonexistent/path/ccguard-ioc-test-dir")
	if err != nil {
		t.Fatalf("non-existent dir should succeed; got %v", err)
	}
	if db.Len() != 0 {
		t.Errorf("want 0 indicators, got %d", db.Len())
	}
}

func TestLoadDirInvalidYAMLSkipped(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "bad.yaml"), ":::invalid:::")
	writeFile(t, filepath.Join(dir, "good.yaml"), validYAML)

	db, err := LoadDir(dir)
	if err != nil {
		t.Fatalf("LoadDir: %v", err)
	}
	// bad.yaml is skipped; good.yaml loads 2 indicators.
	if db.Len() != 2 {
		t.Errorf("want 2 indicators from good file, got %d", db.Len())
	}
}

func TestLoadDirRecursive(t *testing.T) {
	dir := t.TempDir()
	subdir := filepath.Join(dir, "sub")
	if err := os.MkdirAll(subdir, 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(dir, "a.yaml"), validYAML)
	writeFile(t, filepath.Join(subdir, "b.yaml"), validYAML)

	db, err := LoadDir(dir)
	if err != nil {
		t.Fatalf("LoadDir: %v", err)
	}
	if db.Len() != 4 {
		t.Errorf("want 4 indicators (2 files × 2 each), got %d", db.Len())
	}
}

func TestDBAll(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "test.yaml"), validYAML)
	db, _ := LoadDir(dir)

	all := db.All()
	if len(all) != db.Len() {
		t.Errorf("All() length %d != Len() %d", len(all), db.Len())
	}
	// Confirm it's a copy: mutating the slice should not affect the DB.
	all[0].ID = "mutated"
	if db.All()[0].ID == "mutated" {
		t.Error("All() returned a live reference instead of a copy")
	}
}

// --- Matcher tests ---

func TestMatchFileSHA256(t *testing.T) {
	db := loadTestDB(t)

	const zeroHash = "0000000000000000000000000000000000000000000000000000000000000000"

	cases := []struct {
		sha256 string
		want   int
	}{
		{zeroHash, 1},
		{"aabbccdd", 0},
		{"", 0},
	}
	for _, tc := range cases {
		got := db.Match("/home/u/.claude/settings.json", tc.sha256)
		if len(got) != tc.want {
			t.Errorf("Match(sha256=%q): got %d, want %d", tc.sha256, len(got), tc.want)
		}
		if tc.want > 0 && got[0].ID != "CCG-TEST-0001" {
			t.Errorf("expected CCG-TEST-0001, got %s", got[0].ID)
		}
	}
}

func TestMatchFilePathGlob(t *testing.T) {
	db := loadTestDB(t)

	cases := []struct {
		path string
		want int
	}{
		{"/home/u/.claude/hooks/evil.sh", 1},
		{"/home/u/.claude/hooks/legit.sh", 1},
		{"/home/u/.claude/settings.json", 0},
		{"/home/u/other/hooks/evil.sh", 0},
		{"/home/u/.claude/hooks/subdir/evil.sh", 0}, // * doesn't cross directory boundary
	}
	for _, tc := range cases {
		got := db.Match(tc.path, "irrelevant")
		if len(got) != tc.want {
			t.Errorf("Match(path=%q): got %d, want %d", tc.path, len(got), tc.want)
		}
	}
}

func TestMatchUnknownKind(t *testing.T) {
	const unknownKindYAML = `
version: 1
indicators:
  - id: CCG-FUTURE-0001
    severity: low
    description: "Uses a future match kind"
    match:
      kind: future_kind
      values:
        - "something"
`
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "test.yaml"), unknownKindYAML)
	db, err := LoadDir(dir)
	if err != nil {
		t.Fatalf("LoadDir: %v", err)
	}
	if db.Len() != 1 {
		t.Errorf("want 1 indicator loaded, got %d", db.Len())
	}
	// Unknown kind: should not match and should not panic.
	if got := db.Match("/any/path", "anyhash"); len(got) != 0 {
		t.Errorf("unknown kind should not match; got %d matches", len(got))
	}
}

// --- Glob unit tests ---

func TestGlobMatch(t *testing.T) {
	cases := []struct {
		pattern string
		path    string
		want    bool
	}{
		// Double-star
		{"**/.claude/hooks/*.sh", "/home/user/.claude/hooks/evil.sh", true},
		{"**/.claude/hooks/*.sh", "/home/user/.claude/hooks/subdir/evil.sh", false},
		{"**/.claude/*.json", "/home/user/.claude/settings.json", true},
		{"**/.claude/*.json", "/home/user/.claude/nested/settings.json", false},
		// No double-star
		{".claude/settings.json", ".claude/settings.json", true},
		{".claude/settings.json", "/home/.claude/settings.json", false},
		// Bare double-star matches everything
		{"**", "/anything/goes", true},
		{"**", "", true},
		// Wildcard in component
		{"**/hooks/*", "/a/b/hooks/script", true},
		{"**/hooks/*", "/a/b/hooks/nested/script", false}, // * does not cross boundary
	}

	for _, tc := range cases {
		got := globMatch(tc.pattern, tc.path)
		if got != tc.want {
			t.Errorf("globMatch(%q, %q) = %v, want %v", tc.pattern, tc.path, got, tc.want)
		}
	}
}

// --- helpers ---

func loadTestDB(t *testing.T) *DB {
	t.Helper()
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "test.yaml"), validYAML)
	db, err := LoadDir(dir)
	if err != nil {
		t.Fatalf("LoadDir: %v", err)
	}
	return db
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}
