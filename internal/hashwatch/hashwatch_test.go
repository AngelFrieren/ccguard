package hashwatch

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

func TestHashFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "settings.json")
	content := []byte(`{"model":"claude-opus"}`)
	if err := os.WriteFile(path, content, 0o644); err != nil {
		t.Fatal(err)
	}

	got, err := HashFile(path)
	if err != nil {
		t.Fatalf("HashFile: %v", err)
	}

	want := sha256.Sum256(content)
	wantHex := hex.EncodeToString(want[:])
	if got != wantHex {
		t.Errorf("hash mismatch:\n  got:  %s\n  want: %s", got, wantHex)
	}
}

func TestIsMonitored(t *testing.T) {
	cases := map[string]bool{
		"settings.json":                 true,
		"settings.local.json":           true,
		"/home/u/.claude/settings.json": true,
		"random.txt":                    false,
		"settings.json.bak":             false,
		"":                              false,
	}
	for name, want := range cases {
		if got := IsMonitored(name); got != want {
			t.Errorf("IsMonitored(%q) = %v, want %v", name, got, want)
		}
	}
}

func TestResolveTargets(t *testing.T) {
	dir := t.TempDir()
	claudeDir := filepath.Join(dir, ".claude")
	if err := os.MkdirAll(claudeDir, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"settings.json", "settings.local.json", "ignored.txt"} {
		if err := os.WriteFile(filepath.Join(claudeDir, name), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	got, err := ResolveTargets([]string{claudeDir})
	if err != nil {
		t.Fatalf("ResolveTargets: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 targets, got %d: %v", len(got), got)
	}
	for _, p := range got {
		if !IsMonitored(p) {
			t.Errorf("non-monitored file returned: %s", p)
		}
	}
}

func TestResolveTargetsMissingPath(t *testing.T) {
	got, err := ResolveTargets([]string{"/nonexistent/path/.claude"})
	if err != nil {
		t.Fatalf("expected no error for missing path, got %v", err)
	}
	if len(got) != 0 {
		t.Errorf("expected no targets, got %v", got)
	}
}
