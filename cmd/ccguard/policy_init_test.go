package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/AngelFrieren/ccguard/internal/policy"
)

// runPolicyInit executes `ccguard policy init [--force]` against a temp policy
// directory and returns (stdout, stderr, error).
func runPolicyInit(t *testing.T, policyDir string, force bool, stdin string) (string, string, error) {
	t.Helper()
	args := []string{"policy", "init", "--policy-dir", policyDir}
	if force {
		args = append(args, "--force")
	}
	return runCLI(t, strings.NewReader(stdin), args...)
}

func TestPolicyInit_EmptyDir(t *testing.T) {
	dir := t.TempDir()
	policyDir := filepath.Join(dir, "policies") // does not exist yet

	stdout, _, err := runPolicyInit(t, policyDir, false, "")
	if err != nil {
		t.Fatalf("policy init failed: %v", err)
	}
	if !strings.Contains(stdout, "written:") {
		t.Errorf("expected 'written:' in output, got: %s", stdout)
	}

	dest := filepath.Join(policyDir, "default.yaml")
	data, readErr := os.ReadFile(dest)
	if readErr != nil {
		t.Fatalf("default.yaml not created: %v", readErr)
	}

	// Verify the written file is valid and matches the embedded content.
	db, errs := policy.LoadFile(dest)
	if len(errs) != 0 {
		t.Errorf("written policy file has errors: %v", errs)
	}
	if db.Len() == 0 {
		t.Error("written policy file has no policies")
	}

	embedded := policy.DefaultPoliciesYAML()
	if string(data) != string(embedded) {
		t.Error("written content does not match embedded defaults")
	}
}

func TestPolicyInit_ExistingFileNoForce_Aborted(t *testing.T) {
	dir := t.TempDir()
	policyDir := filepath.Join(dir, "policies")
	if err := os.MkdirAll(policyDir, 0o700); err != nil {
		t.Fatal(err)
	}
	dest := filepath.Join(policyDir, "default.yaml")
	original := []byte("# original content\n")
	if err := os.WriteFile(dest, original, 0o644); err != nil {
		t.Fatal(err)
	}

	// Answer "n" to the prompt — file should not be overwritten.
	stdout, _, err := runPolicyInit(t, policyDir, false, "n\n")
	if err != nil {
		t.Fatalf("policy init failed: %v", err)
	}
	if !strings.Contains(stdout, "aborted") {
		t.Errorf("expected 'aborted' in output, got: %s", stdout)
	}

	data, _ := os.ReadFile(dest)
	if string(data) != string(original) {
		t.Error("file was modified despite answering 'n'")
	}
}

func TestPolicyInit_ExistingFileNoForce_Confirmed(t *testing.T) {
	dir := t.TempDir()
	policyDir := filepath.Join(dir, "policies")
	if err := os.MkdirAll(policyDir, 0o700); err != nil {
		t.Fatal(err)
	}
	dest := filepath.Join(policyDir, "default.yaml")
	if err := os.WriteFile(dest, []byte("# old\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Answer "y" to the prompt — file should be overwritten.
	stdout, _, err := runPolicyInit(t, policyDir, false, "y\n")
	if err != nil {
		t.Fatalf("policy init failed: %v", err)
	}
	if !strings.Contains(stdout, "written:") {
		t.Errorf("expected 'written:' in output, got: %s", stdout)
	}

	data, _ := os.ReadFile(dest)
	if string(data) != string(policy.DefaultPoliciesYAML()) {
		t.Error("file not updated after 'y' confirmation")
	}
}

func TestPolicyInit_ExistingFileWithForce(t *testing.T) {
	dir := t.TempDir()
	policyDir := filepath.Join(dir, "policies")
	if err := os.MkdirAll(policyDir, 0o700); err != nil {
		t.Fatal(err)
	}
	dest := filepath.Join(policyDir, "default.yaml")
	if err := os.WriteFile(dest, []byte("# old\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	stdout, _, err := runPolicyInit(t, policyDir, true, "")
	if err != nil {
		t.Fatalf("policy init --force failed: %v", err)
	}
	if !strings.Contains(stdout, "written:") {
		t.Errorf("expected 'written:' in output, got: %s", stdout)
	}

	data, _ := os.ReadFile(dest)
	if string(data) != string(policy.DefaultPoliciesYAML()) {
		t.Error("file not updated with --force")
	}
}
