//go:build linux

package behavior

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// createFakeProc writes a minimal /proc/<pid>/{status,cmdline} in root.
func createFakeProc(t *testing.T, root string, pid, ppid int, cmdline []string) {
	t.Helper()
	dir := filepath.Join(root, strconv.Itoa(pid))
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatalf("createFakeProc MkdirAll: %v", err)
	}
	status := fmt.Sprintf("Name:\ttest\nPPid:\t%d\nPid:\t%d\n", ppid, pid)
	if err := os.WriteFile(filepath.Join(dir, "status"), []byte(status), 0644); err != nil {
		t.Fatalf("write status: %v", err)
	}
	cl := strings.Join(cmdline, "\x00") + "\x00"
	if err := os.WriteFile(filepath.Join(dir, "cmdline"), []byte(cl), 0644); err != nil {
		t.Fatalf("write cmdline: %v", err)
	}
}

func TestProcfsBackend_Available(t *testing.T) {
	root := t.TempDir()
	tr := NewProcTree()
	b := newProcfsBackend(root, tr, nil)
	if !b.Available() {
		t.Error("procfs backend should be available when procRoot exists")
	}

	b2 := newProcfsBackend("/nonexistent-proc-dir-test", tr, nil)
	if b2.Available() {
		t.Error("procfs backend should be unavailable for non-existent root")
	}
}

func TestProcfsBackend_Poll_DetectsNewChild(t *testing.T) {
	root := t.TempDir()
	tr := NewProcTree()
	tr.AddRoot(100)

	// Create "root" process entry in fake /proc.
	createFakeProc(t, root, 100, 1, []string{"ccguard"})

	b := newProcfsBackend(root, tr, nil)

	// First poll: root itself is not a child of anyone tracked (ppid=1 not in tree).
	events := b.poll()
	if len(events) != 0 {
		t.Errorf("first poll should find no children, got %d", len(events))
	}

	// Add a child of root (ppid=100).
	createFakeProc(t, root, 200, 100, []string{"/usr/bin/curl", "https://example.com"})

	events = b.poll()
	if len(events) != 1 {
		t.Fatalf("expected 1 event for new child, got %d", len(events))
	}
	ev := events[0]
	if ev.Pid != 200 {
		t.Errorf("expected pid=200, got %d", ev.Pid)
	}
	if ev.Ppid != 100 {
		t.Errorf("expected ppid=100, got %d", ev.Ppid)
	}
	if ev.Syscall != "execve" {
		t.Errorf("expected syscall=execve, got %q", ev.Syscall)
	}
	if len(ev.Args) == 0 || ev.Args[0] != "/usr/bin/curl" {
		t.Errorf("expected args[0]=/usr/bin/curl, got %v", ev.Args)
	}
	if ev.Backend != "procfs" {
		t.Errorf("expected backend=procfs, got %q", ev.Backend)
	}
}

func TestProcfsBackend_Poll_IgnoresExistingPIDs(t *testing.T) {
	root := t.TempDir()
	tr := NewProcTree()
	tr.AddRoot(100)
	createFakeProc(t, root, 100, 1, []string{"ccguard"})
	createFakeProc(t, root, 200, 100, []string{"/bin/sh"})

	b := newProcfsBackend(root, tr, nil)

	// First poll: finds child 200.
	events := b.poll()
	if len(events) != 1 {
		t.Fatalf("first poll: expected 1 event, got %d", len(events))
	}

	// Second poll: same PIDs — no new events.
	events = b.poll()
	if len(events) != 0 {
		t.Errorf("second poll: expected 0 events (already seen), got %d", len(events))
	}
}

func TestProcfsBackend_Poll_IgnoresNonTrackedProcesses(t *testing.T) {
	root := t.TempDir()
	tr := NewProcTree()
	tr.AddRoot(100)

	// pid=999 has ppid=1 (not in tree).
	createFakeProc(t, root, 999, 1, []string{"/usr/bin/ssh"})

	b := newProcfsBackend(root, tr, nil)
	events := b.poll()
	if len(events) != 0 {
		t.Errorf("expected no events for untracked process, got %d", len(events))
	}
}

func TestProcfsBackend_ReadPPID(t *testing.T) {
	root := t.TempDir()
	createFakeProc(t, root, 42, 7, []string{"test"})

	tr := NewProcTree()
	b := newProcfsBackend(root, tr, nil)
	ppid := b.readPPID(42)
	if ppid != 7 {
		t.Errorf("expected ppid=7, got %d", ppid)
	}

	// Non-existent pid returns -1.
	if b.readPPID(99999) != -1 {
		t.Error("expected -1 for non-existent pid")
	}
}

func TestProcfsBackend_ReadCmdline(t *testing.T) {
	root := t.TempDir()
	createFakeProc(t, root, 42, 1, []string{"/bin/bash", "-c", "echo hello"})

	tr := NewProcTree()
	b := newProcfsBackend(root, tr, nil)
	args := b.readCmdline(42)
	if len(args) != 3 || args[0] != "/bin/bash" || args[2] != "echo hello" {
		t.Errorf("unexpected args: %v", args)
	}
}
