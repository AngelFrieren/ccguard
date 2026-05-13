//go:build linux

package behavior

import (
	"bufio"
	"os"
	"testing"
)

func TestParseAuditLine_ExecveCurl(t *testing.T) {
	line := `type=SYSCALL msg=audit(1700000000.000:100): arch=c000003e syscall=59 success=yes exit=0 a0=5648aaa00000 a1=5648aab00000 a2=5648aac00000 a3=0 items=2 ppid=1234 pid=5678 auid=1000 uid=1000 gid=1000 euid=1000 suid=1000 fsuid=1000 egid=1000 sgid=1000 fsgid=1000 tty=pts0 ses=1 comm="curl" exe="/usr/bin/curl" subj=unconfined key="ccguard"`

	ev, ok := parseAuditLine(line)
	if !ok {
		t.Fatal("expected ok=true")
	}
	if ev.Syscall != "execve" {
		t.Errorf("expected syscall=execve, got %q", ev.Syscall)
	}
	if ev.Pid != 5678 {
		t.Errorf("expected pid=5678, got %d", ev.Pid)
	}
	if ev.Ppid != 1234 {
		t.Errorf("expected ppid=1234, got %d", ev.Ppid)
	}
	if len(ev.Args) == 0 || ev.Args[0] != "/usr/bin/curl" {
		t.Errorf("expected exe=/usr/bin/curl, got %v", ev.Args)
	}
	if ev.Ts != 1700000000 {
		t.Errorf("expected ts=1700000000, got %d", ev.Ts)
	}
	if ev.Backend != "auditd" {
		t.Errorf("expected backend=auditd, got %q", ev.Backend)
	}
}

func TestParseAuditLine_OpenatSyscall(t *testing.T) {
	// syscall=257 → openat
	line := `type=SYSCALL msg=audit(1700000002.000:102): arch=c000003e syscall=257 success=yes exit=5 a0=ffffff9c a1=5648aab00000 a2=0 a3=0 items=1 ppid=5678 pid=5680 auid=1000 uid=1000 gid=1000 euid=1000 suid=1000 fsuid=1000 egid=1000 sgid=1000 fsgid=1000 tty=pts0 ses=1 comm="curl" exe="/usr/bin/curl" subj=unconfined key="ccguard"`

	ev, ok := parseAuditLine(line)
	if !ok {
		t.Fatal("expected ok=true for openat")
	}
	if ev.Syscall != "openat" {
		t.Errorf("expected syscall=openat, got %q", ev.Syscall)
	}
}

func TestParseAuditLine_NonSyscallLine(t *testing.T) {
	lines := []string{
		`type=EXECVE msg=audit(1700000000.000:100): argc=2 a0="curl" a1="https://example.com"`,
		`type=PATH msg=audit(1700000001.000:101): item=0 name="/usr/bin/wget"`,
		`type=EOE msg=audit(1700000002.000:102):`,
		``,
		`some random log line`,
	}
	for _, line := range lines {
		_, ok := parseAuditLine(line)
		if ok {
			t.Errorf("expected ok=false for line: %q", line)
		}
	}
}

func TestParseAuditLine_UnsupportedSyscall(t *testing.T) {
	// syscall=1 (write) — not monitored
	line := `type=SYSCALL msg=audit(1700000003.000:103): arch=c000003e syscall=1 success=yes exit=0 a0=1 a1=5648aab00000 a2=5 a3=0 items=0 ppid=5678 pid=5680 auid=1000 uid=1000 gid=1000 euid=1000 suid=1000 fsuid=1000 egid=1000 sgid=1000 fsgid=1000 tty=pts0 ses=1 comm="curl" exe="/usr/bin/curl" subj=unconfined key=(null)`

	_, ok := parseAuditLine(line)
	if ok {
		t.Error("expected ok=false for unmonitored syscall (write)")
	}
}

func TestParseAuditFields(t *testing.T) {
	line := `type=SYSCALL msg=audit(1700000000.000:100): syscall=59 ppid=1234 pid=5678 comm="bash" exe="/bin/bash" key=(null)`
	fields := parseAuditFields(line)

	tests := []struct{ key, want string }{
		{"type", "SYSCALL"},
		{"syscall", "59"},
		{"ppid", "1234"},
		{"pid", "5678"},
		{"comm", "bash"},
		{"exe", "/bin/bash"},
		{"key", "(null)"},
	}
	for _, tt := range tests {
		if got := fields[tt.key]; got != tt.want {
			t.Errorf("fields[%q] = %q, want %q", tt.key, got, tt.want)
		}
	}
}

func TestParseAuditTimestamp(t *testing.T) {
	tests := []struct {
		msg  string
		want int64
	}{
		{"audit(1700000000.000:100)", 1700000000},
		{"audit(1700000001.500:200)", 1700000001},
		{"audit(0.000:1)", 0},
	}
	for _, tt := range tests {
		got := parseAuditTimestamp(tt.msg)
		if got != tt.want {
			t.Errorf("parseAuditTimestamp(%q) = %d, want %d", tt.msg, got, tt.want)
		}
	}
}

func TestParseAuditLine_FixtureFile(t *testing.T) {
	f, err := os.Open("testdata/audit_execve.log")
	if err != nil {
		t.Fatalf("open fixture: %v", err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	var execveCount, openatCount, skipped int
	for scanner.Scan() {
		ev, ok := parseAuditLine(scanner.Text())
		if !ok {
			skipped++
			continue
		}
		switch ev.Syscall {
		case "execve":
			execveCount++
		case "openat":
			openatCount++
		}
	}

	// Fixture has 2 execve SYSCALL lines and 1 openat SYSCALL line.
	if execveCount != 2 {
		t.Errorf("expected 2 execve events from fixture, got %d", execveCount)
	}
	if openatCount != 1 {
		t.Errorf("expected 1 openat event from fixture, got %d", openatCount)
	}
	// Non-SYSCALL and unmonitored syscall lines are skipped.
	if skipped == 0 {
		t.Error("expected some lines to be skipped (EXECVE, PATH, EOE records)")
	}
}
