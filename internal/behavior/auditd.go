//go:build linux

package behavior

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/AngelFrieren/ccguard/internal/alert"
)

// auditSyscallNames maps x86_64 syscall numbers to canonical names for the
// syscalls ccguard monitors. Only syscalls in this table generate events.
var auditSyscallNames = map[int]string{
	59:  "execve",
	322: "execve", // execveat
	257: "openat",
	42:  "connect",
}

func init() {
	registerBackend(20, func(tree *ProcTree, sink *alert.Sink) Backend {
		return newAuditdBackend("/var/log/audit/audit.log", tree, sink)
	})
}

// auditdBackend tails /var/log/audit/audit.log and emits events for SYSCALL
// records whose PID is in the tracked process tree.
//
// Availability requires:
//   - auditctl installed and executable
//   - /var/log/audit/audit.log readable (requires CAP_AUDIT_READ or root)
//   - auditctl -l succeeds (confirms audit subsystem access)
//
// On WSL2 without systemd, auditd may not be running; Available() returns
// false in that case and the watch daemon falls back to a lower backend.
type auditdBackend struct {
	logPath string
	tree    *ProcTree
	sink    *alert.Sink
}

func newAuditdBackend(logPath string, tree *ProcTree, sink *alert.Sink) *auditdBackend {
	return &auditdBackend{logPath: logPath, tree: tree, sink: sink}
}

func (b *auditdBackend) Name() string { return "auditd" }

func (b *auditdBackend) Available() bool {
	if _, err := exec.LookPath("auditctl"); err != nil {
		return false
	}
	if _, err := os.Stat(b.logPath); err != nil {
		return false
	}
	return exec.Command("auditctl", "-l").Run() == nil
}

func (b *auditdBackend) Start(ctx context.Context) (<-chan Event, error) {
	f, err := os.Open(b.logPath)
	if err != nil {
		return nil, fmt.Errorf("open audit log %s: %w", b.logPath, err)
	}

	ch := make(chan Event, 256)
	go func() {
		defer close(ch)
		defer f.Close()

		// Seek to end: process only new audit events from this point.
		if _, err := f.Seek(0, 2); err != nil {
			return
		}

		r := bufio.NewReader(f)
		pollTick := time.NewTicker(500 * time.Millisecond)
		cleanTick := time.NewTicker(5 * time.Second)
		defer pollTick.Stop()
		defer cleanTick.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-cleanTick.C:
				b.tree.Cleanup()
			case <-pollTick.C:
				b.drainAuditLog(r, ch)
			}
		}
	}()
	return ch, nil
}

func (b *auditdBackend) drainAuditLog(r *bufio.Reader, ch chan<- Event) {
	for {
		line, err := r.ReadString('\n')
		if err == nil && line != "" {
			ev, ok := parseAuditLine(line)
			if ok && b.tree.Contains(ev.Pid) {
				ch <- ev
			}
		}
		if err != nil {
			return
		}
	}
}

// parseAuditLine parses a single type=SYSCALL audit log line.
// Returns (Event{}, false) for non-SYSCALL lines or unmonitored syscalls.
// This function is exported for testing with fixture data.
func parseAuditLine(line string) (Event, bool) {
	line = strings.TrimSpace(line)
	if !strings.HasPrefix(line, "type=SYSCALL") {
		return Event{}, false
	}

	fields := parseAuditFields(line)

	syscallNum, err := strconv.Atoi(fields["syscall"])
	if err != nil {
		return Event{}, false
	}
	syscallName, ok := auditSyscallNames[syscallNum]
	if !ok {
		return Event{}, false
	}

	pid, err := strconv.Atoi(fields["pid"])
	if err != nil {
		return Event{}, false
	}
	ppid, err := strconv.Atoi(fields["ppid"])
	if err != nil {
		return Event{}, false
	}

	ts := parseAuditTimestamp(fields["msg"])
	exe := fields["exe"]
	if exe == "" {
		exe = fields["comm"]
	}

	return Event{
		Ts:      ts,
		Pid:     pid,
		Ppid:    ppid,
		Syscall: syscallName,
		Args:    []string{exe},
		Backend: "auditd",
	}, true
}

// parseAuditFields splits a key=value audit log line into a map.
// Quoted values (key="value") are stored without surrounding quotes.
func parseAuditFields(line string) map[string]string {
	fields := make(map[string]string)
	rest := line
	for rest != "" {
		eq := strings.Index(rest, "=")
		if eq < 0 {
			break
		}
		key := strings.TrimSpace(rest[:eq])
		// Trim key to last space-separated word (handles " key=" patterns)
		if sp := strings.LastIndex(key, " "); sp >= 0 {
			key = key[sp+1:]
		}
		rest = rest[eq+1:]

		var val string
		if strings.HasPrefix(rest, `"`) {
			end := strings.Index(rest[1:], `"`)
			if end < 0 {
				break
			}
			val = rest[1 : end+1]
			rest = rest[end+2:]
		} else {
			sp := strings.IndexAny(rest, " \t\n")
			if sp < 0 {
				val = rest
				rest = ""
			} else {
				val = rest[:sp]
				rest = strings.TrimLeft(rest[sp:], " \t")
			}
		}
		fields[key] = val
	}
	return fields
}

// parseAuditTimestamp extracts the unix second from msg=audit(1234567890.000:123).
func parseAuditTimestamp(msg string) int64 {
	i := strings.Index(msg, "(")
	if i < 0 {
		return time.Now().Unix()
	}
	j := strings.Index(msg[i:], ".")
	if j < 0 {
		return time.Now().Unix()
	}
	ts, err := strconv.ParseInt(msg[i+1:i+j], 10, 64)
	if err != nil {
		return time.Now().Unix()
	}
	return ts
}
