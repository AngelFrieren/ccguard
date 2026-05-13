// Package behavior implements Phase 4 of ccguard's detection architecture:
// behavioral monitoring of processes spawned by Claude Code hooks.
//
// Three backends are supported (highest to lowest precision):
//   - eBPF (linux+ebpf build tag): tracepoint-based capture (execve/openat/connect)
//   - auditd (linux): kernel audit log tailing; requires auditd + CAP_AUDIT_READ
//   - procfs (linux): /proc polling fallback; execve only, best-effort
//
// Backends register themselves via registerBackend() in their init() functions.
// SelectBackend iterates the registry by priority to find the best available
// one. On non-Linux platforms the registry is empty and SelectBackend always
// returns a NoopBackend.
//
// The daemon tracks the hook process tree using ProcTree. Only events from
// processes descended from hook-wrap PIDs (registered via Unix socket) are
// forwarded to the policy evaluator. This bounds monitoring to the Claude Code
// hook process forest, not the entire machine.
package behavior

import (
	"context"
	"fmt"
	"os"
	"sort"
	"sync"

	"github.com/AngelFrieren/ccguard/internal/alert"
)

// Event is a behavioral observation emitted by a backend.
type Event struct {
	Ts      int64    // unix seconds
	Pid     int
	Ppid    int
	Syscall string   // execve | openat | connect
	Args    []string // exe path for execve; file path for openat; host:port for connect
	Backend string   // name of the backend that produced this event
}

// Backend is the interface all detection backends implement.
type Backend interface {
	Name() string
	Available() bool
	// Start begins observation and returns a channel of events. The channel is
	// closed when ctx is cancelled. Callers must drain the channel promptly to
	// avoid blocking the backend's goroutine.
	Start(ctx context.Context) (<-chan Event, error)
}

// ProcTree is a thread-safe set of process IDs descended from registered root
// PIDs. Backends use it to limit monitoring to the hook process forest.
//
// Monitoring is scoped to the tracked tree rather than the full machine to
// avoid generating noise from unrelated processes and to reduce the blast
// radius of false positives.
type ProcTree struct {
	mu   sync.Mutex
	pids map[int]struct{}
}

// NewProcTree creates an empty ProcTree.
func NewProcTree() *ProcTree {
	return &ProcTree{pids: make(map[int]struct{})}
}

// AddRoot registers pid as a root of the tracked tree (called when hook-wrap
// notifies the daemon of its own PID via the Unix socket).
func (t *ProcTree) AddRoot(pid int) {
	t.mu.Lock()
	t.pids[pid] = struct{}{}
	t.mu.Unlock()
}

// AddChild adds pid to the tree if ppid is already tracked. Returns true if added.
func (t *ProcTree) AddChild(pid, ppid int) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	if _, ok := t.pids[ppid]; !ok {
		return false
	}
	t.pids[pid] = struct{}{}
	return true
}

// Contains reports whether pid is in the tracked tree.
func (t *ProcTree) Contains(pid int) bool {
	t.mu.Lock()
	_, ok := t.pids[pid]
	t.mu.Unlock()
	return ok
}

// Cleanup removes PIDs whose /proc/<pid> directory no longer exists.
// Called periodically by the procfs backend to reclaim memory.
func (t *ProcTree) Cleanup() {
	t.mu.Lock()
	defer t.mu.Unlock()
	for pid := range t.pids {
		if _, err := os.Stat(fmt.Sprintf("/proc/%d", pid)); os.IsNotExist(err) {
			delete(t.pids, pid)
		}
	}
}

// Len returns the number of currently tracked PIDs.
func (t *ProcTree) Len() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.pids)
}

// --- backend registry ---

type backendEntry struct {
	priority int // higher = preferred; eBPF=30, auditd=20, procfs=10
	newFn    func(*ProcTree, *alert.Sink) Backend
}

// backendRegistry is populated by init() functions in platform-specific files.
// It is intentionally not mutex-protected: writes happen only during package
// init, reads happen only after init.
var backendRegistry []backendEntry

func registerBackend(priority int, fn func(*ProcTree, *alert.Sink) Backend) {
	backendRegistry = append(backendRegistry, backendEntry{priority: priority, newFn: fn})
}

// noopBackend is returned when no suitable backend is available or when
// --behavior-backend off is specified.
type noopBackend struct{ name string }

func (b *noopBackend) Name() string { return b.name }
func (b *noopBackend) Available() bool { return false }
func (b *noopBackend) Start(_ context.Context) (<-chan Event, error) {
	ch := make(chan Event)
	close(ch)
	return ch, nil
}

// SelectBackend returns the best available backend for the given name.
//
// name may be one of:
//
//	"auto"   — highest-priority available backend
//	"procfs" — force procfs (warn if unavailable)
//	"auditd" — force auditd (warn if unavailable)
//	"ebpf"   — force eBPF (warn if unavailable or not compiled)
//	"off"    — disable behavioral monitoring entirely
//
// Returns (backend, active): active is false when behavioral monitoring is
// disabled or no backend could be started.
func SelectBackend(name string, tree *ProcTree, sink *alert.Sink) (Backend, bool) {
	if name == "off" {
		return &noopBackend{name: "off"}, false
	}

	// Sort registry by priority descending (highest first).
	entries := make([]backendEntry, len(backendRegistry))
	copy(entries, backendRegistry)
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].priority > entries[j].priority
	})

	for _, entry := range entries {
		b := entry.newFn(tree, sink)
		if name != "auto" && b.Name() != name {
			continue
		}
		if b.Available() {
			return b, true
		}
		if name != "auto" {
			if sink != nil {
				sink.Warn("behavior backend unavailable", map[string]any{"backend": name})
			}
			return &noopBackend{name: name}, false
		}
	}

	// No available backend found.
	return &noopBackend{name: "none"}, false
}
