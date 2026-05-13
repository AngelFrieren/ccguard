//go:build linux

package behavior

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/AngelFrieren/ccguard/internal/alert"
)

func init() {
	registerBackend(10, func(tree *ProcTree, sink *alert.Sink) Backend {
		return newProcfsBackend("/proc", tree, sink)
	})
}

// procfsBackend polls /proc every 100 ms to detect new child processes of
// tracked hook PIDs. It can only observe execve events (new process spawns);
// openat and connect require a higher-precision backend.
//
// Best-effort design: processes that start and exit within a single 100 ms
// poll window may be missed. PID reuse between polls is accepted as a known
// limitation of this fallback backend.
type procfsBackend struct {
	procRoot string // "/proc" normally; set to a temp dir in tests
	tree     *ProcTree
	sink     *alert.Sink
	prevPIDs map[int]struct{} // PIDs seen in the previous scan
}

func newProcfsBackend(procRoot string, tree *ProcTree, sink *alert.Sink) *procfsBackend {
	return &procfsBackend{
		procRoot: procRoot,
		tree:     tree,
		sink:     sink,
		prevPIDs: make(map[int]struct{}),
	}
}

func (b *procfsBackend) Name() string { return "procfs" }

func (b *procfsBackend) Available() bool {
	_, err := os.Stat(b.procRoot)
	return err == nil
}

func (b *procfsBackend) Start(ctx context.Context) (<-chan Event, error) {
	ch := make(chan Event, 256)
	go func() {
		defer close(ch)
		pollTick := time.NewTicker(100 * time.Millisecond)
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
				for _, ev := range b.poll() {
					select {
					case ch <- ev:
					case <-ctx.Done():
						return
					}
				}
			}
		}
	}()
	return ch, nil
}

// poll scans procRoot for new child processes of tracked PIDs.
// It is the core of the procfs backend and is accessible to tests.
func (b *procfsBackend) poll() []Event {
	entries, err := os.ReadDir(b.procRoot)
	if err != nil {
		return nil
	}

	current := make(map[int]struct{}, len(entries))
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		current[pid] = struct{}{}
	}

	var events []Event
	for pid := range current {
		if _, seen := b.prevPIDs[pid]; seen {
			continue // already evaluated in a previous poll
		}
		ppid := b.readPPID(pid)
		if ppid < 0 {
			continue // process already gone or unreadable
		}
		if b.tree.AddChild(pid, ppid) {
			events = append(events, Event{
				Ts:      time.Now().Unix(),
				Pid:     pid,
				Ppid:    ppid,
				Syscall: "execve",
				Args:    b.readCmdline(pid),
				Backend: "procfs",
			})
		}
	}

	b.prevPIDs = current
	return events
}

func (b *procfsBackend) readPPID(pid int) int {
	data, err := os.ReadFile(filepath.Join(b.procRoot, strconv.Itoa(pid), "status"))
	if err != nil {
		return -1
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "PPid:") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				if n, err := strconv.Atoi(parts[1]); err == nil {
					return n
				}
			}
		}
	}
	return -1
}

func (b *procfsBackend) readCmdline(pid int) []string {
	data, err := os.ReadFile(filepath.Join(b.procRoot, strconv.Itoa(pid), "cmdline"))
	if err != nil {
		return nil
	}
	// /proc/<pid>/cmdline uses null bytes as argument separators.
	parts := strings.Split(strings.TrimRight(string(data), "\x00"), "\x00")
	var out []string
	for _, p := range parts {
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}
