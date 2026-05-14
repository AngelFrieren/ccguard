//go:build linux && ebpf

// eBPF backend for ccguard behavioral monitoring (Phase 4, Layer 4).
// Enable with: go build -tags ebpf ./cmd/ccguard
//
// WSL2 kernel requirements:
//   - Kernel ≥5.10 (check: uname -r)
//   - CONFIG_BPF_SYSCALL=y (check: zcat /proc/config.gz | grep CONFIG_BPF_SYSCALL)
//   - CONFIG_BPF_LSM=y (optional, for LSM hooks)
//   - Typically requires a custom WSL2 kernel build; the default Microsoft
//     kernel does not enable all required BPF features
//
// A production implementation would use github.com/cilium/ebpf to:
//  1. Load pre-compiled BPF objects (generated with bpf2go / libbpf-go)
//  2. Attach tracepoints: sys_enter_execve, sys_enter_openat, sys_enter_connect
//  3. Stream events via a perf/ring buffer to user space
//
// This skeleton registers the backend (priority 30, highest) and performs a
// kernel version check in Available(). Start() returns an error indicating
// the BPF programs are not yet compiled into the binary. Replace with real
// BPF loader code when implementing full eBPF support.
package behavior

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/AngelFrieren/ccguard/internal/alert"
)

func init() {
	registerBackend(30, func(tree *ProcTree, sink *alert.Sink) Backend {
		return newEbpfBackend(tree, sink)
	})
}

type ebpfBackend struct {
	tree *ProcTree
	sink *alert.Sink
}

func newEbpfBackend(tree *ProcTree, sink *alert.Sink) *ebpfBackend {
	return &ebpfBackend{tree: tree, sink: sink}
}

func (b *ebpfBackend) Name() string { return "ebpf" }

func (b *ebpfBackend) Available() bool {
	return kernelVersionAtLeast(5, 10)
}

// Start is a skeleton that returns an error until BPF programs are compiled in.
// Replace the error return with a real BPF loader implementation.
func (b *ebpfBackend) Start(_ context.Context) (<-chan Event, error) {
	return nil, fmt.Errorf(
		"eBPF backend skeleton: BPF programs not compiled; " +
			"rebuild with actual BPF objects and update Start() in ebpf.go")
}

// kernelVersionAtLeast reports whether the running kernel is at least major.minor.
func kernelVersionAtLeast(major, minor int) bool {
	data, err := os.ReadFile("/proc/version")
	if err != nil {
		return false
	}
	// /proc/version: "Linux version 5.15.0-microsoft-standard-WSL2 ..."
	parts := strings.Fields(string(data))
	if len(parts) < 3 {
		return false
	}
	ver := strings.SplitN(parts[2], ".", 3)
	if len(ver) < 2 {
		return false
	}
	maj, err := strconv.Atoi(ver[0])
	if err != nil {
		return false
	}
	// Strip any non-numeric suffix from the minor version field.
	minStr := ver[1]
	for i, c := range minStr {
		if c < '0' || c > '9' {
			minStr = minStr[:i]
			break
		}
	}
	min, err := strconv.Atoi(minStr)
	if err != nil {
		return false
	}
	return maj > major || (maj == major && min >= minor)
}
