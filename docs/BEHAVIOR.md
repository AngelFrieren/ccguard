# Behavioral Monitoring (Phase 4)

Layer 4 of ccguard observes what hook-spawned processes *do* after they
start, using policy-driven alerts on sensitive syscalls. This document
covers backend selection, setup, limitations, and the WSL2 eBPF path.

## Default policies and customisation

ccguard ships with a set of built-in default policies compiled into the
binary. If your policy directory (`$XDG_CONFIG_HOME/ccguard/policies/`)
contains no `*.yaml` files, the built-in defaults are used automatically.

To get an editable copy that you can customise:

```sh
ccguard policy init
```

This writes `$XDG_CONFIG_HOME/ccguard/policies/default.yaml`. Edit that
file, then restart `ccguard watch`. Your custom policies will be used
instead of the built-in defaults as long as the directory contains at
least one `*.yaml` file.

To verify which source is active:

```sh
ccguard policy list   # prints "Source: user dir" or "Source: built-in defaults"
```

## How it works

1. `ccguard hook-wrap` sends its PID to the watch daemon over a Unix socket.
2. The daemon tracks that PID and all of its descendants as the *hook process forest*.
3. A backend (procfs, auditd, or eBPF) produces `behavior.Event` records.
4. Events from processes in the hook forest are matched against loaded policies.
5. Policy matches emit alerts via the standard `alert.Sink`.

## Backend comparison

| Backend | Requires | Precision | CPU cost | Setup |
|---------|----------|-----------|----------|-------|
| `procfs` | Linux, user-mode | Medium — misses processes shorter than ~100ms | Very low | None |
| `auditd` | Linux, `audit` group or root | High — kernel records every syscall | Low | See below |
| `ebpf` | Linux ≥5.10, custom build | High — in-kernel filter | Lowest | See below |

## Backend selection

`ccguard watch` selects the best available backend automatically:

```
--behavior-backend auto    # default: eBPF > auditd > procfs > noop
--behavior-backend procfs  # force procfs polling
--behavior-backend auditd  # force auditd log tailing
--behavior-backend ebpf    # force eBPF (only available with -tags ebpf build)
--behavior-backend off     # disable behavioral monitoring entirely
```

## procfs backend

The procfs backend is always available on Linux. It polls `/proc` at
approximately 100ms intervals, comparing the current set of PIDs against
the previously observed set, then reading `/proc/<pid>/status` to find
the parent PID and `/proc/<pid>/cmdline` for the command.

Limitation: processes that start and exit within the polling interval are
not observed. For high-confidence monitoring, use auditd or eBPF.

## auditd backend

The auditd backend tails `/var/log/audit/audit.log` and parses
`type=SYSCALL` records for `execve`, `openat`, and `connect` calls.

### Setup

1. Ensure `auditd` is running: `sudo systemctl enable --now auditd`
2. Add your user to the `audit` group (or run ccguard as root):
   ```
   sudo usermod -aG audit $USER
   newgrp audit
   ```
3. Verify log access: `tail -1 /var/log/audit/audit.log`

If the log file is not readable, `ccguard watch` falls back to the next
available backend (procfs).

### WSL2 note

WSL2 kernels do not include `auditd` support by default. Use procfs or
build a custom kernel with `CONFIG_AUDIT=y`. The eBPF backend (below) is
a better option on WSL2 when available.

## eBPF backend

The eBPF backend provides kernel-level syscall interception with the lowest
overhead. It is **not included in default builds** — it requires:

- A custom ccguard build: `go build -tags ebpf ./cmd/ccguard`
- Linux kernel ≥5.10 with `CONFIG_BPF_SYSCALL=y` and `CONFIG_BPF_LSM=y`
- The `cilium/ebpf` library and a compiled BPF object (not yet included)

### WSL2 eBPF setup

1. Check your kernel version: `uname -r`
   - WSL2 ships a Microsoft kernel that may lack BPF LSM support.
2. Build a custom kernel with BPF enabled:
   ```
   git clone --depth=1 https://github.com/microsoft/WSL2-Linux-Kernel
   cd WSL2-Linux-Kernel
   cp Microsoft/config-wsl .config
   scripts/config --enable CONFIG_BPF_SYSCALL --enable CONFIG_BPF_LSM
   make -j$(nproc)
   ```
3. Configure WSL to use the custom kernel in `%USERPROFILE%\.wslconfig`:
   ```ini
   [wsl2]
   kernel = C:\path\to\WSL2-Linux-Kernel\arch\x86_64\boot\bzImage
   ```
4. Restart WSL: `wsl --shutdown && wsl`

The eBPF skeleton implementation (`internal/behavior/ebpf.go`) is a
placeholder. A future release will include the compiled BPF object and
full ring-buffer event delivery.

## Checking status

```
ccguard behavior status
```

Shows the selected backend, its availability, the policy directory, socket
path, and the count of behavioral events recorded in the past 24 hours.

## Disabling behavioral monitoring

Set `--behavior-backend off` or add to your config file:

```yaml
behavior:
  backend: off
```

## Behavioral events in the database

Events are stored in the `behavior_events` table. To query manually:

```sql
SELECT datetime(ts, 'unixepoch') AS time, backend, pid, syscall, args_json, policy_id
FROM behavior_events
ORDER BY ts DESC
LIMIT 20;
```
