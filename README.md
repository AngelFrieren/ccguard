# ccguard

[![CI](https://github.com/AngelFrieren/ccguard/actions/workflows/ci.yml/badge.svg)](https://github.com/AngelFrieren/ccguard/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/AngelFrieren/ccguard)](https://github.com/AngelFrieren/ccguard/releases)
[![Go Reference](https://pkg.go.dev/badge/github.com/AngelFrieren/ccguard.svg)](https://pkg.go.dev/github.com/AngelFrieren/ccguard)
[![Go Report Card](https://goreportcard.com/badge/github.com/AngelFrieren/ccguard)](https://goreportcard.com/report/github.com/AngelFrieren/ccguard)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)

> Claude Code's `settings.json` can configure hooks that execute
> arbitrary shell commands at session events. A silent edit to that
> file is silent persistence on your machine. **ccguard watches for it.**

`ccguard` is a defensive, detective tool that monitors Claude Code's
configuration and hook behavior for unauthorized modifications and
policy-violating runtime behavior. It runs purely in userspace as a
single static binary, in the spirit of Tripwire, AIDE, and osquery.

This is a security tool — **purely detective, never offensive.**

## Quick start

```sh
# 1. Build
git clone https://github.com/AngelFrieren/ccguard
cd ccguard
go build -o ccguard ./cmd/ccguard
sudo install ccguard /usr/local/bin/

# 2. Approve your current Claude Code config as the baseline
ccguard init

# 3. Write the default behavioral policies (editable copy)
ccguard policy init

# 4. Start monitoring (use the systemd unit in examples/ for production)
ccguard watch
```

In a second terminal, simulate a tampered settings.json to see an
alert:

```sh
echo "# tampered" >> ~/.claude/settings.json
# the watch terminal now emits an ALERT with the new SHA-256
```

After legitimate edits, approve the new hash:

```sh
ccguard approve ~/.claude/settings.json
```

Other useful commands:

```sh
ccguard status           # show current approval state without watching
ccguard ioc list         # list loaded threat indicators
ccguard ioc check <path> # test a file against the IOC database
ccguard baseline show    # show hook execution baseline stats
ccguard behavior status  # show selected backend and recent events
```

## Installation

**From source:**
```sh
git clone https://github.com/AngelFrieren/ccguard
cd ccguard
go build -o ccguard ./cmd/ccguard
```

**GoReleaser / pre-built binaries:** see [Releases](https://github.com/AngelFrieren/ccguard/releases).

**systemd user service:** see [`examples/ccguard.service`](examples/ccguard.service).

## How it works

Phase 1 monitors `.claude/` directories with inotify/fsnotify. When a file
changes, ccguard computes its SHA-256 and compares it against an approved
baseline stored in a local SQLite database. Unknown hashes trigger an alert.

Phase 2 adds IOC matching: unapproved hashes and paths are also tested against
a database of known-bad indicators. A match produces a higher-priority, named
alert tied to a specific threat campaign.

**Phase 3** adds Layer 2 statistical anomaly detection. Hook
execution times are recorded via `ccguard hook-wrap`, a small
wrapper that times the wrapped command and writes
(name, duration_ms, exit_code) to SQLite. After a configurable
minimum sample count (default 30), ccguard maintains a rolling
mean+stddev per hook; future executions are flagged via z-score
threshold (warn at 3.0, alert at 5.0 by default). This catches
hooks whose contents are unchanged but whose behavior has been
augmented with background work — e.g. a legitimate Stop hook
that now also quietly exfiltrates the session log. See
[docs/BASELINE.md](docs/BASELINE.md).

**Phase 4** adds Layer 4 behavioral monitoring. ccguard tracks the
process tree spawned by `hook-wrap` (notified via a 0600-mode Unix
socket on `$XDG_RUNTIME_DIR/ccguard.sock`) and observes their
syscalls. Three backends are auto-selected based on availability:

- **procfs** (default): polls `/proc` every 100ms, no kernel
  features required
- **auditd**: subscribes to auditd execve events, requires root
- **eBPF** (build tag `ebpf`): tracepoint-based, most accurate,
  requires a kernel with BPF_LSM (Linux 5.10+ typically)

YAML policies match on `(syscall, path_glob, command_basename_in,
destination_not_in_allowlist)`. See
[docs/BEHAVIOR.md](docs/BEHAVIOR.md) and
[docs/POLICY_FORMAT.md](docs/POLICY_FORMAT.md).

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the full design.

## Roadmap

| Phase | Layer | Feature | Status |
|-------|-------|---------|--------|
| 1 | L1 | SHA-256 hash integrity monitoring | ✅ Shipped |
| 2 | L3 | IOC matching against known threat indicators | ✅ Shipped |
| 3 | L2 | Statistical baseline anomaly detection | ✅ Shipped |
| 4 | L4 | Behavioral monitoring via eBPF/auditd | ✅ Shipped |

## Threat model

See [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md). ccguard is designed against
an adversary who gains write access to the user's home directory and attempts to
quietly persist via Claude Code hooks.

ccguard is **not** a replacement for EDR, antivirus, or OS-level security
hardening.

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md), including the IOC submission guide.
Security vulnerabilities should be reported via
[Security Advisories](https://github.com/AngelFrieren/ccguard/security/advisories/new),
not as public issues.

## License

Apache 2.0 — see [LICENSE](LICENSE).
