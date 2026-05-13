# ccguard

**ccguard** is a defensive file integrity monitor for Claude Code configuration
files. It detects unauthorized modifications to `~/.claude/settings.json` and
project-level `.claude/settings.json` — the files that control Claude Code
hooks and can execute arbitrary shell commands.

This is a security tool in the same category as Tripwire, AIDE, and osquery —
purely **detective**, never offensive.

## Quick start

```sh
# Initialize baseline (approve current config as legitimate)
ccguard init

# Start monitoring (runs in foreground; use systemd unit for production)
ccguard watch

# After an intentional config change, approve the new hash
ccguard approve ~/.claude/settings.json

# Check current approval state without watching
ccguard status

# Query the IOC database
ccguard ioc list
ccguard ioc check ~/.claude/settings.json
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

Phase 2 (shipped) adds IOC matching: unapproved hashes and paths are also
tested against a database of known-bad indicators. A match produces a
higher-priority, named alert tied to a specific threat campaign.

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the full design.

## Roadmap

| Phase | Layer | Feature | Status |
|-------|-------|---------|--------|
| 1 | L1 | SHA-256 hash integrity monitoring | ✅ Shipped |
| 2 | L3 | IOC matching against known threat indicators | ✅ Shipped |
| 3 | L2 | Statistical baseline anomaly detection | Planned |
| 4 | L4 | Behavioral monitoring via eBPF/auditd | Planned |

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

[MIT](LICENSE)
