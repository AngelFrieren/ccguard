# CLAUDE.md

## Project context

ccguard is a **defensive** file integrity monitor for Claude Code
configuration files. It detects unauthorized modifications to
`~/.claude/settings.json` and project-level `.claude/settings.json`
to protect users from supply-chain attacks that hijack Claude Code hooks.

This is a security tool in the same category as Tripwire, AIDE, and
osquery — purely **detective**, never offensive.

## Architecture

The project follows a 4-layer detection design. See `docs/ARCHITECTURE.md`
for the full diagram.

- **Phase 1 (shipped)**: Layer 1 — SHA-256 hash integrity monitoring
- **Phase 2 (next)**: Layer 3 — IOC matching against known threat indicators
- **Phase 3 (planned)**: Layer 2 — Statistical baseline anomaly detection
- **Phase 4 (planned)**: Layer 4 — Behavioral monitoring via eBPF/auditd

## Coding conventions

- Pure Go, no CGO (so we can ship a static binary via GoReleaser)
- Errors wrapped with `fmt.Errorf("...: %w", err)`
- All detections flow through `internal/alert.Sink`
- Every state transition recorded via `storage.RecordEvent`
- Every new package gets a `_test.go` with table-driven tests
- Package-level doc comments on every package
- Follow existing patterns in `internal/hashwatch/` and `internal/storage/`

## File layout

- `cmd/ccguard/` — CLI entry points (one subcommand per file)
- `internal/` — implementation packages, not importable externally
- `docs/` — human-facing design docs (THREAT_MODEL, ARCHITECTURE)
- `configs/` — default config files and IOC databases
- `examples/` — systemd units and integration examples

## What this project is NOT

- NOT an offensive tool
- NOT a sandbox or runtime restriction (that is the OS's job)
- NOT a replacement for EDR or commercial security products
- NOT a network service — `ccguard` makes no outbound calls unless
  explicitly configured to fetch IOC feeds

## Threat model

See `docs/THREAT_MODEL.md`. When adding detection logic, reference the
threat ID (T1, T2, ...) it addresses, or propose a new one.

## Testing requirements

- `go test ./...` must pass with `-race`
- `go vet ./...` must be clean
- `gofmt -l .` must produce no output
- New CLI subcommands need at least one integration test invoking the
  command end-to-end
