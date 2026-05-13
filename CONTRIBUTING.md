# Contributing to ccguard

Thanks for your interest in ccguard. This project values small, focused
changes and clear rationale over volume.

## Ground rules

1. **Defensive scope only.** ccguard is a detective and (later) preventive
   tool. Patches that add offensive features — fingerprinting other users'
   systems, generating exploit payloads, etc. — will be closed.
2. **Threat model first.** New detection layers or rules should reference
   a specific threat in [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) or
   propose an addition to it.
3. **No silent network calls.** ccguard must never make outbound network
   requests without explicit user configuration.
4. **No CGO.** Phase 1 ships as a pure-Go static binary. Keep it that way
   unless there is a strong reason (Phase 4 eBPF code is the planned
   exception, gated behind a build tag).

## Local development

```sh
git clone https://github.com/AngelFrieren/ccguard
cd ccguard
go test ./...
go build ./cmd/ccguard
./ccguard --help
```

## Before opening a PR

- `go test ./...` passes
- `go vet ./...` is clean
- `gofmt -l .` produces no output
- New behaviour has a test
- User-facing changes are reflected in the README

## Issues

- **Bug**: please include OS, kernel (`uname -r`), Go version, and the
  exact command + output.
- **Feature request**: tie it to a concrete threat or operational pain
  point.
- **Security vulnerability**: do **not** open a public issue. Use
  [Security Advisories](https://github.com/AngelFrieren/ccguard/security/advisories/new)
  instead.

## IOC submission

Adding a new Indicator of Compromise is welcome. Follow these steps:

1. **Verify the indicator is real.** Every IOC must reference a public
   advisory, blog post, or security report that documents the threat.
   Fictional or test-only hashes must not appear in upstream IOC files.

2. **Place the YAML in `configs/iocs/`**, following the schema in
   [`docs/IOC_FORMAT.md`](docs/IOC_FORMAT.md). Use the next available
   `CCG-IOC-NNNN` ID (check existing files and open PRs).

3. **Required fields for IOC PRs:**
   - `id`, `severity`, `description` — all must be non-empty.
   - `references` — at least one URL pointing to a public source.
   - `match.kind` and `match.values` — use the narrowest match kind that
     is accurate (prefer `file_sha256` over `file_path_glob` when you
     have the hash).

4. **Test locally:**
   ```sh
   ccguard ioc list --ioc-dir configs/iocs
   ccguard ioc check <path-to-sample-file> --ioc-dir configs/iocs
   go test ./internal/ioc/
   ```

5. **Label the PR** with `ioc-submission` so reviewers with threat
   intelligence expertise are notified.

6. **One indicator per PR** for supply-chain IOCs where the evidence is
   novel. Batching is fine for related indicators from the same campaign.

IOC submissions that cannot be publicly verified, that contain personally
identifiable information, or that extend ccguard beyond its defensive scope
will be closed.

## Commit messages

Conventional Commits encouraged but not required. Examples:

```
feat(hashwatch): catch atomic rename via parent-dir watch
fix(storage): use UPSERT to make Approve idempotent
docs(threat-model): add T4 (revert-to-original evasion)
ioc: add CCG-IOC-0042 — known-bad settings.json from campaign X
```
