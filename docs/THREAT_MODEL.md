# Threat Model

This document describes what `ccguard` is designed to defend against and,
equally importantly, what it is **not**. Being explicit about these
boundaries helps users avoid a false sense of security and helps
contributors keep the scope tight.

## Assets being protected

The primary asset is the **integrity of Claude Code's hook configuration**.
Specifically:

- `~/.claude/settings.json` and `~/.claude/settings.local.json`
- Per-project `.claude/settings.json` and `.claude/settings.local.json`

These files can configure hooks that execute arbitrary shell commands at
events such as session start, tool use, and session stop. Their integrity
is therefore equivalent to the integrity of arbitrary code execution under
the user account that runs Claude Code.

## Adversary model

`ccguard` is designed against an adversary who:

- Has obtained the ability to write to the user's home directory (e.g. via
  a malicious dependency, drive-by download, or supply-chain compromise).
- Wishes to *quietly* persist by modifying Claude Code hooks so that
  subsequent Claude Code sessions exfiltrate data or execute commands on
  the attacker's behalf.
- Prefers stealth over speed; that is, would avoid actions that immediately
  alert the user.

`ccguard` is **not** designed against:

- A privileged adversary (root / Administrator) who can disable or modify
  `ccguard` itself before tampering.
- An adversary running with the user's privileges who has full knowledge
  of `ccguard` and chooses to disable it as part of the attack. Phase 1's
  protections are detective, not preventive.
- Compromise of the Claude Code binary itself, the host kernel, or the
  user's shell — these are out of scope.
- Cloud-side compromise of Anthropic services.

## Threats addressed

| ID | Phase | Threat | Mitigation |
|----|-------|--------|------------|
| T1 | 1 | Silent modification of `settings.json` to add a malicious hook | fsnotify-driven SHA-256 comparison against approved baseline; alert on mismatch |
| T2 | 1 | Replacement of `settings.json` via atomic rename | Directory-level watch catches CREATE events; rename target is hashed and compared |
| T3 | 1 | Deletion of `settings.json` to reset state for a follow-up tampering attempt | REMOVE events generate alerts |
| T4 | 1 | Adversary edits `settings.json` and then re-edits to original content to evade detection | All transitions are recorded in the audit log even when the final hash matches the baseline |
| T5 | 3 | Hook content unchanged but hook launches heavy background work (encryption, exfiltration) each time it fires — invisible to hash-based detection | Layer 2 z-score baseline anomaly detection flags statistically significant duration increases |

## Threats explicitly out of scope

| ID | Threat | Why out of scope |
|----|--------|------------------|
| O1 | Adversary disables or kills `ccguard` before tampering | Same-privilege adversary; mitigated only by Phase 4 (kernel-level) work and OS hardening |
| O2 | Adversary deletes the audit log | Same-privilege adversary. Forwarding events to a remote sink is planned but optional |
| O3 | Adversary modifies files inside `~/.claude/` other than the monitored set | Monitored filename list is conservative; widen via config when needed |
| O4 | Malicious Claude Code MCP server that doesn't require a config change | Phases 3 and 4 will partially address; Phase 1 cannot |
| O5 | Tampering with `ccguard`'s own SQLite database | Phase 1 stores approvals in the same trust domain as Claude Code itself |

## Future phases

- **Phase 2 (IOC matching)** broadens detection to known-bad hashes,
  paths, and command strings observed in real-world Claude Code attacks.
- **Phase 3 (baseline anomaly)** detects subtle hook-timing deviations
  that suggest a hook is doing more than it used to.
- **Phase 4 (behavioral)** uses kernel-level instrumentation (eBPF on
  supported WSL2 kernels, auditd elsewhere) to detect and optionally block
  sensitive command execution by hook-spawned processes. This is the
  phase that begins to address O1 and O2 in a meaningful way.

## Operational guidance

- Run `ccguard watch` under your own user account, not root.
- Keep the `ccguard` binary on a read-only filesystem or under FIM of its
  own (yes, it's turtles).
- Consider forwarding `ccguard --json` output to a log sink outside the
  workstation for tamper-evident retention.
- Review the audit log periodically: `sqlite3 ~/.local/share/ccguard/ccguard.db
  'SELECT datetime(ts,"unixepoch"), path, kind, fs_op FROM events ORDER BY ts DESC LIMIT 50'`.

## Reporting weaknesses in this threat model

If you believe a threat is in scope but unaddressed, or out of scope but
should be in, please open a Discussion or a Security Advisory.
