# Hook-wrap examples

These examples show how to integrate `ccguard hook-wrap` into Claude Code's
`settings.json` for Phase 3 baseline anomaly detection.

## How to use

1. Copy `settings.json` to `~/.claude/settings.json` (or merge the `hooks`
   section into your existing file).
2. Replace `/path/to/your/*.sh` with the actual path to your hook scripts.
3. Run `ccguard init` to approve the updated settings hash.
4. Use Claude Code normally for at least 30 sessions per hook to build the
   learning baseline (configurable via `--baseline-min-samples`).
5. Anomalies will appear on stderr in the Claude Code session.

## Pattern

```
ccguard hook-wrap <HookName> -- <original-command> [args...]
```

- `<HookName>` is a free-form label used to group executions (e.g.
  `PreToolUse`, `UserPromptSubmit`). Use the Claude Code hook event name
  for clarity.
- `--` separates hook-wrap flags from the wrapped command's flags.
- The exit code, stdin, stdout, and stderr of the wrapped command are
  passed through transparently. Claude Code sees no difference.

## Checking baseline status

```sh
ccguard baseline show
ccguard baseline show --hook PreToolUse
```

## Resetting after an intentional hook change

```sh
ccguard baseline reset --hook PreToolUse
```
