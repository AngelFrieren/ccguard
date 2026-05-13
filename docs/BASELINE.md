# Baseline Anomaly Detection (Phase 3 / Layer 2)

Layer 2 detects hooks that have been silently augmented to perform heavy
background work on every invocation — a threat invisible to hash-based
detection (T5).

## How it works

Each time a hook fires, ccguard records its wall-clock duration in a local
SQLite table. Once enough samples have been collected, it computes a rolling
mean and standard deviation and compares each new duration against that
baseline using a z-score:

```
z = (duration − mean) / stddev
```

A high z-score means the hook took significantly longer than usual.

## Data collection modes

### Mode B — hook-wrap (recommended)

Replace the hook command in `settings.json` with `ccguard hook-wrap`:

```json
{
  "hooks": {
    "PreToolUse": [{
      "command": "ccguard hook-wrap PreToolUse -- /path/to/my-hook.sh"
    }]
  }
}
```

`hook-wrap` executes the original command transparently (stdin/stdout/stderr
pass through, exit code is propagated) and writes one execution record to the
database after it completes. No running `ccguard watch` daemon is required —
records accumulate in SQLite and are processed the next time `watch` starts.

### Mode A — log tailing (best-effort)

If Claude Code emits hook execution logs to a directory, ccguard can tail
those files and extract timing data without modifying `settings.json`:

```sh
ccguard watch --log-dir /path/to/claude-logs
```

Mode A requires a `LineParser` implementation that understands the log format.
The current default is `NoOpParser` (skips every line) — Mode B is recommended
until Claude Code's hook log format is stable and documented.

## Learning phase

Anomaly detection does not activate until at least `--baseline-min-samples`
executions have been recorded for a hook (default: 30). During the learning
phase, no warnings or alerts are emitted. The `baseline show` command shows
each hook's current status:

```
$ ccguard baseline show
Hook Execution Baselines  (min-samples: 30)

HOOK           SAMPLES  MEAN      STDDEV   STATUS          UPDATED
----           -------  ----      ------   ------          -------
PreToolUse     12       45.2ms    8.1ms    learning(12/30) 2025-01-01 12:00:00Z
UserPromptSubmit  31   120.4ms   15.3ms   monitoring      2025-01-01 11:55:00Z
```

## Alert thresholds

| Flag | Default | Meaning |
|------|---------|---------|
| `--baseline-warn-z` | 3.0 | Emit WARN if z ≥ this value |
| `--baseline-alert-z` | 5.0 | Emit ALERT if z ≥ this value |
| `--baseline-cooldown` | 5m | Suppress repeated alerts per hook within this window |
| `--baseline-min-samples` | 30 | Samples needed before detection activates |
| `--baseline-window` | 100 | Most-recent executions used for mean/stddev |

## False positives

Common causes of false-positive anomalies:

- **Intentional hook change.** If you updated a hook's implementation and it
  now legitimately runs longer, reset its baseline:
  ```sh
  ccguard baseline reset --hook PreToolUse
  ```
- **System load spike.** A cold JVM, OS update, or antivirus scan can slow
  all processes temporarily. Consider raising `--baseline-warn-z` if your
  environment has high load variance.
- **First run after long gap.** If a hook hasn't fired in weeks, the baseline
  may not reflect current system state. A reset restarts the learning phase.

## Resetting baselines

```sh
# Reset one hook (returns it to learning phase)
ccguard baseline reset --hook PreToolUse

# Reset all hooks
ccguard baseline reset

# Skip confirmation prompt
ccguard baseline reset --force
```

## Tuning recommendations

- Start with the defaults (WarnZ=3.0, AlertZ=5.0, MinSamples=30).
- Run for at least a week before trusting the baseline.
- If you see frequent false positives, raise WarnZ to 4.0 and AlertZ to 6.0.
- For hooks that call external services (high inherent variance), consider a
  larger `--baseline-window` (e.g. 200) to smooth short-term noise.
