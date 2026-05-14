# Architecture

`ccguard` is designed as four cooperating detection layers. Phase 1 ships
Layer 1 only; later layers are additive — each can be disabled and each
contributes events to a shared audit log.

```
                ┌────────────────────────────────────────┐
                │            ccguard daemon              │
                ├────────────────────────────────────────┤
                │ L1 Hash Integrity   (Phase 1, shipped) │
                │ L2 Baseline Anomaly (Phase 3, shipped) │
                │ L3 IOC Matching     (Phase 2, shipped) │
                │ L4 Behavioral       (Phase 4, shipped) │
                ├────────────────────────────────────────┤
                │       Storage (SQLite) + Audit Log     │
                ├────────────────────────────────────────┤
                │     Alert Sink (stdout / JSON / …)     │
                └────────────────────────────────────────┘
```

## Layer 1 — Hash Integrity (Phase 1)

```
                   ┌────────────┐   write/rename/delete   ┌──────────────┐
   ~/.claude/  ───►│  fsnotify  │────────────────────────►│  debounce    │
   ./.claude/      │  (inotify) │       events            │   (150ms)    │
                   └────────────┘                         └──────┬───────┘
                                                                 │
                                                                 ▼
                                                       ┌─────────────────┐
                                                       │ SHA-256 of file │
                                                       └────────┬────────┘
                                                                │
                                                                ▼
                                                       ┌─────────────────┐
                                                       │ approved_hashes │
                                                       │   lookup (DB)   │
                                                       └────────┬────────┘
                                                                │
                                                  match? ◄──────┘
                                                    │
                                          ┌─────────┴──────────┐
                                          ▼                    ▼
                                   record "approved-     emit ALERT,
                                    change" event        record "unapproved-
                                                          change" event
```

Key design choices:

- **Watch the directory, not the file.** Editors save by writing a temp
  file and renaming it over the target; watching only the original inode
  misses the new file. We watch `~/.claude/` itself and filter events by
  filename.

- **Debounce 150 ms before hashing.** A single editor save typically emits
  WRITE, CHMOD, and sometimes RENAME within milliseconds. Hashing on every
  event is wasted work and can race with an in-progress write.

- **Single-writer SQLite with WAL.** Simplifies concurrency and avoids
  CGO. The `modernc.org/sqlite` driver is pure Go, so `ccguard` ships as
  a single static binary.

- **Approvals are `(path, sha256)` pairs.** Approving a file does not
  approve any future content of that file. Rotating the hash requires an
  explicit `ccguard approve` call.

- **Every transition is recorded.** Even "approved" changes generate an
  audit log entry. An attacker who reverts a malicious change after
  exploitation cannot erase evidence that the change happened.

## Storage schema

```sql
CREATE TABLE approved_hashes (
    path        TEXT NOT NULL,
    sha256      TEXT NOT NULL,
    reason      TEXT NOT NULL DEFAULT '',
    approved_at INTEGER NOT NULL,  -- unix seconds
    PRIMARY KEY (path, sha256)
);

CREATE TABLE events (
    id     INTEGER PRIMARY KEY AUTOINCREMENT,
    ts     INTEGER NOT NULL,
    path   TEXT NOT NULL,
    sha256 TEXT NOT NULL DEFAULT '',
    kind   TEXT NOT NULL,   -- approved | approved-change | unapproved-change | removed
    fs_op  TEXT NOT NULL DEFAULT ''
);
```

## Process model

Phase 1 runs as a single user-mode process. Recommended deployment is a
systemd user service so the daemon restarts on crash and survives logout
(when lingering is enabled).

```
systemd --user  ─►  ccguard watch  ─►  fsnotify  ─►  SQLite
                          │                            ▲
                          └──── alert sink ───►  stdout / journal
```

## Layer 3 — IOC Matching (Phase 2)

IOC matching runs as a secondary check inside the Layer 1 pipeline. When a
file change is detected and hashed, the hash (and path) are tested against
a set of known-bad indicators loaded from YAML files at startup.

```
                         ┌─────────────────┐
  hash from Layer 1 ───►│  ioc.DB.Match() │
  file path        ───►│                  │
                         └────────┬────────┘
                                  │
                      match? ◄────┘
                        │
            ┌───────────┴────────────┐
            ▼                       ▼
     emit ALERT               no IOC match →
     (ioc-match),             fall through to
     record ioc_id            unapproved-change
     in audit log             path (Layer 1)
```

Key design choices:

- **Two match kinds in Phase 2**: `file_sha256` for hash-based detection and
  `file_path_glob` for structural pattern matching. Unknown kinds are logged
  and skipped (forward-compatible).

- **IOC check before approval check**: the IOC check runs first in the code
  path. If the file is subsequently found to be approved, the IOC match is
  suppressed — the user explicitly accepted that hash. If the file is
  unapproved, the IOC alert takes priority over the generic alert.

- **`ioc_id` column on `events` table**: every IOC-match event carries the
  matched indicator ID, enabling post-hoc correlation with the IOC database
  even after indicator files are updated.

- **Additive DB migration**: the `ioc_id` column is added via a
  column-existence check rather than a schema version, keeping the migration
  idempotent and backwards-compatible with Phase 1 databases.

- **No network calls**: IOC files are loaded from disk only. Phase 3+
  may add optional IOC feed fetching, but it will always be opt-in.

See [`docs/IOC_FORMAT.md`](IOC_FORMAT.md) for the YAML schema.

## Layer 2 — Baseline Anomaly Detection (Phase 3)

Layer 2 detects T5 threats: a hook whose *content* is unchanged (invisible to
L1) but which has been made to launch expensive background work on every
invocation.

### Data collection

Two complementary modes feed execution records into the `hook_executions` table:

```
  Mode B (recommended)                Mode A (best-effort)
  ──────────────────────              ──────────────────────────────
  settings.json hook command          ccguard watch --log-dir <path>
  ──────────────────────              ──────────────────────────────
  ccguard hook-wrap Name -- cmd       LogTailer goroutine tails *.log
         │                                    │
         │ times cmd, writes                  │ parses lines via
         │ hook_executions row                │ LineParser interface
         └──────────┬─────────               ─┘
                    ▼
             hook_executions (SQLite)
```

### Anomaly detection pipeline

```
  hook_executions
       │
       ▼
  RefreshAllStats() ─► baseline_stats (mean, stddev per hook)
       │
       ▼
  New execution arrives (from Mode A or B)
       │
       ▼
  checkAnomaly(): z = (duration − mean) / stddev
       │
  z ≥ AlertZ? ──► sink.Alert ("baseline-anomaly" event logged)
  z ≥ WarnZ?  ──► sink.Warn
  else        ──► no alert (update stats only)
```

Key design choices:

- **Cold start / learning phase.** No alerts are emitted until at least
  `--baseline-min-samples` executions have been collected for a hook.
  During this phase the detector accumulates data without emitting noise.

- **Rolling window.** Only the most recent `--baseline-window` executions
  are used to compute mean and stddev. This makes the baseline adapt to
  intentional changes (e.g. an updated hook implementation) without
  requiring a manual reset.

- **Bessel-corrected stddev.** Sample standard deviation (divide by n−1)
  avoids underestimating variance on small samples.

- **stddev = 0 guard.** If all recorded durations are identical, the
  z-score formula would divide by zero. The anomaly check is skipped in
  this case (constant-time hooks are not anomalous by definition).

- **Rate-limit per hook.** A configurable `--baseline-cooldown` (default
  5 min) suppresses repeated alerts for the same hook within the window,
  preventing alert storms when a hook consistently misbehaves.

- **Mode B works without watch.** `hook-wrap` writes directly to SQLite.
  Data accumulates even when `ccguard watch` is not running. On next
  startup, `RefreshAllStats()` recomputes stats from the accumulated rows.

See [`docs/BASELINE.md`](BASELINE.md) for setup instructions and tuning guidance.

## Layer 4 — Behavioral Monitoring (Phase 4)

Layer 4 detects T6 threats: hook-spawned processes that attempt sensitive
operations (memory reads, credential access, unexpected outbound connections)
that are invisible to the earlier layers.

### Process tree tracking

`ccguard hook-wrap` notifies the watch daemon of its PID via a Unix domain
socket (`$XDG_RUNTIME_DIR/ccguard.sock`, permissions 0600). The daemon
maintains a `ProcTree` of all known hook-root PIDs and their descendants.
Only processes in this tree are monitored — ccguard does **not** watch the
full machine.

```
  hook-wrap (PID 4321)
       │  connect to ccguard.sock, send "4321\n"
       ▼
  ccguard watch daemon
       │  tree.AddRoot(4321)
       │
       │  backend polls /proc or reads auditd log
       ▼
  new PID 4400, ppid=4321 → tree.AddChild(4400, 4321)  → monitored
  new PID 9999, ppid=1    → tree.AddChild(9999, 1)     → ignored
```

### Backend selection

| Backend | Build tag | Availability | Precision | Notes |
|---------|-----------|--------------|-----------|-------|
| procfs  | `linux`   | Always       | Medium    | Polls `/proc` at ~100ms; misses short-lived processes |
| auditd  | `linux`   | Root or `audit` group | High | Tails `/var/log/audit/audit.log`; kernel-level record |
| eBPF    | `linux && ebpf` | Kernel ≥5.10 + CONFIG_BPF_SYSCALL | High | Lowest overhead; requires custom build |
| noop    | always    | Always       | None      | Silent fallback when no other backend available |

Selection order: eBPF (priority 30) > auditd (priority 20) > procfs (priority 10) > noop.
`--behavior-backend auto` selects the highest-priority available backend.

### Event pipeline

```
  Backend (procfs / auditd / eBPF)
       │  behavior.Event{Ts, Pid, Ppid, Syscall, Args, Backend}
       ▼
  processBehaviorEvents() goroutine
       │
       ├─► policy.DB.Eval(event) → []Match
       │       │
       │       └─► sink.Alert / sink.Warn per match
       │
       └─► batch write to behavior_events (100ms or 100 events)
```

### Policy engine

Behavioral policies are YAML files in `$XDG_CONFIG_HOME/ccguard/policies/`.
Each policy specifies a syscall kind and match conditions:

```yaml
version: 1
policies:
  - id: T6-proc-mem-read
    severity: critical
    when:
      syscall: openat
      path_glob: /proc/*/mem
    action: alert
```

Supported syscalls: `execve`, `openat`, `connect`. The `block` action
requires `-tags active-enforcement` at build time; the default build
observes and alerts only.

Key design choices:

- **Scoped to hook process forest.** ccguard tracks only PIDs that
  descend from a `hook-wrap` root. Unrelated processes are never examined.

- **Best-effort PID notification.** If the watch daemon is not running,
  `hook-wrap` continues normally and the notification is silently dropped.
  Behavioral monitoring degrades gracefully.

- **No CGO, no kernel modules.** procfs and auditd backends are pure Go.
  The eBPF backend is gated behind a build tag so the default static binary
  has no kernel dependencies.

- **Batch writes.** `behavior_events` rows are written in transactions of
  up to 100 events or 100ms, whichever comes first. This amortizes SQLite
  write overhead for high-frequency syscall streams.

- **Forward-compatible policies.** Unknown syscall kinds and unknown policy
  fields are logged and skipped, not errors. This allows newer policy files
  to be used with older ccguard binaries.

See [`docs/BEHAVIOR.md`](BEHAVIOR.md) and [`docs/POLICY_FORMAT.md`](POLICY_FORMAT.md)
for setup and schema documentation.

## Alert Sink

The internal `alert.Sink` is the single point through which all detections
flow. All four layers produce events into the same sink so that the
audit log, JSON output, and (future) webhook delivery work uniformly
regardless of which layer detected the issue.
