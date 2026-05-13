# Architecture

`ccguard` is designed as four cooperating detection layers. Phase 1 ships
Layer 1 only; later layers are additive — each can be disabled and each
contributes events to a shared audit log.

```
                ┌────────────────────────────────────────┐
                │            ccguard daemon              │
                ├────────────────────────────────────────┤
                │ L1 Hash Integrity   (Phase 1, shipped) │
                │ L2 Baseline Anomaly (Phase 3, planned) │
                │ L3 IOC Matching     (Phase 2, planned) │
                │ L4 Behavioral       (Phase 4, planned) │
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

## Future layer hooks

The internal `alert.Sink` is the single point through which all detections
flow. Phase 2–4 layers will produce events into the same sink so that the
audit log, JSON output, and (future) webhook delivery work uniformly
regardless of which layer detected the issue.
