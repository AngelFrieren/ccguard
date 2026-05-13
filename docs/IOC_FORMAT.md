# IOC Format Reference

This document defines the YAML schema for ccguard Indicator of Compromise
(IOC) files. IOC files are placed in the configured IOC directory
(`$XDG_CONFIG_HOME/ccguard/iocs/` by default) and are loaded at startup by
`ccguard watch` and on-demand by `ccguard ioc list` / `ccguard ioc check`.

## Schema

```yaml
version: 1                         # required; must be 1 for Phase 2
indicators:
  - id: CCG-IOC-XXXX               # unique identifier; see Naming below
    severity: critical             # critical | high | medium | low
    description: "Human-readable summary of what this IOC detects"
    references:                    # optional; MUST be present for community PRs
      - "https://example.com/advisory-url"
    match:
      kind: file_sha256            # see Match Kinds below
      values:
        - "<sha256-hex-string>"
```

A single file may contain multiple indicators under the `indicators` key.
Files that fail to parse are logged as warnings and skipped; they do not
prevent other files from loading.

## Match Kinds

### `file_sha256`

Compares the SHA-256 hash of the observed file against the listed values.
Each value must be a 64-character lowercase hexadecimal string.

```yaml
match:
  kind: file_sha256
  values:
    - "0000000000000000000000000000000000000000000000000000000000000000"
    - "aabbcc..."
```

### `file_path_glob`

Matches the absolute path of the observed file against glob patterns.
Uses `/` as the path separator regardless of OS.

- `*` matches any sequence of non-separator characters.
- `?` matches a single non-separator character.
- `[...]` matches a character class (filepath.Match semantics).
- `**` matches zero or more complete path components.

```yaml
match:
  kind: file_path_glob
  values:
    - "**/.claude/hooks/*.sh"
    - "**/.claude/hooks/*.py"
```

### Unknown kinds

Indicators whose `match.kind` is not recognised are logged as a warning
and skipped. They do not cause a load failure. This design allows future
match kinds to be introduced in IOC files without breaking older ccguard
versions that have not yet implemented them.

## Severity levels

| Level      | Meaning |
|------------|---------|
| `critical` | Confirmed malicious artefact from a known campaign. Alert immediately. |
| `high`     | Strong indicator of compromise; investigate urgently. |
| `medium`   | Suspicious pattern; may be legitimate in some contexts. |
| `low`      | Weak signal; useful for hunting but generates false positives. |

## Naming convention

IOC identifiers follow the pattern `CCG-IOC-NNNN` where `NNNN` is a
zero-padded decimal integer assigned sequentially:

- `CCG-IOC-0001` … `CCG-IOC-0999` — reserved for the upstream project.
- `CCG-IOC-L-XXXX` — suggested prefix for local / organisation-specific IOCs.

## Directory layout

The IOC directory may contain arbitrary subdirectories; `ccguard` walks the
tree recursively and loads every `*.yaml` file it finds.

```
~/.config/ccguard/iocs/
├── upstream/
│   └── supply-chain-2025.yaml   # maintained by the ccguard project
└── local/
    └── my-org.yaml              # organisation-specific indicators
```

## Adding IOCs to the upstream project

See the "IOC submission" section of [CONTRIBUTING.md](../CONTRIBUTING.md).

## Example

See [`configs/iocs/example.yaml`](../configs/iocs/example.yaml) for an
annotated sample file with test-only (all-zeros hash) indicators.
