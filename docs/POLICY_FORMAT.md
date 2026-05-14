# Policy YAML Format

Behavioral monitoring policies are YAML files placed in the policy directory
(default: `$XDG_CONFIG_HOME/ccguard/policies/`). All `*.yaml` and `*.yml`
files in that directory are loaded recursively at daemon startup.

If the directory is empty or does not exist, ccguard automatically falls back
to the built-in default policies compiled into the binary. To customise:

```sh
# Write the built-in defaults to your config directory
ccguard policy init

# Validate a policy file before deploying it
ccguard policy check ~/.config/ccguard/policies/default.yaml

# List currently active policies and their source
ccguard policy list
```

## File structure

```yaml
version: 1
policies:
  - id: unique-policy-id
    description: Human-readable description
    severity: critical | high | medium | low
    when:
      syscall: execve | openat | connect
      # ... match conditions (see below)
    action: alert | warn
```

`version` must be `1`. Unknown top-level keys are silently ignored.

## Fields

### `id` (required)

Unique string identifier. Used in audit log entries and alert messages.
Recommended format: `T<threat>-<short-name>`, e.g. `T6-proc-mem-read`.

### `severity` (required)

One of: `critical`, `high`, `medium`, `low`.

### `description` (required)

Human-readable description of what the policy detects. Appears in alert output.

### `when` (required)

Specifies which event to match. The `syscall` sub-field is mandatory;
additional sub-fields provide match conditions specific to each syscall kind.

#### `syscall: execve` — process execution

Match when a hook-spawned process executes a command.

```yaml
when:
  syscall: execve
  command_basename_in:
    - mimikatz
    - lazagne
```

`command_basename_in`: list of exact basenames (no directory path) to match
against `filepath.Base(argv[0])`. If the list is empty, every `execve` matches.

#### `syscall: openat` — file open

Match when a hook-spawned process opens a file path.

```yaml
when:
  syscall: openat
  path_glob: /proc/*/mem
```

`path_glob`: a `filepath.Match`-compatible glob pattern matched against the
absolute file path. Note: `**` (double-star) is **not** supported — use `*`
to match a single path component. If omitted, every `openat` matches.

#### `syscall: connect` — outbound network connection

Match when a hook-spawned process connects to a destination that is **not** in
an allowlist. This implements deny-by-default semantics: the policy fires when
the destination is absent from the list.

```yaml
when:
  syscall: connect
  destination_not_in_allowlist:
    - "127.0.0.1:*"
    - "::1:*"
```

`destination_not_in_allowlist`: list of allowed destinations in `host:port`
form. If the list is empty, no `connect` events match (allow-all).

### `action` (required)

One of:

| Action | Effect | Build tag required |
|--------|--------|--------------------|
| `alert` | Emits a high-severity alert via `alert.Sink` | None |
| `warn` | Emits a warning via `alert.Sink` | None |
| `block` | Kills the offending process | `-tags active-enforcement` |

The `block` action is rejected at policy load time in default builds. Use
OS-level controls (seccomp, AppArmor) if you need enforcement.

## Validation

Use `ccguard policy check <file.yaml>` to validate a policy file before
deploying it. The command exits 0 on success and 1 on any validation error.

```
$ ccguard policy check configs/policies/default.yaml
OK: 3 valid policy(ies) in configs/policies/default.yaml
```

## Listing loaded policies

```
$ ccguard policy list
ID                    SEVERITY  SYSCALL  ACTION  DESCRIPTION
--                    --------  -------  ------  -----------
T6-proc-mem-read      critical  openat   alert   Hook process opened /proc/*/mem
T6-credential-tool    high      execve   alert   Hook process executed a credential-dumping tool
T6-ssh-key-access     high      openat   warn    Hook process accessed SSH private key files
```

## Example policies

### Detect any outbound connection from hooks (strict)

```yaml
version: 1
policies:
  - id: T6-no-outbound
    description: Hook processes must not make outbound connections
    severity: high
    when:
      syscall: connect
      destination_not_in_allowlist: []
    action: alert
```

### Allow only specific outbound destinations

```yaml
version: 1
policies:
  - id: T6-unexpected-outbound
    description: Hook process connected to an unexpected destination
    severity: medium
    when:
      syscall: connect
      destination_not_in_allowlist:
        - "api.anthropic.com:443"
        - "127.0.0.1:*"
    action: warn
```

### Flag shell spawning

```yaml
version: 1
policies:
  - id: T6-shell-spawn
    description: Hook process launched an interactive shell
    severity: high
    when:
      syscall: execve
      command_basename_in:
        - bash
        - sh
        - zsh
        - fish
        - dash
    action: warn
```
