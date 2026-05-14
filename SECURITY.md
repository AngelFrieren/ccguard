# Security Policy

## Supported versions

ccguard is pre-1.0. Security fixes will be applied to the latest minor
release on the `main` branch only.

## Reporting a vulnerability

Please report security issues privately via
[GitHub Security Advisories](https://github.com/AngelFrieren/ccguard/security/advisories/new).

Do **not** open a public issue for security bugs.

We will acknowledge receipt within 7 days and aim to provide a remediation
plan within 14 days. Coordinated disclosure timelines are negotiable based
on severity and exploitability.

## What is in scope

- Bypasses of Phase 1 hash detection where the attacker is a same-privilege
  user (e.g. atomic-rename patterns not caught by the current watcher).
- TOCTOU windows that allow an unapproved hash to be observed by Claude
  Code without being recorded by ccguard.
- Local privilege escalation enabled by ccguard's own code.
- SQL injection or similar issues in storage handling.
- Crashes or denial-of-service against the watcher.

## What is out of scope

- Threats explicitly listed as out of scope in [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md).
- Attacks requiring root or kernel privileges (covered by Phase 4 work).
- Issues in third-party dependencies, unless ccguard's usage materially
  worsens the impact. Please report those upstream first.
