# Security Policy

## Status

ICARUS is Beta, source-available software (PolyForm Noncommercial 1.0.0). It is a
security-research tool that parses untrusted input (filesystem trees, archives, SQLite
databases, audit logs). Treat output as sensitive. A current final sanitization
audit records configured checks; it does not prove every private value was found.
Review the [threat model](docs/THREAT_MODEL.md) and recipient policy before sharing.

## Supported versions

Security fixes target the current development line and published 4.0 beta.
The current published prerelease is
[4.0.0b3](https://github.com/Indegosblade/ICARUS-FRAMEWORK/releases/tag/v4.0.0b3).
Use that explicit link; GitHub's stable `/latest` endpoint can identify an older
historical release. Older versions have no backport guarantee.

| Version | Supported |
|---------|-----------|
| Current 4.0 beta / development line | Fixes on the current line |
| Historical releases | No backport guarantee |

## Reporting a vulnerability

Please report suspected vulnerabilities **privately** — do not open a public issue for
a security report.

- Use GitHub's **private vulnerability reporting** (the repository's *Security* tab →
  *Report a vulnerability*), or
- open a minimal public issue asking for a private contact channel, without disclosing
  details.

Include, where possible: affected version/commit, a description of the issue, and a
minimal reproduction. Please allow a reasonable window for a fix before any public
disclosure.

## Scope

In scope: memory-safety/DoS, path traversal or read-outside-source, sanitization
bypass (secrets surviving into a "sanitized" database), and injection through parsed
input. Out of scope: issues that require an already-privileged local attacker, or the
inherent behavior of the experimental entity resolver (excluded from the beta promise).
