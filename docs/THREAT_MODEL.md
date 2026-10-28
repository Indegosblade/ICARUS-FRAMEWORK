# ICARUS Threat Model

## Assets

- **A1 — The source tree under analysis.** Often *untrusted* (firmware image, container
  export, someone else's rootfs) and possibly *adversarial*.
- **A2 — The intelligence database.** The product's output; used for security decisions.
- **A3 — The database that passed configured sanitization checks.** Sharing still
  requires review for the source, recipient, and policy.
- **A4 — STIX exports.** Meant to interoperate with external threat-intel tooling.
- **A5 — Secrets present in the source or the host** (passwords, WireGuard keys, tokens).

## Actors

- **Analyst (trusted):** runs ICARUS locally.
- **Source-tree author (untrusted → adversarial):** controls file names, symlinks,
  archives, plists, JSON, and binaries in A1.
- **DB recipient (semi-trusted):** receives A3/A4 and trusts the "sanitized"/"valid"
  labels.
- **Dependency/CI supply chain:** the HYGEIA git dependency, GitHub Actions, entry-point
  plugins.

## Trust boundaries & entry points

1. **A1 → parser** (ingest). The primary boundary; input is attacker-controlled.
2. **A2 → query/diff/STIX** (consumers of a possibly-hostile DB file).
3. **A3 → external world** (sharing). Requires configured verification and a
   separate sharing review.
4. **Installed distribution → runtime** (package integrity).
5. **`icarus.parsers` entry-point plugins** — any installed distribution advertising the
   group has its code imported at `import icarus.parsers` time (trusted-by-Python;
   see [parser development](../about/PARSERS.md)).
6. **Dependencies / CI actions** (supply chain).

## Sanitization-marker limits

Supported writable-query statements and initializer metadata updates revoke old
evidence transactionally. Raw `IcarusQuery.conn`/cursor/executescript writes and
independent SQLite connections are outside that guarded contract; see
[PUBLIC_WRITES.md](PUBLIC_WRITES.md). Revocation does not sanitize new content.

The HYGEIA status and audit records are mutable SQLite metadata, not a
cryptographic attestation. ICARUS validates their exact current schema and
invalidates them on its supported write path, which catches stale, malformed,
and incomplete pipeline state. An actor able to alter the database file can
still forge matching metadata; recipients who need provenance against that
actor require an authenticated delivery channel or external signature.

## Abuse cases → mitigation status

| # | Abuse case | Mitigation | Residual (issue) |
|---|---|---|---|
| AC1 | In-root symlink points outside the tree; parser reads host files into A2/A3 | symlinks cataloged, never dereferenced or traversed | **Fixed/merged (#43 → #62)** |
| AC2 | Secret in A1 ends up in A3 and is shared as "clean" | HYGEIA canonical + fail-closed + configured post-sanitize gate | Residual risk depends on configured patterns and supported carriers; no universal secret detection claim |
| AC3 | Malformed/huge/nested input exhausts memory or hangs the run | Format-specific read, nesting, archive and detection budgets | Parser extraction still enumerates each directory; resolver candidate sets scale with corpus size |
| AC4 | Hostile file **name/path** injects into the diff Markdown report | Shared Markdown escaping and bounded display | Regression coverage in `test_query_markdown.py`; a report is evidence, not executable input |
| AC5 | Recipient trusts an invalid STIX bundle / dangling refs | deterministic RFC-4122 `uuid5` ids, valid refs/timestamps | **Fixed/merged (#21 → #61)** |
| AC6 | Consumer acts on a false "moved"/"reassigned" diff edge | natural-key diff throughout | **Fixed/merged — structural_diff + observation_diff + stable entitlement owner (#38)** |
| AC7 | Untrusted **SQLite** input opened read-write / runs on hostile DB | Encoded file URIs; diff/catalog use immutable read-only inputs; query uses read-only plus `query_only` and denies ATTACH | Immutable readers require a frozen, checkpointed database; SQLite itself remains a trusted runtime dependency |
| AC8 | Malicious entry-point plugin executes on import | Plugins are trusted Python code | Install and run only trusted parser packages; this is not a plugin sandbox |
| AC9 | Dependency revision moves / local extensions enter release artifacts | HYGEIA dependency pinned to a full commit; actions pinned to commits; private parser package excluded from wheel and sdist | VCS dependency is outside PyPI vulnerability auditing; build dependencies are not fully locked |
| AC10 | Orphan/inconsistent FK data persisted silently | schema `REFERENCES` + enforced pragma | **Fixed/merged — FK ON on every write path + verify-phase `foreign_key_check` gate (#54)** |
| AC11 | Competing builds overwrite checkpoint identity or replace an active output | Process-held output lease across build and final replacement | Cooperating ICARUS writers only; arbitrary external SQLite writers are not governed by this lease |
| AC12 | Resolver mutation destroys history or assigns one atom to competing bags | Preserve historical bag rows; append events; acquire write ownership before validating membership | Application-level invariants; direct SQL can bypass resolver policy |

## Confidentiality / Integrity / Availability / Supply-chain split

- **Confidentiality:** AC1 (source-boundary reads), AC2 (secret leak), AC9 (distribution
  boundaries). Findings record fingerprints rather than raw matched secrets.
- **Integrity:** AC5 (invalid STIX → fixed #61), AC6 (false diffs → fixed #38), AC10
  (orphan FKs → fixed #54), provenance (#40 → fixed #60), forward-version relabel
  (#39 → fixed #53). Resume validates source/parser/config and original run identity.
- **Availability:** AC3 (DoS via hostile input, #47).
- **Supply-chain:** AC8 (trusted plugins), AC9 (VCS dependency and build reproducibility).

## Operational assumptions and residual limits

- Service and entitlement helpers report collected configuration and metadata,
  not effective credentials, sandbox state, client access, or exploitability.
  Missing service identity is unknown; the root helper requires an explicit
  declaration. See [SERVICE_IDENTITY.md](SERVICE_IDENTITY.md).
- Source contents must remain immutable during a resumable build. Path/config
  fingerprints do not prove source-content identity.
- The source-identity recovery key is private checkpoint state and needs separate
  access protection; see [source identity and privacy](SOURCE_IDENTITY_PRIVACY.md).
- A successful pattern-based sanitization gate means no residual matched the active
  policy. It does not establish that every possible secret or personal identifier
  was recognized. Review sharing policy for the actual source and recipient.
- File traversal and no-follow checks defend against static links/reparse points.
  A concurrently hostile source requires stronger OS isolation; the parser is not
  a filesystem snapshot or a sandbox.
- The repository is public. Neither its license nor limited adoption mitigates
  malicious input or exposure of output data.
