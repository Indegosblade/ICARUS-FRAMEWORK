# ICARUS Threat Model

## Assets

- **A1 — The source tree under analysis.** Often *untrusted* (firmware image, container
  export, someone else's rootfs) and possibly *adversarial*.
- **A2 — The intelligence database.** The product's output; used for security decisions.
- **A3 — The "sanitized" database.** The artifact intended to be *safe to share*.
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
3. **A3 → external world** (sharing). Requires A3 to actually be clean.
4. **Installed distribution → runtime** (package integrity).
5. **`icarus.parsers` entry-point plugins** — any installed distribution advertising the
   group has its code imported at `import icarus.parsers` time (trusted-by-Python, but
   undocumented).
6. **Dependencies / CI actions** (supply chain).

## Sanitization-marker limits

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
| AC2 | Secret in A1 ends up in A3 and is shared as "clean" | HYGEIA canonical + fail-closed + mandatory post-sanitize gate | **Fixed/merged (#41/#42 → #59)** |
| AC3 | Malformed/huge/nested input exhausts memory or hangs the run | FIFO skip, surrogate-escape, depth/decompression budgets | **Fixed/merged (#47 → #62)** — residual: cloudtrail size cap (#25) |
| AC4 | Hostile file **name/path** injects into the diff Markdown report | none | **Open (#35)** |
| AC5 | Recipient trusts an invalid STIX bundle / dangling refs | deterministic RFC-4122 `uuid5` ids, valid refs/timestamps | **Fixed/merged (#21 → #61)** |
| AC6 | Consumer acts on a false "moved"/"reassigned" diff edge | natural-key diff throughout | **Fixed/merged — structural_diff + observation_diff + stable entitlement owner (#38)** |
| AC7 | Untrusted **SQLite** input opened read-write / runs on hostile DB | diff opens `mode=ro&immutable=1` | Diff safe; verify `sqlite_parser`/`query` paths |
| AC8 | Malicious entry-point plugin executes on import | Python trust model | Document + consider opt-in plugin loading |
| AC9 | Dependency tag moved / unreproducible build | version pin (tag) | **Movable tag; git-URL dep (#32/#49)** |
| AC10 | Orphan/inconsistent FK data persisted silently | schema `REFERENCES` + enforced pragma | **Fixed/merged — FK ON on every write path + verify-phase `foreign_key_check` gate (#54)** |

## Confidentiality / Integrity / Availability / Supply-chain split

- **Confidentiality:** AC1 (symlink read-out), AC2 (secret leak), SAN-07 (verifier echoes
  secret). **Highest-priority class — two blockers.**
- **Integrity:** AC5 (invalid STIX → fixed #61), AC6 (false diffs → fixed #38), AC10
  (orphan FKs → fixed #54), provenance (#40 → fixed #60), forward-version relabel
  (#39 → fixed #53). Residual: checkpoint wrong-DB (#45).
- **Availability:** AC3 (DoS via hostile input, #47).
- **Supply-chain:** AC8 (plugins), AC9 (git dep + mutable action pins, #49).

## Accepted residual risk (owner to ratify)

- Entry-point plugin execution is inherent to Python packaging (document it).
- The noncommercial license and private-repo status limit exposure *today*; a public
  release removes that mitigation and makes AC1–AC5 live.
