# CLI Reference

## `icarus build`

Build an intelligence database from a data source.

```bash
icarus build --source PATH --output PATH [--parser NAME] [--fresh] [--skip-hygeia] [--resolve]
```

| Flag | Description |
|------|-------------|
| `--source, -s` | Path to data source directory (required) |
| `--output, -o` | Output database path (required) |
| `--parser, -p` | Parser name (default: auto-detect from source contents) |
| `--fresh` | Ignore checkpoints, start from scratch |
| `--skip-hygeia` | Skip PII sanitization (output contains raw data) |
| `--resolve` | EXPERIMENTAL: run entity resolution (`resolve_scored`) as an in-build phase, after `verify` and before `sanitize` — see [`icarus resolve`](#icarus-resolve) below |

**Auto-detection:** When `--parser` is omitted, the registry runs each parser's `identify()` method against the source. The parser with the lowest specificity level wins. If no specific parser matches, a generic fallback catches it.

**Examples:**
```bash
icarus build -s "C:\Users\Kevin" -o full_scan.db
icarus build -s /var/log/cloudtrail -o trail.db --parser cloud/aws/cloudtrail
icarus build -s /usr -o linux.db --parser linux --fresh
```

---

## `icarus query`

Query an intelligence database. **`query` is read-only** — the connection opens
`mode=ro` with `PRAGMA query_only = ON`, so a write statement passed to `--sql` is
refused (exit code 2) and steered to `icarus exec`. Use `exec` for writes.

```bash
icarus query DATABASE [--sql QUERY] [--search TERMS] [--table TABLE] [--stats] [--allow-unverified]
```

| Flag | Description |
|------|-------------|
| `DATABASE` | Path to ICARUS database (positional) |
| `--sql` | Raw SQL query (read-only) |
| `--search` | Full-text search query (FTS5) |
| `--table` | Table for FTS search (default: files) |
| `--stats` | Show table row counts |
| `--allow-unverified` | Query a database whose sanitization failed or is unmarked. By default either is refused (exit code 3) because it may contain unsanitized data; a verified or `--skip-hygeia` database queries normally. |

**Examples:**
```bash
icarus query intel.db --stats
icarus query intel.db --search "nginx"
icarus query intel.db --search "systemd" --table daemons
icarus query intel.db --sql "SELECT path, size FROM files WHERE size > 100000000 ORDER BY size DESC LIMIT 20"
```

---

## `icarus exec`

Execute a write statement against a database (**read-write; commits**). This is the
explicit mutation path — `query` cannot write. Opening a database with `exec` prints a
notice that it will be modified.

```bash
icarus exec DATABASE --sql "STATEMENT"
```

| Flag | Description |
|------|-------------|
| `DATABASE` | Path to ICARUS database to modify (positional) |
| `--sql` | SQL statement to execute and commit (required) |

**Example:**
```bash
icarus exec intel.db --sql "UPDATE files SET marking = 'REVIEWED' WHERE path = '/etc/passwd'"
```

---

## `icarus diff`

Compare two intelligence databases.

```bash
icarus diff OLD NEW [--output PATH] [--stix PATH] [--allow-unverified]
```

| Flag | Description |
|------|-------------|
| `OLD` | Path to older database (positional) |
| `NEW` | Path to newer database (positional) |
| `--output, -o` | Write markdown report to file (default: stdout) |
| `--stix` | Export diff as STIX 2.1 bundle JSON |
| `--allow-unverified` | Permit an unsafe STIX export when either input failed sanitization or is unmarked. |

**Examples:**
```bash
icarus diff v1.db v2.db
icarus diff v1.db v2.db -o changes.md
icarus diff v1.db v2.db --stix bundle.json
```

---

## `icarus parser`

Parser management commands.

### `icarus parser list`

List all registered parsers with tier, version, specificity, and description.

```bash
icarus parser list
```

Output:
```
Name                 Tier         Version    Spec   Description
--------------------------------------------------------------------------------
cloud/aws/cloudtrail production   1.0.0      5      AWS CloudTrail JSON audit log parser
windows              production   1.0.0      20     Windows application directory or filesystem tree
linux                production   1.0.0      20     Linux filesystem rootfs
generic/json         production   1.0.0      100    Generic JSON file directory
generic/xml          production   1.0.0      100    Generic XML file directory
generic/sqlite       production   1.0.0      100    Generic SQLite database directory
generic/archive      production   1.0.0      100    Generic archive directory
generic/binary       production   1.0.0      100    Generic binary/unknown
```

### `icarus parser validate`

Validate a parser YAML manifest against the JSON Schema.

```bash
icarus parser validate PATH
```

### `icarus parser test`

Run the 4-gate test harness against a parser.

```bash
icarus parser test PARSER_NAME
```

Gates: golden output, complete-output idempotency, schema conformance, zero-PII.
Built-in parsers carry their compact fixtures and goldens in the installed
package, so this command does not require a repository checkout or a particular
current working directory.

---

## `icarus resolve`

EXPERIMENTAL. Atomize one or more source databases and resolve entities across them — cross-source canonical identity. Each source is projected into immutable `atoms` (tagged with a new `versions` row in the output database); unless `--atomize-only` is given, `EntityResolver.resolve_scored()` then runs **block -> score -> cluster -> merge** over the atoms of each requested entity type and writes canonical `bags`.

```bash
icarus resolve --out PATH [--entity-type TYPE] [--threshold FLOAT] [--atomize-only] SOURCE [SOURCE ...]
```

| Flag | Description |
|------|-------------|
| `--out, -o` | Output resolution database path (required) |
| `--entity-type` | Entity type to atomize and resolve: `binaries`, `daemons`, or `all` (default: `all`) |
| `--threshold` | Score cutoff in `[0, 1]` for a candidate pair to count as a match edge (default: `0.85`) |
| `--atomize-only` | Stop after atomizing; skip scored resolution (no `bags`/`match_candidates` rows written) |
| `sources` | One or more source ICARUS database paths (positional, at least one required) |

Every scored candidate pair is persisted to `match_candidates` — including pairs that score *below* threshold — so a merge decision is always auditable, not just the ones that happened. Each merged `bags` row's `score` column is the mean of its in-cluster match scores. See [Schema Reference](Schema-Reference.md#match_candidates) for both tables.

**Example — resolve across two dumps:**

```bash
icarus build -s /mnt/host_a -o host_a.db --parser linux
icarus build -s /mnt/host_b -o host_b.db --parser linux
icarus resolve -o resolved.db host_a.db host_b.db
```

```
[1/2] host_a.db: 42 atoms (binaries=30, daemons=12)
[2/2] host_b.db: 39 atoms (binaries=28, daemons=11)
Total atoms: 81 across 2 source(s) -> resolved.db
[resolve] binaries: clusters=6 merges=9 atoms_resolved=58
[resolve] daemons: clusters=2 merges=2 atoms_resolved=23
Canonical entities: 66 (8 spanning >= 2 sources)
```

A binary present on both hosts under the same `sha256` merges into one canonical entity spanning `host_a.db` and `host_b.db`. Pull those cross-source entities back out with:

```bash
icarus query resolved.db --sql "SELECT id, entity_type, canonical_key, score FROM bags WHERE id IN (SELECT bag_id FROM bag_atoms ba JOIN atoms a ON a.id = ba.atom_id GROUP BY bag_id HAVING COUNT(DISTINCT a.source_version_id) >= 2)"
```
