# ICARUS Architecture

## Design Philosophy

Structured data sources contain implicit relationships that are invisible at the individual-file level but obvious at the relational-query level. ICARUS makes those relationships queryable.

---

## Component Map

```
+-------------------------------------------------------------------+
|                          PIPELINE                                  |
|  Phase orchestrator, checkpoint/resume, streaming                  |
+-------------------------------------------------------------------+
|         |              |              |               |            |
|    +----v----+    +----v----+    +----v----+    +----v----+        |
|    | PARSER  |    | SCHEMA  |    |  QUERY  |    |RESOLVER |        |
|    |Registry |    | Manager |    | Engine  |    | Entity  |        |
|    |9 total  |    |         |    |         |    | Resolve |        |
|    +----+----+    +----+----+    +----+----+    +----+----+        |
|         |              |              |              |              |
|         +------- ------+---------- ---+--------------+             |
|                        |              |                            |
|                   +----v----+    +----v--------+                   |
|                   | SQLite  |    | TWO-GRAPH   |                   |
|                   |  + FTS5 |    | Ontology +  |                   |
|                   +----+----+    | Event Graph |                   |
|                        |         +-------------+                   |
|              +---------+---------+                                 |
|              |         |         |                                 |
|         +----v----+ +--v-----+ +v--------+                        |
|         | DIFFER  | | HYGEIA | |  STIX   |                        |
|         | Cross-  | |Sanitize| | Export  |                        |
|         | version | | Output | | 2.1     |                        |
|         +---------+ +--------+ +---------+                        |
+-------------------------------------------------------------------+
```

---

## Data Flow

```
Source --> Parser.identify() --> Parser.extract_entities() --> SQLite
                                                                |
                              Parser.extract_relationships() <--+
                                                                |
                                           Schema.verify() <----+
                                                                |
                                     HYGEIA.sanitize_output() <-+
                                                                |
                                            QueryEngine <-------+
                                                 |
                                    +------------+------------+
                                    |            |            |
                                  SQL      FTS5 Search     Views
```

---

## Design Decisions

### SQLite, Not Postgres

Single-file database. No server process, no configuration. The output is one `.db` file you can copy anywhere and query with any SQLite client. The only runtime dependency is Python's built-in `sqlite3` module.

### Streaming Extraction

Parsers process records individually with periodic commits. Source data is never loaded into memory as a whole. SQLite memory-mapped I/O and page cache scale to available system RAM automatically. The streaming design ensures correctness (bounded memory regardless of source size), not artificial memory restriction.

### Safe Traversal

Parsers use `os.walk(onerror=lambda e: None)` instead of `pathlib.rglob()`. This handles broken symlinks, inaccessible paths, and permission-denied directories without crashing the pipeline. SQLite connections are wrapped in `try/finally` so they release on any failure.

### Parser Ecosystem

The framework itself has no knowledge of platform-specific formats. Parsers provide that. Each parser ships with a YAML manifest (validated by JSON Schema), declares a quality tier and specificity level, and participates in a registry contest for auto-detection. Generic fallback parsers ensure every directory produces output. The candidate `macos` parser targets iOS/macOS daemon attack-surface mapping, reading Mach-O entitlements with a self-contained stdlib reader — no external `codesign` or `ldid`.

A test harness enforces 4 quality gates: golden output match, idempotency, schema conformance, and zero-PII verification.

### First-Class Diffing

The differ attaches two databases and runs set-difference queries directly in SQLite. Five diff categories cover additions, deletions, property changes, structural topology changes, and resolution changes.

### Built-in Sanitization

HYGEIA runs as a pipeline phase, not a separate post-processing step. PII is stripped before the database is marked complete.

### Cell-Level Provenance

Every entity row carries:
- `source_version_id` — which pipeline run produced it (FK to `versions`)
- `confidence` — 0.0-1.0, parser confidence
- `observed_time` — ISO 8601 timestamp
- `marking` — access classification: `UNCLASSIFIED`, `PII`, `SENSITIVE`, `REDACTED`

The `versions` table records every pipeline run with UUID, parser name, source path, timestamps, and entity count.

### Two-Graph Architecture

A single database contains two complementary graphs:

- **Ontology graph** — entities (files, binaries, daemons, kexts, frameworks) and their relationships. Structural, slow-moving.
- **Event graph** — observations (temporal events) and resolution decisions (atoms grouped into bags). Temporal, fast-moving.

Cross-graph queries join them naturally.

### Entity Resolution (Atom/Bag/EventLog)

When the same entity appears in different sources under different identifiers:

- **Atoms** — immutable property bundles. One per observation per source. Never modified.
- **Bags** — resolved entity groups. Merge and split with full reversibility.
- **Event log** — append-only record of every resolution decision.

Candidate pairs are generated by exact-key blocking (an equality bucket on a chosen key) rather than an O(n^2) all-pairs comparison. The resolver is experimental and excluded from the beta stability promise.

### STIX 2.1 Interoperability

ICARUS entities map to STIX 2.1 objects:
- `files` -> File SCO
- `binaries` -> File SCO with extensions
- `daemons` -> Infrastructure SDO
- `entitlements` -> Course of Action SDO
- `observations` -> Observed Data SDO for SCO targets; Sighting SRO for SDO targets

Diffs export as STIX Note objects with addition, deletion, property-change,
and structural classifications.

---

## Schema (v6)

17 normalized tables. 3 FTS indexes. 3 intelligence views. The authoritative DDL lives
in `icarus/core/schema.py`; `schema/icarus_schema.sql` is a generated v6 reference dump.

| Layer | Tables |
|-------|--------|
| Ontology | files, binaries, daemons, mach_services, entitlements, sandbox_profiles, sandbox_rules, kexts, frameworks |
| Infrastructure | metadata, versions |
| Events | observations |
| Resolution | atoms, bags, bag_atoms, resolution_event_log, match_candidates |
| Search | files_fts, daemons_fts, atoms_fts |
| Views | v_sandbox_escape_surface, v_kernel_attack_surface, v_test_binaries |

`mach_services` links each configured launchd Mach-service name to the job
declaring it. The join supports configuration inspection; it does not verify
runtime registration or client access. `match_candidates` (added in v6) records
audited scored atom pairs from the experimental resolver.

The view names are historical compatibility surfaces. `v_sandbox_escape_surface`
joins Mach-service and entitlement declarations with no recorded profile; its
`privileged_entitlements` column inventories all joined keys without proving
privilege or an escape. `v_kernel_attack_surface` selects user-client metadata
candidates, without proving effective reachability. The query helpers use
[evidence-limited result labels](../docs/SERVICE_IDENTITY.md).

Migration chain: v2 -> v3 -> v4 -> v5 -> v6. `initialize_database()` and build
setup apply migrations; read-only consumers leave the input schema untouched.

---

## Extension Points

| What | How |
|------|-----|
| New data source | Implement `BaseParser` + YAML manifest |
| New entity type | Add table to schema, extend parser extraction |
| New intelligence query | Add method to `IcarusQuery` |
| New sanitization rule | Add pattern to HYGEIA integration |
| New diff dimension | Add method to `IcarusDiffer` |
| New export format | Add module to `integrations/` |
