# ICARUS

[![CI](https://github.com/Indegosblade/icarus-framework/actions/workflows/ci.yml/badge.svg)](https://github.com/Indegosblade/icarus-framework/actions/workflows/ci.yml)
![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-3776AB?style=flat&logo=python&logoColor=white)
![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey?style=flat)
![License: PolyForm NC](https://img.shields.io/badge/license-PolyForm%20NC-orange?style=flat)
![Status: Beta](https://img.shields.io/badge/status-beta-yellow?style=flat)

A modular framework for extracting entities from structured data sources, resolving them across versions, and producing queryable intelligence databases. One command in, one SQLite database out.

> **Status: Beta, source-available.** ICARUS is under active development and its
> interfaces may change. It is licensed under PolyForm Noncommercial 1.0.0 — this is a
> **source-available** license, **not** an OSI-approved open-source license. See
> [License](#license). The experimental entity resolver is excluded from the beta
> stability promise.

Parsers cover Windows, Linux, cloud audit logs, and **iOS/macOS root filesystems** — the last maps the launchd daemon, Mach-service, and entitlement attack surface for Apple-platform security research (validated on a live iOS 27.0 IPSW).

```
Source directory --> Parser --> Entity graph --> SQLite database
                                                     |
                                     +---------------+---------------+
                                     |               |               |
                                  Differ          HYGEIA          STIX
                               (versions)     (sanitization)    (export)
```

## Table of Contents

- [Quick Start](#quick-start)
- [Installation](#installation)
- [Usage](#usage)
- [Parsers](#parsers)
- [Schema](#schema)
- [Architecture](#architecture)
- [Development](#development)
- [Project Structure](#project-structure)
- [Documentation](#documentation)
- [Changelog](#changelog)
- [License](#license)

---

## Quick Start

```bash
pip install git+https://github.com/Indegosblade/icarus-framework.git

icarus build --source /path/to/data --output intel.db
icarus query intel.db --stats
icarus diff v1.db v2.db -o report.md
```

---

## Installation

### Requirements

| Dependency | Version | Purpose |
|-----------|---------|---------|
| Python | >= 3.10 | Runtime. Tested on 3.10, 3.12, 3.13. |
| SQLite | >= 3.35 | FTS5 full-text search support. Ships with Python on all platforms. |
| [HYGEIA](https://github.com/Indegosblade/HYGEIA) | v3.14.0 | PII detection and sanitization. Auto-installed as a dependency. |
| [PyYAML](https://pyyaml.org/) | >= 6.0 | Parser manifest loading. |
| [jsonschema](https://python-jsonschema.readthedocs.io/) | >= 4.20 | Parser manifest validation against JSON Schema. |

No native extensions. No database server. No system-level dependencies beyond Python.

### Install from GitHub

```bash
pip install git+https://github.com/Indegosblade/icarus-framework.git
```

### Install from source

```bash
git clone https://github.com/Indegosblade/icarus-framework.git
cd icarus-framework
pip install .
```

### Development install

Includes pytest, ruff, mypy, and bandit:

```bash
pip install -e ".[dev]"
```

---

## Usage

### CLI

```bash
# Build — auto-detects the best parser from source contents
icarus build --source /path/to/data --output intel.db

# Build — specify parser explicitly
icarus build --source /var/log/cloudtrail --output trail.db --parser cloud/aws/cloudtrail

# Build — skip PII sanitization (raw output, not safe to share)
icarus build --source /data --output raw.db --skip-hygeia

# Query — full-text search
icarus query intel.db --search "nginx"

# Query — table stats
icarus query intel.db --stats

# Query — raw SQL
icarus query intel.db --sql "SELECT path, size FROM files WHERE size > 100000000 ORDER BY size DESC LIMIT 20"

# Diff — compare two databases
icarus diff v1.db v2.db -o report.md

# Diff — export as STIX 2.1 bundle
icarus diff v1.db v2.db --stix bundle.json

# Parsers — list, validate, test
icarus parser list
icarus parser validate icarus/parsers/windows.yaml
icarus parser test windows
```

### Python API

```python
from pathlib import Path
from icarus.core.pipeline import create_default_pipeline
from icarus.core.query import IcarusQuery
from icarus.core.differ import IcarusDiffer
from icarus.core.resolver import EntityResolver
from icarus.integrations.stix_export import export_to_stix

# Build a database
pipeline = create_default_pipeline(
    source=Path("/path/to/data"),
    output=Path("intel.db"),
    parser_name="windows",
)
ctx = pipeline.run()

# Query
with IcarusQuery("intel.db") as q:
    q.root_daemons()              # Services running as root without sandbox
    q.service_map()               # Service -> binary -> permission mapping
    q.kernel_surface()            # Kernel-reachable entry points
    q.escape_surface()            # Privilege escalation paths
    q.mach_service_owners("com.apple.%")               # Mach service -> owning daemon
    q.daemons_with_entitlement("%iokit-user-client%")  # Daemons holding an entitlement
    results = q.search("config", table="daemons")

# Diff two versions
with IcarusDiffer("v1.db", "v2.db") as d:
    diff = d.full_diff()          # All categories: add/delete/change/structural
    report = d.generate_report()  # Markdown

# Resolve entities across sources (experimental — opt in with experimental=True)
with EntityResolver("intel.db", experimental=True) as r:
    r.ingest_atom(version_id=1, entity_type="binaries",
                  source_key="nginx", properties={"executable_name": "nginx", "sha256": "ab12…"})
    r.ingest_atom(version_id=2, entity_type="binaries",
                  source_key="nginx", properties={"executable_name": "nginx", "sha256": "ab12…"})
    r.resolve_scored("binaries")                        # block -> score -> cluster -> merge
    # r.resolve("binaries", blocking_keys=["executable_name"])  # exact-key MVP

# Export to STIX 2.1
export_to_stix(Path("intel.db"), Path("bundle.json"))
```

The top-level `icarus` package curates a public surface via `__all__`: `Pipeline`, `create_default_pipeline`, `IcarusQuery`, `BaseParser`, and `initialize_database` import directly from `icarus` (e.g. `from icarus import create_default_pipeline`) instead of reaching into `icarus.core.*`. The differ, resolver, and STIX export stay submodule imports, as shown above.

### Entity resolution (experimental)

Cross-source canonical identity: the same binary or daemon observed across separate builds (different hosts, different scans over time) is projected into immutable `atoms`, scored pairwise, and grouped into one canonical `bags` row once its match score clears a threshold.

```bash
icarus resolve --out resolved.db host_a.db host_b.db
```

Every candidate pair considered — not just the ones that merge — is persisted to `match_candidates` with its score and per-field features, and each merged bag's confidence lands in `bags.score`, so a resolution decision is always auditable after the fact. `EntityResolver` remains explicitly experimental (construct it with `experimental=True`, as `icarus resolve` and the optional `icarus build --resolve` phase both do) — see [wiki/CLI-Reference.md](wiki/CLI-Reference.md#icarus-resolve) and [wiki/Schema-Reference.md](wiki/Schema-Reference.md) for the full flag/schema reference.

---

## Parsers

Parsers are the extension point — and the only source-specific code in the framework.
Everything *downstream* of a parser (the normalized schema, full-text search, the
cross-version differ, entity resolution, STIX 2.1 export, and the fail-closed
sanitizer) is schema-driven and knows nothing about where the data came from. That is
the whole design, and it means:

> **Write one parser that emits entities into the tables, and you inherit the entire
> engine for free.**

The rows a parser inserts are — with no additional code — immediately full-text
searchable (FTS5), diffable across versions, exportable to STIX, and run through
sanitization. Emit temporal `observations` and you get time-diffing on them; add a
one-line atom projection ([`icarus/core/atomize.py`](icarus/core/atomize.py)) for your
entity type and **cross-source resolution** ("the same binary across two different
dumps") lights up too. The code you write is small; the machine you plug into is not.

Parsers are first-class to write — and to keep private:

- **In-repo** — a `BaseParser` subclass plus a YAML manifest under `icarus/parsers/`.
  Auto-discovery registers it at import; there is no parser list to maintain.
- **Private** — the gitignored `icarus/parsers/private/` package registers and runs
  *exactly* like a shipped parser, but never touches git. Sensitive, client-specific,
  or otherwise-not-for-public parsers stay yours; the public tree stays clean.
- **Distributed** — an installed package can advertise its own parsers through the
  `icarus.parsers` entry-point group.

A 4-gate test harness (golden output, idempotency, schema conformance, zero-PII) is the
bar for production tier, and a manifest's `specificity` slots your parser into the
auto-detection contest automatically. See [about/PARSERS.md](about/PARSERS.md) for the
full development guide.

### Built-in parsers

9 parsers — 8 production, 1 candidate. Auto-detection runs each parser's `identify()` method against the source; the most specific match (lowest specificity number) wins.

| Parser | Tier | Spec | Description |
|--------|------|:----:|-------------|
| `cloud/aws/cloudtrail` | production | 5 | AWS CloudTrail JSON audit logs — IAM identities, API events, error patterns |
| `macos` | candidate | 8 | macOS / iOS root filesystem — launchd daemons, Mach services, entitlements, kexts, frameworks |
| `windows` | production | 20 | Windows directories — PE/DLL binaries, services, frameworks, file metadata |
| `linux` | production | 20 | Linux rootfs — ELF binaries, systemd units, shared libraries, capabilities |
| `generic/json` | production | 100 | JSON file catalog with top-level key extraction |
| `generic/xml` | production | 100 | XML file catalog |
| `generic/sqlite` | production | 100 | SQLite database catalog with schema discovery |
| `generic/archive` | production | 100 | Archive catalog (.zip/.tar/.gz) with contents listing |
| `generic/binary` | production | 100 | Catch-all — catalogs any directory with files |

Lower specificity wins. CloudTrail (5) beats macOS/iOS (8) beats Windows (20) beats generic (100). If no specific parser matches, a generic fallback always catches it.

The **`macos`** parser maps the iOS/macOS daemon attack surface: it reads launchd plists into daemons plus normalized Mach services, and extracts embedded entitlements straight from each Mach-O code signature with a self-contained stdlib reader (`icarus/parsers/macho.py`) — no `codesign`/`ldid` required. See [Validation Results](wiki/Validation-Results.md) for a full iOS 27.0 run.

Each parser ships with a YAML manifest validated by JSON Schema at load time. Manifests declare quality tier, specificity, [Admiralty reliability grade](https://en.wikipedia.org/wiki/Admiralty_code), and test configuration. A 4-gate test harness enforces golden output, idempotency, schema conformance, and zero-PII verification before a parser reaches production tier.

See [about/PARSERS.md](about/PARSERS.md) for the parser development guide.

---

## Schema

17 normalized tables, 3 FTS5 full-text indexes, 3 intelligence views. Schema version 6 with automatic migration from v2 through v5.

| Layer | Tables |
|-------|--------|
| Ontology | `files`, `binaries`, `daemons`, `mach_services`, `entitlements`, `sandbox_profiles`, `sandbox_rules`, `kexts`, `frameworks` |
| Infrastructure | `metadata`, `versions` |
| Events | `observations` |
| Resolution | `atoms`, `bags`, `bag_atoms`, `match_candidates`, `resolution_event_log` |
| Search | `files_fts`, `daemons_fts`, `atoms_fts` |
| Views | `v_sandbox_escape_surface`, `v_kernel_attack_surface`, `v_test_binaries` |

`mach_services` (added in v5) normalizes each launchd job's advertised Mach services into rows — the reachability pivot from a Mach service name to the daemon that vends it, and the join behind `v_sandbox_escape_surface`.

`match_candidates` and `bags.score` (added in v6) make entity resolution auditable: every scored atom pair the resolver considered is stored with its similarity score and per-field features, and each merged bag carries the confidence that produced it.

Every entity row carries cell-level provenance: `source_version_id` (FK to pipeline run), `confidence` (0.0-1.0), `observed_time` (ISO 8601), and `marking` (UNCLASSIFIED / PII / SENSITIVE / REDACTED).

See [wiki/Schema-Reference](wiki/Schema-Reference.md) for full column definitions.

---

## Architecture

**Streaming extraction** — parsers process files and records individually with periodic batch commits. Format-specific read/decompression caps bound materialized input instead of loading an entire source tree. SQLite memory-mapped I/O and page cache scale to available system RAM automatically.

**Source-boundary safety** — parser reads are regular-file-only and no-follow by default. Symlinks are cataloged from link metadata without opening their targets; FIFOs/devices/sockets are skipped with a warning; non-UTF-8 path bytes are escaped for safe SQLite storage. Recursive JSON failures are isolated, and compressed-tar listing stops at a 64 MiB decompressed-data budget.

**Checkpoint/resume** — the pipeline saves progress after each phase. If it crashes at phase 4, it resumes from phase 4.

**Two-graph model** — a single database holds an ontology graph (entities and relationships, structural) and an event graph (observations and resolution decisions, temporal). Cross-graph joins connect them.

**Entity resolution** — the Atom/Bag/EventLog pattern groups observations from different sources that refer to the same real-world entity. Parsed entities are projected into immutable `atoms`, then `resolve_scored` runs a real **block → score → cluster → merge** pipeline: FTS5 + blocking-key candidate generation (no O(n^2) comparison), stdlib per-field similarity scoring, union-find clustering of the above-threshold pairs, and a merge into canonical `bags`. Every scored pair is persisted to `match_candidates` and every merge's confidence to `bags.score`, so a decision is auditable after the fact; an append-only event log records each one, and bags merge/split with full reversibility. The simpler exact-key `resolve()` remains as an MVP. The subsystem is experimental — opt in via `icarus resolve` (cross-source) or `icarus build --resolve` (within a build).

**Diff categories** — ADDITION, DELETION, PROPERTY_CHANGE, STRUCTURAL, RESOLUTION_CHANGE. The differ opens both databases immutable and read-only (`mode=ro&immutable=1` — no `-wal`/`-shm`, safe on untrusted exports) and runs set-difference queries directly in SQLite. Property comparisons are NULL-safe (`IS NOT`, so a change to/from NULL is never missed) and entity identity is diffed on natural keys (e.g. bundle ID + entitlement key/value), not autoincrement IDs that carry no meaning across databases.

**Connection hygiene** — all core code routes through a single `open_db()` helper: `PRAGMA foreign_keys = ON` is enforced on every working connection (not just the one-shot connection used to create the schema), and cache/mmap pragmas scale to available system RAM on every connection, not only the initial one.

**PII sanitization** — [HYGEIA](https://github.com/Indegosblade/HYGEIA) runs as a pipeline phase. PII is stripped before the database is marked complete, not as a separate post-processing step.

**STIX 2.1 export** — entities map to STIX Cyber Observable Objects and Domain Objects. File/binary observations become Observed Data over SCO references; daemon/entitlement observations become Sighting relationships to their SDOs. Every reference resolves within the bundle, timestamps are normalized to UTC, and RFC 4122 UUIDv5 identifiers remain deterministic. Diffs map to complete STIX Note objects across all four diff categories (addition, deletion, change, structural).

See [about/ARCHITECTURE.md](about/ARCHITECTURE.md) for design decisions and extension points.

---

## Development

### Run tests

```bash
pytest tests/ -x -q
```

325 tests across 31 modules covering schema, queries, diffing, pipeline, entity resolution (the atomizer, similarity scoring/blocking, scored resolution, and CLI/pipeline wiring), observations, parsers, manifests, registry, test harness, generic fallbacks, CloudTrail, the macOS/iOS daemon parser, STIX export, HYGEIA sanitization (column-scoped redaction and the fail-closed post-gate), the read-only query barrier, hostile-input safety, provenance, and the top-level public API.

CI runs the full test matrix on every push:

| | ubuntu | windows | macos |
|---|:---:|:---:|:---:|
| **Python 3.10** | x | x | x |
| **Python 3.12** | x | x | x |
| **Python 3.13** | x | x | x |

### Lint

```bash
ruff check .
```

Configured for Python 3.10 target, 100-character line length. Rules: `E` (pycodestyle errors), `F` (pyflakes), `W` (pycodestyle warnings), `I` (isort).

### Type check

```bash
mypy icarus/
```

### Security scan

```bash
bandit -r icarus/ -c pyproject.toml
```

Runs [Bandit](https://bandit.readthedocs.io/) static analysis. B608 (SQL injection via string-built queries) is intentionally **not** in the skip list — this codebase builds SQL with f-strings pervasively, and B608 is the exact bug class it is prone to. Call sites verified safe (table/column names checked against `validate_table`/`validate_column` or sourced from `sqlite_master`, values passed as bound `?` parameters) carry a targeted `# nosec B608` with a one-line justification instead of a blanket skip. Other excluded rules are documented in `pyproject.toml` with rationale (e.g., B101 assert in tests, B110/B112 try-except-pass in defensive parser code).

### Writing a parser

Implement `BaseParser` and drop the module into `icarus/parsers/`:

```python
from icarus.parsers.base import BaseParser
from pathlib import Path

class MyParser(BaseParser):
    @property
    def name(self) -> str:
        return "my_source"

    @property
    def description(self) -> str:
        return "One-line description"

    def identify(self, source: Path) -> bool:
        """Return True if this parser handles the source."""

    def extract_entities(self, source: Path, db_path: Path) -> dict:
        """Walk source, write entities to database."""

    def extract_relationships(self, source: Path, db_path: Path) -> dict:
        """Link entities together."""
```

Parsers are auto-discovered — there is no registry file to edit. Every concrete `BaseParser` subclass found anywhere under `icarus/parsers/` is registered automatically at import time, including local-only parsers dropped into the gitignored `icarus/parsers/private/` package. An installed distribution can instead advertise a parser through the `icarus.parsers` entry-point group. A parser's manifest is its sibling `<module>.yaml`, when one is present. Discovery and manifest-load failures are logged, never silently swallowed.

A working example is in [`examples/custom_parser.py`](examples/custom_parser.py). The full parser development guide is in [about/PARSERS.md](about/PARSERS.md).

---

## Project Structure

```
icarus-framework/
├── icarus/
│   ├── __main__.py               CLI entry point
│   ├── core/
│   │   ├── pipeline.py           Phase orchestrator with checkpoint/resume
│   │   ├── schema.py             SQLite schema v6, FTS5, migrations
│   │   ├── query.py              Query engine with 3 intelligence views
│   │   ├── differ.py             Cross-version diff engine
│   │   ├── atomize.py            Project parser rows into resolver atoms
│   │   ├── matching.py           Blocking, similarity scoring, clustering
│   │   ├── resolver.py           Entity resolution (Atom/Bag/EventLog, scored)
│   │   └── registry.py           Parser registry and detection contest
│   ├── parsers/
│   │   ├── base.py               Abstract parser interface
│   │   ├── manifest.py           YAML manifest loader + JSON Schema validation
│   │   ├── testing.py            4-gate test harness
│   │   ├── windows.py            Windows parser (PE/DLL)
│   │   ├── linux.py              Linux parser (ELF/systemd)
│   │   ├── macos.py              macOS/iOS parser (launchd daemons, Mach services)
│   │   ├── macho.py              Self-contained Mach-O reader (arch, entitlements)
│   │   ├── cloud/                Cloud parsers (aws/cloudtrail)
│   │   ├── generic/              Fallback parsers (json, xml, sqlite, archive, binary)
│   │   ├── catalog/              Two-tier parser catalog
│   │   └── schema/               Manifest JSON Schema
│   └── integrations/
│       ├── hygeia.py             PII sanitization
│       └── stix_export.py        STIX 2.1 export
├── tests/                        325 tests
├── examples/                     Custom parser template
├── schema/                       Standalone SQL reference
├── about/                        Architecture and parser docs
├── wiki/                         GitHub wiki source
├── .github/workflows/ci.yml      CI: 9-job matrix + lint + security
├── pyproject.toml
└── LICENSE
```

---

## Documentation

| Document | Contents |
|----------|----------|
| [about/ARCHITECTURE.md](about/ARCHITECTURE.md) | Design decisions, component map, extension points |
| [about/PARSERS.md](about/PARSERS.md) | Parser development guide, manifest format, registration |
| [wiki/Getting-Started.md](wiki/Getting-Started.md) | Installation and first scan walkthrough |
| [wiki/CLI-Reference.md](wiki/CLI-Reference.md) | All commands and flags |
| [wiki/Schema-Reference.md](wiki/Schema-Reference.md) | Full table and column definitions |
| [wiki/Query-Reference.md](wiki/Query-Reference.md) | Intelligence views, FTS search, SQL patterns |
| [wiki/Parser-Ecosystem.md](wiki/Parser-Ecosystem.md) | Manifests, registry, test harness, quality tiers |
| [wiki/STIX-Export.md](wiki/STIX-Export.md) | STIX 2.1 mapping, custom extensions, bundle format |
| [wiki/Validation-Results.md](wiki/Validation-Results.md) | Test run data from real pipeline executions |
| [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) | Trust boundaries, assumptions, and what sanitization does and does not guarantee |
| [SECURITY.md](SECURITY.md) | Supported versions and how to report a vulnerability |
| [docs/PRODUCTION_AUDIT.md](docs/PRODUCTION_AUDIT.md) | Multi-agent production-readiness audit — findings, fixes, backlog |

---

## Changelog

### 4.0.0b1 (2026-07) — Public beta: correctness, safety, and packaging hardening

The first public, source-available beta. A end-to-end audit and remediation pass
made the framework's guarantees true on real data rather than on fixtures. Highlights:

- **Sanitization is real and fail-closed.** HYGEIA is wired as the canonical engine
  (previously imported but never invoked); a mandatory post-sanitize gate refuses to
  bless output that still contains a residual, and redaction is **column-scoped** so
  value-content patterns (email/IP/etc.) apply only to free-text columns and never
  corrupt or false-abort on structural path/filename data. Verified on a real
  filesystem, not just fixtures.
- **Read-only by default.** `query` opens read-only (`mode=ro` + `PRAGMA query_only`);
  writes require the explicit `exec` command. A failed sanitization is marked and
  `query` refuses it unless `--allow-unverified`.
- **Atomic, honest builds.** `--fresh` builds into a temp file and swaps on full
  success only; an existing output is refused rather than silently unioned; resume
  restores the original run/version identity and requires an exact
  source/parser/config fingerprint match. Keep a crashed build's source immutable:
  ICARUS refuses ordinary path/type/size/mtime tree changes, while deliberately
  timestamp-preserving same-size replacement requires a clean `--fresh` rebuild.
- **Correct output.** Cross-database diffs use natural keys (not local row ids);
  every entity row carries provenance (`source_version_id` + `observed_time`); STIX
  2.1 export validates under strict `stix2.parse` with no dangling refs; diff reports
  neutralize hostile values.
- **Hostile-input safety.** In-root symlinks are cataloged, never dereferenced;
  FIFOs/special files, non-UTF-8 names, deeply nested JSON, and compression bombs are
  skipped-with-warning; file hashing is size-capped.
- **Packaging & CI.** Wheel/sdist ship every parser manifest, JSON Schema, and
  catalog; CI builds and smoke-tests the installed wheel across a 3-OS × 4-Python
  matrix with pinned, Dependabot-free actions, `pip-audit`, and a read-only token.
  The experimental entity resolver is excluded from the beta stability promise.

### v1.4.0 (2026-07-03) — Real entity resolution (block → score → cluster → merge)

The resolver's long-standing "block → score → cluster → merge" promise is now real, cross-source, and auditable — and it is finally fed by the pipeline instead of being created empty on every build. Delivered as four reviewed increments.

- **Atomizer** — a new `icarus/core/atomize.py` projects parsed entity rows (binaries, daemons) into the immutable `atoms` table through a declarative, extensible projection registry. Before this, nothing populated `atoms` outside tests, so the entire resolver subsystem was built and left empty.
- **Scoring + blocking** — `icarus/core/matching.py` adds stdlib (`difflib`) per-field comparators, a weighted `score_pair` that returns a similarity plus its per-field features, and `candidate_pairs`, which generates candidates from normalized blocking-key buckets unioned with an FTS5 token search over `atoms_fts` (the index that was maintained but never used) — no O(n²) all-pairs comparison.
- **Scored resolution** — `EntityResolver.resolve_scored()` runs the full pipeline: block → score (persisting *every* candidate to `match_candidates`) → union-find `cluster()` of the above-threshold pairs → merge each connected component into one canonical `bags` row with a confidence in `bags.score` and a confidence-bearing event-log entry. The exact-key `resolve()` MVP is untouched; `threshold` lives only on the new method.
- **Schema v6** — new `match_candidates` table (audited scored atom pairs) and `bags.score` column, added to fresh databases and to existing ones through a `_v5_to_v6` migration with byte-identical DDL on both paths. 17 tables total.
- **Both surfaces** — `icarus resolve --out resolved.db a.db b.db …` atomizes and resolves across multiple builds (cross-source canonical identity — "the same binary across two dumps"), and an optional `icarus build --resolve` phase resolves within a single build. Both are explicitly experimental.
- **Quality** — 208 tests (up from 163), ruff + mypy + bandit clean, 12-job CI matrix green. Validated end-to-end on a real Linux dump: two ingests merged into 52 canonical entities each spanning both sources, every merge scored and recorded.

### v1.3.0 (2026-07-03) — Parser auto-discovery + production-audit backlog closure

Two remediations, both grounded in [docs/PRODUCTION_AUDIT.md](docs/PRODUCTION_AUDIT.md): the hardcoded parser registry is gone, and the bulk of the open audit backlog is closed.

- **Parser discovery** — the hardcoded `_ALL_PARSERS` list (which named four never-shipped modules and silently swallowed every import/manifest error) is replaced by directory + entry-point auto-discovery. Every concrete `BaseParser` subclass under `icarus/parsers/` is registered automatically, including local-only parsers in the gitignored `icarus/parsers/private/` package, plus anything an installed distribution advertises via the `icarus.parsers` entry-point group. The engine references no parser by name; discovery/manifest failures are logged, not swallowed.
- **Diff/query correctness** — `changed_entities()` is NULL-safe (`IS NOT` instead of `!=`); `entitlement_diff` compares on a natural key (bundle ID + entitlement key/value) instead of a meaningless cross-database autoincrement ID; `structural_diff`'s three join types dedupe ambiguous keys (`HAVING COUNT(*) = 1`) so duplicates can no longer Cartesian-product into false "moved/reassigned" rows; CloudTrail observation dedup now keys on the unique `eventID` instead of second-granularity timestamps.
- **Untrusted-input hardening** — a shared `open_db()` helper enforces `PRAGMA foreign_keys = ON` and RAM-scaled cache/mmap pragmas on every working connection (previously only a one-shot, immediately-closed connection got them); the differ and the generic SQLite parser now open untrusted source databases read-only and immutable (`mode=ro&immutable=1` — no `-wal`/`-shm`, no recovery) and always close them, including on `DatabaseError`; the `deploy_scripts` parser's regexes are length-bounded so a missing terminator can no longer backtrack to end-of-file (ReDoS); HYGEIA's fallback sanitizer streams rows instead of `fetchall()`-ing whole tables, and quotes every identifier pulled from `sqlite_master` instead of interpolating it raw.
- **STIX** — SDOs now carry the spec-required `created`/`modified` timestamps, observed-data SDOs carry valid `object_refs`, and `diff_to_stix` emits all four diff categories (previously `changed`/`structural` were silently dropped).
- **Resolver honesty** — `EntityResolver` is explicit about being an experimental, unwired subsystem: it now requires `experimental=True` (or emits a warning), the unused `threshold` parameter and dead `BlockingIndex` class are gone, and its docstring accurately describes exact-key blocking instead of a "block → score → cluster → merge" pipeline it never ran. The pipeline's checkpoint DB is now cleared after a fully successful run, so re-running a build no longer silently no-ops.
- **Public API** — `icarus/__init__.py` now curates a real public surface via `__all__` (`Pipeline`, `create_default_pipeline`, `IcarusQuery`, `BaseParser`, `initialize_database`), and the parser-authoring docs/example show the real auto-discovery registration path instead of a recipe that no longer existed.
- **Security/lint** — Bandit's B608 (SQL-injection) check is no longer blanket-skipped; genuinely-safe f-string SQL call sites each carry a targeted `# nosec B608` with a one-line justification instead.
- **Quality** — 163 tests (up from 99), ruff + mypy + bandit clean. See [docs/PRODUCTION_AUDIT.md](docs/PRODUCTION_AUDIT.md) for the full finding-by-finding status.

### v1.2.0 (2026-07-02) — iOS/macOS attack-surface mapping + production hardening

- **New `macos` parser** — extracts the iOS/macOS launchd daemon, Mach-service, and entitlement attack surface from an extracted root filesystem. A self-contained stdlib Mach-O reader (`macho.py`) pulls embedded entitlements straight from the code signature — no `codesign`/`ldid`. Each daemon is linked to its executable binary.
- **Schema v5** — new `mach_services` table (the Mach-service → daemon reachability pivot); automatic v4→v5 migration.
- **New query helpers** — `mach_service_owners()`, `daemons_with_entitlement()`.
- **Network parsers** — `network/privacy_stack`, `network/deploy_scripts` (candidate tier). CloudTrail relocated to `cloud/aws/cloudtrail`.
- **Production hardening** — multi-agent readiness audit ([docs/PRODUCTION_AUDIT.md](docs/PRODUCTION_AUDIT.md)): provenance fix, input-size caps, symlink-safe hashing, hardened CloudTrail/JSON/archive parsing, LF normalization.
- **Real-world validation** — a full intelligence database built from a live iOS 27.0 (24A5370h, iPhone 15 Pro) IPSW: 656 daemons, 2,375 Mach services, 55,160 entitlements, 3,763 binaries. See [Validation Results](wiki/Validation-Results.md).
- **Quality** — 99 tests, 9-job CI matrix, ruff + mypy + bandit clean.

### v1.1.1 (2026-06-08) — First stable release

Everything shipped in one sprint.

- **Core:** Pipeline with checkpoint/resume, schema v4 with FTS5 full-text search, query engine with 3 intelligence views, cross-version differ
- **Parsers:** 8 production parsers (Windows, Linux, CloudTrail, JSON, XML, SQLite, Archive, Binary) with YAML manifests, JSON Schema validation, registry detection contest, two-tier catalog, 4-gate test harness
- **Entity resolution:** Atom/Bag/EventLog pattern with FTS5 blocking index, merge/split with full reversibility
- **Observations:** Temporal event layer with generic foreign keys, two-graph architecture (ontology + events)
- **Integrations:** HYGEIA PII sanitization as a pipeline phase, STIX 2.1 export for entities and diffs
- **CLI:** `build`, `query`, `diff`, `parser list/validate/test`
- **Quality:** 77 tests, 9-job CI matrix (3 OS x 3 Python versions), ruff + mypy + bandit

---

## License

[PolyForm Noncommercial 1.0.0](LICENSE) — free for research, education, and personal use.
This is a **source-available** license, **not** an OSI-approved open-source license:
noncommercial use only, no warranty. Review the [LICENSE](LICENSE) before use.

## Author

[@Indegosblade](https://github.com/Indegosblade)
