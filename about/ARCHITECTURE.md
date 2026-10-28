# Architecture

ICARUS is a local pipeline and SQLite analysis library. Parsers turn source
formats into normalized entities, relationships, and observations. Downstream
components query or transform the supported schema. The current schema is v6;
[ontology v7](../docs/ONTOLOGY_DESIGN.md) is a separate design proposal.

## Components and data flow

```text
immutable source snapshot
  -> bounded parser detection or explicit parser
  -> pipeline: initialize -> ingest -> relationships -> verify
              -> optional experimental resolution
              -> sanitize -> finalize -> final audit
  -> SQLite entities, foreign-key relationships, observations, provenance
       -> read-only query / local explorer
       -> frozen snapshot comparison
       -> guarded STIX export
```

| Component | Ownership |
| --- | --- |
| Parser registry and manifests | Discovery, source identification, declared capabilities, and test resources. |
| Pipeline | Phase ordering, output lease, checkpoint recovery, run identity, and final completion. |
| Schema manager | DDL, migrations, indexes, views, connection configuration, and guarded metadata updates. |
| HYGEIA integration | Canonical sanitization, separate content verification, audit policy, and invalidation. |
| Query and explorer | Bounded inspection; writable query operations require explicit opt-in. |
| Differ | Read-only comparison of frozen snapshots by supported natural keys. |
| Resolver | Experimental candidate generation, scoring, grouping, and recorded resolution history. |
| STIX integration | Supported entity/diff mappings and artifact admission. |

## Storage and provenance

SQLite avoids a separate database service and supports relational joins plus FTS5.
A database is portable after committed WAL state has been checkpointed into its
main file. Copying a live main file without its WAL can omit committed data.

Ontology tables store extracted files, binaries, daemons, Mach services,
entitlements, sandbox metadata, kexts, and frameworks. Observations record temporal
events. Resolution uses atoms, bags, memberships, candidates, and an event log.
See the [schema reference](../wiki/Schema-Reference.md); authoritative DDL lives in
[icarus/core/schema.py](../icarus/core/schema.py).

Entity provenance includes source version, confidence, observation time, and
marking. These are row-level attributes; the schema does not provide a separate
provenance record for every cell. Run metadata and protected source identity are
described in [artifact privacy](../docs/SOURCE_IDENTITY_PRIVACY.md).

Migrations cover supported v2–v5 databases through v6. Initialization/build setup
may migrate an input; read-only query and explorer operations do not.

## Transactions and recovery

The pipeline leases each output before changing run identity or checkpoint state.
Linux and Windows ingestion commit rows, provenance, and cursor progress together;
an interrupted batch replays without advancing progress past its durable data.
Other parsers retain phase-level replay. Keep the source immutable: resume does
not rehash every previously processed file.

Output databases and private checkpoints are separate stores. Their recovery
protocol explicitly orders private intent and public version binding; it is not
a distributed atomic transaction. Legacy checkpoint adoption validates ownership
and refuses ambiguous state. See [ingest recovery](../docs/INGEST_RECOVERY.md).

CLI `--fresh` builds into a sibling temporary database and replaces the destination
after successful completion. Cross-source `resolve` similarly publishes only a
new, fully processed output. Direct parser calls and unrelated external writers
are outside pipeline coordination.

## Input and trust boundaries

Built-in parser reads require regular files and reject symlink traversal. Special
files are skipped; links can be cataloged as metadata. Format-specific byte,
record, archive, and detection budgets constrain materialized input. Extraction
is incremental, but memory use still depends on bounded input units and directory
listings; it is not constant for every possible source.

HYGEIA runs before completion, followed by a separate ICARUS content-verification
pass. Both use the canonical SQLite carrier catalog. This detects failures within
the configured policy; it is not independent carrier enumeration or universal
PII detection. Unsupported carrier states fail closed. See
[SQLite carriers](../docs/SQLITE_CARRIERS.md).

Artifact audit metadata is mutable state. Supported writes revoke evidence in the
same transaction as data changes; raw external SQLite writes bypass that guard.
Read-only access does not make unsanitized content safe to disclose. See
[public writes](../docs/PUBLIC_WRITES.md) and the [threat model](../docs/THREAT_MODEL.md).

Parser plugins execute Python code in the analyst's process and are trusted code.
Install only extensions you trust. Private parser modules are local extensions
excluded from public package artifacts.

## Interpretation and deployment limits

Mach-service, entitlement, and service-user relationships describe extracted
declarations. Historical view names do not establish effective privilege,
reachability, or exploitation. See [service identity](../docs/SERVICE_IDENTITY.md).

The experimental resolver generates candidates, scores them, clusters accepted
edges, and records group changes. Candidate scores and calibration results are
evidence about a model on specific data, not proof of identity across all sources.

The [local explorer](../docs/ONTOLOGY_EXPLORER.md) exposes fixed read-only queries
on loopback with a per-session capability. It is a single-user inspection tool.
Multi-user hosting requires its own authorization, audit, and isolation design.

## Extension points

| Need | Implementation and validation |
| --- | --- |
| New source format | `BaseParser`, YAML manifest, and parser fixture gates. |
| New entity type | Schema/migration plus explicit search, diff, atomization, export, and verification coverage as applicable. |
| New query | Bounded `IcarusQuery` helper with documented evidence semantics. |
| New sanitization rule | Canonical HYGEIA policy and positive/negative regression cases. |
| New export | Integration with explicit supported mappings and admission policy. |

See [parser development](PARSERS.md) and [contributing](../CONTRIBUTING.md).
