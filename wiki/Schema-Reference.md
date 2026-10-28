# Schema Reference

ICARUS uses SQLite with schema version 6. 17 normalized tables, 3 FTS5 indexes, 3 intelligence views.

## Entity Tables

All entity tables carry cell-level provenance:

| Column | Type | Description |
|--------|------|-------------|
| `source_version_id` | INTEGER | FK to versions table — which pipeline run produced this |
| `confidence` | REAL | 0.0-1.0, parser confidence in this entity |
| `observed_time` | TEXT | ISO 8601 timestamp |
| `marking` | TEXT | UNCLASSIFIED, PII, SENSITIVE, or REDACTED |

### files

Primary entity table. Every file found during extraction.

| Column | Type | Notes |
|--------|------|-------|
| id | INTEGER | Primary key |
| path | TEXT | Relative path from source root (UNIQUE) |
| filename | TEXT | Basename |
| extension | TEXT | File extension (lowercase) |
| size | INTEGER | Bytes |
| sha256 | TEXT | SHA-256 hash (NULL for large/unreadable files) |
| file_type | TEXT | Parser-assigned type |
| + provenance columns | | |

### binaries

Executable files with architecture detection.

| Column | Type | Notes |
|--------|------|-------|
| id | INTEGER | Primary key |
| file_id | INTEGER | FK to files |
| executable_name | TEXT | Binary name |
| arch | TEXT | x86, x86_64, arm64, aarch64, etc. |
| bundle_id | TEXT | App bundle identifier |
| + provenance columns | | |

### daemons

Services, launch daemons, systemd units, IAM identities.

| Column | Type | Notes |
|--------|------|-------|
| id | INTEGER | Primary key |
| label | TEXT | Service identifier (NOT NULL) |
| plist_path | TEXT | Config path (NOT NULL) |
| program | TEXT | Executable path |
| program_arguments | TEXT | Command line |
| user_name | TEXT | Run-as user |
| group_name | TEXT | Run-as group |
| run_at_load | INTEGER | Auto-start flag |
| keep_alive | INTEGER | Restart flag |
| sandbox_profile | TEXT | Recorded configured profile; missing text does not prove an unsandboxed process |
| mach_services | TEXT | Registered Mach services |
| binary_id | INTEGER | FK to binaries |
| is_disabled | INTEGER | Disabled flag |
| session_type | TEXT | Session type |
| + provenance columns | | |

### mach_services

Normalized launchd `MachServices` declarations. Each row links a configured
service name to the job declaring it, instead of requiring consumers to parse
the serialized `daemons.mach_services` TEXT blob. This records configuration,
not verified registration, runtime client access, or which process answers a
request.

| Column | Type | Notes |
|--------|------|-------|
| id | INTEGER | Primary key |
| daemon_id | INTEGER | FK to daemons (NOT NULL) |
| service_name | TEXT | Mach service name (NOT NULL) |
| + provenance columns | | |

`UNIQUE(daemon_id, service_name)`. Provenance `confidence` defaults to 1.0, `marking` to UNCLASSIFIED.

### entitlements, sandbox_profiles, sandbox_rules, kexts, frameworks

Similar structure — see `schema/icarus_schema.sql` for full DDL.

## Infrastructure Tables

### metadata

Key-value store for database metadata.

| Column | Type | Notes |
|--------|------|-------|
| key | TEXT | Primary key |
| value | TEXT | |

Always contains: `schema_version` (currently "6"), `source` (source path).

### versions

Pipeline run provenance. One row per `icarus build` execution.

| Column | Type | Notes |
|--------|------|-------|
| id | INTEGER | Primary key |
| run_id | TEXT | Unique run identifier |
| parser_name | TEXT | Parser used |
| source_path | TEXT | Source directory |
| started_at | TEXT | Run start timestamp |
| completed_at | TEXT | Run completion timestamp |
| entity_count | INTEGER | Total entities ingested |
| metadata | TEXT | Optional free-form JSON metadata for the run |

New pipeline runs include `source_identity` in `versions.metadata`, with
`version: 1`, `algorithm: "hmac-sha256"`, and a digest. Its random secret key is
persisted only in the private checkpoint and held in private pipeline memory;
it is absent from the public database and returned phase context. Resume
validates the identity against that private state, the output URI, and original
run/version even after HYGEIA redacts the descriptive `source_path`.

Private key/intent, public version, and checkpoint binding commit separately in
that order. Recovery either finds the exact matching run/HMAC or proves an
unbound output is empty; it never creates a new version in unrelated existing
data. Legacy identities are validated only for recovery and upgraded under
ownership locks. The deprecated `source_identity_sha256` field is refused by
current final gates. See [source identity privacy](../docs/SOURCE_IDENTITY_PRIVACY.md)
for completed-artifact remediation without the original source.

The HMAC identifies a path within one run. It is neither a source-content hash
nor an attestation. Source contents must remain immutable across resume, and
direct SQL can bypass application invariants.

## Event Tables

### observations

Temporal events against any ontology entity. Generic foreign key pattern.

| Column | Type | Notes |
|--------|------|-------|
| id | INTEGER | Primary key |
| entity_table | TEXT | Target table name (e.g., "daemons") |
| entity_id | INTEGER | Row ID in target table |
| observed_at | TEXT | When the event occurred |
| event_type | TEXT | Event classification |
| observer | TEXT | What produced this observation |
| properties | TEXT | JSON or text payload |

## Resolution Tables

### atoms

Immutable observations from each source. Never modified after creation.

Binary atoms use `path:<source file path>` as their source-local key; the
executable name remains a separate matching property. This preserves distinct
binaries with the same name in different directories. Legacy rows without a
linked file use `row:<source binary row id>` instead. Re-atomizing a version that
already contains the older name-based binary keys is refused: use a fresh
resolution output or a new source version, rather than duplicating immutable
observations under the new keys.

### bags

Resolved entity groups. Atoms that represent the same real-world thing.

| Column | Type | Notes |
|--------|------|-------|
| id | INTEGER | Primary key |
| entity_type | TEXT | Entity type of the grouped atoms |
| canonical_key | TEXT | Cluster key (`resolve`) or the smallest-id member's `source_key` (`resolve_scored`); NULL for a singleton from `create_bag` with no key given |
| created_at | TEXT | ISO 8601 timestamp |
| resolved_at | TEXT | Set when the bag is merged or split |
| atom_count | INTEGER | Number of atoms currently in this bag |
| score | REAL | Added in v6. Mean of the in-cluster match-edge scores for a `resolve_scored` merge; NULL for singletons and for bags produced by the exact-key `resolve` |

A merge keeps each losing bag as an empty historical record (`atom_count = 0`)
so its original audit events retain a valid foreign-key target and their original
bag identity. Current canonical entities are bags with current `bag_atoms`
memberships; CLI canonical counts and resolution diffs exclude empty historical
bags. Raw table counts include these historical records.

Manual merges and splits clear the surviving bag's prior `score`, because a score
measured for its earlier membership no longer describes the changed group.
Original scores in historical decision events remain unchanged.

### bag_atoms

Junction table: atom-to-bag membership.

### resolution_event_log

Append-only audit trail of every resolution decision (create, merge, split,
resolve), maintained by the resolver API. A merge appends a `merge_into` event to
each losing bag, with JSON `reason` containing `surviving_bag_id` and the caller's
`reason`. A split appends a `split_from` event to its new bag with the moved atom
IDs and JSON `reason` containing `source_bag_id` and the caller's `reason`.
Existing events are never reassigned to another bag. This is application-level
audit history, not tamper-proof storage against a caller with SQL write access.

Resolver mutation APIs acquire a SQLite write lock before reading membership,
so two resolver connections cannot validate the same atom as unassigned and
then both bag it. Each top-level operation, including a full scored resolution,
commits atomically. If the caller has already begun a transaction, the resolver
uses a savepoint and leaves the final commit or rollback to the caller. A busy
database or a stale WAL snapshot raises SQLite's locking error; callers can
retry after ending the conflicting transaction.

### match_candidates

Added in v6. Every atom pair scored during `resolve_scored`, whether or not it cleared the merge threshold — the audit trail behind a resolution decision.

| Column | Type | Notes |
|--------|------|-------|
| id | INTEGER | Primary key |
| entity_type | TEXT | Entity type of the two atoms |
| atom_a | INTEGER | FK to atoms — lower id of the pair |
| atom_b | INTEGER | FK to atoms — higher id of the pair |
| score | REAL | Weighted similarity in `[0, 1]` from `score_pair` |
| features | TEXT | JSON per-field comparator scores (explainability) |
| created_at | TEXT | ISO 8601 timestamp |

`UNIQUE(atom_a, atom_b)`. A row exists here regardless of whether the pair cleared `--threshold` — only pairs at or above threshold become a merge, recorded in `bags`/`resolution_event_log`.

## FTS5 Indexes

| Index | Source Table | Indexed Columns |
|-------|-------------|----------------|
| files_fts | files | path, filename |
| daemons_fts | daemons | label, program |
| atoms_fts | atoms | properties |

Auto-synced via INSERT/DELETE triggers.

## Intelligence Views

| View | What It Shows |
|------|--------------|
| v_sandbox_escape_surface | Legacy Mach-service / entitlement candidate join with no recorded profile; no privilege, access, or escape proof |
| v_kernel_attack_surface | Kext metadata with has_user_client = 1; user-client candidates, not proven runtime reachability |
| v_test_binaries | Binaries with test/debug in their path or bundle ID |

The historical `v_sandbox_escape_surface.privileged_entitlements` field contains
all joined entitlement keys without classifying them as privileged. Schema v6
retains that physical name for compatibility; the Python `escape_surface()`
helper exposes it as `entitlement_keys` with a declaration-candidate title.
Missing profile text is not evidence of an unsandboxed process. See the
[query evidence and compatibility contract](Query-Reference.md#configuration-evidence-and-compatibility).

## Migration Chain

v2 -> v3 -> v4 -> v5 -> v6. `initialize_database()` and build setup apply the
migration chain. Read-only query/explorer consumers do not migrate their inputs.
