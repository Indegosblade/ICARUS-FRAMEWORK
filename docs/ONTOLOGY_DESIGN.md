# Source-neutral ontology increment

Status: proposed design for [issue #105](https://github.com/Indegosblade/ICARUS-FRAMEWORK/issues/105).
This document specifies a compatibility contract and implementation gates. The
tables, semantic API, evidence states, and evaluation results proposed below do
not exist merely because this document exists. The current implementation remains
schema v6, source-specific parser tables, an experimental resolver, and the
read-only explorer described in [ONTOLOGY_EXPLORER.md](ONTOLOGY_EXPLORER.md).

## Problem and ownership

The storage model preserves useful extracted data but gives several sources the
same physical vocabulary. The CloudTrail parser stores an AWS ARN in
`daemons.label`, an identity type in `daemons.program`, and an account identifier
in `daemons.user_name`. Linux stores systemd units in the same table and unit-file
paths in `plist_path`. Windows DLLs, Linux shared objects, and Apple framework
bundles share `frameworks`. These mappings are visible in
`icarus/parsers/cloud/aws/cloudtrail.py`, `linux.py`, `windows.py`, and `macos.py`.

The query layer also needs explicit evidence limits. Before issue #110,
`IcarusQuery.root_daemons()` treated a missing user as root and a missing sandbox
profile as no sandbox. That bounded correction now requires explicit root-user
evidence and labels the profile as unrecorded; it does not implement the v7 model
proposed here. The explorer currently follows schema foreign keys and
shows physical table names. A foreign key establishes a stored reference; it
does not establish the meaning or evidential strength of that reference.

The semantic adapter owns that interpretation. Parsers own extraction and source
locators; schema code owns storage constraints; adapters own source-to-type and
field-to-meaning mappings; queries own explicit evidence filters; the GUI renders
the returned semantics without inventing additional facts. The resolver owns
identity hypotheses, not source truth.

```text
source bytes -> parser -> existing rows and source evidence
                          -> versioned semantic adapter
                             -> typed objects + bounded typed relationships
                                -> query / explorer / export

source assertions -> optional resolver -> auditable identity hypotheses
```

## Architecture decision

Choose an additive semantic projection over the existing relational model for
the first increment. Keep all v6 tables, column values, integer IDs, foreign keys,
and provenance. Add source context, a stable object-address registry, and
evidence metadata in schema v7. Expose source-neutral names through an opt-in
ontology API; keep existing SQL and Python helpers on their documented v6
meaning until an explicit deprecation cycle.

Relationships in this increment are typed projections of existing references
and explicitly named derivation rules. Do not introduce a writable generic
`edges` table or let a GUI request define relation types. A future parser needing
a new relationship must supply a typed backing relation, migration, evidence
rule, cardinality validator, and fixture before registering its projection.

Alternatives considered:

| Approach | Benefit | Cost or failure mode | Decision |
|---|---|---|---|
| Rename existing tables and columns | Clearer names for one source | Breaks saved SQL and IDs; cannot make an AWS identity an OS service | Reject |
| Add only a `platform` column | Small migration | Does not resolve field meanings, missing evidence, or relationship identity | Insufficient alone |
| Replace storage with a generic property graph | Flexible graph writes | Requires a new validation, migration, query, and operational model before correctness is established | Defer |
| Preserve rows and add typed adapters plus evidence | Retains compatibility and makes interpretation explicit | Two API vocabularies during migration; adapters must be versioned and tested | Choose |

## Source context and object types

Each source version receives an explicit context: parser implementation and
manifest version, adapter-policy version, provider/source kind, declared platform,
source namespace, path-comparison policy, and collection coverage. Source namespace
identifies the system/account/image lineage whose observations may be compared.
An operator may supply it; otherwise use a run-local opaque namespace and mark
it `unattributed`. A directory path, parser name, file hash, or machine name alone
must not silently establish that two collections came from the same system.

The initial adapter registry is a closed mapping of parser and physical table
to semantic type. Type names below are the proposed public contract. Namespace
and platform accompany every object; source-specific properties retain their
own names instead of being forced into a common service record.

| Existing rows and source | Proposed semantic type | Properties with source meaning |
|---|---|---|
| `files`, filesystem parsers | `filesystem.entry` | Source-relative path, regular/link kind, size, optional content hash; a link target is link text, not a followed edge |
| `files`, CloudTrail/generic catalogs | `artifact.file`, `artifact.document`, or `artifact.container` as declared by the adapter | Cataloged input artifact; no claim that arbitrary bytes or its records are executable entities |
| `binaries`, Windows/Linux/macOS | `executable.image` | Adapter-declared format family `pe`/`elf`/`macho`, architecture, containing file, source-specific signing properties; magic recognition and structural validation have separate evidence states |
| `daemons`, Linux | `service.systemd.unit` | Unit name and unit-file locator, configured ExecStart target; not a running process |
| `daemons`, macOS parser | `service.launchd.job` | Label, plist locator, configured program, declared Mach services; source context still distinguishes macOS, iOS, or unknown Apple platform |
| `daemons`, CloudTrail | `principal.aws` | ARN, identity type, account identifier, log-record evidence; neither OS username nor executable program |
| `mach_services`, macOS parser | `endpoint.launchd.mach_service` | Advertised service name, owning job, bootstrap/domain scope when known; advertisement does not prove runtime reachability |
| `entitlements`, macOS parser | `security.apple.entitlement` | Embedded key/value and owning image; extraction is not certificate/signature verification or proof of effective authorization |
| `sandbox_profiles`, macOS parser | `policy.apple.sandbox_profile` | Cataloged profile name/path; current cataloging does not imply parsed SBPL rules |
| `sandbox_rules`, compatible declared parser | `policy.apple.sandbox_rule` | Operation/action/filter and owning profile, only when actually emitted |
| `kexts`, macOS parser | `module.apple.kext` | Bundle identifier/version and optional containing file |
| `frameworks`, Windows | `library.windows.dll` | Current parser's DLL-named, MZ-prefixed artifact and location; full PE validity remains unknown without separate validation evidence; no invented service registration |
| `frameworks`, Linux | `library.linux.shared_object` | Cataloged ELF shared-object location/name; no inferred SONAME, dependency, or ABI promise |
| `frameworks`, macOS parser | `bundle.apple.framework` | Framework bundle location, identifier/version if present |
| `observations`, CloudTrail | `event.aws.api_activity` | Event ID when present, event source/name/time, actor reference and preserved request/result properties |
| `observations`, other declared adapters | Registered source-specific event type | Event namespace and target type must be declared; an arbitrary event string is not a global ontology class |

Unknown/private parsers remain usable through the legacy API. Their ontology
projection is `legacy.unclassified` until they register a validated adapter.
Missing or ambiguous `source_version_id` produces unknown attribution, not a
guess from nearby rows. A mixed-source legacy table can therefore contain
multiple semantic types without moving, renumbering, or deleting its rows.
New Windows services, process instances, network connections, Linux capability
claims, or cloud resources are not promised by this mapping: current parser
coverage must first demonstrate those objects.

Type assignment also carries evidence state. A magic-byte probe recognizes a
format hint; it does not validate an entire executable or prove that an OS can
load it. In particular, the Windows parser's MZ prefix and `.dll` suffix check
does not establish full PE validity. New adapters report the actual recognition
and validation checks performed, and migrated rows without that extraction
evidence stay unknown/unclassified for those checks. A semantic type name must
not silently upgrade the strength of the parser's classification.

### Three identities, with different purposes

1. **Storage identity:** the existing `(table, integer id)` inside a database.
   Migration preserves it exactly. It must never be compared as a cross-database
   natural identity.
2. **Object address:** a persisted opaque database UUID plus the existing table
   and row ID. This addresses a particular stored observation and supports stable
   explorer links after migration. Copied database artifacts retain that UUID;
   imported rows receive addresses in the destination plus an origin-address
   mapping. The UUID is not a host identifier or a PII-removal mechanism.
3. **Semantic natural identity:** `(source namespace, semantic type, native key)`.
   A snapshot adds the source-version/run identity to distinguish observations
   over time. Missing namespace/key or redacted key material makes cross-version
   identity unresolved. Resolver bags remain scored hypotheses over observations.

Native keys must be structured, canonical tuples, never delimiter-joined strings:

| Type | Native key within its declared namespace |
|---|---|
| Filesystem entry | Exact source-relative path under the declared path policy |
| Executable image | Containing-file identity plus image/slice discriminator when available; multiple binary rows for one file must be retained or rejected as ambiguous, never silently collapsed |
| systemd unit | Full unit-file locator and unit name; override/configuration relationships require separate evidence |
| launchd job | Job label plus known launch domain; when the domain is missing, retain a source-row discriminator and report ambiguous semantic identity |
| AWS principal | Exact ARN and recorded principal kind; an assumed-role session and its underlying role are distinct until an explicit relation is established |
| Mach service endpoint | Owning job identity, advertised name, and known bootstrap/domain scope |
| Entitlement assertion | Owning image, entitlement key, canonical typed value, and source-version context |
| Library/framework/kext | Source-relative location, or a declared scoped bundle key when supported; bundle name alone is not a universal key |
| CloudTrail event | Provider event ID within the declared provider/account namespace; otherwise source-document plus record locator, marked as lacking a provider identity |

Preserve case and Unicode spelling unless the source context proves a comparison
policy; parser-normalized path separators do not justify global case folding.
Do not follow symlinks to manufacture identity. Equal SHA-256 values establish
equal observed bytes, not equal installed objects, ownership, or runtime roles.
Sanitization may remove native identifiers: keep the object address, expose
`identity_state=redacted`, and decline semantic deduplication on replacement text.
Any future stable pre-redaction identifier needs its own privacy/key-management
design; do not persist an unkeyed hash of guessable private identifiers as a fix.

## Directed relationship contract

Every relationship response contains `relation_type`, source and target object
addresses, source-version context, evidence state/IDs, and optional derivation
rule/version. Natural identity is the canonical tuple of relation type, semantic
source identity, semantic target identity, source namespace, and type-specific
qualifiers. An evidence-instance address additionally identifies the underlying
row/field or record. Unknown semantic keys leave the natural identity unresolved;
the evidence instance is still addressable.

Cardinality applies to a single collected snapshot/context. A missing optional
edge means unknown/not collected unless explicit source evidence establishes
absence. Required backing references are validated before publishing v7 output.

| Relation and direction | Backing evidence | Cardinality and qualification |
|---|---|---|
| `image.contained_in`: image → filesystem entry | `binaries.file_id` | Each image exactly 1 file; a file 0..N images. Do not add a false unique-file constraint that loses image slices |
| `service.configured_image`: systemd/launchd service → image | Existing `daemons.binary_id` plus the configured program evidence and linking rule | Service 0..1 selected executable, image 0..N services. Path matching is a derivation; it is not evidence of execution |
| `service.advertises`: launchd job → Mach endpoint | `mach_services.daemon_id` | Job 0..N endpoints; endpoint observation exactly 1 owner. Same advertised name under another owner is not automatically the same endpoint |
| `image.declares_entitlement`: image → Apple entitlement assertion | `entitlements.binary_id` | Image 0..N assertions; assertion exactly 1 image. Typed value is part of assertion identity |
| `profile.contains_rule`: sandbox profile → sandbox rule | `sandbox_rules.profile_id` | Profile 0..N collected rules; rule exactly 1 profile. Empty catalog is not evidence that the profile permits everything |
| `module.contained_in`: kext → filesystem entry | `kexts.file_id` when present | Module 0..1 linked file; missing linkage stays unknown |
| `bundle.linked_image`: Apple framework bundle → image | `frameworks.binary_id` when present | Bundle 0..1 linked image under the current schema; a future multi-image bundle relation requires a backing-table migration |
| `event.actor`: CloudTrail activity event → AWS principal | Adapter interpretation of the event's existing `entity_table/entity_id` | Event 0..1 observed actor in current parser output; principal 0..N events. No actor is fabricated for records omitted by the current parser |
| `observation.about`: generic observation → declared object | `observations.entity_table/entity_id` with target/type validation | Observation exactly 1 valid target if published as this relation; target 0..N observations |
| `object.observed_in`: object → source version | Existing source-version FK or observation version FK | Object 0..1 attributable source version; missing legacy attribution is explicit unknown |
| `resolution.member_of`: atom → current bag | `bag_atoms` | Atom 0..1 current bag, which the v7 verifier must check explicitly; bag 1..N current atoms. Empty historical bags have no membership edges |

These relation types are distinct from their inverse traversal labels. The GUI
may show incoming and outgoing relationships, but must preserve direction and
type in API data. A two-hop service→image→entitlement result is a path with two
evidence-bearing edges, not a newly asserted direct privilege relationship.
Duplicate natural keys, dangling observation targets, invalid source/target
types, and cardinality violations produce validation findings. Preserve all
original rows and report ambiguity instead of choosing the first match.

The current `link_daemons_to_binaries()` matches program text to file paths.
Legacy linked rows cannot retrospectively prove exactly which bytes/rule created
the edge. Classify them `legacy_unclassified`; new runs must record the program
evidence, matching policy, candidate count, and selected image. Multiple matches
produce an unresolved relation. Current FK existence alone does not upgrade an
edge to independently verified fact.

## Evidence, missing values, and inference

Keep extraction validation, source authenticity, and analytic inference separate.
An assertion has a value state (`present`, `explicit_absent`, `unknown`,
`not_applicable`, `redacted`, or `conflicting`) and an evidence mode
(`direct`, `derived`, or `legacy_unclassified`). A direct assertion means the
adapter can point to source evidence and its extraction rule; it does not imply
the source is truthful or cryptographically authenticated. An independent
`authenticity` field is `verified`, `unverified`, or `not_applicable`, with its
verification method when present.

`unknown` includes a reason: not collected, parser unsupported, parse failure,
missing source field, ambiguous identity, incomplete traversal, or legacy
evidence unavailable. `explicit_absent` requires a source statement or a completed,
scoped enumeration supporting that negative. `NULL`, an empty join, zero rows,
and a column's SQL default do not satisfy that requirement.

New builds record evidence at extraction time: source version, bounded locator
(file/record/field), optional content digest, parser/rule version, and collection
coverage. If the source is private, locators follow sanitization policy. Evidence
records and assertion metadata are sanitized before completion and invalidate
old verified markers when mutated. Original source bytes need not be retained
or exported, and digests do not establish authenticity.

Consequences for queries and displays:

- A missing Linux unit user, launchd UserName, or sandbox-profile field does not
  become root/unsandboxed. A source-specific default may be a separately named,
  versioned inference only when its required platform/domain context is present.
- `has_pie=1`, `is_disabled=0`, `allows_network=0`, and similar legacy defaults
  remain unknown when the old parser did not preserve whether they were observed.
- An embedded entitlement is a declaration. It does not prove its code signature
  was authenticated, an OS honored it, a client could reach it, or an exploit exists.
- A CloudTrail account ID never satisfies an OS-username query. The same field's
  physical storage location does not grant the same semantic meaning.
- Parser confidence and resolver similarity are separately labeled scores, not
  calibrated probabilities or proof. Conflicting evidence remains visible.
- A truncated page or partially collected source cannot support a negative claim.
  Every collection response includes coverage and truncation state.

The proposed query API defaults to `evidence=direct`. Derived results require
`include_derived=true` and return rule/version plus input evidence addresses.
Unknowns can be requested explicitly and appear separately from matching facts;
they never satisfy a positive or negative predicate by SQL NULL substitution.
For example, `privileged_service_candidates(platform=..., include_derived=...)`
returns configured privilege evidence, sandbox evidence state, and path evidence
separately. It must not name the result an escape/exploit proof.

## Schema v7 and API compatibility plan

The schema change is additive and requires a new migration, not a silent v6
reinterpretation. Implement these bounded support structures:

| Structure | Ownership and constraints |
|---|---|
| `ontology_contexts` | One row per attributable version, FK to `versions.id`; source namespace/state, source kind/platform, adapter/identity policy versions, path policy |
| `ontology_objects` | Stable object address, allowlisted legacy table and existing ID, semantic type, nullable original source-version FK, identity state/key; unique `(legacy_table,legacy_id)` |
| `ontology_evidence` | Evidence address, source-version FK when known, source locator/digest, parser/rule version, authenticity state |
| `ontology_assertions` | Object-address FK, allowlisted property name, typed value state/evidence mode, nullable derivation policy; links to evidence through an FK-backed association table |
| `ontology_coverage` | Version FK, extractor/type/property scope, completion/unsupported/error counts; absence is distinguishable from unsupported extraction |

`ontology_objects` is a derived address/type registry, not an alternate store for
entity properties. Its `(legacy_table,legacy_id)` pointer cannot have one native
SQLite FK across several target tables. Compensate explicitly: generate it in the
semantic phase of a build, validate the allowlist and every target under a single
read snapshot, validate again before publication, and reject stale entries. New
parser writes, registry writes, and evidence writes must share a transaction when
the API supports incremental mutations. Direct legacy SQL mutation invalidates
semantic evidence as well as sanitization trust; v7 consumers refuse a stale
registry until it is rebuilt. Do not pretend a polymorphic pointer is FK-enforced.

Migration sequence:

1. Take an explicit source snapshot/backup and acquire the existing output lease.
   Never migrate an active build or mutate a database merely by opening the GUI.
2. Run existing v2→v6 migrations first where needed. In one v6→v7 transaction,
   add support tables/indexes and an opaque database UUID; copy no entity rows and
   preserve every legacy ID, value, version/run ID, provenance field, bag membership,
   and append-only resolution event.
3. Build registry entries from stored source attribution. Parser/table mappings
   that are unambiguous receive a proposed semantic type; their old property
   evidence remains `legacy_unclassified`. Unknown/private adapters and mixed or
   missing attribution remain unclassified. Never reconstruct missing source
   truth from SQL defaults or invent collection completeness.
4. Preserve existing FTS/index/view behavior. Validate registry targets, native-key
   collisions, relationship endpoints/cardinalities, FK integrity, object counts,
   and a byte-preserving value/ID comparison of all legacy tables.
5. Revoke any old sanitization verification because new metadata was written.
   Apply the scoped policy to generated metadata and run final verification
   against the complete v7 artifact before publishing fresh trust evidence.
   Structural migration remains lossless: if sanitization would change a legacy
   value, stop the migration and require a separately selected sanitization/rebuild
   operation rather than silently calling a redacted transformation lossless.
   Originally skipped/unverified inputs must not acquire a verified claim merely
   by migration; preserve their explicit privacy posture or require a separate
   verification operation. Advance the schema marker only with a committed
   successful migration; failure restores the prior file.
6. Keep the original artifact as the rollback path. The v7 application may export
   a legacy projection that excludes new support structures, labeled as such;
   do not offer an untested destructive downgrade or claim old applications can
   open v7. Existing schema-version guards should refuse unknown future versions.

Use a sibling temporary copy plus atomic replacement for the whole migration and
sanitization operation, with the same WAL checkpoint and failure cleanup rules as
fresh builds. Pure transactional DDL is insufficient if later sanitization fails.

The ontology HTTP API is explicitly `/api/v1/ontology/...`; the existing explorer
routes remain a legacy table inspector. API `v1` is independent of schema `v7`.
Python consumers opt into `OntologyQuery`, separate from `IcarusQuery`. Responses
include API version, ontology/adapter-policy version, database schema version,
object address, semantic type/source context, evidence states, and cursor/coverage
metadata. Unsupported versions fail explicitly. Cursor scope includes the database
UUID, source snapshot, filter, and ordering; stale or mismatched cursors are refused.
The loopback capability, allowlists, read-only connection, deadline, and response
caps of the current explorer remain mandatory.

Legacy SQL, CLI commands, and Python helpers are retained without silent result
changes. Document that their names/NULL handling describe legacy behavior, add
deprecation warnings where they imply stronger semantics, and provide replacements
before removal in a separately announced breaking release. Existing physical
table/id GUI links continue to resolve via the registry; a semantic result never
relabels the underlying raw row without showing its source/type mapping.

### Required migration and contract tests

The implementation PR must include fixtures and assertions for each gate:

| Fixture/experiment | Required result |
|---|---|
| Fresh v7 and v2/v3/v4/v5/v6→v7 chains | Equivalent new support DDL/indexes; idempotent migration; all old values and IDs preserved |
| Mixed source versions in `daemons` | AWS principals, systemd units, and launchd jobs get distinct types; ambiguous attribution remains unknown |
| Missing user/profile/default flags | No false root, unsandboxed, or capability finding from missing/defaulted values |
| Duplicate names, paths, architecture slices and redacted native keys | No silent row loss or false identity merge; collision/unknown findings are addressable |
| Duplicate service advertisements in different domains/owners | Separate scoped endpoints; no unproven cross-domain reachability |
| Dangling polymorphic observation or stale registry entry | Verification refuses a consumable semantic artifact |
| Merge/split history and empty retired bags | Original events unchanged; current memberships and historical references remain distinct |
| Fault at each DDL/backfill/sanitize/finalize/replace boundary | Original artifact and trust state preserved; temporary artifacts cleaned; retry deterministic |
| Existing query/diff/STIX/parser-wheel tests against migrated fixtures | Legacy behavior preserved or explicitly version-gated; no implicit read-time migration |
| API contract fixtures and GUI traversal | Direction, type, evidence, unknown/truncated states, paging scope, and provenance match the documented response schema |
| Cross-platform/local-runtime matrix | Same identity encodings and migration results on supported Python/OS combinations; negative path/case tests retained |

Do not count a successful migration or a passing synthetic fixture as validation
of the source semantics or resolver accuracy.

## Independent-corpus evaluation and release gates

The existing `resolver_eval` and [RESOLVER_CALIBRATION.md](RESOLVER_CALIBRATION.md)
measure controlled perturbations, including feature-indistinguishable recompiles
and replacement binaries. Those results are useful regression evidence. They
are not measurements on independently collected host/OS/cloud corpora and do not
establish cross-source precision, recall, or calibrated confidence.

Before promoting a source adapter to production ontology support:

1. Collect at least two independently acquired snapshots per supported source
   family, covering different host/image lineages or provider collections. Keep
   collection provenance, source versions, parser/adapter hashes, acquisition
   limits, and permission/parse failures. A copied dump with edited bytes is a
   controlled test, not an independent collection. Publish only fixtures/metrics
   that the data owner permits; corpus manifests can identify private hashes.
2. Define labeled tasks before tuning: object/type coverage, relationship
   correctness, unknown/absence classification, and cross-version identity.
   Sample positives and hard negatives across names, domains, architectures,
   version drift, missing fields, and conflicting/redacted evidence. An independent
   reviewer adjudicates disagreements; retain an `undetermined` label rather than
   forcing guesses into truth.
3. Split by acquisition/source lineage, not by random rows. Tune policies or
   thresholds only on the development partition. Freeze adapters, rules, thresholds,
   and the precision policy before running the held-out collection. Report every
   excluded/undetermined case and the sampling weights used for aggregate metrics.
4. Report per type and relationship: true positives/false positives/false negatives,
   precision, recall, eligible-source coverage, extraction failure rate, and unknown
   rate, with denominators and confidence intervals. Predeclare the interval
   estimator and account for observations clustered by acquisition/source rather
   than assuming all sampled entity pairs are independent. Measure missing-value handling
   separately; unknowns do not disappear from the coverage denominator. Report
   resolver candidate-generation recall before scoring recall, plus pairwise and
   cluster error measures so transitive false merges cannot hide in an average.
5. Use deterministic schema/type/cardinality/identity tests as hard zero-failure
   gates. For analytic output, the initial proposed promotion floor is a one-sided
   95% lower confidence bound of at least 0.95 precision for every advertised
   relation/type task, not just a pooled score. Report recall and coverage without
   claiming a universal recall threshold; a source-specific minimum must be declared
   before evaluation if product behavior depends on it. Insufficient sample size
   leaves the adapter candidate-tier. Zero observed false positives on a tiny
   fixture never proves the precision floor.
6. Release a result manifest containing corpus independence evidence, policies,
   counts, intervals, failures, representative false-positive/false-negative
   examples, and reproduction commands. A failed gate remains a recorded negative
   result and blocks promotion; lowering the threshold or changing labels after
   seeing held-out results requires a new untouched evaluation collection.

These are proposed promotion criteria, not measurements achieved by this change.
The precision floor is an explicit conservative product choice and may be revised
through review before evaluation, never silently after inspecting results.

## Issue #105 acceptance map

| Requested design outcome | Contract in this document | What still needs implementation or measurement |
|---|---|---|
| Explicit types/source semantics, preserved IDs/provenance | Source-context/type mapping, three separate identities, additive v7 decision | Adapter registry, semantic metadata and object addressing |
| Directed typed relationships with natural identity/cardinality | Directed relation table, structured keys, unknown/collision rules | Projections, evidence emission and cardinality verification |
| Versioned API/schema and lossless migration fixtures | v7 transaction/replacement plan, opt-in API v1, migration/contract test matrix | Migration code, fixtures, API and compatibility checks |
| Facts, missing values and inferred relationships distinguished | Value states, evidence modes, authenticity, explicit query filters | Evidence-aware parser/query/GUI behavior |
| Coverage and false-positive/false-negative evaluation on independent corpora | Acquisition split, labeled tasks, counts/intervals, promotion protocol | Independently collected/held-out corpora and actual results |

## Implementation order and issue completion boundary

1. Review this type/identity/evidence contract and freeze a versioned response
   schema plus representative source fixtures.
2. Implement the additive v7 migration, object registry and source contexts with
   rollback/ID-preservation tests; keep all new APIs opt-in.
3. Add evidence/coverage emission to each supported parser and validate the typed
   relation projections. Unsupported source families remain unclassified.
4. Add OntologyQuery and `/api/v1/ontology` consumers, then adapt the explorer's
   semantic view while retaining its raw-table inspector and security boundaries.
5. Run independent-corpus evaluation and promote adapters individually only after
   their gates pass. Resolver policy changes remain experimental until separately
   validated on the identity tasks.

Issue #105 is a design prerequisite. A reviewed document can satisfy its design
deliverable; it cannot justify claiming that schema v7, typed APIs, evidence-aware
queries, or independent-corpus accuracy have shipped. Implementation and empirical
promotion need their own tracked changes and evidence. Saved investigations,
multi-user permissions, operational pipelines, and cross-application lineage are
separate product increments with their own ownership and trust boundaries.
