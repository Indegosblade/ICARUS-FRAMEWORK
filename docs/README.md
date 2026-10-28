# Documentation

Start with the workflow you need. The current runtime uses schema v6; the proposed
v7 ontology is design work and is not part of the shipped schema.

## Use ICARUS

| Guide | Purpose |
| --- | --- |
| [Getting started](../wiki/Getting-Started.md) | Install, build a snapshot, and inspect it. |
| [CLI reference](../wiki/CLI-Reference.md) | Commands, flags, and admission rules. |
| [Python API](../wiki/Python-API.md) | Public entry points and transaction ownership. |
| [Query reference](../wiki/Query-Reference.md) | Search, SQL, and interpretation of configuration evidence. |
| [Local explorer](ONTOLOGY_EXPLORER.md) | Browser workflow and single-user security boundaries. |
| [STIX export](../wiki/STIX-Export.md) | Supported mappings and export behavior. |

## Operate and recover

- [Ingest recovery](INGEST_RECOVERY.md): immutable sources, checkpoints, leases, and resume behavior.
- [Source identity and legacy remediation](SOURCE_IDENTITY_PRIVACY.md): private recovery material and current artifact policy.
- [SQLite carrier policy](SQLITE_CARRIERS.md): supported text storage and verification limits.
- [Public writes](PUBLIC_WRITES.md): mutation, commit/rollback, and audit invalidation.
- [Threat model](THREAT_MODEL.md): trust boundaries and residual risks.
- [Security reporting](../SECURITY.md): private vulnerability reports.

## Develop and extend

- [Contributing](../CONTRIBUTING.md): environment, local checks, and review workflow.
- [Architecture](../about/ARCHITECTURE.md) and [schema reference](../wiki/Schema-Reference.md).
- [Parser development](../about/PARSERS.md) and [parser ecosystem](../wiki/Parser-Ecosystem.md).
- [Service identity](SERVICE_IDENTITY.md): source declarations and provenance rules.
- [STIX identity](STIX_IDENTITY.md): deterministic identifiers and references.
- [Ontology evolution design](ONTOLOGY_DESIGN.md): proposed v7 model and implementation gates.

## Historical evidence

These documents retain results for specific snapshots and datasets. They are not
a live release checklist or a general claim of production readiness.

- [Production-readiness audit](PRODUCTION_AUDIT.md): original findings and follow-up history.
- [Validation results](../wiki/Validation-Results.md): recorded real-data experiments.
- [Resolver calibration](RESOLVER_CALIBRATION.md): bounded evaluation methodology and results.
- [Changelog](../CHANGELOG.md): release history.

For current changes and checks, use the linked pull requests and their exact
commit revisions in the repository. Passing tests do not replace validation of
your own source formats, privacy policy, and deployment environment.
