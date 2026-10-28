# ICARUS documentation

ICARUS extracts entities and recorded relationships from source snapshots into
SQLite databases for inspection, comparison, and supported STIX 2.1 exports.
It is beta, source-available software. Entity resolution is experimental; the
current schema is v6. Ontology v7 remains a design proposal.

## Start here

- [Getting started](Getting-Started.md) — installation and a first build.
- [CLI reference](CLI-Reference.md) — commands and options.
- [Python API](Python-API.md) — supported entry points and ownership boundaries.
- [Query reference](Query-Reference.md) — search, SQL, and evidence interpretation.
- [Local explorer](../docs/ONTOLOGY_EXPLORER.md) — read-only browser inspection.

## Reference and operations

- [Schema reference](Schema-Reference.md).
- [Parser ecosystem](Parser-Ecosystem.md).
- [STIX export](STIX-Export.md).
- [Recovery](../docs/INGEST_RECOVERY.md), [artifact privacy](../docs/SOURCE_IDENTITY_PRIVACY.md), and [public writes](../docs/PUBLIC_WRITES.md).
- [Full documentation index](../docs/README.md), including architecture and the threat model.

## Historical results

[Validation results](Validation-Results.md) and the
[production-readiness audit](../docs/PRODUCTION_AUDIT.md) preserve results for
specific snapshots. They are not current test counts or guarantees for other data.
