# ICARUS

[![CI](https://github.com/Indegosblade/ICARUS-FRAMEWORK/actions/workflows/ci.yml/badge.svg)](https://github.com/Indegosblade/ICARUS-FRAMEWORK/actions/workflows/ci.yml)

ICARUS extracts entities and recorded relationships from filesystem snapshots and
structured logs into a queryable SQLite database. Use it to inspect a source,
compare snapshots, browse provenance, and export supported entities as STIX 2.1.

**Status:** beta, source-available under [PolyForm Noncommercial 1.0.0](LICENSE).
Interfaces may change. Entity resolution is experimental. The current data model
is schema v6; [ontology v7](docs/ONTOLOGY_DESIGN.md) is a design proposal.

```text
source snapshot -> parser -> entities + relationships + provenance
                          -> HYGEIA sanitization + final verification
                          -> SQLite database -> CLI / local explorer / diff / STIX
```

## Get started

Use Python 3.10 or newer, Git, and a Python SQLite build with FTS5. Create and
activate a virtual environment, then install:

```bash
python -m pip install git+https://github.com/Indegosblade/ICARUS-FRAMEWORK.git
icarus build --source /path/to/snapshot --output intel.db
icarus query intel.db --stats
icarus gui intel.db
```

Keep the source immutable during a build or resume. The build selects a parser
from a bounded source sample; use `--parser NAME` if detection is inconclusive.
Run `icarus parser list` for the installed parser inventory.

The explorer opens a read-only, single-user browser interface on `127.0.0.1`.
It shows entity properties, search, provenance, and recorded relationships.
Keep its session URL private and stop the server with Ctrl+C.

See [Getting started](wiki/Getting-Started.md) for Windows and POSIX setup,
sanitization behavior, and a complete first workflow.

## Work with a database

```bash
icarus query intel.db --search "nginx"
icarus query intel.db --sql "SELECT path, size FROM files ORDER BY size DESC LIMIT 20"
icarus diff before.db after.db --output changes.md
icarus diff before.db after.db --stix changes.json
```

The CLI separates read-only `query` from deliberate writes through `exec`.
Guarded writes revoke existing sanitization evidence. A fresh audit is required
before a changed database can be treated as verified again.

Python callers can use the public API:

```python
from pathlib import Path
from icarus import IcarusQuery, create_default_pipeline

pipeline = create_default_pipeline(
    source=Path("snapshot"), output=Path("intel.db"), parser_name="linux"
)
pipeline.run()

with IcarusQuery("intel.db") as query:
    print(query.search("nginx").to_markdown())
```

## Capabilities and boundaries

| Capability | Scope |
| --- | --- |
| Parsers | Windows and Linux filesystems, AWS CloudTrail, iOS/macOS metadata, and generic file formats. Parser tiers describe their declared test status. |
| Search and inspection | FTS5 over files, daemons, and atoms; bounded SQL results; a local read-only explorer. |
| Snapshot comparison | Entity additions, deletions, property and structural changes using supported natural keys. |
| Entity resolution | Experimental cross-source atom scoring and canonical groups, with recorded candidate scores and resolution history. |
| Sanitization | HYGEIA detection/redaction plus a separate ICARUS content-verification pass over supported SQLite carriers. Both use the same carrier catalog. |
| Export | STIX 2.1 mappings for supported entities, observations, and diffs. |

Sanitization success means the configured checks passed; it does not establish
universal detection of private data. An explicit `--skip-hygeia` build remains raw
and is labeled as skipped. Failed or unmarked artifacts require an explicit
consumer override. Audit metadata is mutable database state, not a cryptographic
attestation. Review the [threat model](docs/THREAT_MODEL.md) before sharing data.

Configuration and binary metadata describe declarations, not proven runtime
privilege, reachability, or exploitability. The explorer is a local inspection
tool; it does not provide multi-user authorization or operational workflows.

## Documentation

- [Documentation index](docs/README.md) — guides, references, operating contracts, and historical evidence.
- [CLI reference](wiki/CLI-Reference.md) and [Python API](wiki/Python-API.md).
- [Query reference](wiki/Query-Reference.md) and [schema reference](wiki/Schema-Reference.md).
- [Parser development](about/PARSERS.md) and [architecture](about/ARCHITECTURE.md).
- [GitHub wiki](https://github.com/Indegosblade/ICARUS-FRAMEWORK/wiki).
- [Changelog](CHANGELOG.md), [contributing](CONTRIBUTING.md), and [security reporting](SECURITY.md).

## Development

```bash
git clone https://github.com/Indegosblade/ICARUS-FRAMEWORK.git
cd ICARUS-FRAMEWORK
python -m pip install -e ".[dev]"
```

Run the local checks in [CONTRIBUTING.md](CONTRIBUTING.md) before publishing a
branch. Keep parser extensions and source data private when required; private
parser modules are excluded from public distributions.

## License

[PolyForm Noncommercial 1.0.0](LICENSE) permits use subject to its noncommercial
terms. This is a source-available license, not an OSI-approved open-source license.
