# Getting started

ICARUS builds a local SQLite database from a source snapshot. No database server
is required. Use Python 3.10+, Git (for the application and pinned HYGEIA
dependency), and a Python SQLite build with FTS5 support.

## Install in a virtual environment

Windows PowerShell:

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install git+https://github.com/Indegosblade/ICARUS-FRAMEWORK.git
```

Linux or macOS:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install git+https://github.com/Indegosblade/ICARUS-FRAMEWORK.git
```

The package installs PyYAML, jsonschema, and a commit-pinned HYGEIA dependency.
The current integration uses HYGEIA 3.15.1. Inspect the installed ICARUS version
and available commands:

```bash
python -c "from importlib.metadata import version; print(version('icarus-framework'))"
icarus --help
icarus parser list
```

Installation from the repository follows its default branch. For a reproducible
deployment, install a reviewed commit by appending `@COMMIT_SHA` to the Git URL
and record the resulting environment.

## Build a snapshot

Choose an immutable copy of the source and an output path outside that source:

```bash
icarus build --source /path/to/snapshot --output intel.db --parser linux
```

For a Windows application directory:

```powershell
icarus build --source "C:\Snapshots\MyApp" --output myapp.db --parser windows
```

Omit `--parser` to use bounded auto-detection. If the sample budget is exhausted
or no reliable choice is available, select a parser explicitly. A build extracts
entities, maps relationships, verifies the schema, sanitizes with HYGEIA,
finalizes provenance, and performs final verification before marking completion.

Keep the source unchanged until completion. To resume an interruption, repeat the
same command. Linux and Windows extraction resumes committed batches; other
parsers replay the interrupted phase. See [ingest recovery](../docs/INGEST_RECOVERY.md)
for checkpoint ownership and fresh-build behavior. Keep checkpoint files private.

## Inspect the result

```bash
icarus query intel.db --stats
icarus query intel.db --search "nginx"
icarus gui intel.db
```

The explorer runs on loopback and opens a browser. Use `--no-browser` to print its
session URL, or `--port 8123` to choose a port. The URL grants access to this
session; keep it private. Stop the server with Ctrl+C. See
[local explorer](../docs/ONTOLOGY_EXPLORER.md) for its security and resource limits.

## Compare snapshots

```bash
icarus diff before.db after.db --output changes.md
icarus diff before.db after.db --stix changes.json
```

Keep both databases frozen during comparison. Source databases with uncheckpointed
WAL data are unsuitable for immutable snapshot reads. See [CLI reference](CLI-Reference.md)
for experimental cross-source resolution and explicit write commands.

## Understand sanitization status

Verified means the configured sanitization and final verification checks passed.
It does not guarantee that every form of private information was detected.

- `--skip-hygeia` explicitly creates raw output, recorded as skipped. Consumers
  permit that intentional exception; it is not verified sanitization.
- Failed or unmarked output is refused by guarded consumers unless the user
  explicitly supplies `--allow-unverified` where supported.
- Writable APIs revoke old audit evidence when data changes. Direct external
  SQLite writes are outside that guard.

Read the [threat model](../docs/THREAT_MODEL.md) before exporting or sharing a
database. For older artifacts, follow the version-specific
[source-identity remediation guide](../docs/SOURCE_IDENTITY_PRIVACY.md).

## Next steps

- [CLI reference](CLI-Reference.md) — every command and option.
- [Python API](Python-API.md) — build, query, compare, and mutation boundaries.
- [Query reference](Query-Reference.md) — search and evidence interpretation.
- [Parser ecosystem](Parser-Ecosystem.md) — supported extensions and test gates.
- [Documentation index](../docs/README.md) — operations and architecture.
