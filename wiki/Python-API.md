# Python API

The top-level `icarus` package exports `Pipeline`, `create_default_pipeline`,
`IcarusQuery`, `BaseParser`, and `initialize_database`. Use submodule imports for
the differ, resolver, and STIX integration. The API is beta.

## Build

```python
from pathlib import Path
from icarus import create_default_pipeline

pipeline = create_default_pipeline(
    source=Path("snapshot"),
    output=Path("intel.db"),
    parser_name="linux",
)
context = pipeline.run()
```

The pipeline owns its output lease, checkpoint protocol, phases, and final audit.
Keep the source immutable while building or resuming. A failed build must not be
treated as completed output. See [recovery](../docs/INGEST_RECOVERY.md).

## Read and compare

```python
from icarus import IcarusQuery
from icarus.core.differ import IcarusDiffer

with IcarusQuery("intel.db") as query:
    result = query.execute("SELECT path, size FROM files ORDER BY size DESC LIMIT 20")
    print(result.to_markdown())

with IcarusDiffer("before.db", "after.db") as differ:
    report = differ.generate_report()
```

Context managers close database handles. Query results are bounded to 100 rows
and indicate truncation. Query connections are read-only by default and reject
`ATTACH` and `DETACH`. The Python constructor is a lower-level read API; it does
not reproduce the CLI's artifact-admission checks. Apply the relevant artifact
policy before presenting or exporting data to others.

See [query reference](Query-Reference.md) for semantic helpers. Their output is
configuration and metadata evidence, not proof of effective runtime privilege.

## Deliberate writes

```python
from icarus import IcarusQuery

with IcarusQuery("working-copy.db", writable=True) as query:
    query.execute("UPDATE files SET marking = ? WHERE id = ?", ("SENSITIVE", 1))
    query.commit()
```

Guarded writes and audit invalidation commit together. `rollback()` or closing
without committing discards both. Use `commit()` and `rollback()` methods for
transaction control; direct SQL transaction commands are refused. Raw connection
or cursor writes bypass this contract. See [public writes](../docs/PUBLIC_WRITES.md).

`initialize_database()` initializes or migrates a schema and may mutate its input.
Work on an appropriate copy, and do not use it as a read-only inspection helper.

## Experimental resolution

For cross-source publication, use `icarus resolve` and its documented admission,
temporary-output, sanitization, and publication gates. Direct `EntityResolver`
use requires `experimental=True` and does not replace those orchestration gates.
See [CLI reference](CLI-Reference.md#icarus-resolve) and
[resolver calibration](../docs/RESOLVER_CALIBRATION.md).

## Export

```python
from pathlib import Path
from icarus.integrations.stix_export import export_to_stix

export_to_stix(Path("intel.db"), Path("entities.json"))
```

STIX export applies artifact admission rules. A verified audit and an explicit
skipped-sanitization exception are distinct states. See [STIX export](STIX-Export.md)
for supported mappings and unsafe overrides.
