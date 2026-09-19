# STIX 2.1 Export

ICARUS maps entities and diffs to STIX 2.1 objects for interoperability with threat intelligence platforms (MISP, OpenCTI, TAXII servers).

## Entity Mapping

| ICARUS Entity | STIX Object | STIX Type |
|--------------|-------------|-----------|
| files | File SCO | `file` |
| binaries | File SCO (with x_icarus_binary extension) | `file` |
| daemons | Infrastructure SDO | `infrastructure` |
| entitlements | Course of Action SDO | `course-of-action` |
| file/binary observations | Observed Data SDO | `observed-data` |
| daemon/entitlement observations | Sighting SRO | `sighting` |

Observation exports automatically include their referenced entity object,
even when `include_tables=["observations"]` is used. A missing or unsupported
target fails the export instead of producing a dangling reference.

## Usage

### CLI

```bash
# Export a diff as STIX 2.1 bundle (both inputs require trusted sanitization)
icarus diff old.db new.db --stix changes.json
```

### Python API

```python
from icarus.integrations.stix_export import export_to_stix, diff_to_stix
from pathlib import Path

# Export all entities from a database
# Default export requires a current verified sanitization audit. A database
# intentionally built with --skip-hygeia retains its documented exception.
bundle = export_to_stix(
    db_path=Path("intel.db"),
    output_path=Path("entities.json"),
    include_tables=["files", "binaries", "daemons"],  # optional filter
)
print(f"Exported {len(bundle['objects'])} STIX objects")

# Export a diff as STIX bundle
bundle = diff_to_stix(
    old_db=Path("v1.db"),
    new_db=Path("v2.db"),
    output_path=Path("diff.json"),
)
```

## Bundle Format

Output is a standard STIX 2.1 bundle:

```json
{
  "type": "bundle",
  "id": "bundle--<deterministic-uuid>",
  "objects": [
    {
      "type": "file",
      "id": "file--<deterministic-uuid>",
      "spec_version": "2.1",
      "name": "example.exe",
      "size": 524288,
      "hashes": {"SHA-256": "abc123..."}
    }
  ]
}
```

Object IDs are deterministic RFC 4122 UUIDv5 identifiers — the same input row
produces the same STIX ID. This makes bundles diffable and deduplicable.

## Diff Export

Diffs export as STIX Note objects:

```json
{
  "type": "note",
  "id": "note--<deterministic-uuid>",
  "spec_version": "2.1",
  "created": "2026-07-18T12:34:56Z",
  "modified": "2026-07-18T12:34:56Z",
  "content": "Added in daemons: new-service",
  "object_refs": ["software--<icarus-uuid>"],
  "x_icarus_diff_category": "addition",
  "x_icarus_diff_table": "daemons"
}
```

Categories: `addition`, `deletion`, `property_change`, and `structural`.

## Custom Extensions

ICARUS-specific data uses `x_icarus_` prefixed properties:

| Extension | On | Contains |
|-----------|------|---------|
| `x_icarus_file_type` | File SCO | Parser-assigned file type |
| `x_icarus_binary` | File SCO | arch, bundle_id |
| `x_icarus_program` | Infrastructure SDO | Executable path |
| `x_icarus_user_name` | Infrastructure SDO | Run-as user |
| `x_icarus_entity_table` | Observed Data / Sighting | Source ontology table |
| `x_icarus_entity_id` | Observed Data / Sighting | Source entity row ID |
| `x_icarus_event_type` | Observed Data / Sighting | Observation event type |
| `x_icarus_diff_category` | Note SDO | Diff category |
| `x_icarus_diff_table` | Note SDO | Source diff table |

Because ICARUS uses custom `x_icarus_*` properties, consumers using the OASIS
Python library should parse with `stix2.parse(bundle, allow_custom=True)`.
