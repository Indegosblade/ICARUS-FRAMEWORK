"""ICARUS STIX 2.1 Export — transform ICARUS entities to STIX 2.1 bundles."""

import json
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

# This namespace is owned by ICARUS.  Do not change it: identity-policy
# versions, rather than a new namespace, distinguish future formats.
_ICARUS_STIX_NAMESPACE = uuid.UUID("28ad9e40-63a7-4de4-a1f0-20f7f1f3cd10")
_ICARUS_STIX_IDENTITY_POLICY = "icarus-stix-identity-v2"


def _stix_id(prefix: str, seed: str) -> str:
    """Generate a deterministic RFC 4122 STIX identifier."""
    return f"{prefix}--{uuid.uuid5(_ICARUS_STIX_NAMESPACE, f'{prefix}:{seed}')}"


def _stix_timestamp(observed: Optional[str] = None) -> str:
    """Return an RFC 3339 UTC timestamp for a STIX created/modified property.

    Derives the timestamp from ``observed`` (e.g. a row's observed_time /
    observed_at column) when given, normalizing it to end in 'Z' as STIX 2.1
    requires. Falls back to the current export time when no observed
    timestamp is available (observed_time is nullable and often unset).
    """
    if observed:
        raw = observed.strip().replace(" ", "T", 1)
        if raw.endswith("Z"):
            raw = raw[:-1] + "+00:00"
        try:
            parsed = datetime.fromisoformat(raw)
        except ValueError as exc:
            raise ValueError(f"Invalid timestamp for STIX export: {observed!r}") from exc
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        parsed = parsed.astimezone(timezone.utc)
        timespec = "microseconds" if parsed.microsecond else "seconds"
        return parsed.isoformat(timespec=timespec).replace("+00:00", "Z")
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _make_bundle(objects: List[dict]) -> dict:
    return {
        "type": "bundle",
        "id": _stix_id("bundle", json.dumps(objects, sort_keys=True)),
        "objects": objects,
    }


_ENTITY_TABLE_STIX_TYPE = {
    "files": "file",
    "binaries": "file",
    "daemons": "infrastructure",
    "entitlements": "course-of-action",
}

_SCO_ENTITY_TABLES = {"files", "binaries"}


def _canonical_string(value: object) -> str:
    """Preserve a SQLite text value while canonical JSON serializes its structure.

    Paths and other identity attributes are opaque database values: SQLite can
    validly store distinct strings which a filesystem normalizer would merge.
    """
    return str(value)


def _file_identity_attributes(path: object, sha256: object) -> dict:
    attributes = {"path": _canonical_string(path)}
    if sha256:
        attributes["sha256"] = _canonical_string(sha256).strip().lower()
    return attributes


def _binary_identity_attributes(
    file_path: object,
    file_sha256: object,
    bundle_id: object,
    executable_name: object,
    arch: object,
) -> dict:
    """Return the domain identity attributes for a binary."""
    attributes = {
        "file": _file_identity_attributes(file_path, file_sha256),
        "executable_name": _canonical_string(executable_name or ""),
    }
    if bundle_id:
        attributes["bundle_id"] = _canonical_string(bundle_id)
    if arch:
        attributes["arch"] = _canonical_string(arch)
    return attributes


def _entity_identity_attributes(entity_table: str, row: dict) -> dict:
    """Return the v2 stable-domain identity attributes for an exported entity."""
    if entity_table == "files":
        return _file_identity_attributes(row["path"], row.get("sha256"))
    if entity_table == "binaries":
        return _binary_identity_attributes(
            row["_icarus_file_path"],
            row.get("_icarus_file_sha256"),
            row.get("bundle_id"),
            row.get("executable_name"),
            row.get("arch"),
        )
    if entity_table == "daemons":
        return {
            "label": _canonical_string(row["label"]),
            "plist_path": _canonical_string(row["plist_path"]),
        }
    if entity_table == "entitlements":
        return {
            "binary": _binary_identity_attributes(
                row["_icarus_file_path"],
                row.get("_icarus_file_sha256"),
                row.get("_icarus_binary_bundle_id"),
                row.get("_icarus_binary_executable_name"),
                row.get("_icarus_binary_arch"),
            ),
            "key": _canonical_string(row["key"]),
            "value": _canonical_string(row["value"]),
        }
    raise ValueError(f"Unsupported observation entity table for STIX export: {entity_table!r}")


def _entity_ref(entity_table: str, row: dict) -> str:
    """Return a v1 canonical STIX id shared by mappers and references."""
    try:
        stix_type = _ENTITY_TABLE_STIX_TYPE[entity_table]
    except KeyError as exc:
        raise ValueError(
            f"Unsupported observation entity table for STIX export: {entity_table!r}"
        ) from exc
    seed = json.dumps(
        {
            "attributes": _entity_identity_attributes(entity_table, row),
            "entity_table": entity_table,
            "policy": _ICARUS_STIX_IDENTITY_POLICY,
        },
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )
    return _stix_id(stix_type, seed)


def _file_to_sco(row: dict) -> dict:
    """Map a files table row to a STIX file SCO."""
    obj = {
        "type": "file",
        "id": _entity_ref("files", row),
        "spec_version": "2.1",
        "name": row.get("filename", ""),
    }
    if row.get("size"):
        obj["size"] = row["size"]
    if row.get("sha256"):
        obj["hashes"] = {"SHA-256": row["sha256"]}
    if row.get("file_type"):
        obj["x_icarus_file_type"] = row["file_type"]
    return obj


def _binary_to_sco(row: dict) -> dict:
    """Map a binaries table row to a STIX file SCO with extension."""
    obj = {
        "type": "file",
        "id": _entity_ref("binaries", row),
        "spec_version": "2.1",
        "name": row.get("executable_name", ""),
    }
    ext = {}
    if row.get("arch"):
        ext["arch"] = row["arch"]
    if row.get("bundle_id"):
        ext["bundle_id"] = row["bundle_id"]
    if ext:
        obj["x_icarus_binary"] = ext
    return obj


def _daemon_to_sdo(row: dict) -> dict:
    """Map a daemons table row to a STIX infrastructure SDO."""
    ts = _stix_timestamp(row.get("observed_time"))
    return {
        "type": "infrastructure",
        "id": _entity_ref("daemons", row),
        "spec_version": "2.1",
        "created": ts,
        "modified": ts,
        "name": row["label"],
        "infrastructure_types": ["hosting-target"],
        "x_icarus_program": row.get("program", ""),
        "x_icarus_user_name": row.get("user_name", ""),
    }


def _entitlement_to_sdo(row: dict) -> dict:
    """Map an entitlements row to a STIX course-of-action SDO."""
    ts = _stix_timestamp(row.get("observed_time"))
    return {
        "type": "course-of-action",
        "id": _entity_ref("entitlements", row),
        "spec_version": "2.1",
        "created": ts,
        "modified": ts,
        "name": row["key"],
        "description": str(row["value"]),
    }


def _observation_to_sdo(row: dict, entity_ref: str) -> dict:
    """Map an observation to observed-data (SCO) or a Sighting (SDO)."""
    ts = _stix_timestamp(row.get("observed_at"))
    seed = json.dumps(
        {
            "entity_ref": entity_ref,
            "event_type": _canonical_string(row.get("event_type", "")),
            "observed_at": ts,
            "policy": _ICARUS_STIX_IDENTITY_POLICY,
        },
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )
    common = {
        "spec_version": "2.1",
        "created": ts,
        "modified": ts,
        "x_icarus_entity_table": row["entity_table"],
        "x_icarus_event_type": row.get("event_type", ""),
    }
    if row["entity_table"] in _SCO_ENTITY_TABLES:
        return {
            "type": "observed-data",
            "id": _stix_id("observed-data", seed),
            **common,
            "first_observed": ts,
            "last_observed": ts,
            "number_observed": 1,
            "object_refs": [entity_ref],
        }
    return {
        "type": "sighting",
        "id": _stix_id("sighting", seed),
        **common,
        "first_seen": ts,
        "last_seen": ts,
        "count": 1,
        "sighting_of_ref": entity_ref,
    }


_ENTITY_SELECTS = {
    "files": "SELECT files.* FROM files",
    "binaries": """
        SELECT binaries.*, files.path AS _icarus_file_path,
               files.sha256 AS _icarus_file_sha256
        FROM binaries JOIN files ON files.id = binaries.file_id
    """,
    "daemons": "SELECT daemons.* FROM daemons",
    "entitlements": """
        SELECT entitlements.*, files.path AS _icarus_file_path,
               files.sha256 AS _icarus_file_sha256,
               binaries.bundle_id AS _icarus_binary_bundle_id,
               binaries.executable_name AS _icarus_binary_executable_name,
               binaries.arch AS _icarus_binary_arch
        FROM entitlements
        JOIN binaries ON binaries.id = entitlements.binary_id
        JOIN files ON files.id = binaries.file_id
    """,
}

_ENTITY_MAPPERS = {
    "files": _file_to_sco,
    "binaries": _binary_to_sco,
    "daemons": _daemon_to_sdo,
    "entitlements": _entitlement_to_sdo,
}


def _load_observation_target(
    conn: sqlite3.Connection, entity_table: str, entity_id: int
) -> dict:
    """Load and map an observation target, refusing a dangling reference."""
    try:
        query = _ENTITY_SELECTS[entity_table]
        mapper = _ENTITY_MAPPERS[entity_table]
    except KeyError as exc:
        raise ValueError(
            f"Unsupported observation entity table for STIX export: {entity_table!r}"
        ) from exc
    row = conn.execute(f"{query} WHERE {entity_table}.id = ?", (entity_id,)).fetchone()
    if row is None:
        raise ValueError(
            "Observation target does not exist: "
            f"{entity_table}[{entity_id}]"
        )
    return mapper(dict(row))


def _append_unique(objects: List[dict], objects_by_id: dict, obj: dict) -> None:
    """Append once, rejecting two different objects which claim one STIX id."""
    existing = objects_by_id.get(obj["id"])
    if existing is not None:
        if existing != obj:
            raise ValueError(f"Conflicting STIX objects share id {obj['id']}")
        return
    objects_by_id[obj["id"]] = obj
    objects.append(obj)


def export_to_stix(
    db_path: Path,
    output_path: Path,
    include_tables: Optional[List[str]] = None,
) -> dict:
    """Export ICARUS database entities to a STIX 2.1 bundle JSON file."""
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    objects = []
    objects_by_id = {}

    try:
        tables = include_tables or [
            "files", "binaries", "daemons", "entitlements", "observations",
        ]

        if "files" in tables:
            for row in conn.execute(_ENTITY_SELECTS["files"]).fetchall():
                _append_unique(objects, objects_by_id, _file_to_sco(dict(row)))

        if "binaries" in tables:
            try:
                for row in conn.execute(_ENTITY_SELECTS["binaries"]).fetchall():
                    _append_unique(objects, objects_by_id, _binary_to_sco(dict(row)))
            except sqlite3.OperationalError:
                pass

        if "daemons" in tables:
            try:
                for row in conn.execute(_ENTITY_SELECTS["daemons"]).fetchall():
                    _append_unique(objects, objects_by_id, _daemon_to_sdo(dict(row)))
            except sqlite3.OperationalError:
                pass

        if "entitlements" in tables:
            try:
                for row in conn.execute(_ENTITY_SELECTS["entitlements"]).fetchall():
                    _append_unique(objects, objects_by_id, _entitlement_to_sdo(dict(row)))
            except sqlite3.OperationalError:
                pass

        if "observations" in tables:
            try:
                for row in conn.execute("SELECT * FROM observations").fetchall():
                    observation = dict(row)
                    target = _load_observation_target(
                        conn,
                        observation["entity_table"],
                        observation["entity_id"],
                    )
                    target_ref = target["id"]
                    if target_ref not in objects_by_id:
                        _append_unique(objects, objects_by_id, target)
                    _append_unique(
                        objects,
                        objects_by_id,
                        _observation_to_sdo(observation, target_ref),
                    )
            except sqlite3.OperationalError:
                pass
    finally:
        conn.close()

    bundle = _make_bundle(objects)
    output_path.write_text(json.dumps(bundle, indent=2) + "\n")
    return bundle


_ICARUS_SOFTWARE_ID = _stix_id("software", "icarus-framework")


def _diff_note(
    category: str,
    table: str,
    seed_parts: list,
    content: str,
    timestamp: str,
) -> dict:
    """Create a complete STIX Note for one ICARUS diff result."""
    seed = json.dumps([category, table, *seed_parts], separators=(",", ":"))
    return {
        "type": "note",
        "id": _stix_id("note", seed),
        "spec_version": "2.1",
        "created": timestamp,
        "modified": timestamp,
        "content": content,
        "object_refs": [_ICARUS_SOFTWARE_ID],
        "x_icarus_diff_category": category,
        "x_icarus_diff_table": table,
    }


def diff_to_stix(
    old_db: Path, new_db: Path, output_path: Path
) -> dict:
    """Export a diff result as a STIX 2.1 bundle."""
    from icarus.core.differ import IcarusDiffer

    timestamp = _stix_timestamp()
    objects = [{
        "type": "software",
        "id": _ICARUS_SOFTWARE_ID,
        "spec_version": "2.1",
        "name": "ICARUS Framework",
    }]
    objects_by_id = {_ICARUS_SOFTWARE_ID: objects[0]}
    with IcarusDiffer(str(old_db), str(new_db)) as d:
        results = d.full_diff()

        for key, diff_result in results.items():
            key_column = diff_result.key_column

            for item in diff_result.added:
                item_key = item.get(key_column, "?")
                _append_unique(
                    objects,
                    objects_by_id,
                    _diff_note(
                        "addition",
                        key,
                        [item_key],
                        f"Added in {key}: {item_key}",
                        timestamp,
                    ),
                )

            for item in diff_result.removed:
                item_key = item.get(key_column, "?")
                _append_unique(
                    objects,
                    objects_by_id,
                    _diff_note(
                        "deletion",
                        key,
                        [item_key],
                        f"Removed from {key}: {item_key}",
                        timestamp,
                    ),
                )

            for item in diff_result.changed:
                item_key = item.get(key_column, "?")
                old_value = item.get("old_value", "?")
                new_value = item.get("new_value", "?")
                _append_unique(
                    objects,
                    objects_by_id,
                    _diff_note(
                        "property_change",
                        key,
                        [item_key, old_value, new_value],
                        f"Changed in {key}: {item_key} ({old_value} -> {new_value})",
                        timestamp,
                    ),
                )

            for item in diff_result.structural:
                item_key = item.get(key_column, "?")
                change_type = item.get("type", "")
                content = item.get(
                    "description", f"Structural change in {key}: {item_key}"
                )
                _append_unique(
                    objects,
                    objects_by_id,
                    _diff_note(
                        "structural",
                        key,
                        [change_type, item_key, content],
                        content,
                        timestamp,
                    ),
                )

    bundle = _make_bundle(objects)
    output_path.write_text(json.dumps(bundle, indent=2) + "\n")
    return bundle
