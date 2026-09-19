"""Tests for Phase 3.6 — STIX 2.1 export."""

import json
import random
import re
import sqlite3
import tempfile
import types
import uuid
from pathlib import Path

import pytest

from icarus import __main__ as cli
from icarus.core.differ import DiffResult, canonical_diff_value
from icarus.core.schema import initialize_database
from icarus.integrations.stix_export import (
    SanitizationTrustError,
    _entity_ref,
    _stix_timestamp,
    diff_to_stix,
    export_to_stix,
)

FIXTURES_DIR = Path(__file__).parent / "fixtures" / "windows"

# RFC 3339 UTC timestamp ending in 'Z', as STIX 2.1 requires for created/modified.
TIMESTAMP_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$")

def _build_db():
    """Build a small ICARUS database from windows fixtures for STIX testing."""
    from icarus.parsers.windows import WindowsParser

    db_path = Path(tempfile.mktemp(suffix=".db"))
    initialize_database(db_path, {"source": "test"})
    WindowsParser().extract_entities(FIXTURES_DIR, db_path)
    conn = sqlite3.connect(str(db_path))
    conn.execute(
        "INSERT OR IGNORE INTO daemons (label, plist_path, program, user_name) "
        "VALUES (?, ?, ?, ?)",
        ("test-daemon", "/Library/LaunchDaemons/test.plist", "/usr/bin/testd", "root"),
    )
    from icarus.integrations import hygeia as hygeia_mod

    engine = {
        "engine": hygeia_mod.ENGINE_NAME,
        "version": hygeia_mod._HYGEIA_VERSION,
        "mode": "fail-closed",
    }
    audit = {
        "audit_version": hygeia_mod.AUDIT_VERSION,
        "engine": engine,
        "verified": True,
        "gate": hygeia_mod.FINAL_GATE_NAME,
        "post_gate": {"passed": True, "total_findings": 0},
        "checked_rows": 0,
        "total_findings": 0,
        "patterns_found": {},
        "findings": [],
        "findings_truncated": False,
    }
    conn.executemany(
        "INSERT OR REPLACE INTO metadata (key, value) VALUES (?, ?)",
        [
            ("hygeia_status", "verified"),
            ("hygeia_engine", json.dumps(engine, sort_keys=True)),
            ("hygeia_audit", json.dumps(audit, sort_keys=True)),
        ],
    )
    conn.commit()
    conn.close()
    return db_path


def _source_bytes(db):
    return {
        suffix: (Path(str(db) + suffix).read_bytes() if Path(str(db) + suffix).exists() else None)
        for suffix in ("", "-wal", "-shm")
    }


@pytest.mark.parametrize(
    ("state", "permitted"),
    [("verified", True), ("skipped", True), ("failed", False), ("unknown", False)],
)
def test_stix_export_enforces_sanitization_trust_without_mutating_source(
    tmp_path, state, permitted
):
    from icarus.integrations.hygeia import mark_sanitization_failed

    db = _build_db()
    out = tmp_path / f"{state}.json"
    try:
        conn = sqlite3.connect(str(db))
        if state == "skipped":
            conn.execute("DELETE FROM metadata WHERE key LIKE 'hygeia_%'")
            conn.execute("INSERT INTO metadata VALUES ('hygeia_skipped', 'true')")
        elif state == "unknown":
            conn.execute("DELETE FROM metadata WHERE key LIKE 'hygeia_%'")
        conn.commit()
        conn.close()
        if state == "failed":
            mark_sanitization_failed(db)

        before = _source_bytes(db)
        if permitted:
            assert export_to_stix(db, out)["type"] == "bundle"
            assert out.exists()
        else:
            with pytest.raises(SanitizationTrustError, match="allow_unverified=True"):
                export_to_stix(db, out)
            assert not out.exists()
        assert _source_bytes(db) == before
    finally:
        db.unlink(missing_ok=True)
        out.unlink(missing_ok=True)


def test_stix_failed_canary_requires_explicit_unsafe_override(tmp_path):
    from icarus.integrations.hygeia import mark_sanitization_failed

    db = _build_db()
    out = tmp_path / "canary.json"
    canary = "Bearer AAAAAAAAAAAAAAAAAAAAAAAA"
    try:
        conn = sqlite3.connect(str(db))
        binary_id = conn.execute("SELECT id FROM binaries LIMIT 1").fetchone()[0]
        conn.execute(
            "INSERT INTO entitlements (binary_id, key, value) VALUES (?, ?, ?)",
            (binary_id, "canary", canary),
        )
        conn.commit()
        conn.close()
        mark_sanitization_failed(db)

        before = _source_bytes(db)
        with pytest.raises(SanitizationTrustError):
            export_to_stix(db, out, include_tables=["entitlements"])
        assert not out.exists()
        assert _source_bytes(db) == before

        bundle = export_to_stix(
            db, out, include_tables=["entitlements"], allow_unverified=True
        )
        assert canary in json.dumps(bundle)
        assert _source_bytes(db) == before
    finally:
        db.unlink(missing_ok=True)
        out.unlink(missing_ok=True)


@pytest.mark.parametrize("untrusted_side", ("old", "new"))
def test_stix_diff_requires_trusted_inputs_or_unsafe_override(tmp_path, untrusted_side):
    from icarus.integrations.hygeia import mark_sanitization_failed

    old = _build_db()
    new = _build_db()
    out = tmp_path / f"{untrusted_side}.json"
    try:
        mark_sanitization_failed(old if untrusted_side == "old" else new)
        with pytest.raises(SanitizationTrustError, match="allow_unverified=True"):
            diff_to_stix(old, new, out)
        assert not out.exists()
        assert diff_to_stix(old, new, out, allow_unverified=True)["type"] == "bundle"
    finally:
        old.unlink(missing_ok=True)
        new.unlink(missing_ok=True)
        out.unlink(missing_ok=True)


def test_cli_stix_diff_requires_explicit_unsafe_override(tmp_path, capsys):
    from icarus.integrations.hygeia import mark_sanitization_failed

    old = _build_db()
    new = _build_db()
    out = tmp_path / "cli.json"
    try:
        mark_sanitization_failed(old)
        args = types.SimpleNamespace(old=str(old), new=str(new), stix=str(out))
        with pytest.raises(SystemExit) as exc:
            cli.cmd_diff(args)
        assert exc.value.code == 3
        assert "allow_unverified=True" in capsys.readouterr().err
        assert not out.exists()

        args.allow_unverified = True
        cli.cmd_diff(args)
        assert out.exists()
    finally:
        old.unlink(missing_ok=True)
        new.unlink(missing_ok=True)
        out.unlink(missing_ok=True)


def test_stix_export_rejects_active_wal_without_sidecar_changes(tmp_path):
    from icarus.core.schema import open_db

    db = _build_db()
    out = tmp_path / "wal.json"
    writer = open_db(db)
    try:
        writer.execute("INSERT INTO files (path, filename) VALUES ('/wal', 'wal')")
        writer.commit()
        assert Path(str(db) + "-wal").stat().st_size > 0
        before = _source_bytes(db)
        with pytest.raises(SanitizationTrustError, match="active WAL"):
            export_to_stix(db, out)
        assert not out.exists()
        assert _source_bytes(db) == before
    finally:
        writer.close()
        db.unlink(missing_ok=True)
        out.unlink(missing_ok=True)
def _build_identity_fixture(
    db_path: Path,
    *,
    insertion_seed: int,
    filler_count: int,
    target_path: str = "/same/target.bin",
    target_sha256: str = "a" * 64,
) -> None:
    """Build equivalent rows while randomizing every table's insertion order."""
    initialize_database(db_path, {"source": "identity-test"})
    conn = sqlite3.connect(str(db_path))
    entities = ["target", *(f"filler-{index}" for index in range(filler_count))]
    randomizer = random.Random(insertion_seed)

    def shuffled():
        result = list(entities)
        randomizer.shuffle(result)
        return result

    file_ids = {}
    for entity in shuffled():
        is_target = entity == "target"
        cursor = conn.execute(
            "INSERT INTO files (path, filename, sha256, file_type, observed_time) "
            "VALUES (?, ?, ?, ?, ?)",
            (
                target_path if is_target else f"/unrelated/{entity}.bin",
                "target.bin" if is_target else f"{entity}.bin",
                target_sha256 if is_target else "b" * 64,
                "binary",
                "2026-07-18T12:34:56Z",
            ),
        )
        file_ids[entity] = cursor.lastrowid

    binary_ids = {}
    for entity in shuffled():
        cursor = conn.execute(
            "INSERT INTO binaries "
            "(file_id, bundle_id, executable_name, arch, observed_time) "
            "VALUES (?, ?, ?, ?, ?)",
            (
                file_ids[entity],
                f"com.example.{entity}",
                f"{entity}.bin",
                "arm64",
                "2026-07-18T12:34:56Z",
            ),
        )
        binary_ids[entity] = cursor.lastrowid

    daemon_ids = {}
    for entity in shuffled():
        cursor = conn.execute(
            "INSERT INTO daemons (label, plist_path, program, observed_time) "
            "VALUES (?, ?, ?, ?)",
            (
                f"com.example.{entity}",
                f"/Library/LaunchDaemons/{entity}.plist",
                f"/usr/bin/{entity}",
                "2026-07-18T12:34:56Z",
            ),
        )
        daemon_ids[entity] = cursor.lastrowid

    entitlement_ids = {}
    for entity in shuffled():
        cursor = conn.execute(
            "INSERT INTO entitlements (binary_id, key, value, observed_time) "
            "VALUES (?, ?, ?, ?)",
            (
                binary_ids[entity],
                f"com.example.{entity}",
                "true",
                "2026-07-18T12:34:56Z",
            ),
        )
        entitlement_ids[entity] = cursor.lastrowid

    observations = [
        ("files", file_ids["target"], "target-file-seen"),
        ("binaries", binary_ids["target"], "target-binary-seen"),
        ("daemons", daemon_ids["target"], "target-daemon-seen"),
        ("entitlements", entitlement_ids["target"], "target-entitlement-seen"),
    ]
    observations.extend(
        ("files", file_ids[entity], f"{entity}-seen")
        for entity in entities if entity != "target"
    )
    randomizer.shuffle(observations)
    for entity_table, entity_id, event_type in observations:
        conn.execute(
            "INSERT INTO observations (entity_table, entity_id, observed_at, event_type) "
            "VALUES (?, ?, ?, ?)",
            (entity_table, entity_id, "2026-07-18T12:34:56Z", event_type),
        )
    conn.commit()
    conn.close()


def _target_stix_ids(bundle: dict) -> dict:
    """Return target IDs by semantic marker, independent of database row IDs."""
    ids = {}
    for obj in bundle["objects"]:
        if obj["type"] == "file" and obj.get("hashes", {}).get("SHA-256", "").lower() == "a" * 64:
            ids["file"] = obj["id"]
        elif (
            obj["type"] == "file"
            and obj.get("x_icarus_binary", {}).get("bundle_id") == "com.example.target"
        ):
            ids["binary"] = obj["id"]
        elif obj["type"] == "infrastructure" and obj["name"] == "com.example.target":
            ids["daemon"] = obj["id"]
        elif obj["type"] == "course-of-action" and obj["name"] == "com.example.target":
            ids["entitlement"] = obj["id"]
        elif obj.get("x_icarus_event_type", "").startswith("target-"):
            ids[obj["x_icarus_event_type"]] = obj["id"]
    return ids


def test_stix_identity_is_stable_across_randomized_rebuild_order_and_unrelated_rows(tmp_path):
    """#90: stable IDs and refs survive deterministic randomized row-ID permutations."""
    baseline_db = tmp_path / "baseline.db"
    _build_identity_fixture(baseline_db, insertion_seed=0, filler_count=0)
    baseline = export_to_stix(
        baseline_db, tmp_path / "baseline.json", allow_unverified=True
    )
    baseline_ids = _target_stix_ids(baseline)

    for seed in range(1, 17):
        variant_db = tmp_path / f"variant-{seed}.db"
        _build_identity_fixture(
            variant_db,
            insertion_seed=seed,
            filler_count=seed % 5 + 1,
            target_sha256="A" * 64,
        )
        variant = export_to_stix(
            variant_db,
            tmp_path / f"variant-{seed}.json",
            allow_unverified=True,
        )
        variant_ids = _target_stix_ids(variant)
        assert variant_ids == baseline_ids

        objects = {obj["id"]: obj for obj in variant["objects"]}
        assert objects[variant_ids["target-file-seen"]]["object_refs"] == [variant_ids["file"]]
        assert objects[variant_ids["target-binary-seen"]]["object_refs"] == [variant_ids["binary"]]
        assert (
            objects[variant_ids["target-daemon-seen"]]["sighting_of_ref"]
            == variant_ids["daemon"]
        )
        assert (
            objects[variant_ids["target-entitlement-seen"]]["sighting_of_ref"]
            == variant_ids["entitlement"]
        )


def test_stix_identity_changes_when_a_material_domain_attribute_changes(tmp_path):
    original_db = tmp_path / "original.db"
    changed_db = tmp_path / "changed.db"
    _build_identity_fixture(original_db, insertion_seed=0, filler_count=0)
    _build_identity_fixture(
        changed_db,
        insertion_seed=1,
        filler_count=2,
        target_path="/same/renamed-target.bin",
    )

    original_ids = _target_stix_ids(
        export_to_stix(original_db, tmp_path / "original.json", allow_unverified=True)
    )
    changed_ids = _target_stix_ids(
        export_to_stix(changed_db, tmp_path / "changed.json", allow_unverified=True)
    )
    for key in ("file", "binary", "entitlement", "target-file-seen", "target-binary-seen"):
        assert changed_ids[key] != original_ids[key]


def test_stix_preserves_distinct_raw_paths_without_hashes(tmp_path):
    """Path normalization must not collapse valid, differently-valued rows."""
    db = tmp_path / "paths.db"
    initialize_database(db)
    conn = sqlite3.connect(str(db))
    try:
        conn.executemany(
            "INSERT INTO files (path, filename, size, file_type) VALUES (?, ?, ?, ?)",
            [
                ("/tmp/../same", "same", 1, "data"),
                ("/same", "same", 2, "data"),
            ],
        )
        conn.commit()
    finally:
        conn.close()

    bundle = export_to_stix(
        db,
        tmp_path / "paths.json",
        include_tables=["files"],
        allow_unverified=True,
    )
    files = [obj for obj in bundle["objects"] if obj["type"] == "file"]
    assert {obj["size"] for obj in files} == {1, 2}
    assert len({obj["id"] for obj in files}) == 2


def test_stix_entitlement_values_have_distinct_ids_and_observation_references(tmp_path):
    """A schema-valid same-key entitlement pair must not collide in STIX."""
    db = tmp_path / "entitlements.db"
    initialize_database(db)
    conn = sqlite3.connect(str(db))
    try:
        file_id = conn.execute(
            "INSERT INTO files (path, filename) VALUES (?, ?)",
            ("/same/tool", "tool"),
        ).lastrowid
        binary_id = conn.execute(
            "INSERT INTO binaries (file_id, executable_name) VALUES (?, ?)",
            (file_id, "tool"),
        ).lastrowid
        entitlement_ids = []
        for value in ("true", "false"):
            entitlement_ids.append(
                conn.execute(
                    "INSERT INTO entitlements (binary_id, key, value, observed_time) "
                    "VALUES (?, ?, ?, ?)",
                    (binary_id, "com.example.flag", value, "2026-07-18T12:34:56Z"),
                ).lastrowid
            )
        for entitlement_id in entitlement_ids:
            conn.execute(
                "INSERT INTO observations (entity_table, entity_id, observed_at, event_type) "
                "VALUES (?, ?, ?, ?)",
                ("entitlements", entitlement_id, "2026-07-18T12:34:56Z", "entitlement-seen"),
            )
        conn.commit()
    finally:
        conn.close()

    bundle = export_to_stix(
        db,
        tmp_path / "entitlements.json",
        include_tables=["observations"],
        allow_unverified=True,
    )
    entitlements = [obj for obj in bundle["objects"] if obj["type"] == "course-of-action"]
    sightings = [obj for obj in bundle["objects"] if obj["type"] == "sighting"]
    assert {obj["description"] for obj in entitlements} == {"true", "false"}
    assert len({obj["id"] for obj in entitlements}) == 2
    assert {obj["sighting_of_ref"] for obj in sightings} == {obj["id"] for obj in entitlements}


def test_stix_export_produces_bundle():
    db = _build_db()
    out = Path(tempfile.mktemp(suffix=".json"))
    try:
        bundle = export_to_stix(db, out)
        assert bundle["type"] == "bundle"
        assert bundle["id"].startswith("bundle--")
        assert len(bundle["objects"]) > 0
        on_disk = json.loads(out.read_text())
        assert on_disk["type"] == "bundle"
        assert on_disk["objects"] == bundle["objects"]
    finally:
        db.unlink(missing_ok=True)
        out.unlink(missing_ok=True)


def test_stix_files_map_to_sco():
    db = _build_db()
    out = Path(tempfile.mktemp(suffix=".json"))
    try:
        bundle = export_to_stix(db, out, include_tables=["files"])
        file_objects = [o for o in bundle["objects"] if o["type"] == "file"]
        assert len(file_objects) > 0
        for obj in file_objects:
            assert obj["id"].startswith("file--")
            assert obj["spec_version"] == "2.1"
            assert "name" in obj
    finally:
        db.unlink(missing_ok=True)
        out.unlink(missing_ok=True)


def test_stix_daemons_map_to_infrastructure():
    db = _build_db()
    out = Path(tempfile.mktemp(suffix=".json"))
    try:
        bundle = export_to_stix(db, out, include_tables=["daemons"])
        infra = [o for o in bundle["objects"] if o["type"] == "infrastructure"]
        assert len(infra) == 1
        assert infra[0]["name"] == "test-daemon"
        assert infra[0]["id"].startswith("infrastructure--")
        assert infra[0]["spec_version"] == "2.1"
        assert "hosting-target" in infra[0]["infrastructure_types"]
    finally:
        db.unlink(missing_ok=True)
        out.unlink(missing_ok=True)


def test_stix_diff_export():
    db_old = _build_db()
    db_new = _build_db()
    conn = sqlite3.connect(str(db_new))
    conn.execute(
        "INSERT OR IGNORE INTO daemons (label, plist_path, program, user_name) "
        "VALUES (?, ?, ?, ?)",
        ("new-daemon", "/Library/LaunchDaemons/new.plist", "/usr/bin/newd", "nobody"),
    )
    conn.commit()
    conn.close()
    out = Path(tempfile.mktemp(suffix=".json"))
    try:
        bundle = diff_to_stix(db_old, db_new, out)
        assert bundle["type"] == "bundle"
        assert bundle["id"].startswith("bundle--")
        on_disk = json.loads(out.read_text())
        assert on_disk["type"] == "bundle"

        # Finding #58/#163: the bundle must contain a real note object for
        # the added daemon (not just an envelope with no content).
        notes = [o for o in bundle["objects"] if o["type"] == "note"]
        assert notes, "diff_to_stix produced no note objects for an added daemon"

        added_daemon_notes = [
            n for n in notes
            if n.get("x_icarus_diff_category") == "addition"
            and n.get("x_icarus_diff_table") == "daemons_added"
        ]
        assert len(added_daemon_notes) == 1
        assert "new-daemon" in added_daemon_notes[0]["content"]
        # item must be indexed by key_column (label), not the stringified dict.
        assert "{" not in added_daemon_notes[0]["content"]
    finally:
        db_old.unlink(missing_ok=True)
        db_new.unlink(missing_ok=True)
        out.unlink(missing_ok=True)


def test_stix_diff_change_notes_preserve_the_changed_fields_contract(
    monkeypatch, tmp_path,
):
    """Every current changed category exports the differ's actual values."""
    results = {
        "files_changed": DiffResult(
            added=[], removed=[], table="files", key_column="path",
            changed=[{
                "path": "/same", "changed_fields": ["sha256"],
                "old_sha256": "aaaa", "new_sha256": "bbbb",
            }],
        ),
        "observations": DiffResult(
            added=[], removed=[], table="observations", key_column="entity_key",
            changed=[{
                "entity_key": "/subject",
                "changed_fields": ["properties", "observer"],
                "old_properties": {"decision": False, "items": [None, "old"]},
                "new_properties": {"decision": True, "items": [None, "new"]},
                "old_observer": None,
                "new_observer": "sensor-a",
            }],
        ),
        "resolution": DiffResult(
            added=[], removed=[], table="bags", key_column="canonical_key",
            changed=[{
                "canonical_key": "bag.common",
                "changed_fields": ["atom_count", "score"],
                "old_atom_count": 2, "new_atom_count": 3,
                "old_score": 0.1, "new_score": 0.9,
            }],
        ),
        "structural": DiffResult(
            added=[], removed=[], changed=[], table="cross_table", key_column="entity",
            structural=[{
                "type": "binary_file_moved", "entity": "tool",
                "changed_fields": ["file_path"],
                "old_file_path": "/old/tool", "new_file_path": "/new/tool",
            }],
        ),
    }

    class FakeDiffer:
        def __init__(self, *_args):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def full_diff(self):
            return results

    monkeypatch.setattr("icarus.core.differ.IcarusDiffer", FakeDiffer)
    bundle = diff_to_stix(
        tmp_path / "old.db",
        tmp_path / "new.db",
        tmp_path / "diff.json",
        allow_unverified=True,
    )
    notes = {
        (note["x_icarus_diff_category"], note["x_icarus_diff_table"]): note
        for note in bundle["objects"] if note["type"] == "note"
    }
    expected = {
        ("property_change", "files_changed"): [{
            "field": "sha256", "old_value": "aaaa", "new_value": "bbbb",
        }],
        ("property_change", "observations"): [{
            "field": "properties",
            "old_value": {"decision": False, "items": [None, "old"]},
            "new_value": {"decision": True, "items": [None, "new"]},
        }, {
            "field": "observer", "old_value": None, "new_value": "sensor-a",
        }],
        ("property_change", "resolution"): [
            {"field": "atom_count", "old_value": 2, "new_value": 3},
            {"field": "score", "old_value": 0.1, "new_value": 0.9},
        ],
        ("structural", "structural"): [{
            "field": "file_path", "old_value": "/old/tool", "new_value": "/new/tool",
        }],
    }
    assert set(notes) == set(expected)
    for key, changed_fields in expected.items():
        note = notes[key]
        assert note["x_icarus_diff_changed_fields"] == changed_fields
        assert "? -> ?" not in note["content"]
        for field in changed_fields:
            assert f"{field['field']}:" in note["content"]
            assert canonical_diff_value(field["old_value"]) in note["content"]
            assert canonical_diff_value(field["new_value"]) in note["content"]


def test_stix_diff_rejects_a_change_without_structured_fields(monkeypatch, tmp_path):
    class FakeDiffer:
        def __init__(self, *_args):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def full_diff(self):
            return {
                "files_changed": DiffResult(
                    added=[], removed=[], table="files", key_column="path",
                    changed=[{"path": "/same", "old_value": "old", "new_value": "new"}],
                ),
            }

    monkeypatch.setattr("icarus.core.differ.IcarusDiffer", FakeDiffer)
    with pytest.raises(ValueError, match="changed_fields"):
        diff_to_stix(
            tmp_path / "old.db",
            tmp_path / "new.db",
            tmp_path / "diff.json",
            allow_unverified=True,
        )


def test_stix_diff_export_includes_structural_change():
    """Finding #58/#163: diff_to_stix must not silently drop structural changes."""
    db_old = _build_db()
    db_new = _build_db()

    # Give the same (unique) executable_name a different owning file_id in
    # old vs. new — this is exactly what IcarusDiffer.structural_diff()'s
    # binary_file_moved case detects.
    conn_old = sqlite3.connect(str(db_old))
    conn_old.execute(
        "INSERT INTO files (path, filename, extension, size, file_type) "
        "VALUES (?, ?, ?, ?, ?)",
        ("/synthetic/old/_filler.bin", "_filler.bin", ".bin", 1, "data"),
    )
    conn_old.execute(
        "INSERT INTO files (path, filename, extension, size, file_type) "
        "VALUES (?, ?, ?, ?, ?)",
        ("/synthetic/old/zzz_structural_probe.exe", "zzz_structural_probe.exe",
         ".exe", 10, "binary"),
    )
    old_file_id = conn_old.execute(
        "SELECT id FROM files WHERE path=?",
        ("/synthetic/old/zzz_structural_probe.exe",),
    ).fetchone()[0]
    conn_old.execute(
        "INSERT INTO binaries (file_id, executable_name, arch) VALUES (?, ?, ?)",
        (old_file_id, "zzz_structural_probe.exe", "x86_64"),
    )
    conn_old.commit()
    conn_old.close()

    conn_new = sqlite3.connect(str(db_new))
    conn_new.execute(
        "INSERT INTO files (path, filename, extension, size, file_type) "
        "VALUES (?, ?, ?, ?, ?)",
        ("/synthetic/new/zzz_structural_probe.exe", "zzz_structural_probe.exe",
         ".exe", 10, "binary"),
    )
    new_file_id = conn_new.execute(
        "SELECT id FROM files WHERE path=?",
        ("/synthetic/new/zzz_structural_probe.exe",),
    ).fetchone()[0]
    conn_new.execute(
        "INSERT INTO binaries (file_id, executable_name, arch) VALUES (?, ?, ?)",
        (new_file_id, "zzz_structural_probe.exe", "x86_64"),
    )
    conn_new.commit()
    conn_new.close()

    assert old_file_id != new_file_id, "test setup must give the binary distinct file_ids"

    out = Path(tempfile.mktemp(suffix=".json"))
    try:
        bundle = diff_to_stix(db_old, db_new, out)
        structural_notes = [
            o for o in bundle["objects"]
            if o["type"] == "note" and o.get("x_icarus_diff_category") == "structural"
        ]
        assert len(structural_notes) == 1
        assert "zzz_structural_probe.exe" in structural_notes[0]["content"]
        assert structural_notes[0]["x_icarus_diff_table"] == "structural"
        assert structural_notes[0]["x_icarus_diff_changed_fields"] == [{
            "field": "file_path",
            "old_value": "/synthetic/old/zzz_structural_probe.exe",
            "new_value": "/synthetic/new/zzz_structural_probe.exe",
        }]
    finally:
        db_old.unlink(missing_ok=True)
        db_new.unlink(missing_ok=True)
        out.unlink(missing_ok=True)


def test_stix_objects_have_spec_version_but_bundle_does_not():
    db = _build_db()
    out = Path(tempfile.mktemp(suffix=".json"))
    try:
        bundle = export_to_stix(db, out)
        # A Bundle is an envelope rather than a STIX Object and therefore
        # does not carry the common spec_version property.
        assert "spec_version" not in bundle
        for obj in bundle["objects"]:
            assert obj["spec_version"] == "2.1"
    finally:
        db.unlink(missing_ok=True)
        out.unlink(missing_ok=True)


def test_stix_daemon_sdo_has_created_and_modified():
    """Finding #53: STIX 2.1 requires created/modified on every SDO."""
    db = _build_db()
    out = Path(tempfile.mktemp(suffix=".json"))
    try:
        bundle = export_to_stix(db, out, include_tables=["daemons"])
        infra = [o for o in bundle["objects"] if o["type"] == "infrastructure"]
        assert len(infra) == 1
        assert TIMESTAMP_RE.match(infra[0].get("created", "")), infra[0].get("created")
        assert TIMESTAMP_RE.match(infra[0].get("modified", "")), infra[0].get("modified")
    finally:
        db.unlink(missing_ok=True)
        out.unlink(missing_ok=True)


def test_stix_entitlement_sdo_has_created_and_modified():
    """Finding #53: STIX 2.1 requires created/modified on every SDO."""
    db = _build_db()
    out = Path(tempfile.mktemp(suffix=".json"))
    try:
        conn = sqlite3.connect(str(db))
        binary_id = conn.execute("SELECT id FROM binaries LIMIT 1").fetchone()[0]
        conn.execute(
            "INSERT INTO entitlements (binary_id, key, value) VALUES (?, ?, ?)",
            (binary_id, "com.apple.security.test", "true"),
        )
        conn.commit()
        conn.close()

        bundle = export_to_stix(db, out, include_tables=["entitlements"])
        coa = [o for o in bundle["objects"] if o["type"] == "course-of-action"]
        assert len(coa) == 1
        assert TIMESTAMP_RE.match(coa[0].get("created", "")), coa[0].get("created")
        assert TIMESTAMP_RE.match(coa[0].get("modified", "")), coa[0].get("modified")
    finally:
        db.unlink(missing_ok=True)
        out.unlink(missing_ok=True)


def test_stix_daemon_observation_becomes_sighting_with_resolved_ref():
    """An SDO observation is a Sighting, not observed-data over an SDO ref."""
    db = _build_db()
    out = Path(tempfile.mktemp(suffix=".json"))
    try:
        conn = sqlite3.connect(str(db))
        daemon_id = conn.execute(
            "SELECT id FROM daemons WHERE label=?", ("test-daemon",)
        ).fetchone()[0]
        conn.execute(
            "INSERT INTO observations "
            "(entity_table, entity_id, observed_at, event_type) "
            "VALUES (?, ?, datetime('now'), ?)",
            ("daemons", daemon_id, "daemon_registered"),
        )
        conn.commit()
        conn.close()

        bundle = export_to_stix(db, out, include_tables=["observations"])
        sightings = [o for o in bundle["objects"] if o["type"] == "sighting"]
        assert len(sightings) == 1
        obj = sightings[0]

        assert TIMESTAMP_RE.match(obj.get("created", "")), obj.get("created")
        assert TIMESTAMP_RE.match(obj.get("modified", "")), obj.get("modified")
        assert TIMESTAMP_RE.match(obj.get("first_seen", "")), obj.get("first_seen")
        assert TIMESTAMP_RE.match(obj.get("last_seen", "")), obj.get("last_seen")
        daemon = next(o for o in bundle["objects"] if o["type"] == "infrastructure")
        assert obj["sighting_of_ref"] == daemon["id"]
        assert obj["sighting_of_ref"] in {o["id"] for o in bundle["objects"]}
    finally:
        db.unlink(missing_ok=True)
        out.unlink(missing_ok=True)


def _strict_parse(bundle):
    stix2 = pytest.importorskip("stix2")
    return stix2.parse(json.dumps(bundle), allow_custom=True)


def test_entity_bundle_passes_strict_parser_and_graph_checks():
    """#21: strict parsing, unique ids, resolved refs, and both ref models."""
    db = _build_db()
    out = Path(tempfile.mktemp(suffix=".json"))
    try:
        conn = sqlite3.connect(str(db))
        file_id = conn.execute("SELECT id FROM files ORDER BY id LIMIT 1").fetchone()[0]
        daemon_id = conn.execute(
            "SELECT id FROM daemons WHERE label = ?", ("test-daemon",)
        ).fetchone()[0]
        binary_ids = [
            row[0]
            for row in conn.execute("SELECT id FROM binaries ORDER BY id LIMIT 2").fetchall()
        ]
        if len(binary_ids) < 2:
            cursor = conn.execute(
                "INSERT INTO files (path, filename, file_type) VALUES (?, ?, ?)",
                ("/strict/second.bin", "second.bin", "binary"),
            )
            cursor = conn.execute(
                "INSERT INTO binaries (file_id, executable_name) VALUES (?, ?)",
                (cursor.lastrowid, "second.bin"),
            )
            binary_ids.append(cursor.lastrowid)

        for binary_id in binary_ids[:2]:
            conn.execute(
                "INSERT INTO entitlements (binary_id, key, value) VALUES (?, ?, ?)",
                (binary_id, "com.apple.private.same", "true"),
            )

        observed_at = "2026-07-18 12:34:56"
        conn.execute(
            "INSERT INTO observations "
            "(entity_table, entity_id, observed_at, event_type) VALUES (?, ?, ?, ?)",
            ("files", file_id, observed_at, "file_seen"),
        )
        for event_type in ("daemon_registered", "daemon_modified"):
            conn.execute(
                "INSERT INTO observations "
                "(entity_table, entity_id, observed_at, event_type) VALUES (?, ?, ?, ?)",
                ("daemons", daemon_id, observed_at, event_type),
            )
        conn.commit()
        conn.close()

        bundle = export_to_stix(db, out)
        _strict_parse(bundle)

        objects = bundle["objects"]
        object_ids = [obj["id"] for obj in objects]
        assert len(object_ids) == len(set(object_ids))
        known_ids = set(object_ids)

        for stix_id in [bundle["id"], *object_ids]:
            _, uuid_text = stix_id.split("--", 1)
            assert uuid.UUID(uuid_text).variant == uuid.RFC_4122

        observed_data = [obj for obj in objects if obj["type"] == "observed-data"]
        sightings = [obj for obj in objects if obj["type"] == "sighting"]
        assert len(observed_data) == 1
        assert len(sightings) == 2
        assert all(ref in known_ids for obj in observed_data for ref in obj["object_refs"])
        assert all(obj["sighting_of_ref"] in known_ids for obj in sightings)
        assert all(TIMESTAMP_RE.match(obj["first_observed"]) for obj in observed_data)
        assert all(TIMESTAMP_RE.match(obj["first_seen"]) for obj in sightings)

        entitlement_ids = [
            obj["id"] for obj in objects if obj["type"] == "course-of-action"
        ]
        assert len(entitlement_ids) == 2
        assert len(set(entitlement_ids)) == 2
    finally:
        db.unlink(missing_ok=True)
        out.unlink(missing_ok=True)


def test_diff_bundle_passes_strict_parser_and_resolves_note_refs():
    db_old = _build_db()
    db_new = _build_db()
    out = Path(tempfile.mktemp(suffix=".json"))
    try:
        conn = sqlite3.connect(str(db_new))
        conn.execute(
            "INSERT INTO daemons (label, plist_path) VALUES (?, ?)",
            ("strict-new-daemon", "/strict/new.plist"),
        )
        conn.commit()
        conn.close()

        bundle = diff_to_stix(db_old, db_new, out)
        _strict_parse(bundle)
        known_ids = {obj["id"] for obj in bundle["objects"]}
        notes = [obj for obj in bundle["objects"] if obj["type"] == "note"]
        assert notes
        for note in notes:
            assert TIMESTAMP_RE.match(note["created"])
            assert TIMESTAMP_RE.match(note["modified"])
            assert note["object_refs"]
            assert all(ref in known_ids for ref in note["object_refs"])
    finally:
        db_old.unlink(missing_ok=True)
        db_new.unlink(missing_ok=True)
        out.unlink(missing_ok=True)


def test_stix_timestamp_normalizes_offsets_and_rejects_garbage():
    assert _stix_timestamp("2026-07-18 12:34:56") == "2026-07-18T12:34:56Z"
    assert _stix_timestamp("2026-07-18T12:34:56+05:00") == "2026-07-18T07:34:56Z"
    with pytest.raises(ValueError, match="Invalid timestamp"):
        _stix_timestamp("definitely-not-a-timestamp")


def test_stix_export_refuses_dangling_polymorphic_observation_target():
    db = _build_db()
    out = Path(tempfile.mktemp(suffix=".json"))
    try:
        conn = sqlite3.connect(str(db))
        conn.execute(
            "INSERT INTO observations "
            "(entity_table, entity_id, observed_at, event_type) VALUES (?, ?, ?, ?)",
            ("files", 999999, "2026-07-18T12:34:56Z", "missing"),
        )
        conn.commit()
        conn.close()

        with pytest.raises(ValueError, match="Observation target does not exist"):
            export_to_stix(db, out)
        assert not out.exists()
    finally:
        db.unlink(missing_ok=True)
        out.unlink(missing_ok=True)
