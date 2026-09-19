"""Tests for Phase 3.6 — STIX 2.1 export."""

import json
import re
import sqlite3
import tempfile
import types
import uuid
from pathlib import Path

import pytest

from icarus import __main__ as cli
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
        assert obj["sighting_of_ref"] == _entity_ref("daemons", daemon_id)
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
