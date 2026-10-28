"""Versioned public-artifact policy and explicit completed legacy remediation."""

import json
import sqlite3
from contextlib import closing

import pytest

from icarus.core.pipeline import Pipeline
from icarus.core.schema import initialize_database
from icarus.integrations import hygeia

LEGACY_DIGEST = "d" * 64


def _stamp_audit(conn, audit_version=1, engine_version=None):
    engine = hygeia.require_hygeia()
    if engine_version is not None:
        engine = dict(engine, version=engine_version)
    audit = {
        "audit_version": audit_version, "engine": engine, "verified": True,
        "gate": hygeia.FINAL_GATE_NAME,
        "post_gate": {"passed": True, "total_findings": 0},
        "checked_rows": 1, "total_findings": 0, "patterns_found": {},
        "findings": [], "findings_truncated": False,
    }
    conn.executemany("INSERT OR REPLACE INTO metadata VALUES (?, ?)", [
        ("hygeia_status", "verified"), ("hygeia_engine", json.dumps(engine)),
        ("hygeia_audit", json.dumps(audit)),
    ])


def _legacy_database(path, *, complete=True, audit_version=1):
    initialize_database(path)
    with closing(sqlite3.connect(path)) as conn, conn:
        conn.execute(
            "INSERT INTO versions(run_id,parser_name,source_path,started_at,completed_at,metadata) "
            "VALUES ('legacy-run','linux','/offline/source','2026-10-28',?,?)",
            ("2026-10-28T12:00:00+00:00" if complete else None, json.dumps({
                "source_identity_sha256": LEGACY_DIGEST,
                "note": "retain inventory", "nested": {"labels": [1, "kept"]},
            })),
        )
        conn.execute("INSERT INTO files(path,filename) VALUES('/usr/bin/example','example')")
        conn.execute("INSERT INTO metadata VALUES('custom_note','preserve this note')")
        _stamp_audit(conn, audit_version)
    return path


def _details(path):
    with closing(sqlite3.connect(path)) as conn:
        return json.loads(conn.execute("SELECT metadata FROM versions").fetchone()[0])


def _checkpoint(path, *, foreign=False, legacy=False, prepared=False):
    pipeline = Pipeline(path.parent, path)
    checkpoint = pipeline.legacy_checkpoint_db if legacy else pipeline.checkpoint_db
    with closing(sqlite3.connect(checkpoint)) as conn, conn:
        conn.execute("CREATE TABLE checkpoint_meta(key TEXT PRIMARY KEY,value TEXT NOT NULL)")
        metadata = {"run_id": "foreign-run" if foreign else "legacy-run"}
        if not prepared:
            metadata["version_id"] = "1"
        if foreign:
            metadata["output_uri"] = (path.parent / "other.sqlite").as_uri()
        conn.executemany("INSERT INTO checkpoint_meta VALUES (?,?)", metadata.items())
    return checkpoint


def test_older_verified_audit_is_unknown_without_rewriting_artifact(tmp_path):
    path = _legacy_database(tmp_path / "old.db")
    before = path.read_bytes()
    assert hygeia.AUDIT_VERSION == 2
    assert hygeia.sanitization_status(path) == "unknown"
    assert path.read_bytes() == before


def test_current_audit_cannot_bless_retained_deprecated_field(tmp_path):
    path = _legacy_database(tmp_path / "leftover.db", audit_version=2)
    assert hygeia.sanitization_status(path) == "unknown"
    with pytest.raises(hygeia.SanitizationError):
        hygeia.finalize_sanitization(path)
    assert _details(path)["source_identity_sha256"] == LEGACY_DIGEST
    assert hygeia.sanitization_status(path) == "failed"


def test_final_audit_rechecks_policy_even_if_verifier_result_was_replaced(tmp_path, monkeypatch):
    path = _legacy_database(tmp_path / "gate.db")
    monkeypatch.setattr(hygeia, "verify_clean", lambda _: {
        "passed": True, "checked_rows": 1, "total_findings": 0,
        "patterns_found": {}, "findings": [], "findings_truncated": False,
    })
    with pytest.raises(hygeia.SanitizationError):
        hygeia.finalize_sanitization(path)
    assert hygeia.sanitization_status(path) == "failed"


def test_supported_public_hmac_format_can_be_verified(tmp_path):
    path = _legacy_database(tmp_path / "modern.db")
    with closing(sqlite3.connect(path)) as conn, conn:
        conn.execute("UPDATE versions SET metadata=?", (json.dumps({
            "source_identity": {"version": 1, "algorithm": "hmac-sha256", "digest": "a" * 64},
        }),))
    hygeia.sanitize_output(path)
    hygeia.finalize_sanitization(path)
    assert hygeia.sanitization_status(path) == "verified"


def test_private_resume_key_cannot_be_certified_or_echoed(tmp_path):
    path = _legacy_database(tmp_path / "private.db")
    private_key = "b" * 64
    with closing(sqlite3.connect(path)) as conn, conn:
        conn.execute("UPDATE versions SET metadata=?", (json.dumps({
            "source_identity_key": private_key,
        }),))
    with pytest.raises(hygeia.SanitizationError) as error:
        hygeia.finalize_sanitization(path)
    assert private_key not in str(error.value)
    assert hygeia.sanitization_status(path) == "failed"


def test_completed_remediation_preserves_provenance_and_uses_real_engine(tmp_path, monkeypatch):
    path = _legacy_database(tmp_path / "completed.db")
    canonical = hygeia.sanitize_database_generic
    called = []

    def engine(*args, **kwargs):
        called.append(True)
        return canonical(*args, **kwargs)

    monkeypatch.setattr(hygeia, "sanitize_database_generic", engine)
    result = hygeia.remediate_legacy_output(path)
    assert called == [True]
    assert result["versions_remediated"] == 1
    assert result["sanitization"]["engine"]["engine"] == hygeia.ENGINE_NAME
    assert hygeia.sanitization_status(path) == "verified"
    assert _details(path) == {"note": "retain inventory", "nested": {"labels": [1, "kept"]}}
    with closing(sqlite3.connect(path)) as conn:
        assert conn.execute("SELECT COUNT(*) FROM files").fetchone() == (1,)
        assert conn.execute("SELECT COUNT(*) FROM versions").fetchone() == (1,)
        assert conn.execute("SELECT value FROM metadata WHERE key='custom_note'").fetchone() == (
            "preserve this note",
        )
        audit = json.loads(conn.execute(
            "SELECT value FROM metadata WHERE key='hygeia_audit'"
        ).fetchone()[0])
    assert audit["audit_version"] == 2
    assert LEGACY_DIGEST.encode() not in path.read_bytes()
    assert b"source_identity_sha256" not in path.read_bytes()


def test_incomplete_provenance_is_not_silently_remediated(tmp_path):
    path = _legacy_database(tmp_path / "incomplete.db", complete=False)
    before = path.read_bytes()
    with pytest.raises(hygeia.SanitizationError, match="resume/recovery"):
        hygeia.remediate_legacy_output(path)
    assert path.read_bytes() == before
    assert _details(path)["source_identity_sha256"] == LEGACY_DIGEST


@pytest.mark.parametrize("posture", ["failed", "skipped", "unknown", "wrong-gate", "current"])
def test_completed_timestamp_does_not_replace_legacy_final_audit_evidence(tmp_path, posture):
    path = _legacy_database(tmp_path / "not-complete.db")
    with closing(sqlite3.connect(path)) as conn, conn:
        if posture == "failed":
            conn.execute("UPDATE metadata SET value='FAILED' WHERE key='hygeia_status'")
        elif posture == "skipped":
            conn.execute("INSERT INTO metadata VALUES('hygeia_skipped','true')")
        elif posture == "unknown":
            conn.execute("DELETE FROM metadata WHERE key='hygeia_audit'")
        elif posture == "current":
            _stamp_audit(conn, audit_version=2)
        else:
            audit = json.loads(conn.execute(
                "SELECT value FROM metadata WHERE key='hygeia_audit'"
            ).fetchone()[0])
            audit["gate"] = "sanitize-phase-only"
            conn.execute(
                "UPDATE metadata SET value=? WHERE key='hygeia_audit'", (json.dumps(audit),),
            )
    before = path.read_bytes()
    with pytest.raises(hygeia.SanitizationError, match="completion evidence"):
        hygeia.remediate_legacy_output(path)
    assert path.read_bytes() == before
    assert _details(path)["source_identity_sha256"] == LEGACY_DIGEST


def test_coherent_older_engine_audit_can_be_remediated_with_current_real_engine(tmp_path):
    path = _legacy_database(tmp_path / "previous-engine.db")
    with closing(sqlite3.connect(path)) as conn, conn:
        _stamp_audit(conn, engine_version="3.14.0")
    assert hygeia.sanitization_status(path) == "unknown"
    hygeia.remediate_legacy_output(path)
    assert hygeia.sanitization_status(path) == "verified"
    with closing(sqlite3.connect(path)) as conn:
        engine = json.loads(conn.execute(
            "SELECT value FROM metadata WHERE key='hygeia_engine'"
        ).fetchone()[0])
    assert engine["version"] == hygeia.require_hygeia()["version"]


def test_orphaned_checkpoint_sidecars_cannot_be_bypassed(tmp_path):
    path = _legacy_database(tmp_path / "orphan.db")
    checkpoint = Pipeline(tmp_path, path).checkpoint_db
    journal = tmp_path / (checkpoint.name + "-journal")
    journal.write_bytes(b"unresolved private checkpoint state")
    before = path.read_bytes()
    with pytest.raises(hygeia.SanitizationError, match="sidecars"):
        hygeia.remediate_legacy_output(path)
    assert path.read_bytes() == before
    assert journal.read_bytes() == b"unresolved private checkpoint state"


@pytest.mark.parametrize("raw", ["not-json", "[]", '"opaque metadata"'])
def test_unknown_version_metadata_shape_is_refused_without_stripping(tmp_path, raw):
    path = _legacy_database(tmp_path / "unknown-shape.db")
    with closing(sqlite3.connect(path)) as conn, conn:
        conn.execute("UPDATE versions SET metadata=?", (raw,))
    before = path.read_bytes()
    with pytest.raises(hygeia.SanitizationError):
        hygeia.remediate_legacy_output(path)
    assert path.read_bytes() == before
    with pytest.raises(hygeia.SanitizationError):
        hygeia.verify_clean(path)


@pytest.mark.parametrize("legacy", [False, True])
def test_owned_checkpoint_requires_resume_without_removing_state(tmp_path, legacy):
    path = _legacy_database(tmp_path / "owned.db")
    checkpoint = _checkpoint(path, legacy=legacy)
    before, checkpoint_before = path.read_bytes(), checkpoint.read_bytes()
    with pytest.raises(hygeia.SanitizationError, match="resume"):
        hygeia.remediate_legacy_output(path)
    assert path.read_bytes() == before
    assert checkpoint.read_bytes() == checkpoint_before


def test_prepared_or_ambiguous_checkpoint_is_preserved(tmp_path):
    path = _legacy_database(tmp_path / "prepared.db")
    checkpoint = _checkpoint(path, prepared=True)
    before = checkpoint.read_bytes()
    with pytest.raises(hygeia.SanitizationError, match="resume/recovery"):
        hygeia.remediate_legacy_output(path)
    assert checkpoint.read_bytes() == before
    assert _details(path)["source_identity_sha256"] == LEGACY_DIGEST


def test_proven_foreign_legacy_checkpoint_is_preserved_and_ignored(tmp_path):
    path = _legacy_database(tmp_path / "foreign.db")
    checkpoint = _checkpoint(path, foreign=True, legacy=True)
    before = checkpoint.read_bytes()
    hygeia.remediate_legacy_output(path)
    assert checkpoint.read_bytes() == before
    assert hygeia.sanitization_status(path) == "verified"


def test_canonical_engine_failure_leaves_remediation_unverified(tmp_path, monkeypatch):
    path = _legacy_database(tmp_path / "failed.db")

    def failing_engine(*args, **kwargs):
        raise RuntimeError("injected engine failure")

    monkeypatch.setattr(hygeia, "sanitize_database_generic", failing_engine)
    with pytest.raises(hygeia.SanitizationError, match="remains unverified"):
        hygeia.remediate_legacy_output(path)
    assert hygeia.sanitization_status(path) == "failed"
    assert "source_identity_sha256" not in _details(path)
    assert _details(path)["note"] == "retain inventory"


def test_rejected_metadata_update_leaves_legacy_evidence_but_revokes_trust(tmp_path):
    path = _legacy_database(tmp_path / "sql-failure.db")
    with closing(sqlite3.connect(path)) as conn:
        conn.executescript("""CREATE TRIGGER reject_metadata BEFORE UPDATE OF metadata ON versions
            BEGIN SELECT RAISE(ABORT, 'injected write failure'); END;""")
    with pytest.raises(hygeia.SanitizationError, match="remains unverified"):
        hygeia.remediate_legacy_output(path)
    assert _details(path)["source_identity_sha256"] == LEGACY_DIGEST
    assert hygeia.sanitization_status(path) == "failed"
