"""Build trust expires before writes; resume identity survives path sanitization."""

import json
import sqlite3
import subprocess
import sys
from contextlib import closing

import pytest

from icarus.core.pipeline import (
    CheckpointFingerprintMismatch,
    CheckpointProvenanceError,
    Pipeline,
    create_default_pipeline,
)
from icarus.core.schema import initialize_database
from icarus.integrations import hygeia


def _mark_skipped(output):
    with closing(sqlite3.connect(output)) as conn:
        conn.execute("INSERT OR REPLACE INTO metadata VALUES ('hygeia_skipped', 'true')")
        conn.commit()


def _fail(_context):
    raise RuntimeError("injected failure")


def test_new_direct_pipeline_run_revokes_trust_before_hard_exit(tmp_path):
    output = tmp_path / "out.db"
    initialize_database(output)
    _mark_skipped(output)
    worker = """
import os, sqlite3, sys
from pathlib import Path
from icarus.core.pipeline import Pipeline
output = Path(sys.argv[1])
pipeline = Pipeline(output.parent, output, parser_name='test')
def die(ctx):
    conn = sqlite3.connect(output)
    conn.execute("INSERT INTO metadata VALUES ('secret', 'password=OnlySyntheticSecretValue')")
    conn.commit()
    os._exit(73)
pipeline.add_phase('ingest', die)
pipeline.run(resume=False)
"""
    result = subprocess.run(
        [sys.executable, "-c", worker, str(output)],
        capture_output=True, text=True, timeout=30,
    )
    assert result.returncode == 73, result.stderr
    assert hygeia.sanitization_status(output) == "unknown"


def test_validated_resume_revokes_trust_before_phase_writes(tmp_path):
    output = tmp_path / "out.db"
    pipeline = Pipeline(tmp_path, output, parser_name="test")
    pipeline.add_phase("ingest", _fail)
    with pytest.raises(RuntimeError):
        pipeline.run()
    _mark_skipped(output)
    resumed = Pipeline(tmp_path, output, parser_name="test")
    resumed.add_phase("ingest", _fail)
    with pytest.raises(RuntimeError):
        resumed.run()
    assert hygeia.sanitization_status(output) == "unknown"


def test_fingerprint_refusal_preserves_existing_trust(tmp_path):
    output = tmp_path / "out.db"
    pipeline = Pipeline(tmp_path, output, parser_name="test", fingerprint={"source": "a"})
    pipeline.add_phase("ingest", _fail)
    with pytest.raises(RuntimeError):
        pipeline.run()
    _mark_skipped(output)
    mismatched = Pipeline(tmp_path, output, parser_name="test", fingerprint={"source": "b"})
    mismatched.add_phase("ingest", _fail)
    with pytest.raises(CheckpointFingerprintMismatch):
        mismatched.run()
    assert hygeia.sanitization_status(output) == "skipped"


def test_failed_version_creation_rolls_back_trust_revocation(tmp_path):
    output = tmp_path / "out.db"
    initialize_database(output)
    _mark_skipped(output)
    with closing(sqlite3.connect(output)) as conn:
        conn.executescript(
            "CREATE TRIGGER reject_version BEFORE INSERT ON versions "
            "BEGIN SELECT RAISE(ABORT, 'injected version-write failure'); END;"
        )
    with pytest.raises(sqlite3.IntegrityError, match="version-write"):
        Pipeline(tmp_path, output, parser_name="test").run()
    assert hygeia.sanitization_status(output) == "skipped"


def test_post_sanitization_failure_can_resume_with_redacted_source_path(tmp_path, monkeypatch):
    source = tmp_path / "source"
    source.mkdir()
    (source / "config.json").write_text('{"kind":"test"}')
    output = tmp_path / "out.db"
    original_gate = hygeia.verify_clean
    monkeypatch.setattr(hygeia, "verify_clean", lambda _path: {
        "passed": False, "total_findings": 1, "patterns_found": {"test": 1},
    })
    with pytest.raises(hygeia.SanitizationError, match="Final post-write"):
        create_default_pipeline(source, output, "generic/json").run()
    with closing(sqlite3.connect(output)) as conn:
        if sys.platform == "win32":
            assert conn.execute("SELECT source_path FROM versions").fetchone()[0] != str(source)
        # Windows test homes are redacted by the real sanitizer. Also model the
        # same transformation on runners whose /tmp path has no username.
        conn.execute("UPDATE versions SET source_path = '[REDACTED_USER_PATH]/source'")
        conn.commit()
    monkeypatch.setattr(hygeia, "verify_clean", original_gate)
    context = create_default_pipeline(source, output, "generic/json").run()
    assert context.version_id == 1
    assert hygeia.sanitization_status(output) == "verified"
    with closing(sqlite3.connect(output)) as conn:
        assert conn.execute("SELECT COUNT(*) FROM versions").fetchone() == (1,)
        metadata = json.loads(conn.execute("SELECT metadata FROM versions").fetchone()[0])
        assert len(metadata["source_identity"]["digest"]) == 64
        assert "source_identity_sha256" not in metadata


def test_source_identity_digest_is_bound_to_its_original_run(tmp_path):
    first = tmp_path / "first.db"
    second = tmp_path / "second.db"
    for output in (first, second):
        pipeline = Pipeline(tmp_path, output, parser_name="test")
        pipeline.add_phase("ingest", _fail)
        with pytest.raises(RuntimeError):
            pipeline.run()
    with closing(sqlite3.connect(first)) as conn:
        first_metadata = conn.execute("SELECT metadata FROM versions").fetchone()[0]
    with closing(sqlite3.connect(second)) as conn:
        conn.execute("UPDATE versions SET metadata = ?", (first_metadata,))
        conn.commit()
    resumed = Pipeline(tmp_path, second, parser_name="test")
    resumed.add_phase("ingest", lambda _ctx: {"ok": True})
    with pytest.raises(CheckpointProvenanceError, match="source_identity"):
        resumed.run()


def test_legacy_run_without_digest_still_resumes_by_exact_path(tmp_path):
    output = tmp_path / "out.db"
    pipeline = Pipeline(tmp_path, output, parser_name="test")
    pipeline.add_phase("ingest", _fail)
    with pytest.raises(RuntimeError):
        pipeline.run()
    with closing(sqlite3.connect(output)) as conn:
        conn.execute("UPDATE versions SET metadata = NULL")
        conn.commit()
    with closing(sqlite3.connect(pipeline.checkpoint_db)) as conn:
        conn.execute("DELETE FROM checkpoint_meta WHERE key IN "
                     "('identity_protocol','identity_state','identity_intent','source_identity_key')")
        conn.commit()
    resumed = Pipeline(tmp_path, output, parser_name="test")
    resumed.add_phase("ingest", lambda _ctx: {"ok": True})
    assert resumed.run().version_id == 1
