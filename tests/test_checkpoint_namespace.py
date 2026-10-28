"""Output checkpoint ownership and compatibility with interrupted legacy runs."""

import json
import shutil
import sqlite3
import subprocess
import sys
import time
from contextlib import closing

import pytest

from icarus.__main__ import cmd_build
from icarus.core.pipeline import (
    CheckpointFingerprintMismatch,
    CheckpointProvenanceError,
    Pipeline,
    _source_identity_digest,
    create_default_pipeline,
)
from icarus.parsers.windows import WindowsParser


def _fail(_ctx):
    raise RuntimeError("interrupted")


def _pipeline(source, output, *, fingerprint=None, first=None, last=None):
    pipeline = Pipeline(source, output, parser_name="test", fingerprint=fingerprint)
    pipeline.add_phase("ingest", first or (lambda _ctx: {"ok": True}))
    pipeline.add_phase("finish", last or (lambda _ctx: {"ok": True}))
    return pipeline


def _interrupted(source, output, *, legacy=False, fingerprint=None):
    pipeline = _pipeline(source, output, fingerprint=fingerprint, last=_fail)
    with pytest.raises(RuntimeError, match="interrupted"):
        pipeline.run(resume=False)
    if legacy:
        _as_legacy(pipeline)
    return pipeline


def _as_legacy(pipeline):
    with closing(sqlite3.connect(pipeline.output)) as conn:
        conn.execute("UPDATE versions SET metadata=? WHERE id=?",
                     (json.dumps({"source_identity_sha256": _source_identity_digest(
                         pipeline.source, pipeline.context.run_id)}), pipeline.context.version_id))
        conn.commit()
    with closing(sqlite3.connect(pipeline.checkpoint_db)) as conn:
        conn.execute("DELETE FROM checkpoint_meta WHERE key IN "
                     "('output_uri','identity_protocol','identity_state','identity_intent',"
                     "'source_identity_key')")
        conn.commit()
    legacy_path = pipeline.output.parent / f".{pipeline.output.stem}_checkpoint.db"
    if pipeline.checkpoint_db != legacy_path:
        pipeline.checkpoint_db.replace(legacy_path)


def test_constructor_is_filesystem_pure_and_namespaces_full_filename(tmp_path):
    before = list(tmp_path.iterdir())
    first = Pipeline(tmp_path, tmp_path / "out.db")
    second = Pipeline(tmp_path, tmp_path / "out.sqlite")
    assert first.checkpoint_db != second.checkpoint_db
    assert first.checkpoint_db.name == ".out.db.icarus-checkpoint.db"
    assert Pipeline(tmp_path, tmp_path / "out").checkpoint_db != first.legacy_checkpoint_db
    assert first.checkpoint_db != tmp_path / ".out.db_checkpoint.db"
    assert list(tmp_path.iterdir()) == before


def test_two_process_same_stem_failures_resume_independently(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    worker = """
import pathlib, sqlite3, sys, time
from icarus.core.pipeline import Pipeline
source, output, ready, release = map(pathlib.Path, sys.argv[1:])
pipeline = Pipeline(source, output, parser_name='test')
def ingest(ctx):
    conn = sqlite3.connect(output)
    conn.execute("INSERT INTO files(path,filename,source_version_id) "
                 "VALUES('/kept','kept',?)", (ctx.version_id,))
    conn.commit(); conn.close()
    ready.write_text('ready')
    end=time.monotonic()+15
    while not release.exists():
        if time.monotonic()>end: raise RuntimeError('release deadline')
        time.sleep(.01)
    raise RuntimeError('interrupted')
pipeline.add_phase('ingest', ingest)
pipeline.add_phase('finish', lambda ctx: {'ok': True})
try: pipeline.run(resume=False)
except RuntimeError: sys.exit(73)
"""
    outputs = [tmp_path / "out.db", tmp_path / "out.sqlite"]
    children = []
    try:
        for index, output in enumerate(outputs):
            ready, release = tmp_path / f"ready-{index}", tmp_path / f"release-{index}"
            child = subprocess.Popen(
                [sys.executable, "-u", "-c", worker, str(source), str(output),
                 str(ready), str(release)], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True,
            )
            children.append(child)
            deadline = time.monotonic() + 10
            while not ready.exists():
                assert child.poll() is None, child.communicate(timeout=1)
                assert time.monotonic() < deadline, "worker did not reach committed ingest"
                time.sleep(.01)
        for index in range(2):
            (tmp_path / f"release-{index}").write_text("release")
        for child in children:
            _, errors = child.communicate(timeout=10)
            assert child.returncode == 73, errors
    finally:
        for child in children:
            if child.poll() is None:
                child.kill()
            child.communicate(timeout=5)
    pending = [_pipeline(source, output) for output in outputs]
    assert all(p.checkpoint_db.exists() for p in pending)
    for index, pipeline in enumerate(pending):
        context = pipeline.run()
        assert context.version_id == 1
        with closing(sqlite3.connect(outputs[index])) as conn:
            assert conn.execute("SELECT COUNT(*) FROM files").fetchone() == (1,)
            assert conn.execute("SELECT COUNT(*) FROM versions").fetchone() == (1,)
        if index == 0:
            assert pending[1].checkpoint_db.exists()


def test_legacy_resume_is_recognized_without_mutating_then_adopted(tmp_path):
    output = tmp_path / "out.db"
    crashed = _interrupted(tmp_path, output, legacy=True, fingerprint={"source": "same"})
    legacy = tmp_path / ".out_checkpoint.db"
    before = legacy.read_bytes()
    resumed = _pipeline(tmp_path, output, fingerprint={"source": "same"})
    initial_identity = (resumed.context.run_id, resumed.context.version_id)
    assert resumed.has_resumable_checkpoint()
    assert legacy.read_bytes() == before
    assert not resumed.checkpoint_db.exists()
    assert (resumed.context.run_id, resumed.context.version_id) == initial_identity
    assert resumed.run().run_id == crashed.context.run_id
    assert not legacy.exists() and not resumed.checkpoint_db.exists()


@pytest.mark.parametrize("resume", [False, True])
def test_foreign_legacy_is_preserved_by_other_output(tmp_path, resume):
    first = tmp_path / "out.db"
    second = tmp_path / "out.sqlite"
    _interrupted(tmp_path, first, legacy=True)
    legacy = tmp_path / ".out_checkpoint.db"
    before = legacy.read_bytes()
    _pipeline(tmp_path, second).run(resume=resume)
    assert legacy.read_bytes() == before
    assert _pipeline(tmp_path, first).run().version_id == 1


def test_modern_run_ignores_a_proven_foreign_legacy(tmp_path):
    first, second = tmp_path / "out.db", tmp_path / "out.sqlite"
    _interrupted(tmp_path, first)
    _interrupted(tmp_path, second, legacy=True)
    legacy = tmp_path / ".out_checkpoint.db"
    before = legacy.read_bytes()
    assert _pipeline(tmp_path, first).run().version_id == 1
    assert legacy.read_bytes() == before
    assert _pipeline(tmp_path, second).run().version_id == 1


def test_nonresume_retires_owned_legacy_before_new_run(tmp_path):
    output = tmp_path / "out.db"
    previous = _interrupted(tmp_path, output, legacy=True)
    new = _pipeline(tmp_path, output).run(resume=False)
    assert new.run_id != previous.context.run_id
    assert not (tmp_path / ".out_checkpoint.db").exists()
    assert not _pipeline(tmp_path, output).has_resumable_checkpoint()


def test_legacy_fingerprint_mismatch_preserves_both_artifacts(tmp_path):
    output = tmp_path / "out.db"
    _interrupted(tmp_path, output, legacy=True, fingerprint={"source": "old"})
    legacy = tmp_path / ".out_checkpoint.db"
    before = legacy.read_bytes()
    changed = _pipeline(tmp_path, output, fingerprint={"source": "new"})
    with pytest.raises(CheckpointFingerprintMismatch):
        changed.has_resumable_checkpoint()
    with pytest.raises(CheckpointFingerprintMismatch):
        changed.run()
    assert legacy.read_bytes() == before
    assert not changed.checkpoint_db.exists()


@pytest.mark.parametrize("resume", [False, True])
def test_two_owned_checkpoints_are_ambiguous_and_preserved(tmp_path, resume):
    output = tmp_path / "out.db"
    current = _interrupted(tmp_path, output)
    legacy = tmp_path / ".out_checkpoint.db"
    shutil.copyfile(current.checkpoint_db, legacy)
    before = (current.checkpoint_db.read_bytes(), legacy.read_bytes())
    with pytest.raises(CheckpointProvenanceError, match="ambiguous|Ambiguous"):
        _pipeline(tmp_path, output).run(resume=resume)
    assert (current.checkpoint_db.read_bytes(), legacy.read_bytes()) == before


@pytest.mark.parametrize("resume", [False, True])
def test_malformed_legacy_with_present_output_is_preserved(tmp_path, resume):
    output = tmp_path / "out.db"
    _interrupted(tmp_path, output, legacy=True)
    legacy = tmp_path / ".out_checkpoint.db"
    legacy.write_bytes(b"unreadable legacy state")
    with pytest.raises(CheckpointProvenanceError, match="legacy|Legacy"):
        _pipeline(tmp_path, output).run(resume=resume)
    assert legacy.read_bytes() == b"unreadable legacy state"


def test_owned_legacy_wal_is_not_moved_or_deleted(tmp_path):
    output = tmp_path / "out.db"
    _interrupted(tmp_path, output, legacy=True)
    legacy = tmp_path / ".out_checkpoint.db"
    with closing(sqlite3.connect(legacy)) as conn:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("INSERT INTO checkpoint_meta VALUES ('pending', 'value')")
        conn.commit()
        assert (tmp_path / ".out_checkpoint.db-wal").stat().st_size
        with pytest.raises(CheckpointProvenanceError, match="WAL|journal"):
            _pipeline(tmp_path, output).run()
        assert legacy.exists()
    assert _pipeline(tmp_path, output).run().version_id == 1


def test_owned_legacy_journal_is_not_moved_or_deleted(tmp_path):
    output = tmp_path / "out.db"
    _interrupted(tmp_path, output, legacy=True)
    legacy = tmp_path / ".out_checkpoint.db"
    with closing(sqlite3.connect(legacy)) as conn:
        conn.execute("UPDATE checkpoint_meta SET value = value WHERE key='run_id'")
        # Force an actual journaled change while retaining the original owner.
        conn.execute("INSERT INTO checkpoint_meta VALUES ('pending', 'value')")
        assert (tmp_path / ".out_checkpoint.db-journal").stat().st_size
        with pytest.raises(CheckpointProvenanceError, match="WAL|journal"):
            _pipeline(tmp_path, output).run(resume=False)
        assert legacy.exists()
        conn.rollback()
    assert _pipeline(tmp_path, output).run().version_id == 1


def test_modern_output_identity_mismatch_is_never_cleared(tmp_path):
    output = tmp_path / "out.db"
    crashed = _interrupted(tmp_path, output)
    with closing(sqlite3.connect(crashed.checkpoint_db)) as conn:
        conn.execute("UPDATE checkpoint_meta SET value = ? WHERE key='output_uri'",
                     ((tmp_path / "other.db").as_uri(),))
        conn.commit()
    before = crashed.checkpoint_db.read_bytes()
    with pytest.raises(CheckpointProvenanceError, match="output"):
        _pipeline(tmp_path, output).run(resume=False)
    assert crashed.checkpoint_db.read_bytes() == before


def test_cli_recognizes_and_resumes_old_interrupted_database(tmp_path, monkeypatch):
    from argparse import Namespace

    source = tmp_path / "source"
    source.mkdir()
    (source / "file.txt").write_text("data")
    output = tmp_path / "out.db"
    original_hash = WindowsParser._safe_hash

    def fail_hash(*_args):
        raise RuntimeError("interrupted file extraction")

    monkeypatch.setattr(WindowsParser, "_safe_hash", staticmethod(fail_hash))
    crashed = create_default_pipeline(source, output, "windows", skip_hygeia=True)
    with pytest.raises(RuntimeError, match="interrupted file extraction"):
        crashed.run()
    monkeypatch.setattr(WindowsParser, "_safe_hash", staticmethod(original_hash))
    _as_legacy(crashed)
    legacy = tmp_path / ".out_checkpoint.db"
    cmd_build(Namespace(source=str(source), output=str(output), parser="windows",
                        fresh=False, skip_hygeia=True, resolve=False))
    assert not legacy.exists()
    with closing(sqlite3.connect(output)) as conn:
        assert conn.execute("SELECT COUNT(*) FROM files").fetchone() == (1,)
        assert conn.execute("SELECT run_id FROM versions").fetchone() == (crashed.context.run_id,)


def test_fresh_cleanup_preserves_foreign_legacy_state(tmp_path):
    from argparse import Namespace

    source = tmp_path / "source"
    source.mkdir()
    (source / "file.txt").write_text("data")
    _interrupted(source, tmp_path / "out.db", legacy=True)
    legacy = tmp_path / ".out_checkpoint.db"
    before = legacy.read_bytes()
    cmd_build(Namespace(source=str(source), output=str(tmp_path / "out.sqlite"), parser="windows",
                        fresh=True, skip_hygeia=True, resolve=False))
    assert legacy.read_bytes() == before
    assert not [p for p in tmp_path.iterdir() if p.name.endswith(".tmp")]
    assert not list(tmp_path.glob("*.tmp.icarus-checkpoint.db"))
