"""Private resume keys bind public identities without enabling path guessing."""

import hashlib
import hmac
import json
import os
import sqlite3
import subprocess
import sys
from contextlib import closing
from pathlib import Path

import pytest

from icarus.core.pipeline import (
    CheckpointProvenanceError,
    Pipeline,
    PipelinePhase,
    _source_identity_digest,
    create_default_pipeline,
)
from icarus.core.schema import initialize_database, open_db
from icarus.integrations import hygeia


def _meta(path):
    with closing(sqlite3.connect(path)) as conn:
        return dict(conn.execute("SELECT key,value FROM checkpoint_meta"))


def _metadata(path):
    with closing(sqlite3.connect(path)) as conn:
        return json.loads(conn.execute("SELECT metadata FROM versions").fetchone()[0])


def _finish(source, output):
    pipeline = Pipeline(source, output, parser_name="test")

    def write(ctx):
        with closing(sqlite3.connect(output)) as conn:
            conn.execute("INSERT INTO files(path,filename,source_version_id) "
                         "VALUES('/kept','kept',?)",
                         (ctx.version_id,))
            conn.commit()
        return {"files": 1}

    pipeline.add_phase("ingest", write)
    return pipeline


WORKER = """
import os, sys
from pathlib import Path
from icarus.core.pipeline import Pipeline
from icarus.core.schema import initialize_database
source, output, stage = Path(sys.argv[1]), Path(sys.argv[2]), sys.argv[3]
pipeline=Pipeline(source, output, parser_name='test')
if stage in ('intent', 'initialized'):
    def crash():
        if stage == 'initialized': initialize_database(output)
        os._exit(73)
    pipeline._create_version_record=crash
elif stage == 'version':
    pipeline._persist_version_identity=lambda: os._exit(73)
elif stage == 'bound':
    pipeline.save_checkpoint=lambda *args, **kwargs: os._exit(73)
pipeline.add_phase('ingest', lambda ctx: {'ok':True})
pipeline.run()
"""


@pytest.mark.parametrize("stage", ["intent", "initialized", "version", "bound"])
def test_process_death_at_identity_commit_boundaries_recovers_same_run(tmp_path, stage):
    source = tmp_path / "source"
    source.mkdir()
    output = tmp_path / "out.db"
    child = subprocess.run(
        [sys.executable, "-c", WORKER, str(source), str(output), stage],
        capture_output=True, text=True, timeout=20,
    )
    assert child.returncode == 73, child.stderr
    resumed = _finish(source, output)
    private = _meta(resumed.checkpoint_db)
    original_run = private["run_id"]
    assert len(private["source_identity_key"]) == 64
    assert private["identity_state"] == ("bound" if stage == "bound" else "prepared")
    before = resumed.checkpoint_db.read_bytes()
    assert resumed.has_resumable_checkpoint()
    assert resumed.checkpoint_db.read_bytes() == before
    assert resumed.run().run_id == original_run
    with closing(sqlite3.connect(output)) as conn:
        assert conn.execute("SELECT run_id FROM versions").fetchall() == [(original_run,)]
        assert conn.execute("SELECT COUNT(*) FROM files").fetchone() == (1,)
    assert not resumed.checkpoint_db.exists()


@pytest.mark.parametrize("unrelated", [
    "row", "unknown_table", "shadow_prefix", "fts_shadow", "invalid_sqlite",
])
def test_prepared_intent_never_unions_an_unrelated_existing_output(tmp_path, unrelated):
    source = tmp_path / "source"
    source.mkdir()
    output = tmp_path / "out.db"
    child = subprocess.run(
        [sys.executable, "-c", WORKER, str(source), str(output), "intent"],
        capture_output=True, text=True, timeout=20,
    )
    assert child.returncode == 73
    if unrelated == "invalid_sqlite":
        output.write_bytes(b"unrelated file must remain untouched")
    else:
        initialize_database(output)
        with closing(sqlite3.connect(output)) as conn:
            if unrelated == "row":
                conn.execute("INSERT INTO files(path,filename) VALUES('/unrelated','unrelated')")
            elif unrelated == "fts_shadow":
                conn.execute("UPDATE files_fts_data SET block=? WHERE id=1", (b"unrelated",))
            else:
                table = "sqliteXunrelated" if unrelated == "shadow_prefix" else "unrelated"
                conn.execute(f"CREATE TABLE {table}(payload TEXT)")  # nosec B608 - names fixed above
                conn.execute(f"INSERT INTO {table} VALUES ('preserve')")  # nosec B608 - names fixed above
            conn.commit()
    before = output.read_bytes()
    resumed = _finish(source, output)
    with pytest.raises(CheckpointProvenanceError, match="output"):
        resumed.has_resumable_checkpoint()
    with pytest.raises(CheckpointProvenanceError, match="output"):
        resumed.run()
    assert output.read_bytes() == before
    assert resumed.checkpoint_db.exists()


def test_prepared_existing_version_requires_matching_private_hmac(tmp_path):
    output = tmp_path / "out.db"
    child = subprocess.run(
        [sys.executable, "-c", WORKER, str(tmp_path), str(output), "version"],
        capture_output=True, text=True, timeout=20,
    )
    assert child.returncode == 73
    with closing(sqlite3.connect(output)) as conn:
        conn.execute("UPDATE versions SET metadata='{}'")
        conn.commit()
    with pytest.raises(CheckpointProvenanceError, match="does not match"):
        _finish(tmp_path, output).run()


def test_public_metadata_does_not_enable_the_old_two_candidate_guess_test(tmp_path):
    # Synthetic source labels differ only in a redacted username component.
    # Custom extraction below requires no source files or real private paths.
    home = "C:/Users" if os.name == "nt" else "/home"
    source = Path(home) / "SYNTHETIC_ALPHA" / "research" / "rootfs"
    alternate = Path(home) / "SYNTHETIC_BETA" / "research" / "rootfs"
    output = tmp_path / "out.db"
    pipeline = Pipeline(source, output, parser_name="synthetic")
    captured = {}

    def capture(_ctx):
        captured.update(_meta(pipeline.checkpoint_db))

    def extract(ctx):
        with closing(open_db(output)) as conn:
            conn.execute("INSERT INTO files(path,filename,source_version_id) "
                         "VALUES('/data','data',?)",
                         (ctx.version_id,))
            conn.commit()

    pipeline.add_phase("inspect_private_state", capture)
    pipeline.add_phase("extract", extract)
    pipeline.add_phase("sanitize", lambda _ctx: hygeia.sanitize_output(output))
    context = pipeline.run()
    public = _metadata(output)
    identity = public["source_identity"]
    assert "source_identity_sha256" not in public
    key = bytes.fromhex(captured["source_identity_key"])
    expected = hmac.new(key, f"{context.run_id}\0{source.resolve()}".encode(), hashlib.sha256)
    assert identity == {"version": 1, "algorithm": "hmac-sha256", "digest": expected.hexdigest()}
    guesses = [source, alternate]
    assert not any(_source_identity_digest(guess, context.run_id) == identity["digest"]
                   for guess in guesses)
    published = output.read_bytes()
    if key in published or captured["source_identity_key"].encode() in published:
        pytest.fail("Private resume key reached the published database")
    if b"SYNTHETIC_ALPHA" in published:
        pytest.fail("Synthetic private path survived canonical cleanup")
    assert "source_identity_key" not in vars(context)
    with closing(sqlite3.connect(output)) as conn:
        assert "SYNTHETIC_ALPHA" not in conn.execute(
            "SELECT source_path FROM versions"
        ).fetchone()[0]
    assert hygeia.sanitization_status(output) == "verified"
    assert not pipeline.checkpoint_db.exists()


def _legacy_interrupted(source, output):
    pipeline = create_default_pipeline(source, output, "generic/json")

    def fail(_ctx):
        raise RuntimeError("interrupted before sanitize")

    pipeline.phases.insert(4, PipelinePhase("interrupt", fail))
    with pytest.raises(RuntimeError):
        pipeline.run()
    _replace_with_legacy_identity(pipeline, source, output)
    return pipeline


def _replace_with_legacy_identity(pipeline, source, output):
    with closing(sqlite3.connect(output)) as conn:
        conn.execute("UPDATE versions SET metadata=?, source_path='[REDACTED_USER_PATH]/source'",
                     (json.dumps({"source_identity_sha256": _source_identity_digest(
                         source, pipeline.context.run_id), "note": "preserve"}),))
        conn.commit()
    with closing(sqlite3.connect(pipeline.checkpoint_db)) as conn:
        conn.execute("DELETE FROM checkpoint_meta WHERE key IN "
                     "('identity_protocol','identity_state','identity_intent','source_identity_key')")
        conn.commit()


@pytest.mark.parametrize("stage", ["private_key", "output_hmac"])
def test_legacy_upgrade_commit_gaps_recover_without_new_run(tmp_path, monkeypatch, stage):
    source = tmp_path / "source"
    source.mkdir()
    (source / "config.json").write_text('{"kind":"test"}')
    output = tmp_path / "out.db"
    original = _legacy_interrupted(source, output)
    resumed = create_default_pipeline(source, output, "generic/json")
    original_upgrade = resumed._upgrade_legacy_identity

    def crash_after_private_key():
        resumed._persist_identity_intent("upgrading")
        raise RuntimeError("injected identity transition failure")

    def crash_after_public_hmac():
        original_upgrade()
        raise RuntimeError("injected identity transition failure")

    crash = crash_after_private_key if stage == "private_key" else crash_after_public_hmac
    monkeypatch.setattr(resumed, "_upgrade_legacy_identity", crash)
    with pytest.raises(RuntimeError, match="identity transition"):
        resumed.run()
    private = _meta(resumed.checkpoint_db)
    assert private["identity_state"] == "upgrading"
    final = create_default_pipeline(source, output, "generic/json").run()
    assert final.run_id == original.context.run_id
    public = _metadata(output)
    assert public["note"] == "preserve"
    assert "source_identity_sha256" not in public
    key = bytes.fromhex(private["source_identity_key"])
    expected = hmac.new(
        key, f"{final.run_id}\0{source.resolve()}".encode(), hashlib.sha256,
    ).hexdigest()
    assert public["source_identity"]["digest"] == expected
    assert hygeia.sanitization_status(output) == "verified"


def test_failed_legacy_public_write_preserves_key_and_original_metadata(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    (source / "config.json").write_text('{"kind":"test"}')
    output = tmp_path / "out.db"
    original = _legacy_interrupted(source, output)
    with closing(sqlite3.connect(output)) as conn:
        conn.executescript(
            "CREATE TRIGGER reject_identity BEFORE UPDATE OF metadata ON versions "
            "BEGIN SELECT RAISE(ABORT, 'injected public write failure'); END;"
        )
    resumed = create_default_pipeline(source, output, "generic/json")
    with pytest.raises(sqlite3.IntegrityError, match="public write"):
        resumed.run()
    private = _meta(resumed.checkpoint_db)
    assert private["identity_state"] == "upgrading"
    public = _metadata(output)
    assert "source_identity_sha256" in public and public["note"] == "preserve"
    with closing(sqlite3.connect(output)) as conn:
        conn.execute("DROP TRIGGER reject_identity")
        conn.commit()
    final = create_default_pipeline(source, output, "generic/json").run()
    assert final.run_id == original.context.run_id
    assert "source_identity_sha256" not in _metadata(output)


def test_bound_checkpoint_missing_key_fails_closed_without_key_diagnostics(tmp_path):
    output = tmp_path / "out.db"
    child = subprocess.run(
        [sys.executable, "-c", WORKER, str(tmp_path), str(output), "bound"],
        capture_output=True, text=True, timeout=20,
    )
    assert child.returncode == 73
    resumed = _finish(tmp_path, output)
    old_key = _meta(resumed.checkpoint_db)["source_identity_key"]
    with closing(sqlite3.connect(resumed.checkpoint_db)) as conn:
        conn.execute("DELETE FROM checkpoint_meta WHERE key='source_identity_key'")
        conn.commit()
    before = output.read_bytes()
    with pytest.raises(CheckpointProvenanceError) as error:
        resumed.run()
    if old_key in str(error.value):
        pytest.fail("Private key appeared in error diagnostics")
    assert output.read_bytes() == before
    assert resumed.checkpoint_db.exists()


@pytest.mark.parametrize("malformed", ["keyless_hmac", "null_identity"])
def test_malformed_keyless_identity_never_falls_back_or_rebinds_legacy_source(
    tmp_path, malformed,
):
    first, second = tmp_path / "source-A", tmp_path / "source-B"
    first.mkdir()
    second.mkdir()
    output = tmp_path / "out.db"
    original = Pipeline(first, output, parser_name="test")

    def interrupt(_ctx):
        raise RuntimeError("interrupted")

    original.add_phase("ingest", interrupt)
    with pytest.raises(RuntimeError):
        original.run()
    identity = (
        {"version": 1, "algorithm": "hmac-sha256", "digest": None}
        if malformed == "keyless_hmac" else None
    )
    with closing(sqlite3.connect(output)) as conn:
        conn.execute("UPDATE versions SET metadata=?",
                     (json.dumps({"source_identity": identity}),))
        conn.commit()
    with closing(sqlite3.connect(original.checkpoint_db)) as conn:
        conn.execute("DELETE FROM checkpoint_meta WHERE key IN "
                     "('identity_protocol','identity_state','identity_intent',"
                     "'source_identity_key','output_uri')")
        conn.commit()
    legacy = tmp_path / ".out_checkpoint.db"
    original.checkpoint_db.replace(legacy)
    before = (hashlib.sha256(output.read_bytes()).digest(),
              hashlib.sha256(legacy.read_bytes()).digest())
    resumed = _finish(second if malformed == "keyless_hmac" else first, output)
    with pytest.raises(CheckpointProvenanceError, match="source_identity"):
        resumed.run()
    assert hashlib.sha256(output.read_bytes()).digest() == before[0]
    assert hashlib.sha256(legacy.read_bytes()).digest() == before[1]
    assert not resumed.checkpoint_db.exists()


@pytest.mark.parametrize("stage", ["version", "bound"])
def test_boolean_public_hmac_version_is_not_an_integer_protocol_version(tmp_path, stage):
    output = tmp_path / "out.db"
    child = subprocess.run(
        [sys.executable, "-c", WORKER, str(tmp_path), str(output), stage],
        capture_output=True, text=True, timeout=20,
    )
    assert child.returncode == 73
    public = _metadata(output)
    public["source_identity"]["version"] = True
    with closing(sqlite3.connect(output)) as conn:
        conn.execute("UPDATE versions SET metadata=?", (json.dumps(public),))
        conn.commit()
    resumed = _finish(tmp_path, output)
    before = (hashlib.sha256(output.read_bytes()).digest(),
              hashlib.sha256(resumed.checkpoint_db.read_bytes()).digest())
    with pytest.raises(CheckpointProvenanceError):
        resumed.run()
    assert hashlib.sha256(output.read_bytes()).digest() == before[0]
    assert hashlib.sha256(resumed.checkpoint_db.read_bytes()).digest() == before[1]


@pytest.mark.parametrize("binding_interruption", [False, True])
def test_legacy_completed_sanitize_checkpoint_still_replays_canonical_cleanup(
    tmp_path, monkeypatch, binding_interruption,
):
    source = tmp_path / "source"
    source.mkdir()
    (source / "config.json").write_text('{"kind":"test"}')
    output = tmp_path / "out.db"
    old = create_default_pipeline(source, output, "generic/json")

    def keep_checkpoint():
        raise RuntimeError("injected checkpoint cleanup failure")

    monkeypatch.setattr(old, "_clear_checkpoint", keep_checkpoint)
    with pytest.raises(RuntimeError, match="checkpoint cleanup"):
        old.run()
    _replace_with_legacy_identity(old, source, output)
    legacy_digest = _metadata(output)["source_identity_sha256"]
    calls = []
    original_sanitize = hygeia.sanitize_output

    def tracked_sanitize(path):
        calls.append(True)
        return original_sanitize(path)

    monkeypatch.setattr(hygeia, "sanitize_output", tracked_sanitize)
    if binding_interruption:
        interrupted = create_default_pipeline(source, output, "generic/json")
        original_binding = interrupted._persist_version_identity

        def fail_after_binding():
            original_binding()
            raise RuntimeError("injected binding interruption")

        monkeypatch.setattr(interrupted, "_persist_version_identity", fail_after_binding)
        with pytest.raises(RuntimeError, match="binding interruption"):
            interrupted.run()
        private = _meta(interrupted.checkpoint_db)
        assert private["identity_state"] == "bound"
        assert private["identity_requires_sanitization"] == "1"
    final = create_default_pipeline(source, output, "generic/json").run()
    assert final.run_id == old.context.run_id
    assert calls == [True]
    assert legacy_digest.encode() not in output.read_bytes()
    assert hygeia.sanitization_status(output) == "verified"


@pytest.mark.skipif(os.name == "nt", reason="POSIX permission bits; Windows uses directory ACLs")
def test_private_key_checkpoint_is_owner_only_before_public_version(tmp_path):
    output = tmp_path / "out.db"
    child = subprocess.run(
        [sys.executable, "-c", WORKER, str(tmp_path), str(output), "intent"],
        capture_output=True, text=True, timeout=20,
    )
    assert child.returncode == 73
    checkpoint = _finish(tmp_path, output).checkpoint_db
    assert checkpoint.stat().st_mode & 0o077 == 0
    assert not output.exists()
