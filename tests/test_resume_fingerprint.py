"""D2 — safe build resume + atomic --fresh (issues #45, #36).

These tests pin the three D2 behaviors:

1. A strict resume fingerprint: a checkpoint is honored only when its stored
   fingerprint (resolved source path, parser identity/version, normalized
   config) matches the current run exactly. A changed ``--source`` or
   ``--parser`` must FAIL LOUDLY — never silently resume (building a DB from
   the old inputs) and never silently discard-and-rebuild.
2. An existing output database is refused by default (no valid matching
   checkpoint to resume) — the user is told to pass ``--fresh``.
3. ``--fresh`` is an atomic clean rebuild via a sibling temp DB + os.replace:
   on failure the destination is untouched and the temp is cleaned up; on
   success the destination is replaced (never reused/unioned into).
"""

import argparse
import sqlite3

import pytest

from icarus.core.pipeline import (
    PROVENANCE_ENTITY_TABLES,
    CheckpointFingerprintMismatch,
    CheckpointProvenanceError,
    OutputExistsError,
    Pipeline,
    _run_parser_phase_with_provenance,
    compute_fingerprint,
    create_default_pipeline,
)
from icarus.core.schema import open_db


def _fp(**overrides):
    """A minimal fingerprint dict with sensible defaults for direct-Pipeline use."""
    base = {
        "source": "/abs/source",
        "parser_name": "demo",
        "parser_impl": "demo.mod.DemoParser",
        "parser_version": "1.0.0",
        "config": {"resolve": False, "skip_hygeia": False},
    }
    base.update(overrides)
    return base


def _build_args(source, output, *, fresh=False, parser="windows",
                skip_hygeia=True, resolve=False):
    return argparse.Namespace(
        source=str(source), output=str(output), parser=parser,
        fresh=fresh, skip_hygeia=skip_hygeia, resolve=resolve,
    )


def _windows_source(tmp_path, name="src"):
    src = tmp_path / name
    src.mkdir()
    (src / "sample.exe").write_bytes(b"MZ" + b"\x00" * 256)
    return src


# ---------------------------------------------------------------------------
# 1. Strict resume fingerprint
# ---------------------------------------------------------------------------

def test_same_fingerprint_resumes_without_redoing_completed_phases(tmp_path):
    """A crash-then-resume with the SAME fingerprint honors the checkpoint:
    already-completed phases are not re-run, the failed one onward is."""
    src = tmp_path / "src"
    src.mkdir()
    out = tmp_path / "out.db"
    fingerprint = _fp(source=str(src))
    calls = []

    def make(fail_on_b):
        pl = Pipeline(src, out, parser_name="demo", fingerprint=fingerprint)
        pl.add_phase("a", lambda ctx: calls.append("a") or {"ok": True})

        def phase_b(ctx):
            calls.append("b")
            if fail_on_b:
                raise RuntimeError("boom")
            return {"ok": True}

        pl.add_phase("b", phase_b)
        pl.add_phase("c", lambda ctx: calls.append("c") or {"ok": True})
        return pl

    with pytest.raises(RuntimeError):
        make(fail_on_b=True).run(resume=False)
    assert calls == ["a", "b"]
    assert make(fail_on_b=True).checkpoint_db.exists()

    calls.clear()
    make(fail_on_b=False).run(resume=True)
    # 'a' completed before the crash and must NOT be re-run; resume restarts at 'b'.
    assert calls == ["b", "c"]


def test_default_pipeline_resume_preserves_one_complete_version(tmp_path):
    """#86: crash after ingest and resume under the original run identity."""
    source = tmp_path / "source"
    source.mkdir()
    (source / "sample.exe").write_bytes(b"MZ" + b"\x00" * 256)
    output = tmp_path / "out.db"

    crashed = create_default_pipeline(
        source, output, parser_name="windows", skip_hygeia=True
    )
    crashed.phases[2].handler = _raise
    with pytest.raises(RuntimeError, match="stop"):
        crashed.run(resume=False)

    original_run_id = crashed.context.run_id
    original_version_id = crashed.context.version_id
    assert original_version_id is not None

    resumed = create_default_pipeline(
        source, output, parser_name="windows", skip_hygeia=True
    )

    def add_post_resume_rows():
        conn = open_db(output)
        try:
            cursor = conn.execute(
                "INSERT INTO files (path, filename, file_type) VALUES (?, ?, ?)",
                ("post-resume.txt", "post-resume.txt", "text"),
            )
            entity_id = cursor.lastrowid
            conn.execute(
                "INSERT INTO observations "
                "(entity_table, entity_id, observed_at, event_type) "
                "VALUES (?, ?, ?, ?)",
                ("files", entity_id, "2026-01-01T00:00:00Z", "resume-test"),
            )
            conn.commit()
        finally:
            conn.close()
        return {"post_resume": 1}

    resumed.phases[2].handler = lambda ctx: _run_parser_phase_with_provenance(
        ctx, add_post_resume_rows
    )
    context = resumed.run(resume=True)

    conn = sqlite3.connect(str(output))
    try:
        versions = conn.execute(
            "SELECT id, run_id, entity_count, completed_at FROM versions"
        ).fetchall()
        expected_entity_count = sum(
            conn.execute(
                f"SELECT COUNT(*) FROM {table} WHERE source_version_id = ?",  # nosec B608
                (original_version_id,),
            ).fetchone()[0]
            for table in PROVENANCE_ENTITY_TABLES
        )
        wrong_entities = sum(
            conn.execute(
                f"SELECT COUNT(*) FROM {table} "  # nosec B608
                "WHERE source_version_id IS NULL OR source_version_id != ?",
                (original_version_id,),
            ).fetchone()[0]
            for table in PROVENANCE_ENTITY_TABLES
        )
        observation_total, wrong_observations = conn.execute(
            "SELECT COUNT(*), SUM(version_id IS NULL OR version_id != ?) "
            "FROM observations",
            (original_version_id,),
        ).fetchone()
    finally:
        conn.close()

    assert context.run_id == original_run_id
    assert context.version_id == original_version_id
    assert versions == [
        (original_version_id, original_run_id, expected_entity_count, versions[0][3])
    ]
    assert versions[0][3] is not None
    assert expected_entity_count >= 2
    assert wrong_entities == 0
    assert observation_total == 1
    assert wrong_observations == 0


def _make_crashed_pipeline(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    output = tmp_path / "out.db"
    fingerprint = _fp(source=str(source.resolve()))
    pipeline = Pipeline(source, output, parser_name="demo", fingerprint=fingerprint)
    pipeline.add_phase("complete", lambda ctx: {"ok": True})
    pipeline.add_phase("crash", _raise)
    with pytest.raises(RuntimeError, match="stop"):
        pipeline.run(resume=False)
    return source, output, fingerprint, pipeline


@pytest.mark.parametrize("missing_key", ["run_id", "version_id"])
def test_resume_refuses_missing_checkpoint_version_metadata(tmp_path, missing_key):
    source, output, fingerprint, crashed = _make_crashed_pipeline(tmp_path)
    conn = sqlite3.connect(str(crashed.checkpoint_db))
    conn.execute("DELETE FROM checkpoint_meta WHERE key = ?", (missing_key,))
    conn.commit()
    conn.close()

    resumed = Pipeline(source, output, parser_name="demo", fingerprint=fingerprint)
    resumed.add_phase("complete", lambda ctx: {"ok": True})
    resumed.add_phase("crash", lambda ctx: {"ok": True})
    with pytest.raises(CheckpointProvenanceError, match=f"missing.*{missing_key}"):
        resumed.run(resume=True)


def test_resume_refuses_checkpoint_referencing_missing_version(tmp_path):
    source, output, fingerprint, crashed = _make_crashed_pipeline(tmp_path)
    conn = sqlite3.connect(str(output))
    conn.execute("DELETE FROM versions WHERE id = ?", (crashed.context.version_id,))
    conn.commit()
    conn.close()

    resumed = Pipeline(source, output, parser_name="demo", fingerprint=fingerprint)
    resumed.add_phase("complete", lambda ctx: {"ok": True})
    resumed.add_phase("crash", lambda ctx: {"ok": True})
    with pytest.raises(CheckpointProvenanceError, match="missing versions row"):
        resumed.run(resume=True)


@pytest.mark.parametrize(
    ("column", "value", "expected"),
    [
        ("run_id", "different-run", "run_id"),
        ("parser_name", "different-parser", "parser_name"),
        ("source_path", "different-source", "source_path"),
    ],
)
def test_resume_refuses_mismatched_version_identity(
    tmp_path, column, value, expected
):
    source, output, fingerprint, crashed = _make_crashed_pipeline(tmp_path)
    conn = sqlite3.connect(str(output))
    conn.execute(
        f"UPDATE versions SET {column} = ? WHERE id = ?",  # nosec B608 - test parameter is fixed above
        (value, crashed.context.version_id),
    )
    conn.commit()
    conn.close()

    resumed = Pipeline(source, output, parser_name="demo", fingerprint=fingerprint)
    resumed.add_phase("complete", lambda ctx: {"ok": True})
    resumed.add_phase("crash", lambda ctx: {"ok": True})
    with pytest.raises(CheckpointProvenanceError, match=expected):
        resumed.run(resume=True)


def test_resume_refuses_source_mutated_in_place(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    sample = source / "sample.exe"
    sample.write_bytes(b"MZ" + b"\x00" * 256)
    output = tmp_path / "out.db"

    crashed = create_default_pipeline(
        source, output, parser_name="windows", skip_hygeia=True
    )
    crashed.phases[2].handler = _raise
    with pytest.raises(RuntimeError, match="stop"):
        crashed.run(resume=False)

    sample.write_bytes(b"MZ-mutated" + b"\x00" * 512)
    resumed = create_default_pipeline(
        source, output, parser_name="windows", skip_hygeia=True
    )
    with pytest.raises(CheckpointFingerprintMismatch, match="different source"):
        resumed.run(resume=True)

    conn = sqlite3.connect(str(output))
    try:
        assert conn.execute("SELECT COUNT(*) FROM versions").fetchone()[0] == 1
    finally:
        conn.close()


def test_changed_source_fails_loudly(tmp_path):
    """#45: a checkpoint for source A must not silently resume for source B."""
    parser = _get_windows()
    out = tmp_path / "out.db"
    cfg = {"skip_hygeia": True, "resolve": False}
    fp_a = compute_fingerprint(tmp_path / "srcA", "windows", parser, cfg)
    fp_b = compute_fingerprint(tmp_path / "srcB", "windows", parser, cfg)
    assert fp_a != fp_b  # differ only by resolved source path

    # Lay down a checkpoint stamped with source A's fingerprint.
    pa = Pipeline(tmp_path / "srcA", out, parser_name="windows", fingerprint=fp_a)
    pa.add_phase("init", lambda ctx: {"ok": True})
    pa.add_phase("boom", _raise)
    with pytest.raises(RuntimeError):
        pa.run(resume=False)
    assert pa.checkpoint_db.exists()

    # Now attempt source B into the same output: must refuse, not resume.
    ran = []
    pb = Pipeline(tmp_path / "srcB", out, parser_name="windows", fingerprint=fp_b)
    pb.add_phase("init", lambda ctx: ran.append("init"))
    pb.add_phase("boom", lambda ctx: ran.append("boom"))
    with pytest.raises(CheckpointFingerprintMismatch):
        pb.run(resume=True)
    # Loud failure happened BEFORE any phase executed — no silent DB from A-or-B.
    assert ran == []


def test_changed_parser_fails_loudly(tmp_path):
    """A checkpoint built with one parser must not silently resume under another."""
    src = tmp_path / "src"
    out = tmp_path / "out.db"
    cfg = {"skip_hygeia": True, "resolve": False}
    fp_win = compute_fingerprint(src, "windows", _get_windows(), cfg)
    fp_lin = compute_fingerprint(src, "linux", _get_linux(), cfg)
    assert fp_win != fp_lin

    pw = Pipeline(src, out, parser_name="windows", fingerprint=fp_win)
    pw.add_phase("init", lambda ctx: {"ok": True})
    pw.add_phase("boom", _raise)
    with pytest.raises(RuntimeError):
        pw.run(resume=False)

    ran = []
    pl = Pipeline(src, out, parser_name="linux", fingerprint=fp_lin)
    pl.add_phase("init", lambda ctx: ran.append("init"))
    pl.add_phase("boom", lambda ctx: ran.append("boom"))
    with pytest.raises(CheckpointFingerprintMismatch):
        pl.run(resume=True)
    assert ran == []


# ---------------------------------------------------------------------------
# 2. Existing output refused by default; --fresh succeeds
# ---------------------------------------------------------------------------

def test_existing_output_refused_then_fresh_succeeds(tmp_path):
    from icarus.__main__ import cmd_build

    src = _windows_source(tmp_path)
    out = tmp_path / "out.db"

    # First build creates the output.
    cmd_build(_build_args(src, out, fresh=True))
    assert out.exists()
    first_bytes = out.read_bytes()

    # A plain (resume) build into the existing output is refused — no silent reuse.
    with pytest.raises(OutputExistsError):
        cmd_build(_build_args(src, out, fresh=False))
    assert out.read_bytes() == first_bytes  # untouched by the refusal

    # --fresh performs a clean rebuild and succeeds.
    cmd_build(_build_args(src, out, fresh=True))
    assert out.exists()


# ---------------------------------------------------------------------------
# 3. --fresh atomicity and no-union
# ---------------------------------------------------------------------------

def test_fresh_is_atomic_on_failure(tmp_path, monkeypatch):
    """A mid-build failure under --fresh leaves the destination byte-for-byte
    unchanged and leaves no .tmp sibling behind."""
    from icarus.__main__ import cmd_build
    from icarus.parsers.windows import WindowsParser

    src = _windows_source(tmp_path)
    out = tmp_path / "out.db"

    cmd_build(_build_args(src, out, fresh=True))
    before_bytes = out.read_bytes()
    before_mtime = out.stat().st_mtime_ns

    def _explode(self, source, db_path):
        raise RuntimeError("simulated mid-build failure")

    monkeypatch.setattr(WindowsParser, "extract_entities", _explode)

    with pytest.raises(RuntimeError):
        cmd_build(_build_args(src, out, fresh=True))

    # Destination untouched.
    assert out.read_bytes() == before_bytes
    assert out.stat().st_mtime_ns == before_mtime
    # No temp sibling or its checkpoint left behind.
    leftovers = [p.name for p in tmp_path.iterdir()
                 if p.name.startswith("out.db.") and p.name.endswith(".tmp")]
    assert leftovers == []
    assert not (tmp_path / ".out_checkpoint.db").exists()


def test_fresh_does_not_union_into_existing_output(tmp_path):
    """A stale row in a pre-existing output DB is gone after a --fresh rebuild
    (the destination is replaced, never unioned into)."""
    import sqlite3

    from icarus.__main__ import cmd_build

    src = _windows_source(tmp_path)
    out = tmp_path / "out.db"

    cmd_build(_build_args(src, out, fresh=True))

    # Seed a stale marker row into the existing output.
    conn = sqlite3.connect(str(out))
    try:
        conn.execute(
            "INSERT OR REPLACE INTO metadata VALUES ('STALE_MARKER', 'from_old_build')"
        )
        conn.commit()
    finally:
        conn.close()

    cmd_build(_build_args(src, out, fresh=True))

    conn = sqlite3.connect(str(out))
    try:
        row = conn.execute(
            "SELECT value FROM metadata WHERE key = 'STALE_MARKER'"
        ).fetchone()
    finally:
        conn.close()
    assert row is None  # stale row did not survive — no union


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _raise(ctx):
    raise RuntimeError("stop")


def _get_windows():
    from icarus.parsers import get_parser
    return get_parser("windows")


def _get_linux():
    from icarus.parsers import get_parser
    return get_parser("linux")
