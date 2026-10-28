"""Tests for wiring the entity resolver to users (increment 4/4).

Covers the CLI/pipeline plumbing added on top of the already-tested engine
(``EntityResolver.resolve_scored`` itself is covered by
``tests/test_resolve_scored.py``; this file does not repeat those cases):

* ``icarus resolve`` end-to-end — atomizing two source databases that share
  an identical (executable_name, sha256, path) binary produces a bag whose
  atoms span both sources; ``--atomize-only`` stops before any bag exists.
* ``create_default_pipeline(..., resolve=True)`` inserts a "resolve" phase
  after "verify" and before the sanitize/skip_hygeia_marker phase, and running
  the pipeline with that phase enabled populates ``atoms``/``bags`` in the
  output database.
* ``resolve=False`` (the default) leaves the phase list exactly as before.
"""

import argparse
import sqlite3
from pathlib import Path

import pytest

from icarus.__main__ import cmd_resolve
from icarus.core.pipeline import create_default_pipeline
from icarus.core.schema import initialize_database

LINUX_FIXTURE = Path(__file__).parent / "fixtures" / "linux"


def _make_source_db(path: Path, run_id: str, executable_name: str, sha256: str) -> None:
    """A tiny v6 source DB: one versions row, one files+binaries row.

    Both callers use the same executable_name/sha256/path so the two
    resulting atoms score a perfect match under the default "binaries"
    scoring spec (sha256 + executable_name + path all agree; arch is left
    NULL on both sides, so it is skipped rather than compared).
    """
    initialize_database(path)
    conn = sqlite3.connect(str(path))
    try:
        conn.execute(
            "INSERT INTO versions (run_id, parser_name, source_path, started_at) "
            "VALUES (?, 'test', '/src', '2026-01-01T00:00:00Z')",
            (run_id,),
        )
        file_path = f"/usr/bin/{executable_name}"
        conn.execute(
            "INSERT INTO files (path, filename, sha256) VALUES (?, ?, ?)",
            (file_path, executable_name, sha256),
        )
        file_id = conn.execute(
            "SELECT id FROM files WHERE path = ?", (file_path,)
        ).fetchone()[0]
        conn.execute(
            "INSERT INTO binaries (file_id, executable_name) VALUES (?, ?)",
            (file_id, executable_name),
        )
        # Synthetic fixtures deliberately opt into the documented raw-input
        # posture. Resolution independently sanitizes its new output.
        conn.execute("INSERT INTO metadata VALUES ('hygeia_skipped', 'true')")
        conn.commit()
    finally:
        conn.close()


# ── `icarus resolve` end-to-end ──────────────────────────────────────────


def test_cmd_resolve_merges_matching_binary_across_sources(tmp_path):
    src_a = tmp_path / "src_a.db"
    src_b = tmp_path / "src_b.db"
    _make_source_db(src_a, "run-a", "shared_bin", "deadbeef")
    _make_source_db(src_b, "run-b", "shared_bin", "deadbeef")
    out_path = tmp_path / "out.db"

    ns = argparse.Namespace(
        out=str(out_path),
        entity_type="binaries",
        sources=[str(src_a), str(src_b)],
        threshold=0.85,
        atomize_only=False,
    )
    cmd_resolve(ns)

    assert out_path.exists()
    conn = sqlite3.connect(str(out_path))
    try:
        # One "binaries" atom projected per source.
        assert conn.execute("SELECT COUNT(*) FROM atoms").fetchone()[0] == 2

        # At least one bag whose atoms span >= 2 distinct source_version_id
        # (i.e. a genuine cross-source canonical entity).
        spanning = conn.execute(
            "SELECT bag_id FROM bag_atoms ba JOIN atoms a ON a.id = ba.atom_id "
            "GROUP BY bag_id HAVING COUNT(DISTINCT a.source_version_id) >= 2"
        ).fetchall()
        assert len(spanning) >= 1

        # That bag's score was persisted and the match was recorded/auditable.
        bag_id = spanning[0][0]
        score = conn.execute(
            "SELECT score FROM bags WHERE id = ?", (bag_id,)
        ).fetchone()[0]
        assert score is not None and score >= 0.85
        assert conn.execute("SELECT COUNT(*) FROM match_candidates").fetchone()[0] >= 1
    finally:
        conn.close()


def test_cmd_resolve_rejects_threshold_above_one(tmp_path, capsys):
    """#30: --threshold documents [0, 1] but out-of-range values were
    accepted silently. Must now exit non-zero with a clear message and
    never touch the output database."""
    src_a = tmp_path / "src_a.db"
    src_b = tmp_path / "src_b.db"
    _make_source_db(src_a, "run-a", "shared_bin", "deadbeef")
    _make_source_db(src_b, "run-b", "shared_bin", "deadbeef")
    out_path = tmp_path / "out.db"

    ns = argparse.Namespace(
        out=str(out_path),
        entity_type="binaries",
        sources=[str(src_a), str(src_b)],
        threshold=1.5,
        atomize_only=False,
    )
    try:
        cmd_resolve(ns)
        raised = False
    except SystemExit as exc:
        raised = True
        assert exc.code != 0

    assert raised, "cmd_resolve accepted an out-of-range --threshold"
    assert "threshold" in capsys.readouterr().err.lower()
    assert not out_path.exists()


def test_cmd_resolve_rejects_negative_threshold(tmp_path, capsys):
    src_a = tmp_path / "src_a.db"
    src_b = tmp_path / "src_b.db"
    _make_source_db(src_a, "run-a", "shared_bin", "deadbeef")
    _make_source_db(src_b, "run-b", "shared_bin", "deadbeef")
    out_path = tmp_path / "out.db"

    ns = argparse.Namespace(
        out=str(out_path),
        entity_type="binaries",
        sources=[str(src_a), str(src_b)],
        threshold=-0.1,
        atomize_only=False,
    )
    with pytest.raises(SystemExit) as exc_info:
        cmd_resolve(ns)
    assert exc_info.value.code != 0
    assert "threshold" in capsys.readouterr().err.lower()


def test_cmd_resolve_accepts_threshold_boundaries(tmp_path):
    """0.0 and 1.0 are valid boundary values, not rejected."""
    src_a = tmp_path / "src_a.db"
    src_b = tmp_path / "src_b.db"
    _make_source_db(src_a, "run-a", "shared_bin", "deadbeef")
    _make_source_db(src_b, "run-b", "shared_bin", "deadbeef")

    for boundary in (0.0, 1.0):
        out_path = tmp_path / f"out_{boundary}.db"
        ns = argparse.Namespace(
            out=str(out_path),
            entity_type="binaries",
            sources=[str(src_a), str(src_b)],
            threshold=boundary,
            atomize_only=True,
        )
        cmd_resolve(ns)
        assert out_path.exists()


def test_cmd_resolve_atomize_only_skips_resolution(tmp_path):
    """--atomize-only stops after atomizing: atoms exist, but no bags do."""
    src_a = tmp_path / "src_a.db"
    src_b = tmp_path / "src_b.db"
    _make_source_db(src_a, "run-a", "shared_bin", "deadbeef")
    _make_source_db(src_b, "run-b", "shared_bin", "deadbeef")
    out_path = tmp_path / "out.db"

    ns = argparse.Namespace(
        out=str(out_path),
        entity_type="binaries",
        sources=[str(src_a), str(src_b)],
        threshold=0.85,
        atomize_only=True,
    )
    cmd_resolve(ns)

    conn = sqlite3.connect(str(out_path))
    try:
        assert conn.execute("SELECT COUNT(*) FROM atoms").fetchone()[0] == 2
        assert conn.execute("SELECT COUNT(*) FROM bags").fetchone()[0] == 0
    finally:
        conn.close()


def test_cmd_resolve_entity_type_all_resolves_every_projected_type(tmp_path):
    """--entity-type all (the default) resolves every ATOM_PROJECTIONS type."""
    src_a = tmp_path / "src_a.db"
    src_b = tmp_path / "src_b.db"
    _make_source_db(src_a, "run-a", "shared_bin", "deadbeef")
    _make_source_db(src_b, "run-b", "shared_bin", "deadbeef")
    out_path = tmp_path / "out.db"

    ns = argparse.Namespace(
        out=str(out_path),
        entity_type="all",
        sources=[str(src_a), str(src_b)],
        threshold=0.85,
        atomize_only=False,
    )
    cmd_resolve(ns)

    conn = sqlite3.connect(str(out_path))
    try:
        # No daemons/frameworks/kexts in either source, but resolving "all" must
        # not error out on those empty types. _make_source_db's one `files` row
        # per source (the binaries FK target) is itself now a projected type
        # too, so each source contributes 1 binaries + 1 files atom (4 total),
        # and both pairs (same path/filename/sha256, same executable_name)
        # cross-source merge.
        assert conn.execute("SELECT COUNT(*) FROM atoms").fetchone()[0] == 4
        assert conn.execute(
            "SELECT COUNT(*) FROM bag_atoms ba JOIN atoms a ON a.id = ba.atom_id "
            "GROUP BY ba.bag_id HAVING COUNT(DISTINCT a.source_version_id) >= 2"
        ).fetchall()
    finally:
        conn.close()


# ── `icarus build --resolve` phase wiring ────────────────────────────────


def test_resolve_phase_inserted_after_verify_before_sanitize(tmp_path):
    pipeline = create_default_pipeline(
        LINUX_FIXTURE, tmp_path / "unused.db", "linux", resolve=True
    )
    names = [p.name for p in pipeline.phases]
    assert "resolve" in names
    assert names.index("resolve") > names.index("verify")
    sanitize_name = "sanitize" if "sanitize" in names else "skip_hygeia_marker"
    assert sanitize_name in names
    assert names.index("resolve") < names.index(sanitize_name)


def test_resolve_phase_absent_by_default(tmp_path):
    """resolve=False (the default) must not change the existing phase list."""
    pipeline = create_default_pipeline(LINUX_FIXTURE, tmp_path / "unused.db", "linux")
    assert "resolve" not in [p.name for p in pipeline.phases]


def test_build_with_resolve_populates_atoms_and_bags(tmp_path):
    out = tmp_path / "linux_resolved.db"
    pipeline = create_default_pipeline(
        LINUX_FIXTURE, out, "linux", skip_hygeia=True, resolve=True
    )
    pipeline.run(resume=False)

    conn = sqlite3.connect(str(out))
    try:
        assert conn.execute("SELECT COUNT(*) FROM atoms").fetchone()[0] > 0
        assert conn.execute("SELECT COUNT(*) FROM bags").fetchone()[0] > 0
    finally:
        conn.close()
