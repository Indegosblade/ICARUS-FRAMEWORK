"""Cross-source resolution publishes only complete, freshly sanitized snapshots."""

import argparse
import re
import sqlite3
import subprocess
import sys
from contextlib import closing

import pytest

from icarus.__main__ import cmd_resolve
from icarus.core.atomize import atomize_db
from icarus.core.build_lock import output_lease
from icarus.core.resolver import EntityResolver
from icarus.core.schema import initialize_database
from icarus.integrations import hygeia as hygeia_mod


def _source(path, *, status="skipped", secret=False):
    path.parent.mkdir(parents=True, exist_ok=True)
    initialize_database(path)
    with closing(sqlite3.connect(path)) as conn:
        conn.execute(
            "INSERT INTO versions (run_id, parser_name, source_path, started_at, completed_at) "
            "VALUES ('source', 'test', '/src', '2026-01-01T00:00:00Z', '2026-01-01T00:00:01Z')"
        )
        conn.execute(
            "INSERT INTO files (path, filename, sha256, file_type) VALUES (?, 'tool', 'abc', ?)",
            ("/usr/bin/tool", "password=OnlySyntheticSecretValue" if secret else "binary"),
        )
        if status == "skipped":
            conn.execute("INSERT INTO metadata VALUES ('hygeia_skipped', 'true')")
        elif status == "failed":
            conn.execute("INSERT INTO metadata VALUES ('hygeia_status', 'FAILED: test')")
        conn.commit()
    return path


def _args(output, *sources, allow_unverified=False, atomize_only=False):
    return argparse.Namespace(
        out=str(output), sources=[str(source) for source in sources], entity_type="files",
        threshold=0.85, atomize_only=atomize_only, allow_unverified=allow_unverified,
    )


def test_existing_output_is_refused_without_writes(tmp_path):
    source = _source(tmp_path / "source.db")
    output = _source(tmp_path / "existing.db")
    before = output.read_bytes()
    with pytest.raises(ValueError, match="already exists"):
        cmd_resolve(_args(output, source))
    assert output.read_bytes() == before


def test_missing_later_source_never_publishes_partial_output(tmp_path):
    source = _source(tmp_path / "source.db")
    output = tmp_path / "resolved.db"
    with pytest.raises((ValueError, FileNotFoundError, SystemExit)):
        cmd_resolve(_args(output, source, tmp_path / "missing.db"))
    assert not output.exists()


def test_corrupt_later_source_never_publishes_partial_output(tmp_path):
    source = _source(tmp_path / "source.db")
    corrupt = tmp_path / "corrupt.db"
    corrupt.write_bytes(b"not a SQLite database")
    output = tmp_path / "resolved.db"
    with pytest.raises(ValueError, match="Could not resolve source"):
        cmd_resolve(_args(output, source, corrupt, allow_unverified=True))
    assert not output.exists()
    assert not [path for path in tmp_path.iterdir() if path.name.endswith(".tmp")]


def test_duplicate_source_is_not_counted_as_independent_evidence(tmp_path):
    source = _source(tmp_path / "source.db")
    output = tmp_path / "resolved.db"
    with pytest.raises(ValueError, match="distinct"):
        cmd_resolve(_args(output, source, source))
    assert not output.exists()


def test_source_output_alias_is_refused(tmp_path):
    source = _source(tmp_path / "source.db")
    before = source.read_bytes()
    with pytest.raises(ValueError, match="source|input|alias"):
        cmd_resolve(_args(source, source))
    assert source.read_bytes() == before


@pytest.mark.parametrize("status", ["unknown", "failed"])
def test_default_resolution_refuses_unverified_inputs(tmp_path, status):
    source = _source(tmp_path / "source.db", status=status)
    output = tmp_path / "resolved.db"
    with pytest.raises(ValueError, match="allow-unverified"):
        cmd_resolve(_args(output, source))
    assert not output.exists()


def test_nonempty_source_wal_is_refused_even_with_override(tmp_path):
    source = _source(tmp_path / "source.db")
    output = tmp_path / "resolved.db"
    with closing(sqlite3.connect(source)) as conn:
        conn.execute("PRAGMA journal_mode = WAL")
        conn.execute("INSERT INTO files (path, filename) VALUES ('/later', 'later')")
        conn.commit()
        assert (tmp_path / "source.db-wal").stat().st_size > 0
        with pytest.raises(ValueError, match="WAL|checkpoint"):
            cmd_resolve(_args(output, source, allow_unverified=True))
    assert not output.exists()


@pytest.mark.parametrize("atomize_only", [False, True])
def test_resolution_output_is_newly_sanitized_and_finalized(tmp_path, atomize_only):
    source = _source(tmp_path / "Users" / "synthetic-user" / "source.db", secret=True)
    output = tmp_path / "resolved.db"
    cmd_resolve(_args(output, source, atomize_only=atomize_only))
    assert hygeia_mod.sanitization_status(output, immutable=True) == "verified"
    assert hygeia_mod.verify_clean(output)["passed"] is True
    with closing(sqlite3.connect(output)) as conn:
        assert "OnlySyntheticSecretValue" not in conn.execute(
            "SELECT properties FROM atoms"
        ).fetchone()[0]
        versions = conn.execute(
            "SELECT source_path, completed_at, entity_count FROM versions"
        ).fetchall()
        assert len(versions) == 1
        assert not re.search(
            r"(?:[A-Za-z]:\\Users\\|/(?:Users|home)/)[^\\/\s]+", versions[0][0]
        )
        assert versions[0][1] is not None
        assert versions[0][2] == 1
        assert conn.execute("PRAGMA foreign_key_check").fetchall() == []


def test_input_override_never_bypasses_output_sanitization(tmp_path):
    source = _source(tmp_path / "source.db", status="failed", secret=True)
    output = tmp_path / "resolved.db"
    cmd_resolve(_args(output, source, allow_unverified=True))
    assert hygeia_mod.sanitization_status(output, immutable=True) == "verified"
    assert hygeia_mod.verify_clean(output)["passed"]


def test_sanitizer_failure_publishes_nothing(tmp_path, monkeypatch):
    source = _source(tmp_path / "source.db")
    output = tmp_path / "resolved.db"

    def fail(_path):
        raise hygeia_mod.SanitizationError("injected sanitizer failure")

    monkeypatch.setattr(hygeia_mod, "sanitize_output", fail)
    with pytest.raises(hygeia_mod.SanitizationError, match="injected"):
        cmd_resolve(_args(output, source))
    assert not output.exists()
    assert not [path for path in tmp_path.iterdir() if path.name.endswith(".tmp")]


def test_final_audit_failure_publishes_nothing(tmp_path, monkeypatch):
    source = _source(tmp_path / "source.db")
    output = tmp_path / "resolved.db"
    monkeypatch.setattr(hygeia_mod, "verify_clean", lambda _path: {
        "passed": False, "total_findings": 1, "patterns_found": {"test": 1},
    })
    with pytest.raises(hygeia_mod.SanitizationError, match="Final post-write"):
        cmd_resolve(_args(output, source))
    assert not output.exists()


def test_audit_publication_failure_publishes_nothing(tmp_path, monkeypatch):
    source = _source(tmp_path / "source.db")
    output = tmp_path / "resolved.db"

    def fail(*_args):
        raise RuntimeError("injected audit failure")

    monkeypatch.setattr(hygeia_mod, "_record_finalized_audit", fail)
    with pytest.raises(hygeia_mod.SanitizationError, match="publish finalized"):
        cmd_resolve(_args(output, source))
    assert not output.exists()


def test_resolution_preserves_input_bytes_and_literal_source_names(tmp_path):
    source = _source(tmp_path / "input #1% complete.db")
    before = source.read_bytes()
    output = tmp_path / "resolved #1% complete.db"
    cmd_resolve(_args(output, source))
    assert source.read_bytes() == before
    assert hygeia_mod.sanitization_status(output, immutable=True) == "verified"


def test_real_verified_marker_is_revoked_by_mutation_and_restored_by_rollback(tmp_path):
    source = _source(tmp_path / "source.db")
    output = tmp_path / "resolved.db"
    cmd_resolve(_args(output, source))
    assert hygeia_mod.sanitization_status(output) == "verified"
    with EntityResolver(str(output), experimental=True) as resolver:
        resolver.conn.execute("BEGIN")
        resolver.ingest_atom(1, "files", "new", {"password": "OnlySyntheticSecretValue"})
        assert resolver.conn.execute(
            "SELECT value FROM metadata WHERE key = 'hygeia_status'"
        ).fetchone() is None
        resolver.conn.rollback()
        assert hygeia_mod.sanitization_status(output) == "verified"
        resolver.ingest_atom(1, "files", "new", {"password": "OnlySyntheticSecretValue"})
    assert hygeia_mod.sanitization_status(output) == "unknown"


def test_atomization_invalidates_trust_in_its_content_commit(tmp_path):
    source = _source(tmp_path / "source.db", secret=True)
    with closing(sqlite3.connect(source)) as conn:
        assert atomize_db(conn, conn, 1, ["files"]) == {"files": 1}
    assert hygeia_mod.sanitization_status(source) == "unknown"


def test_cli_recovery_publishes_output_accepted_by_normal_query(tmp_path):
    source = _source(tmp_path / "source.db", status="unknown", secret=True)
    output = tmp_path / "resolved.db"
    resolved = subprocess.run(
        [sys.executable, "-m", "icarus", "resolve", "--out", str(output),
         "--entity-type", "files", "--allow-unverified", str(source)],
        capture_output=True, text=True, timeout=30,
    )
    assert resolved.returncode == 0, resolved.stderr
    queried = subprocess.run(
        [sys.executable, "-m", "icarus", "query", str(output), "--stats"],
        capture_output=True, text=True, timeout=30,
    )
    assert queried.returncode == 0, queried.stderr
    assert "atoms: 1" in queried.stdout


def test_cli_resolution_respects_destination_lease(tmp_path):
    source = _source(tmp_path / "source.db")
    output = tmp_path / "resolved.db"
    with output_lease(output):
        result = subprocess.run(
            [sys.executable, "-m", "icarus", "resolve", "--out", str(output), str(source)],
            capture_output=True, text=True, timeout=30,
        )
    assert result.returncode == 1
    assert "Another ICARUS build" in result.stderr
    assert "Traceback" not in result.stderr
    assert not output.exists()


def test_appearing_destination_is_preserved(tmp_path, monkeypatch):
    source = _source(tmp_path / "source.db")
    output = tmp_path / "resolved.db"
    original_finalize = hygeia_mod.finalize_sanitization

    def external_writer(path):
        result = original_finalize(path)
        output.write_bytes(b"unrelated external output")
        return result

    monkeypatch.setattr(hygeia_mod, "finalize_sanitization", external_writer)
    with pytest.raises(ValueError, match="appeared"):
        cmd_resolve(_args(output, source))
    assert output.read_bytes() == b"unrelated external output"


def test_successful_resolver_mutation_invalidates_content_trust(tmp_path):
    path = _source(tmp_path / "source.db")
    with EntityResolver(str(path), experimental=True) as resolver:
        resolver.ingest_atom(1, "files", "new", {"password": "OnlySyntheticSecretValue"})
    assert hygeia_mod.sanitization_status(path) == "unknown"


def test_failed_resolver_mutation_preserves_prior_trust(tmp_path):
    path = _source(tmp_path / "source.db")
    with EntityResolver(str(path), experimental=True) as resolver:
        with pytest.raises(ValueError):
            resolver.create_bag("files", [999])
    assert hygeia_mod.sanitization_status(path) == "skipped"
