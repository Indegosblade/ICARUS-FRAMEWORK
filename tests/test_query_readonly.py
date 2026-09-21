"""D1 (#34): `icarus query` is read-only by default; writes require `icarus exec`.

These tests build a real, tiny ICARUS database with ``initialize_database`` and
then drive the DEFAULT query path (``IcarusQuery(db)`` / ``cmd_query``) with a
battery of mutation vectors, asserting each is refused and the database is
byte-for-byte unchanged afterwards. The adversarial vectors covered:

  * INSERT / UPDATE / DELETE   — ordinary DML writes to the main database
  * DROP TABLE / CREATE TABLE  — DDL / schema mutation
  * ATTACH / DETACH — rejected by the authorizer before an attachment can create
    a filesystem side effect
  * writable pragmas           — journal_mode / writable_schema cannot re-open
                                 a mutation path

Plus the positive proof that the explicit ``icarus exec`` interface CAN write,
and that a corrupt database file run through ``cmd_query`` exits non-zero with a
clean message rather than a traceback.
"""

import json
import sqlite3
import types
from pathlib import Path

import pytest

from icarus import __main__ as cli
from icarus.core.query import IcarusQuery
from icarus.core.schema import initialize_database, open_db


def _make_db(tmp_path):
    """A real v6 ICARUS database seeded with one known ``files`` row."""
    db = tmp_path / "icarus.db"
    initialize_database(db)
    conn = open_db(db)
    try:
        conn.execute(
            "INSERT INTO files (path, filename) VALUES (?, ?)", ("/seed", "seed")
        )
        conn.commit()
    finally:
        conn.close()
    return db


def _count(db, table="files"):
    conn = open_db(db, readonly=True)
    try:
        return conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
    finally:
        conn.close()


def _table_exists(db, table):
    conn = open_db(db, readonly=True)
    try:
        row = conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table,)
        ).fetchone()
        return row is not None
    finally:
        conn.close()


def _query_args(db, **over):
    ns = types.SimpleNamespace(
        database=str(db), sql=None, search=None, table="files", stats=False
    )
    for k, v in over.items():
        setattr(ns, k, v)
    return ns


def _mark_verified(db):
    """Seed trusted sanitizer evidence for consumer-policy tests."""
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
    conn = sqlite3.connect(str(db))
    try:
        conn.executemany(
            "INSERT OR REPLACE INTO metadata (key, value) VALUES (?, ?)",
            [
                ("hygeia_status", "verified"),
                ("hygeia_engine", json.dumps(engine, sort_keys=True)),
                ("hygeia_audit", json.dumps(audit, sort_keys=True)),
            ],
        )
        conn.commit()
    finally:
        conn.close()


# ── the default query connection is genuinely read-only ─────────────────────

def test_default_query_connection_reports_writable_false(tmp_path):
    db = _make_db(tmp_path)
    with IcarusQuery(str(db)) as q:
        assert q.writable is False
        # A SELECT still works — read-only, not closed.
        assert q.execute("SELECT COUNT(*) FROM files").rows[0][0] == 1

def test_insert_is_refused(tmp_path):
    db = _make_db(tmp_path)
    before = _count(db)
    with IcarusQuery(str(db)) as q:
        with pytest.raises(sqlite3.OperationalError):
            q.execute("INSERT INTO files (path, filename) VALUES ('/x', 'x')")
    assert _count(db) == before


def test_update_is_refused(tmp_path):
    db = _make_db(tmp_path)
    with IcarusQuery(str(db)) as q:
        with pytest.raises(sqlite3.OperationalError):
            q.execute("UPDATE files SET filename = 'clobbered'")
    conn = open_db(db, readonly=True)
    try:
        assert conn.execute("SELECT filename FROM files").fetchone()[0] == "seed"
    finally:
        conn.close()


def test_delete_is_refused(tmp_path):
    db = _make_db(tmp_path)
    before = _count(db)
    with IcarusQuery(str(db)) as q:
        with pytest.raises(sqlite3.OperationalError):
            q.execute("DELETE FROM files")
    assert _count(db) == before


def test_drop_table_is_refused(tmp_path):
    db = _make_db(tmp_path)
    assert _table_exists(db, "files")
    with IcarusQuery(str(db)) as q:
        with pytest.raises(sqlite3.OperationalError):
            q.execute("DROP TABLE files")
    assert _table_exists(db, "files")


def test_create_table_is_refused(tmp_path):
    db = _make_db(tmp_path)
    with IcarusQuery(str(db)) as q:
        with pytest.raises(sqlite3.OperationalError):
            q.execute("CREATE TABLE injected (x INTEGER)")
    assert not _table_exists(db, "injected")


# ── ATTACH / DETACH: no connection-level filesystem side effects ────────────

def test_attach_nonexistent_database_is_refused_before_creation(tmp_path):
    db = _make_db(tmp_path)
    side = tmp_path / "must-not-exist.db"

    with IcarusQuery(str(db)) as q:
        with pytest.raises(sqlite3.DatabaseError, match="not authorized"):
            q.execute("ATTACH DATABASE ? AS side", (str(side),))
    assert not side.exists()
    assert not Path(str(side) + "-wal").exists()
    assert not Path(str(side) + "-shm").exists()


def test_attach_existing_database_is_refused_without_modifying_it(tmp_path):
    db = _make_db(tmp_path)
    side = tmp_path / "existing.db"
    sconn = sqlite3.connect(str(side))
    try:
        sconn.execute("CREATE TABLE t (x INTEGER)")
        sconn.commit()
    finally:
        sconn.close()
    before = side.read_bytes()

    with IcarusQuery(str(db)) as q:
        with pytest.raises(sqlite3.DatabaseError, match="not authorized"):
            q.execute("ATTACH DATABASE ? AS side", (str(side),))
    assert side.read_bytes() == before


def test_detach_is_refused_by_read_only_authorizer(tmp_path):
    db = _make_db(tmp_path)
    with IcarusQuery(str(db)) as q:
        with pytest.raises(sqlite3.DatabaseError, match="not authorized"):
            q.execute("DETACH DATABASE main")


# ── writable pragmas cannot re-open a mutation path ─────────────────────────

def test_writable_pragmas_do_not_enable_mutation(tmp_path):
    db = _make_db(tmp_path)
    before = _count(db)
    with IcarusQuery(str(db)) as q:
        # Neither of these must open a write path on a read-only connection.
        for pragma in ("PRAGMA journal_mode = DELETE", "PRAGMA writable_schema = ON"):
            try:
                q.conn.execute(pragma)
            except sqlite3.OperationalError:
                pass  # refused outright is fine too
        with pytest.raises(sqlite3.OperationalError):
            q.conn.execute("INSERT INTO files (path, filename) VALUES ('/z', 'z')")
        with pytest.raises(sqlite3.OperationalError):
            q.conn.execute("UPDATE sqlite_master SET name = name")
    assert _count(db) == before


# ── cmd_query surfaces the read-only barrier with a clear exit code ──────────

def test_cmd_query_write_gives_clean_readonly_error(tmp_path, capsys):
    db = _make_db(tmp_path)
    args = _query_args(
        db,
        sql="INSERT INTO files (path, filename) VALUES ('/y', 'y')",
        allow_unverified=True,
    )
    with pytest.raises(SystemExit) as exc:
        cli.cmd_query(args)
    assert exc.value.code != 0
    err = capsys.readouterr().err
    assert "read-only" in err
    assert "icarus exec" in err
    assert "Traceback" not in err
    assert _count(db) == 1


# ── the explicit exec interface CAN write ───────────────────────────────────

def test_exec_can_insert(tmp_path, capsys):
    db = _make_db(tmp_path)
    _mark_verified(db)
    before = _count(db)
    args = types.SimpleNamespace(
        database=str(db),
        sql="INSERT INTO files (path, filename) VALUES ('/added', 'added')",
    )
    cli.cmd_exec(args)
    out = capsys.readouterr()
    assert "Rows affected: 1" in out.out
    assert "READ-WRITE" in out.err  # the mutating-notice
    assert _count(db) == before + 1
    conn = sqlite3.connect(str(db))
    try:
        assert conn.execute(
            "SELECT value FROM metadata WHERE key = 'hygeia_status'"
        ).fetchone() is None
        assert conn.execute(
            "SELECT value FROM metadata WHERE key = 'hygeia_audit'"
        ).fetchone() is None
        assert conn.execute(
            "SELECT value FROM metadata WHERE key = 'hygeia_engine'"
        ).fetchone() is None
    finally:
        conn.close()


def test_exec_failure_keeps_verified_evidence(tmp_path, capsys):
    """The content write and trust invalidation are one transaction."""
    from icarus.integrations.hygeia import sanitization_status

    db = _make_db(tmp_path)
    _mark_verified(db)
    args = types.SimpleNamespace(
        database=str(db),
        sql="INSERT INTO files (path, filename) VALUES ('/seed', 'duplicate')",
    )
    with pytest.raises(SystemExit) as exc:
        cli.cmd_exec(args)
    assert exc.value.code == 1
    assert "exec failed" in capsys.readouterr().err
    assert sanitization_status(db) == "verified"


def test_icarusquery_writable_can_insert(tmp_path):
    db = _make_db(tmp_path)
    before = _count(db)
    with IcarusQuery(str(db), writable=True) as q:
        q.conn.execute("INSERT INTO files (path, filename) VALUES ('/rw', 'rw')")
        q.commit()
    assert _count(db) == before + 1


# ── corrupt input: clean non-zero exit, no traceback ────────────────────────

def test_corrupt_database_clean_exit(tmp_path, capsys):
    bad = tmp_path / "corrupt.db"
    bad.write_bytes(b"NOT-A-SQLITE-DATABASE " * 64)
    args = _query_args(bad, sql="SELECT COUNT(*) FROM files")
    with pytest.raises(SystemExit) as exc:
        cli.cmd_query(args)
    assert exc.value.code != 0
    err = capsys.readouterr().err
    assert "ERROR" in err
    assert "Traceback" not in err


# ── #77: query refuses a database whose sanitization FAILED ──────────────────

def test_query_refuses_sanitization_failed_database(tmp_path, capsys):
    from icarus.integrations.hygeia import mark_sanitization_failed

    db = _make_db(tmp_path)
    mark_sanitization_failed(db)  # stamp FAILED, as a failed sanitize phase now does

    args = _query_args(db, sql="SELECT path FROM files")
    with pytest.raises(SystemExit) as exc:
        cli.cmd_query(args)
    assert exc.value.code == 3
    out = capsys.readouterr()
    assert "not sanitization-verified" in out.err and "not safe" in out.err
    assert "/seed" not in out.out  # the unsanitized row was never emitted


def test_allow_unverified_queries_a_failed_database(tmp_path, capsys):
    from icarus.integrations.hygeia import mark_sanitization_failed

    db = _make_db(tmp_path)
    mark_sanitization_failed(db)

    args = _query_args(db, sql="SELECT path FROM files", allow_unverified=True)
    cli.cmd_query(args)
    assert "/seed" in capsys.readouterr().out


def test_query_allows_verified_and_skipped_databases(tmp_path, capsys):
    db = _make_db(tmp_path)
    _mark_verified(db)
    cli.cmd_query(_query_args(db, stats=True))
    assert capsys.readouterr().err == ""  # verified: no gate, no noise

    conn = sqlite3.connect(str(db))
    conn.execute("DELETE FROM metadata WHERE key LIKE 'hygeia_%'")
    conn.execute(
        "INSERT OR REPLACE INTO metadata (key, value) VALUES ('hygeia_skipped', 'true')"
    )
    conn.commit()
    conn.close()
    cli.cmd_query(_query_args(db, stats=True))
    assert capsys.readouterr().err == ""  # explicit skip remains allowed


def test_query_refuses_unknown_database_without_override(tmp_path, capsys):
    db = _make_db(tmp_path)
    with pytest.raises(SystemExit) as exc:
        cli.cmd_query(_query_args(db, sql="SELECT path FROM files"))
    assert exc.value.code == 3
    assert "not sanitization-verified" in capsys.readouterr().err

    cli.cmd_query(_query_args(db, sql="SELECT path FROM files", allow_unverified=True))
    assert "/seed" in capsys.readouterr().out
