"""Partial atomization cannot leave older trust evidence on committable writes."""

import sqlite3
from contextlib import closing

import pytest

from icarus.core.atomize import ATOM_PROJECTIONS, ProjectionSpec, atomize_db
from icarus.core.schema import initialize_database
from icarus.integrations.hygeia import sanitization_status


@pytest.fixture
def atom_db(tmp_path):
    path = tmp_path / "atoms.db"
    initialize_database(path)
    with closing(sqlite3.connect(path)) as conn:
        conn.execute(
            "INSERT INTO versions (run_id, parser_name, source_path, started_at) "
            "VALUES ('atom-transactions', 'test', '/source', '2026-01-01T00:00:00Z')"
        )
        conn.execute("INSERT INTO files (path, filename) VALUES ('/tool', 'tool')")
        conn.execute("INSERT INTO metadata VALUES ('hygeia_skipped', 'true')")
        conn.commit()
    return path


@pytest.mark.parametrize("decision", ["commit", "rollback"])
def test_later_projection_failure_leaves_trust_consistent_with_caller_decision(
    atom_db, monkeypatch, decision,
):
    monkeypatch.setitem(ATOM_PROJECTIONS, "broken", ProjectionSpec(
        "broken", "SELECT missing FROM nonexistent_source_table", ["missing"],
    ))
    with closing(sqlite3.connect(atom_db)) as conn:
        conn.execute("INSERT INTO metadata VALUES ('caller-owned', 'pending')")
        with pytest.raises(sqlite3.OperationalError, match="nonexistent_source_table"):
            atomize_db(conn, conn, 1, ["files", "broken"])
        assert conn.in_transaction
        if decision == "commit":
            conn.commit()
            assert conn.execute("SELECT COUNT(*) FROM atoms").fetchone() == (1,)
            assert conn.execute(
                "SELECT value FROM metadata WHERE key = 'caller-owned'"
            ).fetchone() == ("pending",)
            assert sanitization_status(atom_db) == "unknown"
        else:
            conn.rollback()
            assert conn.execute("SELECT COUNT(*) FROM atoms").fetchone() == (0,)
            assert conn.execute(
                "SELECT value FROM metadata WHERE key = 'caller-owned'"
            ).fetchone() is None
            assert sanitization_status(atom_db) == "skipped"


def test_revocation_failure_cannot_leave_first_atom_committable(atom_db):
    with closing(sqlite3.connect(atom_db)) as conn:
        conn.executescript(
            "CREATE TRIGGER refuse_trust_removal BEFORE DELETE ON metadata "
            "WHEN OLD.key = 'hygeia_skipped' "
            "BEGIN SELECT RAISE(ABORT, 'injected trust removal failure'); END;"
        )
        conn.execute("INSERT INTO metadata VALUES ('caller-owned', 'preserve')")
        with pytest.raises(sqlite3.IntegrityError, match="trust removal"):
            atomize_db(conn, conn, 1, ["files"])
        conn.commit()
        assert conn.execute("SELECT COUNT(*) FROM atoms").fetchone() == (0,)
        assert conn.execute(
            "SELECT value FROM metadata WHERE key = 'caller-owned'"
        ).fetchone() == ("preserve",)
    assert sanitization_status(atom_db) == "skipped"


def test_noop_atomization_preserves_current_trust(atom_db):
    with closing(sqlite3.connect(atom_db)) as conn:
        assert atomize_db(conn, conn, 1, ["files"]) == {"files": 1}
        conn.execute("INSERT INTO metadata VALUES ('hygeia_skipped', 'true')")
        conn.commit()
        assert atomize_db(conn, conn, 1, ["files"]) == {"files": 0}
    assert sanitization_status(atom_db) == "skipped"
