"""Mutation-boundary regressions for resolver issue #46."""

import sqlite3

import pytest

from icarus.core.resolver import EntityResolver
from icarus.core.schema import initialize_database


@pytest.fixture
def resolver_db(tmp_path):
    path = tmp_path / "resolver.db"
    initialize_database(path)
    conn = sqlite3.connect(path)
    conn.execute(
        "INSERT INTO versions (run_id, parser_name, source_path, started_at) "
        "VALUES ('resolver-invariants', 'test', '/test', '2026-09-25T00:00:00Z')"
    )
    conn.commit()
    conn.close()
    return path


def test_create_bag_rejects_invalid_atoms_without_partial_bag(resolver_db):
    with EntityResolver(str(resolver_db), experimental=True) as resolver:
        atom = resolver.ingest_atom(1, "files", "file-a", {"filename": "a"})

        with pytest.raises(ValueError, match="Unknown atom"):
            resolver.create_bag("files", [atom, 9999])

        assert resolver.conn.execute("SELECT COUNT(*) FROM bags").fetchone()[0] == 0
        assert resolver.conn.execute("SELECT COUNT(*) FROM bag_atoms").fetchone()[0] == 0
        assert resolver.conn.execute(
            "SELECT COUNT(*) FROM resolution_event_log"
        ).fetchone()[0] == 0


def test_create_bag_validates_type_and_membership(resolver_db):
    with EntityResolver(str(resolver_db), experimental=True) as resolver:
        atom = resolver.ingest_atom(1, "files", "file-a", {"filename": "a"})

        with pytest.raises(ValueError, match="do not match entity type"):
            resolver.create_bag("binaries", [atom])

        resolver.create_bag("files", [atom])
        with pytest.raises(ValueError, match="already belong"):
            resolver.create_bag("files", [atom])


def test_merge_validates_all_bags_before_writing(resolver_db):
    with EntityResolver(str(resolver_db), experimental=True) as resolver:
        first = resolver.ingest_atom(1, "files", "file-a", {"filename": "a"})
        second = resolver.ingest_atom(1, "files", "file-b", {"filename": "b"})
        bag = resolver.create_bag("files", [first])
        resolver.create_bag("files", [second])
        events_before = resolver.conn.execute(
            "SELECT COUNT(*) FROM resolution_event_log"
        ).fetchone()[0]

        with pytest.raises(ValueError, match="Unknown bag"):
            resolver.merge_bags([bag, 9999])

        assert resolver.conn.execute("SELECT COUNT(*) FROM bags").fetchone()[0] == 2
        assert resolver.conn.execute(
            "SELECT COUNT(*) FROM resolution_event_log"
        ).fetchone()[0] == events_before


def test_split_rejects_nonmembers_without_fictional_bag_or_event(resolver_db):
    with EntityResolver(str(resolver_db), experimental=True) as resolver:
        first = resolver.ingest_atom(1, "files", "file-a", {"filename": "a"})
        second = resolver.ingest_atom(1, "files", "file-b", {"filename": "b"})
        bag = resolver.create_bag("files", [first, second])
        events_before = resolver.conn.execute(
            "SELECT COUNT(*) FROM resolution_event_log"
        ).fetchone()[0]

        with pytest.raises(ValueError, match="not members"):
            resolver.split_bag(bag, [9999])

        assert resolver.conn.execute("SELECT COUNT(*) FROM bags").fetchone()[0] == 1
        assert resolver.conn.execute(
            "SELECT atom_count FROM bags WHERE id = ?", (bag,)
        ).fetchone()[0] == 2
        assert resolver.conn.execute(
            "SELECT COUNT(*) FROM resolution_event_log"
        ).fetchone()[0] == events_before


@pytest.mark.parametrize("threshold", [-0.01, 1.01, float("nan"), float("inf")])
def test_resolve_scored_rejects_out_of_range_threshold(resolver_db, threshold):
    with EntityResolver(str(resolver_db), experimental=True) as resolver:
        with pytest.raises(ValueError, match="between 0.0 and 1.0"):
            resolver.resolve_scored("files", threshold=threshold)
