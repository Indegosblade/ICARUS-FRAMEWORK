"""Resolution mutations preserve history and expose only current memberships."""

import json
import sqlite3
import threading
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing

import pytest

from icarus.core.differ import IcarusDiffer
from icarus.core.resolver import EntityResolver
from icarus.core.schema import initialize_database


@pytest.fixture
def resolver(tmp_path):
    path = tmp_path / "history.db"
    initialize_database(path)
    with closing(sqlite3.connect(path)) as conn:
        conn.execute(
            "INSERT INTO versions (run_id, parser_name, source_path, started_at) "
            "VALUES ('history', 'test', '/test', '2026-01-01T00:00:00Z')"
        )
        conn.commit()
    with EntityResolver(str(path), experimental=True) as result:
        yield result


def _bags(resolver):
    atoms = [resolver.ingest_atom(1, "files", key, {"filename": key}) for key in "abc"]
    return atoms, [resolver.create_bag("files", [atom], key) for atom, key in zip(atoms, "abc")]


def _events(resolver):
    return resolver.conn.execute("SELECT * FROM resolution_event_log ORDER BY id").fetchall()


def test_merge_preserves_history_and_retains_foreign_key_targets(resolver):
    _, bags = _bags(resolver)
    original_events = _events(resolver)
    survivor = resolver.merge_bags(bags[:2], "same entity")
    assert survivor == bags[0]
    assert _events(resolver)[:len(original_events)] == original_events
    assert resolver.conn.execute("PRAGMA foreign_key_check").fetchall() == []
    assert resolver.conn.execute(
        "SELECT atom_count FROM bags WHERE id = ?", (bags[1],)
    ).fetchone() == (0,)
    destination = resolver.conn.execute(
        "SELECT reason FROM resolution_event_log WHERE bag_id = ? AND event_type = 'merge_into'",
        (bags[1],),
    ).fetchone()
    assert json.loads(destination[0]) == {"surviving_bag_id": survivor, "reason": "same entity"}
    before_retry = _events(resolver)
    with pytest.raises(ValueError, match="no current members"):
        resolver.merge_bags([bags[2], bags[1]])
    assert _events(resolver) == before_retry
    assert resolver.conn.execute(
        "SELECT atom_count FROM bags WHERE id = ?", (survivor,)
    ).fetchone() == (2,)


def test_split_records_new_bag_and_merge_chain_keeps_all_events(resolver):
    atoms, bags = _bags(resolver)
    resolver.merge_bags(bags)
    before_split = _events(resolver)
    split = resolver.split_bag(bags[0], [atoms[1]], "bad match")
    assert _events(resolver)[:len(before_split)] == before_split
    event = resolver.conn.execute(
        "SELECT atom_ids, reason FROM resolution_event_log "
        "WHERE bag_id = ? AND event_type = 'split_from'", (split,)
    ).fetchone()
    assert json.loads(event[0]) == [atoms[1]]
    assert json.loads(event[1]) == {"source_bag_id": bags[0], "reason": "bad match"}
    before_merge = _events(resolver)
    resolver.merge_bags([split, bags[0]])
    assert _events(resolver)[:len(before_merge)] == before_merge
    assert resolver.conn.execute("PRAGMA foreign_key_check").fetchall() == []


def test_failed_merge_rolls_back_membership_and_new_events(resolver, monkeypatch):
    _, bags = _bags(resolver)
    before = _events(resolver)
    old_members = resolver.conn.execute("SELECT * FROM bag_atoms ORDER BY bag_id").fetchall()
    original_log = resolver._log_event

    def fail_retirement(event_type, *args, **kwargs):
        if event_type == "merge_into":
            raise RuntimeError("injected audit-write failure")
        return original_log(event_type, *args, **kwargs)

    monkeypatch.setattr(resolver, "_log_event", fail_retirement)
    with pytest.raises(RuntimeError, match="audit-write"):
        resolver.merge_bags(bags)
    assert _events(resolver) == before
    assert resolver.conn.execute(
        "SELECT * FROM bag_atoms ORDER BY bag_id"
    ).fetchall() == old_members
    assert resolver.conn.execute("SELECT atom_count FROM bags ORDER BY id").fetchall() == [(1,)] * 3


def test_resolution_diff_excludes_retired_bags(resolver, tmp_path):
    _, bags = _bags(resolver)
    resolver.merge_bags(bags[:2])
    new_path = tmp_path / "new.db"
    with closing(sqlite3.connect(new_path)) as conn:
        resolver.conn.backup(conn)
        # A different historical key is not a changed current canonical entity.
        conn.execute("UPDATE bags SET canonical_key = 'historical' WHERE id = ?", (bags[1],))
        conn.commit()
    old_path = tmp_path / "old.db"
    with closing(sqlite3.connect(old_path)) as conn:
        resolver.conn.backup(conn)
    with IcarusDiffer(str(old_path), str(new_path)) as differ:
        result = differ.resolution_diff()
        assert result.added == result.removed == result.changed == []


def test_create_bag_serializes_validation_across_connections(resolver):
    """Pause before the first INSERT: a second writer must not validate stale membership."""
    atom = resolver.ingest_atom(1, "files", "shared", {"filename": "shared"})
    path = resolver.conn.execute("PRAGMA database_list").fetchone()[2]
    at_insert = threading.Event()
    release_insert = threading.Event()

    def first_writer():
        with EntityResolver(path, experimental=True) as other:
            def pause_before_insert(sql):
                if sql.startswith("INSERT INTO bags"):
                    at_insert.set()
                    if not release_insert.wait(5):
                        raise RuntimeError("test did not release first writer")
            other.conn.set_trace_callback(pause_before_insert)
            return other.create_bag("files", [atom])

    with ThreadPoolExecutor(max_workers=1) as pool:
        first = pool.submit(first_writer)
        try:
            assert at_insert.wait(5), "first writer did not reach bag insertion"
            resolver.conn.execute("PRAGMA busy_timeout = 50")
            with pytest.raises(sqlite3.OperationalError, match="locked"):
                resolver.create_bag("files", [atom])
        finally:
            release_insert.set()
        assert first.result(timeout=5) > 0

    with pytest.raises(ValueError, match="already belong"):
        resolver.create_bag("files", [atom])
    assert resolver.conn.execute(
        "SELECT COUNT(*) FROM bag_atoms WHERE atom_id = ?", (atom,)
    ).fetchone() == (1,)


def test_mutation_never_commits_caller_transaction(resolver):
    atom = resolver.ingest_atom(1, "files", "caller", {"filename": "caller"})
    resolver.conn.execute("BEGIN")
    resolver.conn.execute("INSERT INTO metadata VALUES ('caller-owned', 'uncommitted')")
    resolver.create_bag("files", [atom])
    assert resolver.conn.in_transaction
    resolver.conn.rollback()
    assert resolver.conn.execute("SELECT COUNT(*) FROM bags").fetchone() == (0,)
    assert resolver.conn.execute("SELECT COUNT(*) FROM resolution_event_log").fetchone() == (0,)
    assert resolver.conn.execute(
        "SELECT value FROM metadata WHERE key = 'caller-owned'"
    ).fetchone() is None


def test_ingest_never_commits_caller_transaction(resolver):
    resolver.conn.execute("BEGIN")
    resolver.ingest_atom(1, "files", "caller", {"filename": "caller"})
    assert resolver.conn.in_transaction
    resolver.conn.rollback()
    assert resolver.conn.execute("SELECT COUNT(*) FROM atoms").fetchone() == (0,)


def test_caller_with_stale_snapshot_cannot_bag_an_already_assigned_atom(resolver):
    atom = resolver.ingest_atom(1, "files", "shared", {"filename": "shared"})
    path = resolver.conn.execute("PRAGMA database_list").fetchone()[2]
    resolver.conn.execute("BEGIN")
    assert resolver.conn.execute("SELECT COUNT(*) FROM bag_atoms").fetchone() == (0,)
    with EntityResolver(path, experimental=True) as other:
        other.create_bag("files", [atom])
    with pytest.raises(sqlite3.OperationalError, match="locked"):
        resolver.create_bag("files", [atom])
    assert resolver.conn.in_transaction
    resolver.conn.rollback()
    assert resolver.conn.execute("SELECT COUNT(*) FROM bag_atoms").fetchone() == (1,)


def test_failed_nested_mutation_preserves_caller_work(resolver):
    resolver.conn.execute("BEGIN")
    resolver.conn.execute("INSERT INTO metadata VALUES ('caller-owned', 'keep')")
    with pytest.raises(ValueError, match="Unknown atom"):
        resolver.create_bag("files", [999])
    assert resolver.conn.in_transaction
    assert resolver.conn.execute(
        "SELECT value FROM metadata WHERE key = 'caller-owned'"
    ).fetchone() == ("keep",)
    resolver.conn.commit()


def test_manual_membership_changes_clear_previous_cluster_scores(resolver):
    atoms, bags = _bags(resolver)
    resolver.conn.execute("UPDATE bags SET score = 0.99")
    resolver.conn.commit()
    survivor = resolver.merge_bags(bags)
    assert resolver.conn.execute(
        "SELECT score FROM bags WHERE id = ?", (survivor,)
    ).fetchone() == (None,)
    resolver.conn.execute("UPDATE bags SET score = 0.99 WHERE id = ?", (survivor,))
    resolver.conn.commit()
    split = resolver.split_bag(survivor, [atoms[0]])
    assert resolver.conn.execute(
        "SELECT score FROM bags WHERE id IN (?, ?) ORDER BY id", (survivor, split)
    ).fetchall() == [(None,), (None,)]


def test_scored_resolution_rolls_back_all_clusters_on_failure(resolver, monkeypatch):
    for key in "abc":
        resolver.ingest_atom(1, "files", key, {"filename": "shared", "sha256": key})
    original_log = resolver._log_event
    creates = 0

    def fail_second_create(event_type, *args, **kwargs):
        nonlocal creates
        if event_type == "create":
            creates += 1
            if creates == 2:
                raise RuntimeError("injected second-cluster failure")
        return original_log(event_type, *args, **kwargs)

    monkeypatch.setattr(resolver, "_log_event", fail_second_create)
    with pytest.raises(RuntimeError, match="second-cluster"):
        resolver.resolve_scored("files")
    assert resolver.conn.execute("SELECT COUNT(*) FROM bags").fetchone() == (0,)
    assert resolver.conn.execute("SELECT COUNT(*) FROM bag_atoms").fetchone() == (0,)
    assert resolver.conn.execute("SELECT COUNT(*) FROM resolution_event_log").fetchone() == (0,)
    assert resolver.conn.execute("SELECT COUNT(*) FROM match_candidates").fetchone() == (0,)
    assert len(resolver.unresolved_atoms("files")) == 3
