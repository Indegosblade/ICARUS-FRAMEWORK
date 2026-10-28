"""Tests for the atomizer (icarus.core.atomize) and the v5->v6 schema bump.

Covers:
* atomize_db projects binaries/daemons rows into atoms with the right
  entity_type / source_key / JSON properties, and the atoms_fts trigger fires.
* Idempotency (INSERT OR IGNORE): a second atomize of the same source under
  the same version inserts nothing.
* Blank/whitespace source_key rows are skipped.
* The same source_key atomized under two version ids yields two atoms, each
  tagged with its source_version_id.
* A fresh DB is schema v6: match_candidates table exists and bags has score.
* Migration parity: match_candidates DDL produced by _v5_to_v6 is byte-for-byte
  identical to a fresh (CORE_SCHEMA) DB's, _v5_to_v6 is a safe no-op on re-run,
  and bags.score exists on both paths.
"""

import json
import sqlite3
import tempfile
from contextlib import closing
from pathlib import Path

import pytest

from icarus.core.atomize import atomize_db
from icarus.core.schema import get_schema_version, initialize_database


@pytest.fixture
def db_path():
    """A freshly-initialized (v6) ICARUS database path, cleaned up after."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        path = Path(f.name)
    initialize_database(path)
    yield path
    # initialize_database opens WAL mode, so remove side files too.
    for suffix in ("", "-wal", "-shm"):
        Path(str(path) + suffix).unlink(missing_ok=True)


def _insert_version(conn: sqlite3.Connection, run_id: str) -> int:
    cur = conn.execute(
        "INSERT INTO versions (run_id, parser_name, source_path, started_at) "
        "VALUES (?, 'resolve', '/src', '2026-01-01T00:00:00Z')",
        (run_id,),
    )
    conn.commit()
    vid = cur.lastrowid
    assert vid is not None
    return vid


# ── atomize basics ────────────────────────────────────────────────────────


def test_atomize_basic(db_path):
    conn = sqlite3.connect(str(db_path))
    try:
        version_id = _insert_version(conn, "run-basic")
        conn.execute(
            "INSERT INTO files (id, path, filename, sha256) "
            "VALUES (1, '/usr/bin/foo', 'foo', 'abc123')"
        )
        conn.execute(
            "INSERT INTO binaries (file_id, executable_name, arch) "
            "VALUES (1, 'foo', 'arm64')"
        )
        conn.execute(
            "INSERT INTO files (id, path, filename, sha256) "
            "VALUES (2, '/usr/bin/bar', 'bar', 'def456')"
        )
        conn.execute(
            "INSERT INTO binaries (file_id, executable_name, arch) "
            "VALUES (2, 'bar', 'x86_64')"
        )
        conn.execute(
            "INSERT INTO daemons (label, plist_path, program) "
            "VALUES ('com.example.d', '/Library/LaunchDaemons/com.example.d.plist', "
            "'/usr/bin/foo')"
        )
        conn.commit()

        counts = atomize_db(conn, conn, version_id)
        # entity_types=None sweeps every registered projection (Increment B added
        # frameworks/kexts/files); the two `files` rows above (inserted only as
        # the binaries FK target) are themselves now a projected type too.
        assert counts == {
            "binaries": 2, "daemons": 1, "frameworks": 0, "kexts": 0, "files": 2,
        }

        # A binary atom is keyed by source path; name remains a matching feature.
        row = conn.execute(
            "SELECT entity_type, source_key, properties FROM atoms "
            "WHERE entity_type = 'binaries' AND source_key = 'path:/usr/bin/foo'"
        ).fetchone()
        assert row is not None
        assert row[0] == "binaries"
        assert row[1] == "path:/usr/bin/foo"
        assert json.loads(row[2]) == {
            "executable_name": "foo",
            "arch": "arm64",
            "path": "/usr/bin/foo",
            "sha256": "abc123",
        }

        # A daemon atom is keyed by its label.
        drow = conn.execute(
            "SELECT source_key, properties FROM atoms WHERE entity_type = 'daemons'"
        ).fetchone()
        assert drow[0] == "com.example.d"
        assert json.loads(drow[1]) == {
            "label": "com.example.d",
            "program": "/usr/bin/foo",
            "plist_path": "/Library/LaunchDaemons/com.example.d.plist",
        }

        # The AFTER INSERT trigger populated the FTS index for the new atoms.
        fts_keys = {
            r[0]
            for r in conn.execute(
                "SELECT source_key FROM atoms_fts WHERE atoms_fts MATCH 'foo'"
            ).fetchall()
        }
        assert "path:/usr/bin/foo" in fts_keys
    finally:
        conn.close()


def test_atomize_omits_null_columns_from_properties(db_path):
    """Columns that are NULL are dropped from the atom's properties JSON."""
    conn = sqlite3.connect(str(db_path))
    try:
        version_id = _insert_version(conn, "run-null")
        # No file row joined (file_id points nowhere) and arch NULL → path/sha256/arch
        # all resolve to NULL and must be absent from properties.
        conn.execute(
            "INSERT INTO binaries (file_id, executable_name, arch) "
            "VALUES (999, 'lonely', NULL)"
        )
        conn.commit()

        counts = atomize_db(conn, conn, version_id, ["binaries"])
        assert counts == {"binaries": 1}
        props = json.loads(
            conn.execute(
                "SELECT properties FROM atoms WHERE source_key = 'row:1'"
            ).fetchone()[0]
        )
        assert props == {"executable_name": "lonely"}
    finally:
        conn.close()


def test_atomize_idempotent(db_path):
    conn = sqlite3.connect(str(db_path))
    try:
        version_id = _insert_version(conn, "run-idem")
        conn.execute("INSERT INTO files (id, path, filename) VALUES (1, '/b/x', 'x')")
        conn.execute("INSERT INTO binaries (file_id, executable_name) VALUES (1, 'x')")
        conn.execute("INSERT INTO daemons (label, plist_path) VALUES ('d1', '/p')")
        conn.commit()

        first = atomize_db(conn, conn, version_id)
        # entity_types=None sweeps every registered projection (Increment B added
        # frameworks/kexts/files); the `files` row above (inserted only as the
        # binaries FK target) is itself now a projected type too.
        assert first == {
            "binaries": 1, "daemons": 1, "frameworks": 0, "kexts": 0, "files": 1,
        }

        # Second run over the same source under the same version inserts nothing.
        second = atomize_db(conn, conn, version_id)
        assert second == {
            "binaries": 0, "daemons": 0, "frameworks": 0, "kexts": 0, "files": 0,
        }

        assert conn.execute("SELECT COUNT(*) FROM atoms").fetchone()[0] == 3
    finally:
        conn.close()


def test_atomize_skips_empty_source_key(db_path):
    conn = sqlite3.connect(str(db_path))
    try:
        version_id = _insert_version(conn, "run-empty")
        # Empty-string and whitespace-only labels must produce no atom;
        # (daemons.label is NOT NULL so a true NULL can't be inserted here, but
        # the same guard covers None for other entity types).
        conn.execute("INSERT INTO daemons (label, plist_path) VALUES ('', '/p1')")
        conn.execute("INSERT INTO daemons (label, plist_path) VALUES ('   ', '/p2')")
        conn.execute("INSERT INTO daemons (label, plist_path) VALUES ('real.d', '/p3')")
        conn.commit()

        counts = atomize_db(conn, conn, version_id, ["daemons"])
        assert counts == {"daemons": 1}
        keys = [
            r[0]
            for r in conn.execute(
                "SELECT source_key FROM atoms WHERE entity_type = 'daemons'"
            ).fetchall()
        ]
        assert keys == ["real.d"]
    finally:
        conn.close()


def test_atomize_cross_source_tagging(db_path):
    """The same source_key atomized under two versions makes two tagged atoms."""
    conn = sqlite3.connect(str(db_path))
    try:
        v1 = _insert_version(conn, "run-a")
        v2 = _insert_version(conn, "run-b")
        conn.execute("INSERT INTO daemons (label, plist_path) VALUES ('shared.d', '/p')")
        conn.commit()

        assert atomize_db(conn, conn, v1, ["daemons"]) == {"daemons": 1}
        # Different version_id → OR IGNORE does not suppress it (unique key differs).
        assert atomize_db(conn, conn, v2, ["daemons"]) == {"daemons": 1}

        tags = [
            r[0]
            for r in conn.execute(
                "SELECT source_version_id FROM atoms "
                "WHERE entity_type = 'daemons' AND source_key = 'shared.d' "
                "ORDER BY source_version_id"
            ).fetchall()
        ]
        assert tags == sorted([v1, v2])
    finally:
        conn.close()


# ── schema v6 ─────────────────────────────────────────────────────────────


def test_atomize_keeps_same_named_binaries_at_distinct_paths(db_path):
    """An executable name is a matching feature, not a source-local identity."""
    with closing(sqlite3.connect(db_path)) as conn:
        version_id = _insert_version(conn, "duplicate-binary-names")
        for path, digest in (("/usr/bin/tool", "aaa"), ("/opt/vendor/tool", "bbb")):
            file_id = conn.execute(
                "INSERT INTO files (path, filename, sha256) VALUES (?, 'tool', ?)",
                (path, digest),
            ).lastrowid
            conn.execute(
                "INSERT INTO binaries (file_id, executable_name) VALUES (?, 'tool')",
                (file_id,),
            )
        conn.commit()

        assert atomize_db(conn, conn, version_id, ["binaries"]) == {"binaries": 2}
        rows = conn.execute(
            "SELECT source_key, properties FROM atoms WHERE entity_type = 'binaries'"
        ).fetchall()
        assert {key for key, _ in rows} == {"path:/usr/bin/tool", "path:/opt/vendor/tool"}
        assert {json.loads(props)["sha256"] for _, props in rows} == {"aaa", "bbb"}
        assert all(json.loads(props)["executable_name"] == "tool" for _, props in rows)
        assert atomize_db(conn, conn, version_id, ["binaries"]) == {"binaries": 0}


def test_atomize_keeps_unlinked_same_named_binaries(db_path):
    with closing(sqlite3.connect(db_path)) as conn:
        version_id = _insert_version(conn, "unlinked-binary-names")
        conn.executemany(
            "INSERT INTO binaries (file_id, executable_name, arch) VALUES (?, 'tool', ?)",
            [(998, "arm64"), (999, "x86_64")],
        )
        conn.commit()
        assert atomize_db(conn, conn, version_id, ["binaries"]) == {"binaries": 2}
        assert atomize_db(conn, conn, version_id, ["binaries"]) == {"binaries": 0}
        rows = conn.execute("SELECT source_key, properties FROM atoms").fetchall()
        assert len({key for key, _ in rows}) == 2
        assert all("path" not in json.loads(props) for _, props in rows)


def test_atomize_refuses_to_duplicate_legacy_name_keyed_atoms(db_path):
    with closing(sqlite3.connect(db_path)) as conn:
        version_id = _insert_version(conn, "legacy-atom-keys")
        conn.execute("INSERT INTO files (id, path, filename) VALUES (1, '/usr/bin/tool', 'tool')")
        conn.execute("INSERT INTO binaries (file_id, executable_name) VALUES (1, 'tool')")
        properties = json.dumps({"executable_name": "tool", "path": "/usr/bin/tool"})
        conn.execute(
            "INSERT INTO atoms "
            "(source_version_id, entity_type, source_key, properties, created_at) "
            "VALUES (?, 'binaries', 'tool', ?, '2026-01-01T00:00:00Z')",
            (version_id, properties),
        )
        conn.commit()
        with pytest.raises(ValueError, match="fresh resolution output"):
            atomize_db(conn, conn, version_id)
        assert conn.execute("SELECT COUNT(*) FROM atoms").fetchone()[0] == 1


def test_schema_is_v6(db_path):
    assert get_schema_version(db_path) == 6

    conn = sqlite3.connect(str(db_path))
    try:
        table = conn.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table' "
            "AND name = 'match_candidates'"
        ).fetchone()
        assert table is not None

        bags_cols = {r[1] for r in conn.execute("PRAGMA table_info(bags)").fetchall()}
        assert "score" in bags_cols

        mc_cols = {
            r[1] for r in conn.execute("PRAGMA table_info(match_candidates)").fetchall()
        }
        assert {
            "id", "entity_type", "atom_a", "atom_b", "score", "features", "created_at"
        } <= mc_cols
    finally:
        conn.close()


def test_migration_v5_to_v6_parity(tmp_path):
    """match_candidates DDL from the migration path is identical to CORE_SCHEMA's."""
    from icarus.core.schema import _v5_to_v6

    # A genuinely fresh v6 DB: match_candidates comes from CORE_SCHEMA.
    fresh = tmp_path / "fresh.db"
    initialize_database(fresh)

    # A simulated v5 DB (pre-v6 bags without score, no match_candidates), then
    # upgrade it through the migration so match_candidates comes from _v5_to_v6.
    v5 = tmp_path / "v5.db"
    conn = sqlite3.connect(str(v5))
    conn.executescript(
        """
        CREATE TABLE metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL);
        CREATE TABLE versions (id INTEGER PRIMARY KEY AUTOINCREMENT);
        CREATE TABLE atoms (id INTEGER PRIMARY KEY AUTOINCREMENT);
        CREATE TABLE bags (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            entity_type TEXT NOT NULL,
            canonical_key TEXT,
            created_at TEXT NOT NULL,
            resolved_at TEXT,
            atom_count INTEGER DEFAULT 1
        );
        INSERT INTO metadata VALUES ('schema_version', '5');
        """
    )
    conn.commit()

    _v5_to_v6(conn)
    # Re-running must be a safe no-op (CREATE IF NOT EXISTS + guarded ALTER).
    _v5_to_v6(conn)
    version = conn.execute(
        "SELECT value FROM metadata WHERE key = 'schema_version'"
    ).fetchone()[0]
    assert version == "6"
    conn.close()

    def mc_sql(db: Path) -> str:
        c = sqlite3.connect(str(db))
        try:
            return c.execute(
                "SELECT sql FROM sqlite_master WHERE name = 'match_candidates'"
            ).fetchone()[0]
        finally:
            c.close()

    def bags_has_score(db: Path) -> bool:
        c = sqlite3.connect(str(db))
        try:
            return "score" in {
                r[1] for r in c.execute("PRAGMA table_info(bags)").fetchall()
            }
        finally:
            c.close()

    assert mc_sql(fresh) == mc_sql(v5)
    assert bags_has_score(fresh)
    assert bags_has_score(v5)
