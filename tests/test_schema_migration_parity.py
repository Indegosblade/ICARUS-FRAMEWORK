"""Fresh-vs-migrated schema parity for the provenance foreign key (issue #51).

A fresh v6 database builds its entity tables from ``CORE_SCHEMA``, where each
carries ``source_version_id INTEGER REFERENCES versions(id)``. A database
migrated up from v2/v3 reaches that column via ``ALTER TABLE ADD COLUMN`` —
which cannot attach a ``REFERENCES`` constraint — so on a migrated database the
provenance foreign key was silently absent and FK enforcement did not protect
it. These tests build a real legacy v2 database, run it through the actual
migration chain, and assert the migrated entity-table schema is identical to a
freshly initialized v6 database, that every row survives, that the repair is a
safe idempotent no-op, and that the provenance FK is now genuinely enforced.
"""

import re
import sqlite3

import pytest

from icarus.core import schema
from icarus.core.schema import (
    ENTITY_TABLES,
    FTS_SCHEMA,
    FTS_TRIGGERS,
    INDEXES,
    VIEWS,
    initialize_database,
)

# Columns added to every entity table by the v2 -> v3 migration. A genuine v2
# database predates them, so they are stripped when reconstructing one.
_PROVENANCE_COLUMNS = ("source_version_id", "confidence", "observed_time", "marking")

# Indexes/FTS/triggers created by the v3+ migrations (everything else already
# existed at v2 and is therefore part of a faithful legacy database).
_POST_V2_INDEXES = {
    "idx_obs_entity", "idx_obs_time", "idx_obs_type",
    "idx_atoms_type", "idx_atoms_version", "idx_bags_type", "idx_relog_bag",
    "idx_match_entity", "idx_match_atom_a",
    "idx_mach_daemon", "idx_mach_service",
}


def _normalize_ddl(sql):
    """Collapse whitespace runs so DDL is compared for structural, not
    byte-for-byte, equality (the same normalization used elsewhere)."""
    return None if sql is None else " ".join(sql.split())


def _normalize_structural_ddl(sql):
    """Normalize harmless SQLite DDL formatting differences."""
    if sql is None:
        return None
    compact = re.sub(r"\s*([(),;])\s*", r"\1", " ".join(sql.split()))
    return compact.lower()


def _strip_provenance_columns(create_sql: str) -> str:
    """Return an entity-table CREATE statement with the four provenance columns
    removed — i.e. the table as it existed at schema v2."""
    kept = [
        line
        for line in create_sql.split("\n")
        if (line.strip().rstrip(",").split(" ")[0] if line.strip() else "")
        not in _PROVENANCE_COLUMNS
    ]
    # Drop the now-dangling comma before the closing paren.
    return re.sub(r",(\s*\n\);)", r"\1", "\n".join(kept))


def build_legacy_v2_database(path) -> None:
    """Create a faithful schema-v2 ICARUS database.

    A v2 database has the eight entity tables *without* provenance columns and
    *without* the ``versions`` table, but it already carries the entity indexes,
    the ``files``/``daemons`` FTS tables and their triggers, and the views —
    exactly the objects the additive v3+ migrations do not recreate. Rebuilt
    from the live schema constants so it cannot drift from the real schema.
    """
    conn = sqlite3.connect(str(path))
    try:
        conn.execute("PRAGMA foreign_keys = OFF")
        conn.execute("CREATE TABLE metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL)")

        for table in ENTITY_TABLES:
            conn.execute(
                _strip_provenance_columns(schema._extract_create_table(table))
            )

        for statement in (s.strip() for s in INDEXES.split(";") if s.strip()):
            name = re.search(r"IF NOT EXISTS (\w+)", statement).group(1)
            if name not in _POST_V2_INDEXES:
                conn.execute(statement)

        for block in re.findall(r"CREATE VIRTUAL TABLE.*?\);", FTS_SCHEMA, re.DOTALL):
            if re.search(r"EXISTS (\w+)", block).group(1) in ("files_fts", "daemons_fts"):
                conn.execute(block)

        for block in re.findall(r"CREATE TRIGGER.*?END;", FTS_TRIGGERS, re.DOTALL):
            if re.search(r"EXISTS (\w+)", block).group(1).startswith(("files_", "daemons_")):
                conn.execute(block)

        conn.executescript(VIEWS)
        conn.execute("INSERT INTO metadata VALUES ('schema_version', '2')")
        conn.commit()
    finally:
        conn.close()


def _entity_schema_objects(path) -> dict:
    """Map (type, name) -> normalized DDL for every sqlite_master object that
    belongs to an entity table (the table itself plus its indexes/triggers)."""
    conn = sqlite3.connect(str(path))
    try:
        rows = conn.execute(
            "SELECT type, name, sql, tbl_name FROM sqlite_master "
            "WHERE name NOT LIKE 'sqlite_%'"
        ).fetchall()
    finally:
        conn.close()
    return {
        (obj_type, name): _normalize_ddl(sql)
        for obj_type, name, sql, tbl_name in rows
        if tbl_name in ENTITY_TABLES
    }


def _foreign_keys(path, table) -> set:
    conn = sqlite3.connect(str(path))
    try:
        return {
            (row[3], row[2], row[4])  # (from, referenced table, referenced column)
            for row in conn.execute(f"PRAGMA foreign_key_list([{table}])")
        }
    finally:
        conn.close()


def _all_schema_objects(path) -> dict:
    """Return normalized user sqlite_master objects, including FTS shadows."""
    conn = sqlite3.connect(str(path))
    try:
        rows = conn.execute(
            "SELECT type, name, sql FROM sqlite_master "
            "WHERE name NOT LIKE 'sqlite_%'"
        ).fetchall()
    finally:
        conn.close()
    return {
        (obj_type, name): _normalize_structural_ddl(sql)
        for obj_type, name, sql in rows
    }


def _remove_non_fk_objects(path) -> None:
    """Make the legacy fixture exercise every additive non-FK repair path."""
    conn = sqlite3.connect(str(path))
    try:
        for view in ("v_sandbox_escape_surface", "v_kernel_attack_surface", "v_test_binaries"):
            conn.execute(f"DROP VIEW IF EXISTS [{view}]")
        for trigger in re.findall(
            r"CREATE TRIGGER IF NOT EXISTS (\w+)", FTS_TRIGGERS
        ):
            conn.execute(f"DROP TRIGGER IF EXISTS [{trigger}]")
        for fts_table in ("files_fts", "daemons_fts"):
            conn.execute(f"DROP TABLE IF EXISTS [{fts_table}]")
        for index in re.findall(r"CREATE INDEX IF NOT EXISTS (\w+)", INDEXES):
            conn.execute(f"DROP INDEX IF EXISTS [{index}]")
        conn.commit()
    finally:
        conn.close()


@pytest.fixture
def migrated_v6_db(tmp_path):
    """A v2 database with seed rows, migrated up to v6 through the real chain."""
    db = tmp_path / "migrated.db"
    build_legacy_v2_database(db)

    conn = sqlite3.connect(str(db))
    conn.execute("INSERT INTO files (path, filename) VALUES ('/bin/a', 'a'), ('/bin/b', 'b')")
    conn.execute("INSERT INTO binaries (file_id, bundle_id) VALUES (1, 'com.example.a')")
    conn.execute("INSERT INTO daemons (label, plist_path) VALUES ('com.example.d', '/d.plist')")
    conn.commit()
    conn.close()

    result = initialize_database(db)
    assert result["schema_version"] == 6
    return db


@pytest.fixture
def incomplete_migrated_v6_db(tmp_path):
    """A v2 database missing all non-FK objects repaired at the v6 boundary."""
    db = tmp_path / "incomplete-migrated.db"
    build_legacy_v2_database(db)
    _remove_non_fk_objects(db)

    conn = sqlite3.connect(str(db))
    try:
        conn.execute(
            "INSERT INTO files (path, filename) VALUES ('/bin/legacy', 'legacy')"
        )
        conn.commit()
    finally:
        conn.close()

    assert initialize_database(db)["schema_version"] == 6
    return db


@pytest.fixture
def fresh_v6_db(tmp_path):
    db = tmp_path / "fresh.db"
    assert initialize_database(db)["schema_version"] == 6
    return db


def test_migrated_entity_schema_matches_fresh(migrated_v6_db, fresh_v6_db):
    """The full table/index/trigger set for entity tables — including the
    source_version_id foreign keys — is identical between a migrated and a
    freshly built v6 database, and the migrated DB has no FK violations."""
    migrated = _entity_schema_objects(migrated_v6_db)
    fresh = _entity_schema_objects(fresh_v6_db)
    assert migrated == fresh

    for table in ENTITY_TABLES:
        assert ("source_version_id", "versions", "id") in _foreign_keys(
            migrated_v6_db, table
        ), f"{table} is missing the source_version_id -> versions(id) FK"
        # And it matches the fresh database's FK set exactly.
        assert _foreign_keys(migrated_v6_db, table) == _foreign_keys(fresh_v6_db, table)

    conn = sqlite3.connect(str(migrated_v6_db))
    try:
        assert conn.execute("PRAGMA foreign_key_check").fetchall() == []
    finally:
        conn.close()


def test_migrated_schema_objects_match_fresh(
    incomplete_migrated_v6_db, fresh_v6_db
):
    """Every user sqlite_master object, not only entity FKs, reaches parity."""
    assert _all_schema_objects(incomplete_migrated_v6_db) == _all_schema_objects(
        fresh_v6_db
    )

    # A second open runs the current-version validation path successfully.
    assert initialize_database(incomplete_migrated_v6_db)["schema_version"] == 6


def test_non_fk_repair_is_idempotent_and_resyncs_fts(incomplete_migrated_v6_db):
    """Missing objects are repaired once and FTS triggers resync migrated rows."""
    before = _all_schema_objects(incomplete_migrated_v6_db)
    conn = schema.open_db(incomplete_migrated_v6_db)
    try:
        schema._repair_migrated_non_fk_objects(conn)
        schema._repair_migrated_non_fk_objects(conn)
        conn.commit()
        conn.execute(
            "INSERT INTO versions "
            "(run_id, parser_name, started_at) VALUES ('fts-run', 'test', 'now')"
        )
        version_id = conn.execute("SELECT id FROM versions WHERE run_id = 'fts-run'").fetchone()[0]
        conn.execute(
            "INSERT INTO atoms "
            "(source_version_id, entity_type, source_key, properties, created_at) "
            "VALUES (?, 'test', 'key', 'before_marker', 'now')",
            (version_id,),
        )
        conn.commit()
        assert conn.execute(
            "SELECT rowid FROM atoms_fts WHERE atoms_fts MATCH 'before_marker'"
        ).fetchone()
        conn.execute("UPDATE atoms SET properties = 'after_marker' WHERE source_key = 'key'")
        conn.commit()
        assert conn.execute(
            "SELECT rowid FROM atoms_fts WHERE atoms_fts MATCH 'before_marker'"
        ).fetchone() is None
        assert conn.execute(
            "SELECT rowid FROM atoms_fts WHERE atoms_fts MATCH 'after_marker'"
        ).fetchone()
    finally:
        conn.close()

    after = _all_schema_objects(incomplete_migrated_v6_db)
    assert after == before


def test_migration_preserves_all_rows(tmp_path):
    """Every row present before the FK-parity rebuild is present, unchanged,
    afterward — the table rebuild copies data faithfully."""
    db = tmp_path / "data.db"
    build_legacy_v2_database(db)

    conn = sqlite3.connect(str(db))
    conn.execute(
        "INSERT INTO files (path, filename, size) VALUES "
        "('/one', 'one', 11), ('/two', 'two', 22), ('/three', 'three', 33)"
    )
    conn.execute(
        "INSERT INTO daemons (label, plist_path, program) VALUES "
        "('com.a', '/a.plist', '/usr/bin/a'), ('com.b', '/b.plist', '/usr/bin/b')"
    )
    conn.commit()
    before_files = conn.execute(
        "SELECT id, path, filename, size FROM files ORDER BY id"
    ).fetchall()
    before_daemons = conn.execute(
        "SELECT id, label, plist_path, program FROM daemons ORDER BY id"
    ).fetchall()
    conn.close()

    initialize_database(db)

    conn = sqlite3.connect(str(db))
    try:
        after_files = conn.execute(
            "SELECT id, path, filename, size FROM files ORDER BY id"
        ).fetchall()
        after_daemons = conn.execute(
            "SELECT id, label, plist_path, program FROM daemons ORDER BY id"
        ).fetchall()
    finally:
        conn.close()

    assert after_files == before_files
    assert after_daemons == before_daemons


def test_fk_parity_repair_is_idempotent(migrated_v6_db):
    """Re-running the repair on an already-repaired database rebuilds nothing
    and leaves the schema byte-for-byte unchanged."""
    # Guard reports nothing to do once parity is restored.
    conn = sqlite3.connect(str(migrated_v6_db))
    try:
        for table in ENTITY_TABLES:
            assert not schema._entity_table_needs_fk_repair(conn, table)
    finally:
        conn.close()

    before = _entity_schema_objects(migrated_v6_db)

    conn = schema.open_db(migrated_v6_db)
    try:
        schema._repair_migrated_entity_fks(conn)
        schema._repair_migrated_entity_fks(conn)  # twice, for good measure
        conn.commit()
    finally:
        conn.close()

    assert _entity_schema_objects(migrated_v6_db) == before


def test_repair_is_noop_on_fresh_database(fresh_v6_db):
    """A freshly initialized v6 database already has the FKs, so the guard
    finds nothing to rebuild and the schema is untouched."""
    conn = sqlite3.connect(str(fresh_v6_db))
    try:
        for table in ENTITY_TABLES:
            assert not schema._entity_table_needs_fk_repair(conn, table)
    finally:
        conn.close()

    before = _entity_schema_objects(fresh_v6_db)
    initialize_database(fresh_v6_db)  # re-run full init path
    assert _entity_schema_objects(fresh_v6_db) == before


def test_migrated_db_enforces_source_version_fk(migrated_v6_db, fresh_v6_db):
    """Inserting an entity row whose source_version_id has no matching versions
    row is rejected on the migrated DB, exactly as on a fresh DB — proving the
    REFERENCES constraint is real, not merely a column."""

    def insert_dangling(db):
        conn = schema.open_db(db)  # opens with foreign_keys = ON
        try:
            assert conn.execute("PRAGMA foreign_keys").fetchone()[0] == 1
            conn.execute(
                "INSERT INTO files (path, filename, source_version_id) "
                "VALUES ('/orphan', 'orphan', 999999)"
            )
            conn.commit()
        finally:
            conn.close()

    with pytest.raises(sqlite3.IntegrityError, match="FOREIGN KEY"):
        insert_dangling(migrated_v6_db)
    # Same behavior on a fresh database confirms parity of enforcement.
    with pytest.raises(sqlite3.IntegrityError, match="FOREIGN KEY"):
        insert_dangling(fresh_v6_db)
