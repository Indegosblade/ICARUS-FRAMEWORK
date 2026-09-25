"""Core tests for icarus-framework."""

import re
import sqlite3
import sys
import tempfile
from pathlib import Path

import pytest


@pytest.fixture
def tmp_db():
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = Path(f.name)
    yield db_path
    db_path.unlink(missing_ok=True)


@pytest.fixture
def two_dbs():
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db1 = Path(f.name)
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db2 = Path(f.name)
    yield db1, db2
    db1.unlink(missing_ok=True)
    db2.unlink(missing_ok=True)


def test_imports():
    from icarus import __version__
    from icarus.core import VALID_FTS_TABLES, VALID_TABLES
    from icarus.core.schema import SCHEMA_VERSION
    from icarus.parsers import list_parsers
    assert __version__ == "4.0.0b1"
    assert SCHEMA_VERSION == 6
    assert len(VALID_TABLES) == 17
    assert len(VALID_FTS_TABLES) == 3
    assert "windows" in list_parsers()
    assert "linux" in list_parsers()


def test_schema_init_and_fts(tmp_db):
    from icarus.core.schema import initialize_database

    stats = initialize_database(tmp_db, {"source": "test"})
    assert stats["schema_version"] == 6
    assert stats["tables"] > 8

    conn = sqlite3.connect(str(tmp_db))
    triggers = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='trigger'"
    ).fetchall()
    trigger_names = {t[0] for t in triggers}
    assert "files_ai" in trigger_names
    assert "files_ad" in trigger_names
    assert "daemons_ai" in trigger_names

    conn.execute("""
        INSERT INTO files (path, filename, extension, size, file_type)
        VALUES ('/usr/bin/testbinary', 'testbinary', '', 1000, 'binary')
    """)
    conn.commit()

    result = conn.execute(
        "SELECT * FROM files_fts WHERE files_fts MATCH 'testbinary'"
    ).fetchall()
    assert len(result) == 1
    conn.close()


def test_initialize_database_refuses_future_schema_without_relabeling(tmp_db):
    from icarus.core.schema import SchemaVersionError, initialize_database

    initialize_database(tmp_db)
    conn = sqlite3.connect(str(tmp_db))
    conn.execute(
        "UPDATE metadata SET value = '99' WHERE key = 'schema_version'"
    )
    conn.commit()
    conn.close()

    with pytest.raises(SchemaVersionError, match=r"Unsupported.*99.*refusing"):
        initialize_database(tmp_db)

    conn = sqlite3.connect(str(tmp_db))
    try:
        stored = conn.execute(
            "SELECT value FROM metadata WHERE key = 'schema_version'"
        ).fetchone()[0]
    finally:
        conn.close()
    assert stored == "99"


def test_initialize_database_rejects_malformed_schema_version(tmp_db):
    from icarus.core.schema import SchemaVersionError, initialize_database

    initialize_database(tmp_db)
    conn = sqlite3.connect(str(tmp_db))
    conn.execute(
        "UPDATE metadata SET value = 'not-an-integer' WHERE key = 'schema_version'"
    )
    conn.commit()
    conn.close()

    with pytest.raises(SchemaVersionError, match=r"Invalid.*not-an-integer.*integer"):
        initialize_database(tmp_db)

    conn = sqlite3.connect(str(tmp_db))
    try:
        stored = conn.execute(
            "SELECT value FROM metadata WHERE key = 'schema_version'"
        ).fetchone()[0]
    finally:
        conn.close()
    assert stored == "not-an-integer"


def test_initialize_database_does_not_restamp_current_schema(tmp_db):
    from icarus.core.schema import initialize_database

    initialize_database(tmp_db)
    conn = sqlite3.connect(str(tmp_db))
    conn.executescript("""
        CREATE TRIGGER reject_schema_version_restamp
        BEFORE INSERT ON metadata
        WHEN NEW.key = 'schema_version'
        BEGIN
            SELECT RAISE(ABORT, 'schema version was re-stamped');
        END;
    """)
    conn.commit()
    conn.close()

    result = initialize_database(tmp_db)
    assert result["schema_version"] == 6


def test_initialize_database_rejects_incomplete_current_schema(tmp_db):
    from icarus.core.schema import SchemaValidationError, initialize_database

    initialize_database(tmp_db)
    conn = sqlite3.connect(str(tmp_db))
    conn.execute("DROP TRIGGER files_ai")
    conn.commit()
    conn.close()

    with pytest.raises(SchemaValidationError, match=r"version 6.*trigger 'files_ai'.*refusing"):
        initialize_database(tmp_db)

    conn = sqlite3.connect(str(tmp_db))
    try:
        stored = conn.execute(
            "SELECT value FROM metadata WHERE key = 'schema_version'"
        ).fetchone()[0]
    finally:
        conn.close()
    assert stored == "6"


def test_initialize_database_refuses_unsupported_legacy_schema(tmp_db):
    from icarus.core.schema import SchemaVersionError, initialize_database

    conn = sqlite3.connect(str(tmp_db))
    conn.executescript("""
        CREATE TABLE metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL);
        INSERT INTO metadata VALUES ('schema_version', '1');
    """)
    conn.commit()
    conn.close()

    with pytest.raises(SchemaVersionError, match=r"supports versions 2 through 6"):
        initialize_database(tmp_db)


def test_query_sql_injection(tmp_db):
    from icarus.core.query import IcarusQuery
    from icarus.core.schema import initialize_database

    initialize_database(tmp_db)
    with IcarusQuery(str(tmp_db)) as q:
        result = q.search("test", table="files")
        assert result.count == 0

        with pytest.raises(ValueError, match="Invalid"):
            q.search("test", table="files; DROP TABLE files; --")

        stats = q.stats()
        assert "files" in stats
        assert "binaries" in stats


def test_differ_sql_injection(two_dbs):
    from icarus.core.differ import IcarusDiffer
    from icarus.core.schema import initialize_database

    db1, db2 = two_dbs
    initialize_database(db1)
    initialize_database(db2)
    with IcarusDiffer(str(db1), str(db2)) as d:
        result = d.added_entities("files", "path")
        assert result.total_changes == 0

        with pytest.raises(ValueError):
            d.added_entities("evil_table", "path")

        with pytest.raises(ValueError):
            d.changed_entities("files", "path", "sha256; DROP TABLE files")


def test_differ_full_pipeline(two_dbs):
    from icarus.core.differ import IcarusDiffer
    from icarus.core.schema import initialize_database

    db1, db2 = two_dbs
    initialize_database(db1)
    initialize_database(db2)

    conn = sqlite3.connect(str(db2))
    conn.execute("""
        INSERT INTO files (path, filename, extension, size, file_type)
        VALUES ('/usr/bin/newbinary', 'newbinary', '', 500, 'binary')
    """)
    conn.commit()
    conn.close()

    with IcarusDiffer(str(db1), str(db2)) as d:
        results = d.full_diff()
        assert results["files_added"].total_changes == 1
        assert results["files_removed"].total_changes == 0

        report = d.generate_report()
        assert "newbinary" in report
        assert "# ICARUS Version Diff" in report


def test_query_intelligence_views(tmp_db):
    from icarus.core.query import IcarusQuery
    from icarus.core.schema import initialize_database

    initialize_database(tmp_db)
    with IcarusQuery(str(tmp_db)) as q:
        assert q.root_daemons().query_name == "Root Daemons (No Sandbox)"
        assert q.service_map().query_name == "MachService Map"
        assert q.kernel_surface().query_name == "Kernel Attack Surface"
        assert q.test_binaries().query_name == "Test Binaries in Production"
        assert q.escape_surface().query_name == "Sandbox Escape Surface"
        assert q.privileged_entitlements().query_name == "Privileged Entitlements"


def test_windows_parser():
    from icarus.parsers.windows import WindowsParser

    p = WindowsParser()
    assert p.name == "windows"
    assert p.get_required_tools() == []
    with tempfile.TemporaryDirectory() as empty:
        assert not p.identify(Path(empty))


def test_linux_parser():
    from icarus.parsers.linux import LinuxParser

    p = LinuxParser()
    assert p.name == "linux"
    assert "readelf" in p.get_required_tools()


def test_cli():
    from icarus.__main__ import main

    old_argv = sys.argv
    sys.argv = ["icarus", "--help"]
    try:
        main()
    except SystemExit as e:
        assert e.code == 0
    finally:
        sys.argv = old_argv


def test_hygeia_integration(tmp_db):
    from icarus.core.schema import initialize_database
    from icarus.integrations.hygeia import sanitize_output, verify_clean

    initialize_database(tmp_db)
    conn = sqlite3.connect(str(tmp_db))
    conn.execute("""
        INSERT INTO files (path, filename, extension, size, file_type)
        VALUES ('/Users/john/secret.txt', 'secret.txt', '.txt', 100, 'other')
    """)
    conn.commit()
    conn.close()

    stats = sanitize_output(tmp_db)
    assert stats["redacted"] > 0

    result = verify_clean(tmp_db)
    assert result["passed"]


def test_pipeline_checkpoint_resume():
    """#168: a fully successful run clears its own checkpoint DB.

    Checkpoints exist only to resume a crashed run — leaving them behind
    after success would mean a later run computes start = last_complete + 1
    > len(phases) and silently skips every phase. So a successful run must
    delete the checkpoint DB, and a subsequent run must therefore redo all
    phases rather than silently no-op.
    """
    from icarus.core.pipeline import Pipeline

    with tempfile.TemporaryDirectory() as tmpdir:
        src = Path(tmpdir) / "source"
        src.mkdir()
        out = Path(tmpdir) / "output.db"

        p = Pipeline(src, out, parser_name="test")
        call_log = []
        p.add_phase("phase_a", lambda ctx: call_log.append("a") or {"done": True}, "First")
        p.add_phase("phase_b", lambda ctx: call_log.append("b") or {"done": True}, "Second")

        p.run(resume=False)
        assert call_log == ["a", "b"]

        # Success must remove the checkpoint DB (and any -wal/-shm siblings).
        assert not p.checkpoint_db.exists()

        call_log.clear()
        p.run(resume=True)
        # No checkpoint left to resume from, so both phases really re-run.
        assert call_log == ["a", "b"]


def test_pipeline_populates_version_record(tmp_path):
    """Regression: a fresh build must record a finalized version row.

    Previously _create_version_record ran before the init phase created the
    DB, so the versions table stayed empty and provenance was silently lost.
    """
    from icarus.core.pipeline import create_default_pipeline

    src = tmp_path / "src"
    src.mkdir()
    (src / "test.exe").write_bytes(b"MZ" + b"\x00" * 200)
    out = tmp_path / "out.db"
    create_default_pipeline(
        src, out, parser_name="windows", skip_hygeia=True
    ).run(resume=False)

    conn = sqlite3.connect(str(out))
    try:
        rows = conn.execute(
            "SELECT parser_name, entity_count, completed_at FROM versions"
        ).fetchall()
    finally:
        conn.close()
    assert len(rows) == 1
    assert rows[0][0] == "windows"
    assert rows[0][1] > 0
    assert rows[0][2] is not None


def test_no_personal_data():
    personal_patterns = [
        r"[A-Z][a-z]+ [A-Z][a-z]+rada",
        r"[a-z]+akh@gmail\.com",
    ]
    root = Path(__file__).parent.parent
    violations = []
    for py_file in root.rglob("*.py"):
        if "test_" in py_file.name:
            continue
        content = py_file.read_text(errors="ignore")
        for pat in personal_patterns:
            if re.search(pat, content):
                violations.append(f"{py_file.name}: matches {pat}")
    for md_file in root.rglob("*.md"):
        content = md_file.read_text(errors="ignore")
        for pat in personal_patterns:
            if re.search(pat, content):
                violations.append(f"{md_file.name}: matches {pat}")

    assert not violations, "Personal data found:\n" + "\n".join(violations)


def test_provenance_columns_exist(tmp_db):
    from icarus.core.schema import ENTITY_TABLES, initialize_database

    initialize_database(tmp_db)
    conn = sqlite3.connect(str(tmp_db))

    for table in ENTITY_TABLES:
        columns = conn.execute(f"PRAGMA table_info({table})").fetchall()
        col_names = {c[1] for c in columns}
        assert "source_version_id" in col_names, f"{table} missing source_version_id"
        assert "confidence" in col_names, f"{table} missing confidence"
        assert "observed_time" in col_names, f"{table} missing observed_time"
        assert "marking" in col_names, f"{table} missing marking"

    conn.close()


def test_versions_table_exists(tmp_db):
    from icarus.core.schema import initialize_database

    initialize_database(tmp_db)
    conn = sqlite3.connect(str(tmp_db))

    tables = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='versions'"
    ).fetchall()
    assert len(tables) == 1

    columns = conn.execute("PRAGMA table_info(versions)").fetchall()
    col_names = {c[1] for c in columns}
    assert "run_id" in col_names
    assert "parser_name" in col_names
    assert "started_at" in col_names
    conn.close()


def test_marking_default(tmp_db):
    from icarus.core.schema import initialize_database

    initialize_database(tmp_db)
    conn = sqlite3.connect(str(tmp_db))

    conn.execute("""
        INSERT INTO files (path, filename, extension, size, file_type)
        VALUES ('/usr/bin/test', 'test', '', 100, 'binary')
    """)
    conn.commit()

    row = conn.execute("SELECT marking FROM files WHERE path = '/usr/bin/test'").fetchone()
    assert row[0] == "UNCLASSIFIED"
    conn.close()


def test_diff_categories_exist():
    from icarus.core.differ import DiffCategory
    assert DiffCategory.ADDITION.value == "addition"
    assert DiffCategory.DELETION.value == "deletion"
    assert DiffCategory.PROPERTY_CHANGE.value == "property_change"
    assert DiffCategory.STRUCTURAL.value == "structural"
    assert DiffCategory.RESOLUTION_CHANGE.value == "resolution_change"


def test_structural_diff(two_dbs):
    from icarus.core.differ import DiffCategory, IcarusDiffer
    from icarus.core.schema import initialize_database

    db1, db2 = two_dbs
    initialize_database(db1)
    initialize_database(db2)

    conn1 = sqlite3.connect(str(db1))
    conn1.execute("""
        INSERT INTO files (path, filename, extension, size, file_type)
        VALUES ('/usr/bin/test', 'test', '', 500, 'binary')
    """)
    conn1.execute("INSERT INTO binaries (file_id, executable_name) VALUES (1, 'test')")
    conn1.commit()
    conn1.close()

    conn2 = sqlite3.connect(str(db2))
    conn2.execute("""
        INSERT INTO files (path, filename, extension, size, file_type)
        VALUES ('/usr/sbin/test', 'test', '', 500, 'binary')
    """)
    conn2.execute("INSERT INTO binaries (file_id, executable_name) VALUES (1, 'test')")
    conn2.commit()
    conn2.close()

    with IcarusDiffer(str(db1), str(db2)) as d:
        result = d.structural_diff()
        assert result.category == DiffCategory.STRUCTURAL
        assert len(result.structural) == 1
        assert result.structural[0]["type"] == "binary_file_moved"
        # reported on the file's natural key (path), not the local file_id
        assert result.structural[0]["old_value"] == "/usr/bin/test"
        assert result.structural[0]["new_value"] == "/usr/sbin/test"


def test_full_diff_includes_structural(two_dbs):
    from icarus.core.differ import IcarusDiffer
    from icarus.core.schema import initialize_database

    db1, db2 = two_dbs
    initialize_database(db1)
    initialize_database(db2)

    with IcarusDiffer(str(db1), str(db2)) as d:
        results = d.full_diff()
        assert "structural" in results


def test_resolution_change_is_produced_by_full_diff(two_dbs):
    """full_diff() wires a real resolution (bag) diff — the RESOLUTION_CHANGE
    category the module docstring advertises now appears in its output (DIFF-02,
    #35). With no bags it must still produce no spurious resolution changes."""
    from icarus.core.differ import DiffCategory, IcarusDiffer
    from icarus.core.schema import initialize_database

    db1, db2 = two_dbs
    initialize_database(db1)
    initialize_database(db2)

    conn2 = sqlite3.connect(str(db2))
    conn2.execute("""
        INSERT INTO files (path, filename, extension, size, file_type)
        VALUES ('/usr/bin/new', 'new', '', 100, 'binary')
    """)
    conn2.commit()
    conn2.close()

    with IcarusDiffer(str(db1), str(db2)) as d:
        results = d.full_diff()

    assert "resolution" in results
    assert results["resolution"].category == DiffCategory.RESOLUTION_CHANGE
    # No bags on either side -> the resolution diff is empty, not fabricated.
    assert results["resolution"].total_changes == 0


def test_skip_hygeia_metadata(tmp_db):
    from icarus.core.pipeline import _mark_hygeia_skipped
    from icarus.core.schema import initialize_database

    initialize_database(tmp_db)

    class FakeCtx:
        output_db = tmp_db

    _mark_hygeia_skipped(FakeCtx())
    conn = sqlite3.connect(str(tmp_db))
    val = conn.execute("SELECT value FROM metadata WHERE key = 'hygeia_skipped'").fetchone()
    assert val[0] == "true"
    warn = conn.execute("SELECT value FROM metadata WHERE key = 'hygeia_warning'").fetchone()
    assert "unsanitized" in warn[0]
    conn.close()


def test_observations_table_exists(tmp_db):
    from icarus.core.schema import initialize_database

    initialize_database(tmp_db)
    conn = sqlite3.connect(str(tmp_db))
    tables = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='observations'"
    ).fetchall()
    assert len(tables) == 1

    columns = conn.execute("PRAGMA table_info(observations)").fetchall()
    col_names = {c[1] for c in columns}
    assert "entity_table" in col_names
    assert "entity_id" in col_names
    assert "observed_at" in col_names
    assert "event_type" in col_names
    assert "confidence" in col_names
    conn.close()


def test_observation_insert(tmp_db):
    from icarus.core.schema import initialize_database

    initialize_database(tmp_db)
    conn = sqlite3.connect(str(tmp_db))

    conn.execute("""
        INSERT INTO files (path, filename, extension, size, file_type)
        VALUES ('/usr/bin/test', 'test', '', 100, 'binary')
    """)
    conn.execute("""
        INSERT INTO observations (entity_table, entity_id, observed_at, event_type, confidence)
        VALUES ('files', 1, '2026-06-07T12:00:00Z', 'seen', 1.0)
    """)
    conn.commit()

    row = conn.execute("SELECT * FROM observations WHERE entity_id = 1").fetchone()
    assert row is not None
    conn.close()


def test_observations_for(tmp_db):
    from icarus.core.query import IcarusQuery
    from icarus.core.schema import initialize_database

    initialize_database(tmp_db)
    conn = sqlite3.connect(str(tmp_db))
    conn.execute("""
        INSERT INTO files (path, filename, extension, size, file_type)
        VALUES ('/usr/bin/test', 'test', '', 100, 'binary')
    """)
    conn.execute("""
        INSERT INTO observations (entity_table, entity_id, observed_at, event_type)
        VALUES ('files', 1, '2026-06-07T12:00:00Z', 'seen')
    """)
    conn.execute("""
        INSERT INTO observations (entity_table, entity_id, observed_at, event_type)
        VALUES ('files', 1, '2026-06-08T12:00:00Z', 'changed')
    """)
    conn.commit()
    conn.close()

    with IcarusQuery(str(tmp_db)) as q:
        result = q.observations_for("files", 1)
        assert result.count == 2


def test_pattern_of_life(tmp_db):
    from icarus.core.query import IcarusQuery
    from icarus.core.schema import initialize_database

    initialize_database(tmp_db)
    conn = sqlite3.connect(str(tmp_db))
    conn.execute("""
        INSERT INTO files (path, filename, extension, size, file_type)
        VALUES ('/usr/bin/test', 'test', '', 100, 'binary')
    """)
    for ts in ["2026-06-01T00:00:00Z", "2026-06-05T00:00:00Z", "2026-06-10T00:00:00Z"]:
        conn.execute(
            "INSERT INTO observations (entity_table, entity_id, observed_at, event_type) "
            "VALUES ('files', 1, ?, 'seen')", (ts,)
        )
    conn.commit()
    conn.close()

    with IcarusQuery(str(tmp_db)) as q:
        result = q.pattern_of_life("files", 1, "2026-06-02", "2026-06-09")
        assert result.count == 1


def _setup_resolver_db(tmp_db):
    """Helper: init DB and insert a version record for atom ingestion."""
    from icarus.core.schema import initialize_database
    initialize_database(tmp_db)
    conn = sqlite3.connect(str(tmp_db))
    conn.execute(
        "INSERT INTO versions (run_id, parser_name, source_path, started_at) "
        "VALUES ('test-run-1', 'test', '/test', '2026-06-07T00:00:00Z')"
    )
    conn.commit()
    conn.close()


def test_atom_immutable(tmp_db):
    from icarus.core.resolver import EntityResolver
    _setup_resolver_db(tmp_db)
    with EntityResolver(str(tmp_db), experimental=True) as r:
        atom_id = r.ingest_atom(1, "files", "key1", {"name": "a"})
        assert atom_id == 1
        conn = sqlite3.connect(str(tmp_db))
        row = conn.execute("SELECT properties FROM atoms WHERE id = 1").fetchone()
        assert "a" in row[0]
        conn.close()


def test_atom_unique_constraint(tmp_db):
    from icarus.core.resolver import EntityResolver
    _setup_resolver_db(tmp_db)
    with EntityResolver(str(tmp_db), experimental=True) as r:
        r.ingest_atom(1, "files", "key1", {"name": "a"})
        with pytest.raises(sqlite3.IntegrityError):
            r.ingest_atom(1, "files", "key1", {"name": "b"})


def test_bag_creation(tmp_db):
    from icarus.core.resolver import EntityResolver
    _setup_resolver_db(tmp_db)
    with EntityResolver(str(tmp_db), experimental=True) as r:
        a1 = r.ingest_atom(1, "files", "k1", {"x": 1})
        a2 = r.ingest_atom(1, "files", "k2", {"x": 2})
        bag_id = r.create_bag("files", [a1, a2], canonical_key="merged")
        assert bag_id >= 1

        conn = sqlite3.connect(str(tmp_db))
        count = conn.execute(
            "SELECT atom_count FROM bags WHERE id = ?", (bag_id,)
        ).fetchone()[0]
        assert count == 2
        conn.close()


def test_merge_bags_logs_event(tmp_db):
    from icarus.core.resolver import EntityResolver
    _setup_resolver_db(tmp_db)
    with EntityResolver(str(tmp_db), experimental=True) as r:
        a1 = r.ingest_atom(1, "files", "k1", {"x": 1})
        a2 = r.ingest_atom(1, "files", "k2", {"x": 2})
        a3 = r.ingest_atom(1, "files", "k3", {"x": 3})
        b1 = r.create_bag("files", [a1])
        b2 = r.create_bag("files", [a2, a3])

        surviving = r.merge_bags([b1, b2], reason="duplicate entity")
        assert surviving == b1

        conn = sqlite3.connect(str(tmp_db))
        events = conn.execute(
            "SELECT event_type, reason FROM resolution_event_log WHERE event_type = 'merge'"
        ).fetchall()
        assert len(events) == 1
        assert events[0][1] == "duplicate entity"

        atom_count = conn.execute(
            "SELECT atom_count FROM bags WHERE id = ?", (surviving,)
        ).fetchone()[0]
        assert atom_count == 3
        conn.close()


def test_merge_bags_shared_atom_does_not_raise(tmp_db):
    """#30: bag_atoms is PRIMARY KEY(bag_id, atom_id). Merging two bags that
    both already contain the same atom used to raise IntegrityError from the
    plain UPDATE bag_atoms SET bag_id=? — the public merge_bags API must
    survive this without ever bypassing it."""
    from icarus.core.resolver import EntityResolver
    _setup_resolver_db(tmp_db)
    with EntityResolver(str(tmp_db), experimental=True) as r:
        a1 = r.ingest_atom(1, "files", "k1", {"x": 1})
        a2 = r.ingest_atom(1, "files", "k2", {"x": 2})
        a3 = r.ingest_atom(1, "files", "k3", {"x": 3})
        # create_bag rejects multi-bag membership. Simulate a legacy/corrupt
        # database that predates that validation so merge_bags remains robust
        # when repairing an overlap already present on disk.
        b1 = r.create_bag("files", [a1, a2])
        b2 = r.create_bag("files", [a3])
        r.conn.execute(
            "INSERT INTO bag_atoms (bag_id, atom_id) VALUES (?, ?)", (b2, a2)
        )
        r.conn.execute("UPDATE bags SET atom_count = 2 WHERE id = ?", (b2,))
        r.conn.commit()

        surviving = r.merge_bags([b1, b2], reason="shared atom")
        assert surviving == b1

        conn = sqlite3.connect(str(tmp_db))
        try:
            # The shared atom collapses to a single row under the survivor;
            # a1/a2/a3 all present, no duplicates, no IntegrityError raised.
            rows = conn.execute(
                "SELECT atom_id FROM bag_atoms WHERE bag_id = ? ORDER BY atom_id",
                (surviving,),
            ).fetchall()
            assert [r_[0] for r_ in rows] == [a1, a2, a3]

            # The losing bag's rows are fully gone.
            assert conn.execute(
                "SELECT COUNT(*) FROM bag_atoms WHERE bag_id = ?", (b2,)
            ).fetchone()[0] == 0
            assert conn.execute(
                "SELECT COUNT(*) FROM bags WHERE id = ?", (b2,)
            ).fetchone()[0] == 0

            atom_count = conn.execute(
                "SELECT atom_count FROM bags WHERE id = ?", (surviving,)
            ).fetchone()[0]
            assert atom_count == 3
        finally:
            conn.close()


def test_split_bag_reversible(tmp_db):
    from icarus.core.resolver import EntityResolver
    _setup_resolver_db(tmp_db)
    with EntityResolver(str(tmp_db), experimental=True) as r:
        a1 = r.ingest_atom(1, "files", "k1", {"x": 1})
        a2 = r.ingest_atom(1, "files", "k2", {"x": 2})
        a3 = r.ingest_atom(1, "files", "k3", {"x": 3})
        bag_id = r.create_bag("files", [a1, a2, a3])

        new_bag = r.split_bag(bag_id, [a3], reason="wrong merge")
        assert new_bag != bag_id

        conn = sqlite3.connect(str(tmp_db))
        orig_count = conn.execute(
            "SELECT atom_count FROM bags WHERE id = ?", (bag_id,)
        ).fetchone()[0]
        new_count = conn.execute(
            "SELECT atom_count FROM bags WHERE id = ?", (new_bag,)
        ).fetchone()[0]
        assert orig_count == 2
        assert new_count == 1

        orig_bag_exists = conn.execute(
            "SELECT id FROM bags WHERE id = ?", (bag_id,)
        ).fetchone()
        assert orig_bag_exists is not None
        conn.close()


def test_event_log_append_only(tmp_db):
    from icarus.core.resolver import EntityResolver
    _setup_resolver_db(tmp_db)
    with EntityResolver(str(tmp_db), experimental=True) as r:
        a1 = r.ingest_atom(1, "files", "k1", {"x": 1})
        r.create_bag("files", [a1])

    conn = sqlite3.connect(str(tmp_db))
    events = conn.execute("SELECT * FROM resolution_event_log").fetchall()
    assert len(events) == 1

    event_id = events[0][0]
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute(
            "INSERT INTO resolution_event_log (id, event_type, bag_id, atom_ids, timestamp) "
            "VALUES (?, 'test', 1, '[]', '2026-01-01')", (event_id,)
        )
    conn.close()


def test_unresolved_atoms(tmp_db):
    from icarus.core.resolver import EntityResolver
    _setup_resolver_db(tmp_db)
    with EntityResolver(str(tmp_db), experimental=True) as r:
        a1 = r.ingest_atom(1, "files", "k1", {"x": 1})
        a2 = r.ingest_atom(1, "files", "k2", {"x": 2})
        a3 = r.ingest_atom(1, "files", "k3", {"x": 3})

        unresolved = r.unresolved_atoms("files")
        assert len(unresolved) == 3

        r.create_bag("files", [a1, a2])
        unresolved = r.unresolved_atoms("files")
        assert len(unresolved) == 1
        assert a3 in unresolved


def test_atoms_fts_trigger(tmp_db):
    from icarus.core.resolver import EntityResolver
    _setup_resolver_db(tmp_db)
    with EntityResolver(str(tmp_db), experimental=True) as r:
        r.ingest_atom(1, "files", "server_config", {"name": "nginx.conf", "role": "webserver"})

    conn = sqlite3.connect(str(tmp_db))
    rows = conn.execute(
        "SELECT rowid FROM atoms_fts WHERE atoms_fts MATCH 'server_config'"
    ).fetchall()
    assert len(rows) == 1
    conn.close()


def test_cross_graph_query(tmp_db):
    from icarus.core.query import IcarusQuery
    from icarus.core.schema import initialize_database

    initialize_database(tmp_db)
    conn = sqlite3.connect(str(tmp_db))
    conn.execute("""
        INSERT INTO files (path, filename, extension, size, file_type)
        VALUES ('/usr/bin/test', 'test', '', 100, 'binary')
    """)
    conn.execute("""
        INSERT INTO observations (entity_table, entity_id, observed_at, event_type, observer)
        VALUES ('files', 1, '2026-06-07T00:00:00Z', 'seen', 'linux_parser')
    """)
    conn.execute("""
        INSERT INTO observations (entity_table, entity_id, observed_at, event_type, observer)
        VALUES ('files', 1, '2026-06-08T00:00:00Z', 'changed', 'linux_parser')
    """)
    conn.commit()
    conn.close()

    with IcarusQuery(str(tmp_db)) as q:
        result = q.cross_graph_query("files")
        assert result.count == 2

        result_filtered = q.cross_graph_query("files", event_type="seen")
        assert result_filtered.count == 1


def test_observation_diff_query(tmp_db):
    from icarus.core.query import IcarusQuery
    from icarus.core.schema import initialize_database

    initialize_database(tmp_db)
    conn = sqlite3.connect(str(tmp_db))
    conn.execute(
        "INSERT INTO versions (run_id, parser_name, source_path, started_at) "
        "VALUES ('run1', 'test', '/test', '2026-06-07T00:00:00Z')"
    )
    conn.execute(
        "INSERT INTO versions (run_id, parser_name, source_path, started_at) "
        "VALUES ('run2', 'test', '/test', '2026-06-08T00:00:00Z')"
    )
    conn.execute("""
        INSERT INTO files (path, filename, extension, size, file_type)
        VALUES ('/usr/bin/a', 'a', '', 100, 'binary')
    """)
    conn.execute("""
        INSERT INTO observations (entity_table, entity_id, observed_at, event_type, version_id)
        VALUES ('files', 1, '2026-06-07T00:00:00Z', 'seen', 1)
    """)
    conn.execute("""
        INSERT INTO observations (entity_table, entity_id, observed_at, event_type, version_id)
        VALUES ('files', 1, '2026-06-08T00:00:00Z', 'changed', 2)
    """)
    conn.commit()
    conn.close()

    with IcarusQuery(str(tmp_db)) as q:
        result = q.observation_diff(1, 2)
        assert result.count == 1


def test_observation_diff_differ(two_dbs):
    from icarus.core.differ import IcarusDiffer
    from icarus.core.schema import initialize_database

    db1, db2 = two_dbs
    initialize_database(db1)
    initialize_database(db2)

    conn1 = sqlite3.connect(str(db1))
    conn1.execute("""
        INSERT INTO files (path, filename, extension, size, file_type)
        VALUES ('/usr/bin/a', 'a', '', 100, 'binary')
    """)
    conn1.execute("""
        INSERT INTO observations (entity_table, entity_id, observed_at, event_type)
        VALUES ('files', 1, '2026-06-07T00:00:00Z', 'seen')
    """)
    conn1.commit()
    conn1.close()

    conn2 = sqlite3.connect(str(db2))
    conn2.execute("""
        INSERT INTO files (path, filename, extension, size, file_type)
        VALUES ('/usr/bin/a', 'a', '', 100, 'binary')
    """)
    conn2.execute("""
        INSERT INTO observations (entity_table, entity_id, observed_at, event_type)
        VALUES ('files', 1, '2026-06-07T00:00:00Z', 'seen')
    """)
    conn2.execute("""
        INSERT INTO observations (entity_table, entity_id, observed_at, event_type)
        VALUES ('files', 1, '2026-06-08T00:00:00Z', 'changed')
    """)
    conn2.commit()
    conn2.close()

    with IcarusDiffer(str(db1), str(db2)) as d:
        result = d.observation_diff()
        assert len(result.added) == 1
        assert len(result.removed) == 0


def test_valid_tables_updated():
    from icarus.core import VALID_TABLES
    for table in ["observations", "atoms", "bags", "bag_atoms", "resolution_event_log"]:
        assert table in VALID_TABLES


def test_obs_fk_any_ontology_table(tmp_db):
    from icarus.core.schema import initialize_database

    initialize_database(tmp_db)
    conn = sqlite3.connect(str(tmp_db))

    conn.execute("""
        INSERT INTO files (path, filename, extension, size, file_type)
        VALUES ('/usr/bin/a', 'a', '', 100, 'binary')
    """)
    conn.execute("""
        INSERT INTO sandbox_profiles (name) VALUES ('test_profile')
    """)
    conn.execute("""
        INSERT INTO observations (entity_table, entity_id, observed_at, event_type)
        VALUES ('files', 1, '2026-06-07T00:00:00Z', 'seen')
    """)
    conn.execute("""
        INSERT INTO observations (entity_table, entity_id, observed_at, event_type)
        VALUES ('sandbox_profiles', 1, '2026-06-07T00:00:00Z', 'seen')
    """)
    conn.commit()

    rows = conn.execute("SELECT COUNT(*) FROM observations").fetchone()
    assert rows[0] == 2
    conn.close()


def test_migration_v2_to_v3(tmp_db):
    from icarus.core.schema import migrate_v2_to_v3

    conn = sqlite3.connect(str(tmp_db))
    conn.executescript("""
        PRAGMA journal_mode = WAL;
        CREATE TABLE IF NOT EXISTS metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            path TEXT NOT NULL UNIQUE, filename TEXT NOT NULL,
            extension TEXT, size INTEGER DEFAULT 0, file_type TEXT
        );
        CREATE TABLE IF NOT EXISTS binaries (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            file_id INTEGER NOT NULL, bundle_id TEXT
        );
        CREATE TABLE IF NOT EXISTS daemons (
            id INTEGER PRIMARY KEY AUTOINCREMENT, label TEXT NOT NULL UNIQUE,
            plist_path TEXT NOT NULL, program TEXT
        );
        CREATE TABLE IF NOT EXISTS entitlements (
            id INTEGER PRIMARY KEY AUTOINCREMENT, binary_id INTEGER NOT NULL,
            key TEXT NOT NULL, value TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS sandbox_profiles (
            id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL UNIQUE
        );
        CREATE TABLE IF NOT EXISTS sandbox_rules (
            id INTEGER PRIMARY KEY AUTOINCREMENT, profile_id INTEGER NOT NULL,
            operation TEXT NOT NULL, action TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS kexts (
            id INTEGER PRIMARY KEY AUTOINCREMENT, bundle_id TEXT NOT NULL UNIQUE
        );
        CREATE TABLE IF NOT EXISTS frameworks (
            id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, path TEXT NOT NULL UNIQUE
        );
        INSERT INTO metadata VALUES ('schema_version', '2');
        INSERT INTO files (path, filename, size, file_type) VALUES ('/bin/ls', 'ls', 500, 'binary');
    """)
    conn.commit()

    migrate_v2_to_v3(conn)

    version = conn.execute(
        "SELECT value FROM metadata WHERE key = 'schema_version'"
    ).fetchone()[0]
    assert version == "3"

    row = conn.execute("SELECT confidence, marking FROM files WHERE path = '/bin/ls'").fetchone()
    assert row[0] == 1.0
    assert row[1] == "UNCLASSIFIED"

    tables = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='versions'"
    ).fetchall()
    assert len(tables) == 1

    conn.close()


def test_migration_v3_to_v4(tmp_db):
    from icarus.core.schema import migrate_v2_to_v3, migrate_v3_to_v4

    conn = sqlite3.connect(str(tmp_db))
    conn.executescript("""
        PRAGMA journal_mode = WAL;
        CREATE TABLE IF NOT EXISTS metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            path TEXT NOT NULL UNIQUE, filename TEXT NOT NULL,
            extension TEXT, size INTEGER DEFAULT 0, file_type TEXT
        );
        CREATE TABLE IF NOT EXISTS binaries (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            file_id INTEGER NOT NULL, bundle_id TEXT
        );
        CREATE TABLE IF NOT EXISTS daemons (
            id INTEGER PRIMARY KEY AUTOINCREMENT, label TEXT NOT NULL UNIQUE,
            plist_path TEXT NOT NULL, program TEXT
        );
        CREATE TABLE IF NOT EXISTS entitlements (
            id INTEGER PRIMARY KEY AUTOINCREMENT, binary_id INTEGER NOT NULL,
            key TEXT NOT NULL, value TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS sandbox_profiles (
            id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL UNIQUE
        );
        CREATE TABLE IF NOT EXISTS sandbox_rules (
            id INTEGER PRIMARY KEY AUTOINCREMENT, profile_id INTEGER NOT NULL,
            operation TEXT NOT NULL, action TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS kexts (
            id INTEGER PRIMARY KEY AUTOINCREMENT, bundle_id TEXT NOT NULL UNIQUE
        );
        CREATE TABLE IF NOT EXISTS frameworks (
            id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, path TEXT NOT NULL UNIQUE
        );
        INSERT INTO metadata VALUES ('schema_version', '2');
        INSERT INTO files (path, filename, size, file_type) VALUES ('/bin/ls', 'ls', 500, 'binary');
    """)
    conn.commit()

    migrate_v2_to_v3(conn)
    migrate_v3_to_v4(conn)

    version = conn.execute(
        "SELECT value FROM metadata WHERE key = 'schema_version'"
    ).fetchone()[0]
    assert version == "4"

    phase2_tables = {"observations", "atoms", "bags", "bag_atoms", "resolution_event_log"}
    existing = {r[0] for r in conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table'"
    ).fetchall()}
    for t in phase2_tables:
        assert t in existing, f"Missing table after v3->v4 migration: {t}"

    triggers = {r[0] for r in conn.execute(
        "SELECT name FROM sqlite_master WHERE type='trigger'"
    ).fetchall()}
    assert "atoms_ai" in triggers
    assert "atoms_ad" in triggers

    row = conn.execute("SELECT confidence, marking FROM files WHERE path = '/bin/ls'").fetchone()
    assert row[0] == 1.0
    assert row[1] == "UNCLASSIFIED"

    conn.close()


def test_migration_v4_to_v5(tmp_db):
    from icarus.core.schema import migrate_v4_to_v5

    conn = sqlite3.connect(str(tmp_db))
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS daemons (
            id INTEGER PRIMARY KEY AUTOINCREMENT, label TEXT NOT NULL UNIQUE,
            plist_path TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS versions (id INTEGER PRIMARY KEY AUTOINCREMENT);
        INSERT INTO metadata VALUES ('schema_version', '4');
    """)
    conn.commit()

    migrate_v4_to_v5(conn)

    version = conn.execute(
        "SELECT value FROM metadata WHERE key = 'schema_version'"
    ).fetchone()[0]
    assert version == "5"

    tables = {r[0] for r in conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table'"
    ).fetchall()}
    assert "mach_services" in tables

    cols = {c[1] for c in conn.execute("PRAGMA table_info(mach_services)")}
    assert {"daemon_id", "service_name"} <= cols

    conn.close()


# ---------------------------------------------------------------------------
# Differ audit-backlog regression tests (findings #38/#78, #43, #48, #158, #225)
# ---------------------------------------------------------------------------

def _add_file(db, path, sha256):
    conn = sqlite3.connect(str(db))
    conn.execute(
        "INSERT INTO files (path, filename, extension, size, file_type, sha256) "
        "VALUES (?, ?, '', 1, 'binary', ?)",
        (path, path.rsplit("/", 1)[-1], sha256),
    )
    conn.commit()
    conn.close()


def test_changed_entities_detects_null_transitions(two_dbs):
    """#38/#78: changed_entities must catch NULL<->value transitions.

    SQL `!=` is NULL-blind (NULL != x is NULL, never TRUE), so NULL->value and
    value->NULL changes were silently dropped. The IS NOT fix must report them,
    while genuinely-unchanged rows (including NULL->NULL) stay excluded.
    """
    from icarus.core.differ import IcarusDiffer
    from icarus.core.schema import initialize_database

    db1, db2 = two_dbs
    initialize_database(db1)
    initialize_database(db2)

    _add_file(db1, "/a", "aaa")     # value -> value
    _add_file(db2, "/a", "bbb")
    _add_file(db1, "/b", None)      # NULL  -> value
    _add_file(db2, "/b", "ccc")
    _add_file(db1, "/c", "ddd")     # value -> NULL
    _add_file(db2, "/c", None)
    _add_file(db1, "/same", "eee")  # unchanged
    _add_file(db2, "/same", "eee")
    _add_file(db1, "/nn", None)     # NULL  -> NULL
    _add_file(db2, "/nn", None)

    with IcarusDiffer(str(db1), str(db2)) as d:
        result = d.changed_entities("files", "path", "sha256")
        by_path = {r["path"]: (r["old_value"], r["new_value"]) for r in result.changed}

    assert by_path == {
        "/a": ("aaa", "bbb"),
        "/b": (None, "ccc"),
        "/c": ("ddd", None),
    }


def test_removed_entities_positive(two_dbs):
    """#158(a): a file present only in the old DB is reported as removed."""
    from icarus.core.differ import IcarusDiffer
    from icarus.core.schema import initialize_database

    db1, db2 = two_dbs
    initialize_database(db1)
    initialize_database(db2)

    conn = sqlite3.connect(str(db1))
    conn.execute(
        "INSERT INTO files (path, filename, extension, size, file_type) "
        "VALUES ('/usr/bin/gone', 'gone', '', 1, 'binary')"
    )
    conn.execute(  # shared file -> must NOT be reported as removed
        "INSERT INTO files (path, filename, extension, size, file_type) "
        "VALUES ('/usr/bin/keep', 'keep', '', 1, 'binary')"
    )
    conn.commit()
    conn.close()

    conn = sqlite3.connect(str(db2))
    conn.execute(
        "INSERT INTO files (path, filename, extension, size, file_type) "
        "VALUES ('/usr/bin/keep', 'keep', '', 1, 'binary')"
    )
    conn.commit()
    conn.close()

    with IcarusDiffer(str(db1), str(db2)) as d:
        removed = d.removed_entities("files", "path")
        assert len(removed.removed) == 1
        assert removed.removed[0]["path"] == "/usr/bin/gone"

        full = d.full_diff()
        assert full["files_removed"].total_changes == 1
        assert full["files_removed"].removed[0]["path"] == "/usr/bin/gone"


def test_structural_diff_sandbox_and_entitlement_branches(two_dbs):
    """#158(c)/(d): sandbox_rule_reassigned and entitlement_reassigned branches."""
    from icarus.core.differ import IcarusDiffer
    from icarus.core.schema import initialize_database

    db1, db2 = two_dbs
    initialize_database(db1)
    initialize_database(db2)

    # Referenced profiles and binaries must exist so the diff can resolve each
    # foreign key to its natural key (profile name / binary identity). The
    # reassignment is expressed by pointing at a differently-named profile and a
    # different binary (distinct executable_name), not by a raw id change.
    conn = sqlite3.connect(str(db1))
    conn.execute("INSERT INTO sandbox_profiles (name) VALUES ('profile.A')")  # id 1
    conn.execute("INSERT INTO sandbox_profiles (name) VALUES ('profile.B')")  # id 2
    conn.execute(
        "INSERT INTO sandbox_rules (profile_id, operation, action) "
        "VALUES (1, 'file-read-data', 'allow')"
    )
    conn.execute("INSERT INTO files (path, filename) VALUES ('/bin/appA', 'appA')")  # id 1
    conn.execute("INSERT INTO binaries (file_id, executable_name) VALUES (1, 'appA')")  # id 1
    conn.execute(
        "INSERT INTO entitlements (binary_id, key, value) "
        "VALUES (1, 'com.apple.security.network.client', 'true')"
    )
    conn.commit()
    conn.close()

    conn = sqlite3.connect(str(db2))
    conn.execute("INSERT INTO sandbox_profiles (name) VALUES ('profile.A')")  # id 1
    conn.execute("INSERT INTO sandbox_profiles (name) VALUES ('profile.B')")  # id 2
    conn.execute(  # same rule, now under profile.B (reassigned by profile name)
        "INSERT INTO sandbox_rules (profile_id, operation, action) "
        "VALUES (2, 'file-read-data', 'allow')"
    )
    conn.execute("INSERT INTO files (path, filename) VALUES ('/bin/appB', 'appB')")  # id 1
    conn.execute("INSERT INTO binaries (file_id, executable_name) VALUES (1, 'appB')")  # id 1
    conn.execute(  # same entitlement, now on the appB binary (reassigned by file path)
        "INSERT INTO entitlements (binary_id, key, value) "
        "VALUES (1, 'com.apple.security.network.client', 'true')"
    )
    conn.commit()
    conn.close()

    with IcarusDiffer(str(db1), str(db2)) as d:
        result = d.structural_diff()

    by_type = {c["type"]: c for c in result.structural}
    assert by_type["sandbox_rule_reassigned"]["old_value"] == "profile.A"
    assert by_type["sandbox_rule_reassigned"]["new_value"] == "profile.B"
    assert by_type["entitlement_reassigned"]["old_value"] == "appA"
    assert by_type["entitlement_reassigned"]["new_value"] == "appB"


def test_structural_diff_dedupes_no_cartesian(two_dbs):
    """#48: duplicate join keys must not Cartesian-product into false rows.

    Each side has two 'helper' binaries, two 'mach-lookup' rules and two 'k/v'
    entitlements (ambiguous keys) plus one unambiguous 'solo' binary that really
    moved. The old joins cross-produced the duplicates into six false
    moved/reassigned rows; only the genuine 'solo' move must survive.
    """
    from icarus.core.differ import IcarusDiffer
    from icarus.core.schema import initialize_database

    db1, db2 = two_dbs
    initialize_database(db1)
    initialize_database(db2)

    def seed(db, solo_path):
        conn = sqlite3.connect(str(db))
        # Ambiguous rows (duplicate executable_name / operation+action / key+value)
        # are filtered out by the HAVING COUNT(*) = 1 dedup guard before any join,
        # so their dangling foreign keys never need to resolve.
        conn.execute("INSERT INTO binaries (file_id, executable_name) VALUES (10, 'helper')")
        conn.execute("INSERT INTO binaries (file_id, executable_name) VALUES (20, 'helper')")
        # The unambiguous 'solo' binary really moved; its file must exist so the
        # natural-key (path) join resolves.
        conn.execute("INSERT INTO files (path, filename) VALUES (?, 'solo')", (solo_path,))
        fid = conn.execute("SELECT id FROM files WHERE path=?", (solo_path,)).fetchone()[0]
        conn.execute(
            "INSERT INTO binaries (file_id, executable_name) VALUES (?, 'solo')", (fid,)
        )
        conn.execute(
            "INSERT INTO sandbox_rules (profile_id, operation, action) "
            "VALUES (1, 'mach-lookup', 'allow')"
        )
        conn.execute(
            "INSERT INTO sandbox_rules (profile_id, operation, action) "
            "VALUES (2, 'mach-lookup', 'allow')"
        )
        conn.execute("INSERT INTO entitlements (binary_id, key, value) VALUES (5, 'k', 'v')")
        conn.execute("INSERT INTO entitlements (binary_id, key, value) VALUES (6, 'k', 'v')")
        conn.commit()
        conn.close()

    seed(db1, "/bin/solo")   # solo -> /bin/solo (old)
    seed(db2, "/sbin/solo")  # solo -> /sbin/solo (new; genuine move)

    with IcarusDiffer(str(db1), str(db2)) as d:
        result = d.structural_diff()

    assert [c["type"] for c in result.structural] == ["binary_file_moved"]
    only = result.structural[0]
    assert only["entity"] == "solo"
    assert only["old_value"] == "/bin/solo"
    assert only["new_value"] == "/sbin/solo"


def test_entitlement_diff_uses_natural_key(two_dbs):
    """#43: new_entitlements must diff on bundle_id+key+value, not autoincrement id.

    The shared entitlement is given a different autoincrement id in each DB (by
    inserting the genuinely-new entitlement first in the new DB). An id-based
    diff flags the shared row as new and misses the real one; the natural-key
    diff reports exactly the genuinely-new entitlement.
    """
    from icarus.core.differ import IcarusDiffer
    from icarus.core.schema import initialize_database

    db1, db2 = two_dbs
    initialize_database(db1)
    initialize_database(db2)

    conn = sqlite3.connect(str(db1))
    conn.execute(
        "INSERT INTO binaries (file_id, executable_name, bundle_id) "
        "VALUES (1, 'app', 'com.acme.app')"
    )
    bid1 = conn.execute("SELECT id FROM binaries WHERE bundle_id='com.acme.app'").fetchone()[0]
    conn.execute(
        "INSERT INTO entitlements (binary_id, key, value) "
        "VALUES (?, 'com.apple.security.network.client', 'true')",
        (bid1,),
    )
    conn.commit()
    conn.close()

    conn = sqlite3.connect(str(db2))
    conn.execute(
        "INSERT INTO binaries (file_id, executable_name, bundle_id) "
        "VALUES (1, 'app', 'com.acme.app')"
    )
    bid2 = conn.execute("SELECT id FROM binaries WHERE bundle_id='com.acme.app'").fetchone()[0]
    conn.execute(  # genuinely-new entitlement inserted first -> shifts the shared id
        "INSERT INTO entitlements (binary_id, key, value) "
        "VALUES (?, 'com.apple.security.get-task-allow', 'true')",
        (bid2,),
    )
    conn.execute(  # shared entitlement: same bundle+key+value -> must NOT be 'new'
        "INSERT INTO entitlements (binary_id, key, value) "
        "VALUES (?, 'com.apple.security.network.client', 'true')",
        (bid2,),
    )
    conn.commit()
    conn.close()

    with IcarusDiffer(str(db1), str(db2)) as d:
        new_keys = sorted(r["key"] for r in d.entitlement_diff()["new_entitlements"].added)

    assert new_keys == ["com.apple.security.get-task-allow"]


def test_differ_opens_databases_read_only(two_dbs):
    """#225: the differ opens both DBs immutable read-only and never writes."""
    from icarus.core.differ import IcarusDiffer
    from icarus.core.schema import initialize_database

    db1, db2 = two_dbs
    initialize_database(db1)
    initialize_database(db2)

    with IcarusDiffer(str(db1), str(db2)) as d:
        with pytest.raises(sqlite3.OperationalError):
            d.conn.execute("CREATE TABLE should_not_exist (x)")
        # reads still work through the read-only connection
        assert d.added_entities("files", "path").total_changes == 0

    # immutable=1 means no WAL/SHM sidecars are ever created for either DB
    for base in (db1, db2):
        assert not Path(str(base) + "-wal").exists()
        assert not Path(str(base) + "-shm").exists()


# ---------------------------------------------------------------------------
# Schema/query audit-backlog regression tests (findings #63, #68)
# ---------------------------------------------------------------------------

class _FakeConn:
    """Minimal connection double that records executed pragma SQL.

    Lets us assert exactly what _apply_performance_pragmas() computes and
    asks SQLite to set, independent of whatever further clamping a given
    SQLite build's compiled-in mmap ceiling applies on top of that (which
    varies by platform/build and is not what finding #63 is about).
    """

    def __init__(self):
        self.executed: list = []

    def execute(self, sql, params=()):
        self.executed.append(sql)


def _pragma_value(executed: list, pragma: str) -> int:
    stmt = next(s for s in executed if pragma in s)
    return int(stmt.split("=", 1)[1].strip())


def test_pragmas_scale_with_available_not_total_ram(monkeypatch):
    """#63: pragma sizing must track AVAILABLE RAM, not TOTAL RAM.

    A host can report abundant total RAM while very little is actually free
    (e.g. under load from other processes). Available is set low and total
    is set implausibly high; the resulting mmap/cache targets must derive
    from the low available figure, not the high total one.
    """
    import icarus.core.schema as schema

    small_available = 512 * 1024 * 1024   # 512 MiB actually free
    huge_total = 64 * 1024 * 1024 * 1024  # 64 GiB installed

    monkeypatch.setattr(schema, "_get_available_ram_bytes", lambda: small_available)
    monkeypatch.setattr(schema, "_get_system_ram_bytes", lambda: huge_total)

    fake = _FakeConn()
    schema._apply_performance_pragmas(fake)

    mmap_bytes = _pragma_value(fake.executed, "mmap_size")
    cache_kb = -_pragma_value(fake.executed, "cache_size")

    assert mmap_bytes == int(small_available * schema.RAM_TARGET_RATIO)
    assert cache_kb == int(small_available * schema.RAM_TARGET_RATIO) // 1024
    # Nowhere near what sizing off the (much larger) total would have produced.
    assert mmap_bytes < int(huge_total * schema.RAM_TARGET_RATIO)


def test_pragmas_capped_at_sane_ceiling_on_high_ram_box(monkeypatch):
    """#63: even with abundant available RAM, cache/mmap must be capped at a
    sane ceiling rather than scaled up without bound."""
    import icarus.core.schema as schema

    monkeypatch.setattr(
        schema, "_get_available_ram_bytes", lambda: 512 * 1024 * 1024 * 1024  # 512 GiB
    )

    fake = _FakeConn()
    schema._apply_performance_pragmas(fake)

    mmap_bytes = _pragma_value(fake.executed, "mmap_size")
    cache_kb = -_pragma_value(fake.executed, "cache_size")

    assert mmap_bytes == schema.FALLBACK_MMAP_BYTES
    assert cache_kb == schema.FALLBACK_CACHE_KB


def test_icarus_query_working_connection_gets_tuned_cache_size(tmp_db):
    """#63: IcarusQuery's long-lived connection must carry the RAM-scaled
    cache_size pragma, not just a throwaway init connection that
    initialize_database() closes immediately after applying it.
    """
    from icarus.core.query import IcarusQuery
    from icarus.core.schema import initialize_database

    initialize_database(tmp_db)
    with IcarusQuery(str(tmp_db)) as q:
        cache_size = q.conn.execute("PRAGMA cache_size").fetchone()[0]
        assert cache_size != -2000  # sqlite3's own untouched default


def test_bare_connect_vs_open_db_foreign_key_enforcement(tmp_db):
    """#68: parsers/pipeline write through a bare sqlite3.connect() today,
    which silently accepts entities with dangling foreign keys because
    SQLite defaults foreign_keys OFF per-connection. open_db() must close
    that gap for any connection routed through it.
    """
    from icarus.core.schema import initialize_database, open_db

    initialize_database(tmp_db)

    # The pre-fix pattern used throughout the codebase: a bare connect() has
    # FK enforcement off, so a binaries row referencing a nonexistent
    # files.id is silently accepted. This is the exact bug #68 documents.
    bare = sqlite3.connect(str(tmp_db))
    bare.execute("INSERT INTO binaries (file_id, bundle_id) VALUES (99999, 'orphan.bare')")
    bare.commit()
    assert bare.execute(
        "SELECT COUNT(*) FROM binaries WHERE bundle_id = 'orphan.bare'"
    ).fetchone()[0] == 1
    bare.close()

    # open_db() must reject the same dangling reference...
    conn = open_db(tmp_db)
    assert conn.execute("PRAGMA foreign_keys").fetchone()[0] == 1
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute(
            "INSERT INTO binaries (file_id, bundle_id) VALUES (88888, 'orphan.open_db')"
        )

    # ...while a real, valid reference still inserts cleanly on that same connection.
    conn.execute(
        "INSERT INTO files (path, filename, extension, size, file_type) "
        "VALUES ('/usr/bin/real', 'real', '', 1, 'binary')"
    )
    file_id = conn.execute("SELECT id FROM files WHERE path = '/usr/bin/real'").fetchone()[0]
    conn.execute(
        "INSERT INTO binaries (file_id, bundle_id) VALUES (?, 'com.example.real')", (file_id,)
    )
    conn.commit()
    assert conn.execute(
        "SELECT COUNT(*) FROM binaries WHERE bundle_id = 'com.example.real'"
    ).fetchone()[0] == 1
    conn.close()


def test_initialize_database_migration_path_leaves_fk_enforceable(tmp_db):
    """#68: the migration path (upgrading an existing v2 DB) must also end
    up enforcing FK constraints, not only a freshly-created (CORE_SCHEMA)
    database -- CORE_SCHEMA's own 'PRAGMA foreign_keys = ON' is skipped
    entirely on the migration branch.
    """
    from icarus.core.schema import initialize_database, open_db

    # Build a legacy v2-shaped database by hand (mirrors test_migration_v2_to_v3).
    conn = sqlite3.connect(str(tmp_db))
    conn.executescript("""
        PRAGMA journal_mode = WAL;
        CREATE TABLE IF NOT EXISTS metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            path TEXT NOT NULL UNIQUE, filename TEXT NOT NULL,
            extension TEXT, size INTEGER DEFAULT 0, file_type TEXT
        );
        CREATE TABLE IF NOT EXISTS binaries (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            file_id INTEGER NOT NULL REFERENCES files(id), bundle_id TEXT
        );
        CREATE TABLE IF NOT EXISTS daemons (
            id INTEGER PRIMARY KEY AUTOINCREMENT, label TEXT NOT NULL UNIQUE,
            plist_path TEXT NOT NULL, program TEXT
        );
        CREATE TABLE IF NOT EXISTS entitlements (
            id INTEGER PRIMARY KEY AUTOINCREMENT, binary_id INTEGER NOT NULL,
            key TEXT NOT NULL, value TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS sandbox_profiles (
            id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL UNIQUE
        );
        CREATE TABLE IF NOT EXISTS sandbox_rules (
            id INTEGER PRIMARY KEY AUTOINCREMENT, profile_id INTEGER NOT NULL,
            operation TEXT NOT NULL, action TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS kexts (
            id INTEGER PRIMARY KEY AUTOINCREMENT, bundle_id TEXT NOT NULL UNIQUE
        );
        CREATE TABLE IF NOT EXISTS frameworks (
            id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, path TEXT NOT NULL UNIQUE
        );
        INSERT INTO metadata VALUES ('schema_version', '2');
    """)
    conn.commit()
    conn.close()

    stats = initialize_database(tmp_db)
    assert stats["schema_version"] == 6

    conn = open_db(tmp_db)
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute("INSERT INTO binaries (file_id, bundle_id) VALUES (12345, 'orphan')")
    conn.close()


def test_open_db_readonly_is_immutable_with_no_side_effects(tmp_db):
    """open_db(readonly=True, immutable=True): reads work, writes are rejected,
    and no -wal/-shm sidecar files get created -- mirrors the differ's
    read-only open pattern for untrusted/read-only use (finding #225).

    Note (D1, #34): the no-sidecar guarantee is the ``immutable=1`` behaviour,
    now behind the explicit ``immutable=True`` flag. Plain ``readonly=True``
    (used by the query engine) is ``mode=ro`` and deliberately HONOURS the WAL
    so a freshly-built database reads current data -- so it may create sidecars
    and is covered separately by test_open_db_readonly_without_immutable_*.
    """
    from icarus.core.schema import initialize_database, open_db

    initialize_database(tmp_db)
    conn = sqlite3.connect(str(tmp_db))
    conn.execute(
        "INSERT INTO files (path, filename, extension, size, file_type) "
        "VALUES ('/bin/a', 'a', '', 1, 'binary')"
    )
    conn.commit()
    conn.close()

    ro = open_db(tmp_db, readonly=True, immutable=True)
    try:
        assert ro.execute("SELECT COUNT(*) FROM files").fetchone()[0] == 1
        assert ro.execute("PRAGMA foreign_keys").fetchone()[0] == 1
        with pytest.raises(sqlite3.OperationalError):
            ro.execute(
                "INSERT INTO files (path, filename, extension, size, file_type) "
                "VALUES ('/bin/b', 'b', '', 1, 'binary')"
            )
    finally:
        ro.close()

    assert not Path(str(tmp_db) + "-wal").exists()
    assert not Path(str(tmp_db) + "-shm").exists()


def test_open_db_readonly_without_immutable_rejects_writes_but_honours_wal(tmp_db):
    """Plain open_db(readonly=True) (mode=ro, no immutable) — the query
    engine's mode (D1, #34): reads reflect data committed via the WAL and every
    write is still rejected. Unlike immutable, it does NOT promise no sidecars,
    because it must read a freshly-built (WAL-mode) database's current rows.
    """
    from icarus.core.schema import initialize_database, open_db

    initialize_database(tmp_db)  # open_db() puts the DB in persistent WAL mode
    w = open_db(tmp_db)
    w.execute(
        "INSERT INTO files (path, filename, extension, size, file_type) "
        "VALUES ('/bin/a', 'a', '', 1, 'binary')"
    )
    w.commit()
    w.close()

    ro = open_db(tmp_db, readonly=True)
    try:
        # WAL-committed row is visible (would be missing/stale under immutable).
        assert ro.execute("SELECT COUNT(*) FROM files").fetchone()[0] == 1
        with pytest.raises(sqlite3.OperationalError):
            ro.execute(
                "INSERT INTO files (path, filename, extension, size, file_type) "
                "VALUES ('/bin/b', 'b', '', 1, 'binary')"
            )
    finally:
        ro.close()
