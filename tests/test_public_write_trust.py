"""Public writable-query and initializer changes cannot inherit a clean audit."""

import sqlite3
from contextlib import closing

import pytest

from icarus.core.query import IcarusQuery
from icarus.core.schema import initialize_database
from icarus.integrations import hygeia


def _verify(database):
    gate = hygeia.verify_clean(database)
    assert gate["passed"], gate
    hygeia._record_finalized_audit(database, hygeia.require_hygeia(), gate)
    assert hygeia.sanitization_status(database) == "verified"


@pytest.fixture
def verified_db(tmp_path):
    database = tmp_path / "verified.db"
    initialize_database(database, {"source": "synthetic"})
    _verify(database)
    return database


def _metadata(database, key):
    with closing(sqlite3.connect(database)) as conn:
        return conn.execute("SELECT value FROM metadata WHERE key=?", (key,)).fetchone()


def test_writable_query_commits_content_and_revocation_together(verified_db):
    with IcarusQuery(str(verified_db), writable=True) as query:
        query.execute("INSERT INTO metadata VALUES ('secret', 'password=OnlySyntheticSecretValue')")
        assert query.conn.in_transaction
        assert hygeia.sanitization_status(verified_db) == "verified"
        assert _metadata(verified_db, "secret") is None
        query.commit()
    assert hygeia.sanitization_status(verified_db) == "unknown"
    assert not hygeia.verify_clean(verified_db)["passed"]


@pytest.mark.parametrize("finish", ["rollback", "close", "raw_rollback"])
def test_unpublished_writes_restore_prior_data_and_trust(verified_db, finish):
    query = IcarusQuery(str(verified_db), writable=True)
    query.execute("INSERT INTO metadata VALUES ('discard', 'password=OnlySyntheticSecretValue')")
    if finish == "raw_rollback":
        query.conn.rollback()
        query.commit()  # A stale pending flag must not revoke restored evidence.
    else:
        getattr(query, finish)()
    query.close()
    assert hygeia.sanitization_status(verified_db) == "verified"
    assert _metadata(verified_db, "discard") is None


def test_open_reads_and_empty_commit_do_not_revoke_trust(verified_db):
    with IcarusQuery(str(verified_db), writable=True) as query:
        query.commit()
        assert query.execute("SELECT 1").rows == [(1,)]
        assert not query.conn.in_transaction
        assert query.execute("PRAGMA table_info(metadata)").rows
        query.commit()
    assert hygeia.sanitization_status(verified_db) == "verified"


def test_reused_statement_rearms_after_commit_and_rollback(verified_db):
    statement = "INSERT INTO metadata VALUES (?, ?)"
    with IcarusQuery(str(verified_db), writable=True) as query:
        query.execute(statement, ("first", "clean"))
        query.commit()
        assert hygeia.sanitization_status(verified_db) == "unknown"
        _verify(verified_db)
        query.execute(statement, ("discard", "clean"))
        query.rollback()
        assert hygeia.sanitization_status(verified_db) == "verified"
        query.execute(statement, ("last", "password=OnlySyntheticSecretValue"))
        query.commit()
    assert hygeia.sanitization_status(verified_db) == "unknown"
    assert _metadata(verified_db, "discard") is None
    assert not hygeia.verify_clean(verified_db)["passed"]


def test_zero_row_dml_conservatively_revokes_trust(verified_db):
    with IcarusQuery(str(verified_db), writable=True) as query:
        query.execute("UPDATE files SET filename='unused' WHERE 0")
        query.commit()
    assert hygeia.sanitization_status(verified_db) == "unknown"
    assert hygeia.verify_clean(verified_db)["passed"]


@pytest.mark.parametrize("commit", [False, True])
def test_ddl_is_transactional_and_revokes_trust(verified_db, commit):
    with IcarusQuery(str(verified_db), writable=True) as query:
        query.execute(
            "CREATE TABLE credentials AS SELECT 'password=OnlySyntheticSecretValue' value"
        )
        with closing(sqlite3.connect(verified_db)) as observer:
            assert observer.execute(
                "SELECT 1 FROM sqlite_master WHERE name='credentials'"
            ).fetchone() is None
        assert hygeia.sanitization_status(verified_db) == "verified"
        if commit:
            query.commit()
    assert hygeia.sanitization_status(verified_db) == ("unknown" if commit else "verified")
    if commit:
        assert not hygeia.verify_clean(verified_db)["passed"]


def test_bounded_returning_finalizes_before_releasing_savepoint(verified_db):
    with IcarusQuery(str(verified_db), writable=True) as query:
        result = query.execute("""
            WITH RECURSIVE rows(n) AS (VALUES(1) UNION ALL SELECT n+1 FROM rows WHERE n<150)
            INSERT INTO files(path,filename) SELECT '/row-'||n, 'row-'||n FROM rows RETURNING id
        """)
        assert len(result.rows) == 100 and result.truncated
        query.commit()
    with closing(sqlite3.connect(verified_db)) as conn:
        assert conn.execute("SELECT COUNT(*) FROM files").fetchone() == (150,)
    assert hygeia.sanitization_status(verified_db) == "unknown"


def test_failed_statement_preserves_caller_transaction(verified_db):
    with IcarusQuery(str(verified_db), writable=True) as query:
        query.conn.execute("BEGIN")
        query.conn.execute("INSERT INTO metadata VALUES ('caller', 'pending')")
        with pytest.raises(sqlite3.OperationalError):
            query.execute("INSERT INTO missing_table VALUES ('failure')")
        assert query.conn.in_transaction
        row = query.conn.execute("SELECT value FROM metadata WHERE key='caller'").fetchone()
        assert row[0] == "pending"
        query.rollback()
    assert hygeia.sanitization_status(verified_db) == "verified"


def test_failed_trust_guard_rolls_back_the_whole_statement(verified_db):
    with closing(sqlite3.connect(verified_db)) as conn:
        conn.execute("""
            CREATE TRIGGER reject_revocation BEFORE DELETE ON metadata
            WHEN OLD.key='hygeia_status' BEGIN SELECT RAISE(ABORT,'reject revoke'); END
        """)
    with IcarusQuery(str(verified_db), writable=True) as query:
        with pytest.raises(sqlite3.IntegrityError, match="reject revoke"):
            query.execute(
                "INSERT INTO metadata VALUES ('secret', 'password=OnlySyntheticSecretValue')"
            )
        query.commit()
    assert _metadata(verified_db, "secret") is None
    assert hygeia.sanitization_status(verified_db) == "verified"


def test_trigger_cannot_silently_ignore_revocation(verified_db):
    with closing(sqlite3.connect(verified_db)) as conn:
        conn.execute("""
            CREATE TRIGGER ignore_revocation BEFORE DELETE ON metadata
            WHEN OLD.key LIKE 'hygeia_%' BEGIN SELECT RAISE(IGNORE); END
        """)
    with IcarusQuery(str(verified_db), writable=True) as query:
        with pytest.raises(sqlite3.IntegrityError, match="could not be revoked"):
            query.execute(
                "INSERT INTO metadata VALUES ('secret', 'password=OnlySyntheticSecretValue')"
            )
    assert _metadata(verified_db, "secret") is None
    assert hygeia.sanitization_status(verified_db) == "verified"


@pytest.mark.parametrize("sql", ["COMMIT", "END", "ROLLBACK", "SAVEPOINT bypass"])
def test_sql_transaction_controls_cannot_escape_guard(verified_db, sql):
    with IcarusQuery(str(verified_db), writable=True) as query:
        query.execute("INSERT INTO metadata VALUES ('pending', 'clean')")
        with pytest.raises(sqlite3.DatabaseError, match="authorized"):
            query.execute(sql)
        assert query.conn.in_transaction
        query.rollback()
    assert hygeia.sanitization_status(verified_db) == "verified"


def test_failed_statement_keeps_earlier_guarded_writes_pending(verified_db):
    with IcarusQuery(str(verified_db), writable=True) as query:
        query.execute("INSERT INTO metadata VALUES ('first', 'clean')")
        with pytest.raises(sqlite3.IntegrityError):
            query.execute("INSERT INTO metadata VALUES ('first', 'duplicate')")
        query.commit()
    assert _metadata(verified_db, "first") == ("clean",)
    assert hygeia.sanitization_status(verified_db) == "unknown"


def test_sqlite_transaction_rollback_preserves_original_exception_and_trust(verified_db):
    with IcarusQuery(str(verified_db), writable=True) as query:
        query.execute("INSERT INTO metadata VALUES ('first', 'clean')")
        with pytest.raises(sqlite3.IntegrityError):
            query.execute("INSERT OR ROLLBACK INTO metadata VALUES ('first', 'duplicate')")
        assert not query.conn.in_transaction
        query.commit()
    assert _metadata(verified_db, "first") is None
    assert hygeia.sanitization_status(verified_db) == "verified"


def test_deferred_commit_failure_can_roll_back_content_and_revocation(verified_db):
    with closing(sqlite3.connect(verified_db)) as conn:
        conn.execute("""
            CREATE TABLE deferred_child (
                parent INTEGER REFERENCES files(id) DEFERRABLE INITIALLY DEFERRED
            )
        """)
    _verify(verified_db)
    with IcarusQuery(str(verified_db), writable=True) as query:
        query.execute("INSERT INTO deferred_child VALUES (999)")
        with pytest.raises(sqlite3.IntegrityError, match="FOREIGN KEY"):
            query.commit()
        assert query.conn.in_transaction
        assert hygeia.sanitization_status(verified_db) == "verified"
        query.rollback()
    assert hygeia.sanitization_status(verified_db) == "verified"


def test_query_cannot_copy_framework_evidence_back_after_a_write(verified_db):
    with closing(sqlite3.connect(verified_db)) as conn:
        evidence = conn.execute(
            "SELECT key,value FROM metadata "
            "WHERE key IN ('hygeia_status','hygeia_engine','hygeia_audit')"
        ).fetchall()
    placeholders = ",".join("(?,?)" for _ in evidence)
    values = tuple(value for row in evidence for value in row)
    with IcarusQuery(str(verified_db), writable=True) as query:
        query.execute("INSERT INTO metadata VALUES ('new', 'clean')")
        query.execute("INSERT OR REPLACE INTO metadata VALUES " + placeholders, values)
        query.commit()
    assert hygeia.sanitization_status(verified_db) == "unknown"


def test_guarded_drop_of_metadata_removes_the_evidence_itself(verified_db):
    with IcarusQuery(str(verified_db), writable=True) as query:
        query.execute("DROP TABLE metadata")
        query.commit()
    assert hygeia.sanitization_status(verified_db) == "unknown"


def test_guarded_attach_cannot_write_another_database(verified_db, tmp_path):
    other = tmp_path / "not-created.db"
    with IcarusQuery(str(verified_db), writable=True) as query:
        with pytest.raises(sqlite3.DatabaseError, match="authorized"):
            query.execute("ATTACH DATABASE ? AS other", (str(other),))
    assert not other.exists()
    assert hygeia.sanitization_status(verified_db) == "verified"


def test_initializer_metadata_revokes_existing_audit(verified_db):
    initialize_database(verified_db, {"secret": "password=OnlySyntheticSecretValue"})
    assert hygeia.sanitization_status(verified_db) == "unknown"
    assert not hygeia.verify_clean(verified_db)["passed"]


def test_recursive_execute_cannot_clear_the_outer_write_guard(verified_db):
    with IcarusQuery(str(verified_db), writable=True) as query:
        def callback():
            with pytest.raises(sqlite3.ProgrammingError, match="Recursive"):
                query.execute("SELECT 1")
            return "done"

        query.conn.create_function("nested_read", 0, callback)
        result = query.execute(
            "INSERT INTO metadata VALUES ('new','clean') RETURNING nested_read()"
        )
        assert result.rows == [("done",)]
        query.commit()
    assert hygeia.sanitization_status(verified_db) == "unknown"


@pytest.mark.parametrize("method", ["commit", "rollback", "close"])
def test_callback_cannot_interrupt_guarded_transaction_control(verified_db, method):
    with IcarusQuery(str(verified_db), writable=True) as query:
        def callback():
            with pytest.raises(sqlite3.ProgrammingError, match="guarded statement"):
                getattr(query, method)()
            return "done"

        query.conn.create_function("interrupt", 0, callback)
        query.execute("INSERT INTO metadata VALUES ('new','clean') RETURNING interrupt()")
        query.commit()
    assert _metadata(verified_db, "new") == ("clean",)
    assert hygeia.sanitization_status(verified_db) == "unknown"


def test_initializer_noops_preserve_existing_audit(verified_db):
    initialize_database(verified_db)
    initialize_database(verified_db, {"source": "synthetic"})
    assert hygeia.sanitization_status(verified_db) == "verified"


@pytest.mark.parametrize("key", ["schema_version", *hygeia._TRUST_METADATA_KEYS])
def test_initializer_rejects_framework_metadata_before_changes(verified_db, tmp_path, key):
    before = _metadata(verified_db, key)
    with pytest.raises(ValueError, match="Framework-owned"):
        initialize_database(verified_db, {"ordinary": "new", key: "copied"})
    assert _metadata(verified_db, key) == before
    assert _metadata(verified_db, "ordinary") is None
    assert hygeia.sanitization_status(verified_db) == "verified"
    absent = tmp_path / "not-created.db"
    with pytest.raises(ValueError, match="Framework-owned"):
        initialize_database(absent, {key: "copied"})
    assert not absent.exists()


def test_initializer_failure_restores_metadata_and_trust(verified_db):
    with closing(sqlite3.connect(verified_db)) as conn:
        conn.execute("""
            CREATE TRIGGER reject_metadata BEFORE INSERT ON metadata
            WHEN NEW.key='reject' BEGIN SELECT RAISE(ABORT,'reject metadata'); END
        """)
    with pytest.raises(sqlite3.IntegrityError, match="reject metadata"):
        initialize_database(verified_db, {"first": "new", "reject": "failure"})
    assert _metadata(verified_db, "first") is None
    assert hygeia.sanitization_status(verified_db) == "verified"
