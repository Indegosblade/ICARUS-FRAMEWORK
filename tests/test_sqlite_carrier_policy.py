"""An omitted SQLite carrier cannot receive a verified public artifact audit."""

import sqlite3
from contextlib import closing

import pytest

from icarus.core.schema import initialize_database
from icarus.integrations import hygeia

EMAIL = "carriercheck@example.com"


@pytest.mark.parametrize("name", [
    "records", "sqliteXextension", "SQLITExExtension2", "sqlite-like", "gifts_archive",
    "Gifts_Archive2", "files_fts_private_notes",
])
def test_extension_table_names_do_not_escape_scan_or_actual_redaction(tmp_path, name):
    database = tmp_path / "catalog.db"
    initialize_database(database)
    with closing(sqlite3.connect(database)) as conn, conn:
        conn.execute('CREATE TABLE "' + name + '"(payload TEXT)')
        conn.execute('INSERT INTO "' + name + '" VALUES (?)', (EMAIL,))
    before = hygeia.verify_clean(database)
    assert not before["passed"], name
    assert any(finding["table"] == name for finding in before["findings"])
    hygeia.sanitize_output(database)
    hygeia.finalize_sanitization(database)
    with closing(sqlite3.connect(database)) as conn:
        assert EMAIL not in conn.execute('SELECT payload FROM "' + name + '"').fetchone()[0]
    assert hygeia.sanitization_status(database) == "verified"


@pytest.mark.parametrize("affinity,value", [
    ("TEXT", EMAIL), ("INTEGER", EMAIL), ("REAL", EMAIL), ("BLOB", EMAIL.encode()),
    ("BLOB", EMAIL.encode("utf-16")),
])
def test_dynamic_sqlite_affinity_does_not_hide_text_or_blob_carriers(tmp_path, affinity, value):
    database = tmp_path / "affinity.db"
    initialize_database(database)
    with closing(sqlite3.connect(database)) as conn, conn:
        conn.execute(f"CREATE TABLE extension(payload {affinity})")
        conn.execute("INSERT INTO extension VALUES (?)", (value,))
    assert not hygeia.verify_clean(database)["passed"]
    hygeia.sanitize_output(database)
    hygeia.finalize_sanitization(database)
    with closing(sqlite3.connect(database)) as conn:
        remaining = conn.execute("SELECT payload FROM extension").fetchone()[0]
    assert EMAIL not in str(remaining)


@pytest.mark.parametrize("storage", ["VIRTUAL", "STORED"])
def test_constant_generated_carrier_cannot_be_published_clean(tmp_path, storage):
    database = tmp_path / "generated.db"
    initialize_database(database)
    with closing(sqlite3.connect(database)) as conn, conn:
        conn.execute(f"CREATE TABLE extension(id INTEGER,payload TEXT AS "
                     f"('carriercheck' || '@example.com') {storage})")
        conn.execute("INSERT INTO extension(id) VALUES (1)")
    assert not hygeia.verify_clean(database)["passed"]
    with pytest.raises(hygeia.SanitizationError):
        hygeia.sanitize_output(database)


def test_true_core_fts_indexes_remain_valid_and_name_lookalikes_are_scanned(tmp_path):
    database = tmp_path / "fts.db"
    initialize_database(database)
    with closing(sqlite3.connect(database)) as conn, conn:
        conn.execute("CREATE TABLE files_fts_notes(payload TEXT)")
        conn.execute("INSERT INTO files_fts_notes VALUES (?)", (EMAIL,))
        conn.execute("INSERT INTO files(path,filename) VALUES('/usr/bin/inventory','inventory')")
    assert not hygeia.verify_clean(database)["passed"]
    hygeia.sanitize_output(database)
    hygeia.finalize_sanitization(database)
    with closing(sqlite3.connect(database)) as conn:
        assert EMAIL not in conn.execute("SELECT payload FROM files_fts_notes").fetchone()[0]
        assert conn.execute("PRAGMA integrity_check").fetchone()[0] == "ok"


def test_user_named_rowid_never_becomes_raw_finding_metadata(tmp_path):
    database = tmp_path / "rowid.db"
    initialize_database(database)
    with closing(sqlite3.connect(database)) as conn, conn:
        conn.execute("CREATE TABLE extension(rowid TEXT,payload TEXT)")
        conn.execute("INSERT INTO extension VALUES (?,?)", (EMAIL, EMAIL))
    findings = hygeia.verify_clean(database)["findings"]
    assert findings and all(isinstance(item["rowid"], int) for item in findings)
    assert EMAIL not in str(findings)


def test_real_fts_config_carrier_is_scanned_even_though_rebuild_does_not_own_its_values(tmp_path):
    database = tmp_path / "config.db"
    initialize_database(database)
    with closing(sqlite3.connect(database)) as conn, conn:
        conn.execute("INSERT INTO files_fts_config(k,v) VALUES ('user_note',?)", (EMAIL,))
    assert not hygeia.verify_clean(database)["passed"]
    with pytest.raises(hygeia.SanitizationError):
        hygeia.sanitize_output(database)
