"""Database paths are filesystem names, never SQLite URI query strings."""

import os
import sqlite3
from contextlib import closing

import pytest

from icarus.core.differ import IcarusDiffer
from icarus.core.query import IcarusQuery
from icarus.core.schema import initialize_database, open_db
from icarus.integrations.hygeia import sanitization_status


@pytest.mark.parametrize("filename", ["intel #100% complete.db", "literal%23name.db"])
@pytest.mark.parametrize("relative", [False, True])
def test_all_consumers_open_literal_path(tmp_path, monkeypatch, filename, relative):
    monkeypatch.chdir(tmp_path)
    database = tmp_path / filename
    initialize_database(database)
    with closing(sqlite3.connect(database)) as conn:
        conn.execute("INSERT INTO files (path, filename) VALUES ('/expected', 'expected')")
        conn.execute("INSERT INTO metadata (key, value) VALUES ('hygeia_skipped', 'true')")
        conn.commit()
    path = database.name if relative else database

    with closing(open_db(path, readonly=True)) as conn:
        assert conn.execute("SELECT path FROM files").fetchone()[0] == "/expected"
        with pytest.raises(sqlite3.OperationalError, match="readonly"):
            conn.execute("DELETE FROM files")
    with IcarusQuery(str(path)) as query:
        assert query.execute("SELECT path FROM files").rows == [("/expected",)]
    assert sanitization_status(path) == "skipped"
    with IcarusDiffer(str(path), str(path)) as differ:
        assert differ.added_entities("files", "path").added == []
        assert differ.removed_entities("files", "path").removed == []


@pytest.mark.skipif(os.name == "nt", reason="Windows does not permit '?' in filenames")
def test_query_delimiter_is_literal_on_posix(tmp_path):
    database = tmp_path / "intel?mode=rwc.db"
    initialize_database(database)
    with closing(open_db(database, readonly=True, immutable=True)) as conn:
        assert conn.execute("SELECT COUNT(*) FROM files").fetchone()[0] == 0
        with pytest.raises(sqlite3.OperationalError, match="readonly"):
            conn.execute("DELETE FROM files")
