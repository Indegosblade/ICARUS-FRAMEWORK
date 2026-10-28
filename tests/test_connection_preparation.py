"""The connection factory owns handles until every setup step succeeds."""

import sqlite3
from contextlib import closing

import pytest

from icarus.core import schema


@pytest.mark.parametrize("readonly", [False, True])
@pytest.mark.parametrize("failure", ["corrupt_input", "performance_setup"])
def test_failed_connection_preparation_closes_before_ownership_transfer(
    tmp_path, monkeypatch, readonly, failure,
):
    database = tmp_path / "input.db"
    original_connect = sqlite3.connect
    if failure == "corrupt_input":
        database.write_bytes(b"not a database")
    else:
        with closing(original_connect(database)) as conn:
            conn.execute("CREATE TABLE records(value TEXT)")
            conn.commit()

    tracked = []

    class TrackedConnection(sqlite3.Connection):
        explicitly_closed = False

        def close(self):
            self.explicitly_closed = True
            return super().close()

    def connect(*args, **kwargs):
        conn = original_connect(*args, factory=TrackedConnection, **kwargs)
        tracked.append(conn)
        return conn

    monkeypatch.setattr(schema.sqlite3, "connect", connect)
    if failure == "performance_setup":
        def fail(_connection):
            raise sqlite3.OperationalError("injected connection setup failure")
        monkeypatch.setattr(schema, "_apply_performance_pragmas", fail)
    try:
        with pytest.raises(sqlite3.Error):
            schema.open_db(database, readonly=readonly)
        assert len(tracked) == 1
        assert tracked[0].explicitly_closed
        with pytest.raises(sqlite3.ProgrammingError, match="closed"):
            tracked[0].execute("SELECT 1")
    finally:
        # A red regression must not leave its intentionally observed handle open.
        for conn in tracked:
            conn.close()
