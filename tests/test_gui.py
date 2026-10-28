"""The local explorer exposes bounded read APIs behind a session capability."""

import hashlib
import http.client
import json
import socket
import sqlite3
import threading
import time
from contextlib import closing, contextmanager

import pytest

from icarus.core.schema import initialize_database
from icarus.gui import server as server_module
from icarus.gui.server import CELL_LIMIT, PAGE_LIMIT, ExplorerServer


@contextmanager
def database_writer(path):
    # sqlite3.Connection's context manager commits/rolls back but does not
    # close the handle. Flush WAL before the GUI's read-only byte comparison.
    with closing(sqlite3.connect(path)) as conn:
        with conn:
            yield conn
        assert conn.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()[0] == 0


@pytest.fixture
def database(tmp_path):
    path = tmp_path / "intel.db"
    initialize_database(path)
    with database_writer(path) as conn:
        conn.execute(
            "INSERT INTO metadata(key,value) VALUES('hygeia_skipped','true')"
        )
        conn.execute(
            "INSERT INTO versions(run_id,parser_name,started_at) VALUES('run','test','2026-01-01')"
        )
        for index in range(1, PAGE_LIMIT + 8):
            conn.execute(
                "INSERT INTO files(path,filename,source_version_id,observed_time) VALUES(?,?,1,?)",
                (f"/file-{index:03d}", "needle" if index == 1 else f"file-{index}", "2026-01-01"),
            )
        conn.execute("UPDATE files SET owner=? WHERE id=1",
                     ("<img onerror=alert(1)>" + "x" * 2000,))
        conn.execute("INSERT INTO binaries(file_id,executable_name) VALUES(1,'app')")
        conn.execute("INSERT INTO daemons(label,plist_path,binary_id) VALUES('job','/job.plist',1)")
        conn.execute(
            "INSERT INTO observations(entity_table,entity_id,observed_at,event_type) "
            "VALUES('files',1,'2026-01-01','test')"
        )
    return path


@contextmanager
def running_server(database, **kwargs):
    with ExplorerServer(database, **kwargs) as server:
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            yield server
        finally:
            server.shutdown()
            thread.join(timeout=3)
            assert not thread.is_alive()


def request(server, path, *, token=True, headers=None, method="GET"):
    supplied = {"Authorization": "Bearer " + server.token} if token else {}
    supplied.update(headers or {})
    conn = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=4)
    try:
        conn.request(method, path, headers=supplied)
        response = conn.getresponse()
        body = response.read()
        return response.status, dict(response.getheaders()), body
    finally:
        conn.close()


def test_auth_origin_and_security_headers(database):
    with running_server(database) as server:
        assert server.server_address[0] == "127.0.0.1"
        assert len(server.token) == 43
        assert "#token=" in server.url
        assert request(server, "/api/summary", token=False)[0] == 401
        assert request(server, "/api/summary", headers={"Authorization": "Bearer wrong"})[0] == 401
        assert request(server, "/api/summary", headers={"Authorization": "Bearer ÿ"})[0] == 401
        for headers in ({"Host": "attacker.example"}, {"Origin": "https://attacker.example"},
                        {"Origin": "null"}, {"Sec-Fetch-Site": "cross-site"}):
            assert request(server, "/api/summary", headers=headers)[0] == 403
        status, headers, body = request(server, "/api/summary")
        assert status == 200
        assert "Access-Control-Allow-Origin" not in headers
        assert headers["Cache-Control"] == "no-store"
        assert headers["Referrer-Policy"] == "no-referrer"
        assert "frame-ancestors 'none'" in headers["Content-Security-Policy"]
        assert json.loads(body)["sanitization"] == "skipped"
        assert server.token.encode() not in body


def test_keyset_pagination_search_detail_and_read_only(database):
    before = hashlib.sha256(database.read_bytes()).hexdigest()
    with running_server(database) as server:
        status, _, body = request(server, "/api/entities?table=files")
        assert status == 200
        first = json.loads(body)
        assert len(first["rows"]) == PAGE_LIMIT
        assert first["next_after"] == PAGE_LIMIT
        assert len(first["rows"][0]["owner"]) == CELL_LIMIT + 1
        assert first["rows"][0]["_truncated_fields"] == ["owner"]
        second = json.loads(request(server, f"/api/entities?table=files&after={PAGE_LIMIT}")[2])
        assert len(second["rows"]) == 7
        assert second["next_after"] is None
        assert not {row["id"] for row in first["rows"]} & {row["id"] for row in second["rows"]}
        searched = json.loads(request(server, "/api/entities?table=files&q=needle")[2])
        assert [row["id"] for row in searched["rows"]] == [1]
        entity = json.loads(request(server, "/api/entity?table=files&id=1")[2])
        assert entity["entity"]["source_version_id"] == 1
        assert {group["table"] for group in entity["relationships"]} >= {
            "versions", "binaries", "observations",
        }
        assert request(server, "/api/entity?table=files&id=999")[0] == 404
        for path in ("/api/sql", "/api/entities?sql=DELETE", "/api/entities?table=sqlite_master",
                     "/api/entities?table=files&after=-1", "/api/entities?table=files&table=atoms"):
            assert request(server, path)[0] in (400, 404)
        assert request(server, "/api/entities", method="POST")[0] == 405
    assert hashlib.sha256(database.read_bytes()).hexdigest() == before


def test_static_assets_are_local_and_never_bootstrap_the_capability(database):
    with running_server(database) as server:
        for path in ("/", "/app.js", "/style.css"):
            status, headers, body = request(server, path, token=False)
            assert status == 200
            assert server.token.encode() not in body
            assert headers["X-Content-Type-Options"] == "nosniff"
        assert request(server, "/../pyproject.toml")[0] == 404
        assert request(server, "/%2e%2e/pyproject.toml")[0] == 404
        script = request(server, "/app.js")[2].decode()
        assert "innerHTML" not in script
        assert "textContent" in script
        assert "history.replaceState" in script


def test_unverified_requires_explicit_override_and_is_rechecked(database):
    with database_writer(database) as conn:
        conn.execute("DELETE FROM metadata WHERE key='hygeia_skipped'")
    with pytest.raises(ValueError, match="allow-unverified"):
        ExplorerServer(database)
    with running_server(database, allow_unverified=True) as server:
        assert json.loads(request(server, "/api/summary")[2])["sanitization"] == "unknown"
    with database_writer(database) as conn:
        conn.execute("INSERT INTO metadata(key,value) VALUES('hygeia_skipped','true')")
    with running_server(database) as server:
        with database_writer(database) as conn:
            conn.execute("DELETE FROM metadata WHERE key='hygeia_skipped'")
        assert request(server, "/api/entities")[0] == 400


def test_unreadable_database_is_a_clean_error(tmp_path):
    path = tmp_path / "broken.db"
    path.write_text("not sqlite")
    with pytest.raises(ValueError, match="unreadable"):
        ExplorerServer(path, allow_unverified=True)


def test_trickling_headers_cannot_hold_the_server_indefinitely(database, monkeypatch):
    monkeypatch.setattr(server_module, "REQUEST_SECONDS", 0.25)
    with running_server(database) as server:
        with socket.create_connection(server.server_address, timeout=1.5) as client:
            client.sendall(
                f"GET / HTTP/1.1\r\nHost: 127.0.0.1:{server.server_port}\r\nX-Slow: ".encode()
            )
            stop = threading.Event()

            def trickle():
                while not stop.wait(0.03):
                    try:
                        client.sendall(b"x")
                    except OSError:
                        return

            sender = threading.Thread(target=trickle, daemon=True)
            sender.start()
            started = time.monotonic()
            try:
                try:
                    received = client.recv(1)
                except (ConnectionResetError, ConnectionAbortedError):
                    # Windows may reset/abort a socket with unread trickled
                    # data instead of reporting EOF. Timeouts must still fail.
                    received = b""
                assert received == b""
                assert time.monotonic() - started < 1.5
            finally:
                stop.set()
                sender.join(timeout=1)
        # The expired connection does not prevent subsequent legitimate requests.
        assert request(server, "/api/summary")[0] == 200
