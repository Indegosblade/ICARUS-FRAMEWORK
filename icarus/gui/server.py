"""Capability-protected loopback HTTP interface over an ICARUS database.

This is a single-user inspection tool. It exposes fixed, bounded read queries;
it never accepts SQL, filesystem paths, or mutations over HTTP.
"""

import hmac
import json
import math
import re
import secrets
import socket
import sqlite3
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from importlib.resources import files
from pathlib import Path
from socketserver import TCPServer
from urllib.parse import parse_qs, urlsplit

from icarus.core import VALID_FTS_TABLES
from icarus.core.query import IcarusQuery
from icarus.integrations.hygeia import (
    sanitization_allows_default_consumer,
    sanitization_status,
)

TABLES = (
    "files", "binaries", "daemons", "mach_services", "entitlements",
    "sandbox_profiles", "sandbox_rules", "kexts", "frameworks", "observations",
    "versions", "atoms", "bags", "resolution_event_log", "match_candidates",
)
LABELS = {
    "files": "path", "binaries": "executable_name", "daemons": "label",
    "mach_services": "service_name", "entitlements": "key",
    "sandbox_profiles": "name", "sandbox_rules": "operation", "kexts": "bundle_id",
    "frameworks": "path", "observations": "event_type", "versions": "run_id",
    "atoms": "source_key", "bags": "canonical_key", "resolution_event_log": "event_type",
    "match_candidates": "entity_type",
}
PAGE_LIMIT = 25
CELL_LIMIT = 1024
RELATION_GROUP_LIMIT = 24
RESPONSE_LIMIT = 1_000_000
QUERY_SECONDS = 2.0
REQUEST_SECONDS = 8.0
IDENTIFIER = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,63}$")
ASSETS = {"/": ("index.html", "text/html; charset=utf-8"),
          "/app.js": ("app.js", "text/javascript; charset=utf-8"),
          "/style.css": ("style.css", "text/css; charset=utf-8")}


def _integer(value: str, maximum: int = 2**63 - 1) -> int:
    if not value.isascii() or not value.isdecimal() or len(value) > 19:
        raise ValueError("Expected a nonnegative integer")
    result = int(value)
    if result > maximum:
        raise ValueError("Integer exceeds the supported range")
    return result


def _columns(conn, table):
    if table not in TABLES:
        raise ValueError("Unknown entity type")
    # The table is checked against TABLES above.
    info = conn.execute(f"PRAGMA table_info({table})").fetchall()  # nosec B608
    if not info:
        return []
    if len(info) > 32 or any(not IDENTIFIER.fullmatch(row[1]) for row in info):
        raise ValueError("Unsupported entity schema")
    if not any(row[1] == "id" and row[2].upper() == "INTEGER" and row[5] for row in info):
        raise ValueError("Entity table requires an integer primary key")
    return [row[1] for row in info]


def _selection(columns):
    # Names passed here come only from validated schema column identifiers.
    return ", ".join(
        f'CASE WHEN typeof("{column}") IN (\'text\',\'blob\') '
        f'THEN substr("{column}",1,{CELL_LIMIT + 1}) ELSE "{column}" END AS "{column}"'
        for column in columns
    )


def _row(row):
    result = {}
    truncated = []
    for key, value in dict(row).items():
        if isinstance(value, bytes):
            value = "[binary value]"
            truncated.append(key)
        elif isinstance(value, str) and len(value) > CELL_LIMIT:
            value = value[:CELL_LIMIT] + "…"
            truncated.append(key)
        elif isinstance(value, float) and not math.isfinite(value):
            value = str(value)
        result[key] = value
    if truncated:
        result["_truncated_fields"] = truncated
    return result


def _related(conn, table, entity):
    """Return bounded declared FK edges plus the schema's polymorphic observations."""
    groups: list[dict] = []

    def add(target, condition, params, title):
        if len(groups) >= RELATION_GROUP_LIMIT:
            return
        if not _columns(conn, target):
            return
        label = LABELS[target]
        # target/label are fixed mappings, condition is built only below.
        rows = conn.execute(
            f'SELECT id, substr("{label}",1,160) AS label FROM {target} '  # nosec B608
            f"WHERE {condition} ORDER BY id LIMIT 11", params,
        ).fetchall()
        if rows:
            groups.append({"title": title, "table": target,
                           "items": [_row(row) for row in rows[:10]],
                           "truncated": len(rows) > 10})

    for source in TABLES:
        if len(groups) >= RELATION_GROUP_LIMIT:
            break
        if not _columns(conn, source):
            continue
        # Source is an element of TABLES, not an HTTP parameter.
        for fk in conn.execute(f"PRAGMA foreign_key_list({source})"):  # nosec B608
            target, column, target_column = fk[2:5]
            if target not in TABLES or target_column != "id" or not IDENTIFIER.fullmatch(column):
                continue
            if source == table and entity.get(column) is not None:
                add(target, "id = ?", (entity[column],), f"{column} → {target}")
            if target == table:
                add(source, f'"{column}" = ?', (entity["id"],), f"{source} via {column}")
    if table == "observations" and entity.get("entity_table") in TABLES:
        add(entity["entity_table"], "id = ?", (entity["entity_id"],), "Observed entity")
    elif table not in ("observations", "versions", "resolution_event_log", "match_candidates"):
        add("observations", "entity_table = ? AND entity_id = ?",
            (table, entity["id"]), "Observations")
    if table == "atoms":
        add("bags", "id IN (SELECT bag_id FROM bag_atoms WHERE atom_id = ?)",
            (entity["id"],), "Canonical membership")
    elif table == "bags":
        add("atoms", "id IN (SELECT atom_id FROM bag_atoms WHERE bag_id = ?)",
            (entity["id"],), "Member observations")
    return groups


class ExplorerServer(HTTPServer):
    """Single-request server; bounded query and socket timeouts cap resource use."""

    allow_reuse_address = False

    def __init__(self, database: Path, *, port: int = 0, allow_unverified: bool = False):
        self.database = Path(database).resolve()
        if not self.database.is_file():
            raise FileNotFoundError("An existing ICARUS database is required")
        self.allow_unverified = allow_unverified
        self.token = secrets.token_urlsafe(32)
        self.check_posture()
        try:
            with IcarusQuery(str(self.database)) as query:
                if not _columns(query.conn, "files"):
                    raise ValueError("Database has no ICARUS files table")
        except sqlite3.Error:
            raise ValueError("Database is unreadable or is not an ICARUS database") from None
        super().__init__(("127.0.0.1", port), ExplorerHandler)
        self.origin = f"http://127.0.0.1:{self.server_port}"
        self.url = f"{self.origin}/#token={self.token}"

    def server_bind(self):
        # HTTPServer's hook calls socket.getfqdn even for a numeric loopback
        # address. That system resolver operation is unnecessary and unbounded
        # by our request timeouts because it runs before requests can start.
        TCPServer.server_bind(self)
        self.server_name = "127.0.0.1"
        self.server_port = self.server_address[1]

    def check_posture(self):
        status = sanitization_status(self.database)
        if not self.allow_unverified and not sanitization_allows_default_consumer(status):
            raise ValueError(
                "Database is not sanitization-verified; rebuild or explicitly "
                "use --allow-unverified"
            )
        return status

    def get_request(self):
        sock, address = super().get_request()
        sock.settimeout(5)
        return sock, address

    def api(self, path, params):
        status = self.check_posture()
        with IcarusQuery(str(self.database)) as query:
            conn = query.conn
            conn.execute("PRAGMA trusted_schema = OFF")
            conn.execute("PRAGMA busy_timeout = 1000")
            deadline = time.monotonic() + QUERY_SECONDS
            conn.set_progress_handler(lambda: int(time.monotonic() > deadline), 1000)
            if path == "/api/summary":
                if params:
                    raise ValueError("Unexpected summary parameters")
                counts = {}
                for table in TABLES:
                    if _columns(conn, table):
                        counts[table] = conn.execute(
                            f"SELECT COUNT(*) FROM {table}"  # nosec B608
                        ).fetchone()[0]
                return {"database": self.database.name, "sanitization": status,
                        "tables": counts, "page_limit": PAGE_LIMIT,
                        "fts_tables": sorted(VALID_FTS_TABLES), "read_only": True}
            if path not in ("/api/entities", "/api/entity"):
                raise LookupError("Unknown endpoint")
            allowed = {"table", "id"} if path == "/api/entity" else {"table", "after", "q"}
            if set(params) - allowed:
                raise ValueError("Unexpected query parameter")
            table = params.get("table", "files")
            columns = _columns(conn, table)
            if not columns:
                raise LookupError("Entity type is absent from this database")
            selection = _selection(columns)
            if path == "/api/entity":
                entity_id = _integer(params.get("id", ""))
                row = conn.execute(
                    f"SELECT {selection} FROM {table} WHERE id = ?",  # nosec B608
                    (entity_id,),
                ).fetchone()
                if row is None:
                    raise LookupError("Entity does not exist")
                entity = _row(row)
                return {"table": table, "entity": entity,
                        "relationships": _related(conn, table, entity),
                        "relationship_group_limit": RELATION_GROUP_LIMIT}
            after = _integer(params.get("after", "0"))
            search = params.get("q", "")
            condition, values = "id > ?", [after]
            if search:
                if table not in VALID_FTS_TABLES or len(search) > 200:
                    raise ValueError(
                        "Search supports files, daemons, and atoms; maximum 200 characters"
                    )
                # Table has additionally been checked against VALID_FTS_TABLES.
                condition += (
                    f" AND id IN (SELECT rowid FROM {table}_fts WHERE {table}_fts MATCH ?)"  # nosec B608
                )
                values.append(search)
            rows = conn.execute(
                f"SELECT {selection} FROM {table} WHERE {condition} "  # nosec B608
                f"ORDER BY id LIMIT {PAGE_LIMIT + 1}", values,
            ).fetchall()
            visible = [_row(row) for row in rows[:PAGE_LIMIT]]
            more = len(rows) > PAGE_LIMIT
            while visible and len(json.dumps(visible, ensure_ascii=False).encode()) > 800_000:
                visible.pop()
                more = True
            return {"table": table, "columns": columns, "rows": visible,
                    "next_after": visible[-1]["id"] if more and visible else None,
                    "cells_truncated_at": CELL_LIMIT}


class ExplorerHandler(BaseHTTPRequestHandler):
    server: ExplorerServer
    server_version = "ICARUS"
    sys_version = ""

    def _expire_connection(self):
        try:
            self.connection.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass

    def handle(self):
        # Socket inactivity timeouts alone reset on every byte. An absolute
        # deadline also bounds a client trickling incomplete request headers.
        deadline = threading.Timer(REQUEST_SECONDS, self._expire_connection)
        deadline.daemon = True
        deadline.start()
        try:
            super().handle()
        except OSError:
            pass  # Disconnects and deadline expiry do not fail the server.
        finally:
            deadline.cancel()

    def log_message(self, format, *args):
        # Capability tokens, queried identifiers, and database values stay out of logs.
        pass

    def _send(self, status, body, content_type="application/json; charset=utf-8"):
        if not isinstance(body, bytes):
            body = json.dumps(body, ensure_ascii=False, allow_nan=False).encode()
        if len(body) > RESPONSE_LIMIT:
            status, body = 503, b'{"error":"Response exceeded the inspection limit"}'
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Cross-Origin-Resource-Policy", "same-origin")
        self.send_header("Content-Security-Policy",
                         "default-src 'none'; script-src 'self'; style-src 'self'; "
                         "connect-src 'self'; img-src 'self'; base-uri 'none'; "
                         "frame-ancestors 'none'; form-action 'none'")
        self.send_header("Connection", "close")
        self.end_headers()
        try:
            self.wfile.write(body)
        except OSError:
            # A closed or timed-out browser connection does not fail the server lifecycle.
            pass
        self.close_connection = True

    def do_GET(self):
        expected_host = f"127.0.0.1:{self.server.server_port}"
        if (
            self.headers.get_all("Host") != [expected_host]
            or self.headers.get_all("Origin", [self.server.origin]) != [self.server.origin]
            or self.headers.get("Sec-Fetch-Site") == "cross-site"
        ):
            self._send(403, {"error": "Local origin required"})
            return
        if len(self.path) > 4096:
            self._send(414, {"error": "Request URL too long"})
            return
        try:
            route = urlsplit(self.path)
        except ValueError:
            self._send(400, {"error": "Invalid request target"})
            return
        if route.netloc or route.scheme:
            self._send(400, {"error": "Relative request target required"})
            return
        if route.path in ASSETS:
            name, content_type = ASSETS[route.path]
            asset = files("icarus.gui").joinpath("assets").joinpath(name)
            self._send(200, asset.read_bytes(), content_type)
            return
        supplied = self.headers.get("Authorization", "")
        if not hmac.compare_digest(supplied.encode(), ("Bearer " + self.server.token).encode()):
            self._send(401, {
                "error": "Session capability required; open the URL printed by ICARUS",
            })
            return
        try:
            parsed = parse_qs(route.query, keep_blank_values=True, max_num_fields=8)
            if any(len(value) != 1 for value in parsed.values()):
                raise ValueError("Duplicate parameters are not supported")
            result = self.server.api(
                route.path, {key: value[0] for key, value in parsed.items()},
            )
            self._send(200, result)
        except ValueError as exc:
            self._send(400, {"error": str(exc)})
        except LookupError:
            self._send(404, {"error": "Entity or endpoint not found"})
        except sqlite3.Error:
            self._send(422, {
                "error": "Query could not complete; check the search or database schema",
            })

    def do_POST(self):
        self._send(405, {"error": "Read-only inspection supports GET only"})

    do_PUT = do_POST
    do_PATCH = do_POST
    do_DELETE = do_POST
    do_OPTIONS = do_POST


def serve(database: Path, *, port: int = 0, allow_unverified=False, open_browser=True):
    import webbrowser

    with ExplorerServer(database, port=port, allow_unverified=allow_unverified) as server:
        print(f"[ICARUS] Read-only ontology explorer: {server.url}", flush=True)
        print("[ICARUS] Keep this session URL private. Stop the server with Ctrl+C.")
        if open_browser:
            webbrowser.open(server.url)
        try:
            server.serve_forever(poll_interval=0.25)
        except KeyboardInterrupt:
            pass
