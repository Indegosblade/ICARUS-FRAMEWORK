"""
ICARUS Query Engine — SQL interface with full-text search and intelligence views.

Provides both raw SQL access and pre-built intelligence queries
for declared configuration patterns and inspection candidates.
"""

import sqlite3
from pathlib import Path
from typing import Any, Dict, List, Optional

from icarus.core import VALID_FTS_TABLES, VALID_TABLES
from icarus.core.markdown import sanitize_markdown
from icarus.core.schema import open_db

QUERY_DISPLAY_LIMIT = 100
FTS_RESULT_LIMIT = 100
_WRITE_ACTIONS = frozenset({
    sqlite3.SQLITE_INSERT, sqlite3.SQLITE_UPDATE, sqlite3.SQLITE_DELETE,
    sqlite3.SQLITE_CREATE_INDEX, sqlite3.SQLITE_CREATE_TABLE, sqlite3.SQLITE_CREATE_TRIGGER,
    sqlite3.SQLITE_CREATE_VIEW, sqlite3.SQLITE_CREATE_VTABLE,
    sqlite3.SQLITE_CREATE_TEMP_INDEX, sqlite3.SQLITE_CREATE_TEMP_TABLE,
    sqlite3.SQLITE_CREATE_TEMP_TRIGGER, sqlite3.SQLITE_CREATE_TEMP_VIEW,
    sqlite3.SQLITE_DROP_INDEX, sqlite3.SQLITE_DROP_TABLE, sqlite3.SQLITE_DROP_TRIGGER,
    sqlite3.SQLITE_DROP_VIEW, sqlite3.SQLITE_DROP_VTABLE,
    sqlite3.SQLITE_DROP_TEMP_INDEX, sqlite3.SQLITE_DROP_TEMP_TABLE,
    sqlite3.SQLITE_DROP_TEMP_TRIGGER, sqlite3.SQLITE_DROP_TEMP_VIEW,
    sqlite3.SQLITE_ALTER_TABLE, sqlite3.SQLITE_ANALYZE, sqlite3.SQLITE_REINDEX,
})
_READ_PRAGMAS_WITH_ARGUMENT = frozenset({
    "table_info", "table_xinfo", "table_list", "index_info", "index_xinfo", "index_list",
    "foreign_key_list", "foreign_key_check", "integrity_check", "quick_check",
})


class QueryResult:
    """Structured query result with metadata."""

    def __init__(
        self,
        rows: List[tuple],
        columns: List[str],
        query_name: str = "",
        *,
        truncated: bool = False,
    ):
        self.rows = rows
        self.columns = columns
        self.query_name = query_name
        self.truncated = truncated

    @property
    def count(self) -> int:
        return len(self.rows)

    def as_dicts(self) -> List[Dict[str, Any]]:
        return [dict(zip(self.columns, row)) for row in self.rows]

    def to_markdown(self) -> str:
        if not self.rows:
            return f"*{sanitize_markdown(self.query_name)}: No results.*\n"

        lines = []
        if self.query_name:
            lines.append(
                f"### {sanitize_markdown(self.query_name)} ({self.count} results)\n"
            )

        lines.append("| " + " | ".join(map(sanitize_markdown, self.columns)) + " |")
        lines.append("| " + " | ".join(["---"] * len(self.columns)) + " |")

        for row in self.rows[:QUERY_DISPLAY_LIMIT]:
            cells = []
            for v in row:
                s = str(v) if v is not None else ""
                if len(s) > 60:
                    s = s[:57] + "..."
                cells.append(sanitize_markdown(s))
            lines.append("| " + " | ".join(cells) + " |")

        if self.truncated:
            lines.append(f"\n*Results truncated at {QUERY_DISPLAY_LIMIT} rows.*")
        elif self.count > QUERY_DISPLAY_LIMIT:
            lines.append(f"\n*... and {self.count - QUERY_DISPLAY_LIMIT} more rows.*")

        return "\n".join(lines)



class IcarusQuery:
    """
    Query engine for ICARUS intelligence databases.

    Supports raw SQL, full-text search, and pre-built intelligence queries.
    """

    def __init__(self, db_path: str, *, writable: bool = False):
        self.db_path = Path(db_path)
        if not self.db_path.exists():
            raise FileNotFoundError(f"Database not found: {db_path}")
        self.writable = writable
        self._write_pending = False
        self._executing_writable = False
        self._guarding_statement = False
        self._statement_writes = False
        # open_db() enables foreign_keys enforcement and scales cache/mmap
        # pragmas to available RAM on this long-lived working connection
        # (see icarus.core.schema.open_db).
        if writable:
            # Explicit mutation path (``icarus exec``): read-write handle.
            self.conn = open_db(self.db_path)
        else:
            # Default query path is READ-ONLY. ``mode=ro`` (not immutable, so
            # the WAL is still honoured for freshly-built databases) blocks
            # writes to the MAIN database file. ``PRAGMA query_only = ON`` is
            # additionally required because ``mode=ro`` protects only the main
            # file — it does NOT stop writes to a database brought in with
            # ``ATTACH``. query_only rejects every write statement on the
            # connection, ATTACHed databases included.
            self.conn = open_db(self.db_path, readonly=True)
            self.conn.execute("PRAGMA query_only = ON")
            self.conn.set_authorizer(self._read_only_authorizer)
        self.conn.row_factory = sqlite3.Row

    @staticmethod
    def _read_only_authorizer(
        action_code: int,
        _arg1: Optional[str],
        _arg2: Optional[str],
        _database: Optional[str],
        _trigger: Optional[str],
    ) -> int:
        """Reject connection-level filesystem operations on query handles."""
        if action_code in (sqlite3.SQLITE_ATTACH, sqlite3.SQLITE_DETACH):
            return sqlite3.SQLITE_DENY
        return sqlite3.SQLITE_OK

    def commit(self) -> None:
        """Publish guarded writes and their trust revocation together."""
        if self._executing_writable:
            raise sqlite3.ProgrammingError(
                "Transaction control during a guarded statement is unsupported"
            )
        if self.writable and self._write_pending and self.conn.in_transaction:
            self._invalidate_write_trust()
        self.conn.commit()
        self._write_pending = False

    def rollback(self) -> None:
        """Discard pending guarded writes and restore their prior trust state."""
        if self._executing_writable:
            raise sqlite3.ProgrammingError(
                "Transaction control during a guarded statement is unsupported"
            )
        self.conn.rollback()
        self._write_pending = False

    def _write_authorizer(self, action, arg1, arg2, _database, _trigger):
        if self._guarding_statement:
            # A SQL COMMIT/ROLLBACK/RELEASE must not escape the statement guard.
            # Raw connection management remains available to the existing CLI.
            if action in (sqlite3.SQLITE_TRANSACTION, sqlite3.SQLITE_SAVEPOINT,
                          sqlite3.SQLITE_ATTACH, sqlite3.SQLITE_DETACH):
                return sqlite3.SQLITE_DENY
            if action in _WRITE_ACTIONS:
                self._statement_writes = True
            elif action == sqlite3.SQLITE_PRAGMA:
                name = (arg1 or "").lower()
                if ((arg2 is not None and name not in _READ_PRAGMAS_WITH_ARGUMENT)
                        or name in {"optimize", "incremental_vacuum", "wal_checkpoint"}):
                    self._statement_writes = True
        return sqlite3.SQLITE_OK

    def _invalidate_write_trust(self):
        # Dropping metadata removes the evidence itself. If it still exists,
        # failed revocation must fail the write rather than silently bless it.
        if self.conn.execute(
            "SELECT 1 FROM sqlite_master WHERE name = 'metadata'"
        ).fetchone() is not None:
            from icarus.integrations.hygeia import invalidate_sanitization
            invalidate_sanitization(self.conn)

    def _execute_writable(self, sql: str, params: tuple) -> QueryResult:
        if self._executing_writable:
            raise sqlite3.ProgrammingError("Recursive guarded statements are not supported")
        self._executing_writable = True
        try:
            return self._execute_writable_statement(sql, params)
        finally:
            self._executing_writable = False

    def _execute_writable_statement(self, sql: str, params: tuple) -> QueryResult:
        owned_transaction = not self.conn.in_transaction
        if owned_transaction:
            self._write_pending = False
            self.conn.execute("BEGIN IMMEDIATE")
        self.conn.execute("SAVEPOINT icarus_query_statement")
        cursor = None
        try:
            self._statement_writes = False
            # Reinstalling the authorizer expires cached preparations, so a
            # repeated statement is authorized again in the next transaction.
            self.conn.set_authorizer(self._write_authorizer)
            self._guarding_statement = True
            try:
                cursor = self.conn.execute(sql, params)
                result = self._consume_result(cursor)
            finally:
                try:
                    if cursor is not None:
                        cursor.close()  # Finalize RETURNING before savepoint release.
                finally:
                    self._guarding_statement = False
            if self._statement_writes:
                self._invalidate_write_trust()
            self.conn.execute("RELEASE SAVEPOINT icarus_query_statement")
            if self._statement_writes:
                self._write_pending = True
            elif owned_transaction:
                self.conn.rollback()  # A read does not retain a writer transaction.
            return result
        except BaseException:
            if self.conn.in_transaction:
                self.conn.execute("ROLLBACK TO SAVEPOINT icarus_query_statement")
                self.conn.execute("RELEASE SAVEPOINT icarus_query_statement")
                if owned_transaction:
                    self.conn.rollback()
            if not self.conn.in_transaction:
                self._write_pending = False
            raise

    def execute(self, sql: str, params: tuple = ()) -> QueryResult:
        """Execute one statement; writable changes remain pending until commit().

        Guarded writes revoke sanitizer evidence atomically. Transaction SQL,
        attachments, and nontransactional operations are not supported here;
        use commit()/rollback() for this connection's transaction lifecycle.
        Direct raw-connection/cursor writes bypass this contract.
        """
        if self.writable:
            return self._execute_writable(sql, params)
        cursor = self.conn.execute(sql, params)
        try:
            return self._consume_result(cursor)
        finally:
            cursor.close()

    @staticmethod
    def _consume_result(cursor) -> QueryResult:
        columns = [desc[0] for desc in cursor.description] if cursor.description else []
        rows = [tuple(row) for row in cursor.fetchmany(QUERY_DISPLAY_LIMIT + 1)]
        truncated = len(rows) > QUERY_DISPLAY_LIMIT
        if truncated:
            rows.pop()
        return QueryResult(rows, columns, truncated=truncated)

    def search(self, query: str, table: str = "files") -> QueryResult:
        """Full-text search via FTS5."""
        if table not in VALID_FTS_TABLES:
            raise ValueError(f"Invalid FTS table: {table!r}")
        fts_table = f"{table}_fts"
        sql = (
            f"SELECT * FROM {table} "  # nosec B608 - table checked against VALID_FTS_TABLES allowlist above; fts_table derived from it; FTS_RESULT_LIMIT is a module constant
            f"WHERE id IN (SELECT rowid FROM {fts_table} WHERE {fts_table} MATCH ?) "
            f"LIMIT {FTS_RESULT_LIMIT}"
        )
        return self.execute(sql, (query,))

    def root_daemons(self) -> QueryResult:
        """Explicit root-user declarations with no recorded sandbox profile.

        Missing identity stays unknown. Numeric UID 0 counts only when the
        row's provenance identifies the Linux parser; a numeric launchd
        UserName or cloud-account field must not inherit UID semantics.
        Configuration does not prove execution or effective sandbox state.
        """
        result = self.execute("""
            SELECT label, program, mach_services
            FROM daemons
            WHERE (user_name = 'root' OR (
                user_name = '0' AND EXISTS (
                    SELECT 1 FROM versions v
                    WHERE v.id = daemons.source_version_id AND v.parser_name = 'linux'
                )
            ))
              AND (sandbox_profile IS NULL OR sandbox_profile = '')
            ORDER BY label
        """)
        result.query_name = "Explicit Root User Declarations (No Recorded Sandbox Profile)"
        return result

    def privileged_entitlements(self, keys: Optional[List[str]] = None) -> QueryResult:
        """Inventory entitlement keys or match caller-specified keys.

        Pass platform-specific keys via the keys parameter. No defaults —
        what counts as 'privileged' depends on the data source. This legacy
        method name does not classify every stored key as privileged.
        """
        if not keys:
            result = self.execute("""
                SELECT e.key, COUNT(*) AS holders
                FROM entitlements e GROUP BY e.key ORDER BY holders DESC LIMIT 50
            """)
            result.query_name = "Entitlement Key Inventory"
            return result
        placeholders = ",".join(["?"] * len(keys))
        result = self.execute(
            f"SELECT e.key, e.value, b.bundle_id, f.path "  # nosec B608 - only bare `?` placeholders interpolated; values passed bound as params below
            f"FROM entitlements e "
            f"JOIN binaries b ON e.binary_id = b.id "
            f"JOIN files f ON b.file_id = f.id "
            f"WHERE e.key IN ({placeholders}) "
            f"ORDER BY e.key, b.bundle_id",
            tuple(keys),
        )
        result.query_name = "Entitlements Matching Requested Keys"
        return result

    def service_map(self) -> QueryResult:
        """All MachServices mapped to their daemons."""
        result = self.execute("""
            SELECT label, mach_services, sandbox_profile, user_name
            FROM daemons
            WHERE mach_services IS NOT NULL
            ORDER BY label
        """)
        result.query_name = "MachService Map"
        return result

    def mach_service_owners(self, pattern: Optional[str] = None) -> QueryResult:
        """Normalized Mach service -> owning daemon (the reachability pivot).

        Resolves a service name to its daemon by join on the mach_services
        table. Pass an optional SQL LIKE pattern to filter service names.
        """
        base = (
            "SELECT m.service_name, d.label, d.user_name, d.sandbox_profile "
            "FROM mach_services m JOIN daemons d ON m.daemon_id = d.id "
        )
        if pattern:
            result = self.execute(
                base + "WHERE m.service_name LIKE ? ORDER BY m.service_name",
                (pattern,),
            )
        else:
            result = self.execute(base + "ORDER BY m.service_name")
        result.query_name = "Mach Service Owners"
        return result

    def daemons_with_entitlement(self, key_pattern: str) -> QueryResult:
        """Service/image declarations linked to a matching extracted entitlement key.

        Joins daemons -> binaries -> entitlements (key LIKE). This is source
        configuration and image metadata, not proof of runtime reachability,
        effective authorization, or an exploitable privilege boundary.
        """
        result = self.execute("""
            SELECT d.label, e.key, e.value, d.sandbox_profile, d.user_name
            FROM daemons d
            JOIN binaries b ON d.binary_id = b.id
            JOIN entitlements e ON e.binary_id = b.id
            WHERE e.key LIKE ?
            ORDER BY d.label, e.key
        """, (key_pattern,))
        result.query_name = f"Daemons with entitlement like {key_pattern!r}"
        return result

    def kernel_surface(self) -> QueryResult:
        """Kext metadata declaring user-client candidates, not proven reachability."""
        result = self.execute("SELECT * FROM v_kernel_attack_surface")
        result.query_name = "Kernel User-Client Declaration Candidates"
        return result

    def test_binaries(self) -> QueryResult:
        """Debug/test artifacts in production."""
        result = self.execute("SELECT * FROM v_test_binaries")
        result.query_name = "Test Binaries in Production"
        return result

    def escape_surface(self) -> QueryResult:
        """Mach-service/entitlement declarations with no recorded sandbox profile.

        The historical raw view retains its schema and column names. This
        helper aliases its unclassified key inventory to entitlement_keys;
        it does not prove privilege, client access, execution, or an escape.
        """
        result = self.execute("""
            SELECT label, program, mach_services, sandbox_profile, user_name,
                   privileged_entitlements AS entitlement_keys
            FROM v_sandbox_escape_surface
        """)
        result.query_name = "Mach Service / Entitlement Declaration Candidates"
        return result

    def observations_for(
        self, entity_table: str, entity_id: int
    ) -> QueryResult:
        """All observations for a specific entity."""
        result = self.execute(
            "SELECT * FROM observations WHERE entity_table = ? AND entity_id = ? "
            "ORDER BY observed_at",
            (entity_table, entity_id),
        )
        result.query_name = f"Observations for {entity_table}:{entity_id}"
        return result

    def pattern_of_life(
        self, entity_table: str, entity_id: int, start: str, end: str
    ) -> QueryResult:
        """Observations for an entity within a time window."""
        result = self.execute(
            "SELECT * FROM observations WHERE entity_table = ? AND entity_id = ? "
            "AND observed_at >= ? AND observed_at <= ? ORDER BY observed_at",
            (entity_table, entity_id, start, end),
        )
        result.query_name = f"Pattern of Life: {entity_table}:{entity_id}"
        return result

    def first_seen(self, entity_table: str, entity_id: int) -> QueryResult:
        """Earliest observation for a specific entity."""
        result = self.execute(
            "SELECT * FROM observations WHERE entity_table = ? AND entity_id = ? "
            "ORDER BY observed_at ASC LIMIT 1",
            (entity_table, entity_id),
        )
        result.query_name = f"First Seen: {entity_table}:{entity_id}"
        return result

    def cross_graph_query(
        self, ontology_table: str, event_type: Optional[str] = None
    ) -> QueryResult:
        """Join ontology entities with their observations."""
        if ontology_table not in VALID_TABLES:
            raise ValueError(f"Invalid table: {ontology_table!r}")
        sql = (
            f"SELECT o.*, obs.observed_at, obs.event_type, obs.observer "  # nosec B608 - ontology_table checked against VALID_TABLES allowlist above; only bound ? params follow
            f"FROM [{ontology_table}] o "
            f"JOIN observations obs ON obs.entity_table = ? AND obs.entity_id = o.id "
        )
        params: list = [ontology_table]
        if event_type:
            sql += "WHERE obs.event_type = ? "
            params.append(event_type)
        sql += "ORDER BY obs.observed_at"
        result = self.execute(sql, tuple(params))
        result.query_name = f"Cross-Graph: {ontology_table}"
        return result

    def observation_diff(
        self, start_version_id: int, end_version_id: int
    ) -> QueryResult:
        """Observations in end_version that don't exist in start_version."""
        result = self.execute(
            "SELECT entity_table, entity_id, event_type, observed_at, observer "
            "FROM observations WHERE version_id = ? "
            "AND id NOT IN ("
            "  SELECT e.id FROM observations e "
            "  JOIN observations s ON e.entity_table = s.entity_table "
            "    AND e.entity_id = s.entity_id "
            "    AND e.event_type = s.event_type "
            "    AND e.observed_at = s.observed_at "
            "  WHERE s.version_id = ? AND e.version_id = ?"
            ") ORDER BY entity_table, entity_id",
            (end_version_id, start_version_id, end_version_id),
        )
        result.query_name = f"Observation Diff: v{start_version_id} -> v{end_version_id}"
        return result

    def stats(self) -> Dict[str, int]:
        """Database statistics."""
        counts = {}
        for table in sorted(VALID_TABLES - {"metadata", "versions"}):
            try:
                row = self.conn.execute(f"SELECT COUNT(*) FROM [{table}]").fetchone()  # nosec B608 - table drawn from the VALID_TABLES allowlist itself (loop var), not external input
                counts[table] = row[0]
            except sqlite3.OperationalError:
                counts[table] = 0
        return counts

    def close(self) -> None:
        if self._executing_writable:
            raise sqlite3.ProgrammingError("Closing during a guarded statement is unsupported")
        # SQLite closes by rolling back an uncommitted transaction, including
        # its pending trust revocation. Native close also remains idempotent.
        self.conn.close()
        self._write_pending = False

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()
