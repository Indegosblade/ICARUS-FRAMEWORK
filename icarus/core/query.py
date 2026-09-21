"""
ICARUS Query Engine — SQL interface with full-text search and intelligence views.

Provides both raw SQL access and pre-built intelligence queries
for common patterns (privilege escalation surface, anomalies, etc.).
"""

import sqlite3
from pathlib import Path
from typing import Any, Dict, List, Optional

from icarus.core import VALID_FTS_TABLES, VALID_TABLES
from icarus.core.markdown import sanitize_markdown
from icarus.core.schema import open_db

QUERY_DISPLAY_LIMIT = 100
FTS_RESULT_LIMIT = 100


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
        """Commit pending changes (only meaningful on a writable connection)."""
        self.conn.commit()

    def execute(self, sql: str, params: tuple = ()) -> QueryResult:
        """Execute raw SQL with a bounded result set for terminal display."""
        cursor = self.conn.execute(sql, params)
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
        """Daemons running as root with no sandbox."""
        result = self.execute("""
            SELECT label, program, mach_services
            FROM daemons
            WHERE (user_name = 'root' OR user_name IS NULL)
              AND (sandbox_profile IS NULL OR sandbox_profile = '')
            ORDER BY label
        """)
        result.query_name = "Root Daemons (No Sandbox)"
        return result

    def privileged_entitlements(self, keys: Optional[List[str]] = None) -> QueryResult:
        """Binaries holding specified privileged entitlements.

        Pass platform-specific keys via the keys parameter. No defaults —
        what counts as 'privileged' depends on the data source.
        """
        if not keys:
            result = self.execute("""
                SELECT e.key, COUNT(*) AS holders
                FROM entitlements e GROUP BY e.key ORDER BY holders DESC LIMIT 50
            """)
            result.query_name = "Privileged Entitlements"
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
        result.query_name = "Privileged Entitlements"
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
        """Daemons whose executable binary holds a matching entitlement key.

        Joins daemons -> binaries -> entitlements (key LIKE). The core
        attack-surface question: which reachable daemons hold a powerful
        entitlement (e.g. an IOKit user-client class or a private TCC allow).
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
        """Kernel extensions with user-reachable interfaces."""
        result = self.execute("SELECT * FROM v_kernel_attack_surface")
        result.query_name = "Kernel Attack Surface"
        return result

    def test_binaries(self) -> QueryResult:
        """Debug/test artifacts in production."""
        result = self.execute("SELECT * FROM v_test_binaries")
        result.query_name = "Test Binaries in Production"
        return result

    def escape_surface(self) -> QueryResult:
        """Privileged daemons reachable via mach-lookup."""
        result = self.execute("SELECT * FROM v_sandbox_escape_surface")
        result.query_name = "Sandbox Escape Surface"
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
        self.conn.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()
