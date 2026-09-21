"""Generic SQLite parser — catalogs .db/.sqlite files and their table schemas."""

import os
import sqlite3
from contextlib import closing
from pathlib import Path
from typing import Any, Dict

from icarus.core.detection import DetectionEvidence
from icarus.core.schema import open_db
from icarus.parsers.base import BATCH_COMMIT_INTERVAL, BaseParser


class SqliteParser(BaseParser):
    @property
    def name(self) -> str:
        return "generic/sqlite"

    @property
    def description(self) -> str:
        return "Generic SQLite database directory — catalogs .db/.sqlite files and schemas"

    def identify(self, source: Path) -> bool:
        if not source.is_dir():
            return False
        for dirpath, _, filenames in os.walk(source, onerror=lambda e: None):
            for f in filenames:
                if f.lower().endswith((".db", ".sqlite", ".sqlite3")):
                    return True
        return False

    def identify_evidence(self, evidence: DetectionEvidence) -> bool:
        return any(
            entry.relative.lower().endswith((".db", ".sqlite", ".sqlite3"))
            for entry in evidence.files
        )

    def extract_entities(self, source: Path, db_path: Path) -> Dict[str, Any]:
        conn = open_db(db_path)
        stats = {"files": 0}
        try:
            for dirpath, _, filenames in os.walk(source, onerror=lambda e: None):
                for fname in filenames:
                    if not fname.lower().endswith((".db", ".sqlite", ".sqlite3")):
                        continue
                    path = Path(dirpath) / fname
                    try:
                        st, kind = self._file_kind(path)
                        if st is None or kind in ("special", "unreadable"):
                            continue
                        rel = self._rel_path(path, source)
                        is_link = kind == "symlink"
                        conn.execute(
                            "INSERT OR IGNORE INTO files "
                            "(path,filename,extension,size,sha256,file_type,"
                            "is_symlink,symlink_target) VALUES (?,?,?,?,?,?,?,?)",
                            (
                                rel, self._safe_text(path.name), path.suffix.lower(),
                                st.st_size, self._safe_hash(path, st.st_size),
                                "symlink" if is_link else "database",
                                int(is_link), self._symlink_target(path),
                            ),
                        )
                        stats["files"] += 1

                        file_row = conn.execute(
                            "SELECT id FROM files WHERE path=?", (rel,)
                        ).fetchone()
                        if file_row and not is_link:
                            try:
                                # Open the untrusted source DB read-only and
                                # immutable via a safe file: URI. immutable=1
                                # prevents -wal/-shm sidecar creation and
                                # rollback/recovery, so merely cataloging a
                                # hostile .db never mutates the source tree.
                                # as_uri() percent-encodes the path so a
                                # filename containing '?' cannot inject query
                                # parameters (e.g. mode=rwc). closing() always
                                # closes the source connection, including when
                                # the sqlite_master read raises DatabaseError
                                # on a corrupt/encrypted/non-database file.
                                src_uri = (
                                    Path(os.path.abspath(str(path))).as_uri()
                                    + "?mode=ro&immutable=1"
                                )
                                with closing(
                                    sqlite3.connect(src_uri, uri=True)
                                ) as src_conn:
                                    tables = src_conn.execute(
                                        "SELECT name FROM sqlite_master "
                                        "WHERE type='table' "
                                        "AND name NOT LIKE 'sqlite_%'"
                                    ).fetchall()
                                schema_info = ", ".join(t[0] for t in tables[:30])
                                dup = conn.execute(
                                    "SELECT id FROM observations "
                                    "WHERE entity_table=? AND entity_id=? "
                                    "AND event_type=?",
                                    ("files", file_row[0], "schema_tables"),
                                ).fetchone()
                                if not dup:
                                    conn.execute(
                                        "INSERT INTO observations "
                                        "(entity_table,entity_id,"
                                        "observed_at,event_type,"
                                        "properties) "
                                        "VALUES "
                                        "(?,?,datetime('now'),?,?)",
                                        ("files", file_row[0],
                                         "schema_tables", schema_info),
                                    )
                            except sqlite3.DatabaseError:
                                pass
                    except (PermissionError, OSError):
                        continue
                    if stats["files"] % BATCH_COMMIT_INTERVAL == 0:
                        conn.commit()
            conn.commit()
        finally:
            conn.close()
        return stats

    def extract_relationships(self, source: Path, db_path: Path) -> Dict[str, Any]:
        return {"linked": 0}
