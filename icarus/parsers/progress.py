"""Crash-safe directory frontier for filesystem parsers.

The source must stay immutable during an interrupted build. Progress lives in
the output database so entity rows, provenance, and the next input position
commit together. Successful extraction removes all private progress state.
"""

import json
import os
import sqlite3
import warnings
from pathlib import Path
from typing import Iterator

from icarus.core.schema import ENTITY_TABLES
from icarus.parsers.base import BATCH_COMMIT_INTERVAL, BaseParser


class IngestProgress:
    """Own commits for one parser's resumable file walk on one connection."""

    def __init__(self, conn: sqlite3.Connection, source: Path, parser: str, stats: dict):
        self.conn = conn
        self.source = Path(source).resolve()
        self.parser = parser
        self.stats = stats
        self.interval = BATCH_COMMIT_INTERVAL
        self.processed = 0
        self.exhausted = False
        versions = conn.execute(
            "SELECT id, run_id, started_at FROM versions "
            "WHERE completed_at IS NULL ORDER BY id DESC LIMIT 2"
        ).fetchall()
        if len(versions) > 1:
            raise ValueError("Ingest requires one unambiguous active run")
        self.version = versions[0] if versions else None
        self.tables = (*ENTITY_TABLES, "mach_services")
        # All identifiers are schema-owned, never source-controlled.
        self.watermarks = {
            table: conn.execute(
                f"SELECT COALESCE(MAX(id), 0) FROM {table}"  # nosec B608
            ).fetchone()[0]
            for table in self.tables
        }

    def __enter__(self):
        self.conn.execute(
            "CREATE TABLE IF NOT EXISTS _icarus_ingest_state "
            "(singleton INTEGER PRIMARY KEY CHECK(singleton = 1), "
            "source BLOB NOT NULL, parser TEXT NOT NULL, run_id TEXT, stats TEXT NOT NULL)"
        )
        self.conn.execute(
            "CREATE TABLE IF NOT EXISTS _icarus_ingest_frontier "
            "(directory BLOB PRIMARY KEY, last_filename BLOB)"
        )
        identity = (
            os.fsencode(self.source), self.parser, self.version[1] if self.version else None,
        )
        state = self.conn.execute(
            "SELECT source, parser, run_id, stats FROM _icarus_ingest_state WHERE singleton = 1"
        ).fetchone()
        if state is not None:
            if tuple(state[:3]) != identity:
                raise ValueError(
                    "Ingest progress belongs to a different source/parser/run; rebuild fresh"
                )
            self.stats.update(json.loads(state[3]))
        else:
            self.conn.execute(
                "INSERT INTO _icarus_ingest_state VALUES (1, ?, ?, ?, ?)",
                (*identity, json.dumps(self.stats)),
            )
            self.conn.execute("INSERT INTO _icarus_ingest_frontier VALUES (?, NULL)", (b"",))
        self.conn.commit()
        return self

    def _commit(self):
        if self.version is not None:
            version_id, _, observed_time = self.version
            for table in self.tables:
                self.conn.execute(
                    f"UPDATE {table} SET source_version_id = ?, "  # nosec B608
                    "observed_time = COALESCE(observed_time, ?) WHERE id > ?",
                    (version_id, observed_time, self.watermarks[table]),
                )
        self.conn.execute(
            "UPDATE _icarus_ingest_state SET stats = ? WHERE singleton = 1",
            (json.dumps(self.stats),),
        )
        self.conn.commit()
        for table in self.tables:
            self.watermarks[table] = self.conn.execute(
                f"SELECT COALESCE(MAX(id), 0) FROM {table}"  # nosec B608
            ).fetchone()[0]

    def walk(self) -> Iterator[tuple[Path, Iterator[str]]]:
        """Yield directories with a cursor-aware filename iterator.

        Only pending directories are opened on resume. File names are ordered
        by their raw filesystem encoding; the durable cursor is never an
        ordinal in an unstable operating-system directory listing.
        """
        while True:
            row = self.conn.execute(
                "SELECT directory, last_filename FROM _icarus_ingest_frontier "
                "ORDER BY directory LIMIT 1"
            ).fetchone()
            if row is None:
                self.exhausted = True
                return
            relative, cursor = row
            directory = self.source / os.fsdecode(relative)
            filenames = []
            if not BaseParser._path_has_symlink(directory, root=self.source):
                try:
                    with os.scandir(directory) as entries:
                        for entry in entries:
                            try:
                                if entry.is_dir(follow_symlinks=False):
                                    child = os.fsencode(Path(entry.path).relative_to(self.source))
                                    self.conn.execute(
                                        "INSERT OR IGNORE INTO _icarus_ingest_frontier "
                                        "VALUES (?, NULL)", (child,),
                                    )
                                elif not (entry.is_symlink() and entry.is_dir()):
                                    encoded = os.fsencode(entry.name)
                                    if cursor is None or encoded > cursor:
                                        filenames.append(encoded)
                            except OSError:
                                warnings.warn(
                                    "Skipping unreadable directory entry: "
                                    + BaseParser._safe_text(str(directory / entry.name)),
                                    RuntimeWarning, stacklevel=2,
                                )
                except OSError:
                    # Match the filesystem parsers' existing inaccessible-directory policy.
                    pass
            self.directory_complete = False
            yield directory, self._filenames(relative, sorted(filenames))
            if not self.directory_complete:
                raise RuntimeError("Ingest directory iterator was not fully consumed")
            self.conn.execute(
                "DELETE FROM _icarus_ingest_frontier WHERE directory = ?", (relative,)
            )
            self.processed += 1
            if self.processed % self.interval == 0:
                self._commit()

    def _filenames(self, relative: bytes, filenames: list[bytes]) -> Iterator[str]:
        for filename in filenames:
            yield os.fsdecode(filename)
            # Advance only after the caller finishes all writes for this input.
            self.processed += 1
            if self.processed % self.interval == 0:
                self.conn.execute(
                    "UPDATE _icarus_ingest_frontier SET last_filename = ? WHERE directory = ?",
                    (filename, relative),
                )
                self._commit()
        self.directory_complete = True

    def __exit__(self, exc_type, exc_value, traceback):
        if exc_type is not None or not self.exhausted:
            self.conn.rollback()
            if exc_type is None:
                raise RuntimeError("Ingest walk was not fully consumed")
            return False
        self._commit()
        self.conn.execute("DROP TABLE _icarus_ingest_frontier")
        self.conn.execute("DROP TABLE _icarus_ingest_state")
        self.conn.commit()
        return False
