"""
ICARUS Base Parser — Abstract interface for data source parsers.

Every parser implements this interface. The pipeline calls these methods
in sequence. Each parser knows how to extract entities and relationships
from one specific data source type.
"""

import hashlib
import os
import sqlite3
import stat
import warnings
from abc import ABC, abstractmethod
from contextlib import contextmanager
from pathlib import Path
from typing import Any, BinaryIO, Dict, Iterator, List, Optional

from icarus.core.schema import open_db

MAX_HASH_FILE_SIZE = 50_000_000
BATCH_COMMIT_INTERVAL = 50_000


class BaseParser(ABC):
    """
    Abstract base class for ICARUS parsers.

    Implement this to add support for a new data source type.
    Auto-detection may call identify; an explicit parser selection bypasses it.
    The pipeline then calls extract_entities, extract_relationships, and verify.
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """Short identifier for this parser (e.g., 'windows', 'linux', 'android')."""
        ...

    @property
    @abstractmethod
    def description(self) -> str:
        """One-line description of what this parser handles."""
        ...

    @abstractmethod
    def identify(self, source: Path) -> bool:
        """
        Return True if this parser can handle the given source.

        The pipeline may call this on multiple parsers to auto-detect
        the source type. Check for characteristic files/structures.
        """
        ...

    @abstractmethod
    def extract_entities(self, source: Path, db_path: Path) -> Dict[str, Any]:
        """
        Walk the source and extract entities into the database.

        This is the main extraction phase. Write files, binaries,
        daemons, entitlements, etc. into the ICARUS schema tables.

        Returns stats dict (e.g., {"files": 500000, "binaries": 15000}).
        """
        ...

    @abstractmethod
    def extract_relationships(self, source: Path, db_path: Path) -> Dict[str, Any]:
        """
        Map relationships between extracted entities.

        Called after extract_entities. Link daemons to binaries,
        binaries to entitlements, sandbox profiles to rules, etc.

        Returns stats dict.
        """
        ...

    def verify(self, db_path: Path) -> Dict[str, Any]:
        """
        Run quality gates on the populated database.

        Override to add parser-specific verification. Default
        counts files and binaries and requires at least one file row.
        """
        conn = open_db(db_path)
        try:
            tables = ["files", "binaries"]
            stats = {}
            for t in tables:
                try:
                    count = conn.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0]  # nosec B608 - t iterates the hardcoded ["files", "binaries"] literal above, not external input
                    stats[t] = count
                except sqlite3.OperationalError:
                    stats[t] = 0
        finally:
            conn.close()

        if stats.get("files", 0) == 0:
            raise ValueError("Verification failed: files table is empty")

        return stats

    def get_required_tools(self) -> List[str]:
        """
        Return list of external tools this parser requires.

        Override to declare dependencies (e.g., ['readelf'] for Linux).
        This method describes prerequisites; callers or the parser must check
        availability. The current pipeline does not invoke it automatically.
        """
        return []

    @staticmethod
    def _rel_path(path: Path, source: Path) -> str:
        """Normalized relative path for database storage."""
        relative = str(path.relative_to(source)).replace("\\", "/")
        return "/" + BaseParser._safe_text(relative)

    @staticmethod
    def _safe_text(value: str) -> str:
        """Return UTF-8-bindable text, escaping filesystem surrogate bytes."""
        return value.encode("utf-8", "backslashreplace").decode("utf-8")

    @staticmethod
    def _file_kind(path: Path):
        """Return ``(lstat, kind)`` without following links.

        Readable results are ``regular``, ``symlink``, or ``special``;
        ``unreadable`` is a fail-closed result.
        Callers may catalog final-component symlinks from their own inode
        metadata, but must only open ``regular`` paths.
        """
        try:
            st = path.lstat()
        except (OSError, PermissionError):
            return None, "unreadable"
        if stat.S_ISLNK(st.st_mode):
            return st, "symlink"
        if stat.S_ISREG(st.st_mode):
            return st, "regular"
        warnings.warn(
            f"Skipping non-regular input: {BaseParser._safe_text(str(path))}",
            RuntimeWarning,
            stacklevel=2,
        )
        return st, "special"

    @staticmethod
    def _path_has_symlink(path: Path, root: Optional[Path] = None) -> bool:
        """True when a component below ``root`` is a symlink or Windows reparse point.

        Host-managed ancestors outside the source tree are intentionally ignored:
        macOS runners, for example, may place temporary directories beneath a
        symlinked system component.  Treating those as hostile would reject every
        otherwise-regular input.  Callers that walk a source tree already rely on
        ``os.walk(..., followlinks=False)``; direct-directory parsers pass their
        source root here to enforce the same boundary.
        """
        absolute = Path(os.path.abspath(os.fspath(path)))
        if root is None:
            start = Path(absolute.anchor)
            parts = absolute.parts[1:]
        else:
            start = Path(os.path.abspath(os.fspath(root)))
            try:
                parts = absolute.relative_to(start).parts
            except ValueError:
                return True
        current = start
        for part in parts:
            current /= part
            try:
                entry_stat = current.lstat()
                if stat.S_ISLNK(entry_stat.st_mode) or (
                    getattr(entry_stat, "st_file_attributes", 0)
                    & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
                ):
                    return True
            except (OSError, PermissionError):
                return True
        return False

    @staticmethod
    def _symlink_target(path: Path) -> Optional[str]:
        """Read link metadata only; never dereference the target."""
        try:
            return BaseParser._safe_text(os.readlink(path))
        except (OSError, PermissionError):
            return None

    @staticmethod
    @contextmanager
    def _open_regular(path: Path) -> Iterator[BinaryIO]:
        """Open one regular file without following a final symlink on POSIX.

        ``O_NONBLOCK`` prevents a raced-in FIFO from hanging, ``O_NOFOLLOW``
        rejects a raced-in final symlink where the platform supports it, and
        ``fstat`` verifies the opened object rather than trusting only the
        earlier path metadata check.
        """
        _, kind = BaseParser._file_kind(path)
        if kind != "regular":
            raise OSError("input is not a regular file")
        flags = (
            os.O_RDONLY
            | getattr(os, "O_BINARY", 0)
            | getattr(os, "O_NONBLOCK", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        fd = os.open(path, flags)
        try:
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                raise OSError("opened input is not a regular file")
            with os.fdopen(fd, "rb") as handle:
                fd = -1
                yield handle
        finally:
            if fd >= 0:
                os.close(fd)

    @staticmethod
    def _safe_hash(path: Path, size: int) -> Optional[str]:
        """SHA-256 of file contents, or None if >50MB, a symlink, or inaccessible.

        Symlinks are never dereferenced: hashing a link would read its target,
        which may resolve to a file outside the source tree.
        """
        if size >= MAX_HASH_FILE_SIZE:
            return None
        try:
            digest = hashlib.sha256()
            with BaseParser._open_regular(path) as handle:
                for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                    digest.update(chunk)
            return digest.hexdigest()
        except (PermissionError, OSError):
            return None

    @staticmethod
    def _check_magic(path: Path, magic: bytes) -> bool:
        """Check if file starts with the given magic bytes."""
        try:
            with BaseParser._open_regular(path) as f:
                return f.read(len(magic)) == magic
        except (PermissionError, OSError):
            return False


def link_daemons_to_binaries(conn: sqlite3.Connection) -> int:
    """Populate ``daemons.binary_id`` by matching each daemon's ``program``
    executable path to the ``binaries`` row for that file. Returns the number of
    edges created. Does not commit — the caller owns the transaction.

    This daemon -> binary edge is what makes the escape-surface views (which
    JOIN ``daemons.binary_id = binaries.id``) non-empty; without it a daemon and
    the binary it launches stay disconnected in the entity graph (finding #93).
    Shared by every parser whose daemons record an executable path, so the
    linking rule lives in exactly one place.
    """
    linked = 0
    rows = conn.execute(
        "SELECT id, program FROM daemons "
        "WHERE program IS NOT NULL AND program != '' AND binary_id IS NULL"
    ).fetchall()
    for daemon_id, program in rows:
        bin_row = conn.execute(
            "SELECT b.id FROM binaries b JOIN files f ON b.file_id = f.id "
            "WHERE f.path = ? LIMIT 1",
            (program,),
        ).fetchone()
        if bin_row:
            conn.execute(
                "UPDATE daemons SET binary_id = ? WHERE id = ?",
                (bin_row[0], daemon_id),
            )
            linked += 1
    return linked
