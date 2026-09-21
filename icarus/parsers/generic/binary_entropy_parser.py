"""Generic binary parser — catalogs unrecognized files by metadata (size, hash,
extension) and records a Shannon-entropy observation for each one."""

import json
import math
import os
from collections import Counter
from pathlib import Path
from typing import Any, Dict, Optional

from icarus.core.detection import DetectionEvidence
from icarus.core.schema import open_db
from icarus.parsers.base import BATCH_COMMIT_INTERVAL, MAX_HASH_FILE_SIZE, BaseParser

# Same cap used for hashing (base._safe_hash) — entropy needs the whole file
# read into memory for its byte-frequency histogram, so the bound matters
# even more here than for the streaming SHA-256 pass.
MAX_ENTROPY_FILE_SIZE = MAX_HASH_FILE_SIZE

KNOWN_EXTENSIONS = frozenset({
    ".json", ".xml", ".yaml", ".yml", ".toml", ".ini", ".conf", ".cfg",
    ".py", ".js", ".ts", ".java", ".c", ".h", ".cpp", ".rs", ".go",
    ".md", ".txt", ".rst", ".html", ".css", ".csv",
    ".db", ".sqlite", ".sqlite3",
    ".zip", ".tar", ".gz", ".tgz", ".bz2", ".xz",
    ".exe", ".dll", ".sys", ".so", ".dylib",
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
})


class BinaryEntropyParser(BaseParser):
    @property
    def name(self) -> str:
        return "generic/binary"

    @property
    def description(self) -> str:
        return (
            "Generic binary/unknown — catalogs files by metadata (size, hash, "
            "extension) and a Shannon-entropy observation"
        )

    def identify(self, source: Path) -> bool:
        if not source.is_dir():
            return False
        for dirpath, _, filenames in os.walk(source, onerror=lambda e: None):
            if filenames:
                return True
        return False

    def identify_evidence(self, evidence: DetectionEvidence) -> bool:
        return bool(evidence.files)

    def extract_entities(self, source: Path, db_path: Path) -> Dict[str, Any]:
        conn = open_db(db_path)
        stats = {"files": 0}
        try:
            for dirpath, _, filenames in os.walk(source, onerror=lambda e: None):
                for fname in filenames:
                    path = Path(dirpath) / fname
                    try:
                        st, kind = self._file_kind(path)
                        if st is None or kind in ("special", "unreadable"):
                            continue
                        ext = path.suffix.lower()
                        rel = self._rel_path(path, source)
                        is_link = kind == "symlink"
                        file_type = "symlink" if is_link else "unknown"
                        if not is_link and ext in KNOWN_EXTENSIONS:
                            file_type = ext.lstrip(".")
                        conn.execute(
                            "INSERT OR IGNORE INTO files "
                            "(path,filename,extension,size,sha256,file_type,"
                            "is_symlink,symlink_target) VALUES (?,?,?,?,?,?,?,?)",
                            (
                                rel, self._safe_text(path.name), ext or None, st.st_size,
                                self._safe_hash(path, st.st_size), file_type,
                                int(is_link), self._symlink_target(path),
                            ),
                        )
                        stats["files"] += 1

                        if not is_link:
                            file_row = conn.execute(
                                "SELECT id FROM files WHERE path=?", (rel,)
                            ).fetchone()
                            if file_row:
                                entropy = self._shannon_entropy(path, st.st_size)
                                if entropy is not None:
                                    dup = conn.execute(
                                        "SELECT id FROM observations "
                                        "WHERE entity_table=? AND entity_id=? "
                                        "AND event_type=?",
                                        ("files", file_row[0], "binary_entropy"),
                                    ).fetchone()
                                    if not dup:
                                        conn.execute(
                                            "INSERT INTO observations "
                                            "(entity_table,entity_id,observed_at,"
                                            "event_type,properties) VALUES "
                                            "(?,?,datetime('now'),?,?)",
                                            (
                                                "files", file_row[0], "binary_entropy",
                                                json.dumps({"shannon_entropy": entropy}),
                                            ),
                                        )
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

    @staticmethod
    def _shannon_entropy(path: Path, size: int) -> Optional[float]:
        """Shannon entropy (bits/byte, 0.0-8.0) of a regular file's contents.

        Returns None for files over MAX_ENTROPY_FILE_SIZE, empty files, symlinks,
        or on any read failure — callers skip recording an observation in that
        case rather than store a misleading zero.
        """
        if size <= 0 or size >= MAX_ENTROPY_FILE_SIZE:
            return None
        try:
            counts: Counter = Counter()
            total = 0
            with BaseParser._open_regular(path) as handle:
                for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                    counts.update(chunk)
                    total += len(chunk)
        except (PermissionError, OSError):
            return None
        if total == 0:
            return None
        entropy = 0.0
        for occurrences in counts.values():
            p = occurrences / total
            entropy -= p * math.log2(p)
        return round(entropy, 4)
