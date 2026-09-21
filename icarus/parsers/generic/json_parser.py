"""Generic JSON parser — extracts file entities from directories containing .json files."""

import json
import os
import warnings
from pathlib import Path
from typing import Any, Dict

from icarus.core.detection import DetectionEvidence
from icarus.core.schema import open_db
from icarus.parsers.base import BATCH_COMMIT_INTERVAL, BaseParser

# Do not read files larger than this fully into memory to parse keys.
_MAX_JSON_BYTES = 50_000_000


class JsonParser(BaseParser):
    @property
    def name(self) -> str:
        return "generic/json"

    @property
    def description(self) -> str:
        return "Generic JSON file directory — catalogs .json files and top-level keys"

    def identify(self, source: Path) -> bool:
        if not source.is_dir():
            return False
        for dirpath, _, filenames in os.walk(source, onerror=lambda e: None):
            for f in filenames:
                if f.lower().endswith(".json"):
                    return True
        return False

    def identify_evidence(self, evidence: DetectionEvidence) -> bool:
        return any(entry.relative.lower().endswith(".json") for entry in evidence.files)

    def extract_entities(self, source: Path, db_path: Path) -> Dict[str, Any]:
        conn = open_db(db_path)
        stats = {"files": 0}
        try:
            for dirpath, _, filenames in os.walk(source, onerror=lambda e: None):
                for fname in filenames:
                    path = Path(dirpath) / fname
                    if not fname.lower().endswith(".json"):
                        continue
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
                                rel, self._safe_text(path.name), ".json", st.st_size,
                                self._safe_hash(path, st.st_size),
                                "symlink" if is_link else "json",
                                int(is_link), self._symlink_target(path),
                            ),
                        )
                        stats["files"] += 1

                        try:
                            if not is_link and 0 < st.st_size <= _MAX_JSON_BYTES:
                                with self._open_regular(path) as handle:
                                    raw = handle.read(_MAX_JSON_BYTES + 1)
                                data = (
                                    json.loads(raw.decode(errors="replace"))
                                    if len(raw) <= _MAX_JSON_BYTES
                                    else None
                                )
                            else:
                                data = None
                            if isinstance(data, dict):
                                keys = json.dumps(
                                    [self._safe_text(key) for key in sorted(data.keys())[:20]]
                                )
                                file_row = conn.execute(
                                    "SELECT id FROM files WHERE path=?", (rel,)
                                ).fetchone()
                                if file_row:
                                    dup = conn.execute(
                                        "SELECT id FROM observations"
                                        " WHERE entity_table=?"
                                        " AND entity_id=?"
                                        " AND event_type=?",
                                        ("files", file_row[0],
                                         "json_keys"),
                                    ).fetchone()
                                    if not dup:
                                        conn.execute(
                                            "INSERT INTO observations"
                                            " (entity_table,entity_id,"
                                            "observed_at,event_type,"
                                            "properties)"
                                            " VALUES"
                                            " (?,?,datetime('now'),?,?)",
                                            ("files", file_row[0],
                                             "json_keys", keys),
                                        )
                        except (
                            json.JSONDecodeError,
                            UnicodeDecodeError,
                        ):
                            pass
                        except (RecursionError, MemoryError):
                            warnings.warn(
                                "Skipping JSON that exceeds parser depth/memory limits: "
                                f"{self._safe_text(str(path))}",
                                RuntimeWarning,
                                stacklevel=2,
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
