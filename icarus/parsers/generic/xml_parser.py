"""Generic XML parser — extracts file entities from directories containing .xml files."""

import os
from pathlib import Path
from typing import Any, Dict

from icarus.core.detection import DetectionEvidence
from icarus.core.schema import open_db
from icarus.parsers.base import BATCH_COMMIT_INTERVAL, BaseParser


class XmlParser(BaseParser):
    @property
    def name(self) -> str:
        return "generic/xml"

    @property
    def description(self) -> str:
        return "Generic XML file directory — catalogs .xml files"

    def identify(self, source: Path) -> bool:
        if not source.is_dir():
            return False
        for dirpath, _, filenames in os.walk(source, onerror=lambda e: None):
            for f in filenames:
                if f.lower().endswith(".xml"):
                    return True
        return False

    def identify_evidence(self, evidence: DetectionEvidence) -> bool:
        return any(entry.relative.lower().endswith(".xml") for entry in evidence.files)

    def extract_entities(self, source: Path, db_path: Path) -> Dict[str, Any]:
        conn = open_db(db_path)
        stats = {"files": 0}
        try:
            for dirpath, _, filenames in os.walk(source, onerror=lambda e: None):
                for fname in filenames:
                    if not fname.lower().endswith(".xml"):
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
                                rel, self._safe_text(path.name), ".xml", st.st_size,
                                self._safe_hash(path, st.st_size),
                                "symlink" if is_link else "xml",
                                int(is_link), self._symlink_target(path),
                            ),
                        )
                        stats["files"] += 1
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
