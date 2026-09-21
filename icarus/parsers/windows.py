"""
ICARUS Windows Parser — Generic Windows application/directory analysis.

Extracts entities from any Windows directory tree in a single walk:
- Filesystem inventory (every file, hashed)
- PE binaries (EXE/DLL with architecture detection)
- Frameworks (DLLs as shared libraries)
"""

import os
import struct
from pathlib import Path
from typing import Any, Dict

from icarus.core.detection import DetectionEvidence
from icarus.core.schema import open_db
from icarus.parsers.base import BATCH_COMMIT_INTERVAL, BaseParser

PE_MAGIC = b"MZ"
PE_ARCH = {0x8664: "x86_64", 0x14C: "x86", 0xAA64: "arm64"}

# Bounds for the auto-detect probe (identify()) so it never full-walks a large
# or slow source just to answer yes/no. A real Windows tree carries .exe/.dll
# within this sample; extraction (not detection) does the full walk.
_IDENTIFY_FILE_BUDGET = 5000
_IDENTIFY_DIR_BUDGET = 1000
FILE_TYPES = {
    ".exe": "binary", ".dll": "dylib", ".sys": "driver",
    ".json": "config", ".xml": "config", ".ini": "config",
    ".pdb": "debug", ".pak": "resource", ".dat": "data",
    ".manifest": "manifest", ".cat": "catalog",
}


class WindowsParser(BaseParser):
    """Parser for Windows application directories."""

    @property
    def name(self) -> str:
        return "windows"

    @property
    def description(self) -> str:
        return "Windows application directory or filesystem tree"

    def identify(self, source: Path) -> bool:
        # Auto-detection must not pay a full tree walk just to answer yes/no:
        # during `build` without -p, each candidate parser's identify() runs in
        # turn, so an unbounded walk here can dwarf extraction on a large or slow
        # source (#78). Bound the probe — inspect at most _IDENTIFY_FILE_BUDGET
        # files across at most _IDENTIFY_DIR_BUDGET directories (os.walk is
        # top-down, so shallow locations are checked first) and answer from that
        # sample. A real Windows tree carries .exe/.dll near the top.
        if not source.is_dir():
            return False
        files_seen = 0
        dirs_seen = 0
        for _dirpath, _, filenames in os.walk(source, onerror=lambda e: None):
            dirs_seen += 1
            for fname in filenames:
                if fname.lower().endswith((".exe", ".dll")):
                    return True
                files_seen += 1
                if files_seen >= _IDENTIFY_FILE_BUDGET:
                    return False
            if dirs_seen >= _IDENTIFY_DIR_BUDGET:
                return False
        return False

    def identify_evidence(self, evidence: DetectionEvidence) -> bool:
        return any(
            entry.relative.lower().endswith((".exe", ".dll"))
            for entry in evidence.files
        )

    def extract_entities(self, source: Path, db_path: Path) -> Dict[str, Any]:
        conn = open_db(db_path)
        stats = {"files": 0, "binaries": 0, "frameworks": 0}
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
                        filename = self._safe_text(path.name)
                        is_link = kind == "symlink"
                        file_type = "symlink" if is_link else FILE_TYPES.get(ext, "other")

                        conn.execute(
                            "INSERT OR IGNORE INTO files "
                            "(path,filename,extension,size,sha256,file_type,"
                            "is_symlink,symlink_target) VALUES (?,?,?,?,?,?,?,?)",
                            (rel, filename, ext or None, st.st_size,
                             self._safe_hash(path, st.st_size),
                             file_type, int(is_link), self._symlink_target(path)),
                        )
                        stats["files"] += 1

                        if is_link:
                            if stats["files"] % BATCH_COMMIT_INTERVAL == 0:
                                conn.commit()
                            continue

                        is_pe = ext in (".exe", ".dll") and self._check_magic(path, PE_MAGIC)
                        if is_pe:
                            row = conn.execute(
                                "SELECT id FROM files WHERE path=?", (rel,)
                            ).fetchone()
                            if row:
                                existing = conn.execute(
                                    "SELECT id FROM binaries WHERE file_id=?",
                                    (row[0],),
                                ).fetchone()
                                if not existing:
                                    conn.execute(
                                        "INSERT INTO binaries "
                                        "(file_id,executable_name,arch) VALUES (?,?,?)",
                                        (row[0], filename, _detect_pe_arch(path)),
                                    )
                                    stats["binaries"] += 1

                        # A file merely named *.dll is not a framework unless it
                        # actually carries PE magic (#28) — mirrors the binaries
                        # path above, which already validates MZ before trusting
                        # the extension.
                        if ext == ".dll" and is_pe:
                            cur = conn.execute(
                                "INSERT OR IGNORE INTO frameworks "
                                "(name,path,is_private) VALUES (?,?,0)",
                                (self._safe_text(path.stem), rel),
                            )
                            if cur.rowcount:
                                stats["frameworks"] += 1
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


def _detect_pe_arch(path: Path) -> str:
    try:
        with BaseParser._open_regular(path) as f:
            f.seek(0x3C)
            pe_offset = struct.unpack("<I", f.read(4))[0]
            f.seek(pe_offset + 4)
            machine = struct.unpack("<H", f.read(2))[0]
            return PE_ARCH.get(machine, "unknown")
    except (PermissionError, OSError, struct.error):
        return "unknown"
