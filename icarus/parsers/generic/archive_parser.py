"""Generic archive parser — catalogs .zip/.tar/.gz files and their contents."""

import gzip
import io
import itertools
import os
import tarfile
import warnings
import zipfile
from pathlib import Path
from typing import Any, BinaryIO, Dict

from icarus.core.detection import DetectionEvidence
from icarus.core.schema import open_db
from icarus.parsers.base import BaseParser

# Listing a compressed tar requires inflating bytes to advance through member
# payloads. Stop after a bounded amount instead of turning cataloging into an
# unbounded decompression operation.
MAX_DECOMPRESSED_TAR_BYTES = 64 * 1024 * 1024

# ``zipfile.ZipFile`` creates one ZipInfo object for every central-directory
# entry while opening the file.  Validate these on-disk bounds first so a
# member-listing request cannot amplify a small archive into unbounded heap.
MAX_ZIP_ARCHIVE_BYTES = 64 * 1024 * 1024
MAX_ZIP_CENTRAL_DIRECTORY_BYTES = 8 * 1024 * 1024
MAX_ZIP_ENTRIES = 10_000
_ZIP_EOCD_SIGNATURE = b"PK\x05\x06"
_ZIP64_LOCATOR_SIGNATURE = b"PK\x06\x07"
_ZIP64_EOCD_SIGNATURE = b"PK\x06\x06"
_ZIP_EOCD_SIZE = 22
_ZIP64_LOCATOR_SIZE = 20
_ZIP64_EOCD_SIZE = 56


class ArchiveParser(BaseParser):
    @property
    def name(self) -> str:
        return "generic/archive"

    @property
    def description(self) -> str:
        return "Generic archive directory — catalogs .zip/.tar/.gz files and contents"

    def identify(self, source: Path) -> bool:
        if not source.is_dir():
            return False
        for dirpath, _, filenames in os.walk(source, onerror=lambda e: None):
            for f in filenames:
                if f.lower().endswith((".zip", ".tar", ".tar.gz", ".tgz", ".gz")):
                    return True
        return False

    def identify_evidence(self, evidence: DetectionEvidence) -> bool:
        return any(
            entry.relative.lower().endswith((".zip", ".tar", ".tar.gz", ".tgz", ".gz"))
            for entry in evidence.files
        )

    def extract_entities(self, source: Path, db_path: Path) -> Dict[str, Any]:
        conn = open_db(db_path)
        stats = {"files": 0}
        try:
            for dirpath, _, filenames in os.walk(source, onerror=lambda e: None):
                for fname in filenames:
                    if not fname.lower().endswith((".zip", ".tar", ".tar.gz", ".tgz", ".gz")):
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
                                "symlink" if is_link else "archive",
                                int(is_link), self._symlink_target(path),
                            ),
                        )
                        stats["files"] += 1

                        file_row = conn.execute(
                            "SELECT id FROM files WHERE path=?", (rel,)
                        ).fetchone()
                        if file_row and not is_link:
                            contents = _list_archive(path)
                            if contents:
                                dup = conn.execute(
                                    "SELECT id FROM observations "
                                    "WHERE entity_table=? "
                                    "AND entity_id=? "
                                    "AND event_type=?",
                                    ("files", file_row[0],
                                     "archive_contents"),
                                ).fetchone()
                                if not dup:
                                    conn.execute(
                                        "INSERT INTO observations "
                                        "(entity_table,entity_id,"
                                        "observed_at,event_type,"
                                        "properties) VALUES "
                                        "(?,?,datetime('now'),?,?)",
                                        ("files", file_row[0],
                                         "archive_contents",
                                         ", ".join(contents[:50])),
                                    )
                    except (PermissionError, OSError):
                        continue
            conn.commit()
        finally:
            conn.close()
        return stats

    def extract_relationships(self, source: Path, db_path: Path) -> Dict[str, Any]:
        return {"linked": 0}


def _list_archive(path: Path, limit: int = 50) -> list:
    """List up to ``limit`` members within bounded work/memory.

    Plain tar members are iterated lazily; compressed tar data is capped before
    parsing; ZIP metadata is checked before ``ZipFile`` can materialize its
    central directory; and all returned name lists retain their output limit.
    """
    try:
        _, kind = BaseParser._file_kind(path)
        if kind != "regular":
            return []
        if path.suffix.lower() == ".zip":
            with BaseParser._open_regular(path) as source:
                _check_zip_listing_budget(source, path)
                source.seek(0)
                with zipfile.ZipFile(source) as zf:
                    return [
                        BaseParser._safe_text(info.filename)
                        for info in itertools.islice(zf.filelist, limit)
                    ]
        elif path.suffix.lower() == ".tar":
            names = []
            with BaseParser._open_regular(path) as source:
                with tarfile.open(fileobj=source, mode="r:") as tf:
                    for member in tf:  # lazy — does not scan the whole archive
                        names.append(BaseParser._safe_text(member.name))
                        if len(names) >= limit:
                            break
            return names
        elif path.suffix.lower() == ".tgz" or path.name.lower().endswith(".tar.gz"):
            with BaseParser._open_regular(path) as source:
                with gzip.GzipFile(fileobj=source) as compressed:
                    data = compressed.read(MAX_DECOMPRESSED_TAR_BYTES + 1)
            if len(data) > MAX_DECOMPRESSED_TAR_BYTES:
                warnings.warn(
                    "Skipping compressed tar whose decompressed data exceeds "
                    f"{MAX_DECOMPRESSED_TAR_BYTES} bytes: "
                    f"{BaseParser._safe_text(str(path))}",
                    RuntimeWarning,
                    stacklevel=2,
                )
                return []
            names = []
            with tarfile.open(fileobj=io.BytesIO(data), mode="r:") as tf:
                for member in tf:
                    names.append(BaseParser._safe_text(member.name))
                    if len(names) >= limit:
                        break
            return names
    except (
        zipfile.BadZipFile,
        tarfile.TarError,
        gzip.BadGzipFile,
        OSError,
        EOFError,
        MemoryError,
    ):
        pass
    return []


def _check_zip_listing_budget(source: BinaryIO, path: Path) -> None:
    """Reject unsafe ZIP directory metadata before constructing ``ZipFile``.

    The stdlib eagerly parses central directories.  Only the trailing EOCD
    (and, when required, its ZIP64 record) is read here; member data is never
    extracted or inspected.
    """
    source.seek(0, os.SEEK_END)
    archive_size = source.tell()
    if archive_size > MAX_ZIP_ARCHIVE_BYTES:
        _skip_zip_listing(path, "archive exceeds " f"{MAX_ZIP_ARCHIVE_BYTES} byte budget")

    tail_size = min(archive_size, _ZIP_EOCD_SIZE + 65535)
    source.seek(archive_size - tail_size)
    tail = source.read(tail_size)
    eocd_at = tail.rfind(_ZIP_EOCD_SIGNATURE)
    if eocd_at < 0 or len(tail) - eocd_at < _ZIP_EOCD_SIZE:
        _skip_zip_listing(path, "missing or truncated end-of-central-directory record")

    eocd = tail[eocd_at:eocd_at + _ZIP_EOCD_SIZE]
    comment_size = int.from_bytes(eocd[20:22], "little")
    if eocd_at + _ZIP_EOCD_SIZE + comment_size != len(tail):
        _skip_zip_listing(path, "malformed end-of-central-directory comment")
    if eocd[4:8] != b"\0\0\0\0" or eocd[8:10] != eocd[10:12]:
        _skip_zip_listing(path, "multi-disk or inconsistent entry metadata")
    eocd_offset = archive_size - tail_size + eocd_at
    entries = int.from_bytes(eocd[10:12], "little")
    directory_size = int.from_bytes(eocd[12:16], "little")
    directory_offset = int.from_bytes(eocd[16:20], "little")
    needs_zip64 = (
        entries == 0xFFFF
        or directory_size == 0xFFFFFFFF
        or directory_offset == 0xFFFFFFFF
    )
    if needs_zip64:
        entries, directory_size, directory_offset, directory_start = _zip64_directory(
            source, eocd_offset, path
        )
    else:
        directory_start = eocd_offset - directory_size - directory_offset

    if entries > MAX_ZIP_ENTRIES:
        _skip_zip_listing(path, f"entry count exceeds {MAX_ZIP_ENTRIES} budget")
    if directory_size > MAX_ZIP_CENTRAL_DIRECTORY_BYTES:
        _skip_zip_listing(
            path,
            "central directory exceeds " f"{MAX_ZIP_CENTRAL_DIRECTORY_BYTES} byte budget",
        )
    directory_end = directory_start + directory_offset + directory_size
    if (
        directory_start < 0
        or directory_offset < 0
        or directory_end > eocd_offset
    ):
        _skip_zip_listing(path, "malformed central-directory bounds")


def _zip64_directory(
    source: BinaryIO, eocd_offset: int, path: Path
) -> tuple[int, int, int, int]:
    """Return ZIP64 entry/directory metadata, rejecting malformed records."""
    if eocd_offset < _ZIP64_LOCATOR_SIZE:
        _skip_zip_listing(path, "missing ZIP64 locator")
    source.seek(eocd_offset - _ZIP64_LOCATOR_SIZE)
    locator = source.read(_ZIP64_LOCATOR_SIZE)
    if len(locator) != _ZIP64_LOCATOR_SIZE or locator[:4] != _ZIP64_LOCATOR_SIGNATURE:
        _skip_zip_listing(path, "missing or malformed ZIP64 locator")
    record_offset = int.from_bytes(locator[8:16], "little")
    if locator[4:8] != b"\0\0\0\0" or locator[16:20] != b"\x01\0\0\0":
        _skip_zip_listing(path, "multi-disk ZIP64 metadata")
    source.seek(0, os.SEEK_END)
    archive_size = source.tell()
    if record_offset < 0 or record_offset + _ZIP64_EOCD_SIZE > archive_size:
        _skip_zip_listing(path, "ZIP64 end-of-central-directory is out of bounds")
    source.seek(record_offset)
    record = source.read(_ZIP64_EOCD_SIZE)
    if (
        len(record) != _ZIP64_EOCD_SIZE
        or record[:4] != _ZIP64_EOCD_SIGNATURE
        or int.from_bytes(record[4:12], "little") < 44
    ):
        _skip_zip_listing(path, "malformed ZIP64 end-of-central-directory")
    if record[16:24] != b"\0" * 8 or record[24:32] != record[32:40]:
        _skip_zip_listing(path, "multi-disk or inconsistent ZIP64 entry metadata")
    entries = int.from_bytes(record[32:40], "little")
    directory_size = int.from_bytes(record[40:48], "little")
    directory_offset = int.from_bytes(record[48:56], "little")
    directory_start = record_offset - directory_size - directory_offset
    return entries, directory_size, directory_offset, directory_start


def _skip_zip_listing(path: Path, reason: str) -> None:
    """Warn and stop member listing while preserving archive cataloging."""
    warnings.warn(
        "Skipping ZIP member listing "
        f"({reason}): {BaseParser._safe_text(str(path))}",
        RuntimeWarning,
        stacklevel=3,
    )
    raise zipfile.BadZipFile(reason)
