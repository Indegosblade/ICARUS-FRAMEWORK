"""Hostile filesystem regression coverage for #43 and #47."""

import io
import os
import plistlib
import sqlite3
import sys
import tarfile
import zipfile
from pathlib import Path

import pytest

from icarus.core.schema import initialize_database
from icarus.parsers.cloud.aws.cloudtrail import CloudTrailParser
from icarus.parsers.generic.archive_parser import ArchiveParser, _list_archive
from icarus.parsers.generic.binary_entropy_parser import BinaryEntropyParser
from icarus.parsers.generic.json_parser import JsonParser
from icarus.parsers.generic.sqlite_parser import SqliteParser
from icarus.parsers.linux import LinuxParser
from icarus.parsers.macos import MacosParser


def _make_symlink(link: Path, target: Path) -> None:
    try:
        link.symlink_to(target)
    except (NotImplementedError, OSError) as exc:
        pytest.skip(f"symlinks unavailable: {exc}")


def _norm_target(value):
    """Windows ``os.readlink`` returns absolute targets with the ``\\\\?\\``
    extended-length prefix; strip it so target comparisons are cross-platform."""
    if value and value.startswith("\\\\?\\"):
        return value[4:]
    return value


def _file_row(db: Path):
    conn = sqlite3.connect(str(db))
    try:
        return conn.execute(
            "SELECT path,filename,size,file_type,is_symlink,symlink_target,sha256 "
            "FROM files"
        ).fetchone()
    finally:
        conn.close()


def test_linux_service_symlink_is_cataloged_without_reading_target(tmp_path):
    source = tmp_path / "rootfs"
    units = source / "lib" / "systemd" / "system"
    units.mkdir(parents=True)
    outside = tmp_path / "secret_external.service"
    outside.write_text(
        "[Service]\nExecStart=/OUTSIDE/secret_binary --marker OUTSIDE-ROOT-CANARY\n"
    )
    link = units / "evil.service"
    _make_symlink(link, outside)

    db = tmp_path / "linux.db"
    initialize_database(db)
    LinuxParser().extract_entities(source, db)

    row = _file_row(db)
    assert row[:5] == (
        "/lib/systemd/system/evil.service",
        "evil.service",
        link.lstat().st_size,
        "symlink",
        1,
    )
    assert _norm_target(row[5]) == str(outside)
    assert row[6] is None
    conn = sqlite3.connect(str(db))
    assert conn.execute("SELECT COUNT(*) FROM daemons").fetchone()[0] == 0
    assert "OUTSIDE-ROOT-CANARY" not in "\n".join(conn.iterdump())
    conn.close()


def test_macos_plist_symlink_is_cataloged_without_parsing_target(tmp_path):
    source = tmp_path / "rootfs"
    launchd = source / "System" / "Library" / "LaunchDaemons"
    launchd.mkdir(parents=True)
    outside = tmp_path / "secret_external.plist"
    outside.write_bytes(plistlib.dumps({
        "Label": "com.attacker.EXFILTRATED-FROM-OUTSIDE-ROOT",
        "Program": "/OUTSIDE/root/secret_daemon",
        "MachServices": {"com.attacker.secret": True},
    }))
    link = launchd / "evil.plist"
    _make_symlink(link, outside)

    db = tmp_path / "macos.db"
    initialize_database(db)
    MacosParser().extract_entities(source, db)

    row = _file_row(db)
    assert row[2:5] == (link.lstat().st_size, "symlink", 1)
    assert _norm_target(row[5]) == str(outside)
    conn = sqlite3.connect(str(db))
    assert conn.execute("SELECT COUNT(*) FROM daemons").fetchone()[0] == 0
    assert conn.execute("SELECT COUNT(*) FROM mach_services").fetchone()[0] == 0
    assert "EXFILTRATED-FROM-OUTSIDE-ROOT" not in "\n".join(conn.iterdump())
    conn.close()


def test_macos_symlinked_launchd_directory_is_not_traversed(tmp_path):
    source = tmp_path / "rootfs"
    library = source / "System" / "Library"
    library.mkdir(parents=True)
    outside = tmp_path / "outside-launchd"
    outside.mkdir()
    (outside / "evil.plist").write_bytes(plistlib.dumps({
        "Label": "com.attacker.outside-directory",
        "Program": "/OUTSIDE/daemon",
    }))
    _make_symlink(library / "LaunchDaemons", outside)
    db = tmp_path / "macos-directory.db"
    initialize_database(db)

    MacosParser().extract_entities(source, db)

    conn = sqlite3.connect(str(db))
    assert conn.execute("SELECT COUNT(*) FROM files").fetchone()[0] == 0
    assert conn.execute("SELECT COUNT(*) FROM daemons").fetchone()[0] == 0
    conn.close()


@pytest.mark.parametrize(
    ("parser", "filename", "target_factory"),
    [
        (ArchiveParser(), "outside.tar.gz", lambda path: path.write_bytes(b"not a tar")),
        (
            SqliteParser(),
            "outside.sqlite",
            lambda path: sqlite3.connect(str(path)).close(),
        ),
        (BinaryEntropyParser(), "outside.bin", lambda path: path.write_bytes(b"SECRET")),
    ],
)
def test_generic_parsers_never_dereference_symlink_targets(
    tmp_path, parser, filename, target_factory
):
    source = tmp_path / "source"
    source.mkdir()
    outside = tmp_path / filename
    target_factory(outside)
    link = source / filename
    _make_symlink(link, outside)
    db = tmp_path / f"{parser.name.replace('/', '-')}.db"
    initialize_database(db)

    parser.extract_entities(source, db)

    row = _file_row(db)
    assert row[2:5] == (link.lstat().st_size, "symlink", 1)
    assert _norm_target(row[5]) == str(outside)
    assert row[6] is None
    conn = sqlite3.connect(str(db))
    assert conn.execute("SELECT COUNT(*) FROM observations").fetchone()[0] == 0
    conn.close()


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="FIFO unavailable on this OS")
def test_fifo_is_skipped_without_opening_or_hanging(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    os.mkfifo(source / "hostile.bin")
    (source / "regular.bin").write_bytes(b"safe")
    db = tmp_path / "fifo.db"
    initialize_database(db)

    with pytest.warns(RuntimeWarning, match="non-regular input"):
        stats = BinaryEntropyParser().extract_entities(source, db)

    assert stats["files"] == 1
    conn = sqlite3.connect(str(db))
    assert conn.execute("SELECT filename FROM files").fetchall() == [("regular.bin",)]
    conn.close()


@pytest.mark.skipif(
    os.name == "nt" or sys.platform == "darwin",
    reason="surrogate filenames require a filesystem that accepts non-UTF-8 byte paths",
)
def test_non_utf8_filename_is_escaped_instead_of_aborting_walk(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    raw_path = os.fsencode(source) + b"/data_\xff.json"
    fd = os.open(raw_path, os.O_WRONLY | os.O_CREAT, 0o600)
    try:
        os.write(fd, b'{"safe": true}')
    finally:
        os.close(fd)
    db = tmp_path / "surrogate.db"
    initialize_database(db)

    stats = JsonParser().extract_entities(source, db)

    assert stats["files"] == 1
    conn = sqlite3.connect(str(db))
    filename, path = conn.execute("SELECT filename,path FROM files").fetchone()
    conn.close()
    assert filename == r"data_\udcff.json"
    assert path == r"/data_\udcff.json"


def test_deep_cloudtrail_json_is_rejected_without_recursion_crash(tmp_path):
    source = tmp_path / "cloudtrail"
    source.mkdir()
    (source / "deep.json").write_text("[" * 200_000 + "]" * 200_000)
    parser = CloudTrailParser()

    with pytest.warns(RuntimeWarning, match="depth/memory limits"):
        assert parser.identify(source) is False
    db = tmp_path / "cloudtrail.db"
    initialize_database(db)
    with pytest.warns(RuntimeWarning, match="depth/memory limits"):
        assert parser.extract_entities(source, db) == {
            "files": 0,
            "daemons": 0,
            "observations": 0,
        }


def test_compressed_tar_listing_stops_at_decompressed_budget(tmp_path, monkeypatch):
    import icarus.parsers.generic.archive_parser as archive_module

    monkeypatch.setattr(archive_module, "MAX_DECOMPRESSED_TAR_BYTES", 1_000_000)
    archive = tmp_path / "bomb.tar.gz"
    payload = b"A" * 2_000_000
    with tarfile.open(archive, "w:gz") as tf:
        info = tarfile.TarInfo("large.txt")
        info.size = len(payload)
        tf.addfile(info, io.BytesIO(payload))

    with pytest.warns(RuntimeWarning, match="decompressed data exceeds"):
        assert _list_archive(archive) == []


def test_zip_member_listing_stops_before_zipfile_for_entry_budget(tmp_path, monkeypatch):
    """#89: a directory budget is checked before ZipFile builds ZipInfo rows."""
    import icarus.parsers.generic.archive_parser as archive_module

    archive = tmp_path / "many.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        for index in range(20):
            zf.writestr(f"member-{index}", b"")
    monkeypatch.setattr(archive_module, "MAX_ZIP_ENTRIES", 10)

    def should_not_open(*_args, **_kwargs):
        raise AssertionError("ZipFile must not materialize an over-budget directory")

    monkeypatch.setattr(archive_module.zipfile, "ZipFile", should_not_open)
    with pytest.warns(RuntimeWarning, match="entry count exceeds 10"):
        assert _list_archive(archive) == []


def test_zip_member_listing_accepts_budget_boundaries(tmp_path, monkeypatch):
    import icarus.parsers.generic.archive_parser as archive_module

    archive = tmp_path / "boundary.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("one.txt", b"one")
    raw = archive.read_bytes()
    eocd = raw.rfind(b"PK\x05\x06")
    directory_size = int.from_bytes(raw[eocd + 12:eocd + 16], "little")
    monkeypatch.setattr(archive_module, "MAX_ZIP_ARCHIVE_BYTES", len(raw))
    monkeypatch.setattr(archive_module, "MAX_ZIP_CENTRAL_DIRECTORY_BYTES", directory_size)
    monkeypatch.setattr(archive_module, "MAX_ZIP_ENTRIES", 1)

    assert _list_archive(archive) == ["one.txt"]


def test_zip64_member_listing_uses_valid_zip64_directory_metadata(tmp_path, monkeypatch):
    """A valid ZIP64 directory remains listable when it fits every budget."""
    archive = tmp_path / "zip64.zip"
    monkeypatch.setattr(zipfile, "ZIP64_LIMIT", 1)
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("one.txt", b"one")
    raw = bytearray(archive.read_bytes())
    eocd = raw.rfind(b"PK\x05\x06")
    # Force ZipFile to read the valid ZIP64 record written above, rather than
    # the small-file copies retained in its conventional EOCD.
    raw[eocd + 8:eocd + 20] = b"\xff" * 12
    archive.write_bytes(raw)

    assert _list_archive(archive) == ["one.txt"]


def test_zip_forged_eocd_and_zip64_metadata_skip_before_zipfile(tmp_path, monkeypatch):
    """Malformed and ZIP64 declarations fail closed without archive parsing."""
    import icarus.parsers.generic.archive_parser as archive_module

    def should_not_open(*_args, **_kwargs):
        raise AssertionError("ZipFile must not open forged metadata")

    monkeypatch.setattr(archive_module.zipfile, "ZipFile", should_not_open)
    forged = tmp_path / "forged.zip"
    # EOCD says ZIP64 is required, but provides no preceding ZIP64 locator.
    forged.write_bytes(
        b"PK\x05\x06" + b"\0" * 4 + b"\xff\xff" * 2 + b"\xff" * 8 + b"\0\0"
    )
    with pytest.warns(RuntimeWarning, match="ZIP64 locator"):
        assert _list_archive(forged) == []

    zip64 = tmp_path / "zip64-too-many.zip"
    zip64_eocd = (
        b"PK\x06\x06" + (44).to_bytes(8, "little") + b"-\0-\0"
        + b"\0" * 8 + (10_001).to_bytes(8, "little") * 2
        + b"\0" * 16
    )
    locator = b"PK\x06\x07" + b"\0" * 4 + b"\0" * 8 + b"\x01\0\0\0"
    eocd = b"PK\x05\x06" + b"\0" * 4 + b"\xff" * 12 + b"\0\0"
    zip64.write_bytes(zip64_eocd + locator + eocd)
    with pytest.warns(RuntimeWarning, match="entry count exceeds"):
        assert _list_archive(zip64) == []
