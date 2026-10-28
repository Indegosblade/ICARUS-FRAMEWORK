"""Ingest recovery commits the input cursor with rows and provenance (#82)."""

import os
import sqlite3
import subprocess
import sys
from contextlib import contextmanager
from itertools import chain
from pathlib import Path

import pytest

from icarus.core.pipeline import create_default_pipeline
from icarus.core.schema import initialize_database, open_db
from icarus.parsers import progress as progress_module
from icarus.parsers.linux import LinuxParser
from icarus.parsers.progress import IngestProgress
from icarus.parsers.windows import WindowsParser


@pytest.mark.parametrize("parser_type", [LinuxParser, WindowsParser])
def test_resume_skips_committed_files_and_rolls_back_partial_input(
    tmp_path, monkeypatch, parser_type,
):
    source = tmp_path / "source"
    source.mkdir()
    for name in ("a.txt", "b.txt", "c.txt", "d.txt"):
        (source / name).write_text(name)
    output = tmp_path / "out.db"
    initialize_database(output)
    monkeypatch.setattr(progress_module, "BATCH_COMMIT_INTERVAL", 2)
    original_hash = parser_type._safe_hash

    def crash_during_third_file(path, size):
        if path.name == "c.txt":
            raise RuntimeError("injected crash")
        return original_hash(path, size)

    monkeypatch.setattr(parser_type, "_safe_hash", staticmethod(crash_during_third_file))
    with pytest.raises(RuntimeError, match="injected crash"):
        parser_type().extract_entities(source, output)
    with sqlite3.connect(output) as conn:
        assert conn.execute("SELECT path FROM files ORDER BY path").fetchall() == [
            ("/a.txt",), ("/b.txt",),
        ]
        assert conn.execute(
            "SELECT last_filename FROM _icarus_ingest_frontier"
        ).fetchone() == (b"b.txt",)

    seen = []

    def record_hash(path, size):
        seen.append(path.name)
        return original_hash(path, size)

    monkeypatch.setattr(parser_type, "_safe_hash", staticmethod(record_hash))
    stats = parser_type().extract_entities(source, output)
    assert seen == ["c.txt", "d.txt"]
    assert stats["files"] == 4
    with sqlite3.connect(output) as conn:
        assert conn.execute("SELECT COUNT(*) FROM files").fetchone()[0] == 4
        assert not conn.execute(
            "SELECT name FROM sqlite_master WHERE name LIKE '_icarus_ingest_%'"
        ).fetchall()


def test_hard_exit_resume_preserves_provenance_and_skips_completed_directories(
    tmp_path, monkeypatch,
):
    """A process exit bypasses finally blocks, unlike an ordinary exception."""
    source = tmp_path / "source"
    for directory, names in (("a", ("a.txt", "b.txt")), ("z", ("c.txt", "d.txt"))):
        folder = source / directory
        folder.mkdir(parents=True)
        for name in names:
            (folder / name).write_text(name)
    output = tmp_path / "out.db"
    worker = """
import os, sys
from pathlib import Path
from icarus.parsers import progress
from icarus.parsers.windows import WindowsParser
from icarus.core.pipeline import create_default_pipeline
progress.BATCH_COMMIT_INTERVAL = 1
original = WindowsParser._safe_hash
def die(path, size):
    if path.name == 'c.txt':
        os._exit(73)
    return original(path, size)
WindowsParser._safe_hash = staticmethod(die)
create_default_pipeline(Path(sys.argv[1]), Path(sys.argv[2]), 'windows', skip_hygeia=True).run()
"""
    crashed = subprocess.run(
        [sys.executable, "-c", worker, str(source), str(output)],
        capture_output=True, text=True,
    )
    assert crashed.returncode == 73, crashed.stderr
    with sqlite3.connect(output) as conn:
        assert conn.execute(
            "SELECT path, source_version_id, observed_time FROM files ORDER BY path"
        ).fetchall() == [
            ("/a/a.txt", 1, conn.execute("SELECT started_at FROM versions").fetchone()[0]),
            ("/a/b.txt", 1, conn.execute("SELECT started_at FROM versions").fetchone()[0]),
        ]

    original_scandir = os.scandir
    scanned = []

    def record_scandir(path):
        scanned.append(Path(path))
        return original_scandir(path)

    monkeypatch.setattr(progress_module.os, "scandir", record_scandir)
    pipeline = create_default_pipeline(source, output, "windows", skip_hygeia=True)
    context = pipeline.run()
    assert source / "a" not in scanned
    assert context.stats["ingest"]["files"] == 4
    with sqlite3.connect(output) as conn:
        assert conn.execute("SELECT COUNT(*) FROM versions").fetchone()[0] == 1
        assert conn.execute("SELECT COUNT(*) FROM files").fetchone()[0] == 4
        assert conn.execute(
            "SELECT COUNT(*) FROM files WHERE source_version_id != 1 OR observed_time IS NULL"
        ).fetchone()[0] == 0
        assert conn.execute("PRAGMA foreign_key_check").fetchall() == []


def test_progress_rejects_another_source_and_run(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    (source / "a.txt").write_text("a")
    output = tmp_path / "out.db"
    initialize_database(output)
    conn = open_db(output)
    try:
        with pytest.raises(RuntimeError):
            with IngestProgress(conn, source, "windows", {"files": 0}):
                raise RuntimeError("leave durable initial state")
        other = tmp_path / "other"
        other.mkdir()
        with pytest.raises(ValueError, match="different source/parser/run"):
            with IngestProgress(conn, other, "windows", {"files": 0}):
                pass
        conn.execute(
            "INSERT INTO versions (run_id, parser_name, started_at) "
            "VALUES ('new', 'windows', 'now')"
        )
        conn.commit()
        with pytest.raises(ValueError, match="different source/parser/run"):
            with IngestProgress(conn, source, "windows", {"files": 0}):
                pass
    finally:
        conn.close()


def test_uncommitted_entity_and_cursor_roll_back_together(tmp_path, monkeypatch):
    source = tmp_path / "source"
    source.mkdir()
    for name in ("a", "b", "c"):
        (source / name).write_text(name)
    output = tmp_path / "out.db"
    initialize_database(output)
    monkeypatch.setattr(progress_module, "BATCH_COMMIT_INTERVAL", 2)
    conn = open_db(output)
    try:
        with pytest.raises(RuntimeError):
            with IngestProgress(conn, source, "test", {"files": 0}) as progress:
                for _, filenames in progress.walk():
                    for name in filenames:
                        conn.execute("INSERT INTO files (path, filename) VALUES (?, ?)",
                                     ("/" + name, name))
                        progress.stats["files"] += 1
                        if name == "c":
                            raise RuntimeError("after insert, before cursor")
        assert conn.execute("SELECT filename FROM files ORDER BY path").fetchall() == [
            ("a",), ("b",),
        ]
        assert conn.execute(
            "SELECT last_filename FROM _icarus_ingest_frontier"
        ).fetchone() == (b"b",)
        stats = {"files": 0}
        with IngestProgress(conn, source, "test", stats) as progress:
            for _, filenames in progress.walk():
                for name in filenames:
                    assert name == "c"
                    conn.execute("INSERT INTO files (path, filename) VALUES (?, ?)",
                                 ("/" + name, name))
                    stats["files"] += 1
        assert stats["files"] == 3
        assert conn.execute("SELECT COUNT(*) FROM files").fetchone()[0] == 3
    finally:
        conn.close()


@pytest.mark.parametrize("parser_type", [LinuxParser, WindowsParser])
def test_relative_source_is_supported(tmp_path, monkeypatch, parser_type):
    source = tmp_path / "source"
    source.mkdir()
    (source / "file.txt").write_text("data")
    output = tmp_path / "out.db"
    initialize_database(output)
    monkeypatch.chdir(tmp_path)
    assert parser_type().extract_entities(Path("source"), output)["files"] == 1


def test_abandoned_walk_cannot_succeed(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    (source / "file.txt").write_text("data")
    output = tmp_path / "out.db"
    initialize_database(output)
    conn = open_db(output)
    try:
        with pytest.raises(RuntimeError, match="not fully consumed"):
            with IngestProgress(conn, source, "test", {"files": 0}) as progress:
                for _, filenames in progress.walk():
                    # Abandoning a directory must not delete its durable cursor.
                    pass
        assert conn.execute("SELECT directory FROM _icarus_ingest_frontier").fetchall() == [
            (b"",),
        ]
    finally:
        conn.close()


def test_unreadable_entry_does_not_discard_later_siblings(tmp_path, monkeypatch):
    source = tmp_path / "source"
    source.mkdir()
    (source / "readable.txt").write_text("keep this sibling")
    output = tmp_path / "out.db"
    initialize_database(output)
    original_scandir = os.scandir

    class UnreadableEntry:
        name = "unreadable"

        def is_dir(self, *, follow_symlinks=True):
            raise OSError("injected per-entry metadata failure")

    @contextmanager
    def failing_entry_first(path):
        with original_scandir(path) as entries:
            yield chain([UnreadableEntry()], entries)

    monkeypatch.setattr(progress_module.os, "scandir", failing_entry_first)
    with pytest.warns(RuntimeWarning, match="unreadable directory entry"):
        stats = WindowsParser().extract_entities(source, output)
    assert stats["files"] == 1
    conn = sqlite3.connect(output)
    try:
        assert conn.execute("SELECT filename FROM files").fetchall() == [("readable.txt",)]
    finally:
        conn.close()


@pytest.mark.skipif(sys.platform != "win32", reason="Windows directory junction boundary")
def test_directory_junction_is_not_followed(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "private.txt").write_text("must not be read")
    link = source / "escape"
    proc = subprocess.run(
        ["cmd", "/c", "mklink", "/J", str(link), str(outside)],
        capture_output=True, text=True,
    )
    if proc.returncode:
        pytest.skip(f"junction creation unavailable: {proc.stderr}")
    try:
        output = tmp_path / "out.db"
        initialize_database(output)
        stats = WindowsParser().extract_entities(source, output)
        assert stats["files"] == 0
        conn = sqlite3.connect(output)
        try:
            assert conn.execute("SELECT COUNT(*) FROM files").fetchone() == (0,)
        finally:
            conn.close()
    finally:
        os.rmdir(link)  # Remove the junction itself; never traverse its target.
