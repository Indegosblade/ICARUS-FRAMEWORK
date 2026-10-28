"""Build leases protect checkpoint identity and atomic replacement across processes."""

import argparse
import os
import subprocess
import sys
from contextlib import contextmanager

import pytest

from icarus.__main__ import cmd_build
from icarus.core.build_lock import BuildInProgressError, output_lease
from icarus.core.pipeline import Pipeline


@contextmanager
def _other_process_lease(output):
    worker = """
import os, sys
from pathlib import Path
from icarus.core.build_lock import output_lease
with output_lease(Path(sys.argv[1])):
    print('held', flush=True)
    command = sys.stdin.readline().strip()
    if command == 'crash':
        os._exit(29)
"""
    child = subprocess.Popen(
        [sys.executable, "-u", "-c", worker, str(output)],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )
    try:
        assert child.stdout.readline().strip() == "held"
        yield child
    finally:
        if child.poll() is None:
            try:
                child.communicate("release\n", timeout=5)
            except subprocess.TimeoutExpired:
                child.kill()
                child.communicate(timeout=5)
        else:
            child.communicate(timeout=5)


def _args(source, output, fresh):
    return argparse.Namespace(
        source=str(source), output=str(output), parser="windows",
        skip_hygeia=True, resolve=False, fresh=fresh,
    )


@pytest.mark.parametrize("fresh", [False, True])
def test_cli_conflict_does_not_write_output_or_checkpoint(tmp_path, fresh):
    source = tmp_path / "source"
    source.mkdir()
    (source / "file.txt").write_text("data")
    output = tmp_path / "out.db"
    if fresh:
        output.write_bytes(b"original output")
    with _other_process_lease(output):
        with pytest.raises(BuildInProgressError, match="Another ICARUS build"):
            cmd_build(_args(source, output, fresh))
        assert not (tmp_path / ".out_checkpoint.db").exists()
        if fresh:
            assert output.read_bytes() == b"original output"
        else:
            assert not output.exists()
    cmd_build(_args(source, output, fresh))
    assert output.read_bytes().startswith(b"SQLite format 3")


def test_direct_pipeline_conflict_precedes_any_database_mutation(tmp_path):
    output = tmp_path / "out.db"
    with _other_process_lease(output):
        with pytest.raises(BuildInProgressError):
            Pipeline(tmp_path, output, parser_name="test").run()
        assert not output.exists()
        assert not (tmp_path / ".out_checkpoint.db").exists()


def test_process_death_releases_lock_without_deleting_sidecar(tmp_path):
    output = tmp_path / "out.db"
    sidecar = tmp_path / ".out.db.icarus.lock"
    with _other_process_lease(output) as child:
        before = sidecar.stat().st_ino
        child.stdin.write("crash\n")
        child.stdin.flush()
        assert child.wait(timeout=5) == 29
    with output_lease(output):
        assert sidecar.stat().st_ino == before
    assert sidecar.read_bytes() == b"\0"


def test_nested_lease_preserves_original_until_outer_scope_exits(tmp_path):
    output = tmp_path / "out.db"
    with output_lease(output):
        with output_lease(output):
            pass
        with _other_process_lease(tmp_path / "different.db"):
            # A separate path is independent; the same path still conflicts.
            worker = (
                "from pathlib import Path; "
                "from icarus.core.build_lock import output_lease; "
                f"lease=output_lease(Path({str(output)!r})); lease.__enter__()"
            )
            result = subprocess.run(
                [sys.executable, "-c", worker], capture_output=True, text=True, timeout=5,
            )
            assert result.returncode != 0
            assert "BuildInProgressError" in result.stderr
    with output_lease(output):
        pass


def test_linked_output_is_refused_without_writing_target(tmp_path):
    original = tmp_path / "original.db"
    original.write_bytes(b"unchanged")
    alias = tmp_path / "alias.db"
    try:
        os.link(original, alias)
    except OSError:
        pytest.skip("hard links unavailable")
    with pytest.raises(ValueError, match="multiple hard links"):
        with output_lease(alias):
            pass
    assert original.read_bytes() == b"unchanged"
