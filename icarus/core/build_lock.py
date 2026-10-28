"""Process-owned output leases for pipeline builds and atomic replacement.

The sidecar inode persists: unlinking it on unlock would let another process
lock a different inode at the same pathname while an earlier waiter still held
the original. The operating system releases the lock when its handle closes or
the process exits; no PID files or stale-lock deletion are needed.
"""

import errno
import os
import stat
import sys
import threading
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

_active = threading.local()


class BuildInProgressError(ValueError):
    """Another process or thread owns the requested output build."""


def _is_reparse(entry_stat: os.stat_result) -> bool:
    return bool(
        getattr(entry_stat, "st_file_attributes", 0)
        & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    )


@contextmanager
def output_lease(output: Path) -> Iterator[None]:
    """Fail fast on an overlapping build; nest safely in the same thread.

    CLI builds lease their final destination across checking, building and
    replacement. Pipeline.run leases its output too for direct API callers.
    Parent directory aliases are normalized; linked output files are refused
    because pathname leases cannot serialize writes through arbitrary aliases.
    """
    output = Path(output)
    canonical = output.parent.resolve() / output.name
    try:
        entry_stat = canonical.lstat()
    except FileNotFoundError:
        pass
    else:
        if not stat.S_ISREG(entry_stat.st_mode) or _is_reparse(entry_stat):
            raise ValueError("Build output must be a regular file, not a link or special file")
        if entry_stat.st_nlink > 1:
            raise ValueError("Build output has multiple hard links; choose a dedicated output path")

    key = os.path.normcase(str(canonical))
    if getattr(_active, "pid", None) != os.getpid():
        _active.paths = set()
        _active.pid = os.getpid()
    if key in _active.paths:
        yield
        return

    lock_path = canonical.parent / f".{canonical.name}.icarus.lock"
    try:
        lock_stat = lock_path.lstat()
    except FileNotFoundError:
        pass
    else:
        if not stat.S_ISREG(lock_stat.st_mode) or _is_reparse(lock_stat):
            raise ValueError("Build lease sidecar must be a regular file")
        if lock_stat.st_nlink > 1:
            raise ValueError("Build lease sidecar must not have multiple hard links")
    flags = (
        os.O_CREAT | os.O_RDWR
        | getattr(os, "O_BINARY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOINHERIT", 0)
    )
    fd = os.open(lock_path, flags, 0o600)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise ValueError("Build lease sidecar must be a regular file")
        # Windows byte-range locks need a byte to lock. Write no source path,
        # process metadata or other potentially sensitive information.
        if os.fstat(fd).st_size == 0:
            os.write(fd, b"\0")
        os.lseek(fd, 0, os.SEEK_SET)
        try:
            if sys.platform == "win32":
                import msvcrt
                msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as error:
            if error.errno in (errno.EACCES, errno.EAGAIN, errno.EDEADLK):
                raise BuildInProgressError(
                    "Another ICARUS build owns this output; wait for it to finish "
                    "or choose a different output path"
                ) from None
            raise
        _active.paths.add(key)
        try:
            yield
        finally:
            _active.paths.remove(key)
    finally:
        os.close(fd)  # Closing the handle releases the OS lock, including on exceptions.
