"""Bounded, shared evidence used by parser auto-detection."""

import os
import stat
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from icarus.parsers.base import BaseParser

# Auto-detection is a sample, not extraction.  These bounds cap tree entries
# and source bytes across the entire parser contest; an explicit --parser does
# not use this path.
DETECTION_ENTRY_BUDGET = 5_000
DETECTION_BYTE_BUDGET = 4 * 1024 * 1024


class DetectionBudgetExceeded(RuntimeError):
    """The source sample was incomplete, so auto-detection must not guess."""


@dataclass(frozen=True)
class DetectionEntry:
    """One sampled file, represented without opening its content."""

    path: Path
    relative: str
    size: int
    regular: bool


@dataclass
class DetectionEvidence:
    """A single, read-only-ish source sample shared by built-in detectors."""

    source: Path
    files: tuple[DetectionEntry, ...]
    directories: frozenset[str]
    entry_budget_exhausted: bool = False
    byte_budget_exhausted: bool = False
    _bytes_remaining: int = DETECTION_BYTE_BUDGET
    _samples: dict[str, bytes] = field(default_factory=dict)

    @property
    def exhausted(self) -> bool:
        return self.entry_budget_exhausted or self.byte_budget_exhausted

    @classmethod
    def collect(cls, source: Path) -> "DetectionEvidence":
        """Walk at most the global entry budget once, without following links."""
        if not source.is_dir():
            return cls(source, (), frozenset())
        files: list[DetectionEntry] = []
        directories = {""}
        entries_seen = 0
        exhausted = False

        def onerror(_error: OSError) -> None:
            # A permission-denied branch contributes no evidence and does not
            # stop inspection of the accessible portion of the source.
            return None

        for dirpath, dirs, filenames in os.walk(source, topdown=True, onerror=onerror):
            current = Path(dirpath)
            try:
                relative_dir = current.relative_to(source)
            except ValueError:
                dirs[:] = []
                continue
            safe_dirs = []
            for dirname in sorted(dirs):
                child = current / dirname
                try:
                    if stat.S_ISLNK(child.lstat().st_mode):
                        continue
                except OSError:
                    continue
                if entries_seen >= DETECTION_ENTRY_BUDGET:
                    exhausted = True
                    break
                entries_seen += 1
                child_relative = relative_dir / dirname
                directories.add(child_relative.as_posix())
                safe_dirs.append(dirname)
            dirs[:] = safe_dirs
            if exhausted:
                dirs[:] = []

            for filename in sorted(filenames):
                if entries_seen >= DETECTION_ENTRY_BUDGET:
                    exhausted = True
                    dirs[:] = []
                    break
                path = current / filename
                try:
                    st = path.lstat()
                except OSError:
                    continue
                entries_seen += 1
                files.append(
                    DetectionEntry(
                        path=path,
                        relative=(relative_dir / filename).as_posix(),
                        size=st.st_size,
                        regular=stat.S_ISREG(st.st_mode),
                    )
                )
            if exhausted:
                break
            if entries_seen >= DETECTION_ENTRY_BUDGET:
                exhausted = True
                dirs[:] = []
                break
        return cls(
            source,
            tuple(files),
            frozenset(directories),
            entry_budget_exhausted=exhausted,
            _bytes_remaining=DETECTION_BYTE_BUDGET,
        )

    def has_directory(self, relative: str) -> bool:
        return relative.strip("/") in self.directories

    def has_file(self, relative: str) -> bool:
        return any(entry.relative == relative.strip("/") for entry in self.files)

    def read_file(self, entry: DetectionEntry) -> Optional[bytes]:
        """Read one sampled regular file within the shared source-byte budget."""
        if not entry.regular:
            return None
        cached = self._samples.get(entry.relative)
        if cached is not None:
            return cached
        if entry.size > self._bytes_remaining:
            self.byte_budget_exhausted = True
            return None
        try:
            with BaseParser._open_regular(entry.path) as handle:
                data = handle.read(entry.size + 1)
        except (OSError, PermissionError):
            return None
        if len(data) > entry.size:
            return None
        self._bytes_remaining -= len(data)
        self._samples[entry.relative] = data
        return data
