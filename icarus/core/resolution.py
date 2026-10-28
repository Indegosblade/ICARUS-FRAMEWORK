"""Atomic publication of cross-source resolution snapshots.

Inputs must be frozen, checkpointed databases. Their trust markers govern input
admission only; the new database is independently sanitized and verified after
all atom, membership, source-path and audit writes have finished.
"""

import math
import os
import sqlite3
import tempfile
import uuid
import warnings
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from icarus.core.atomize import ATOM_PROJECTIONS, atomize_db
from icarus.core.build_lock import output_lease
from icarus.core.pipeline import OutputExistsError
from icarus.core.resolver import EntityResolver
from icarus.core.schema import initialize_database, open_db
from icarus.integrations import hygeia


def _admit_sources(sources: list[Path], output: Path, allow_unverified: bool) -> None:
    if not sources:
        raise ValueError("Resolution requires at least one source database")
    for index, source in enumerate(sources):
        if source == output or (output.exists() and source.exists() and source.samefile(output)):
            raise ValueError("Resolution output must not alias an input source database")
        if not source.is_file():
            raise FileNotFoundError(f"Source database does not exist: {source}")
        if any(source.samefile(previous) for previous in sources[:index]):
            raise ValueError("Resolution sources must be distinct database snapshots")
        wal = Path(f"{source}-wal")
        if wal.exists() and wal.stat().st_size:
            raise ValueError(
                "Refusing resolution from a database with a nonempty WAL; "
                "checkpoint the source database and keep it immutable during resolution"
            )
        status = hygeia.sanitization_status(source, immutable=True)
        if not allow_unverified and not hygeia.sanitization_allows_default_consumer(status):
            raise ValueError(
                "Resolution source is not sanitization-verified; rebuild it or pass "
                "--allow-unverified to recover it. Output sanitization remains mandatory."
            )


def _populate(
    temporary: Path, sources: list[Path], entity_types: list[str],
    threshold: float, atomize_only: bool,
) -> dict[str, Any]:
    initialize_database(temporary)
    summaries = []
    total = 0
    conn = open_db(temporary)
    try:
        for source in sources:
            source_conn: Optional[sqlite3.Connection] = None
            try:
                source_conn = open_db(source, readonly=True, immutable=True)
                started = datetime.now(timezone.utc).isoformat()
                version_id = conn.execute(
                    "INSERT INTO versions (run_id, parser_name, source_path, started_at) "
                    "VALUES (?, 'resolve', ?, ?)", (str(uuid.uuid4()), str(source), started),
                ).lastrowid
                assert version_id is not None
                counts = atomize_db(source_conn, conn, version_id, entity_types)
                count = sum(counts.values())
                conn.execute(
                    "UPDATE versions SET completed_at = ?, entity_count = ? WHERE id = ?",
                    (datetime.now(timezone.utc).isoformat(), count, version_id),
                )
                conn.commit()
            except sqlite3.Error as error:
                raise ValueError(
                    f"Could not resolve source database {source.name}: {error}"
                ) from error
            finally:
                if source_conn is not None:
                    source_conn.close()
            total += count
            summaries.append({"name": source.name, "counts": counts, "atoms": count})
    finally:
        conn.close()

    resolutions = {}
    canonical_count = cross_source_count = 0
    if not atomize_only:
        with EntityResolver(str(temporary), experimental=True) as resolver:
            for entity_type in entity_types:
                resolutions[entity_type] = resolver.resolve_scored(
                    entity_type, threshold=threshold,
                )
            canonical_count = resolver.conn.execute(
                "SELECT COUNT(DISTINCT bag_id) FROM bag_atoms"
            ).fetchone()[0]
            cross_source_count = resolver.conn.execute(
                "SELECT COUNT(*) FROM ("
                "SELECT bag_id FROM bag_atoms ba JOIN atoms a ON a.id = ba.atom_id "
                "GROUP BY bag_id HAVING COUNT(DISTINCT a.source_version_id) >= 2)"
            ).fetchone()[0]
    return {
        "sources": summaries, "total_atoms": total, "resolutions": resolutions,
        "canonical_entities": canonical_count, "cross_source_entities": cross_source_count,
    }


def _checkpoint(temporary: Path) -> None:
    conn = open_db(temporary)
    try:
        if conn.execute("PRAGMA foreign_key_check").fetchone() is not None:
            raise ValueError("Resolution output failed foreign-key verification")
        busy, log, checkpointed = conn.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()
        if busy or log != checkpointed:
            raise ValueError("Resolution output WAL could not be checkpointed completely")
    finally:
        conn.close()
    for suffix in ("-wal", "-shm"):
        Path(f"{temporary}{suffix}").unlink(missing_ok=True)


def resolve_sources(
    sources: list[Path], output: Path, *, entity_types: Optional[list[str]] = None,
    threshold: float = 0.85, atomize_only: bool = False, allow_unverified: bool = False,
) -> dict[str, Any]:
    """Create one new resolution snapshot, publishing only on complete success.

    Existing output is refused. `allow_unverified` permits recovery from an
    untrusted input; it never skips the new output's HYGEIA gates. Inputs must
    remain unchanged for the operation's duration, including no new WAL writes.
    """
    if not math.isfinite(threshold) or not 0.0 <= threshold <= 1.0:
        raise ValueError("threshold must be between 0.0 and 1.0")
    selected = list(ATOM_PROJECTIONS) if entity_types is None else list(dict.fromkeys(entity_types))
    if not selected or any(entity_type not in ATOM_PROJECTIONS for entity_type in selected):
        raise ValueError("Unknown or empty resolution entity types")
    sources = [Path(source).resolve() for source in sources]
    output = Path(output).parent.resolve() / Path(output).name
    with output_lease(output):
        _admit_sources(sources, output, allow_unverified)
        if output.exists():
            raise OutputExistsError(
                "Resolution output already exists; choose a new output path. "
                "Implicit append or replacement is not supported."
            )
        hygeia.require_hygeia()
        fd, name = tempfile.mkstemp(prefix=f".{output.name}.", suffix=".tmp", dir=output.parent)
        os.close(fd)
        temporary = Path(name)
        try:
            result = _populate(temporary, sources, selected, threshold, atomize_only)
            hygeia.sanitize_output(temporary)
            hygeia.finalize_sanitization(temporary)
            _checkpoint(temporary)
            if output.exists():
                raise OutputExistsError(
                    "Resolution output appeared during the build; refusing overwrite"
                )
            os.replace(temporary, output)
            return result
        except BaseException:
            # Preserve the original failure if cleanup itself is obstructed.
            for suffix in ("", "-wal", "-shm"):
                try:
                    Path(f"{temporary}{suffix}").unlink(missing_ok=True)
                except OSError:
                    warnings.warn(
                        "Could not remove an unpublished resolution temporary file",
                        RuntimeWarning, stacklevel=2,
                    )
            raise
