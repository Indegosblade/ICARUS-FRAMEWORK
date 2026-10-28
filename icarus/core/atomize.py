"""ICARUS Atomizer — project parsed entity rows into resolver ``atoms``.

The entity resolver works over immutable ``atoms`` (raw per-source
observations). This module owns the declarative bridge from the normalized
parser tables (``binaries``, ``daemons``, ...) into that atom space: each
``ProjectionSpec`` says which rows to select from a source database and how to
name their columns, and :func:`atomize_db` runs those projections and inserts
one atom per row.

Insertion is ``INSERT OR IGNORE`` against the ``atoms`` uniqueness constraint
(``source_version_id, entity_type, source_key``), so re-atomizing the same
source under the same version is idempotent and only genuinely-new atoms fire
the ``atoms_fts`` trigger.
"""

import json
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Dict, List, Optional


@dataclass(frozen=True)
class ProjectionSpec:
    """How to project one entity type's rows into atoms.

    ``field_names`` names the leading selected columns that become matching
    properties. ``key_column`` selects a source-local identity column (column
    zero by default); it may be an extra column excluded from those properties.
    """

    entity_type: str
    select_sql: str
    field_names: List[str]
    key_column: int = 0


ATOM_PROJECTIONS: Dict[str, ProjectionSpec] = {
    "binaries": ProjectionSpec(
        "binaries",
        "SELECT b.executable_name, b.arch, f.path, f.sha256, "
        "CASE WHEN f.path IS NOT NULL AND trim(f.path) != '' THEN 'path:' || f.path "
        "ELSE 'row:' || b.id END "
        "FROM binaries b LEFT JOIN files f ON b.file_id = f.id",
        ["executable_name", "arch", "path", "sha256"], key_column=4),
    "daemons": ProjectionSpec(
        "daemons",
        "SELECT label, program, plist_path FROM daemons",
        ["label", "program", "plist_path"]),
    "frameworks": ProjectionSpec(
        "frameworks",
        "SELECT path, name, bundle_id, version FROM frameworks",
        ["path", "name", "bundle_id", "version"]),
    "kexts": ProjectionSpec(
        "kexts",
        "SELECT bundle_id, name, version FROM kexts",
        ["bundle_id", "name", "version"]),
    "files": ProjectionSpec(
        "files",
        "SELECT path, filename, extension, size, sha256, file_type FROM files",
        ["path", "filename", "extension", "size", "sha256", "file_type"]),
}


def _insert_atom(conn: sqlite3.Connection, values: tuple, *, revoke_trust: bool) -> int:
    """Make the first inserted atom inseparable from revocation of old evidence."""
    if revoke_trust:
        # A savepoint alone would commit when released if it were outermost.
        # Keep one enclosing transaction so atomize_db still commits only once.
        if not conn.in_transaction:
            conn.execute("BEGIN")
        conn.execute("SAVEPOINT icarus_atomize_first_write")
    try:
        cursor = conn.execute(
            "INSERT OR IGNORE INTO atoms (source_version_id, entity_type, "
            "source_key, properties, created_at) VALUES (?, ?, ?, ?, ?)", values,
        )
        if cursor.rowcount == 1 and revoke_trust:
            from icarus.integrations.hygeia import invalidate_sanitization
            invalidate_sanitization(conn)
    except BaseException:
        if revoke_trust:
            conn.execute("ROLLBACK TO SAVEPOINT icarus_atomize_first_write")
            conn.execute("RELEASE SAVEPOINT icarus_atomize_first_write")
        raise
    else:
        if revoke_trust:
            conn.execute("RELEASE SAVEPOINT icarus_atomize_first_write")
    return cursor.rowcount


def atomize_db(
    src_conn: sqlite3.Connection,
    out_conn: sqlite3.Connection,
    version_id: int,
    entity_types: Optional[List[str]] = None,
) -> Dict[str, int]:
    """Project entity rows from ``src_conn`` into atoms in ``out_conn``.

    For each requested entity type (default: every key in
    :data:`ATOM_PROJECTIONS`), runs its projection SQL against the source
    database and inserts one atom per row into the output database's ``atoms``
    table, tagged with ``version_id``. Rows whose source_key is
    NULL or blank/whitespace are skipped. Atom ``properties`` is the JSON of
    the non-NULL selected columns keyed by ``field_names`` (sorted keys).

    Inserts use ``INSERT OR IGNORE`` so re-runs are idempotent; only rows that
    actually inserted (``rowcount == 1``) are counted. ``src_conn`` and
    ``out_conn`` may be the same connection object (within-build atomization).
    Commits ``out_conn`` once on success (including any caller-pending writes)
    and returns ``{entity_type: inserted_count}``. On failure, earlier successful
    inserts may remain pending: the caller owns the choice to commit or roll
    back that transaction. Old content-trust evidence is revoked alongside the
    first inserted atom, so a committed partial result cannot inherit it. If
    revocation itself fails, that first insert is rolled back to a savepoint
    without discarding unrelated caller writes. A no-op retains existing trust.
    """
    if entity_types is None:
        entity_types = list(ATOM_PROJECTIONS)

    if "binaries" in entity_types:
        # Keys changed from executable names to source-local identities. Never
        # silently add a second atom for each existing observation on upgrade;
        # atoms are immutable, so an old version needs a fresh resolution run.
        for source_key, properties in out_conn.execute(
            "SELECT source_key, properties FROM atoms "
            "WHERE source_version_id = ? AND entity_type = 'binaries'", (version_id,)
        ):
            path = json.loads(properties).get("path")
            expected = f"path:{path}" if path is not None and str(path).strip() else None
            if source_key != expected and not (expected is None and source_key.startswith("row:")):
                raise ValueError(
                    "Existing binary atoms use a different source-key format; "
                    "use a fresh resolution output or a new source version"
                )

    now = datetime.now(timezone.utc).isoformat()
    counts: Dict[str, int] = {}
    trust_revoked = False

    for entity_type in entity_types:
        spec = ATOM_PROJECTIONS[entity_type]
        inserted = 0
        # Source projections do not read atoms, so a separate read cursor may
        # stream while inserts update atoms (also on the same connection).
        # Avoid materializing an entire filesystem's projected properties.
        rows = src_conn.execute(spec.select_sql)
        try:
            for row in rows:
                if row[spec.key_column] is None:
                    continue
                source_key = str(row[spec.key_column])
                if not source_key.strip():
                    continue
                props = {
                    name: row[i]
                    for i, name in enumerate(spec.field_names)
                    if row[i] is not None
                }
                inserted_rows = _insert_atom(
                    out_conn,
                    (
                        version_id,
                        entity_type,
                        source_key,
                        json.dumps(props, sort_keys=True),
                        now,
                    ),
                    revoke_trust=not trust_revoked,
                )
                if inserted_rows == 1:
                    inserted += 1
                    trust_revoked = True
        finally:
            rows.close()
        counts[entity_type] = inserted

    out_conn.commit()
    return counts
