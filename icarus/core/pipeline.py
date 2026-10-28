"""
ICARUS Pipeline — Phase orchestrator with checkpoint/resume.

Processes data sources through a configurable sequence of phases,
saving progress at each checkpoint. Crash at phase N? Resume from phase N.
"""

import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import stat
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, List, Optional

from icarus.core.build_lock import output_lease
from icarus.core.schema import (
    CORE_SCHEMA,
    ENTITY_TABLES,
    FTS_SCHEMA,
    FTS_TRIGGERS,
    INDEXES,
    SCHEMA_VERSION,
    VIEWS,
    open_db,
)

PROVENANCE_ENTITY_TABLES = (*ENTITY_TABLES, "mach_services")
SOURCE_IDENTITY_PROTOCOL = "hmac-sha256-v1"


class CheckpointFingerprintMismatch(ValueError):
    """Raised when a checkpoint belongs to a different source/parser/config.

    The stored fingerprint (resolved source path, parser identity/version, and
    normalized effective config) does not match the current run. Resuming would
    silently graft the current run's identity onto a database built from
    different inputs (issue #45), so the build refuses loudly rather than
    resuming or discarding-and-rebuilding on its own.
    """


class CheckpointProvenanceError(ValueError):
    """Raised when a resumable checkpoint cannot prove its run identity."""


class OutputExistsError(ValueError):
    """Raised when an output database already exists and cannot be safely reused.

    A pre-existing output with no valid, fingerprint-matching in-progress
    checkpoint is refused by default (issue #36): reusing it would union new
    data into a stale database. The user must pass ``--fresh`` for a clean
    atomic rebuild, or remove/redirect the output.
    """


def compute_fingerprint(
    source: Path, parser_name: str, parser: object, config: dict
) -> dict:
    """Build the resume fingerprint identifying what a checkpoint was built from.

    Captures everything that, if changed, means a stored checkpoint must NOT be
    resumed into:

    * ``source`` — the resolved absolute source path.
    * ``parser_name`` — the requested parser name.
    * ``parser_impl`` — the module-qualified parser class name (implementation
      identity, so swapping which class serves a name is detected).
    * ``parser_version`` — the parser's manifest version, or ``"unknown"``.
    * ``config`` — the normalized effective build config (the flags that change
      the produced phases/output: ``skip_hygeia`` and ``resolve``). The output
      path and the resume policy (``--fresh``) are deliberately excluded — they
      change where/whether we resume, not the identity of what is produced.
    """
    cls = type(parser)
    version = "unknown"
    try:
        from icarus.parsers import get_registry

        manifest = get_registry().get_manifest(parser_name)
        if manifest is not None:
            version = manifest.version
    except Exception:
        version = "unknown"

    return {
        "source": str(Path(source).resolve()),
        "parser_name": parser_name,
        "parser_impl": f"{cls.__module__}.{cls.__qualname__}",
        "parser_version": version,
        "config": {key: config[key] for key in sorted(config)},
    }


def _canonical_fingerprint(fingerprint: dict) -> str:
    """Deterministic serialization for stable equality comparison and storage."""
    return json.dumps(fingerprint, sort_keys=True, separators=(",", ":"))


def _source_identity_digest(source: Path, run_id: str) -> str:
    """Read-only compatibility for deprecated, publicly guessable path hashes."""
    value = f"{run_id}\0{Path(source).resolve()}"
    return hashlib.sha256(value.encode("utf-8", "surrogatepass")).hexdigest()


def _source_identity_hmac(source: Path, run_id: str, key: bytes) -> str:
    value = f"{run_id}\0{Path(source).resolve()}"
    return hmac.new(key, value.encode("utf-8", "surrogatepass"), hashlib.sha256).hexdigest()


class PipelinePhase:
    """A single processing phase."""

    def __init__(self, name: str, handler: Callable, description: str = ""):
        self.name = name
        self.handler = handler
        self.description = description


class PipelineContext:
    """Shared state across pipeline phases."""

    def __init__(self, source: Path, output_db: Path, parser_name: str):
        self.source = source
        self.output_db = output_db
        self.parser_name = parser_name
        self.start_time = time.time()
        self.phase_times: dict[str, float] = {}
        self.stats: dict[str, Any] = {}
        self.errors: list[tuple[str, str]] = []
        self.version_id: Optional[int] = None
        self.run_id: str = str(uuid.uuid4())

    @property
    def elapsed(self) -> float:
        return time.time() - self.start_time


class Pipeline:
    """Main pipeline orchestrator.

    Sequences phases, manages checkpoints, handles resume-from-failure.
    SQLite cache and mmap scale to available system RAM automatically.
    """

    def __init__(
        self, source: Path, output: Path, parser_name: str = "windows",
        skip_hygeia: bool = False, fingerprint: Optional[dict] = None,
    ):
        self.source = Path(source)
        self.output = Path(output)
        self.parser_name = parser_name
        self.skip_hygeia = skip_hygeia
        # Resume fingerprint identifying what this run is built from. When set,
        # a stored checkpoint is honored ONLY if its fingerprint matches exactly
        # (see _validate_fingerprint); when None (direct low-level use), resume
        # falls back to phase-name alignment alone.
        self.fingerprint = fingerprint
        self.phases: List[PipelinePhase] = []
        # Full filename prevents out.db/out.sqlite from sharing state. The new
        # suffix is also disjoint from every legacy '*_checkpoint.db' name.
        self.checkpoint_db = self.output.parent / f".{self.output.name}.icarus-checkpoint.db"
        self.legacy_checkpoint_db = self.output.parent / f".{self.output.stem}_checkpoint.db"
        self.context = PipelineContext(self.source, self.output, parser_name)
        self._source_identity_key: Optional[bytes] = None
        self._recover_empty_output = False
        self._identity_upgrade_pending = False

    def add_phase(self, name: str, handler: Callable, description: str = "") -> None:
        """Append a processing phase to the pipeline."""
        self.phases.append(PipelinePhase(name, handler, description))

    def get_last_checkpoint(self) -> int:
        """Return the index of the last completed phase, or -1 if none.

        A stored checkpoint is only honored when every completed phase still
        matches the current pipeline definition at that index (same
        phase_name). If the pipeline was redefined between runs — phases
        renamed or reordered — the stored indices no longer line up, so
        resuming by index would skip or mis-run phases; in that case the
        checkpoint is discarded and the pipeline re-runs from scratch (-1).
        """
        if not self.checkpoint_db.exists():
            return -1

        # Strict fingerprint guard runs first: a checkpoint from a different
        # source/parser/config must fail loudly, never resume (issue #45).
        self._validate_fingerprint()

        conn = sqlite3.connect(str(self.checkpoint_db))
        try:
            rows = conn.execute(
                "SELECT phase_index, phase_name FROM checkpoints WHERE status = 'complete'"
            ).fetchall()
        except sqlite3.OperationalError:
            return -1
        finally:
            conn.close()

        last = -1
        for phase_index, phase_name in rows:
            if phase_index >= len(self.phases) or self.phases[phase_index].name != phase_name:
                return -1
            if phase_index > last:
                last = phase_index
        return last

    def _load_stored_fingerprint(self) -> Optional[str]:
        """Return the canonical fingerprint stored in the checkpoint, or None."""
        if not self.checkpoint_db.exists():
            return None
        conn = sqlite3.connect(str(self.checkpoint_db))
        try:
            row = conn.execute(
                "SELECT value FROM checkpoint_meta WHERE key = 'fingerprint'"
            ).fetchone()
        except sqlite3.OperationalError:
            return None
        finally:
            conn.close()
        return row[0] if row else None

    def _validate_fingerprint(self) -> None:
        """Fail loudly if the stored checkpoint fingerprint differs from this run.

        No-op when this pipeline carries no fingerprint (low-level direct use)
        or when no checkpoint exists yet. When a fingerprint IS set and a
        checkpoint is present, the stored fingerprint must match exactly —
        including the case where the checkpoint predates fingerprinting and has
        none — otherwise the build refuses rather than silently resuming or
        discarding-and-rebuilding.
        """
        if self.fingerprint is None:
            return
        stored = self._load_stored_fingerprint()
        if stored is None:
            if not self.checkpoint_db.exists():
                return
            raise CheckpointFingerprintMismatch(
                f"Checkpoint {self.checkpoint_db.name} carries no build fingerprint "
                "(created by an older ICARUS or by hand) and cannot be safely "
                "resumed. Pass --fresh for a clean rebuild, or remove the "
                f"checkpoint file {self.checkpoint_db}."
            )
        current = _canonical_fingerprint(self.fingerprint)
        if stored != current:
            raise CheckpointFingerprintMismatch(
                f"Checkpoint {self.checkpoint_db.name} belongs to a different "
                "source/parser/config than this run — resuming would build a "
                "database from the OLD inputs while presenting it as the new run.\n"
                f"  checkpoint fingerprint: {stored}\n"
                f"  this run's fingerprint: {current}\n"
                "Pass --fresh for a clean rebuild, or remove the checkpoint file "
                f"{self.checkpoint_db}."
            )

    def has_resumable_checkpoint(self) -> bool:
        """True if a checkpoint exists AND its fingerprint matches this run.

        Used to decide whether a pre-existing output may be resumed into rather
        than refused. A fingerprint MISMATCH raises (loud failure) rather than
        returning False, so a wrong-source checkpoint is never quietly treated
        as "no checkpoint" and rebuilt over the existing output.
        """
        with output_lease(self.output):
            checkpoint = self._select_checkpoint(resume=True, adopt=False)
            if checkpoint is None:
                return False
            self._validate_checkpoint_at(checkpoint)
            return True

    def _validate_checkpoint_at(self, checkpoint: Path) -> None:
        """Validate without changing this pipeline's context or checkpoint files."""
        probe = Pipeline(
            self.source, self.output, self.parser_name,
            skip_hygeia=self.skip_hygeia, fingerprint=self.fingerprint,
        )
        probe.checkpoint_db = checkpoint
        probe._validate_fingerprint()
        probe._restore_version_identity()

    def _checkpoint_owned_by_output(self, checkpoint: Path, *, legacy: bool = False) -> bool:
        """Establish ownership from the actual output, never the stem alone."""
        label = "legacy checkpoint" if legacy else "checkpoint"
        try:
            conn = sqlite3.connect(checkpoint.resolve().as_uri() + "?mode=ro", uri=True)
            try:
                metadata = dict(conn.execute(
                    "SELECT key, value FROM checkpoint_meta "
                    "WHERE key IN ('run_id', 'version_id', 'output_uri')"
                ))
            finally:
                conn.close()
            run_id = metadata["run_id"]
            version_id = int(metadata["version_id"])
            if not isinstance(run_id, str) or not run_id or version_id < 1:
                raise ValueError("Invalid run identity")
            conn = open_db(self.output, readonly=True)
            try:
                row = conn.execute(
                    "SELECT run_id FROM versions WHERE id = ?", (version_id,),
                ).fetchone()
            finally:
                conn.close()
        except (sqlite3.Error, KeyError, TypeError, ValueError) as error:
            raise CheckpointProvenanceError(
                f"Cannot establish ownership of {label} {checkpoint.name}; "
                "preserving it. Use --fresh or a separate output path, or recover "
                "the original database/checkpoint pair before resuming."
            ) from error
        owned = row is not None and row[0] == run_id
        stored_output = metadata.get("output_uri")
        if stored_output is not None and stored_output != self.output.resolve().as_uri():
            if owned:
                raise CheckpointProvenanceError(
                    f"Ambiguous {label} output identity; preserving both artifacts. "
                    "Use --fresh or recover the original database/checkpoint pair."
                )
            return False
        return owned

    @staticmethod
    def _require_quiescent_legacy(checkpoint: Path) -> None:
        for suffix in ("-wal", "-journal"):
            sidecar = Path(str(checkpoint) + suffix)
            if sidecar.exists() and sidecar.stat().st_size:
                raise CheckpointProvenanceError(
                    "Legacy checkpoint has a nonempty WAL or journal; preserving "
                    "all files. Close its writer and recover/checkpoint SQLite "
                    "before retrying, or use --fresh."
                )

    def _select_checkpoint(self, *, resume: bool, adopt: bool) -> Optional[Path]:
        """Recognize old state; migrate only a proven owner under both leases.

        The caller holds the output lease. A shared legacy-namespace lease
        serializes inspection/migration by outputs that formerly shared a stem.
        A read-only predicate never renames or removes checkpoint data.
        """
        modern = self.checkpoint_db if self.checkpoint_db.exists() else None
        legacy = self.legacy_checkpoint_db
        if not legacy.exists() or not self.output.exists():
            return modern
        with output_lease(legacy):
            if not legacy.exists():
                return modern
            if not self._checkpoint_owned_by_output(legacy, legacy=True):
                return modern  # Foreign legacy state is never cleared or adopted.
            if modern is not None:
                raise CheckpointProvenanceError(
                    "Ambiguous modern and owned legacy checkpoint state; preserving "
                    "both. Recover the intended pair or use --fresh."
                )
            self._require_quiescent_legacy(legacy)
            if resume:
                self._validate_checkpoint_at(legacy)
            if not adopt:
                return legacy
            legacy.replace(self.checkpoint_db)
            # With no WAL/journal data and no open connection, these are only
            # owned empty journals/shared-memory indexes, not separate state.
            for suffix in ("-wal", "-shm", "-journal"):
                Path(str(legacy) + suffix).unlink(missing_ok=True)
            return self.checkpoint_db

    @staticmethod
    def _ensure_checkpoint_schema(conn: sqlite3.Connection) -> None:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS checkpoints (
                phase_index INTEGER PRIMARY KEY,
                phase_name TEXT,
                status TEXT,
                timestamp REAL,
                stats TEXT
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS checkpoint_meta (
                key TEXT PRIMARY KEY,
                value TEXT
            )
        """)

    def _persist_version_identity(self) -> None:
        """Bind this checkpoint to the one versions row it may resume."""
        if self.context.version_id is None:
            raise CheckpointProvenanceError(
                "Cannot create a resumable checkpoint without an active versions row"
            )
        self._persist_identity_intent("bound")

    def _identity_intent(self) -> str:
        return _canonical_fingerprint({
            "source": str(self.source.resolve()), "parser_name": self.parser_name,
            "skip_hygeia": self.skip_hygeia, "fingerprint": self.fingerprint,
        })

    def _persist_identity_intent(self, state: str = "prepared") -> None:
        """Durably store the private key before publishing any dependent HMAC."""
        conn = self._private_checkpoint_connection()
        try:
            if self._source_identity_key is None:
                self._source_identity_key = secrets.token_bytes(32)
            self._ensure_checkpoint_schema(conn)
            metadata = {
                "run_id": self.context.run_id,
                "output_uri": self.output.resolve().as_uri(),
                "identity_protocol": SOURCE_IDENTITY_PROTOCOL,
                "identity_state": state,
                "identity_intent": self._identity_intent(),
                "source_identity_key": self._source_identity_key.hex(),
            }
            if self.context.version_id is not None:
                metadata["version_id"] = str(self.context.version_id)
            if self.fingerprint is not None:
                metadata["fingerprint"] = _canonical_fingerprint(self.fingerprint)
            conn.executemany(
                "INSERT OR REPLACE INTO checkpoint_meta (key, value) VALUES (?, ?)",
                metadata.items(),
            )
            conn.commit()
        finally:
            conn.close()

    def _private_checkpoint_connection(self) -> sqlite3.Connection:
        flags = os.O_CREAT | os.O_EXCL | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0)
        try:
            fd = os.open(self.checkpoint_db, flags, 0o600)
        except FileExistsError:
            pass
        else:
            os.close(fd)
        entry = self.checkpoint_db.lstat()
        if (
            not stat.S_ISREG(entry.st_mode) or entry.st_nlink != 1
            or getattr(entry, "st_file_attributes", 0)
            & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
        ):
            raise CheckpointProvenanceError(
                "Private checkpoint must be a regular file with no aliases; preserving it"
            )
        if os.name != "nt":
            os.chmod(self.checkpoint_db, 0o600)
        return sqlite3.connect(str(self.checkpoint_db))

    def _read_private_identity(self, metadata: dict) -> bytes:
        try:
            if metadata["identity_protocol"] != SOURCE_IDENTITY_PROTOCOL:
                raise ValueError("Unsupported identity protocol")
            if metadata["identity_intent"] != self._identity_intent():
                raise ValueError("Changed identity intent")
            key = bytes.fromhex(metadata["source_identity_key"])
            if len(key) != 32:
                raise ValueError("Invalid key length")
            return key
        except (KeyError, TypeError, ValueError):
            raise CheckpointProvenanceError(
                "Private resume identity is missing, invalid, or belongs to a "
                "different source/config; preserving all artifacts. Use --fresh."
            ) from None

    def _public_identity(self) -> dict:
        key = self._source_identity_key
        if key is None:
            raise CheckpointProvenanceError("Private resume identity was not prepared")
        return {"version": 1, "algorithm": "hmac-sha256", "digest": _source_identity_hmac(
            self.source, self.context.run_id, key,
        )}

    def _empty_prepared_output(self) -> bool:
        """Recognize an empty new output, never an unrelated existing dataset."""
        if not self.output.exists():
            return True
        conn = open_db(self.output, readonly=True)
        reference = sqlite3.connect(":memory:")
        try:
            for ddl in (CORE_SCHEMA, INDEXES, FTS_SCHEMA, FTS_TRIGGERS, VIEWS):
                reference.executescript(ddl)
            reference.execute("INSERT INTO metadata VALUES ('schema_version', ?)",
                              (str(SCHEMA_VERSION),))
            expected = {
                (row[0], row[1]): row[2] for row in reference.execute(
                    "SELECT name,type,sql FROM sqlite_master"
                )
            }
            objects = conn.execute(
                "SELECT name,type,sql FROM sqlite_master"
            ).fetchall()
            for name, kind, ddl in objects:
                known = expected.get((name, kind))
                if (
                    (name, kind) not in expected
                    or " ".join((ddl or "").split()) != " ".join((known or "").split())
                ):
                    return False
                if kind != "table":
                    continue
                # Every identifier is from the fixed fresh-schema reference.
                quoted = '"' + name.replace('"', '""') + '"'
                columns = [row[1] for row in reference.execute(
                    f"PRAGMA table_info({quoted})"  # nosec B608 - fresh schema reference owns name
                )]
                fields: list[str] = []
                for column in columns:
                    qcolumn = '"' + column.replace('"', '""') + '"'
                    fields.extend((f"typeof({qcolumn})", f"length({qcolumn})",
                                   f"substr({qcolumn},1,256)"))
                selection = ", ".join(fields)
                query = f"SELECT {selection} FROM {quoted} LIMIT 9"  # nosec B608 - fresh schema reference owns identifiers
                fresh_rows = reference.execute(query).fetchall()
                current_rows = conn.execute(query).fetchall()
                # A schema-initialization crash can precede the version marker.
                if name == "metadata" and not current_rows:
                    continue
                if current_rows != fresh_rows:
                    return False
            if conn.execute(
                "SELECT 1 FROM sqlite_master WHERE name='sqlite_sequence'"
            ).fetchone() and conn.execute("SELECT 1 FROM sqlite_sequence LIMIT 1").fetchone():
                return False
            return all(conn.execute(f"PRAGMA {setting}").fetchone()[0] == 0  # nosec B608 - settings fixed below
                       for setting in ("freelist_count", "user_version", "application_id"))
        finally:
            reference.close()
            conn.close()

    def _restore_prepared_identity(self, metadata: dict, key: bytes) -> None:
        if metadata.get("output_uri") != self.output.resolve().as_uri():
            raise CheckpointProvenanceError("Prepared intent belongs to another output")
        conn = sqlite3.connect(self.checkpoint_db.resolve().as_uri() + "?mode=ro", uri=True)
        try:
            if conn.execute("SELECT 1 FROM checkpoints LIMIT 1").fetchone():
                raise CheckpointProvenanceError(
                    "Prepared identity unexpectedly contains phase state"
                )
        finally:
            conn.close()
        self.context.run_id = metadata["run_id"]
        self.context.version_id = None
        self._source_identity_key = key
        self._recover_empty_output = False
        row = None
        empty = False
        try:
            if self.output.exists():
                conn = open_db(self.output, readonly=True)
                try:
                    if conn.execute(
                        "SELECT 1 FROM sqlite_master WHERE type='table' AND name='versions'"
                    ).fetchone():
                        row = conn.execute(
                            "SELECT id, parser_name, metadata FROM versions WHERE run_id=?",
                            (self.context.run_id,),
                        ).fetchone()
                finally:
                    conn.close()
            if row is None:
                empty = self._empty_prepared_output()
        except sqlite3.Error:
            raise CheckpointProvenanceError(
                "Prepared run cannot establish ownership of this output; preserving "
                "all artifacts. Recover the original pair or use --fresh."
            ) from None
        if row is not None:
            try:
                details = json.loads(row[2] or "{}")
                identity = details.get("source_identity") if isinstance(details, dict) else None
            except (TypeError, ValueError, RecursionError):
                identity = None
            if row[1] != self.parser_name or identity != self._public_identity():
                raise CheckpointProvenanceError("Prepared run does not match its output identity")
            self.context.version_id = row[0]
        elif empty:
            self._recover_empty_output = True
        else:
            raise CheckpointProvenanceError(
                "Prepared run has no matching version in this nonempty output; "
                "preserving it rather than creating an implicit union. Use --fresh."
            )

    def _restore_version_identity(self) -> None:
        """Restore and validate the original run identity before resume."""
        if not self.checkpoint_db.exists():
            return
        conn = sqlite3.connect(str(self.checkpoint_db))
        try:
            rows = conn.execute(
                "SELECT key, value FROM checkpoint_meta"
            ).fetchall()
        except sqlite3.OperationalError as error:
            raise CheckpointProvenanceError(
                f"Checkpoint {self.checkpoint_db.name} has no usable provenance "
                "metadata and cannot be resumed; pass --fresh for a clean rebuild"
            ) from error
        finally:
            conn.close()

        metadata = dict(rows)
        if (
            "output_uri" in metadata
            and metadata["output_uri"] != self.output.resolve().as_uri()
        ):
            raise CheckpointProvenanceError(
                "Checkpoint belongs to a different output path; preserving it. "
                "Recover the original database/checkpoint pair or use --fresh."
            )
        protocol = metadata.get("identity_protocol")
        if protocol is not None and metadata.get("output_uri") != self.output.resolve().as_uri():
            raise CheckpointProvenanceError(
                "Private resume identity has no matching output path; preserving all artifacts"
            )
        key = self._read_private_identity(metadata) if protocol is not None else None
        state = metadata.get("identity_state")
        if protocol is not None and state == "prepared":
            if not metadata.get("run_id"):
                raise CheckpointProvenanceError("Prepared intent has no run identity")
            if key is None:
                raise CheckpointProvenanceError("Prepared intent has no private identity")
            self._restore_prepared_identity(metadata, key)
            return
        missing = {"run_id", "version_id"} - metadata.keys()
        if missing:
            raise CheckpointProvenanceError(
                f"Checkpoint {self.checkpoint_db.name} is missing provenance "
                f"metadata ({', '.join(sorted(missing))}) and cannot be resumed; "
                "pass --fresh for a clean rebuild"
            )
        try:
            version_id = int(metadata["version_id"])
        except (TypeError, ValueError) as error:
            raise CheckpointProvenanceError(
                f"Checkpoint {self.checkpoint_db.name} has an invalid version_id "
                f"{metadata['version_id']!r}; pass --fresh for a clean rebuild"
            ) from error

        if not self.output.exists():
            raise CheckpointProvenanceError(
                f"Checkpoint {self.checkpoint_db.name} references version "
                f"{version_id}, but output database {self.output} is missing; "
                "pass --fresh for a clean rebuild"
            )
        conn = open_db(self.output, readonly=True)
        try:
            row = conn.execute(
                "SELECT run_id, parser_name, source_path, metadata FROM versions WHERE id = ?",
                (version_id,),
            ).fetchone()
        except sqlite3.OperationalError as error:
            raise CheckpointProvenanceError(
                f"Checkpoint {self.checkpoint_db.name} cannot validate version "
                f"{version_id}; pass --fresh for a clean rebuild"
            ) from error
        finally:
            conn.close()

        if row is None:
            raise CheckpointProvenanceError(
                f"Checkpoint {self.checkpoint_db.name} references missing versions "
                f"row {version_id}; pass --fresh for a clean rebuild"
            )
        run_id, parser_name, source_path, version_metadata = row
        expected_source = str(self.source.resolve())
        actual_source = str(Path(source_path).resolve()) if source_path else None
        mismatches = []
        if run_id != metadata["run_id"]:
            mismatches.append("run_id")
        if parser_name != self.parser_name:
            mismatches.append("parser_name")
        try:
            version_details = json.loads(version_metadata or "{}")
        except (TypeError, ValueError, RecursionError):
            version_details = {}
        identity = (
            version_details.get("source_identity") if isinstance(version_details, dict) else None
        )
        legacy_identity = (
            version_details.get("source_identity_sha256")
            if isinstance(version_details, dict) else None
        )
        if protocol is not None and state not in ("bound", "upgrading"):
            mismatches.append("private_identity_state")
        if identity is not None:
            expected_identity = {"version": 1, "algorithm": "hmac-sha256", "digest":
                                 _source_identity_hmac(self.source, metadata["run_id"], key)
                                 if key is not None else None}
            if identity != expected_identity:
                mismatches.append("source_identity")
        elif protocol is not None and state == "bound":
            mismatches.append("source_identity")
        elif legacy_identity is not None:
            if legacy_identity != _source_identity_digest(self.source, metadata["run_id"]):
                mismatches.append("source_identity")
        elif actual_source != expected_source:
            # Older checkpoints lack the digest, so retain their original
            # exact-path validation rather than guessing at redacted labels.
            mismatches.append("source_path")
        if mismatches:
            raise CheckpointProvenanceError(
                f"Checkpoint {self.checkpoint_db.name} version identity mismatches "
                f"the output/current build ({', '.join(mismatches)}); pass --fresh "
                "for a clean rebuild"
            )

        self.context.run_id = metadata["run_id"]
        self.context.version_id = version_id
        self._source_identity_key = key
        self._identity_upgrade_pending = protocol is None or state == "upgrading"

    def _upgrade_legacy_identity(self) -> None:
        # The private key must survive a crash before its public HMAC is written.
        self._persist_identity_intent("upgrading")
        conn = open_db(self.output)
        try:
            from icarus.integrations.hygeia import invalidate_sanitization
            row = conn.execute(
                "SELECT metadata FROM versions WHERE id=? AND run_id=?",
                (self.context.version_id, self.context.run_id),
            ).fetchone()
            if row is None:
                raise CheckpointProvenanceError(
                    "Original version disappeared during identity upgrade"
                )
            try:
                details = json.loads(row[0] or "{}")
            except (TypeError, ValueError, RecursionError):
                raise CheckpointProvenanceError(
                    "Unsupported version metadata; preserving legacy state"
                ) from None
            if not isinstance(details, dict):
                raise CheckpointProvenanceError(
                    "Unsupported version metadata; preserving legacy state"
                )
            details.pop("source_identity_sha256", None)
            details["source_identity"] = self._public_identity()
            conn.execute("UPDATE versions SET metadata=? WHERE id=? AND run_id=?",
                         (json.dumps(details), self.context.version_id, self.context.run_id))
            invalidate_sanitization(conn)
            conn.commit()
            self._identity_upgrade_pending = False
        finally:
            conn.close()

    def save_checkpoint(self, phase_index: int, status: str, stats: Optional[dict] = None) -> None:
        """Persist phase completion status for resume-on-crash."""
        conn = sqlite3.connect(str(self.checkpoint_db))
        try:
            self._ensure_checkpoint_schema(conn)
            # Stamp the fingerprint once, on the first checkpoint write, so every
            # checkpoint this build produces carries the identity of what it was
            # built from. INSERT OR IGNORE keeps it immutable for the run.
            if self.fingerprint is not None:
                conn.execute(
                    "INSERT OR IGNORE INTO checkpoint_meta VALUES ('fingerprint', ?)",
                    (_canonical_fingerprint(self.fingerprint),),
                )
            conn.execute(
                "INSERT OR REPLACE INTO checkpoints VALUES (?, ?, ?, ?, ?)",
                (phase_index, self.phases[phase_index].name, status,
                 time.time(), json.dumps(stats or {}))
            )
            conn.commit()
        finally:
            conn.close()

    def _clear_checkpoint(self) -> None:
        """Delete the checkpoint DB after a fully successful run.

        Checkpoints exist only to resume a crashed run. Leaving them after
        success marks every phase 'complete', so a later build to the same
        output would compute start = last + 1 > len(phases) and silently skip
        every phase (a no-op). Removing the file forces a clean re-run.
        """
        base = str(self.checkpoint_db)
        for suffix in ("", "-wal", "-shm"):
            Path(base + suffix).unlink(missing_ok=True)

    def _create_version_record(self):
        """Record this pipeline run in the versions table.

        Ensures the database and schema exist first. On a fresh build the init
        phase has not run yet when this is called, so without this guard the
        version record — and therefore all run provenance — was silently
        skipped, leaving the versions table empty on every first build.
        """
        if not self.output.exists() or self._recover_empty_output:
            from icarus.core.schema import initialize_database
            initialize_database(self.output)
        conn = open_db(self.output)
        try:
            from icarus.integrations.hygeia import invalidate_sanitization
            conn.execute("""
                INSERT INTO versions
                (run_id, parser_name, source_path, started_at, metadata)
                VALUES (?, ?, ?, ?, ?)
            """, (
                self.context.run_id,
                self.parser_name,
                str(self.source.resolve()),
                datetime.now(timezone.utc).isoformat(),
                json.dumps({
                    "source_identity": self._public_identity(),
                }),
            ))
            row = conn.execute(
                "SELECT id FROM versions WHERE run_id = ?", (self.context.run_id,)
            ).fetchone()
            invalidate_sanitization(conn)
            conn.commit()
            if row:
                self.context.version_id = row[0]
        finally:
            conn.close()

    def _finalize_version_record(self):
        """Update the version record with entity count and completion timestamp."""
        if not self.output.exists() or not self.context.version_id:
            return
        conn = open_db(self.output)
        try:
            entity_count = sum(
                conn.execute(
                    f"SELECT COUNT(*) FROM {table} WHERE source_version_id = ?",  # nosec B608 - table comes from fixed schema-owned tuple
                    (self.context.version_id,),
                ).fetchone()[0]
                for table in PROVENANCE_ENTITY_TABLES
            )
            cursor = conn.execute(
                "UPDATE versions SET entity_count = ?, completed_at = ? WHERE id = ?",
                (entity_count, datetime.now(timezone.utc).isoformat(),
                 self.context.version_id),
            )
            if cursor.rowcount != 1:
                raise CheckpointProvenanceError(
                    f"Active versions row {self.context.version_id} disappeared "
                    "before finalization"
                )
            conn.commit()
        finally:
            conn.close()

    def run(self, resume: bool = True, start_phase: Optional[int] = None) -> "PipelineContext":
        """Execute the pipeline.

        Args:
            resume: If True, skip completed phases (default behavior).
            start_phase: Force start from this phase index (overrides resume).
        """
        with output_lease(self.output):
            selected = self._select_checkpoint(resume=resume, adopt=True)
            if not resume and selected is not None:
                if not self.output.exists() or not self._checkpoint_owned_by_output(selected):
                    raise CheckpointProvenanceError(
                        "Cannot discard a checkpoint owned by a different or missing "
                        "output; preserving it. Recover its original output or use --fresh."
                    )
            return self._run(resume=resume, start_phase=start_phase)

    def _run(self, resume: bool = True, start_phase: Optional[int] = None) -> "PipelineContext":
        restored_identity = resume and self.checkpoint_db.exists()
        if restored_identity:
            self._validate_fingerprint()
            self._restore_version_identity()
            last_complete = self.get_last_checkpoint()
        else:
            if not resume:
                self._clear_checkpoint()
            last_complete = -1
        start = start_phase if start_phase is not None else (last_complete + 1)

        if not restored_identity:
            self._persist_identity_intent(
                "bound" if self.context.version_id is not None else "prepared"
            )
            if self.context.version_id is not None:
                self._validate_checkpoint_at(self.checkpoint_db)
        elif self._source_identity_key is None or self._identity_upgrade_pending:
            self._upgrade_legacy_identity()

        if self.context.version_id is None:
            self._create_version_record()
        else:
            # A validated resume (or reuse of this low-level Pipeline object)
            # can write again. Revoke earlier content evidence before any phase
            # or completion write, including builds that subsequently hard-exit.
            from icarus.integrations.hygeia import invalidate_sanitization
            conn = open_db(self.output)
            try:
                invalidate_sanitization(conn)
                conn.commit()
            finally:
                conn.close()
        self._persist_version_identity()

        print(f"[ICARUS] Pipeline: {len(self.phases)} phases, "
              f"source={self.source}, output={self.output}")

        if start >= len(self.phases):
            print(f"[ICARUS] All {len(self.phases)} phases already complete.")

        elif start > 0:
            print(f"[ICARUS] Resuming from phase {start} "
                  f"({self.phases[start].name})")

        for i in range(start, len(self.phases)):
            phase = self.phases[i]
            print(f"\n[ICARUS] Phase {i}: {phase.name} — {phase.description}")
            phase_start = time.time()

            try:
                self.save_checkpoint(i, "running")
                stats = phase.handler(self.context)
                elapsed = time.time() - phase_start
                self.context.phase_times[phase.name] = elapsed
                if stats:
                    self.context.stats[phase.name] = stats
                self.save_checkpoint(i, "complete", stats)
                print(f"[ICARUS] Phase {i} complete ({elapsed:.1f}s)")
            except Exception as e:
                self.save_checkpoint(i, "failed", {"error": str(e)})
                self.context.errors.append((phase.name, str(e)))
                print(f"[ICARUS] Phase {i} FAILED: {e}")
                if phase.name == "sanitize":
                    # A failed sanitize phase leaves partially-processed,
                    # unverified data in the (non-atomic default-path) output.
                    # Stamp it FAILED so `query` refuses it and resume re-runs
                    # sanitization instead of trusting the file (#77).
                    try:
                        from icarus.integrations.hygeia import mark_sanitization_failed
                        mark_sanitization_failed(self.output)
                    except Exception:
                        pass
                raise

        self._finalize_version_record()

        # Finalization writes completion metadata after the sanitize phase. A
        # second, read-only gate ensures no post-sanitize write can invalidate
        # the share-safe claim. If it fails, mark sanitize failed so resume
        # re-runs sanitization instead of skipping every completed phase.
        sanitize_indices = [
            index for index, phase in enumerate(self.phases) if phase.name == "sanitize"
        ]
        if sanitize_indices:
            from icarus.integrations.hygeia import (
                SanitizationError,
                finalize_sanitization,
            )

            sanitize_index = sanitize_indices[-1]
            try:
                finalize_sanitization(self.output)
            except SanitizationError as error:
                self.save_checkpoint(sanitize_index, "failed", {"error": str(error)})
                self.context.errors.append(("sanitize_final_gate", str(error)))
                raise error

            self.context.stats["sanitize_final_gate"] = {
                "passed": True,
                "total_findings": 0,
            }
        self._clear_checkpoint()

        total = time.time() - self.context.start_time
        print(f"\n[ICARUS] Pipeline complete. {len(self.phases)} phases in {total:.1f}s")
        return self.context


def create_default_pipeline(
    source: Path, output: Path, parser_name: str = "windows",
    skip_hygeia: bool = False, resolve: bool = False,
) -> Pipeline:
    """Create a pipeline with the standard phase sequence.

    Args:
        skip_hygeia: If True, skips HYGEIA sanitization. The output database
            will contain raw, unsanitized data. A warning is printed and
            the skip is recorded in the database metadata.
        resolve: If True, inserts an EXPERIMENTAL "resolve" phase after
            "verify" and before the sanitize/skip_hygeia_marker phase, which
            atomizes this build's own entities and runs
            ``EntityResolver.resolve_scored`` over them (see
            ``icarus.core.resolver``). Default False leaves the phase list
            unchanged from before this option existed. For cross-source
            resolution (multiple builds merged together), use the separate
            ``icarus resolve`` CLI command instead.
    """
    from icarus.core.schema import initialize_database
    from icarus.integrations.hygeia import require_hygeia, sanitize_output
    from icarus.parsers import get_parser

    parser = get_parser(parser_name)
    fingerprint = compute_fingerprint(
        source, parser_name, parser,
        {"skip_hygeia": skip_hygeia, "resolve": resolve},
    )
    pipeline = Pipeline(
        source, output, parser_name, skip_hygeia=skip_hygeia, fingerprint=fingerprint,
    )

    pipeline.add_phase("init", lambda ctx: initialize_database(ctx.output_db),
                       "Initialize SQLite database and schema")
    pipeline.add_phase(
        "ingest",
        lambda ctx: _run_parser_phase_with_provenance(
            ctx, lambda: parser.extract_entities(ctx.source, ctx.output_db)
        ),
        "Walk source, extract entities, and stamp run provenance",
    )
    pipeline.add_phase(
        "relationships",
        lambda ctx: _run_parser_phase_with_provenance(
            ctx, lambda: parser.extract_relationships(ctx.source, ctx.output_db)
        ),
        "Map relationships and stamp run provenance",
    )
    pipeline.add_phase("verify", lambda ctx: _verify_phase(ctx, parser),
                       "Quality gates and verification")

    if resolve:
        pipeline.add_phase(
            "resolve", _resolve_phase,
            "EXPERIMENTAL: entity resolution (resolve_scored)")

    if skip_hygeia:
        print("\n" + "!" * 60)
        print("WARNING: HYGEIA SANITIZATION DISABLED (--skip-hygeia)")
        print("Output database will contain raw, unsanitized data.")
        print("DO NOT share this database without manual review.")
        print("!" * 60 + "\n")
        pipeline.add_phase("skip_hygeia_marker", _mark_hygeia_skipped,
                           "Record HYGEIA skip in metadata")
    else:
        engine = require_hygeia()
        pipeline.context.stats["sanitizer"] = engine
        print(
            f"[ICARUS] Sanitizer: {engine['engine']} "
            f"v{engine['version']} ({engine['mode']})"
        )
        pipeline.add_phase("sanitize", lambda ctx: sanitize_output(ctx.output_db),
                           "HYGEIA canonical sanitizer + mandatory post-gate")

    return pipeline


def _capture_provenance_watermarks(db_path: Path) -> dict:
    """Capture the highest row id present before a parser phase starts."""
    conn = open_db(db_path)
    try:
        # Identifiers come exclusively from the fixed schema-owned tuple.
        return {
            table: conn.execute(
                f"SELECT COALESCE(MAX(id), 0) FROM {table}"  # nosec B608
            ).fetchone()[0]
            for table in (*PROVENANCE_ENTITY_TABLES, "observations")
        }
    finally:
        conn.close()


def _stamp_new_provenance(ctx, watermarks: dict) -> dict:
    """Attribute only rows inserted after the supplied phase watermarks.

    This deliberately does not backfill every NULL row: doing so would claim
    legacy/output-reuse rows as products of the current source. Rows committed
    before a parser crash are stamped from the caller's ``finally`` block, so a
    resumed phase cannot strand partial output without provenance.
    """
    if ctx.version_id is None:
        raise RuntimeError("Cannot stamp parser output without an active versions row")

    conn = open_db(ctx.output_db)
    stamped = {}
    try:
        version = conn.execute(
            "SELECT started_at FROM versions WHERE id = ?", (ctx.version_id,)
        ).fetchone()
        if version is None:
            raise RuntimeError("Cannot stamp parser output: active versions row is missing")
        observed_time = version[0]

        for table in PROVENANCE_ENTITY_TABLES:
            # The identifier comes exclusively from the fixed schema-owned tuple.
            cursor = conn.execute(
                f"UPDATE {table} "  # nosec B608
                "SET source_version_id = ?, "
                "observed_time = COALESCE(observed_time, ?) "
                "WHERE id > ?",
                (ctx.version_id, observed_time, watermarks[table]),
            )
            stamped[table] = max(cursor.rowcount, 0)

        observation_cursor = conn.execute(
            "UPDATE observations SET version_id = COALESCE(version_id, ?) WHERE id > ?",
            (ctx.version_id, watermarks["observations"]),
        )
        stamped["observations"] = max(observation_cursor.rowcount, 0)
        conn.commit()
    finally:
        conn.close()
    return stamped


def _run_parser_phase_with_provenance(ctx, handler: Callable) -> dict:
    """Run one parser phase and stamp even rows committed before a failure."""
    watermarks = _capture_provenance_watermarks(ctx.output_db)
    try:
        result = handler()
    finally:
        stamped = _stamp_new_provenance(ctx, watermarks)

    stats = dict(result or {})
    stats["provenance"] = {
        "rows_stamped": stamped,
        "total": sum(stamped.values()),
    }
    return stats


def _verify_phase(ctx, parser) -> dict:
    """Run parser checks, then enforce relational integrity for every build."""
    stats = dict(parser.verify(ctx.output_db) or {})
    conn = open_db(ctx.output_db)
    try:
        violation = conn.execute("PRAGMA foreign_key_check").fetchone()
    finally:
        conn.close()

    if violation is not None:
        table, rowid, parent, constraint_index = violation
        raise ValueError(
            "Verification failed: foreign key violation "
            f"in table {table!r}, rowid {rowid!r}, parent {parent!r}, "
            f"constraint {constraint_index!r}"
        )

    stats["foreign_key_violations"] = 0
    return stats


def _resolve_phase(ctx) -> dict:
    """EXPERIMENTAL pipeline phase: atomize this build's entities and resolve them.

    Runs entirely within the build's own output database: atomizes the
    entities just produced by the "ingest"/"relationships" phases (tagged
    under this run's own ``ctx.version_id``, already populated before any
    phase runs — see ``Pipeline._create_version_record``), then runs
    ``EntityResolver.resolve_scored`` for every projected entity type. This
    resolves duplicates *within* one build; it does not merge across separate
    builds — use the ``icarus resolve`` CLI command for that.
    """
    print("[ICARUS] EXPERIMENTAL: running entity resolution (resolve_scored) "
          "— API/behavior may still change.")
    from icarus.core.atomize import ATOM_PROJECTIONS, atomize_db
    from icarus.core.resolver import EntityResolver

    with EntityResolver(str(ctx.output_db), experimental=True) as r:
        atomized = atomize_db(r.conn, r.conn, ctx.version_id)
        resolved = {et: r.resolve_scored(et) for et in ATOM_PROJECTIONS}

    return {"atomized": atomized, "resolved": resolved}


def _mark_hygeia_skipped(ctx) -> dict:
    """Record in metadata that HYGEIA was explicitly skipped."""
    conn = open_db(ctx.output_db)
    try:
        conn.execute(
            "INSERT OR REPLACE INTO metadata VALUES (?, ?)",
            ("hygeia_skipped", "true"),
        )
        conn.execute(
            "INSERT OR REPLACE INTO metadata VALUES (?, ?)",
            ("hygeia_warning", "Output contains unsanitized data — review before sharing"),
        )
        conn.commit()
    finally:
        conn.close()
    return {"hygeia": "SKIPPED"}
