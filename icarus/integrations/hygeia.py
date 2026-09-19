"""Fail-closed HYGEIA integration for ICARUS intelligence databases.

HYGEIA is the canonical sanitization engine. ICARUS supplies an ICARUS-safe
pattern registry, records only non-reversible finding fingerprints, and runs an
independent post-sanitize gate before an output may be called clean.
"""

import hashlib
import hmac
import json
import re
import secrets
import sqlite3
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from typing import Any, Dict, List

try:
    from hygeia.patterns import PatternRegistry, get_default_registry
    from hygeia.sqlite_sanitizer import sanitize_database_generic
    from hygeia.verifier import _is_false_positive as _hygeia_is_false_positive

    _HAS_HYGEIA_PACKAGE = True
except ImportError:
    PatternRegistry = None  # type: ignore[assignment,misc]
    get_default_registry = None  # type: ignore[assignment]
    sanitize_database_generic = None  # type: ignore[assignment]
    _hygeia_is_false_positive = None  # type: ignore[assignment]
    _HAS_HYGEIA_PACKAGE = False

try:
    _HYGEIA_VERSION = version("hygeia")
except PackageNotFoundError:
    _HYGEIA_VERSION = "unavailable"


ENGINE_NAME = "hygeia.sqlite_sanitizer.sanitize_database_generic"
MAX_RECORDED_FINDINGS = 100
AUDIT_VERSION = 1
FINAL_GATE_NAME = "pipeline-final"

# This metadata is evidence about the database contents, not durable database
# configuration.  Any supported write must remove it in that same transaction.
_TRUST_METADATA_KEYS = (
    "hygeia_status",
    "hygeia_engine",
    "hygeia_audit",
    "hygeia_skipped",
    "hygeia_warning",
)

# HYGEIA's generic SQLite engine consumes regex_patterns, not context_patterns.
# Promote HYGEIA's self-labelled password pattern and add narrowly labelled
# ICARUS extensions for common credential formats observed in intelligence data.
_ICARUS_PATTERN_EXTENSIONS = {
    # HYGEIA's bare floating-point GPS regex also matches fractional seconds
    # in ISO timestamps. Require an explicit location label in ICARUS data.
    "gps_coord": re.compile(
        r"\b(?:latitude|longitude|lat|lng|lon|gps(?:_coord)?)\s*[:=]\s*"
        r"-?\d{1,3}\.\d{4,}",
        re.IGNORECASE,
    ),
    "uuid": re.compile(
        r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b",
        re.IGNORECASE,
    ),
    "username_path": re.compile(r"/(?:Users|home)/[^/\s]+"),
    "username_path_win": re.compile(r"C:\\Users\\[^\\\s]+", re.IGNORECASE),
    "aws_secret_key_kv": re.compile(
        r"\b(?:AWS_SECRET_ACCESS_KEY|aws_secret(?:_access)?_key)\s*[:=]\s*"
        r"[A-Za-z0-9/+=]{20,}",
        re.IGNORECASE,
    ),
    "private_key_kv": re.compile(
        r"\b(?:private[_ -]?key|wireguard[_ -]?key)\s*[:=]\s*"
        r"[A-Za-z0-9+/]{32,}={0,2}",
        re.IGNORECASE,
    ),
    "token_kv": re.compile(
        r"\b(?:api[_ -]?key|access[_ -]?token|auth[_ -]?token|bearer[_ -]?token|"
        r"client[_ -]?secret)\s*[:=]\s*(?:Bearer\s+)?[^\s,;]+",
        re.IGNORECASE,
    ),
    "bearer_token": re.compile(r"\bBearer\s+[A-Za-z0-9._~+/=-]{16,}", re.IGNORECASE),
}


# Column scoping (issue #76).
#
# ICARUS databases are overwhelmingly a *filesystem catalog*: paths, filenames,
# versions, bundle ids, arches, and enums. HYGEIA's generic value-content
# patterns (email/ip_v4/swift_bic/uuid/phone/url/...) were designed to find
# secrets inside free-text *values*; applied to structural path/name columns
# they are dominated by false positives — library version strings match
# `ip_v4` (`6.6.87.2`), uppercase filename fragments match `swift_bic`
# (`RTKVHD64.SYS`), systemd `foo@.service` units match `email`, and GUID
# filenames match `uuid`. On a real rootfs that is thousands of false matches:
# the fail-closed post-gate aborts the build, and any redaction that *did* land
# would corrupt the catalog (`/lib/modules/6.6.87.2-.../` -> `[REDACTED_IP_V4]`).
#
# So value-content patterns apply ONLY to genuinely free-text/value columns;
# structural columns get only path-shaped and label-anchored-secret patterns,
# which cannot false-match a version number, filename, or GUID.

# Patterns safe to apply to structural (path/name) columns: path-specific, or
# label-anchored key/value secret patterns that require an explicit `key = ...`
# context and therefore never match a bare filename/version/identifier.
_PATH_SAFE_PATTERN_NAMES = frozenset({
    "username_path",
    "username_path_win",
    "password_kv",
    "aws_secret_key_kv",
    "private_key_kv",
    "token_kv",
    "bearer_token",
})

# Known core tables. A table not in this set is an extension/unknown table and
# is scanned with the FULL pattern set (see `_patterns_for_column`) so extension
# free-text is never silently under-scanned (#42) — only the known, high-volume
# structural columns of the core schema are exempted from value-content patterns.
_KNOWN_TABLES = frozenset({
    "metadata", "files", "binaries", "daemons", "entitlements",
    "sandbox_profiles", "sandbox_rules", "kexts", "frameworks", "versions",
    "observations", "atoms", "bags", "bag_atoms", "resolution_event_log",
    "match_candidates", "mach_services",
})

# Free-text / JSON payload columns of the core schema where real secrets or PII
# can live and where the full pattern set (including HYGEIA's value-content
# patterns) must apply. Every OTHER column of a known table is structural.
_VALUE_COLUMNS = frozenset({
    ("observations", "properties"),
    ("atoms", "properties"),
    ("match_candidates", "features"),
    ("versions", "metadata"),
    ("entitlements", "value"),
    ("metadata", "value"),
    ("resolution_event_log", "reason"),
    ("sandbox_profiles", "raw_sbpl"),
})


# FTS virtual tables mirror content columns of their source table and must be
# scoped identically (else a structural path re-flagged via its FTS mirror would
# reintroduce the #76 false positives).
_FTS_SOURCE = {"files_fts": "files", "daemons_fts": "daemons", "atoms_fts": "atoms"}


def _patterns_for_column(table: str, column: str, regex_patterns: Dict[str, Any]) -> Dict[str, Any]:
    """Scope patterns to a column.

    Value columns and any column of an unknown/extension table get the full
    pattern set. Only the known, structural columns of the core schema — paths,
    filenames, versions, ids, enums — are limited to path-safe patterns, so
    value-content patterns (email/ip_v4/swift_bic/uuid/...) can never
    false-match a version number, filename, or GUID (#76). FTS mirror tables
    inherit their source table's scope.
    """
    table = _FTS_SOURCE.get(table, table)
    if table not in _KNOWN_TABLES or (table, column) in _VALUE_COLUMNS:
        return regex_patterns
    return {
        name: pattern
        for name, pattern in regex_patterns.items()
        if name in _PATH_SAFE_PATTERN_NAMES
    }


class HygeiaUnavailableError(RuntimeError):
    """Raised when the mandatory HYGEIA dependency cannot be loaded."""


class SanitizationError(RuntimeError):
    """Raised when sanitization or its mandatory verification gate fails."""


def require_hygeia() -> Dict[str, str]:
    """Return active engine metadata or fail before a build modifies its output."""
    if (
        not _HAS_HYGEIA_PACKAGE
        or PatternRegistry is None
        or get_default_registry is None
        or sanitize_database_generic is None
        or _hygeia_is_false_positive is None
    ):
        raise HygeiaUnavailableError(
            "HYGEIA is required for sanitized builds but its canonical SQLite API "
            "could not be loaded; install the pinned dependency or explicitly use "
            "--skip-hygeia for an unsanitized output"
        ) from None
    return {"engine": ENGINE_NAME, "version": _HYGEIA_VERSION, "mode": "fail-closed"}


def _build_registry():
    """Build a HYGEIA registry that preserves ICARUS ontology column semantics."""
    require_hygeia()
    default = get_default_registry()
    regex_patterns = dict(default.regex_patterns)

    # This context regex contains its own label, so it remains self-gating when
    # promoted for the generic SQLite sanitizer.
    password_pattern = default.context_patterns.get("password_kv")
    if password_pattern is not None:
        regex_patterns["password_kv"] = password_pattern[0]
    regex_patterns.update(_ICARUS_PATTERN_EXTENSIONS)

    descriptions = dict(default.pattern_descriptions)
    descriptions.update(
        {
            name: "ICARUS labelled-secret extension"
            for name in _ICARUS_PATTERN_EXTENSIONS
        }
    )

    # HYGEIA's default sensitive-column list includes generic ontology fields
    # such as `name`. Direct-column redaction would destroy ICARUS's product
    # data, so this registry uses HYGEIA's value patterns but no whole-column or
    # whole-table deletion rules.
    return PatternRegistry(
        regex_patterns=regex_patterns,
        context_patterns={},
        sensitive_columns=set(),
        sensitive_json_keys=set(),
        pii_tables=set(),
        active_categories=set(default.active_categories),
        pattern_descriptions=descriptions,
    )


def _path_safe_registry(full_registry):
    """Derive a registry carrying only the structural-column-safe patterns.

    HYGEIA's generic engine applies every registry pattern to every non-safe
    text column and cannot be told to scope by column (`SAFE_COLUMNS` is
    hardcoded). Handing it only the path-safe patterns lets it run as the
    canonical engine — redacting usernames and label-anchored secrets, plus its
    secure_delete VACUUM — without ever touching a version number or filename.
    """
    return PatternRegistry(
        regex_patterns={
            name: pattern
            for name, pattern in full_registry.regex_patterns.items()
            if name in _PATH_SAFE_PATTERN_NAMES
        },
        context_patterns={},
        sensitive_columns=set(),
        sensitive_json_keys=set(),
        pii_tables=set(),
        active_categories=set(full_registry.active_categories),
        pattern_descriptions=dict(full_registry.pattern_descriptions),
    )


def _redact_scoped(db_path: Path, registry) -> int:
    """Deterministically redact every column with its column-scoped patterns.

    This is ICARUS's ontology-aware redaction pass. It applies the full pattern
    set to free-text/value columns and only path-safe patterns to structural
    columns (see `_patterns_for_column`), so version numbers, filenames, and
    GUIDs are never corrupted. Unlike HYGEIA's generic engine it handles each
    row independently — a per-row failure never abandons the rest of a column's
    batch (HYGEIA#39) — and a redaction skipped here is caught by the
    fail-closed post-gate. False positives are suppressed with the same HYGEIA
    oracle the verifier uses, so redaction and verification always agree.
    """
    redacted = 0
    conn = sqlite3.connect(str(db_path))
    try:
        conn.execute("PRAGMA secure_delete = ON")
        for table, columns in _get_text_columns(conn).items():
            # FTS virtual tables are rebuilt from the redacted source by
            # _rebuild_fts_indexes; never UPDATE them directly.
            if table in _FTS_SOURCE:
                continue
            for column in columns:
                patterns = _patterns_for_column(table, column, registry.regex_patterns)
                if not patterns:
                    continue
                location = f"{db_path.name}.{table}.{column}"
                rows = conn.execute(
                    f"SELECT rowid, {_quote_ident(column)} FROM {_quote_ident(table)} "  # nosec B608 - identifiers are double-quoted and escaped
                    f"WHERE {_quote_ident(column)} IS NOT NULL"
                ).fetchall()
                for rowid, value in rows:
                    if not isinstance(value, str) or not value:
                        continue
                    new_value = value
                    for name, pattern in patterns.items():
                        def _replace(match, _name=name):
                            text = match.group(0)
                            if _hygeia_is_false_positive(location, _name, text):
                                return text
                            return f"[REDACTED_{_name.upper()}]"

                        new_value = pattern.sub(_replace, new_value)
                    if new_value != value:
                        try:
                            conn.execute(
                                f"UPDATE {_quote_ident(table)} SET {_quote_ident(column)} = ? "  # nosec B608 - identifiers are double-quoted and escaped
                                f"WHERE rowid = ?",
                                (new_value, rowid),
                            )
                            redacted += 1
                        except sqlite3.Error:
                            # Do not abandon the batch (contrast HYGEIA#39); the
                            # unredacted row is caught by the post-gate below.
                            continue
        conn.commit()
    finally:
        conn.close()
    return redacted


def _quote_ident(name: str) -> str:
    """Double-quote a SQL identifier and escape embedded quotes."""
    return '"' + name.replace('"', '""') + '"'


def _get_text_columns(conn: sqlite3.Connection) -> Dict[str, List[str]]:
    """Return scannable columns from every user-facing table, including metadata/FTS."""
    result: Dict[str, List[str]] = {}
    tables = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
    ).fetchall()

    fts_tables = {"files_fts", "daemons_fts", "atoms_fts"}
    fts_shadow_prefixes = tuple(f"{name}_" for name in fts_tables)
    for (table_name,) in tables:
        # The public FTS virtual table exposes the searchable content. Scanning
        # its internal shadow tables would duplicate findings and inspect BLOBs.
        if table_name.startswith(fts_shadow_prefixes):
            continue

        columns = conn.execute(
            f"PRAGMA table_info({_quote_ident(table_name)})"  # nosec B608 - identifier is double-quoted and embedded quotes are escaped
        ).fetchall()
        text_cols = []
        for col in columns:
            declared_type = (col[2] or "").upper()
            if not declared_type or any(
                text_type in declared_type for text_type in ("TEXT", "VARCHAR", "CHAR", "CLOB")
            ):
                text_cols.append(col[1])

        if text_cols:
            result[table_name] = text_cols
    return result


def _fingerprint(value: str, key: bytes) -> str:
    """Create a per-run, non-reversible fingerprint for safe correlation."""
    digest = hmac.new(key, value.encode("utf-8", "surrogatepass"), hashlib.sha256)
    return f"hmac-sha256:{digest.hexdigest()}"


def _scan_database(db_path: Path, registry, fingerprint_key: bytes) -> Dict[str, Any]:
    """Scan with HYGEIA patterns and return locations/fingerprints, never matches."""
    if not db_path.exists() or not db_path.is_file():
        raise SanitizationError("Sanitization target is not an existing database file")

    conn = sqlite3.connect(str(db_path))
    findings = []
    pattern_counts: Dict[str, int] = {}
    checked_rows = 0
    total_findings = 0
    try:
        for table, columns in _get_text_columns(conn).items():
            quoted_table = _quote_ident(table)
            select_list = ", ".join(_quote_ident(column) for column in columns)
            try:
                cursor = conn.execute(
                    f"SELECT rowid, {select_list} FROM {quoted_table}"  # nosec B608 - all identifiers are double-quoted and embedded quotes are escaped
                )
            except sqlite3.Error:
                raise SanitizationError(
                    f"Fail-closed verification could not scan table {table!r}"
                ) from None

            scoped = [
                (column, _patterns_for_column(table, column, registry.regex_patterns))
                for column in columns
            ]
            for row in cursor:
                checked_rows += 1
                for index, (column, patterns) in enumerate(scoped):
                    value = row[index + 1]
                    if not isinstance(value, str) or not value:
                        continue
                    for pattern_name, pattern in patterns.items():
                        for match in pattern.finditer(value):
                            match_text = match.group(0)
                            location = f"{db_path.name}.{table}.{column}"
                            if _hygeia_is_false_positive(
                                location, pattern_name, match_text
                            ):
                                continue
                            total_findings += 1
                            pattern_counts[pattern_name] = pattern_counts.get(pattern_name, 0) + 1
                            if len(findings) < MAX_RECORDED_FINDINGS:
                                findings.append(
                                    {
                                        "table": table,
                                        "column": column,
                                        "rowid": row[0],
                                        "pattern": pattern_name,
                                        "fingerprint": _fingerprint(match_text, fingerprint_key),
                                    }
                                )
    finally:
        conn.close()

    return {
        "passed": total_findings == 0,
        "checked_rows": checked_rows,
        "findings": findings,
        "total_findings": total_findings,
        "findings_truncated": total_findings > len(findings),
        "patterns_found": dict(sorted(pattern_counts.items())),
    }


def _record_finalized_audit(db_path: Path, engine: Dict[str, str], audit: Dict[str, Any]) -> None:
    """Persist evidence only after the pipeline's final post-write gate succeeds."""
    payload = {
        "audit_version": AUDIT_VERSION,
        "engine": engine,
        "verified": True,
        "gate": FINAL_GATE_NAME,
        "post_gate": {"passed": True, "total_findings": 0},
        "checked_rows": audit["checked_rows"],
        "total_findings": audit["total_findings"],
        "patterns_found": audit["patterns_found"],
        "findings": audit["findings"],
        "findings_truncated": audit["findings_truncated"],
    }
    conn = sqlite3.connect(str(db_path))
    try:
        conn.execute(
            "DELETE FROM metadata WHERE key IN ('hygeia_skipped', 'hygeia_warning')"
        )
        conn.execute(
            "INSERT OR REPLACE INTO metadata (key, value) VALUES (?, ?)",
            ("hygeia_engine", json.dumps(engine, sort_keys=True)),
        )
        conn.execute(
            "INSERT OR REPLACE INTO metadata (key, value) VALUES (?, ?)",
            ("hygeia_audit", json.dumps(payload, sort_keys=True, separators=(",", ":"))),
        )
        conn.execute(
            "INSERT OR REPLACE INTO metadata (key, value) VALUES (?, ?)",
            ("hygeia_status", "verified"),
        )
        conn.commit()
    finally:
        conn.close()


_FTS_TABLES = ("files_fts", "daemons_fts", "atoms_fts")


def _rebuild_fts_indexes(db_path: Path) -> None:
    """Rebuild every FTS index so no secret can survive a stale FTS row.

    HYGEIA's generic sanitizer redacts content-table rows via UPDATE. Older
    ICARUS databases (schema versions built before an AFTER UPDATE trigger
    existed for a given content table) never re-sync their FTS shadow tables
    on UPDATE, so a redacted value can remain searchable in the FTS index
    regardless of how thoroughly the content table itself was cleaned. This
    runs unconditionally, after every sanitize, on every FTS table present in
    the database — it does not depend on which triggers the database has.
    Fails closed: any error rebuilding an index aborts sanitization.
    """
    conn = sqlite3.connect(str(db_path))
    try:
        existing = {
            row[0]
            for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name IN "
                "('files_fts', 'daemons_fts', 'atoms_fts')"
            ).fetchall()
        }
        for fts_table in _FTS_TABLES:
            if fts_table not in existing:
                continue
            quoted = _quote_ident(fts_table)
            try:
                conn.execute(f"INSERT INTO {quoted}({quoted}) VALUES('rebuild')")  # nosec B608 - identifier is from a fixed allowlist, double-quoted and escaped
            except sqlite3.Error:
                raise SanitizationError(
                    f"Fail-closed verification could not rebuild FTS index {fts_table!r}"
                ) from None
        conn.commit()
    finally:
        conn.close()


def _has_valid_verified_audit(rows: Dict[str, str]) -> bool:
    """Return whether metadata contains the versioned successful-gate evidence."""
    try:
        engine = json.loads(rows["hygeia_engine"])
        audit = json.loads(rows["hygeia_audit"])
    except (KeyError, TypeError, ValueError):
        return False
    expected_engine = {
        "engine": ENGINE_NAME,
        "version": _HYGEIA_VERSION,
        "mode": "fail-closed",
    }
    return (
        _HYGEIA_VERSION != "unavailable"
        and engine == expected_engine
        and isinstance(audit, dict)
        and audit.get("audit_version") == AUDIT_VERSION
        and audit.get("engine") == engine
        and audit.get("verified") is True
        and audit.get("gate") == FINAL_GATE_NAME
        and audit.get("post_gate") == {"passed": True, "total_findings": 0}
        and isinstance(audit.get("checked_rows"), int)
        and audit.get("total_findings") == 0
        and audit.get("patterns_found") == {}
        and audit.get("findings") == []
        and audit.get("findings_truncated") is False
    )


def sanitization_status(db_path: Path, *, immutable: bool = False) -> str:
    """Classify a database's sanitization posture from its metadata markers.

    Returns one of: ``verified`` (post-gate passed), ``skipped``
    (built with --skip-hygeia — unsanitized by explicit choice), ``failed``
    (sanitization ran but did not verify — not safe to share), or ``unknown``
    (no completion marker: an incomplete/crashed build or a legacy database).
    """
    path = Path(db_path)
    if not path.exists():
        return "unknown"
    try:
        uri = f"file:{path}?mode=ro"
        if immutable:
            uri += "&immutable=1"
        conn = sqlite3.connect(uri, uri=True)
    except sqlite3.Error:
        return "unknown"
    try:
        rows = dict(
            conn.execute(
                "SELECT key, value FROM metadata WHERE key IN "
                "('hygeia_status', 'hygeia_skipped', 'hygeia_engine', 'hygeia_audit')"
            ).fetchall()
        )
    except sqlite3.Error:
        return "unknown"
    finally:
        conn.close()
    status = rows.get("hygeia_status", "") or ""
    if status.startswith("FAILED"):
        return "failed"
    if status == "verified" and _has_valid_verified_audit(rows):
        return "verified"
    if rows.get("hygeia_skipped") == "true":
        return "skipped"
    return "unknown"


def sanitization_allows_default_consumer(status: str) -> bool:
    """Return whether the documented default consumer policy permits ``status``."""
    return status in {"verified", "skipped"}


def invalidate_sanitization(conn: sqlite3.Connection) -> None:
    """Remove content-coupled trust evidence on an existing write transaction.

    Deliberately does not commit: callers that mutate content must commit this
    deletion together with their mutation, so a stale verified marker cannot
    survive a successful write.
    """
    placeholders = ", ".join("?" for _ in _TRUST_METADATA_KEYS)
    conn.execute(
        f"DELETE FROM metadata WHERE key IN ({placeholders})",  # nosec B608 - placeholders are generated from a fixed tuple
        _TRUST_METADATA_KEYS,
    )


def mark_sanitization_failed(db_path: Path) -> None:
    """Invalidate prior clean markers when a later mandatory gate fails."""
    conn = sqlite3.connect(str(db_path))
    try:
        invalidate_sanitization(conn)
        conn.execute(
            "INSERT OR REPLACE INTO metadata (key, value) VALUES (?, ?)",
            ("hygeia_status", "FAILED: output is not safe to share"),
        )
        conn.commit()
    finally:
        conn.close()


def sanitize_output(db_path: Path) -> Dict[str, Any]:
    """Sanitize an ICARUS database with HYGEIA and enforce a clean post-gate."""
    db_path = Path(db_path)
    engine = require_hygeia()
    registry = _build_registry()
    fingerprint_key = secrets.token_bytes(32)
    before = _scan_database(db_path, registry, fingerprint_key)

    # ICARUS ontology-aware redaction (issue #76): the full pattern set on
    # free-text/value columns, only path-safe patterns on structural columns,
    # deterministic per-row so no batch is abandoned (HYGEIA#39).
    redacted = _redact_scoped(db_path, registry)

    # HYGEIA canonical engine, scoped to the path-safe patterns so it can never
    # corrupt a structural column; it also runs the secure_delete VACUUM that
    # purges pre-redaction values from freed pages.
    try:
        result = sanitize_database_generic(db_path, registry=_path_safe_registry(registry))
    except Exception:
        raise SanitizationError("HYGEIA raised an error while sanitizing the database") from None

    if not isinstance(result, dict) or result.get("error"):
        raise SanitizationError("HYGEIA reported a sanitization failure") from None
    if result.get("integrity_post") is not True:
        raise SanitizationError("HYGEIA did not verify database integrity after sanitization")

    _rebuild_fts_indexes(db_path)

    after = _scan_database(db_path, registry, fingerprint_key)
    if not after["passed"]:
        residual_types = ", ".join(after["patterns_found"].keys())
        raise SanitizationError(
            f"Post-sanitize verification found {after['total_findings']} residual "
            f"finding(s) of type(s): {residual_types}"
        )

    return {
        "engine": engine,
        "checked_rows": before["checked_rows"],
        "redacted": redacted + int(result.get("rows_redacted", 0)),
        "patterns_found": before["patterns_found"],
        "findings": before["findings"],
        "total_findings": before["total_findings"],
        "findings_truncated": before["findings_truncated"],
        "verified": True,
        "post_sanitize_findings": 0,
    }


def verify_clean(db_path: Path) -> Dict[str, Any]:
    """Verify with HYGEIA's registry without ever returning raw matched values."""
    require_hygeia()
    registry = _build_registry()
    return _scan_database(Path(db_path), registry, secrets.token_bytes(32))


def using_standalone_hygeia() -> bool:
    """Return whether HYGEIA's canonical SQLite API is available."""
    return _HAS_HYGEIA_PACKAGE
