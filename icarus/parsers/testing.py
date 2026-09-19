"""ICARUS Parser Testing Harness — quality gates for parser production tier."""

import hashlib
import json
import sqlite3
import tempfile
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import List

from icarus.core.schema import open_db
from icarus.parsers.base import BaseParser
from icarus.parsers.manifest import ParserManifest


def resolve_test_resource(reference: str) -> Path:
    """Resolve a manifest test resource from the installed parser package.

    Absolute paths remain supported for third-party/development manifests.
    Built-in manifests use package-relative ``selftest/...`` references, so
    ``icarus parser test`` never depends on the current working directory or
    on a source checkout containing ``tests/``.
    """
    path = Path(reference)
    if path.is_absolute():
        return path
    return Path(__file__).parent / path


@dataclass
class HarnessResult:
    test_name: str
    passed: bool
    message: str = ""
    details: dict = field(default_factory=dict)


class ParserTestHarness:
    """Four mandatory tests for parser production tier."""

    # initialize_database() owns these bookkeeping tables. They describe the
    # harness/run rather than parser output, so they are intentionally outside
    # the idempotency contract. SQLite's FTS virtual tables and shadow tables
    # are also excluded as derived indexes; their source entity tables remain
    # in the snapshot.
    _IDEMPOTENCY_METADATA_TABLES = {"metadata", "versions", "sqlite_sequence"}

    def __init__(self, parser: BaseParser, manifest: ParserManifest, fixtures_dir: Path):
        if not fixtures_dir.exists():
            raise FileNotFoundError(f"Fixtures directory not found: {fixtures_dir}")
        self.parser = parser
        self.manifest = manifest
        self.fixtures_dir = fixtures_dir
        self._last_relationship_stats: dict = {}

    def test_golden_output(self) -> HarnessResult:
        """Run parser on fixture; compare entity counts, a deterministic
        content fingerprint, and the golden file's own declared zero_pii /
        has_relationships / observation_count fields (checked only when the
        golden file declares them, so older golden files without those keys
        still validate on counts alone)."""
        golden_path = self.manifest.tests.get("golden_output") if self.manifest.tests else None
        if not golden_path:
            return HarnessResult("golden_output", False, "No golden_output path in manifest")

        golden_file = Path(golden_path)
        if not golden_file.is_absolute():
            golden_file = resolve_test_resource(golden_path)
        if not golden_file.exists():
            return HarnessResult("golden_output", False, f"Golden file not found: {golden_file}")

        golden = json.loads(golden_file.read_text())
        db_path = self._run_parser()

        try:
            conn = open_db(db_path)
            try:
                actual_counts = {}
                for table in golden.get("entity_counts", {}):
                    try:
                        count = conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]  # nosec B608 - table keys come from the in-repo tests/golden/*.json fixture, not external input
                        actual_counts[table] = count
                    except sqlite3.OperationalError:
                        actual_counts[table] = 0

                expected = golden["entity_counts"]
                if actual_counts != expected:
                    return HarnessResult(
                        "golden_output", False,
                        f"Mismatch: expected {expected}, got {actual_counts}",
                        {"expected": expected, "actual": actual_counts},
                    )

                mismatches = []

                if "content_fingerprint" in golden:
                    actual_fp = self._content_fingerprint(conn, list(expected.keys()))
                    if actual_fp != golden["content_fingerprint"]:
                        mismatches.append(
                            f"content_fingerprint mismatch: expected "
                            f"{golden['content_fingerprint']}, got {actual_fp}"
                        )

                if "observation_count" in golden:
                    try:
                        actual_obs = conn.execute(
                            "SELECT COUNT(*) FROM observations"
                        ).fetchone()[0]
                    except sqlite3.OperationalError:
                        actual_obs = 0
                    if actual_obs != golden["observation_count"]:
                        mismatches.append(
                            f"observation_count mismatch: expected "
                            f"{golden['observation_count']}, got {actual_obs}"
                        )

                if "zero_pii" in golden:
                    from icarus.integrations.hygeia import verify_clean
                    actual_zero_pii = verify_clean(db_path)["passed"]
                    if actual_zero_pii != golden["zero_pii"]:
                        mismatches.append(
                            f"zero_pii mismatch: golden declares {golden['zero_pii']}, "
                            f"actual {actual_zero_pii}"
                        )

                if "has_relationships" in golden:
                    # _run_parser() above already ran extract_relationships once;
                    # reuse those stats instead of re-running it (a second call
                    # against the same DB is not guaranteed to be idempotent).
                    rel_stats = self._last_relationship_stats
                    actual_has_rel = bool(rel_stats.get("linked", 0))
                    if actual_has_rel != golden["has_relationships"]:
                        mismatches.append(
                            f"has_relationships mismatch: golden declares "
                            f"{golden['has_relationships']}, actual {actual_has_rel}"
                        )
            finally:
                conn.close()

            if mismatches:
                return HarnessResult("golden_output", False, "; ".join(mismatches))
            return HarnessResult(
                "golden_output", True, "Entity counts and declared fields match golden file"
            )
        finally:
            db_path.unlink(missing_ok=True)

    @staticmethod
    def _content_fingerprint(conn: sqlite3.Connection, tables: List[str]) -> str:
        """Deterministic sha256 fingerprint of row content across `tables`.

        Excludes the `id` autoincrement primary key (a storage detail, not
        content) from both the selected columns and the ordering, so the
        fingerprint reflects only actual field values and is stable
        regardless of row insertion order.
        """
        hasher = hashlib.sha256()
        for table in sorted(tables):
            try:
                cols = [
                    r[1] for r in conn.execute(f"PRAGMA table_info({table})").fetchall()
                    if r[1] != "id"
                ]
            except sqlite3.OperationalError:
                continue
            if not cols:
                continue
            col_list = ", ".join(cols)
            try:
                rows = conn.execute(
                    f"SELECT {col_list} FROM {table} ORDER BY {col_list}"  # nosec B608 - table/col_list sourced from golden-fixture keys and this table's own PRAGMA table_info(), not external input
                ).fetchall()
            except sqlite3.OperationalError:
                continue
            hasher.update(table.encode())
            for row in rows:
                hasher.update(repr(row).encode())
        return hasher.hexdigest()

    def test_schema_conformance(self) -> HarnessResult:
        """All emitted entities are in tables declared in manifest.produces
        .entity_types, and (when the manifest declares event_types) every
        observation.event_type produced on the fixture is one of them."""
        db_path = self._run_parser()
        try:
            conn = open_db(db_path)
            try:
                declared = set(self.manifest.entity_types)
                violations = []

                all_tables = [
                    r[0] for r in conn.execute(
                        "SELECT name FROM sqlite_master WHERE type='table'"
                    ).fetchall()
                ]
                skip = {"metadata", "versions", "observations", "atoms", "bags",
                        "bag_atoms", "resolution_event_log", "match_candidates",
                        "sqlite_sequence"}
                for table in all_tables:
                    if table in skip or table.endswith("_fts") or "_fts_" in table:
                        continue
                    if table not in declared:
                        count = conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]  # nosec B608 - table read directly from sqlite_master of the harness's own temp DB above
                        if count > 0:
                            violations.append(f"{table} has {count} rows but not in produces")

                declared_event_types = self.manifest.produces.get("event_types")
                if declared_event_types is not None:
                    try:
                        actual_event_types = {
                            r[0] for r in conn.execute(
                                "SELECT DISTINCT event_type FROM observations"
                            ).fetchall()
                        }
                    except sqlite3.OperationalError:
                        actual_event_types = set()
                    undeclared = actual_event_types - set(declared_event_types)
                    if undeclared:
                        violations.append(
                            "observations produced event_type(s) not in "
                            f"manifest.produces.event_types: {sorted(undeclared)}"
                        )
            finally:
                conn.close()

            if violations:
                return HarnessResult("schema_conformance", False, "; ".join(violations))
            return HarnessResult("schema_conformance", True, "All entities in declared tables")
        finally:
            db_path.unlink(missing_ok=True)

    def test_idempotency(self) -> HarnessResult:
        """Run both parser phases twice and compare their complete output."""
        db_path = self._run_parser()
        try:
            conn = open_db(db_path)
            try:
                before = self._output_snapshot(conn)
            finally:
                conn.close()

            self.parser.extract_entities(self.fixtures_dir, db_path)
            self.parser.extract_relationships(self.fixtures_dir, db_path)

            conn = open_db(db_path)
            try:
                after = self._output_snapshot(conn)
            finally:
                conn.close()

            changed = sorted(
                table
                for table in before.keys() | after.keys()
                if before.get(table, []) != after.get(table, [])
            )
            if not changed:
                return HarnessResult(
                    "idempotency", True, "Second complete parser run produced no changes"
                )

            evidence = {
                table: self._snapshot_difference(before.get(table, []), after.get(table, []))
                for table in changed
            }
            summary = ", ".join(
                f"{table} ({len(before.get(table, []))} -> "
                f"{len(after.get(table, []))} rows)"
                for table in changed
            )
            return HarnessResult(
                "idempotency", False,
                f"Output changed in tables: {summary}",
                {"changed_tables": evidence},
            )
        finally:
            db_path.unlink(missing_ok=True)

    @classmethod
    def _output_snapshot(cls, conn: sqlite3.Connection) -> dict:
        """Return canonical, row-order-independent parser output by table."""
        tables = conn.execute(
            "SELECT name, sql FROM sqlite_master WHERE type='table' ORDER BY name"
        ).fetchall()
        snapshot = {}
        for table, create_sql in tables:
            if table in cls._IDEMPOTENCY_METADATA_TABLES:
                continue
            if table.endswith("_fts") or "_fts_" in table:
                continue
            if create_sql and create_sql.lstrip().upper().startswith("CREATE VIRTUAL TABLE"):
                continue
            quoted = '"' + table.replace('"', '""') + '"'
            rows = conn.execute(
                f"SELECT * FROM {quoted}"  # nosec B608 - identifier comes from sqlite_master
            ).fetchall()
            canonical_rows = [cls._canonical_row(row) for row in rows]
            snapshot[table] = sorted(canonical_rows)
        return snapshot

    @staticmethod
    def _canonical_row(row: tuple) -> str:
        """Serialize SQLite values deterministically, including JSON objects."""
        values = []
        for value in row:
            if isinstance(value, bytes):
                values.append({"type": "bytes", "value": value.hex()})
            elif isinstance(value, str):
                normalized = value
                if value.lstrip().startswith(("{", "[")):
                    try:
                        normalized = json.dumps(
                            json.loads(value), sort_keys=True, separators=(",", ":")
                        )
                    except (json.JSONDecodeError, TypeError):
                        pass
                values.append({"type": "text", "value": normalized})
            else:
                values.append({"type": type(value).__name__, "value": value})
        return json.dumps(values, sort_keys=True, separators=(",", ":"))

    @staticmethod
    def _snapshot_difference(before: List[str], after: List[str]) -> dict:
        """Summarize a changed table with bounded before/after row evidence."""
        removed = list((Counter(before) - Counter(after)).elements())
        added = list((Counter(after) - Counter(before)).elements())
        return {
            "before_count": len(before),
            "after_count": len(after),
            "before_sha256": hashlib.sha256("\n".join(before).encode()).hexdigest(),
            "after_sha256": hashlib.sha256("\n".join(after).encode()).hexdigest(),
            "removed_rows": removed[:3],
            "added_rows": added[:3],
        }

    def test_zero_pii(self) -> HarnessResult:
        """Run HYGEIA verify_clean() on output — must return passed: True."""
        from icarus.integrations.hygeia import verify_clean

        db_path = self._run_parser()
        try:
            result = verify_clean(db_path)
            if result["passed"]:
                return HarnessResult("zero_pii", True, "No PII detected")
            return HarnessResult(
                "zero_pii", False,
                f"{result['total_findings']} PII findings",
                {"findings": result["findings"][:5]},
            )
        finally:
            db_path.unlink(missing_ok=True)

    def run_all(self) -> List[HarnessResult]:
        results = [
            self.test_golden_output(),
            self.test_schema_conformance(),
            self.test_idempotency(),
            self.test_zero_pii(),
        ]
        for r in results:
            status = "PASS" if r.passed else "FAIL"
            print(f"  [{status}] {r.test_name}: {r.message}")
        return results

    def _run_parser(self) -> Path:
        """Run the parser on fixtures and return the DB path."""
        from icarus.core.schema import initialize_database

        f = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        db_path = Path(f.name)
        f.close()
        # A host-absolute fixture path (for example /Users/runner/...) is
        # itself source-identifying PII. Keep harness metadata neutral so the
        # zero-PII gate measures parser output instead of the CI runner's home
        # directory. Production builds still record and sanitize the real path.
        initialize_database(db_path, {"source": "parser-test-fixture"})
        self.parser.extract_entities(self.fixtures_dir, db_path)
        # Relationships phase can emit its own observations/entities (e.g.
        # event_type values only produced while linking entities together).
        # Run it here so every gate that consumes _run_parser's DB — not just
        # test_golden_output's optional has_relationships check — sees that
        # output and can catch declared-vs-emitted drift from this phase.
        self._last_relationship_stats = self.parser.extract_relationships(
            self.fixtures_dir, db_path
        )
        return db_path
