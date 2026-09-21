"""
ICARUS Differ — Cross-version intelligence comparison.

Compares two ICARUS databases and identifies what changed between versions:
added entities, removed entities, modified entities, and relationship changes.

Five diff categories, every one of which ``full_diff()`` produces:
  ADDITION        — entity exists in new, not in old
  DELETION        — entity exists in old, not in new
  PROPERTY_CHANGE — same entity, different attribute value (files: sha256, or
                    size when either side's hash is NULL)
  STRUCTURAL      — relationship topology changed (edges, not nodes)
  RESOLUTION_CHANGE — entity-resolution (bag) outcomes changed between versions

All comparisons key on stable NATURAL identifiers; local AUTOINCREMENT ids
(file_id, binary_id, bag_id, atom ids, …) are never compared across databases —
they are assigned per-build and carry no cross-version meaning.
"""

import enum
import json
import sqlite3
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from icarus.core import validate_column, validate_table
from icarus.core.markdown import sanitize_markdown

DIFF_DISPLAY_LIMIT = 50

def _md_sanitize(value: Any) -> str:
    """Backward-compatible alias for the shared Markdown sanitization policy."""
    return sanitize_markdown(value)


def canonical_diff_value(value: Any) -> str:
    """Render a valid diff value as compact, type-preserving JSON text.

    This shared representation keeps text consumers aligned with the typed JSON
    diff: ``None`` is ``null``, booleans stay lowercase, strings stay quoted,
    and collections are sorted deterministically. Boundary-specific renderers
    may then escape this text without replacing a valid value with a placeholder.
    """
    try:
        return json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
            allow_nan=False,
        )
    except (TypeError, ValueError) as exc:
        raise ValueError("changed field values must be JSON serializable") from exc


def changed_field_values(item: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Return one labeled old/new value for every declared changed field.

    Changed records use the contract introduced for mutable observations:
    ``changed_fields`` lists field names, and every name has matching
    ``old_<field>`` and ``new_<field>`` values. Consumers must reject a record
    that does not meet that contract instead of inventing placeholder values.
    """
    field_names = item.get("changed_fields")
    if not isinstance(field_names, list) or not field_names:
        raise ValueError("expected a non-empty changed_fields list")

    fields = []
    seen = set()
    for field_name in field_names:
        if not isinstance(field_name, str) or not field_name:
            raise ValueError("changed_fields entries must be non-empty strings")
        if field_name in seen:
            raise ValueError("changed_fields entries must be unique")
        seen.add(field_name)
        old_name = f"old_{field_name}"
        new_name = f"new_{field_name}"
        if old_name not in item or new_name not in item:
            raise ValueError(
                f"{field_name!r} requires {old_name!r} and {new_name!r}"
            )
        fields.append({
            "field": field_name,
            "old_value": item[old_name],
            "new_value": item[new_name],
        })
    return fields


class DiffCategory(enum.Enum):
    ADDITION = "addition"
    DELETION = "deletion"
    PROPERTY_CHANGE = "property_change"
    STRUCTURAL = "structural"
    RESOLUTION_CHANGE = "resolution_change"


@dataclass
class DiffResult:
    """Result of a cross-version comparison."""
    added: List[Dict[str, Any]]
    removed: List[Dict[str, Any]]
    changed: List[Dict[str, Any]]
    table: str
    key_column: str
    structural: List[Dict[str, Any]] = field(default_factory=list)
    category: Optional[DiffCategory] = None

    @property
    def total_changes(self) -> int:
        return len(self.added) + len(self.removed) + len(self.changed) + len(self.structural)

    def to_markdown(self) -> str:
        lines = [f"## {self.table} diff ({self.total_changes} changes)\n"]

        if self.added:
            lines.append(f"### Added ({len(self.added)})")
            for item in self.added[:DIFF_DISPLAY_LIMIT]:
                lines.append(f"- `{_md_sanitize(item.get(self.key_column, '?'))}`")

        if self.removed:
            lines.append(f"\n### Removed ({len(self.removed)})")
            for item in self.removed[:DIFF_DISPLAY_LIMIT]:
                lines.append(f"- `{_md_sanitize(item.get(self.key_column, '?'))}`")

        if self.changed:
            lines.append(f"\n### Changed ({len(self.changed)})")
            for item in self.changed[:DIFF_DISPLAY_LIMIT]:
                label = f"- `{_md_sanitize(item.get(self.key_column, '?'))}`"
                details = []
                for change in changed_field_values(item):
                    field_name = change["field"]
                    old_value = change["old_value"]
                    new_value = change["new_value"]
                    details.append(
                        f"{field_name}: {_md_sanitize(canonical_diff_value(old_value))} -> "
                        f"{_md_sanitize(canonical_diff_value(new_value))}"
                    )
                if details:
                    label += f" ({'; '.join(details)})"
                lines.append(label)

        if self.structural:
            lines.append(f"\n### Structural ({len(self.structural)})")
            for item in self.structural[:DIFF_DISPLAY_LIMIT]:
                lines.append(f"- {_md_sanitize(item.get('description', '?'))}")

        return "\n".join(lines)


class IcarusDiffer:
    """
    Compare two ICARUS databases for version-to-version analysis.

    Attach both databases and run set-difference queries to find
    what was added, removed, or modified between versions.
    """

    def __init__(self, old_db: str, new_db: str):
        self.old_path = Path(old_db)
        self.new_path = Path(new_db)

        if not self.old_path.exists():
            raise FileNotFoundError(f"Old database not found: {old_db}")
        if not self.new_path.exists():
            raise FileNotFoundError(f"New database not found: {new_db}")

        # Diff never writes: open both databases immutable read-only via URI so
        # an untrusted export can never be mutated (and no -wal/-shm is created).
        self.conn = sqlite3.connect(
            f"file:{self.new_path}?mode=ro&immutable=1", uri=True
        )
        try:
            self.conn.row_factory = sqlite3.Row
            self.conn.execute(
                "ATTACH DATABASE ? AS old_db",
                (f"file:{self.old_path}?mode=ro&immutable=1",),
            )
        except Exception:
            self.conn.close()
            raise

    def added_entities(self, table: str, key: str) -> DiffResult:
        """Entities present in new DB but not in old DB."""
        table = validate_table(table)
        key = validate_column(key)
        rows = self.conn.execute(
            f"SELECT n.* FROM main.[{table}] n "  # nosec B608 - table/key validated via validate_table/validate_column above
            f"LEFT JOIN old_db.[{table}] o ON n.[{key}] = o.[{key}] "
            f"WHERE o.[{key}] IS NULL"
        ).fetchall()

        return DiffResult(
            added=[dict(r) for r in rows],
            removed=[],
            changed=[],
            table=table,
            key_column=key
        )

    def removed_entities(self, table: str, key: str) -> DiffResult:
        """Entities present in old DB but not in new DB."""
        table = validate_table(table)
        key = validate_column(key)
        rows = self.conn.execute(
            f"SELECT o.* FROM old_db.[{table}] o "  # nosec B608 - table/key validated via validate_table/validate_column above
            f"LEFT JOIN main.[{table}] n ON o.[{key}] = n.[{key}] "
            f"WHERE n.[{key}] IS NULL"
        ).fetchall()

        return DiffResult(
            added=[],
            removed=[dict(r) for r in rows],
            changed=[],
            table=table,
            key_column=key
        )

    def changed_entities(self, table: str, key: str, compare: str) -> DiffResult:
        """Entities present in both but with different values in compare column."""
        table = validate_table(table)
        key = validate_column(key)
        compare = validate_column(compare)
        rows = self.conn.execute(
            f"SELECT n.[{key}], o.[{compare}] AS old_value, n.[{compare}] AS new_value "  # nosec B608 - table/key/compare validated via validate_table/validate_column above
            f"FROM main.[{table}] n "
            f"JOIN old_db.[{table}] o ON n.[{key}] = o.[{key}] "
            f"WHERE n.[{compare}] IS NOT o.[{compare}]"
        ).fetchall()

        changed = []
        for row in rows:
            item = dict(row)
            item["changed_fields"] = [compare]
            item[f"old_{compare}"] = item["old_value"]
            item[f"new_{compare}"] = item["new_value"]
            changed.append(item)

        return DiffResult(
            added=[],
            removed=[],
            changed=changed,
            table=table,
            key_column=key
        )

    def entitlement_diff(self, dangerous_keys: Optional[List[str]] = None) -> Dict[str, DiffResult]:
        """Specialized entitlement comparison across versions."""
        results = {}

        # Diff on the natural key (owning binary's bundle_id + entitlement
        # key/value), NOT the autoincrement id, which is assigned independently
        # in each DB and so carries no cross-version meaning.
        new_rows = self.conn.execute("""
            SELECT e.key, e.value, b.bundle_id, e.binary_id
            FROM main.entitlements e
            JOIN main.binaries b ON e.binary_id = b.id
            WHERE NOT EXISTS (
                SELECT 1 FROM old_db.entitlements eo
                JOIN old_db.binaries bo ON eo.binary_id = bo.id
                WHERE bo.bundle_id IS b.bundle_id
                  AND eo.key = e.key
                  AND eo.value = e.value
            )
        """).fetchall()
        results["new_entitlements"] = DiffResult(
            added=[dict(r) for r in new_rows],
            removed=[], changed=[],
            table="entitlements", key_column="key",
        )

        if dangerous_keys:
            placeholders = ",".join(["?"] * len(dangerous_keys))
            rows = self.conn.execute(
                f"SELECT e.key, e.value, b.bundle_id "  # nosec B608 - only bare `?` placeholders interpolated; values passed bound as params below
                f"FROM main.entitlements e "
                f"JOIN main.binaries b ON e.binary_id = b.id "
                f"WHERE e.key IN ({placeholders}) "
                f"AND e.key NOT IN ( "
                f"    SELECT eo.key FROM old_db.entitlements eo "
                f"    JOIN old_db.binaries bo ON eo.binary_id = bo.id "
                f"    WHERE bo.bundle_id = b.bundle_id AND eo.key = e.key "
                f")",
                tuple(dangerous_keys),
            ).fetchall()

            results["new_dangerous"] = DiffResult(
                added=[dict(r) for r in rows],
                removed=[], changed=[],
                table="entitlements", key_column="key"
            )

        return results

    def structural_diff(self) -> DiffResult:
        """Detect relationship topology changes between versions.

        Finds entities whose foreign-key relationships changed even when
        the entity itself still exists in both versions. For example:
        a binary that moved to a different daemon, or an entitlement
        that shifted to a different binary.
        """
        structural_changes = []

        # Binaries whose parent file changed. Compare the file's NATURAL key
        # (files.path), never file_id: file_id is a local autoincrement id assigned
        # independently in each database, so comparing it fabricates "moved" rows
        # from mere insertion-order skew and hides real moves when ids coincide.
        # executable_name is not unique, so restrict to names that identify exactly
        # one binary on each side; otherwise the join Cartesian-products duplicates
        # into false rows. Ambiguous names are skipped.
        rows = self.conn.execute("""
            SELECT n.executable_name,
                   nf.path AS new_path, of.path AS old_path
            FROM (
                SELECT executable_name, file_id FROM main.binaries
                WHERE executable_name IS NOT NULL
                GROUP BY executable_name HAVING COUNT(*) = 1
            ) n
            JOIN (
                SELECT executable_name, file_id FROM old_db.binaries
                WHERE executable_name IS NOT NULL
                GROUP BY executable_name HAVING COUNT(*) = 1
            ) o ON n.executable_name = o.executable_name
            JOIN main.files nf ON nf.id = n.file_id
            JOIN old_db.files of ON of.id = o.file_id
            WHERE nf.path IS NOT of.path
        """).fetchall()
        for r in rows:
            r = dict(r)
            structural_changes.append({
                "type": "binary_file_moved",
                "entity": r.get("executable_name"),
                "old_value": r.get("old_path"),
                "new_value": r.get("new_path"),
                "changed_fields": ["file_path"],
                "old_file_path": r.get("old_path"),
                "new_file_path": r.get("new_path"),
                "description": f"binary '{r.get('executable_name')}' file: "
                               f"{r.get('old_path')} -> {r.get('new_path')}",
            })

        # Sandbox rules whose profile assignment changed. Compare the profile's
        # NATURAL key (sandbox_profiles.name), not profile_id (a local autoincrement
        # id with no cross-database meaning). (operation, action) is not unique;
        # restrict to pairs identifying exactly one rule on each side so duplicates
        # cannot cross-product.
        rows = self.conn.execute("""
            SELECT n.operation, n.action,
                   np.name AS new_profile, op.name AS old_profile
            FROM (
                SELECT operation, action, profile_id FROM main.sandbox_rules
                GROUP BY operation, action HAVING COUNT(*) = 1
            ) n
            JOIN (
                SELECT operation, action, profile_id FROM old_db.sandbox_rules
                GROUP BY operation, action HAVING COUNT(*) = 1
            ) o ON n.operation = o.operation AND n.action = o.action
            JOIN main.sandbox_profiles np ON np.id = n.profile_id
            JOIN old_db.sandbox_profiles op ON op.id = o.profile_id
            WHERE np.name IS NOT op.name
        """).fetchall()
        for r in rows:
            r = dict(r)
            structural_changes.append({
                "type": "sandbox_rule_reassigned",
                "entity": f"{r.get('operation')}:{r.get('action')}",
                "old_value": r.get("old_profile"),
                "new_value": r.get("new_profile"),
                "changed_fields": ["profile"],
                "old_profile": r.get("old_profile"),
                "new_profile": r.get("new_profile"),
                "description": f"sandbox rule '{r.get('operation')}:{r.get('action')}' "
                               f"profile: {r.get('old_profile')} -> {r.get('new_profile')}",
            })

        # Entitlements whose owning binary changed (same key+value, different
        # binary). The owner is identified by the binary's most stable available
        # identity -- bundle_id, else executable_name, else the file path -- NOT the
        # file path alone. executable_name is exactly the identity binary_file_moved
        # (above) uses to track a binary across a move, so a binary that merely moves
        # paths keeps the same owner identity here and its entitlements are correctly
        # seen as unchanged; only a move onto a genuinely different binary is reported.
        # Keying on path alone reported every path move as a spurious reassignment (on
        # top of the binary_file_moved row for the same event). Residual limitation: a
        # binary with neither bundle_id nor executable_name falls back to path, so its
        # moves remain ambiguous. (key, value) is not unique; restrict to pairs
        # identifying exactly one entitlement on each side so duplicates cannot
        # cross-product into false rows.
        rows = self.conn.execute("""
            SELECT n.key, n.value,
                   COALESCE(nb.bundle_id, nb.executable_name, 'path:' || nf.path) AS new_owner,
                   COALESCE(ob.bundle_id, ob.executable_name, 'path:' || of.path) AS old_owner
            FROM (
                SELECT key, value, binary_id FROM main.entitlements
                GROUP BY key, value HAVING COUNT(*) = 1
            ) n
            JOIN (
                SELECT key, value, binary_id FROM old_db.entitlements
                GROUP BY key, value HAVING COUNT(*) = 1
            ) o ON n.key = o.key AND n.value = o.value
            JOIN main.binaries nb ON nb.id = n.binary_id
            JOIN old_db.binaries ob ON ob.id = o.binary_id
            JOIN main.files nf ON nf.id = nb.file_id
            JOIN old_db.files of ON of.id = ob.file_id
            WHERE COALESCE(nb.bundle_id, nb.executable_name, 'path:' || nf.path)
               IS NOT COALESCE(ob.bundle_id, ob.executable_name, 'path:' || of.path)
        """).fetchall()
        for r in rows:
            r = dict(r)
            structural_changes.append({
                "type": "entitlement_reassigned",
                "entity": r.get("key"),
                "old_value": r.get("old_owner"),
                "new_value": r.get("new_owner"),
                "changed_fields": ["binary"],
                "old_binary": r.get("old_owner"),
                "new_binary": r.get("new_owner"),
                "description": f"entitlement '{r.get('key')}' "
                               f"binary: {r.get('old_owner')} -> {r.get('new_owner')}",
            })

        return DiffResult(
            added=[], removed=[], changed=[],
            structural=structural_changes,
            table="cross_table",
            key_column="entity",
            category=DiffCategory.STRUCTURAL,
        )

    def observation_diff(self) -> DiffResult:
        """Diff observation records between old and new databases.

        Observations reference their subject polymorphically as
        ``(entity_table, entity_id)`` where ``entity_id`` is a local
        AUTOINCREMENT row id. That id has no meaning across two independently
        built databases: the same logical file gets different ids depending on
        insertion order, so matching observations on the raw id fabricated
        "added"/"removed" rows from mere insertion-order skew (and hid real
        changes when ids happened to coincide). Each observation is therefore
        resolved to its subject's NATURAL key before comparison. Observations
        whose subject row is absent, or whose entity_table has no known natural
        key, are excluded from the natural-key comparison and surfaced
        separately so they are neither silently dropped nor compared on a
        meaningless id.

        Identity is ``(entity_table, natural_key, event_type, observed_at)``;
        ``properties``, ``observer``, and ``confidence`` are mutable content.
        Properties are compared as canonical JSON. Duplicate identities use
        multiset semantics: exact content cancels one-for-one, remaining rows
        pair in canonical order, and excess rows stay added or removed. A NULL
        timestamp remains a literal identity component for deterministic legacy
        database handling.
        """
        new_keyed, new_unresolved = self._resolve_observations("main")
        old_keyed, old_unresolved = self._resolve_observations("old_db")
        added, removed, changed = self._diff_resolved_observations(
            old_keyed, new_keyed
        )

        # Unresolved observations (missing subject row or unmapped table) cannot
        # be compared by natural key; report them on both sides for visibility.
        for side, unresolved in (("new", new_unresolved), ("old", old_unresolved)):
            for record in sorted(unresolved, key=self._observation_record_sort_key):
                row = dict(record["output"])
                row["unresolved"] = side
                (added if side == "new" else removed).append(row)

        return DiffResult(
            added=added,
            removed=removed,
            changed=changed,
            table="observations",
            key_column="entity_key",
            category=DiffCategory.PROPERTY_CHANGE,
        )

    # entity_table -> the column on that table that is its stable natural key.
    # "binaries" is resolved to its file's path via file_id (see _resolve_observations).
    _OBSERVATION_ENTITY_KEY = {
        "files": "path",
        "daemons": "label",
        "kexts": "bundle_id",
        "frameworks": "path",
        "sandbox_profiles": "name",
    }

    def _resolve_observations(self, schema: str):
        """Resolve observations to stable identity plus mutable content records."""
        entity_tables = {
            row[0]
            for row in self.conn.execute(
                f"SELECT DISTINCT entity_table FROM {schema}.observations"  # nosec B608 - schema is a fixed literal
            )
        }

        keyed = []
        unresolved = []
        for table in entity_tables:
            if table == "binaries":
                # A binary has no unique column of its own; use its file path,
                # which is UNIQUE, via the mandatory file_id foreign key.
                query = (
                    f"SELECT ob.entity_table, f.path, ob.event_type, ob.observed_at, "  # nosec B608 - identifiers are fixed literals; entity_table bound as a parameter
                    f"ob.properties, ob.observer, ob.confidence, ob.entity_id "
                    f"FROM {schema}.observations ob "
                    f"JOIN {schema}.binaries b ON b.id = ob.entity_id "
                    f"JOIN {schema}.files f ON f.id = b.file_id "
                    f"WHERE ob.entity_table = ?"
                )
            elif table in self._OBSERVATION_ENTITY_KEY:
                key_col = self._OBSERVATION_ENTITY_KEY[table]
                query = (
                    f"SELECT ob.entity_table, e.{key_col}, ob.event_type, ob.observed_at, "  # nosec B608 - table/key_col come from a fixed whitelist; entity_table bound as a parameter
                    f"ob.properties, ob.observer, ob.confidence, ob.entity_id "
                    f"FROM {schema}.observations ob "
                    f"JOIN {schema}.{table} e ON e.id = ob.entity_id "
                    f"WHERE ob.entity_table = ?"
                )
            else:
                # No known natural key: keep the raw id, marked unresolved.
                for row in self.conn.execute(
                    f"SELECT entity_table, entity_id, event_type, observed_at, "  # nosec B608 - schema is a fixed literal
                    f"properties, observer, confidence "
                    f"FROM {schema}.observations WHERE entity_table = ?",
                    (table,),
                ):
                    unresolved.append(self._observation_record(
                        row[0], f"id:{row[1]}", row[2], row[3],
                        row[4], row[5], row[6],
                    ))
                continue

            for row in self.conn.execute(query, (table,)):
                natural = row[1]
                if natural is None:
                    unresolved.append(self._observation_record(
                        row[0], f"id:{row[7]}", row[2], row[3],
                        row[4], row[5], row[6],
                    ))
                else:
                    keyed.append(self._observation_record(
                        row[0], str(natural), row[2], row[3],
                        row[4], row[5], row[6],
                    ))

            # Observations whose subject row is missing (orphaned) or whose key
            # column is NULL are surfaced as unresolved rather than dropped.
            for row in self.conn.execute(
                f"SELECT entity_table, entity_id, event_type, observed_at, "  # nosec B608 - schema is a fixed literal
                f"properties, observer, confidence "
                f"FROM {schema}.observations ob WHERE entity_table = ? "
                f"AND NOT EXISTS (SELECT 1 FROM {schema}.{table} e WHERE e.id = ob.entity_id)",
                (table,),
            ):
                unresolved.append(self._observation_record(
                    row[0], f"id:{row[1]}", row[2], row[3],
                    row[4], row[5], row[6],
                ))

        return keyed, unresolved

    @staticmethod
    def _canonical_observation_properties(raw: Optional[str]):
        if raw is None:
            # SQL NULL and a JSON ``null`` payload both mean no properties.
            return "json:null", None
        try:
            value = json.loads(raw)
            canonical = json.dumps(value, sort_keys=True, separators=(",", ":"))
        except (ValueError, TypeError, RecursionError):
            return f"raw:{raw}", raw
        return f"json:{canonical}", value

    @classmethod
    def _observation_record(
        cls, entity_table, entity_key, event_type, observed_at,
        properties, observer, confidence,
    ):
        properties_key, properties_value = cls._canonical_observation_properties(
            properties
        )
        identity = (entity_table, entity_key, event_type, observed_at)
        content_key = json.dumps(
            [properties_key, observer, confidence],
            separators=(",", ":"),
        )
        return {
            "identity": identity,
            "content_key": content_key,
            "properties_key": properties_key,
            "output": {
                "entity_table": entity_table,
                "entity_key": entity_key,
                "event_type": event_type,
                "observed_at": observed_at,
                "properties": properties_value,
                "observer": observer,
                "confidence": confidence,
            },
        }

    @staticmethod
    def _observation_record_sort_key(record) -> str:
        return json.dumps(
            [record["identity"], record["content_key"]],
            separators=(",", ":"),
        )

    @classmethod
    def _diff_resolved_observations(cls, old_records, new_records):
        """Multiset diff, pairing duplicate content deterministically."""
        old_by_identity = defaultdict(list)
        new_by_identity = defaultdict(list)
        for record in old_records:
            old_by_identity[record["identity"]].append(record)
        for record in new_records:
            new_by_identity[record["identity"]].append(record)

        added = []
        removed = []
        changed = []
        identities = set(old_by_identity) | set(new_by_identity)
        for identity in sorted(
            identities,
            key=lambda value: json.dumps(value, separators=(",", ":")),
        ):
            old_by_content = defaultdict(list)
            new_by_content = defaultdict(list)
            for record in old_by_identity[identity]:
                old_by_content[record["content_key"]].append(record)
            for record in new_by_identity[identity]:
                new_by_content[record["content_key"]].append(record)

            # Equal content cancels one-for-one, retaining duplicate cardinality.
            for content_key in set(old_by_content) & set(new_by_content):
                matched = min(
                    len(old_by_content[content_key]),
                    len(new_by_content[content_key]),
                )
                del old_by_content[content_key][:matched]
                del new_by_content[content_key][:matched]

            old_remaining = sorted(
                (record for records in old_by_content.values() for record in records),
                key=cls._observation_record_sort_key,
            )
            new_remaining = sorted(
                (record for records in new_by_content.values() for record in records),
                key=cls._observation_record_sort_key,
            )

            paired = min(len(old_remaining), len(new_remaining))
            for old, new in zip(old_remaining[:paired], new_remaining[:paired]):
                row = {
                    key: value for key, value in new["output"].items()
                    if key not in {"properties", "observer", "confidence"}
                }
                changed_fields = []
                for field_name in ("properties", "observer", "confidence"):
                    old_value = old["output"][field_name]
                    new_value = new["output"][field_name]
                    differs = (
                        old["properties_key"] != new["properties_key"]
                        if field_name == "properties"
                        else old_value != new_value
                    )
                    if differs:
                        changed_fields.append(field_name)
                        row[f"old_{field_name}"] = old_value
                        row[f"new_{field_name}"] = new_value
                row["changed_fields"] = changed_fields
                changed.append(row)

            added.extend(
                dict(record["output"]) for record in new_remaining[paired:]
            )
            removed.extend(
                dict(record["output"]) for record in old_remaining[paired:]
            )

        return added, removed, changed

    def _natural_diff(
        self,
        table: str,
        key_column: str,
        key_cols: List[str],
        new_sql: str,
        old_sql: str,
    ) -> DiffResult:
        """Set-difference two natural-key projections into added/removed.

        ``new_sql``/``old_sql`` each SELECT the SAME natural-key columns from
        ``main``/``old_db`` respectively. Identity is the tuple of ``key_cols``
        values, so only the projected natural key ever participates — a local
        AUTOINCREMENT id can never leak into the comparison (DIFF-01 discipline).
        """
        new_rows = [dict(r) for r in self.conn.execute(new_sql)]  # nosec B608 - SQL is a fixed literal built in-method; no external input interpolated
        old_rows = [dict(r) for r in self.conn.execute(old_sql)]  # nosec B608 - SQL is a fixed literal built in-method; no external input interpolated

        def key(d: Dict[str, Any]) -> tuple:
            return tuple(d[c] for c in key_cols)

        old_keys = {key(d) for d in old_rows}
        new_keys = {key(d) for d in new_rows}
        return DiffResult(
            added=[d for d in new_rows if key(d) not in old_keys],
            removed=[d for d in old_rows if key(d) not in new_keys],
            changed=[],
            table=table,
            key_column=key_column,
        )

    def files_changed_diff(self) -> DiffResult:
        """Files present in both versions whose content changed.

        Keyed on ``sha256`` when both sides have a hash. Files >= 50 MB and
        symlinks are stored with ``sha256 = NULL`` (hashing is skipped), so a
        raw ``sha256 IS NOT sha256`` test can never see a content change in
        them — both NULLs compare equal. When either side's hash is NULL we
        fall back to comparing ``size``, so a large-file or symlink content
        change that alters the byte size is still reported. Genuinely unchanged
        NULL-hash files (same size) are NOT reported, avoiding false positives.
        """
        rows = self.conn.execute("""
            SELECT n.path,
                   o.sha256 AS old_sha256, n.sha256 AS new_sha256,
                   o.size   AS old_size,   n.size   AS new_size
            FROM main.files n
            JOIN old_db.files o ON n.path = o.path
            WHERE (n.sha256 IS NOT NULL AND o.sha256 IS NOT NULL
                   AND n.sha256 IS NOT o.sha256)
               OR ((n.sha256 IS NULL OR o.sha256 IS NULL)
                   AND n.size IS NOT o.size)
        """).fetchall()

        changed = []
        for r in rows:
            d = dict(r)
            if d["old_sha256"] is not None and d["new_sha256"] is not None:
                d["change_basis"] = "sha256"
                d["changed_fields"] = ["sha256"]
            else:
                # At least one side's content is unknown (>=50 MB or symlink);
                # the reported change is inferred from the size delta.
                d["change_basis"] = "size"
                d["content_unknown"] = True
                d["changed_fields"] = ["size"]
            changed.append(d)

        return DiffResult(
            added=[], removed=[], changed=changed,
            table="files", key_column="path",
            category=DiffCategory.PROPERTY_CHANGE,
        )

    def binaries_diff(self) -> DiffResult:
        """Binaries added/removed, keyed on the owning file's path.

        A binary has no unique column of its own (executable_name is not
        unique); its stable natural identity is its file's path via the
        mandatory ``file_id`` foreign key (files.path is UNIQUE).
        """
        return self._natural_diff(
            "binaries", "path", ["path"],
            "SELECT f.path, b.bundle_id, b.executable_name "
            "FROM main.binaries b JOIN main.files f ON f.id = b.file_id",
            "SELECT f.path, b.bundle_id, b.executable_name "
            "FROM old_db.binaries b JOIN old_db.files f ON f.id = b.file_id",
        )

    def entitlements_diff(self) -> DiffResult:
        """Entitlements added/removed, keyed on (owning bundle_id, key, value).

        Mirrors ``entitlement_diff``'s natural key: the owning binary's
        ``bundle_id`` plus the entitlement's ``key``/``value`` — never the
        per-database autoincrement entitlement id or binary id.
        """
        return self._natural_diff(
            "entitlements", "key", ["bundle_id", "key", "value"],
            "SELECT b.bundle_id, e.key, e.value "
            "FROM main.entitlements e JOIN main.binaries b ON b.id = e.binary_id",
            "SELECT b.bundle_id, e.key, e.value "
            "FROM old_db.entitlements e JOIN old_db.binaries b ON b.id = e.binary_id",
        )

    def sandbox_rules_diff(self) -> DiffResult:
        """Sandbox rules added/removed, keyed on the owning profile + rule shape.

        Natural key = owning profile name (via profile_id) plus the rule's
        (operation, action, filter_type, filter_value) — never profile_id.
        """
        return self._natural_diff(
            "sandbox_rules", "operation",
            ["profile", "operation", "action", "filter_type", "filter_value"],
            "SELECT p.name AS profile, r.operation, r.action, "
            "       r.filter_type, r.filter_value "
            "FROM main.sandbox_rules r "
            "JOIN main.sandbox_profiles p ON p.id = r.profile_id",
            "SELECT p.name AS profile, r.operation, r.action, "
            "       r.filter_type, r.filter_value "
            "FROM old_db.sandbox_rules r "
            "JOIN old_db.sandbox_profiles p ON p.id = r.profile_id",
        )

    def mach_services_diff(self) -> DiffResult:
        """Mach services added/removed, keyed on (owning daemon label, service_name).

        Natural key = the owning daemon's ``label`` (via daemon_id, which is a
        local autoincrement id) plus ``service_name``.
        """
        return self._natural_diff(
            "mach_services", "service_name", ["daemon", "service_name"],
            "SELECT d.label AS daemon, m.service_name "
            "FROM main.mach_services m JOIN main.daemons d ON d.id = m.daemon_id",
            "SELECT d.label AS daemon, m.service_name "
            "FROM old_db.mach_services m JOIN old_db.daemons d ON d.id = m.daemon_id",
        )

    def resolution_diff(self) -> DiffResult:
        """Diff entity-resolution outcomes (bags) between versions.

        A bag is a resolved cluster of atoms identified by its
        ``canonical_key``. Bags are compared on the NATURAL
        (``entity_type``, ``canonical_key``); the autoincrement bag id and the
        atom ids listed in the event log are never compared (they carry no
        cross-database meaning). Bags with no ``canonical_key`` (not yet
        resolved) have no stable cross-version identity and are excluded.

        Reports resolved entities added/removed, and — for bags present in both
        versions — a change when the clustered ``atom_count`` or ``score``
        differs (the resolution regrouped or re-scored the same entity).
        """
        def load(schema: str) -> Dict[tuple, Dict[str, Any]]:
            return {
                (r["entity_type"], r["canonical_key"]): dict(r)
                for r in self.conn.execute(
                    f"SELECT entity_type, canonical_key, atom_count, score "  # nosec B608 - schema is a fixed literal ('main'/'old_db')
                    f"FROM {schema}.bags WHERE canonical_key IS NOT NULL"
                )
            }

        new_bags = load("main")
        old_bags = load("old_db")

        added = [v for k, v in new_bags.items() if k not in old_bags]
        removed = [v for k, v in old_bags.items() if k not in new_bags]
        changed = []
        for k in new_bags.keys() & old_bags.keys():
            n, o = new_bags[k], old_bags[k]
            if n["atom_count"] != o["atom_count"] or n["score"] != o["score"]:
                row = {
                    "entity_type": k[0],
                    "canonical_key": k[1],
                    "changed_fields": [],
                }
                for field_name in ("atom_count", "score"):
                    if o[field_name] != n[field_name]:
                        row["changed_fields"].append(field_name)
                        row[f"old_{field_name}"] = o[field_name]
                        row[f"new_{field_name}"] = n[field_name]
                changed.append(row)

        return DiffResult(
            added=added, removed=removed, changed=changed,
            table="bags", key_column="canonical_key",
            category=DiffCategory.RESOLUTION_CHANGE,
        )

    def full_diff(self) -> Dict[str, DiffResult]:
        """Run diff across all major tables, including structural, observation,
        and resolution analysis. Produces every category the module docstring
        advertises: ADDITION/DELETION (per-table added/removed), PROPERTY_CHANGE
        (files_changed, incl. NULL-hash size compare), STRUCTURAL, and
        RESOLUTION_CHANGE."""
        results = {}
        # Files (add/remove/changed — sha256, with size fallback for NULL hashes).
        results["files_added"] = self.added_entities("files", "path")
        results["files_removed"] = self.removed_entities("files", "path")
        results["files_changed"] = self.files_changed_diff()
        # Daemons.
        results["daemons_added"] = self.added_entities("daemons", "label")
        results["daemons_removed"] = self.removed_entities("daemons", "label")
        # Kexts.
        results["kexts_added"] = self.added_entities("kexts", "bundle_id")
        results["kexts_removed"] = self.removed_entities("kexts", "bundle_id")
        # Frameworks (path is UNIQUE — direct natural-key helper).
        results["frameworks_added"] = self.added_entities("frameworks", "path")
        results["frameworks_removed"] = self.removed_entities("frameworks", "path")
        # Sandbox profiles (name is UNIQUE — direct natural-key helper).
        results["sandbox_profiles_added"] = self.added_entities("sandbox_profiles", "name")
        results["sandbox_profiles_removed"] = self.removed_entities("sandbox_profiles", "name")
        # Tables whose natural key spans a join (no single UNIQUE own column).
        results["binaries"] = self.binaries_diff()
        results["entitlements"] = self.entitlements_diff()
        results["sandbox_rules"] = self.sandbox_rules_diff()
        results["mach_services"] = self.mach_services_diff()
        # Cross-table / relationship, observation, and resolution analysis.
        results["structural"] = self.structural_diff()
        results["observations"] = self.observation_diff()
        results["resolution"] = self.resolution_diff()
        return results

    def generate_report(self) -> str:
        """Generate a full Markdown diff report."""
        results = self.full_diff()
        lines = ["# ICARUS Version Diff\n",
                 f"Old: `{_md_sanitize(self.old_path.name)}`\n",
                 f"New: `{_md_sanitize(self.new_path.name)}`\n",
                 "---\n"]

        for name, diff in results.items():
            if diff.total_changes > 0:
                lines.append(diff.to_markdown())
                lines.append("")

        return "\n".join(lines)

    def close(self) -> None:
        self.conn.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()
