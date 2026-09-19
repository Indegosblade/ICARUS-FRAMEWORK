"""Observation diff identity, content, and duplicate-cardinality regressions."""

import json
import sqlite3
from pathlib import Path

import pytest

from icarus.core.differ import IcarusDiffer
from icarus.core.schema import initialize_database


def _build_db(path: Path, observations: list[dict]) -> None:
    initialize_database(path)
    conn = sqlite3.connect(str(path))
    try:
        conn.execute(
            "INSERT INTO files (path, filename) VALUES ('/subject', 'subject')"
        )
        file_id = conn.execute(
            "SELECT id FROM files WHERE path = '/subject'"
        ).fetchone()[0]
        for observation in observations:
            conn.execute(
                "INSERT INTO observations "
                "(entity_table, entity_id, observed_at, event_type, properties, "
                "observer, confidence) VALUES ('files', ?, ?, ?, ?, ?, ?)",
                (
                    file_id,
                    observation.get("observed_at", "2026-01-01T00:00:00Z"),
                    observation.get("event_type", "access"),
                    observation.get("properties"),
                    observation.get("observer"),
                    observation.get("confidence", 1.0),
                ),
            )
        conn.commit()
    finally:
        conn.close()


def _diff(tmp_path: Path, old_rows: list[dict], new_rows: list[dict]):
    old = tmp_path / "old.db"
    new = tmp_path / "new.db"
    _build_db(old, old_rows)
    _build_db(new, new_rows)
    with IcarusDiffer(str(old), str(new)) as differ:
        return differ.observation_diff()


def test_properties_change_is_structured_and_rendered(tmp_path):
    result = _diff(
        tmp_path,
        [{"properties": '{"decision":"denied"}'}],
        [{"properties": '{"decision":"allowed"}'}],
    )

    assert result.added == []
    assert result.removed == []
    assert result.changed == [{
        "entity_table": "files",
        "entity_key": "/subject",
        "event_type": "access",
        "observed_at": "2026-01-01T00:00:00Z",
        "old_properties": {"decision": "denied"},
        "new_properties": {"decision": "allowed"},
        "changed_fields": ["properties"],
    }]
    # Structured consumers retain the nested values, and Markdown does not
    # collapse the change to a bare subject identifier.
    assert json.loads(json.dumps(result.changed))[0]["new_properties"] == {
        "decision": "allowed"
    }
    markdown = result.to_markdown()
    assert 'properties: {"decision":"denied"} -> {"decision":"allowed"}' in markdown


def test_reordered_nested_json_and_nulls_are_unchanged(tmp_path):
    old = '{"z":null,"nested":{"b":2,"a":[1,null]}}'
    new = '{ "nested": {"a": [1, null], "b": 2}, "z": null }'

    result = _diff(tmp_path, [{"properties": old}], [{"properties": new}])

    assert result.total_changes == 0


@pytest.mark.parametrize(
    ("old_row", "new_row", "field", "old_value", "new_value"),
    [
        ({"observer": "sensor-a"}, {"observer": "sensor-b"},
         "observer", "sensor-a", "sensor-b"),
        ({"confidence": 0.25}, {"confidence": 0.75},
         "confidence", 0.25, 0.75),
    ],
)
def test_observer_and_confidence_changes_are_reported(
    tmp_path, old_row, new_row, field, old_value, new_value,
):
    result = _diff(tmp_path, [old_row], [new_row])

    assert len(result.changed) == 1
    assert result.changed[0]["changed_fields"] == [field]
    assert result.changed[0][f"old_{field}"] == old_value
    assert result.changed[0][f"new_{field}"] == new_value


@pytest.mark.parametrize(
    ("old_value", "new_value", "expected"),
    [
        (None, "sensor-a", 'observer: null -> "sensor-a"'),
        ("sensor-a", None, 'observer: "sensor-a" -> null'),
    ],
)
def test_nullable_observer_changes_render_as_json_values(
    tmp_path, old_value, new_value, expected,
):
    result = _diff(
        tmp_path, [{"observer": old_value}], [{"observer": new_value}],
    )

    assert result.changed[0]["old_observer"] == old_value
    assert result.changed[0]["new_observer"] == new_value
    markdown = result.to_markdown()
    assert expected in markdown
    assert "? ->" not in markdown and "-> ?" not in markdown


def test_nested_boolean_properties_render_as_canonical_json(tmp_path):
    old = '{"items":[null,"old"],"enabled":false}'
    new = '{"items":[null,"new"],"enabled":true}'
    result = _diff(tmp_path, [{"properties": old}], [{"properties": new}])

    assert result.changed[0]["old_properties"] == {
        "items": [None, "old"], "enabled": False,
    }
    assert result.changed[0]["new_properties"] == {
        "items": [None, "new"], "enabled": True,
    }
    assert (
        'properties: {"enabled":false,"items":[null,"old"]} -> '
        '{"enabled":true,"items":[null,"new"]}'
    ) in result.to_markdown()


def test_duplicate_observations_use_multiset_semantics(tmp_path):
    denied = {"properties": '{"decision":"denied"}'}
    allowed = {"properties": '{"decision":"allowed"}'}

    # One exact duplicate cancels. The other old row pairs deterministically
    # with one changed row, and the excess new duplicate remains an addition.
    result = _diff(tmp_path, [denied, denied], [denied, allowed, allowed])

    assert len(result.changed) == 1
    assert result.changed[0]["old_properties"] == {"decision": "denied"}
    assert result.changed[0]["new_properties"] == {"decision": "allowed"}
    assert len(result.added) == 1
    assert result.added[0]["properties"] == {"decision": "allowed"}
    assert result.removed == []


def _build_nullable_timestamp_db(path: Path, properties: str) -> None:
    """Model a legacy/corrupt input whose observed_at constraint is absent."""
    conn = sqlite3.connect(str(path))
    try:
        conn.executescript("""
            CREATE TABLE files (id INTEGER PRIMARY KEY, path TEXT UNIQUE);
            CREATE TABLE observations (
                id INTEGER PRIMARY KEY,
                entity_table TEXT,
                entity_id INTEGER,
                observed_at TEXT,
                observer TEXT,
                event_type TEXT,
                properties TEXT,
                confidence REAL
            );
            INSERT INTO files (id, path) VALUES (1, '/subject');
        """)
        conn.execute(
            "INSERT INTO observations "
            "(entity_table, entity_id, observed_at, event_type, properties, confidence) "
            "VALUES ('files', 1, NULL, 'access', ?, 1.0)",
            (properties,),
        )
        conn.commit()
    finally:
        conn.close()


def test_missing_timestamp_is_an_explicit_deterministic_identity(tmp_path):
    old = tmp_path / "old.db"
    new = tmp_path / "new.db"
    _build_nullable_timestamp_db(old, '{"decision":"denied"}')
    _build_nullable_timestamp_db(new, '{"decision":"allowed"}')

    with IcarusDiffer(str(old), str(new)) as differ:
        result = differ.observation_diff()

    assert result.added == [] and result.removed == []
    assert len(result.changed) == 1
    assert result.changed[0]["observed_at"] is None
    assert result.changed[0]["changed_fields"] == ["properties"]
