"""Complete-output idempotency regressions for parser quality gates (#98)."""

from pathlib import Path

import pytest

from icarus.core.schema import open_db
from icarus.parsers.base import BaseParser
from icarus.parsers.manifest import ParserManifest
from icarus.parsers.testing import ParserTestHarness


class _SyntheticParser(BaseParser):
    mode = "stable"

    def __init__(self):
        self.entity_runs = 0
        self.relationship_runs = 0

    @property
    def name(self):
        return f"test/{self.mode}"

    @property
    def description(self):
        return "Synthetic idempotency fixture"

    def identify(self, source):
        return True

    def extract_entities(self, source, db_path):
        self.entity_runs += 1
        conn = open_db(db_path)
        try:
            if self.mode == "duplicate-entity":
                suffix = self.entity_runs
                conn.execute(
                    "INSERT INTO files (path,filename,size) VALUES (?,?,?)",
                    (f"/fixture-{suffix}", f"fixture-{suffix}", suffix),
                )
            else:
                conn.execute(
                    "INSERT OR IGNORE INTO files (path,filename,size) VALUES (?,?,?)",
                    ("/fixture", "fixture", 1),
                )

            file_id = conn.execute(
                "SELECT id FROM files ORDER BY id LIMIT 1"
            ).fetchone()[0]
            if self.mode == "duplicate-observation":
                conn.execute(
                    "INSERT INTO observations "
                    "(entity_table,entity_id,observed_at,event_type) VALUES (?,?,?,?)",
                    ("files", file_id, "2026-01-01T00:00:00Z", "entity-run"),
                )
            if self.mode == "changed-content" and self.entity_runs == 2:
                conn.execute("UPDATE files SET filename='changed' WHERE id=?", (file_id,))
            conn.commit()
        finally:
            conn.close()
        return {"files": 1}

    def extract_relationships(self, source, db_path):
        self.relationship_runs += 1
        if self.mode == "duplicate-relationship":
            conn = open_db(db_path)
            try:
                file_id = conn.execute(
                    "SELECT id FROM files ORDER BY id LIMIT 1"
                ).fetchone()[0]
                conn.execute(
                    "INSERT INTO observations "
                    "(entity_table,entity_id,observed_at,event_type) VALUES (?,?,?,?)",
                    ("files", file_id, "2026-01-01T00:00:00Z", "relationship-run"),
                )
                conn.commit()
            finally:
                conn.close()
        return {"linked": 0}


class _StableParser(_SyntheticParser):
    mode = "stable"


class _DuplicateEntityParser(_SyntheticParser):
    mode = "duplicate-entity"


class _DuplicateObservationParser(_SyntheticParser):
    mode = "duplicate-observation"


class _DuplicateRelationshipParser(_SyntheticParser):
    mode = "duplicate-relationship"


class _ChangedContentParser(_SyntheticParser):
    mode = "changed-content"


class _ReorderedEquivalentParser(_SyntheticParser):
    mode = "reordered-equivalent"

    def extract_entities(self, source, db_path):
        self.entity_runs += 1
        conn = open_db(db_path)
        try:
            conn.execute("CREATE TABLE IF NOT EXISTS parser_output (value TEXT)")
            conn.execute("DELETE FROM parser_output")
            values = ["alpha", "beta"]
            if self.entity_runs == 2:
                values.reverse()
            conn.executemany("INSERT INTO parser_output VALUES (?)", [(v,) for v in values])
            conn.commit()
        finally:
            conn.close()
        return {"parser_output": 2}


def _manifest(parser):
    return ParserManifest(
        parser_id=parser.name,
        version="1.0.0",
        spec_version="icarus-parser/1.0",
        author="test",
        license="MIT",
        quality_tier="production",
        description="fixture",
        identify={"specificity_level": 10},
        consumes=[],
        produces={"entity_types": ["files"]},
        reliability="C",
        default_confidence=0.5,
    )


def _run(parser, tmp_path: Path):
    return ParserTestHarness(parser, _manifest(parser), tmp_path).test_idempotency()


def test_idempotency_accepts_stable_complete_output(tmp_path):
    result = _run(_StableParser(), tmp_path)
    assert result.passed, result.message


@pytest.mark.parametrize(
    ("parser_cls", "changed_table"),
    [
        (_DuplicateEntityParser, "files"),
        (_DuplicateObservationParser, "observations"),
        (_DuplicateRelationshipParser, "observations"),
        (_ChangedContentParser, "files"),
    ],
)
def test_idempotency_rejects_complete_output_changes(parser_cls, changed_table, tmp_path):
    result = _run(parser_cls(), tmp_path)

    assert not result.passed
    assert changed_table in result.message
    evidence = result.details["changed_tables"][changed_table]
    assert evidence["before_sha256"] != evidence["after_sha256"]
    assert evidence["removed_rows"] or evidence["added_rows"]


def test_idempotency_runs_relationship_phase_twice(tmp_path):
    parser = _DuplicateRelationshipParser()
    result = _run(parser, tmp_path)
    assert not result.passed
    assert parser.entity_runs == 2
    assert parser.relationship_runs == 2


def test_idempotency_ignores_equivalent_row_order(tmp_path):
    result = _run(_ReorderedEquivalentParser(), tmp_path)
    assert result.passed, result.message
