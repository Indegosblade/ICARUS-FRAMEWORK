"""Behavioral tests for audit-backlog findings #83, #88, #138, #143.

  - #83  CloudTrail observation dedup must key on the unique eventID, not
         just (entity, second-granularity eventTime, eventName), so two
         distinct events landing in the same second do not collapse.
  - #88  ParserTestHarness.test_schema_conformance must catch event_type
         drift against manifest.produces.event_types (previously
         unchecked — 'observations' was skip-listed and the only loop that
         touched entity tables was dead code).
  - #138 ParserTestHarness.test_golden_output must compare more than row
         COUNTS: a deterministic content fingerprint, plus the golden
         file's own declared zero_pii / has_relationships / observation_count
         fields (previously loaded but never read).
  - #143 Harness wiring (run_all(), every HarnessResult.passed) for the
         linux parser and each generic/* production parser, whose golden
         files were wired but never exercised by any test.
"""

import importlib
import json
import sqlite3
from pathlib import Path

import pytest

from icarus.core.schema import initialize_database
from icarus.parsers.manifest import ParserManifest, load_manifest
from icarus.parsers.testing import ParserTestHarness

FIXTURES_DIR = Path(__file__).parent / "fixtures"
PARSERS_DIR = Path(__file__).parent.parent / "icarus" / "parsers"


# ---------------------------------------------------------------------------
# #83 — CloudTrail observation dedup must not collapse distinct eventIDs
# that share the same (entity, second, eventName).
# ---------------------------------------------------------------------------

def _cloudtrail_record(arn, event_id, event_name="DescribeInstances",
                        event_time="2026-06-01T10:00:00Z", **extra):
    record = {
        "eventVersion": "1.08",
        "userIdentity": {
            "type": "IAMUser",
            "arn": arn,
            "accountId": "123456789012",
            "userName": arn.rsplit("/", 1)[-1],
        },
        "eventTime": event_time,
        "eventSource": "ec2.amazonaws.com",
        "eventName": event_name,
        "eventID": event_id,
        "awsRegion": "us-east-1",
    }
    record.update(extra)
    return record


def _write_cloudtrail_fixture(tmp_path, records, name="log.json"):
    src = tmp_path / "cloudtrail_src"
    src.mkdir(parents=True, exist_ok=True)
    (src / name).write_text(json.dumps({"Records": records}))
    return src


def test_cloudtrail_dedup_keeps_distinct_events_same_second(tmp_path):
    """#83: two distinct CloudTrail events for the same identity, same
    eventName, and the same eventTime (1s granularity) but different
    eventID must both survive as separate observations."""
    from icarus.parsers.cloud.aws.cloudtrail import CloudTrailParser

    arn = "arn:aws:iam::123456789012:user/dup-test"
    records = [
        _cloudtrail_record(arn, "11111111-1111-1111-1111-111111111111",
                            sourceIPAddress="10.0.0.1"),
        _cloudtrail_record(arn, "22222222-2222-2222-2222-222222222222",
                            sourceIPAddress="10.0.0.2"),
    ]
    src = _write_cloudtrail_fixture(tmp_path, records)
    db = tmp_path / "out.db"
    initialize_database(db, {"source": str(src)})
    CloudTrailParser().extract_entities(src, db)

    conn = sqlite3.connect(str(db))
    try:
        rows = conn.execute(
            "SELECT properties FROM observations WHERE event_type='DescribeInstances'"
        ).fetchall()
    finally:
        conn.close()

    assert len(rows) == 2, f"distinct eventIDs collapsed into {len(rows)} observation(s)"
    stored_event_ids = {json.loads(p).get("eventID") for (p,) in rows}
    assert stored_event_ids == {
        "11111111-1111-1111-1111-111111111111",
        "22222222-2222-2222-2222-222222222222",
    }


def test_cloudtrail_dedup_still_collapses_true_duplicate(tmp_path):
    """Same eventID appearing twice (e.g. overlapping CloudTrail exports)
    is a genuine duplicate and must still collapse to one observation."""
    from icarus.parsers.cloud.aws.cloudtrail import CloudTrailParser

    arn = "arn:aws:iam::123456789012:user/dup-test"
    same_id = "33333333-3333-3333-3333-333333333333"
    records = [
        _cloudtrail_record(arn, same_id, sourceIPAddress="10.0.0.1"),
        _cloudtrail_record(arn, same_id, sourceIPAddress="10.0.0.1"),
    ]
    src = _write_cloudtrail_fixture(tmp_path, records)
    db = tmp_path / "out.db"
    initialize_database(db, {"source": str(src)})
    CloudTrailParser().extract_entities(src, db)

    conn = sqlite3.connect(str(db))
    try:
        count = conn.execute(
            "SELECT COUNT(*) FROM observations WHERE event_type='DescribeInstances'"
        ).fetchone()[0]
    finally:
        conn.close()
    assert count == 1


def test_cloudtrail_dedup_idempotent_across_reruns(tmp_path):
    """Running extract_entities twice on the same fixture must not double
    the observation count — the eventID-aware dedup stays idempotent."""
    from icarus.parsers.cloud.aws.cloudtrail import CloudTrailParser

    arn = "arn:aws:iam::123456789012:user/dup-test"
    records = [
        _cloudtrail_record(arn, "44444444-4444-4444-4444-444444444444"),
        _cloudtrail_record(arn, "55555555-5555-5555-5555-555555555555"),
    ]
    src = _write_cloudtrail_fixture(tmp_path, records)
    db = tmp_path / "out.db"
    initialize_database(db, {"source": str(src)})
    parser = CloudTrailParser()

    parser.extract_entities(src, db)
    conn = sqlite3.connect(str(db))
    first = conn.execute("SELECT COUNT(*) FROM observations").fetchone()[0]
    conn.close()

    parser.extract_entities(src, db)
    conn = sqlite3.connect(str(db))
    second = conn.execute("SELECT COUNT(*) FROM observations").fetchone()[0]
    conn.close()

    assert first == 2
    assert second == 2


def test_cloudtrail_dedup_missing_event_id_falls_back_safely(tmp_path):
    """Records without an eventID (malformed/legacy export) must not crash
    the build; two such records sharing entity/time/eventName still dedupe
    exactly like the pre-fix behavior."""
    from icarus.parsers.cloud.aws.cloudtrail import CloudTrailParser

    arn = "arn:aws:iam::123456789012:user/no-id-test"
    record = _cloudtrail_record(arn, event_id="")
    del record["eventID"]
    src = _write_cloudtrail_fixture(tmp_path, [record, dict(record)])
    db = tmp_path / "out.db"
    initialize_database(db, {"source": str(src)})

    stats = CloudTrailParser().extract_entities(src, db)
    assert stats["observations"] == 1

    conn = sqlite3.connect(str(db))
    try:
        props = conn.execute(
            "SELECT properties FROM observations WHERE event_type='DescribeInstances'"
        ).fetchone()[0]
    finally:
        conn.close()
    assert props is None or "eventID" not in json.loads(props)


# ---------------------------------------------------------------------------
# #88 — event_types conformance check in
# ParserTestHarness.test_schema_conformance, and repair of the dead loop.
# ---------------------------------------------------------------------------

def _cloudtrail_manifest_with_event_types(event_types):
    """A manifest identical to the real cloudtrail manifest except for a
    caller-controlled produces.event_types, so the conformance check can be
    exercised against both a covering and an under-declared contract."""
    real = load_manifest(PARSERS_DIR / "cloud" / "aws" / "cloudtrail.yaml")
    return ParserManifest(
        parser_id=real.parser_id,
        version=real.version,
        spec_version=real.spec_version,
        author=real.author,
        license=real.license,
        quality_tier=real.quality_tier,
        description=real.description,
        identify=real.identify,
        consumes=real.consumes,
        produces={"entity_types": real.produces["entity_types"], "event_types": event_types},
        dependencies=real.dependencies,
        reliability=real.reliability,
        default_confidence=real.default_confidence,
        tests=real.tests,
    )


_REAL_CLOUDTRAIL_FIXTURE = FIXTURES_DIR / "cloud_aws_cloudtrail"
_REAL_CLOUDTRAIL_EVENT_TYPES = {
    "DescribeInstances", "GetBucketPolicy", "CreateUser",
    "ConsoleLogin", "ListFunctions", "DescribeSecurityGroups",
}


def test_schema_conformance_passes_when_event_types_cover_fixture():
    """When manifest.produces.event_types is a superset of what the fixture
    actually produces, schema_conformance passes."""
    from icarus.parsers.cloud.aws.cloudtrail import CloudTrailParser

    manifest = _cloudtrail_manifest_with_event_types(sorted(_REAL_CLOUDTRAIL_EVENT_TYPES))
    harness = ParserTestHarness(CloudTrailParser(), manifest, _REAL_CLOUDTRAIL_FIXTURE)
    result = harness.test_schema_conformance()
    assert result.passed, result.message


def test_schema_conformance_catches_undeclared_event_type():
    """#88: before the fix, event_type drift against manifest.produces
    .event_types was invisible — 'observations' sat in the schema-conformance
    skip set and no test ever read event_types at all. An under-declared
    manifest must now fail the gate with an actionable message."""
    from icarus.parsers.cloud.aws.cloudtrail import CloudTrailParser

    manifest = _cloudtrail_manifest_with_event_types(["ConsoleLogin"])  # misses 5 of 6
    harness = ParserTestHarness(CloudTrailParser(), manifest, _REAL_CLOUDTRAIL_FIXTURE)
    result = harness.test_schema_conformance()

    assert not result.passed
    assert "event_type" in result.message
    assert "DescribeInstances" in result.message


def test_schema_conformance_skips_event_type_check_when_undeclared():
    """Parsers whose manifest does not declare event_types at all (the
    schema field is optional) are not penalized — the check only activates
    when the parser opts in."""
    from icarus.parsers.linux import LinuxParser

    manifest = load_manifest(PARSERS_DIR / "linux.yaml")
    assert manifest.produces.get("event_types") is None  # linux never declares it
    harness = ParserTestHarness(LinuxParser(), manifest, FIXTURES_DIR / "linux")
    result = harness.test_schema_conformance()
    assert result.passed, result.message


def test_schema_conformance_still_catches_undeclared_entity_table():
    """Repairing the dead first loop must not regress the real (second-loop)
    check: an entity emitted into a table absent from produces.entity_types
    is still flagged."""
    from icarus.parsers.linux import LinuxParser

    real = load_manifest(PARSERS_DIR / "linux.yaml")
    narrowed = ParserManifest(
        parser_id=real.parser_id, version=real.version, spec_version=real.spec_version,
        author=real.author, license=real.license, quality_tier=real.quality_tier,
        description=real.description, identify=real.identify, consumes=real.consumes,
        produces={"entity_types": ["files"]},  # drops binaries/daemons/frameworks
        dependencies=real.dependencies, reliability=real.reliability,
        default_confidence=real.default_confidence, tests=real.tests,
    )
    harness = ParserTestHarness(LinuxParser(), narrowed, FIXTURES_DIR / "linux")
    result = harness.test_schema_conformance()
    assert not result.passed
    assert "not in produces" in result.message


# ---------------------------------------------------------------------------
# #138 — golden-output gate must inspect content (not just counts) and must
# assert the golden file's own declared zero_pii / has_relationships fields.
# ---------------------------------------------------------------------------

def _cloudtrail_manifest_with_golden(golden_path):
    real = load_manifest(PARSERS_DIR / "cloud" / "aws" / "cloudtrail.yaml")
    return ParserManifest(
        parser_id=real.parser_id, version=real.version, spec_version=real.spec_version,
        author=real.author, license=real.license, quality_tier=real.quality_tier,
        description=real.description, identify=real.identify, consumes=real.consumes,
        produces=real.produces, dependencies=real.dependencies, reliability=real.reliability,
        default_confidence=real.default_confidence,
        tests={"golden_output": str(golden_path)},
    )


def _single_record_cloudtrail_fixture(tmp_path, arn_user):
    from icarus.parsers.cloud.aws.cloudtrail import CloudTrailParser

    record = _cloudtrail_record(
        f"arn:aws:iam::123456789012:user/{arn_user}",
        "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
    )
    src = _write_cloudtrail_fixture(tmp_path, [record])
    return CloudTrailParser(), src


def test_golden_output_content_fingerprint_catches_same_count_different_content(tmp_path):
    """#138: two runs can share identical entity_counts while the actual row
    content differs (e.g. a different IAM ARN). The old count-only gate
    called these equivalent; the fingerprint must now tell them apart."""
    parser_a, src_a = _single_record_cloudtrail_fixture(tmp_path / "a", "alice")
    parser_b, src_b = _single_record_cloudtrail_fixture(tmp_path / "b", "bob")

    db_a = tmp_path / "a.db"
    initialize_database(db_a, {"source": str(src_a)})
    parser_a.extract_entities(src_a, db_a)

    db_b = tmp_path / "b.db"
    initialize_database(db_b, {"source": str(src_b)})
    parser_b.extract_entities(src_b, db_b)

    conn_a = sqlite3.connect(str(db_a))
    conn_b = sqlite3.connect(str(db_b))
    try:
        counts_a = {t: conn_a.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0]
                    for t in ("files", "daemons")}
        counts_b = {t: conn_b.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0]
                    for t in ("files", "daemons")}
        assert counts_a == counts_b  # counts alone cannot tell these apart

        fp_a = ParserTestHarness._content_fingerprint(conn_a, ["files", "daemons"])
        fp_b = ParserTestHarness._content_fingerprint(conn_b, ["files", "daemons"])
    finally:
        conn_a.close()
        conn_b.close()

    assert fp_a != fp_b, "fingerprint failed to distinguish different content with equal counts"

    golden_path = tmp_path / "golden_a.json"
    golden_path.write_text(json.dumps({"entity_counts": counts_a, "content_fingerprint": fp_a}))
    manifest = _cloudtrail_manifest_with_golden(golden_path)

    # Golden built from run A's content must reject run B's DB...
    harness_b = ParserTestHarness(parser_b, manifest, src_b)
    result_b = harness_b.test_golden_output()
    assert not result_b.passed
    assert "content_fingerprint" in result_b.message

    # ...and must accept run A's own DB.
    harness_a = ParserTestHarness(parser_a, manifest, src_a)
    result_a = harness_a.test_golden_output()
    assert result_a.passed, result_a.message


def test_golden_output_flags_wrong_declared_zero_pii(tmp_path):
    """#138: golden files carry a zero_pii field that nothing ever checked
    against reality. A golden that misdeclares zero_pii must now fail."""
    parser, src = _single_record_cloudtrail_fixture(tmp_path, "carol")
    golden_path = tmp_path / "golden.json"
    golden_path.write_text(json.dumps({
        "entity_counts": {"files": 1, "daemons": 1},
        # The synthetic event UUID is intentionally detected. Declaring this
        # raw parser output clean must fail the golden comparison.
        "zero_pii": True,
    }))
    manifest = _cloudtrail_manifest_with_golden(golden_path)
    harness = ParserTestHarness(parser, manifest, src)
    result = harness.test_golden_output()
    assert not result.passed
    assert "zero_pii" in result.message


def test_golden_output_flags_wrong_declared_has_relationships(tmp_path):
    """#138: a golden claiming has_relationships=True for a parser whose
    extract_relationships is a documented no-op must now fail, not pass."""
    parser, src = _single_record_cloudtrail_fixture(tmp_path, "dave")
    golden_path = tmp_path / "golden.json"
    golden_path.write_text(json.dumps({
        "entity_counts": {"files": 1, "daemons": 1},
        "has_relationships": True,  # cloudtrail.extract_relationships() -> {"linked": 0}
    }))
    manifest = _cloudtrail_manifest_with_golden(golden_path)
    harness = ParserTestHarness(parser, manifest, src)
    result = harness.test_golden_output()
    assert not result.passed
    assert "has_relationships" in result.message


def test_golden_output_accepts_correct_declared_fields(tmp_path):
    """Sanity check: correctly declared zero_pii/has_relationships/
    content_fingerprint all together still pass."""
    parser, src = _single_record_cloudtrail_fixture(tmp_path, "erin")
    db = tmp_path / "probe.db"
    initialize_database(db, {"source": str(src)})
    parser.extract_entities(src, db)
    conn = sqlite3.connect(str(db))
    try:
        counts = {t: conn.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0]
                  for t in ("files", "daemons")}
        fp = ParserTestHarness._content_fingerprint(conn, list(counts.keys()))
    finally:
        conn.close()
    db.unlink()

    golden_path = tmp_path / "golden.json"
    golden_path.write_text(json.dumps({
        "entity_counts": counts,
        "content_fingerprint": fp,
        # The raw fixture retains its synthetic event UUID; the full pipeline's
        # HYGEIA phase removes it before an output is represented as shareable.
        "zero_pii": False,
        "has_relationships": False,
        "observation_count": 1,
    }))
    manifest = _cloudtrail_manifest_with_golden(golden_path)
    harness = ParserTestHarness(parser, manifest, src)
    result = harness.test_golden_output()
    assert result.passed, result.message


# ---------------------------------------------------------------------------
# #143 — activate the harness (run_all(), every HarnessResult.passed) for
# the linux parser and each generic/* production parser: their golden files
# were wired in their manifests but no test ever ran ParserTestHarness
# against them.
# ---------------------------------------------------------------------------

_STATIC_HARNESS_CASES = [
    ("icarus.parsers.linux", "LinuxParser", "linux.yaml", "linux"),
    ("icarus.parsers.generic.archive_parser", "ArchiveParser",
     "generic/archive_parser.yaml", "generic_archive"),
    ("icarus.parsers.generic.binary_entropy_parser", "BinaryEntropyParser",
     "generic/binary_entropy_parser.yaml", "generic_binary"),
    ("icarus.parsers.generic.json_parser", "JsonParser",
     "generic/json_parser.yaml", "generic_json"),
    ("icarus.parsers.generic.xml_parser", "XmlParser",
     "generic/xml_parser.yaml", "generic_xml"),
]


@pytest.mark.parametrize("mod_name,cls_name,manifest_rel,fixture_name", _STATIC_HARNESS_CASES)
def test_production_parser_harness_all_pass(mod_name, cls_name, manifest_rel, fixture_name):
    """#143: run all four mandatory gates (golden/schema/idempotency/
    zero-pii) for a production parser whose golden file was wired but
    never exercised."""
    mod = importlib.import_module(mod_name)
    cls = getattr(mod, cls_name)
    manifest = load_manifest(PARSERS_DIR / manifest_rel)
    harness = ParserTestHarness(cls(), manifest, FIXTURES_DIR / fixture_name)
    results = harness.run_all()
    for r in results:
        assert r.passed, f"{cls_name} {r.test_name} failed: {r.message}"


def test_generic_sqlite_harness_all_pass():
    """#143/#96: exercise the SQLite parser's installed self-test corpus."""
    from icarus.parsers.generic.sqlite_parser import SqliteParser
    from icarus.parsers.testing import resolve_test_resource

    manifest = load_manifest(PARSERS_DIR / "generic" / "sqlite_parser.yaml")
    fixtures = resolve_test_resource(manifest.tests["fixtures_dir"])
    harness = ParserTestHarness(SqliteParser(), manifest, fixtures)
    results = harness.run_all()
    for r in results:
        assert r.passed, f"SqliteParser {r.test_name} failed: {r.message}"
