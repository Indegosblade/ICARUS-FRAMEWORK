"""Security regressions for the fail-closed HYGEIA integration (#41/#42)."""

import json
import sqlite3
from pathlib import Path

import pytest

from icarus.core.schema import initialize_database
from icarus.integrations import hygeia as hygeia_mod

SYNTHETIC_SECRETS = {
    "password": "SyntheticSecretValue-Only-For-Test",
    "aws_access_key": "AKIAABCDEFGHIJKLMNOP",
    "jwt": "eyJabcdefghijk.eyJabcdefghijk.abcdefghijklm",
    "wireguard_key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
    "bearer": "synthetic-bearer-token-value-1234567890",
}


@pytest.fixture
def secret_db(tmp_path):
    """Create an ICARUS DB with synthetic credentials across text surfaces."""
    db_path = tmp_path / "secrets.db"
    initialize_database(db_path, {"source": "synthetic-test"})
    conn = sqlite3.connect(str(db_path))
    rows = [
        f"password = {SYNTHETIC_SECRETS['password']}",
        f"aws_access_key = {SYNTHETIC_SECRETS['aws_access_key']}",
        f"Authorization: Bearer {SYNTHETIC_SECRETS['jwt']}",
        f"PrivateKey = {SYNTHETIC_SECRETS['wireguard_key']}",
        f"bearer_token = {SYNTHETIC_SECRETS['bearer']}",
        "-----BEGIN PRIVATE KEY-----",
    ]
    for index, value in enumerate(rows, start=1):
        conn.execute(
            """
            INSERT INTO observations
                (entity_table, entity_id, observed_at, observer, event_type, properties)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            ("files", index, "2026-01-01T00:00:00Z", "synthetic", "note", value),
        )

    # Metadata was skipped by the old verifier. It must now be sanitized too.
    conn.execute(
        "INSERT OR REPLACE INTO metadata (key, value) VALUES (?, ?)",
        ("synthetic_credential", f"password={SYNTHETIC_SECRETS['password']}"),
    )
    # files_fts mirrors these fields through triggers. Both the source table
    # and the searchable virtual table must be clean after sanitization.
    conn.execute(
        "INSERT INTO files (path, filename, file_type) VALUES (?, ?, ?)",
        (
            f"/tmp/password={SYNTHETIC_SECRETS['password']}",
            f"Bearer {SYNTHETIC_SECRETS['bearer']}",
            "synthetic",
        ),
    )
    conn.commit()
    conn.close()
    return db_path


def _all_public_text(db_path: Path) -> str:
    conn = sqlite3.connect(str(db_path))
    try:
        values = []
        for table, columns in hygeia_mod._get_text_columns(conn).items():
            quoted_table = hygeia_mod._quote_ident(table)
            select_list = ", ".join(hygeia_mod._quote_ident(column) for column in columns)
            for row in conn.execute(f"SELECT {select_list} FROM {quoted_table}"):
                values.extend(value for value in row if isinstance(value, str))
        return "\n".join(values)
    finally:
        conn.close()


def test_real_hygeia_api_is_active():
    engine = hygeia_mod.require_hygeia()

    assert hygeia_mod.using_standalone_hygeia() is True
    assert engine["engine"] == "hygeia.sqlite_sanitizer.sanitize_database_generic"
    assert engine["mode"] == "fail-closed"


def test_sanitize_removes_credentials_and_enforces_post_gate(secret_db):
    stats = hygeia_mod.sanitize_output(secret_db)
    output = _all_public_text(secret_db)

    assert stats["verified"] is True
    assert stats["post_sanitize_findings"] == 0
    assert stats["redacted"] >= len(SYNTHETIC_SECRETS)
    assert "password_kv" in stats["patterns_found"]
    assert "private_key_kv" in stats["patterns_found"]
    for secret in SYNTHETIC_SECRETS.values():
        assert secret not in output

    verified = hygeia_mod.verify_clean(secret_db)
    assert verified["passed"] is True
    assert verified["total_findings"] == 0


def test_findings_and_metadata_never_retain_raw_secret(secret_db):
    before = hygeia_mod.verify_clean(secret_db)
    stats = hygeia_mod.sanitize_output(secret_db)

    conn = sqlite3.connect(str(secret_db))
    audit_json = conn.execute(
        "SELECT value FROM metadata WHERE key = 'hygeia_audit'"
    ).fetchone()[0]
    engine_json = conn.execute(
        "SELECT value FROM metadata WHERE key = 'hygeia_engine'"
    ).fetchone()[0]
    conn.close()

    serialized = json.dumps({"before": before, "stats": stats, "audit": audit_json})
    for secret in SYNTHETIC_SECRETS.values():
        assert secret not in serialized

    assert before["findings"]
    assert all("sample" not in finding for finding in before["findings"])
    assert all(
        finding["fingerprint"].startswith("hmac-sha256:")
        for finding in before["findings"]
    )
    assert json.loads(audit_json)["verified"] is True
    assert json.loads(engine_json)["mode"] == "fail-closed"


def test_full_pipeline_sanitizes_seeded_cloudtrail_secret(tmp_path):
    from icarus.core.pipeline import create_default_pipeline

    source = tmp_path / "cloudtrail"
    source.mkdir()
    secret = SYNTHETIC_SECRETS["password"]
    payload = {
        "Records": [
            {
                "eventVersion": "1.08",
                "userIdentity": {
                    "type": "IAMUser",
                    "arn": "arn:aws:iam::123456789012:user/synthetic",
                    "accountId": "123456789012",
                },
                "eventTime": "2026-01-01T00:00:00Z",
                "eventSource": "iam.amazonaws.com",
                "eventName": "DescribeInstances",
                "awsRegion": "us-east-1",
                "errorMessage": f"password={secret}",
            }
        ]
    }
    (source / "events.json").write_text(json.dumps(payload), encoding="utf-8")
    output = tmp_path / "output.db"

    pipeline = create_default_pipeline(source, output, "cloud/aws/cloudtrail")
    context = pipeline.run(resume=False)

    assert context.stats["sanitizer"]["mode"] == "fail-closed"
    assert context.stats["sanitize"]["verified"] is True
    assert context.stats["sanitize_final_gate"]["passed"] is True
    assert secret not in _all_public_text(output)
    verification = hygeia_mod.verify_clean(output)
    assert verification["passed"] is True, verification

    conn = sqlite3.connect(str(output))
    started_at, completed_at = conn.execute(
        "SELECT started_at, completed_at FROM versions"
    ).fetchone()
    conn.close()
    assert "REDACTED" not in started_at
    assert "REDACTED" not in completed_at


def test_missing_hygeia_fails_closed_before_output_is_created(tmp_path, monkeypatch):
    from icarus.core.pipeline import create_default_pipeline

    source = tmp_path / "source"
    source.mkdir()
    (source / "input.json").write_text('{"safe": true}', encoding="utf-8")
    output = tmp_path / "output.db"
    monkeypatch.setattr(hygeia_mod, "_HAS_HYGEIA_PACKAGE", False)

    with pytest.raises(hygeia_mod.HygeiaUnavailableError, match="HYGEIA is required"):
        create_default_pipeline(source, output, "generic/json")

    assert not output.exists()


def test_final_pipeline_gate_invalidates_clean_marker_on_late_secret(tmp_path):
    from icarus.core.pipeline import create_default_pipeline

    source = tmp_path / "source"
    source.mkdir()
    (source / "input.json").write_text('{"safe": true}', encoding="utf-8")
    output = tmp_path / "output.db"
    secret = SYNTHETIC_SECRETS["password"]
    pipeline = create_default_pipeline(source, output, "generic/json")
    original_finalize = pipeline._finalize_version_record

    def inject_after_sanitize():
        original_finalize()
        conn = sqlite3.connect(str(output))
        conn.execute(
            "INSERT OR REPLACE INTO metadata (key, value) VALUES (?, ?)",
            ("late_write", f"password={secret}"),
        )
        conn.commit()
        conn.close()

    pipeline._finalize_version_record = inject_after_sanitize

    with pytest.raises(hygeia_mod.SanitizationError) as caught:
        pipeline.run(resume=False)

    assert secret not in str(caught.value)
    assert pipeline.checkpoint_db.exists()
    conn = sqlite3.connect(str(output))
    status = conn.execute(
        "SELECT value FROM metadata WHERE key = 'hygeia_status'"
    ).fetchone()[0]
    audit = conn.execute(
        "SELECT value FROM metadata WHERE key = 'hygeia_audit'"
    ).fetchone()
    conn.close()
    assert status == "FAILED: output is not safe to share"
    assert audit is None


def test_noop_sanitizer_is_caught_by_mandatory_post_gate(secret_db, monkeypatch):
    def noop(_path, registry):
        return {"rows_redacted": 0, "integrity_post": True}

    # Bypass BOTH redaction paths — ICARUS's scoped redactor and the HYGEIA
    # engine — so that nothing is redacted and the independent post-sanitize
    # gate is what must fail closed on the residual secrets.
    monkeypatch.setattr(hygeia_mod, "_redact_scoped", lambda _path, _registry: 0)
    monkeypatch.setattr(hygeia_mod, "sanitize_database_generic", noop)

    with pytest.raises(hygeia_mod.SanitizationError) as caught:
        hygeia_mod.sanitize_output(secret_db)

    message = str(caught.value)
    assert "Post-sanitize verification found" in message
    for secret in SYNTHETIC_SECRETS.values():
        assert secret not in message

    conn = sqlite3.connect(str(secret_db))
    marker = conn.execute(
        "SELECT value FROM metadata WHERE key = 'hygeia_engine'"
    ).fetchone()
    conn.close()
    assert marker is None


def test_dependency_exception_is_redacted_from_pipeline_error(secret_db, monkeypatch):
    raw_secret = SYNTHETIC_SECRETS["password"]

    def broken(_path, registry):
        raise ValueError(f"dependency leaked {raw_secret}")

    monkeypatch.setattr(hygeia_mod, "sanitize_database_generic", broken)

    with pytest.raises(hygeia_mod.SanitizationError) as caught:
        hygeia_mod.sanitize_output(secret_db)

    assert raw_secret not in str(caught.value)
    assert caught.value.__cause__ is None


def test_ontology_name_columns_are_not_blanket_redacted(tmp_path):
    db_path = tmp_path / "ontology.db"
    initialize_database(db_path)
    conn = sqlite3.connect(str(db_path))
    conn.execute(
        "INSERT INTO frameworks (name, path, version) VALUES (?, ?, ?)",
        ("SecurityFramework", "/System/Library/Frameworks/Security.framework", "1.0"),
    )
    conn.commit()
    conn.close()

    hygeia_mod.sanitize_output(db_path)

    conn = sqlite3.connect(str(db_path))
    name = conn.execute("SELECT name FROM frameworks").fetchone()[0]
    conn.close()
    assert name == "SecurityFramework"


def test_unknown_table_is_scanned_instead_of_silently_ignored(tmp_path):
    db_path = tmp_path / "unknown-table.db"
    initialize_database(db_path)
    conn = sqlite3.connect(str(db_path))
    conn.execute("CREATE TABLE extension_data (id INTEGER PRIMARY KEY, notes TEXT)")
    conn.execute(
        "INSERT INTO extension_data (notes) VALUES (?)",
        (f"password={SYNTHETIC_SECRETS['password']}",),
    )
    conn.commit()
    conn.close()

    stats = hygeia_mod.sanitize_output(db_path)

    conn = sqlite3.connect(str(db_path))
    value = conn.execute("SELECT notes FROM extension_data").fetchone()[0]
    conn.close()
    assert SYNTHETIC_SECRETS["password"] not in value
    assert any(finding["table"] == "extension_data" for finding in stats["findings"])


def test_structural_columns_survive_value_pattern_false_positives(tmp_path):
    """#76: value-content patterns must not fire on structural path columns.

    Real filesystem paths whose text happens to match email/ip_v4/swift_bic/uuid
    must be preserved verbatim (not corrupted, not treated as residual secrets
    that abort the fail-closed build), while genuine usernames in the same
    column are still redacted.
    """
    db_path = tmp_path / "fp.db"
    initialize_database(db_path)
    conn = sqlite3.connect(str(db_path))
    survivors = [
        "/lib/modules/6.6.87.2-microsoft-standard-WSL2/kernel/x.ko",  # ip_v4 shape
        "/share/doc/git/RelNotes/1.5.0.1.txt",                        # ip_v4 shape
        "/lib/wsl/drivers/foo/RTKVHD64.sys",                          # swift_bic shape
        "/lib/systemd/system/user@0.service",                        # email shape
        "/Windows/System32/07409496-a423-4a3e-b620-2cfb01a9318d.dll",  # uuid shape
    ]
    redact_me = ["/home/alice/notes.txt", "/home/über/u.txt", "/Users/bob/x"]
    for p in survivors + redact_me:
        conn.execute(
            "INSERT INTO files (path, filename, file_type) VALUES (?, ?, ?)",
            (p, p.rsplit("/", 1)[-1], "other"),
        )
    # A value column must still get the full pattern set.
    conn.execute(
        "INSERT INTO observations (entity_table, entity_id, observed_at, event_type, properties) "
        "VALUES ('files', 1, '2026-01-01T00:00:00Z', 'note', ?)",
        ('{"src_ip": "203.0.113.9", "contact": "ops@corp.example"}',),
    )
    conn.commit()
    conn.close()

    # Must NOT abort — this is the real-world failure the fix addresses.
    hygeia_mod.sanitize_output(db_path)

    conn = sqlite3.connect(str(db_path))
    paths = [r[0] for r in conn.execute("SELECT path FROM files")]
    props = conn.execute("SELECT properties FROM observations").fetchone()[0]
    status = conn.execute(
        "SELECT value FROM metadata WHERE key = 'hygeia_status'"
    ).fetchone()[0]
    conn.close()

    assert status == "verified"
    for p in survivors:
        assert p in paths, f"structural path corrupted or dropped: {p}"
    assert not any(p in paths for p in redact_me), "username path not redacted"
    assert all(p.startswith("[REDACTED_USERNAME_PATH]") for p in paths if "REDACTED" in p)
    # value column still sanitized
    assert "203.0.113.9" not in props and "ops@corp.example" not in props
    assert "REDACTED_IP_V4" in props and "REDACTED_EMAIL" in props


def test_unknown_table_gets_full_value_patterns(tmp_path):
    """#76/#42: extension tables are not in the structural exemption — an IP in
    an unknown table's free-text column is still redacted (full pattern set)."""
    db_path = tmp_path / "ext.db"
    initialize_database(db_path)
    conn = sqlite3.connect(str(db_path))
    conn.execute("CREATE TABLE ext_notes (id INTEGER PRIMARY KEY, body TEXT)")
    conn.execute("INSERT INTO ext_notes (body) VALUES (?)", ("callback to 203.0.113.9 now",))
    conn.commit()
    conn.close()

    hygeia_mod.sanitize_output(db_path)

    conn = sqlite3.connect(str(db_path))
    body = conn.execute("SELECT body FROM ext_notes").fetchone()[0]
    conn.close()
    assert "203.0.113.9" not in body and "REDACTED_IP_V4" in body


def test_sanitization_status_classifies_markers(tmp_path):
    """#77: sanitization_status maps metadata markers to a posture."""
    def _db(name, **markers):
        p = tmp_path / name
        initialize_database(p)
        conn = sqlite3.connect(str(p))
        for k, v in markers.items():
            conn.execute("INSERT OR REPLACE INTO metadata (key, value) VALUES (?, ?)", (k, v))
        conn.commit()
        conn.close()
        return p

    engine = {"engine": "test", "version": "1", "mode": "fail-closed"}
    audit = {
        "audit_version": hygeia_mod.AUDIT_VERSION,
        "engine": engine,
        "verified": True,
        "post_gate": {"passed": True, "total_findings": 0},
    }
    assert hygeia_mod.sanitization_status(_db(
        "v.db",
        hygeia_status="verified",
        hygeia_engine=json.dumps(engine),
        hygeia_audit=json.dumps(audit),
    )) == "verified"
    assert hygeia_mod.sanitization_status(_db("forged.db", hygeia_status="verified")) == "unknown"
    assert hygeia_mod.sanitization_status(_db("s.db", hygeia_skipped="true")) == "skipped"
    failed = _db("f.db")
    hygeia_mod.mark_sanitization_failed(failed)
    assert hygeia_mod.sanitization_status(failed) == "failed"
    assert hygeia_mod.sanitization_status(_db("u.db")) == "unknown"
    assert hygeia_mod.sanitization_status(tmp_path / "missing.db") == "unknown"


def test_failed_sanitize_phase_marks_database(tmp_path, monkeypatch):
    """#77: when the sanitize PHASE raises on the default (non-atomic) path, the
    output left on disk is stamped FAILED so `query` refuses it."""
    from icarus.core.pipeline import create_default_pipeline

    src = tmp_path / "src"
    (src / "etc").mkdir(parents=True)
    (src / "usr" / "bin").mkdir(parents=True)
    (src / "lib" / "systemd" / "system").mkdir(parents=True)
    (src / "etc" / "passwd").write_text("root:x:0:0:root:/root:/bin/bash\n")
    (src / "usr" / "bin" / "true").write_bytes(b"\x7fELF\x02\x01\x01\x00")
    out = tmp_path / "out.db"

    def boom(_db_path):
        raise hygeia_mod.SanitizationError("forced residual")

    monkeypatch.setattr(hygeia_mod, "sanitize_output", boom)

    pipeline = create_default_pipeline(src, out, "linux")
    with pytest.raises(hygeia_mod.SanitizationError):
        pipeline.run(resume=True)

    assert out.exists()  # default path is non-atomic; the file is left behind
    assert hygeia_mod.sanitization_status(out) == "failed"


def test_quote_ident_escapes_embedded_double_quotes():
    assert hygeia_mod._quote_ident("files") == '"files"'
    assert hygeia_mod._quote_ident('weird"name') == '"weird""name"'
