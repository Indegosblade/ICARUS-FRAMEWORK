"""Configuration evidence must not become an invented runtime privilege (#110)."""

import plistlib
import sqlite3
from contextlib import closing

import pytest

from icarus.core.pipeline import create_default_pipeline
from icarus.core.query import IcarusQuery
from icarus.core.schema import initialize_database
from icarus.parsers.base import BaseParser
from icarus.parsers.linux import MAX_SYSTEMD_UNIT_BYTES, LinuxParser, _parse_service_identity
from icarus.parsers.macos import MacosParser
from tests.test_macos import _build_signed_macho


@pytest.mark.parametrize(("source", "expected"), [
    ("[Service]\nUser=nobody\nGroup=daemon\n", ("nobody", "daemon")),
    ("[Unit]\nUser=root\n[Service]\nGroup=daemon\n", (None, "daemon")),
    ("[Service]\nUser=nobody\n[Install]\nUser=root\n", ("nobody", None)),
    ("[Service]\nUser=root\nUser=nobody\nGroup=root\nGroup=daemon\n", ("nobody", "daemon")),
    ("[Service]\nUser=nobody\nUser=\nGroup=daemon\nGroup=\n", (None, None)),
    ("[Service]\nUser=root\n[Unit]\nUser=other\n[Service]\nUser=nobody\n", ("nobody", None)),
    ("[Service]\n# User=root\n; Group=root\n", (None, None)),
    ("[Service]\nUser=root # literal text\n", ("root # literal text", None)),
    ("[Service]\nUser=%i\nGroup=%u\n", ("%i", "%u")),
    ('[Service]\nUser="root"\n', ('"root"', None)),
    ("[Service]\nEnvironment=TEXT=\\\nUser=root\nGroup=daemon\n", (None, "daemon")),
    ("[Service]\nEnvironment=TEXT=\\\n# skipped comment\nUser=root\n", (None, None)),
    ("[Service]\nEnvironment=TEXT=\\\\\nUser=root\n", ("root", None)),
    ("[Service]\nEnvironment=TEXT=\\ \t\nUser=root\n", ("root", None)),
    ("[Service]\nUser=root\\", ("root", None)),
    ("[Service]\nEnvironment=TEXT=\\\nUser=root\\", (None, None)),
    ("[Service]\rUser=nobody\rGroup=daemon\r", ("nobody", "daemon")),
    ("[Service]\nUser=ro\\\not\n", ("ro ot", None)),
    ("[Service]\nUser=nobody\u2028User=root\n", ("nobody\u2028User=root", None)),
    ("[Service]\nUser=root\0\n", (None, None)),
])
def test_only_explicit_service_identity_assignments_are_preserved(tmp_path, source, expected):
    path = tmp_path / "example.service"
    path.write_bytes(source.encode("utf-8"))
    assert _parse_service_identity(path) == expected


def test_identity_read_cap_and_invalid_encoding_fail_unknown(tmp_path, monkeypatch):
    path = tmp_path / "example.service"
    path.write_bytes(b"[Service]\nUser=ro\xffot\n")
    assert _parse_service_identity(path) == (None, None)
    path.write_bytes(b"[Service]\nUser=root\n" + b"x" * MAX_SYSTEMD_UNIT_BYTES)
    assert _parse_service_identity(path) == (None, None)

    # A source can grow after lstat. The bounded read must still refuse partial
    # configuration rather than trusting an early User=root without later keys.
    class SmallStat:
        st_size = 1

    monkeypatch.setattr(
        BaseParser, "_file_kind", staticmethod(lambda path: (SmallStat(), "regular")),
    )
    assert _parse_service_identity(path) == (None, None)


def test_linux_build_preserves_users_provenance_and_excludes_unknown_root(tmp_path):
    source = tmp_path / "rootfs"
    units = source / "usr/lib/systemd/system"
    units.mkdir(parents=True)
    for name, identity in (
        ("nonroot", "User=nobody\nGroup=daemon\nNoNewPrivileges=yes\nProtectSystem=strict"),
        ("root", "User=root"), ("uidzero", "User=0"), ("unknown", ""),
        ("specifier", "User=%i"), ("quoted", 'User="root"'),
    ):
        (units / f"{name}.service").write_text(
            f"[Service]\nExecStart=/usr/bin/example\n{identity}\n", encoding="utf-8",
        )
    database = tmp_path / "linux.db"
    context = create_default_pipeline(source, database, "linux", skip_hygeia=True).run()
    with IcarusQuery(str(database)) as query:
        assert {row[0] for row in query.root_daemons().rows} == {"root", "uidzero"}
        rows = query.execute(
            "SELECT id,label,user_name,group_name,source_version_id,observed_time "
            "FROM daemons ORDER BY id"
        ).rows
    values = {row[1]: row for row in rows}
    assert values["nonroot"][2:4] == ("nobody", "daemon")
    assert values["unknown"][2] is None
    assert all(row[4] == context.version_id and row[5] for row in rows)

    # Direct re-extraction stays idempotent and does not rewrite existing IDs
    # or configured identity/provenance merely because a helper was added.
    LinuxParser().extract_entities(source, database)
    with IcarusQuery(str(database)) as query:
        assert query.execute(
            "SELECT id,label,user_name,group_name,source_version_id,observed_time "
            "FROM daemons ORDER BY id"
        ).rows == rows


def test_uid_zero_requires_linux_provenance(tmp_path):
    database = tmp_path / "mixed.db"
    initialize_database(database)
    with closing(sqlite3.connect(database)) as conn, conn:
        for parser in ("linux", "macos", "cloud/aws/cloudtrail"):
            version_id = conn.execute(
                "INSERT INTO versions(run_id,parser_name,started_at) VALUES(?,?,?)",
                (parser, parser, "2026-01-01"),
            ).lastrowid
            conn.execute(
                "INSERT INTO daemons(label,plist_path,user_name,source_version_id) VALUES(?,?,?,?)",
                (parser, parser, "0", version_id),
            )
        conn.execute("INSERT INTO daemons(label,plist_path,user_name) VALUES('legacy','/old','0')")
    with IcarusQuery(str(database)) as query:
        assert [row[0] for row in query.root_daemons().rows] == ["linux"]


def test_launch_agent_without_user_name_is_not_assumed_root(tmp_path):
    source = tmp_path / "rootfs"
    agents = source / "System/Library/LaunchAgents"
    agents.mkdir(parents=True)
    (agents / "agent.plist").write_bytes(plistlib.dumps({
        "Label": "com.example.agent", "Program": "/usr/bin/example",
    }))
    database = tmp_path / "macos.db"
    initialize_database(database)
    MacosParser().extract_entities(source, database)
    with IcarusQuery(str(database)) as query:
        assert query.execute("SELECT user_name FROM daemons").rows == [(None,)]
        assert query.root_daemons().rows == []


def test_entitlement_and_mach_service_joins_remain_unclassified_candidates(tmp_path):
    source = tmp_path / "rootfs"
    binary = source / "usr/bin/example"
    binary.parent.mkdir(parents=True)
    binary.write_bytes(_build_signed_macho({"com.example.marker": True}))
    jobs = source / "System/Library/LaunchDaemons"
    jobs.mkdir(parents=True)
    (jobs / "job.plist").write_bytes(plistlib.dumps({
        "Label": "com.example.nonroot", "Program": "/usr/bin/example", "UserName": "nobody",
        "MachServices": {"com.example.endpoint": True},
    }))
    database = tmp_path / "macos.db"
    initialize_database(database)
    parser = MacosParser()
    parser.extract_entities(source, database)
    parser.extract_relationships(source, database)
    with IcarusQuery(str(database)) as query:
        assert query.root_daemons().rows == []
        result = query.escape_surface()
        assert result.query_name == "Mach Service / Entitlement Declaration Candidates"
        assert result.as_dicts()[0]["entitlement_keys"] == "com.example.marker"
        assert "privileged_entitlements" not in result.columns
        assert query.execute(
            "SELECT privileged_entitlements FROM v_sandbox_escape_surface"
        ).rows == [("com.example.marker",)]
        assert query.privileged_entitlements().query_name == "Entitlement Key Inventory"
        assert query.privileged_entitlements().rows == [("com.example.marker", 1)]
        assert query.privileged_entitlements(["com.example.marker"]).query_name == (
            "Entitlements Matching Requested Keys"
        )
        assert query.kernel_surface().query_name == "Kernel User-Client Declaration Candidates"
