"""Tests for the macOS / iOS parser and Mach-O entitlement extraction."""

import plistlib
import sqlite3
import struct
from pathlib import Path

import pytest

FIXTURES_DIR = Path(__file__).parent / "fixtures"
PARSERS_DIR = Path(__file__).parent.parent / "icarus" / "parsers"
GATES = ["test_golden_output", "test_schema_conformance", "test_idempotency", "test_zero_pii"]


def _harness():
    from icarus.parsers.macos import MacosParser
    from icarus.parsers.manifest import load_manifest
    from icarus.parsers.testing import ParserTestHarness

    manifest = load_manifest(PARSERS_DIR / "macos.yaml")
    return ParserTestHarness(MacosParser(), manifest, FIXTURES_DIR / "macos")


@pytest.mark.parametrize("gate", GATES)
def test_macos_harness(gate):
    result = getattr(_harness(), gate)()
    assert result.passed, f"{gate} failed: {result.message}"


def test_macos_detects_fixture():
    from icarus.parsers import detect_parser

    assert detect_parser(FIXTURES_DIR / "macos") == "macos"


# ── Mach-O code-signature entitlement extraction ──

def _build_signed_macho(entitlements: dict, *, flags: int = 0x12000,
                        cputype: int = 0x0100000C) -> bytes:
    """A minimal arm64 Mach-O carrying an embedded-entitlements code signature.

    Layout: mach_header_64 (32) + LC_CODE_SIGNATURE (16) + code-signature
    SuperBlob (big-endian) holding a single CSSLOT_ENTITLEMENTS blob.
    """
    xml = plistlib.dumps(entitlements)
    ent_blob = struct.pack(">II", 0xFADE7171, 8 + len(xml)) + xml
    code_dir = struct.pack(">IIII", 0xFADE0C02, 16, 0, flags)
    ent_offset = 28
    code_dir_offset = ent_offset + len(ent_blob)
    body = (struct.pack(">II", 5, ent_offset)
            + struct.pack(">II", 0, code_dir_offset)
            + ent_blob + code_dir)
    superblob = struct.pack(">III", 0xFADE0CC0, 12 + len(body), 2) + body
    header = struct.pack("<IIIIIIII", 0xFEEDFACF, cputype, 0, 2, 1, 16, 0, 0)
    lc = struct.pack("<IIII", 0x1D, 16, 48, len(superblob))  # dataoff=48 = 32+16
    return header + lc + superblob


def _wrap_fat(slices: list[bytes], *, wide: bool = False,
              declared_sizes: list[int] | None = None) -> bytes:
    """Wrap thin slices in a FAT/FAT64 container with page-aligned offsets."""
    entry_size = 32 if wide else 20
    cursor = 0x1000
    entries = []
    payload = bytearray()
    for i, thin in enumerate(slices):
        cputype = int.from_bytes(thin[4:8], "little")
        size = declared_sizes[i] if declared_sizes else len(thin)
        if wide:
            entries.append(struct.pack(">IIQQII", cputype, 0, cursor, size, 12, 0))
        else:
            entries.append(struct.pack(">IIIII", cputype, 0, cursor, size, 12))
        if len(payload) < cursor - (8 + entry_size * len(slices)):
            payload.extend(b"\0" * (cursor - (8 + entry_size * len(slices)) - len(payload)))
        payload.extend(thin)
        cursor += len(thin)
    magic = 0xCAFEBABF if wide else 0xCAFEBABE
    return struct.pack(">II", magic, len(slices)) + b"".join(entries) + payload


def test_macho_entitlement_extraction(tmp_path):
    from icarus.parsers.macho import is_macho_magic, macho_info

    ents = {
        "get-task-allow": True,
        "com.apple.security.iokit-user-client-class": ["FooUserClient"],
    }
    b = tmp_path / "sample"
    b.write_bytes(_build_signed_macho(ents))
    assert is_macho_magic(b.read_bytes()[:4])
    info = macho_info(b)
    assert info["arch"] == "arm64"
    assert info["entitlements"] == ents
    assert info["code_sign_flags"] == 0x12000


@pytest.mark.parametrize("wide", [False, True], ids=["fat", "fat64"])
def test_fat_macho_codesign_matches_thin_slice(tmp_path, wide):
    from icarus.parsers.macho import macho_info

    thin_bytes = _build_signed_macho({"com.example.slice": True}, flags=0x20400)
    thin = tmp_path / "thin"
    fat = tmp_path / ("fat64" if wide else "fat")
    thin.write_bytes(thin_bytes)
    fat.write_bytes(_wrap_fat([thin_bytes], wide=wide))

    assert macho_info(fat) == macho_info(thin) == {
        "arch": "arm64",
        "entitlements": {"com.example.slice": True},
        "code_sign_flags": 0x20400,
    }


def test_fat_macho_codesign_cannot_escape_declared_slice(tmp_path):
    from icarus.parsers.macho import macho_info

    thin_bytes = _build_signed_macho({"com.example.neighbor": True}, flags=0x4000)
    fat = tmp_path / "truncated-slice"
    # The signature bytes physically follow the slice, but the FAT entry declares
    # that this architecture ends immediately after its load command.
    fat.write_bytes(_wrap_fat([thin_bytes], declared_sizes=[48]))

    assert macho_info(fat) == {
        "arch": "arm64",
        "entitlements": None,
        "code_sign_flags": None,
    }


def test_fat_macho_prefers_arm64_from_multiple_slices(tmp_path):
    from icarus.parsers.macho import macho_info

    x86 = _build_signed_macho({"arch": "x86"}, cputype=0x01000007)
    arm = _build_signed_macho({"arch": "arm"})
    fat = tmp_path / "universal"
    fat.write_bytes(_wrap_fat([x86, arm]))

    assert macho_info(fat)["arch"] == "arm64"
    assert macho_info(fat)["entitlements"] == {"arch": "arm"}


def test_macho_info_ignores_non_macho(tmp_path):
    from icarus.parsers.macho import macho_info

    junk = tmp_path / "notmacho"
    junk.write_bytes(b"this is not a mach-o file")
    assert macho_info(junk) is None


def test_macos_end_to_end_with_binary(tmp_path):
    """Full parse of a mini rootfs with a signed Mach-O daemon program.

    Exercises binaries, entitlements, the daemon->binary relationship,
    normalized mach_services, and the attack-surface queries end to end.
    """
    from icarus.core.query import IcarusQuery
    from icarus.core.schema import initialize_database
    from icarus.parsers.macos import MacosParser

    root = tmp_path / "rootfs"
    (root / "System/Library/CoreServices").mkdir(parents=True)
    (root / "System/Library/LaunchDaemons").mkdir(parents=True)
    (root / "usr/libexec").mkdir(parents=True)
    with open(root / "System/Library/CoreServices/SystemVersion.plist", "wb") as f:
        plistlib.dump({"ProductVersion": "26.5"}, f)
    (root / "usr/libexec/testd").write_bytes(_build_signed_macho({
        "get-task-allow": True,
        "com.apple.security.iokit-user-client-class": ["TestUserClient"],
    }))
    with open(root / "System/Library/LaunchDaemons/com.test.testd.plist", "wb") as f:
        plistlib.dump({
            "Label": "com.test.testd", "Program": "/usr/libexec/testd",
            "MachServices": {"com.test.testd": True, "com.test.testd.aux": True},
            "UserName": "root", "RunAtLoad": True,
        }, f)

    db = tmp_path / "out.db"
    initialize_database(db, {"source": str(root)})
    p = MacosParser()
    p.extract_entities(root, db)
    assert p.extract_relationships(root, db)["linked"] == 1

    conn = sqlite3.connect(str(db))
    try:
        assert conn.execute("SELECT COUNT(*) FROM binaries").fetchone()[0] == 1
        assert conn.execute("SELECT arch FROM binaries").fetchone()[0] == "arm64"
        assert conn.execute("SELECT COUNT(*) FROM entitlements").fetchone()[0] == 2
        assert conn.execute("SELECT COUNT(*) FROM mach_services").fetchone()[0] == 2
        assert conn.execute(
            "SELECT binary_id FROM daemons WHERE label='com.test.testd'"
        ).fetchone()[0] is not None
    finally:
        conn.close()

    with IcarusQuery(str(db)) as q:
        owners = q.mach_service_owners("com.test.%")
        assert owners.count == 2
        assert all(row[1] == "com.test.testd" for row in owners.rows)

        surface = q.daemons_with_entitlement("com.apple.security.iokit-user-client-class")
        assert surface.count == 1
        assert surface.rows[0][0] == "com.test.testd"

        # unsandboxed daemon exposing Mach services with entitlements
        assert q.escape_surface().count == 1


def test_daemon_feature_flag_conditional_values(tmp_path):
    """iOS 27 launchd plists use feature-flag conditional dicts for keys that
    are normally scalars (UserName/GroupName/LimitLoadToSessionType). The parser
    must store them as JSON text instead of crashing on the SQLite bind.

    Regression for the iPhone16,1 27.0 (24A5370h) rootfs build, where
    com.apple.securityd's UserName is a feature-flag conditional dict.
    """
    import json

    from icarus.core.schema import initialize_database
    from icarus.parsers.macos import MacosParser

    root = tmp_path / "rootfs"
    (root / "System/Library/CoreServices").mkdir(parents=True)
    (root / "System/Library/LaunchDaemons").mkdir(parents=True)
    with open(root / "System/Library/CoreServices/SystemVersion.plist", "wb") as f:
        plistlib.dump({"ProductVersion": "27.0"}, f)
    cond = {"#IfFeatureFlagDisabled": "Security/SeparateUserKeychain",
            "#Then": "_securityd", "#Else": "mobile"}
    with open(root / "System/Library/LaunchDaemons/com.apple.securityd.plist", "wb") as f:
        plistlib.dump({
            "Label": "com.apple.securityd",
            "Program": "/usr/libexec/securityd",
            "MachServices": {"com.apple.securityd": True},
            "UserName": cond,
            "GroupName": {"#IfFeatureFlagDisabled": "Security/SeparateUserKeychain",
                          "#Then": "_securityd"},
            "LimitLoadToSessionType": {"#IfFeatureFlagEnabled": "UserManagement/SystemSessionD1",
                                       "#Then": "System"},
        }, f)

    db = tmp_path / "out.db"
    initialize_database(db, {"source": str(root)})
    p = MacosParser()
    stats = p.extract_entities(root, db)   # must not raise
    assert stats["daemons"] == 1

    conn = sqlite3.connect(str(db))
    try:
        user_name, group_name, session = conn.execute(
            "SELECT user_name, group_name, session_type FROM daemons "
            "WHERE label='com.apple.securityd'"
        ).fetchone()
    finally:
        conn.close()
    # conditional dicts are preserved as JSON text, not silently dropped
    assert json.loads(user_name) == cond
    assert json.loads(group_name)["#Then"] == "_securityd"
    assert json.loads(session)["#Then"] == "System"
