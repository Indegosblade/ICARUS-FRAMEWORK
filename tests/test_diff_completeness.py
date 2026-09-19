"""DIFF-02 (#35): full_diff() coverage, NULL-hash size compare, and Markdown
report escaping.

Three gaps closed here:
  1. full_diff() now covers every entity table (binaries, entitlements,
     frameworks, sandbox_profiles, sandbox_rules, mach_services) and calls
     observation_diff() + resolution_diff(), producing every category the
     module docstring advertises (incl. RESOLUTION_CHANGE).
  2. files_changed keyed on sha256 alone was blind to >=50 MB files and symlinks
     (sha256 = NULL): a content change that alters size is now reported via size.
  3. to_markdown() rendered source-derived paths/descriptions raw; a hostile
     value with backticks/pipes/newlines/control chars could break the report or
     inject content. All such values are now sanitized.
"""
import sqlite3
from pathlib import Path

import pytest

from icarus.core.differ import DiffCategory, DiffResult, IcarusDiffer, _md_sanitize
from icarus.core.schema import initialize_database


def _insert_min(conn, table, values):
    """INSERT filling any other NOT NULL non-pk column with a typed dummy."""
    info = conn.execute(f"PRAGMA table_info({table})").fetchall()
    data = dict(values)
    for _cid, name, typ, notnull, dflt, pk in info:
        if name in data or pk:
            continue
        if notnull and dflt is None:
            data[name] = 0 if "INT" in (typ or "").upper() else ""
    keys = list(data.keys())
    placeholders = ",".join(["?"] * len(keys))
    conn.execute(
        f"INSERT INTO {table} ({','.join(keys)}) VALUES ({placeholders})",
        [data[k] for k in keys],
    )


def _file_id(conn, path):
    return conn.execute("SELECT id FROM files WHERE path=?", (path,)).fetchone()[0]


def _last_id(conn, table):
    return conn.execute(f"SELECT MAX(id) FROM {table}").fetchone()[0]


# --------------------------------------------------------------------------- #
# 1. Coverage: every documented table/category shows up in full_diff().
# --------------------------------------------------------------------------- #
def _build_coverage_db(path, *, new: bool):
    """Build a DB with a diff in every entity table.

    Entities suffixed 'old' exist only in the OLD db, 'new' only in the NEW db;
    'common' entities exist in both (parents for keyed child diffs).
    """
    initialize_database(Path(path))
    conn = sqlite3.connect(str(path))
    try:
        # files: one common(changed), one add/remove side.
        _insert_min(conn, "files", {"path": "/change/c", "sha256": "new" if new else "old"})
        _insert_min(conn, "files", {"path": "/f/new" if new else "/f/old"})

        # binaries: keyed on owning file path -> distinct file per side.
        _insert_min(conn, "files", {"path": "/bin/new" if new else "/bin/old"})
        bfid = _file_id(conn, "/bin/new" if new else "/bin/old")
        _insert_min(conn, "binaries", {"file_id": bfid, "executable_name": "b"})

        # a common binary (same bundle_id) to host entitlement add/remove.
        _insert_min(conn, "files", {"path": "/bin/common"})
        cfid = _file_id(conn, "/bin/common")
        _insert_min(conn, "binaries",
                    {"file_id": cfid, "bundle_id": "com.common.bin", "executable_name": "c"})
        cbid = _last_id(conn, "binaries")
        _insert_min(conn, "entitlements",
                    {"binary_id": cbid, "key": "ent.new" if new else "ent.old", "value": "v"})

        # daemons: add/remove side + a common daemon for mach_services.
        _insert_min(conn, "daemons", {"label": "com.new.daemon" if new else "com.old.daemon"})
        _insert_min(conn, "daemons", {"label": "com.common.daemon"})
        cdid = conn.execute(
            "SELECT id FROM daemons WHERE label='com.common.daemon'").fetchone()[0]
        _insert_min(conn, "mach_services",
                    {"daemon_id": cdid, "service_name": "svc.new" if new else "svc.old"})

        # kexts.
        _insert_min(conn, "kexts", {"bundle_id": "com.new.kext" if new else "com.old.kext"})

        # frameworks.
        _insert_min(conn, "frameworks", {"path": "/fw/new" if new else "/fw/old"})

        # sandbox_profiles: add/remove side + a common profile for sandbox_rules.
        _insert_min(conn, "sandbox_profiles", {"name": "prof.new" if new else "prof.old"})
        _insert_min(conn, "sandbox_profiles", {"name": "prof.common"})
        cpid = conn.execute(
            "SELECT id FROM sandbox_profiles WHERE name='prof.common'").fetchone()[0]
        _insert_min(conn, "sandbox_rules",
                    {"profile_id": cpid,
                     "operation": "write" if new else "read", "action": "allow"})

        # observations: NEW db carries an extra observation on the changed file.
        cid = _file_id(conn, "/change/c")
        _insert_min(conn, "observations",
                    {"entity_table": "files", "entity_id": cid,
                     "event_type": "seen", "observed_at": "2026-01-01T00:00:00Z"})
        if new:
            _insert_min(conn, "observations",
                        {"entity_table": "files", "entity_id": cid,
                         "event_type": "exec", "observed_at": "2026-02-02T00:00:00Z"})

        # bags (resolution): a common bag whose atom_count changes + an add/remove side.
        _insert_min(conn, "bags",
                    {"entity_type": "file", "canonical_key": "bag.common",
                     "atom_count": 3 if new else 2, "score": 0.9,
                     "created_at": "2026-01-01T00:00:00Z"})
        _insert_min(conn, "bags",
                    {"entity_type": "file", "canonical_key": "bag.new" if new else "bag.old",
                     "atom_count": 1, "score": 0.5, "created_at": "2026-01-01T00:00:00Z"})

        conn.commit()
    finally:
        conn.close()


def test_full_diff_covers_every_documented_category(tmp_path):
    old, new = tmp_path / "old.db", tmp_path / "new.db"
    _build_coverage_db(old, new=False)
    _build_coverage_db(new, new=True)

    with IcarusDiffer(str(old), str(new)) as d:
        res = d.full_diff()

    # Every documented table appears as a result group.
    for name in (
        "files_added", "files_removed", "files_changed",
        "daemons_added", "daemons_removed",
        "kexts_added", "kexts_removed",
        "frameworks_added", "frameworks_removed",
        "sandbox_profiles_added", "sandbox_profiles_removed",
        "binaries", "entitlements", "sandbox_rules", "mach_services",
        "structural", "observations", "resolution",
    ):
        assert name in res, f"full_diff() omitted {name}"

    # ADDITION / DELETION for each table (add/remove side entities).
    assert any(r["path"] == "/f/new" for r in res["files_added"].added)
    assert any(r["path"] == "/f/old" for r in res["files_removed"].removed)
    assert any(r["label"] == "com.new.daemon" for r in res["daemons_added"].added)
    assert any(r["label"] == "com.old.daemon" for r in res["daemons_removed"].removed)
    assert any(r["bundle_id"] == "com.new.kext" for r in res["kexts_added"].added)
    assert any(r["bundle_id"] == "com.old.kext" for r in res["kexts_removed"].removed)
    assert any(r["path"] == "/fw/new" for r in res["frameworks_added"].added)
    assert any(r["path"] == "/fw/old" for r in res["frameworks_removed"].removed)
    assert any(r["name"] == "prof.new" for r in res["sandbox_profiles_added"].added)
    assert any(r["name"] == "prof.old" for r in res["sandbox_profiles_removed"].removed)

    # Join-keyed tables: added on the new side, removed on the old side.
    assert any(r["path"] == "/bin/new" for r in res["binaries"].added)
    assert any(r["path"] == "/bin/old" for r in res["binaries"].removed)
    assert any(r["key"] == "ent.new" for r in res["entitlements"].added)
    assert any(r["key"] == "ent.old" for r in res["entitlements"].removed)
    assert any(r["operation"] == "write" for r in res["sandbox_rules"].added)
    assert any(r["operation"] == "read" for r in res["sandbox_rules"].removed)
    assert any(r["service_name"] == "svc.new" for r in res["mach_services"].added)
    assert any(r["service_name"] == "svc.old" for r in res["mach_services"].removed)

    # PROPERTY_CHANGE: /change/c changed its sha256.
    assert res["files_changed"].category == DiffCategory.PROPERTY_CHANGE
    file_change = next(
        r for r in res["files_changed"].changed if r["path"] == "/change/c"
    )
    assert file_change["changed_fields"] == ["sha256"]
    assert file_change["old_sha256"] == "old"
    assert file_change["new_sha256"] == "new"

    # observation_diff() is wired: the extra 'exec' observation is reported.
    assert any(r.get("event_type") == "exec" for r in res["observations"].added)

    # RESOLUTION_CHANGE: bag.common re-clustered (atom_count 2->3), and add/remove.
    resolution = res["resolution"]
    assert resolution.category == DiffCategory.RESOLUTION_CHANGE
    resolution_change = next(
        r for r in resolution.changed if r["canonical_key"] == "bag.common"
    )
    assert resolution_change["changed_fields"] == ["atom_count"]
    assert resolution_change["old_atom_count"] == 2
    assert resolution_change["new_atom_count"] == 3
    assert any(r["canonical_key"] == "bag.new" for r in resolution.added)
    assert any(r["canonical_key"] == "bag.old" for r in resolution.removed)


def test_natural_key_diffs_ignore_insertion_order_skew(tmp_path):
    """Identical logical content, inserted in a different order (so local ids
    differ), must not fabricate binary/entitlement/mach_service changes."""
    old, new = tmp_path / "old.db", tmp_path / "new.db"

    def build(path, decoys):
        initialize_database(Path(path))
        conn = sqlite3.connect(str(path))
        try:
            for i in range(decoys):  # shift every downstream autoincrement id
                _insert_min(conn, "files", {"path": f"/decoy/{i}"})
            _insert_min(conn, "files", {"path": "/bin/x"})
            fid = _file_id(conn, "/bin/x")
            _insert_min(conn, "binaries",
                        {"file_id": fid, "bundle_id": "com.x", "executable_name": "x"})
            bid = _last_id(conn, "binaries")
            _insert_min(conn, "entitlements", {"binary_id": bid, "key": "k", "value": "v"})
            _insert_min(conn, "daemons", {"label": "com.x.daemon"})
            did = _last_id(conn, "daemons")
            _insert_min(conn, "mach_services", {"daemon_id": did, "service_name": "svc"})
            conn.commit()
        finally:
            conn.close()

    build(old, decoys=0)
    build(new, decoys=3)  # ids shifted, logical content identical
    with IcarusDiffer(str(old), str(new)) as d:
        assert d.binaries_diff().total_changes == 0
        assert d.entitlements_diff().total_changes == 0
        assert d.mach_services_diff().total_changes == 0


# --------------------------------------------------------------------------- #
# 2. NULL-hash blind spot: size-based detection for >=50 MB files / symlinks.
# --------------------------------------------------------------------------- #
def _build_null_hash_db(path, *, big_size, symlink_size):
    initialize_database(Path(path))
    conn = sqlite3.connect(str(path))
    try:
        # A >=50 MB file: parser stores sha256 = NULL, only size is known.
        _insert_min(conn, "files",
                    {"path": "/big/blob", "sha256": None, "size": big_size})
        # A symlink: sha256 = NULL as well.
        _insert_min(conn, "files",
                    {"path": "/link", "sha256": None, "size": symlink_size,
                     "is_symlink": 1})
        # A genuinely-unchanged NULL-hash file (identical size both sides).
        _insert_min(conn, "files",
                    {"path": "/big/steady", "sha256": None, "size": 999})
        # A normal hashed file that does NOT change (control).
        _insert_min(conn, "files",
                    {"path": "/normal", "sha256": "abc", "size": 10})
        conn.commit()
    finally:
        conn.close()


def test_null_hash_size_change_is_detected(tmp_path):
    old, new = tmp_path / "old.db", tmp_path / "new.db"
    _build_null_hash_db(old, big_size=60_000_000, symlink_size=12)
    _build_null_hash_db(new, big_size=60_500_000, symlink_size=34)  # both grew

    with IcarusDiffer(str(old), str(new)) as d:
        result = d.files_changed_diff()
        changed = result.changed
    by_path = {c["path"]: c for c in changed}

    # The >=50 MB file and the symlink both changed size -> reported via size.
    assert "/big/blob" in by_path, "NULL-hash large file size change not detected"
    assert by_path["/big/blob"]["change_basis"] == "size"
    assert by_path["/big/blob"]["content_unknown"] is True
    assert "/link" in by_path, "NULL-hash symlink size change not detected"

    # No false positives: unchanged NULL-hash file and unchanged hashed file.
    assert "/big/steady" not in by_path
    assert "/normal" not in by_path


def test_null_hash_unchanged_size_is_not_reported(tmp_path):
    """A NULL-hash file with identical size on both sides is NOT a change."""
    old, new = tmp_path / "old.db", tmp_path / "new.db"
    _build_null_hash_db(old, big_size=60_000_000, symlink_size=12)
    _build_null_hash_db(new, big_size=60_000_000, symlink_size=12)  # nothing changed
    with IcarusDiffer(str(old), str(new)) as d:
        assert d.files_changed_diff().changed == []


def test_sha256_change_still_detected_and_labelled(tmp_path):
    """Both sides hashed and differing -> reported with change_basis 'sha256'."""
    old, new = tmp_path / "old.db", tmp_path / "new.db"
    for p, h in [(old, "hash_old"), (new, "hash_new")]:
        initialize_database(Path(p))
        conn = sqlite3.connect(str(p))
        try:
            _insert_min(conn, "files", {"path": "/f", "sha256": h, "size": 5})
            conn.commit()
        finally:
            conn.close()
    with IcarusDiffer(str(old), str(new)) as d:
        result = d.files_changed_diff()
        changed = result.changed
    assert len(changed) == 1
    assert changed[0]["path"] == "/f"
    assert changed[0]["change_basis"] == "sha256"
    assert changed[0]["changed_fields"] == ["sha256"]
    assert 'sha256: "hash_old" -> "hash_new"' in result.to_markdown()


# --------------------------------------------------------------------------- #
# 3. Markdown report escaping.
# --------------------------------------------------------------------------- #
HOSTILE = "evil`inject|pipe\nNEWLINE\x1b[31mANSI\x07bell"


def test_md_sanitize_neutralizes_hostile_value():
    out = _md_sanitize(HOSTILE)
    # Raw control bytes are gone (newline, ESC, bell).
    assert "\n" not in out
    assert "\x1b" not in out
    assert "\x07" not in out
    # The code-span-closing backtick is gone (replaced, not backslash-escaped).
    assert "`" not in out
    # The pipe is escaped (\|), never left bare.
    assert "inject|pipe" not in out
    assert "\\|pipe" in out
    # The whole hostile sequence is not present verbatim.
    assert HOSTILE not in out


def test_markdown_rejects_a_malformed_changed_record():
    result = DiffResult(
        added=[], removed=[], changed=[{"path": "/same"}],
        table="files", key_column="path",
    )
    with pytest.raises(ValueError, match="changed_fields"):
        result.to_markdown()


def test_report_escaping_added_path_does_not_break(tmp_path):
    """A hostile file path flows through generate_report() without injecting a
    newline into its list item or leaving raw backticks/control bytes."""
    old, new = tmp_path / "old.db", tmp_path / "new.db"
    initialize_database(Path(old))  # empty old -> the file is 'added'
    initialize_database(Path(new))
    conn = sqlite3.connect(str(new))
    try:
        _insert_min(conn, "files", {"path": HOSTILE})
        conn.commit()
    finally:
        conn.close()

    with IcarusDiffer(str(old), str(new)) as d:
        report = d.generate_report()

    # No raw control bytes anywhere in the rendered report.
    assert "\x1b" not in report
    assert "\x07" not in report
    # The hostile value did not inject a line break: 'evil' and 'NEWLINE' land on
    # the same rendered line (the raw newline was neutralized).
    line = next(ln for ln in report.splitlines() if "evil" in ln)
    assert "NEWLINE" in line
    # Its backtick did not escape the code span.
    assert "evil`inject" not in report
    assert HOSTILE not in report


def test_report_escaping_structural_description():
    """The structural description (emitted outside a code span) is sanitized."""
    dr = DiffResult(
        added=[], removed=[], changed=[],
        structural=[{"description": HOSTILE}],
        table="cross_table", key_column="entity",
    )
    md = dr.to_markdown()
    assert "\n" + "NEWLINE" not in md  # no injected line break from the value
    assert "\x1b" not in md
    assert "`" not in md.split("Structural")[1]  # no raw backtick in the item
    assert HOSTILE not in md
