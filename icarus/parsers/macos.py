"""
ICARUS macOS / iOS parser — daemon and attack-surface mapping.

Ingests an extracted macOS/iOS root filesystem (an IPSW rootfs, a device dump,
or a mounted system volume) and fills the ontology the security views were
built for:

  - daemons        launchd LaunchDaemon/LaunchAgent plists
  - mach_services  normalized service_name -> daemon rows (the reachability pivot)
  - binaries       Mach-O executables/dylibs (architecture, code-sign flags)
  - entitlements   parsed from each Mach-O's embedded code signature
  - kexts          IOKit personalities and user-client (kernel) surface
  - frameworks     system and private frameworks
  - sandbox_profiles  .sb profile catalog (SBPL rule decompilation is out of scope)

Daemon -> executable binary links are resolved in extract_relationships so the
v_sandbox_escape_surface view (daemon -> binary -> entitlements) works.

plist parsing uses the stdlib plistlib, which reads both XML and binary plists.
Entitlement extraction is self-contained (no external codesign/ldid needed).
"""

import json
import os
import plistlib
import sqlite3
from pathlib import Path
from typing import Any, Dict, List, Optional

from icarus.core.detection import DetectionEvidence
from icarus.core.schema import open_db
from icarus.parsers.base import BATCH_COMMIT_INTERVAL, BaseParser, link_daemons_to_binaries
from icarus.parsers.macho import is_macho_magic, macho_info

FILE_TYPES = {
    ".plist": "plist", ".dylib": "binary", ".framework": "bundle",
    ".kext": "bundle", ".app": "bundle", ".appex": "bundle",
    ".sb": "sandbox_profile", ".sqlite": "database", ".db": "database",
    ".png": "image", ".jpg": "image", ".car": "asset_catalog",
    ".strings": "strings", ".nib": "nib",
}

# launchd job directories, relative to the rootfs.
LAUNCHD_DIRS = [
    ("System", "Library", "LaunchDaemons"),
    ("System", "Library", "LaunchAgents"),
    ("Library", "LaunchDaemons"),
    ("Library", "LaunchAgents"),
]


def _load_plist(path: Path) -> Optional[dict]:
    """Load an XML or binary plist. Returns a dict, or None on any failure."""
    try:
        with BaseParser._open_regular(path) as f:
            data = plistlib.load(f)
        return data if isinstance(data, dict) else None
    except (OSError, PermissionError, ValueError, plistlib.InvalidFileException):
        return None
    except Exception:
        return None


def _ent_value(value: Any):
    """Normalize an entitlement value to (text, value_type) for storage."""
    if isinstance(value, bool):
        return ("true" if value else "false"), "boolean"
    if isinstance(value, str):
        return value, "string"
    if isinstance(value, int):
        return str(value), "integer"
    if isinstance(value, list):
        return json.dumps(value), "array"
    if isinstance(value, dict):
        return json.dumps(value), "dict"
    return json.dumps(value, default=str), "other"


def _text(value: Any) -> Optional[str]:
    """Coerce a plist value to TEXT for a scalar column.

    iOS launchd plists sometimes use feature-flag conditional dicts for keys
    that are normally scalars, e.g.
        UserName = {'#IfFeatureFlagDisabled': 'Security/SeparateUserKeychain',
                    '#Then': '_securityd', '#Else': 'mobile'}
    Preserve the conditional as JSON rather than crashing the SQLite bind.
    """
    if value is None or isinstance(value, str):
        return value
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    return json.dumps(value, default=str)


class MacosParser(BaseParser):
    """Parser for extracted macOS / iOS root filesystems."""

    @property
    def name(self) -> str:
        return "macos"

    @property
    def description(self) -> str:
        return (
            "macOS / iOS root filesystem — daemons, Mach services, "
            "entitlements, kexts, frameworks"
        )

    def identify(self, source: Path) -> bool:
        """True if source looks like an extracted macOS/iOS root filesystem."""
        if not source.is_dir():
            return False
        sysver = source / "System" / "Library" / "CoreServices" / "SystemVersion.plist"
        if sysver.exists():
            return True
        markers = [
            source / "System" / "Library" / "LaunchDaemons",
            source / "System" / "Library" / "Frameworks",
            source / "System" / "Library" / "CoreServices",
            source / "System" / "Library" / "Extensions",
        ]
        return sum(1 for m in markers if m.is_dir()) >= 2

    def identify_evidence(self, evidence: DetectionEvidence) -> bool:
        if evidence.has_file("System/Library/CoreServices/SystemVersion.plist"):
            return True
        markers = (
            "System/Library/LaunchDaemons",
            "System/Library/Frameworks",
            "System/Library/CoreServices",
            "System/Library/Extensions",
        )
        return sum(evidence.has_directory(marker) for marker in markers) >= 2

    def extract_entities(self, source: Path, db_path: Path) -> Dict[str, Any]:
        conn = open_db(db_path)
        stats = {
            "files": 0, "binaries": 0, "daemons": 0, "mach_services": 0,
            "entitlements": 0, "kexts": 0, "frameworks": 0, "sandbox_profiles": 0,
        }
        try:
            self._walk_files(conn, source, stats)
            conn.commit()
            self._extract_daemons(conn, source, stats)
            conn.commit()
            self._extract_kexts(conn, source, stats)
            self._extract_frameworks(conn, source, stats)
            self._extract_sandbox_profiles(conn, source, stats)
            conn.commit()
        finally:
            conn.close()
        return stats

    # ── Phase 1: filesystem walk + Mach-O binary/entitlement extraction ──

    def _walk_files(self, conn, source: Path, stats: Dict[str, int]) -> None:
        for dirpath, dirs, filenames in os.walk(source, onerror=lambda e: None):
            # Prune hidden dirs and caches in place (avoids the rel_dir='.' trap).
            dirs[:] = [
                d for d in dirs
                if not d.startswith(".")
                and d != "__pycache__"
                and not (Path(dirpath) / d).is_symlink()
            ]
            for fname in filenames:
                path = Path(dirpath) / fname
                st, kind = self._file_kind(path)
                if st is None or kind in ("special", "unreadable"):
                    continue
                # Never dereference symlinks — a link may target a file outside
                # the source tree. Catalog it, but don't read its content.
                is_link = kind == "symlink"
                try:
                    rel = self._rel_path(path, source)
                    ext = path.suffix.lower()
                    filename = self._safe_text(path.name)
                    is_macho = False
                    if not is_link:
                        try:
                            with self._open_regular(path) as fh:
                                is_macho = is_macho_magic(fh.read(4))
                        except (OSError, PermissionError):
                            is_macho = False
                    file_type = (
                        "symlink" if is_link
                        else "binary" if is_macho
                        else FILE_TYPES.get(ext, "other")
                    )

                    conn.execute(
                        "INSERT OR IGNORE INTO files "
                        "(path,filename,extension,size,sha256,file_type,"
                        "is_symlink,symlink_target) VALUES (?,?,?,?,?,?,?,?)",
                        (
                            rel, filename, ext or None, st.st_size,
                            self._safe_hash(path, st.st_size), file_type,
                            int(is_link), self._symlink_target(path),
                        ),
                    )
                    stats["files"] += 1

                    if is_macho:
                        self._extract_binary(conn, source, path, rel, stats)
                except (OSError, PermissionError):
                    continue

                if stats["files"] % BATCH_COMMIT_INTERVAL == 0:
                    conn.commit()

    def _extract_binary(self, conn, source: Path, path: Path, rel: str,
                        stats: Dict[str, int]) -> None:
        file_row = conn.execute("SELECT id FROM files WHERE path=?", (rel,)).fetchone()
        if not file_row:
            return
        file_id = file_row[0]
        if conn.execute("SELECT id FROM binaries WHERE file_id=?", (file_id,)).fetchone():
            return  # already analyzed (idempotent)

        info = macho_info(path)
        if not info:
            return

        bundle_id = None
        info_plist = path.parent / "Info.plist"
        if info_plist.exists():
            pl = _load_plist(info_plist)
            if pl:
                bundle_id = pl.get("CFBundleIdentifier")

        flags = info.get("code_sign_flags")
        conn.execute(
            "INSERT INTO binaries (file_id,bundle_id,executable_name,arch,code_sign_flags) "
            "VALUES (?,?,?,?,?)",
            (file_id, _text(bundle_id), self._safe_text(path.name), info.get("arch"),
             hex(flags) if isinstance(flags, int) else None),
        )
        stats["binaries"] += 1
        binary_id = conn.execute(
            "SELECT id FROM binaries WHERE file_id=?", (file_id,)
        ).fetchone()[0]

        ents = info.get("entitlements") or {}
        for key, value in ents.items():
            text, vtype = _ent_value(value)
            exists = conn.execute(
                "SELECT id FROM entitlements WHERE binary_id=? AND key=? AND value=?",
                (binary_id, key, text),
            ).fetchone()
            if not exists:
                conn.execute(
                    "INSERT INTO entitlements (binary_id,key,value,value_type) VALUES (?,?,?,?)",
                    (binary_id, key, text, vtype),
                )
                stats["entitlements"] += 1

    # ── Phase 2: launchd daemons + normalized Mach services ──

    def _extract_daemons(self, conn, source: Path, stats: Dict[str, int]) -> None:
        for parts in LAUNCHD_DIRS:
            ld_dir = source.joinpath(*parts)
            if self._path_has_symlink(ld_dir, source) or not ld_dir.is_dir():
                continue
            try:
                entries = sorted(ld_dir.glob("*.plist"))
            except (OSError, PermissionError):
                continue
            for plist_path in entries:
                pl = _load_plist(plist_path)
                if not pl:
                    continue
                label = pl.get("Label")
                if not isinstance(label, str) or not label:
                    label = self._safe_text(plist_path.stem)
                prog_args = pl.get("ProgramArguments")
                program = pl.get("Program")
                if not program and isinstance(prog_args, list) and prog_args:
                    program = prog_args[0]
                mach = pl.get("MachServices")
                sandbox = pl.get("SandboxProfile") or pl.get("POSIXSpawnSandboxProfile")
                session = pl.get("LimitLoadToSessionType")
                if isinstance(session, list):
                    session = ",".join(str(s) for s in session)
                rel = self._rel_path(plist_path, source)

                cur = conn.execute(
                    "INSERT OR IGNORE INTO daemons "
                    "(label,plist_path,program,program_arguments,user_name,group_name,"
                    "run_at_load,keep_alive,sandbox_profile,mach_services,session_type) "
                    "VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                    (
                        label, rel, _text(program),
                        json.dumps(prog_args) if prog_args else None,
                        _text(pl.get("UserName")), _text(pl.get("GroupName")),
                        1 if pl.get("RunAtLoad") else 0,
                        1 if pl.get("KeepAlive") else 0,
                        _text(sandbox),
                        json.dumps(mach) if mach else None,
                        _text(session),
                    ),
                )
                if cur.rowcount == 0:
                    # `label` is UNIQUE and already belongs to a daemon we ingested
                    # earlier (same Label reused across LaunchDaemons/LaunchAgents,
                    # or two plists deriving the same fallback label from their
                    # filename stem). Skip this plist entirely rather than
                    # attaching its MachServices to the *other* daemon's id —
                    # grafting services onto an unrelated daemon is worse than
                    # dropping the duplicate (see issue #24).
                    continue
                daemon_id = cur.lastrowid
                stats["daemons"] += 1

                service_names: List[str] = []
                if isinstance(mach, dict):
                    service_names = list(mach.keys())
                elif isinstance(mach, list):
                    service_names = [s for s in mach if isinstance(s, str)]
                for svc in service_names:
                    cur = conn.execute(
                        "INSERT OR IGNORE INTO mach_services (daemon_id,service_name) VALUES (?,?)",
                        (daemon_id, svc),
                    )
                    if cur.rowcount:
                        stats["mach_services"] += 1
        conn.commit()

    # ── Phase 3: kexts (kernel attack surface) ──

    def _extract_kexts(self, conn, source: Path, stats: Dict[str, int]) -> None:
        ext_dir = source / "System" / "Library" / "Extensions"
        if self._path_has_symlink(ext_dir, source) or not ext_dir.is_dir():
            return
        for kext in sorted(ext_dir.glob("*.kext")):
            if kext.is_symlink():
                continue
            info = _load_plist(kext / "Info.plist")
            if not info:
                continue
            bundle_id = info.get("CFBundleIdentifier")
            if not bundle_id:
                continue
            personalities = info.get("IOKitPersonalities")
            if not isinstance(personalities, dict):
                personalities = {}
            deps = info.get("OSBundleLibraries")
            if not isinstance(deps, dict):
                deps = {}
            iokit_classes: List[str] = []
            has_user_client = 0
            for p in personalities.values():
                if not isinstance(p, dict):
                    continue
                if p.get("IOClass"):
                    iokit_classes.append(p["IOClass"])
                if p.get("IOUserClientClass"):
                    has_user_client = 1
            cur = conn.execute(
                "INSERT OR IGNORE INTO kexts "
                "(bundle_id,name,version,dependencies,personalities,iokit_classes,has_user_client) "
                "VALUES (?,?,?,?,?,?,?)",
                (
                    _text(bundle_id), _text(info.get("CFBundleName")) or kext.stem,
                    _text(info.get("CFBundleVersion")),
                    json.dumps(sorted(deps)) if deps else None,
                    json.dumps(sorted(personalities)) if personalities else None,
                    json.dumps(sorted(set(iokit_classes))) if iokit_classes else None,
                    has_user_client,
                ),
            )
            if cur.rowcount:
                stats["kexts"] += 1

    # ── Phase 4: frameworks ──

    def _extract_frameworks(self, conn, source: Path, stats: Dict[str, int]) -> None:
        for sub, is_private in (("Frameworks", 0), ("PrivateFrameworks", 1)):
            fw_dir = source / "System" / "Library" / sub
            if self._path_has_symlink(fw_dir, source) or not fw_dir.is_dir():
                continue
            for fw in sorted(fw_dir.glob("*.framework")):
                if fw.is_symlink():
                    continue
                info = _load_plist(fw / "Info.plist") or {}
                rel = self._rel_path(fw, source)
                cur = conn.execute(
                    "INSERT OR IGNORE INTO frameworks (name,path,bundle_id,version,is_private) "
                    "VALUES (?,?,?,?,?)",
                    (fw.stem, rel, _text(info.get("CFBundleIdentifier")),
                     _text(info.get("CFBundleVersion")), is_private),
                )
                if cur.rowcount:
                    stats["frameworks"] += 1

    # ── Phase 5: sandbox profiles (catalog only) ──

    def _extract_sandbox_profiles(self, conn, source: Path, stats: Dict[str, int]) -> None:
        sb_dirs = [
            source / "System" / "Library" / "Sandbox" / "Profiles",
            source / "usr" / "share" / "sandbox",
        ]
        for sb_dir in sb_dirs:
            if self._path_has_symlink(sb_dir, source) or not sb_dir.is_dir():
                continue
            try:
                sb_files = sorted(sb_dir.rglob("*.sb"))
            except (OSError, PermissionError):
                continue
            for sb in sb_files:
                _, kind = self._file_kind(sb)
                if kind != "regular":
                    continue
                rel = self._rel_path(sb, source)
                cur = conn.execute(
                    "INSERT OR IGNORE INTO sandbox_profiles (name,profile_path) VALUES (?,?)",
                    (sb.stem, rel),
                )
                if cur.rowcount:
                    stats["sandbox_profiles"] += 1

    # ── Relationships: daemon -> executable binary ──

    def extract_relationships(self, source: Path, db_path: Path) -> Dict[str, Any]:
        conn = open_db(db_path)
        try:
            linked = link_daemons_to_binaries(conn)
            conn.commit()
        finally:
            conn.close()
        return {"linked": linked}

    def verify(self, db_path: Path) -> Dict[str, Any]:
        conn = open_db(db_path)
        try:
            stats = {}
            for table in ("files", "binaries", "daemons", "mach_services",
                          "entitlements", "kexts", "frameworks", "sandbox_profiles"):
                try:
                    stats[table] = conn.execute(
                        f"SELECT COUNT(*) FROM {table}"  # nosec B608 - table iterates the hardcoded tuple literal above, not external input
                    ).fetchone()[0]
                except sqlite3.OperationalError:
                    stats[table] = 0
        finally:
            conn.close()
        if stats.get("files", 0) == 0:
            raise ValueError("Verification failed: files table is empty")
        if stats.get("daemons", 0) == 0:
            raise ValueError("Verification failed: no daemons found (expected LaunchDaemons)")
        return stats
