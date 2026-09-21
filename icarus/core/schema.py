"""
ICARUS Schema Manager — SQLite database initialization and migrations.

Manages the normalized relational model: entities, relationships,
attributes, FTS5 full-text search, and materialized views.
"""

import platform
import re
import sqlite3
from pathlib import Path
from typing import Optional, Union


def _windows_memory_status() -> Optional[tuple]:
    """Return (total_bytes, available_bytes) on Windows, or None on failure."""
    try:
        import ctypes

        class MEMORYSTATUSEX(ctypes.Structure):
            _fields_ = [
                ("dwLength", ctypes.c_ulong),
                ("dwMemoryLoad", ctypes.c_ulong),
                ("ullTotalPhys", ctypes.c_ulonglong),
                ("ullAvailPhys", ctypes.c_ulonglong),
                ("ullTotalPageFile", ctypes.c_ulonglong),
                ("ullAvailPageFile", ctypes.c_ulonglong),
                ("ullTotalVirtual", ctypes.c_ulonglong),
                ("ullAvailVirtual", ctypes.c_ulonglong),
                ("ullAvailExtendedVirtual", ctypes.c_ulonglong),
            ]
        stat = MEMORYSTATUSEX()
        stat.dwLength = ctypes.sizeof(stat)
        ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(stat))
        return stat.ullTotalPhys, stat.ullAvailPhys
    except Exception:
        return None


def _get_system_ram_bytes() -> int:
    """Detect total system RAM. Returns bytes, or 0 on failure."""
    try:
        system = platform.system()
        if system == "Linux":
            with open("/proc/meminfo") as f:
                for line in f:
                    if line.startswith("MemTotal:"):
                        return int(line.split()[1]) * 1024
        elif system == "Darwin":
            import subprocess
            out = subprocess.check_output(["sysctl", "-n", "hw.memsize"], text=True)
            return int(out.strip())
        elif system == "Windows":
            status = _windows_memory_status()
            if status:
                return status[0]
    except Exception:
        pass
    return 0


def _get_available_ram_bytes() -> int:
    """Detect currently available (not total) system RAM. Returns bytes, or 0 on failure."""
    try:
        system = platform.system()
        if system == "Linux":
            with open("/proc/meminfo") as f:
                for line in f:
                    if line.startswith("MemAvailable:"):
                        return int(line.split()[1]) * 1024
        elif system == "Darwin":
            import subprocess
            out = subprocess.check_output(["vm_stat"], text=True)
            page_size = 4096
            size_match = re.search(r"page size of (\d+) bytes", out)
            if size_match:
                page_size = int(size_match.group(1))
            free_pages = 0
            for label in ("Pages free", "Pages inactive"):
                count_match = re.search(rf"{re.escape(label)}:\s+(\d+)\.", out)
                if count_match:
                    free_pages += int(count_match.group(1))
            if free_pages:
                return free_pages * page_size
        elif system == "Windows":
            status = _windows_memory_status()
            if status:
                return status[1]
    except Exception:
        pass
    return 0


RAM_TARGET_RATIO = 0.7
FALLBACK_CACHE_KB = 2_097_152
FALLBACK_MMAP_BYTES = 8_589_934_592


def _apply_performance_pragmas(conn: sqlite3.Connection) -> None:
    """Set SQLite cache and mmap based on available system RAM.

    Scales to *available* (not total) RAM so the pragmas don't oversubscribe
    a machine that is already under memory pressure, and caps the result at
    the same ceiling used as the no-RAM-detected fallback below, so a huge
    box doesn't get an unbounded cache/mmap allocation either.
    """
    ram = _get_available_ram_bytes()
    if ram > 0:
        target = min(int(ram * RAM_TARGET_RATIO), FALLBACK_MMAP_BYTES)
        cache_kb = min(target // 1024, FALLBACK_CACHE_KB)
        conn.execute(f"PRAGMA cache_size = -{cache_kb}")
        conn.execute(f"PRAGMA mmap_size = {target}")
    else:
        conn.execute(f"PRAGMA cache_size = -{FALLBACK_CACHE_KB}")
        conn.execute(f"PRAGMA mmap_size = {FALLBACK_MMAP_BYTES}")


def open_db(
    path: Union[str, Path], *, readonly: bool = False, immutable: bool = False
) -> sqlite3.Connection:
    """
    Open a SQLite connection with durable, safe per-connection state applied
    immediately. This is the one place core/parser code should go through
    instead of a bare ``sqlite3.connect()``.

    ``foreign_keys`` and cache/mmap sizing are per-connection settings in
    SQLite — they do NOT carry over from one connection to the next (unlike
    the schema itself). Previously ``PRAGMA foreign_keys = ON`` only ran
    inside CORE_SCHEMA, on the one-shot connection used for a fresh
    ``initialize_database()`` call that is closed immediately after, so
    every other connection (parsers, the query engine, the resolver, the
    pipeline) silently got SQLite's default of foreign_keys OFF and
    unenforced ``REFERENCES``. Route connections through here so that FK
    constraints are actually enforced and cache/mmap pragmas scale to
    available RAM on every working connection, not just a connection that's
    about to be closed.

    Pass ``readonly=True`` to open the database read-only via URI (``mode=ro``:
    no writes to the main file, no -wal/-shm side files created).

    Pass ``immutable=True`` (only meaningful with ``readonly=True``) to also
    add ``immutable=1``, which promises SQLite the file cannot change and lets
    it skip all locking. Use this ONLY for genuinely untrusted/frozen inputs:
    ``immutable=1`` makes SQLite IGNORE the ``-wal`` file, so a freshly-built
    database whose latest writes still live in the WAL would read stale or
    missing rows. The interactive query path must therefore use
    ``readonly=True`` WITHOUT ``immutable`` so it honours the WAL.
    """
    if readonly:
        uri = f"file:{path}?mode=ro"
        if immutable:
            uri += "&immutable=1"
        conn = sqlite3.connect(uri, uri=True)
    else:
        conn = sqlite3.connect(str(path))
        conn.execute("PRAGMA journal_mode = WAL")
    conn.execute("PRAGMA foreign_keys = ON")
    _apply_performance_pragmas(conn)
    return conn


SCHEMA_VERSION = 6


class SchemaVersionError(ValueError):
    """Raised when a database declares a schema version ICARUS cannot safely use."""


class SchemaValidationError(RuntimeError):
    """Raised when a current-version database is missing required schema objects."""

ENTITY_TABLES = (
    "files", "binaries", "daemons", "entitlements",
    "sandbox_profiles", "sandbox_rules", "kexts", "frameworks",
)

CORE_SCHEMA = """
PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS metadata (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS files (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    path TEXT NOT NULL UNIQUE,
    filename TEXT NOT NULL,
    extension TEXT,
    size INTEGER DEFAULT 0,
    permissions TEXT,
    owner TEXT,
    group_name TEXT,
    modified_time TEXT,
    sha256 TEXT,
    file_type TEXT,
    is_symlink INTEGER DEFAULT 0,
    symlink_target TEXT,
    source_version_id INTEGER REFERENCES versions(id),
    confidence REAL DEFAULT 1.0,
    observed_time TEXT,
    marking TEXT DEFAULT 'UNCLASSIFIED'
);

CREATE TABLE IF NOT EXISTS binaries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    file_id INTEGER NOT NULL REFERENCES files(id),
    bundle_id TEXT,
    executable_name TEXT,
    arch TEXT,
    min_os_version TEXT,
    sdk_version TEXT,
    code_sign_flags TEXT,
    team_id TEXT,
    linked_dylibs TEXT,
    rpaths TEXT,
    segments TEXT,
    has_restrict INTEGER DEFAULT 0,
    has_pie INTEGER DEFAULT 1,
    is_encrypted INTEGER DEFAULT 0,
    source_version_id INTEGER REFERENCES versions(id),
    confidence REAL DEFAULT 1.0,
    observed_time TEXT,
    marking TEXT DEFAULT 'UNCLASSIFIED'
);

CREATE TABLE IF NOT EXISTS daemons (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    label TEXT NOT NULL UNIQUE,
    plist_path TEXT NOT NULL,
    program TEXT,
    program_arguments TEXT,
    user_name TEXT,
    group_name TEXT,
    run_at_load INTEGER DEFAULT 0,
    keep_alive INTEGER DEFAULT 0,
    sandbox_profile TEXT,
    mach_services TEXT,
    binary_id INTEGER REFERENCES binaries(id),
    is_disabled INTEGER DEFAULT 0,
    session_type TEXT,
    source_version_id INTEGER REFERENCES versions(id),
    confidence REAL DEFAULT 1.0,
    observed_time TEXT,
    marking TEXT DEFAULT 'UNCLASSIFIED'
);

CREATE TABLE IF NOT EXISTS entitlements (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    binary_id INTEGER NOT NULL REFERENCES binaries(id),
    key TEXT NOT NULL,
    value TEXT NOT NULL,
    value_type TEXT,
    source_version_id INTEGER REFERENCES versions(id),
    confidence REAL DEFAULT 1.0,
    observed_time TEXT,
    marking TEXT DEFAULT 'UNCLASSIFIED'
);

CREATE TABLE IF NOT EXISTS sandbox_profiles (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    profile_path TEXT,
    raw_sbpl TEXT,
    rule_count INTEGER DEFAULT 0,
    allows_network INTEGER DEFAULT 0,
    allows_mach_lookup INTEGER DEFAULT 0,
    source_version_id INTEGER REFERENCES versions(id),
    confidence REAL DEFAULT 1.0,
    observed_time TEXT,
    marking TEXT DEFAULT 'UNCLASSIFIED'
);

CREATE TABLE IF NOT EXISTS sandbox_rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    profile_id INTEGER NOT NULL REFERENCES sandbox_profiles(id),
    operation TEXT NOT NULL,
    action TEXT NOT NULL,
    filter_type TEXT,
    filter_value TEXT,
    requires TEXT,
    source_version_id INTEGER REFERENCES versions(id),
    confidence REAL DEFAULT 1.0,
    observed_time TEXT,
    marking TEXT DEFAULT 'UNCLASSIFIED'
);

CREATE TABLE IF NOT EXISTS kexts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    bundle_id TEXT NOT NULL UNIQUE,
    name TEXT,
    version TEXT,
    file_id INTEGER REFERENCES files(id),
    dependencies TEXT,
    personalities TEXT,
    iokit_classes TEXT,
    has_user_client INTEGER DEFAULT 0,
    source_version_id INTEGER REFERENCES versions(id),
    confidence REAL DEFAULT 1.0,
    observed_time TEXT,
    marking TEXT DEFAULT 'UNCLASSIFIED'
);

CREATE TABLE IF NOT EXISTS frameworks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    path TEXT NOT NULL UNIQUE,
    bundle_id TEXT,
    version TEXT,
    is_private INTEGER DEFAULT 0,
    binary_id INTEGER REFERENCES binaries(id),
    exported_symbols_count INTEGER DEFAULT 0,
    source_version_id INTEGER REFERENCES versions(id),
    confidence REAL DEFAULT 1.0,
    observed_time TEXT,
    marking TEXT DEFAULT 'UNCLASSIFIED'
);

CREATE TABLE IF NOT EXISTS versions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id TEXT NOT NULL UNIQUE,
    parser_name TEXT NOT NULL,
    source_path TEXT,
    started_at TEXT NOT NULL,
    completed_at TEXT,
    entity_count INTEGER DEFAULT 0,
    metadata TEXT
);

CREATE TABLE IF NOT EXISTS observations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    entity_table TEXT NOT NULL,
    entity_id INTEGER NOT NULL,
    observed_at TEXT NOT NULL,
    observer TEXT,
    event_type TEXT NOT NULL,
    properties TEXT,
    version_id INTEGER REFERENCES versions(id),
    confidence REAL DEFAULT 1.0
);

CREATE TABLE IF NOT EXISTS atoms (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source_version_id INTEGER NOT NULL REFERENCES versions(id),
    entity_type TEXT NOT NULL,
    source_key TEXT NOT NULL,
    properties TEXT NOT NULL,
    created_at TEXT NOT NULL,
    UNIQUE(source_version_id, entity_type, source_key)
);

CREATE TABLE IF NOT EXISTS bags (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    entity_type TEXT NOT NULL,
    canonical_key TEXT,
    created_at TEXT NOT NULL,
    resolved_at TEXT,
    atom_count INTEGER DEFAULT 1,
    score REAL
);

CREATE TABLE IF NOT EXISTS bag_atoms (
    bag_id INTEGER NOT NULL REFERENCES bags(id),
    atom_id INTEGER NOT NULL REFERENCES atoms(id),
    PRIMARY KEY(bag_id, atom_id)
);

CREATE TABLE IF NOT EXISTS resolution_event_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_type TEXT NOT NULL,
    bag_id INTEGER NOT NULL REFERENCES bags(id),
    atom_ids TEXT NOT NULL,
    reason TEXT,
    confidence REAL,
    operator TEXT,
    timestamp TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS match_candidates (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    entity_type TEXT NOT NULL,
    atom_a INTEGER NOT NULL REFERENCES atoms(id),
    atom_b INTEGER NOT NULL REFERENCES atoms(id),
    score REAL NOT NULL,
    features TEXT,
    created_at TEXT NOT NULL,
    UNIQUE(atom_a, atom_b)
);

CREATE TABLE IF NOT EXISTS mach_services (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    daemon_id INTEGER NOT NULL REFERENCES daemons(id),
    service_name TEXT NOT NULL,
    source_version_id INTEGER REFERENCES versions(id),
    confidence REAL DEFAULT 1.0,
    observed_time TEXT,
    marking TEXT DEFAULT 'UNCLASSIFIED',
    UNIQUE(daemon_id, service_name)
);
"""

INDEXES = """
CREATE INDEX IF NOT EXISTS idx_files_path ON files(path);
CREATE INDEX IF NOT EXISTS idx_files_extension ON files(extension);
CREATE INDEX IF NOT EXISTS idx_files_type ON files(file_type);
CREATE INDEX IF NOT EXISTS idx_files_size ON files(size DESC);
CREATE INDEX IF NOT EXISTS idx_binaries_bundle ON binaries(bundle_id);
CREATE INDEX IF NOT EXISTS idx_binaries_file ON binaries(file_id);
CREATE INDEX IF NOT EXISTS idx_daemons_label ON daemons(label);
CREATE INDEX IF NOT EXISTS idx_daemons_sandbox ON daemons(sandbox_profile);
CREATE INDEX IF NOT EXISTS idx_ent_binary ON entitlements(binary_id);
CREATE INDEX IF NOT EXISTS idx_ent_key ON entitlements(key);
CREATE INDEX IF NOT EXISTS idx_ent_key_value ON entitlements(key, value);
CREATE INDEX IF NOT EXISTS idx_sandbox_name ON sandbox_profiles(name);
CREATE INDEX IF NOT EXISTS idx_rules_profile ON sandbox_rules(profile_id);
CREATE INDEX IF NOT EXISTS idx_rules_operation ON sandbox_rules(operation);
CREATE INDEX IF NOT EXISTS idx_kexts_bundle ON kexts(bundle_id);
CREATE INDEX IF NOT EXISTS idx_frameworks_name ON frameworks(name);
CREATE INDEX IF NOT EXISTS idx_obs_entity ON observations(entity_table, entity_id);
CREATE INDEX IF NOT EXISTS idx_obs_time ON observations(observed_at);
CREATE INDEX IF NOT EXISTS idx_obs_type ON observations(event_type);
CREATE INDEX IF NOT EXISTS idx_atoms_type ON atoms(entity_type);
CREATE INDEX IF NOT EXISTS idx_atoms_version ON atoms(source_version_id);
CREATE INDEX IF NOT EXISTS idx_bags_type ON bags(entity_type);
CREATE INDEX IF NOT EXISTS idx_relog_bag ON resolution_event_log(bag_id);
CREATE INDEX IF NOT EXISTS idx_match_entity ON match_candidates(entity_type);
CREATE INDEX IF NOT EXISTS idx_match_atom_a ON match_candidates(atom_a);
CREATE INDEX IF NOT EXISTS idx_mach_daemon ON mach_services(daemon_id);
CREATE INDEX IF NOT EXISTS idx_mach_service ON mach_services(service_name);
"""

FTS_SCHEMA = """
CREATE VIRTUAL TABLE IF NOT EXISTS files_fts USING fts5(
    path, filename, file_type,
    content='files', content_rowid='id'
);

CREATE VIRTUAL TABLE IF NOT EXISTS daemons_fts USING fts5(
    label, program, mach_services, sandbox_profile,
    content='daemons', content_rowid='id'
);

CREATE VIRTUAL TABLE IF NOT EXISTS atoms_fts USING fts5(
    entity_type, source_key, properties,
    content='atoms', content_rowid='id'
);
"""

FTS_TRIGGERS = """
CREATE TRIGGER IF NOT EXISTS files_ai AFTER INSERT ON files BEGIN
    INSERT INTO files_fts(rowid, path, filename, file_type)
    VALUES (new.id, new.path, new.filename, new.file_type);
END;

CREATE TRIGGER IF NOT EXISTS files_ad AFTER DELETE ON files BEGIN
    INSERT INTO files_fts(files_fts, rowid, path, filename, file_type)
    VALUES ('delete', old.id, old.path, old.filename, old.file_type);
END;

CREATE TRIGGER IF NOT EXISTS files_au AFTER UPDATE ON files BEGIN
    INSERT INTO files_fts(files_fts, rowid, path, filename, file_type)
    VALUES ('delete', old.id, old.path, old.filename, old.file_type);
    INSERT INTO files_fts(rowid, path, filename, file_type)
    VALUES (new.id, new.path, new.filename, new.file_type);
END;

CREATE TRIGGER IF NOT EXISTS daemons_ai AFTER INSERT ON daemons BEGIN
    INSERT INTO daemons_fts(rowid, label, program, mach_services, sandbox_profile)
    VALUES (new.id, new.label, new.program, new.mach_services, new.sandbox_profile);
END;

CREATE TRIGGER IF NOT EXISTS daemons_ad AFTER DELETE ON daemons BEGIN
    INSERT INTO daemons_fts(daemons_fts, rowid, label, program, mach_services, sandbox_profile)
    VALUES ('delete', old.id, old.label, old.program, old.mach_services, old.sandbox_profile);
END;

CREATE TRIGGER IF NOT EXISTS daemons_au AFTER UPDATE ON daemons BEGIN
    INSERT INTO daemons_fts(daemons_fts, rowid, label, program, mach_services, sandbox_profile)
    VALUES ('delete', old.id, old.label, old.program, old.mach_services, old.sandbox_profile);
    INSERT INTO daemons_fts(rowid, label, program, mach_services, sandbox_profile)
    VALUES (new.id, new.label, new.program, new.mach_services, new.sandbox_profile);
END;

CREATE TRIGGER IF NOT EXISTS atoms_ai AFTER INSERT ON atoms BEGIN
    INSERT INTO atoms_fts(rowid, entity_type, source_key, properties)
    VALUES (new.id, new.entity_type, new.source_key, new.properties);
END;

CREATE TRIGGER IF NOT EXISTS atoms_ad AFTER DELETE ON atoms BEGIN
    INSERT INTO atoms_fts(atoms_fts, rowid, entity_type, source_key, properties)
    VALUES ('delete', old.id, old.entity_type, old.source_key, old.properties);
END;

CREATE TRIGGER IF NOT EXISTS atoms_au AFTER UPDATE ON atoms BEGIN
    INSERT INTO atoms_fts(atoms_fts, rowid, entity_type, source_key, properties)
    VALUES ('delete', old.id, old.entity_type, old.source_key, old.properties);
    INSERT INTO atoms_fts(rowid, entity_type, source_key, properties)
    VALUES (new.id, new.entity_type, new.source_key, new.properties);
END;
"""

VIEWS = """
CREATE VIEW IF NOT EXISTS v_sandbox_escape_surface AS
SELECT
    d.label, d.program, d.mach_services,
    d.sandbox_profile, d.user_name,
    GROUP_CONCAT(e.key, ', ') AS privileged_entitlements
FROM daemons d
JOIN binaries b ON d.binary_id = b.id
JOIN entitlements e ON e.binary_id = b.id
WHERE (d.sandbox_profile IS NULL OR d.sandbox_profile = '')
AND d.mach_services IS NOT NULL
GROUP BY d.id;

CREATE VIEW IF NOT EXISTS v_kernel_attack_surface AS
SELECT
    k.bundle_id, k.name AS kext_name,
    k.version, k.personalities, k.iokit_classes
FROM kexts k WHERE k.has_user_client = 1;

CREATE VIEW IF NOT EXISTS v_test_binaries AS
SELECT f.path, b.bundle_id, b.executable_name
FROM binaries b
JOIN files f ON b.file_id = f.id
WHERE f.path LIKE '%/test%' OR f.path LIKE '%/debug%'
    OR b.bundle_id LIKE '%test%' OR b.bundle_id LIKE '%debug%';
"""


# Derive the required named objects from the canonical DDL so the validation
# list cannot drift independently from fresh-database initialization.
_EXPECTED_SCHEMA_OBJECTS = {
    "table": frozenset(re.findall(
        r"CREATE\s+(?:VIRTUAL\s+)?TABLE\s+IF\s+NOT\s+EXISTS\s+(\w+)",
        CORE_SCHEMA + FTS_SCHEMA,
        re.IGNORECASE,
    )),
    "index": frozenset(re.findall(
        r"CREATE\s+INDEX\s+IF\s+NOT\s+EXISTS\s+(\w+)",
        INDEXES,
        re.IGNORECASE,
    )),
    "trigger": frozenset(re.findall(
        r"CREATE\s+TRIGGER\s+IF\s+NOT\s+EXISTS\s+(\w+)",
        FTS_TRIGGERS,
        re.IGNORECASE,
    )),
    "view": frozenset(re.findall(
        r"CREATE\s+VIEW\s+IF\s+NOT\s+EXISTS\s+(\w+)",
        VIEWS,
        re.IGNORECASE,
    )),
}


def _validate_current_schema(conn: sqlite3.Connection) -> None:
    """Refuse a database that claims the current version but is incomplete."""
    missing = []
    for object_type, expected_names in _EXPECTED_SCHEMA_OBJECTS.items():
        actual_names = {
            row[0]
            for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type = ?", (object_type,)
            )
        }
        missing.extend(
            f"{object_type} {name!r}" for name in sorted(expected_names - actual_names)
        )

    if missing:
        raise SchemaValidationError(
            f"ICARUS database claims schema version {SCHEMA_VERSION} but is incomplete; "
            f"missing {', '.join(missing)}; refusing to modify the database"
        )


def migrate_v2_to_v3(conn: sqlite3.Connection) -> None:
    """Additive migration: adds versions table and provenance columns."""
    conn.execute("""
        CREATE TABLE IF NOT EXISTS versions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            run_id TEXT NOT NULL UNIQUE,
            parser_name TEXT NOT NULL,
            source_path TEXT,
            started_at TEXT NOT NULL,
            completed_at TEXT,
            entity_count INTEGER DEFAULT 0,
            metadata TEXT
        )
    """)
    for table in ENTITY_TABLES:
        for col, typedef in [
            ("source_version_id", "INTEGER"),
            ("confidence", "REAL DEFAULT 1.0"),
            ("observed_time", "TEXT"),
            ("marking", "TEXT DEFAULT 'UNCLASSIFIED'"),
        ]:
            try:
                conn.execute(f"ALTER TABLE [{table}] ADD COLUMN {col} {typedef}")
            except sqlite3.OperationalError:
                pass  # column already exists
    conn.execute(
        "INSERT OR REPLACE INTO metadata VALUES (?, ?)",
        ("schema_version", "3")
    )
    conn.commit()


def migrate_v3_to_v4(conn: sqlite3.Connection) -> None:
    """Additive migration: adds Phase 2 tables — observations, atoms, bags, resolution_event_log."""
    conn.execute("""
        CREATE TABLE IF NOT EXISTS observations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            entity_table TEXT NOT NULL,
            entity_id INTEGER NOT NULL,
            observed_at TEXT NOT NULL,
            observer TEXT,
            event_type TEXT NOT NULL,
            properties TEXT,
            version_id INTEGER REFERENCES versions(id),
            confidence REAL DEFAULT 1.0
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS atoms (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            source_version_id INTEGER NOT NULL REFERENCES versions(id),
            entity_type TEXT NOT NULL,
            source_key TEXT NOT NULL,
            properties TEXT NOT NULL,
            created_at TEXT NOT NULL,
            UNIQUE(source_version_id, entity_type, source_key)
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS bags (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            entity_type TEXT NOT NULL,
            canonical_key TEXT,
            created_at TEXT NOT NULL,
            resolved_at TEXT,
            atom_count INTEGER DEFAULT 1
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS bag_atoms (
            bag_id INTEGER NOT NULL REFERENCES bags(id),
            atom_id INTEGER NOT NULL REFERENCES atoms(id),
            PRIMARY KEY(bag_id, atom_id)
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS resolution_event_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_type TEXT NOT NULL,
            bag_id INTEGER NOT NULL REFERENCES bags(id),
            atom_ids TEXT NOT NULL,
            reason TEXT,
            confidence REAL,
            operator TEXT,
            timestamp TEXT NOT NULL
        )
    """)
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_obs_entity "
        "ON observations(entity_table, entity_id)"
    )
    conn.execute("CREATE INDEX IF NOT EXISTS idx_obs_time ON observations(observed_at)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_obs_type ON observations(event_type)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_atoms_type ON atoms(entity_type)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_atoms_version ON atoms(source_version_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_bags_type ON bags(entity_type)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_relog_bag ON resolution_event_log(bag_id)")
    conn.executescript("""
        CREATE VIRTUAL TABLE IF NOT EXISTS atoms_fts USING fts5(
            entity_type, source_key, properties,
            content='atoms', content_rowid='id'
        );
        CREATE TRIGGER IF NOT EXISTS atoms_ai AFTER INSERT ON atoms BEGIN
            INSERT INTO atoms_fts(rowid, entity_type, source_key, properties)
            VALUES (new.id, new.entity_type, new.source_key, new.properties);
        END;
        CREATE TRIGGER IF NOT EXISTS atoms_ad AFTER DELETE ON atoms BEGIN
            INSERT INTO atoms_fts(atoms_fts, rowid, entity_type, source_key, properties)
            VALUES ('delete', old.id, old.entity_type, old.source_key, old.properties);
        END;
    """)
    conn.execute(
        "INSERT OR REPLACE INTO metadata VALUES (?, ?)",
        ("schema_version", "4")
    )
    conn.commit()


def migrate_v4_to_v5(conn: sqlite3.Connection) -> None:
    """Additive migration: adds the normalized mach_services table.

    mach_services makes the daemon <-> Mach service relationship a first-class
    join (service_name -> daemon_id) instead of a serialized TEXT blob on
    daemons.mach_services, which is the key pivot for attack-surface queries.
    """
    conn.execute("""
        CREATE TABLE IF NOT EXISTS mach_services (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            daemon_id INTEGER NOT NULL REFERENCES daemons(id),
            service_name TEXT NOT NULL,
            source_version_id INTEGER REFERENCES versions(id),
            confidence REAL DEFAULT 1.0,
            observed_time TEXT,
            marking TEXT DEFAULT 'UNCLASSIFIED',
            UNIQUE(daemon_id, service_name)
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_mach_daemon ON mach_services(daemon_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_mach_service ON mach_services(service_name)")
    conn.execute(
        "INSERT OR REPLACE INTO metadata VALUES (?, ?)",
        ("schema_version", "5")
    )
    conn.commit()


def _v5_to_v6(conn: sqlite3.Connection) -> None:
    """Additive migration: adds match_candidates and the bags.score column.

    match_candidates records scored atom-pair candidates (the output of the
    scored-resolver increment) and bags gains a score column for the
    confidence of a resolved grouping.

    The CREATE TABLE text below is kept byte-identical (same 4-space column
    indentation) to the match_candidates definition in CORE_SCHEMA so that a
    freshly-initialized v6 database and a v5 database upgraded through here
    store the same statement in sqlite_master. ALTER TABLE cannot be made
    conditional, so bags.score is added only when PRAGMA table_info shows it
    is absent — which makes re-running this migration a safe no-op.
    """
    conn.execute("""CREATE TABLE IF NOT EXISTS match_candidates (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    entity_type TEXT NOT NULL,
    atom_a INTEGER NOT NULL REFERENCES atoms(id),
    atom_b INTEGER NOT NULL REFERENCES atoms(id),
    score REAL NOT NULL,
    features TEXT,
    created_at TEXT NOT NULL,
    UNIQUE(atom_a, atom_b)
)""")
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_match_entity ON match_candidates(entity_type)"
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_match_atom_a ON match_candidates(atom_a)"
    )
    bags_cols = {r[1] for r in conn.execute("PRAGMA table_info(bags)").fetchall()}
    if "score" not in bags_cols:
        conn.execute("ALTER TABLE bags ADD COLUMN score REAL")
    conn.execute(
        "INSERT OR REPLACE INTO metadata VALUES (?, ?)",
        ("schema_version", "6")
    )
    conn.commit()


def _extract_create_table(table: str) -> str:
    """Return the canonical ``CREATE TABLE`` statement for an entity table.

    Sliced verbatim from ``CORE_SCHEMA`` so a table rebuilt during FK-parity
    repair stores DDL byte-identical to a freshly initialized database's
    ``sqlite_master`` entry (SQLite strips ``IF NOT EXISTS`` consistently).
    """
    match = re.search(
        rf"CREATE TABLE IF NOT EXISTS {re.escape(table)} \(.*?\n\);",
        CORE_SCHEMA,
        re.DOTALL,
    )
    if match is None:  # pragma: no cover - guards against future schema drift
        raise SchemaValidationError(
            f"CORE_SCHEMA has no CREATE TABLE definition for entity table {table!r}"
        )
    return match.group(0)


def _entity_table_needs_fk_repair(conn: sqlite3.Connection, table: str) -> bool:
    """True when ``table`` has a ``source_version_id`` column that lacks the
    ``REFERENCES versions(id)`` foreign key.

    This is exactly the divergence a v2/v3 → v6 migration produces: the column
    is added by ``ALTER TABLE ADD COLUMN``, which cannot carry a ``REFERENCES``
    clause, so the provenance foreign key present on a fresh v6 build is silently
    absent. A fresh v6 table already has the FK, so this returns ``False`` there
    and the rebuild is skipped (idempotent no-op).
    """
    columns = {row[1] for row in conn.execute(f"PRAGMA table_info([{table}])")}
    if "source_version_id" not in columns:
        # Table absent, or predates the provenance columns — nothing to repair.
        return False
    fk_rows = conn.execute(f"PRAGMA foreign_key_list([{table}])").fetchall()
    has_version_fk = any(
        row[3] == "source_version_id" and row[2] == "versions" for row in fk_rows
    )
    return not has_version_fk


def _rebuild_entity_table_with_fk(conn: sqlite3.Connection, table: str) -> None:
    """Rebuild one entity table to the canonical v6 definition (with the
    ``source_version_id -> versions(id)`` foreign key) via SQLite's supported
    table-redefinition procedure, preserving every row.

    The caller must have disabled ``foreign_keys`` and left no open transaction.
    Rather than the create-new-then-rename form (whose ``ALTER ... RENAME``
    re-quotes the table name in the stored DDL, breaking byte-identity with a
    fresh build), this renames the *old* table aside and recreates the target
    verbatim from ``CORE_SCHEMA``. ``legacy_alter_table`` keeps that rename from
    rewriting ``REFERENCES`` clauses in other tables that point at this one.
    """
    create_sql = _extract_create_table(table)
    aside = f"_icarus_fkrepair_{table}"

    before = conn.execute(f"SELECT COUNT(*) FROM [{table}]").fetchone()[0]  # nosec B608 - table iterates the hardcoded ENTITY_TABLES tuple, not external input

    # Remember the indexes and triggers that belong to this table so exactly
    # those — no more, no less — are recreated afterward. Auto-created indexes
    # (UNIQUE/PK constraints) have sql = NULL and are rebuilt by the CREATE
    # TABLE itself, so they are excluded here.
    attached = conn.execute(
        "SELECT type, name, sql FROM sqlite_master "
        "WHERE tbl_name = ? AND type IN ('index', 'trigger') AND sql IS NOT NULL",
        (table,),
    ).fetchall()

    conn.execute("BEGIN")
    # Drop the attached objects explicitly first so the rename/drop below can't
    # leave a same-named orphan that would collide when we recreate them.
    for obj_type, name, _ in attached:
        conn.execute(f"DROP {obj_type} IF EXISTS [{name}]")

    conn.execute("PRAGMA legacy_alter_table = ON")
    try:
        # legacy_alter_table keeps this rename from rewriting REFERENCES clauses
        # in OTHER tables that point at this one.
        conn.execute(f"ALTER TABLE [{table}] RENAME TO [{aside}]")
    finally:
        conn.execute("PRAGMA legacy_alter_table = OFF")

    # Recreate the table verbatim -> stored DDL matches a fresh v6 database.
    conn.execute(create_sql)

    # Copy only columns the old table actually had. A legacy database may
    # predate some non-provenance columns too; those are left to their column
    # defaults in the rebuilt table rather than failing the copy.
    new_cols = [row[1] for row in conn.execute(f"PRAGMA table_info([{table}])")]
    old_cols = {row[1] for row in conn.execute(f"PRAGMA table_info([{aside}])")}
    common = [c for c in new_cols if c in old_cols]
    col_list = ", ".join(f"[{c}]" for c in common)
    conn.execute(
        f"INSERT INTO [{table}] ({col_list}) SELECT {col_list} FROM [{aside}]"  # nosec B608 - identifiers from ENTITY_TABLES and the tables' own PRAGMA table_info(), not external input
    )
    conn.execute(f"DROP TABLE [{aside}]")

    # Recreate the remembered indexes/triggers from their original DDL.
    for _, _, sql in attached:
        conn.execute(sql)

    violations = conn.execute(f"PRAGMA foreign_key_check([{table}])").fetchall()
    if violations:
        conn.rollback()
        raise SchemaValidationError(
            f"FK-parity rebuild of {table!r} would introduce foreign key "
            f"violations: {violations!r}; rolled back"
        )

    after = conn.execute(f"SELECT COUNT(*) FROM [{table}]").fetchone()[0]  # nosec B608 - table iterates the hardcoded ENTITY_TABLES tuple, not external input
    if after != before:  # pragma: no cover - copy is a straight column-wise SELECT
        conn.rollback()
        raise SchemaValidationError(
            f"FK-parity rebuild of {table!r} changed row count {before} -> {after}"
        )
    conn.commit()


def _repair_migrated_entity_fks(conn: sqlite3.Connection) -> None:
    """Bring migrated entity tables to FK parity with a fresh v6 build.

    ``ALTER TABLE ADD COLUMN`` cannot add a ``REFERENCES`` constraint, so a
    database migrated up from v2/v3 reaches v6 with the ``source_version_id``
    provenance column present but its ``-> versions(id)`` foreign key missing —
    a schema divergence from a freshly initialized v6 database, where FK
    enforcement does not protect provenance on the migrated database. This
    rebuilds only the entity tables that actually lack the FK, so it is a safe
    idempotent no-op on a fresh v6 database and on re-runs.
    """
    to_rebuild = [t for t in ENTITY_TABLES if _entity_table_needs_fk_repair(conn, t)]
    if not to_rebuild:
        return

    prior_fk = conn.execute("PRAGMA foreign_keys").fetchone()[0]
    conn.commit()  # PRAGMA foreign_keys is a no-op inside a transaction
    conn.execute("PRAGMA foreign_keys = OFF")
    try:
        for table in to_rebuild:
            _rebuild_entity_table_with_fk(conn, table)
        violations = conn.execute("PRAGMA foreign_key_check").fetchall()
        if violations:
            raise SchemaValidationError(
                f"FK-parity repair left foreign key violations: {violations!r}"
            )
    finally:
        conn.execute(f"PRAGMA foreign_keys = {'ON' if prior_fk else 'OFF'}")


def _repair_migrated_non_fk_objects(conn: sqlite3.Connection) -> None:
    """Restore non-table objects omitted by older additive migrations.

    Older v2-v5 migration steps could reach v6 without some indexes, FTS
    tables/triggers, or views that a fresh v6 build has. Replaying the
    canonical DDL with ``IF NOT EXISTS`` is guarded, additive, and idempotent:
    existing objects are left untouched.

    FTS5 external-content tables do not index rows that predate their creation.
    Rebuild only tables absent on entry, so pre-existing rows are searchable
    without needlessly rewriting valid existing indexes.
    """
    fts_names = ("files_fts", "daemons_fts", "atoms_fts")
    existing_fts = {
        row[0]
        for row in conn.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table' AND name IN "
            "('files_fts', 'daemons_fts', 'atoms_fts')"
        )
    }

    conn.executescript(INDEXES)
    conn.executescript(FTS_SCHEMA)
    conn.executescript(FTS_TRIGGERS)
    conn.executescript(VIEWS)

    for fts_name in fts_names:
        if fts_name in existing_fts:
            continue
        quoted = f'"{fts_name}"'
        conn.execute(
            f"INSERT INTO {quoted}({quoted}) VALUES ('rebuild')"  # nosec B608 - fts_name is a fixed allowlist
        )


def _read_schema_version(conn: sqlite3.Connection) -> Optional[int]:
    """Read and validate the metadata schema version without changing the database."""
    metadata_exists = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'metadata'"
    ).fetchone()
    if metadata_exists is None:
        return None

    row = conn.execute(
        "SELECT value FROM metadata WHERE key = 'schema_version'"
    ).fetchone()
    if row is None:
        return None

    try:
        return int(row[0])
    except (TypeError, ValueError) as exc:
        raise SchemaVersionError(
            f"Invalid ICARUS schema version {row[0]!r}: expected an integer; "
            "refusing to modify the database"
        ) from exc


def initialize_database(db_path: Path, metadata: Optional[dict] = None) -> dict:
    """
    Create and initialize an ICARUS database.

    Creates a fresh v6 database, or migrates an existing v2/v3/v4/v5 database
    forward. Databases outside that supported range are refused before their
    stored version is changed. Returns stats dict with table count and schema
    version.
    """
    conn = open_db(db_path)
    try:
        existing_version = _read_schema_version(conn)

        if existing_version is not None and not 2 <= existing_version <= SCHEMA_VERSION:
            raise SchemaVersionError(
                f"Unsupported ICARUS schema version {existing_version}: this install "
                f"supports versions 2 through {SCHEMA_VERSION}; refusing to modify "
                "the database"
            )

        migrated = existing_version is not None and existing_version < SCHEMA_VERSION

        if existing_version == 2:
            migrate_v2_to_v3(conn)
            migrate_v3_to_v4(conn)
            migrate_v4_to_v5(conn)
            _v5_to_v6(conn)
        elif existing_version == 3:
            migrate_v3_to_v4(conn)
            migrate_v4_to_v5(conn)
            _v5_to_v6(conn)
        elif existing_version == 4:
            migrate_v4_to_v5(conn)
            _v5_to_v6(conn)
        elif existing_version == 5:
            _v5_to_v6(conn)
        elif existing_version == SCHEMA_VERSION:
            _validate_current_schema(conn)
        elif existing_version is None:
            conn.executescript(CORE_SCHEMA)
            conn.executescript(INDEXES)
            conn.executescript(FTS_SCHEMA)
            conn.executescript(FTS_TRIGGERS)
            conn.executescript(VIEWS)
            conn.execute(
                "INSERT INTO metadata VALUES (?, ?)",
                ("schema_version", str(SCHEMA_VERSION))
            )

        # Complete the additive migration before the v6 validation path is used
        # on the next open. The repair is limited to databases that actually
        # migrated from a supported older version.
        if migrated:
            _repair_migrated_non_fk_objects(conn)

        # Restore fresh-vs-migrated schema parity: any DB that reached v6 by
        # migration (or was stamped v6 by an older, buggy migration chain) is
        # missing the source_version_id -> versions(id) FK that a fresh build
        # has. Guarded and idempotent — a no-op on a correct fresh v6 DB.
        _repair_migrated_entity_fks(conn)

        if metadata:
            for k, v in metadata.items():
                conn.execute(
                    "INSERT OR REPLACE INTO metadata VALUES (?, ?)", (k, str(v))
                )

        conn.commit()

        tables = conn.execute(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='table'"
        ).fetchone()[0]
    finally:
        conn.close()

    return {"tables": tables, "schema_version": SCHEMA_VERSION}


def get_schema_version(db_path: Path) -> Optional[int]:
    """Get the schema version of an existing database."""
    conn = sqlite3.connect(str(db_path))
    try:
        return _read_schema_version(conn)
    finally:
        conn.close()
