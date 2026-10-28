# Parser development guide

A parser translates source data into normalized entities, relationships, and
observations. Implement `BaseParser`, declare its capabilities in a YAML manifest,
and validate source-specific behavior with fixtures.

Existing integrations operate on explicit schema mappings. FTS indexes cover
files, daemons, and atoms; STIX and diff support defined types; experimental
resolution requires an `ATOM_PROJECTIONS` entry. Adding a new table does not
automatically provide these capabilities.

Private modules under the gitignored `icarus/parsers/private/` package use the
same discovery mechanism and are excluded from public package artifacts. Plugins
execute trusted Python code in the caller's process; review them before installing.

## Production Parsers

| Parser | Specificity | Reliability |
|--------|:-----------:|:-----------:|
| `cloud/aws/cloudtrail` | 5 | A |
| `windows` | 20 | B |
| `linux` | 20 | B |
| `generic/json` | 100 | F |
| `generic/xml` | 100 | F |
| `generic/sqlite` | 100 | F |
| `generic/archive` | 100 | F |
| `generic/binary` | 100 | F |

**Specificity** determines priority in auto-detection. Lower wins.

**Reliability** uses Admiralty/NATO source-grade labels: A (completely reliable) through F (reliability cannot be judged). These labels describe source reliability, not parser correctness.

---

## Candidate Parsers

Under evaluation in `parsers-devel.json` — not yet gated for production.

| Parser | Specificity | Reliability |
|--------|:-----------:|:-----------:|
| `macos` | 8 | B |

**`macos`** — macOS / iOS root filesystem: daemons, Mach services, entitlements, kexts, frameworks. Ingests an extracted rootfs for iOS/macOS daemon and attack-surface mapping (Apple Security Bounty research), in phases:

1. **launchd** — LaunchDaemon/LaunchAgent plists become `daemons`; each `MachServices` key is normalized into a `mach_services` declaration linked to its declaring daemon. This does not establish runtime client reachability.
2. **Mach-O binaries** — architecture, code-signing flags, and embedded entitlements, extracted by a self-contained stdlib Mach-O reader at `icarus/parsers/macho.py` (no external `codesign` or `ldid`).
3. **IOKit kexts**, **frameworks**, and the **sandbox-profile catalog**.

`extract_relationships` links each daemon to its executable binary.

---

## Parser Manifest

Every parser ships with a YAML manifest validated by JSON Schema at load time. The manifest declares identity, capabilities, quality, and test configuration.
The parser class's `name` must equal `parser_id`; the registry rejects a mismatch.
Passing the fixture harness does not automatically promote `quality_tier`.

```yaml
parser_id: "my_parser"
version: "1.0.0"
spec_version: "icarus-parser/1.0"
author: "Your Name"
license: "PolyForm-Noncommercial-1.0.0"
quality_tier: "prototype"         # production | candidate | prototype | private
description: "One-line description"

identify:
  specificity_level: 20           # 1-100, lower = more specific
  markers:
    - "Description of what identify() looks for"

consumes:
  - "file_type_or_format"

produces:
  entity_types:
    - files

reliability: "B"                  # A-F Admiralty grade
default_confidence: 0.85          # 0.0-1.0

tests:
  fixtures_dir: "selftest/fixtures/my_parser"
  golden_output: "selftest/golden/my_parser.json"
```

Built-in test resources live below `icarus/parsers/selftest/` and are included
as package data, so the same gates run from source and from an installed wheel.

Validate a manifest:
```bash
icarus parser validate path/to/my_parser.yaml
```

---

## Writing a Parser

### Interface

This is a template showing the required method signatures; the extraction example
below is a complete minimal parser implementation.

```python
from icarus.parsers.base import BaseParser
from pathlib import Path

class MyParser(BaseParser):

    @property
    def name(self) -> str:
        return "my_parser"

    @property
    def description(self) -> str:
        return "One-line description of what this parser handles"

    def identify(self, source: Path) -> bool:
        """Return True if this parser can handle this source.
        Called during auto-detection. Keep it fast."""

    def extract_entities(self, source: Path, db_path: Path) -> dict:
        """Main extraction. Walk source, write entities to DB tables.
        Return stats dict."""

    def extract_relationships(self, source: Path, db_path: Path) -> dict:
        """Link entities together. Runs after extract_entities."""

    def verify(self, db_path: Path) -> dict:
        """Quality gates. Assert expected state."""
```

### Extraction Pattern

```python
import os
from pathlib import Path

from icarus.core.schema import open_db
from icarus.parsers.base import BaseParser


def fail_walk(error: OSError) -> None:
    raise error


class MyParser(BaseParser):
    @property
    def name(self) -> str:
        return "my_parser"  # Must match manifest parser_id.

    @property
    def description(self) -> str:
        return "Example MY_FORMAT parser"

    def identify(self, source: Path) -> bool:
        marker = Path(source) / "MY_FORMAT.marker"
        _st, kind = self._file_kind(marker)
        return kind == "regular" and not self._path_has_symlink(marker, source)

    def extract_entities(self, source: Path, db_path: Path) -> dict:
        source = Path(source).resolve()
        inserted = 0
        conn = open_db(db_path)
        try:
            with conn:  # one atomic transaction; no periodic partial commits
                for directory, dirs, files in os.walk(
                    source, followlinks=False, onerror=fail_walk
                ):
                    parent = Path(directory)
                    dirs[:] = [name for name in dirs
                               if not self._path_has_symlink(parent / name, source)]
                    for filename in files:
                        path = parent / filename
                        _st, kind = self._file_kind(path)
                        if kind != "regular" or self._path_has_symlink(path, source):
                            continue
                        st = path.lstat()
                        digest = self._safe_hash(path, st.st_size)
                        try:
                            with self._open_regular(path) as handle:
                                text = handle.read(4096).decode("utf-8", "replace")
                        except OSError:
                            continue
                        if "MY_FORMAT" not in text:
                            continue
                        cur = conn.execute(
                            "INSERT OR IGNORE INTO files "
                            "(path, filename, extension, size, sha256, file_type) "
                            "VALUES (?, ?, ?, ?, ?, ?)",
                            (self._rel_path(path, source), path.name,
                             path.suffix.lower(), st.st_size, digest, "my_format"),
                        )
                        inserted += cur.rowcount
        finally:
            conn.close()
        return {"files": inserted}

    def extract_relationships(self, source: Path, db_path: Path) -> dict:
        return {}
```

This example emits only file rows and inherits `BaseParser.verify`. The helper
checks regular files, refuses symlink/reparse components, and safely opens files;
the SQL uses parameters and counts actual inserted rows. Traversal errors should
be handled according to parser policy and reported rather than silently ignored.
Repeating this extraction inserts zero additional rows for already-seen paths.
Keep source data immutable, output outside the source tree, and logs private.
Direct parser calls do not acquire pipeline leases or create pipeline audit evidence.

This is not resumable per batch. Phase replay, cursor, and provenance transaction
behavior is defined by the pipeline and built-in parsers; see
[ingest recovery](../docs/INGEST_RECOVERY.md) and `icarus/parsers/progress.py`.

### Idempotency

Tables with UNIQUE constraints (`files` on `path`) can use `INSERT OR IGNORE`. Tables without UNIQUE constraints (`binaries`, `observations`) require an explicit existence check:

```python
existing = conn.execute(
    "SELECT id FROM binaries WHERE file_id=?", (file_id,)
).fetchone()
if not existing:
    conn.execute("INSERT INTO binaries (...) VALUES (...)", (...))
```

The test harness verifies this: second run must add zero entities.

---

## Registration

Parsers are auto-discovered — there is no list to edit.

### In this repo (recommended)

1. Create your parser module (e.g., `icarus/parsers/cloud/my_cloud.py`) with a concrete `BaseParser` subclass.
2. Create a YAML manifest alongside it (e.g., `icarus/parsers/cloud/my_cloud.yaml`).
3. That's it. At import time, `icarus.parsers` walks the package tree and registers every concrete `BaseParser` subclass it finds; the sibling `<module>.yaml` becomes that parser's manifest automatically.

The parser is immediately available via CLI (`--parser cloud/my_cloud`) and auto-detection — no registry file to edit.

### Local-only (not published)

Drop the module (plus an optional manifest) into the gitignored `icarus/parsers/private/` package instead of `icarus/parsers/`. It is discovered and registered exactly the same way, but never tracked in git or shipped in the published package — for parsers written against data you don't want in a public repo.

### From an installed package

A separately-packaged distribution can advertise a parser without touching this repo at all, via the `icarus.parsers` entry-point group in its own `pyproject.toml`:

```toml
[project.entry-points."icarus.parsers"]
my_cloud = "my_pkg.custom_parser:MyCloudParser"
```

ICARUS loads every entry point in that group at import time and registers the classes it finds, the same as a directory-discovered parser.

Discovery and manifest-load failures are logged (module or manifest name plus the exception), never silently swallowed — a broken or half-written parser degrades to "that one parser doesn't register," not a lost registry.

### Quality Tiers

| Tier | Requirements | Catalog |
|------|-------------|---------|
| `production` | All 4 harness tests pass, manifest validates, real-world validation | parsers.json |
| `candidate` | Under evaluation, may have known issues | parsers-devel.json |
| `prototype` | Proof of concept, incomplete | Not cataloged |
| `private` | Internal use only | Not cataloged |

### Test Harness

4 mandatory quality gates for production parsers:

```bash
icarus parser test my_parser
```

1. **Golden output** — entity counts match the packaged baseline
2. **Idempotency** — a second complete entity + relationship run leaves all parser output unchanged
3. **Schema conformance** — parser only writes to tables it declares in manifest
4. **Zero-PII** — HYGEIA verify_clean passes on output

---

## Schema Mapping

Map your source's concepts to ICARUS tables:

| Potential ICARUS mapping | Windows concept | Linux concept | CloudTrail concept | Your Parser |
|-------------|---------|-------|------------|-------------|
| `files` | Filesystem | Filesystem | -- | ? |
| `binaries` | PE/DLL | ELF/.so | -- | ? |
| `daemons` | Services | systemd units | IAM identities | ? |
| `entitlements` | Permissions | Capabilities | IAM policies | ? |
| `sandbox_profiles` | AppLocker | AppArmor | -- | ? |
| `kexts` | Drivers | .ko modules | -- | ? |
| `frameworks` | DLLs | .so libraries | -- | ? |
| `observations` | -- | -- | API events | ? |

This is a design table, not a declaration of implemented parser capabilities.
Check each manifest's `produces.entity_types`: CloudTrail declares `files`,
`daemons`, and `observations`.

---

## Parser Ideas

| Source | identify() Checks | Entities |
|--------|-------------------|----------|
| Android OTA | `META-INF/`, `system/app/` | APKs, permissions, intents, SELinux policies |
| Docker image | `manifest.json`, layers | Layer contents, ENV, exposed ports, users |
| Network scan | Nmap XML | Hosts, ports, banners, OS fingerprints |
| Kubernetes | YAML manifests | Pods, RBAC, network policies, secrets refs |
| API spec | OpenAPI/Swagger JSON | Endpoints, auth, schemas |
| GCP IAM | GCP policy JSON | Roles, bindings, service accounts |
| Azure AD | Azure policy JSON | Users, groups, role assignments |
