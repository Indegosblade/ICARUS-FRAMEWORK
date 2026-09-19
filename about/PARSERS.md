# Parser Development Guide

A parser is the only source-specific code in ICARUS. Everything downstream — schema,
FTS5 search, the cross-version differ, entity resolution, STIX export, and the
fail-closed sanitizer — is source-agnostic, so a parser that emits rows into the entity
tables inherits all of it for free. Your job is to turn one messy input into normalized
entities, relationships, and observations; the engine does the rest.

The payoff scales with how well you model the source:

- Emit **entity rows** → they are immediately searchable (FTS5), diffable across
  versions, exportable to STIX, and sanitized.
- Emit **observations** (temporal events) → `observation_diff` gives you
  "what changed over time" for free.
- Register your entity type in `ATOM_PROJECTIONS`
  ([`icarus/core/atomize.py`](../icarus/core/atomize.py)) — a short declarative
  projection — → the resolver clusters that entity type **across builds** into one
  canonical identity ("the same thing seen in two dumps").

Parsers are also first-class to keep private: anything under the gitignored
`icarus/parsers/private/` package registers and runs exactly like a shipped parser but
never enters git (see [Registration](#registration)).

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

**Reliability** uses Admiralty/NATO grades: A (completely reliable) through F (reliability cannot be judged).

---

## Candidate Parsers

Under evaluation in `parsers-devel.json` — not yet gated for production.

| Parser | Specificity | Reliability |
|--------|:-----------:|:-----------:|
| `macos` | 8 | B |

**`macos`** — macOS / iOS root filesystem: daemons, Mach services, entitlements, kexts, frameworks. Ingests an extracted rootfs for iOS/macOS daemon and attack-surface mapping (Apple Security Bounty research), in phases:

1. **launchd** — LaunchDaemon/LaunchAgent plists become `daemons`; each `MachServices` key is normalized into a `mach_services` row (the service -> daemon reachability pivot).
2. **Mach-O binaries** — architecture, code-signing flags, and embedded entitlements, extracted by a self-contained stdlib Mach-O reader at `icarus/parsers/macho.py` (no external `codesign` or `ldid`).
3. **IOKit kexts**, **frameworks**, and the **sandbox-profile catalog**.

`extract_relationships` links each daemon to its executable binary.

---

## Parser Manifest

Every parser ships with a YAML manifest validated by JSON Schema at load time. The manifest declares identity, capabilities, quality, and test configuration.

```yaml
parser_id: "my_parser"
version: "1.0.0"
spec_version: "icarus-parser/1.0"
author: "Your Name"
license: "PolyForm-Noncommercial-1.0.0"
quality_tier: "production"        # production | candidate | prototype | private
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
    - binaries

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
import sqlite3

def extract_entities(self, source: Path, db_path: Path) -> dict:
    conn = sqlite3.connect(str(db_path))
    count = 0
    try:
        for dirpath, _dirs, files in os.walk(source, onerror=lambda e: None):
            for fname in files:
                path = Path(dirpath) / fname
                try:
                    # Normalize and insert
                    rel = self._rel_path(path, source)
                    st = path.stat()
                    conn.execute(
                        "INSERT OR IGNORE INTO files "
                        "(path, filename, extension, size, sha256, file_type) "
                        "VALUES (?,?,?,?,?,?)",
                        (rel, path.name, path.suffix, st.st_size,
                         self._safe_hash(path, st.st_size), "my_type"),
                    )
                    count += 1
                except (PermissionError, OSError):
                    continue
                if count % 50000 == 0:
                    conn.commit()
        conn.commit()
    finally:
        conn.close()
    return {"files": count}
```

Rules:
- **Use `os.walk` with `onerror`, not `rglob`.** Broken symlinks crash `rglob`.
- **Wrap connections in `try/finally`.** Always close on crash.
- **Stream, never batch-load.** Iterate and commit periodically.
- **Check for duplicates** before INSERT on tables without UNIQUE constraints (binaries, observations).
- **Return stats** for pipeline provenance.

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

| ICARUS Table | Windows | Linux | CloudTrail | Your Parser |
|-------------|---------|-------|------------|-------------|
| `files` | Filesystem | Filesystem | -- | ? |
| `binaries` | PE/DLL | ELF/.so | -- | ? |
| `daemons` | Services | systemd units | IAM identities | ? |
| `entitlements` | Permissions | Capabilities | IAM policies | ? |
| `sandbox_profiles` | AppLocker | AppArmor | -- | ? |
| `kexts` | Drivers | .ko modules | -- | ? |
| `frameworks` | DLLs | .so libraries | -- | ? |
| `observations` | -- | -- | API events | ? |

Not every table needs data. A CloudTrail parser only writes to `daemons` and `observations`. A network scanner might only use `daemons` (listening services) and `entitlements` (port/protocol). Use what applies.

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
