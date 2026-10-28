# Getting Started

## Requirements

| Dependency | Version | Notes |
|-----------|---------|-------|
| Python | >= 3.10 | Tested on 3.10, 3.12, 3.13 |
| SQLite | >= 3.35 | Required for FTS5. Ships with Python on all platforms. |
| [HYGEIA](https://github.com/Indegosblade/HYGEIA) | v3.15.0 | PII sanitization. Auto-installed from a pinned commit. |
| [PyYAML](https://pyyaml.org/) | >= 6.0 | Parser manifest loading |
| [jsonschema](https://python-jsonschema.readthedocs.io/) | >= 4.20 | Manifest validation |

No native extensions or system-level dependencies beyond Python.

## Install

```bash
pip install git+https://github.com/Indegosblade/icarus-framework.git
```

From source:
```bash
git clone https://github.com/Indegosblade/icarus-framework.git
cd icarus-framework
pip install .
```

Development (adds pytest, ruff, mypy, bandit):
```bash
pip install -e ".[dev]"
```

## First Scan

```bash
# Auto-detect parser from source contents
icarus build --source /path/to/data --output intel.db

# Specify parser explicitly
icarus build --source "C:\Program Files\MyApp" --output myapp.db --parser windows

# Skip PII sanitization (raw output)
icarus build --source /data --output raw.db --skip-hygeia
```

The pipeline:
1. Auto-detects the best parser (or uses `--parser`)
2. Extracts entities (files, binaries, daemons, frameworks, etc.)
3. Maps relationships between entities
4. Runs HYGEIA sanitization (unless `--skip-hygeia`)
5. Finalizes provenance (entity count, completion timestamp)

## Query

```bash
# Full-text search
icarus query intel.db --search "nginx"

# Table row counts
icarus query intel.db --stats

# Raw SQL
icarus query intel.db --sql "SELECT COUNT(*) FROM binaries WHERE arch='x86_64'"

# Search specific table
icarus query intel.db --search "config" --table daemons
```

## Diff

```bash
# Compare two databases
icarus diff v1.db v2.db

# Write report to file
icarus diff v1.db v2.db -o report.md

# Export as STIX 2.1 bundle
icarus diff v1.db v2.db --stix changes.json
```

## Resolve (experimental)

Merge the same entity observed across multiple builds into one canonical identity:

```bash
# Atomize two builds and resolve binaries/daemons across them
icarus resolve --out resolved.db host_a.db host_b.db

# Or resolve within a single build
icarus build --source /data --output intel.db --resolve
```

Every scored candidate pair is recorded in `match_candidates` and each merge's confidence in `bags.score`, so a resolution stays auditable. See [[CLI Reference]] for flags and [[Schema Reference]] for the tables.

## Parser Management

```bash
# List all registered parsers
icarus parser list

# Validate a parser manifest
icarus parser validate icarus/parsers/windows.yaml

# Run parser test harness
icarus parser test windows
```

## Python API

```python
from icarus.core.pipeline import create_default_pipeline
from icarus.core.query import IcarusQuery
from icarus.core.differ import IcarusDiffer

# Build
p = create_default_pipeline(source, output, parser_name="windows")
p.run()

# Query
with IcarusQuery("intel.db") as q:
    q.root_daemons()
    q.service_map()

# Diff
with IcarusDiffer("v1.db", "v2.db") as d:
    report = d.generate_report()
```
