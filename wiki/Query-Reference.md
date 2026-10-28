# Query Reference

## Configuration and metadata queries

Pre-built queries via `IcarusQuery`:

```python
from icarus.core.query import IcarusQuery

with IcarusQuery("intel.db") as q:
    # Explicit root-user declarations with no recorded sandbox profile
    q.root_daemons()

    # Configured Mach-service declarations
    q.service_map()

    # Normalized Mach-service declaration -> declaring daemon
    q.mach_service_owners()
    # ...or filter service names with a SQL LIKE pattern
    q.mach_service_owners("com.apple.%")

    # Kernel user-client metadata candidates (not proven client reachability)
    q.kernel_surface()

    # Binary names selected by test/debug naming heuristics
    q.test_binaries()

    # Mach-service / entitlement declaration candidates (not escalation proof)
    q.escape_surface()

    # Inventory of every extracted entitlement key (no privilege classification)
    q.privileged_entitlements()

    # Services whose linked image declares a matching entitlement key (LIKE)
    q.daemons_with_entitlement("com.apple.private.%")
```

## Configuration evidence and compatibility

These helpers inspect configuration files and extracted binary metadata. They do
not establish that a job ran, its effective credentials or sandbox, an allowed
client connection, or an exploitable privilege boundary.

`root_daemons()` includes an explicit `user_name='root'`, or numeric `'0'` when
the row's version provenance identifies the Linux parser. Missing users remain
unknown, including launch agents without `UserName`. A missing or empty
`sandbox_profile` means **no recorded profile**, not an unsandboxed process.
Linux `User=` and `Group=` declarations are preserved from the `[Service]`
section; see [service-identity parsing](../docs/SERVICE_IDENTITY.md) for limits.
Existing Linux databases need a fresh rebuild to collect this newly preserved
metadata; querying an old NULL does not reconstruct a source declaration.

`privileged_entitlements()` is a legacy method name: without keys it inventories
all entitlement keys, and with keys it matches the caller's selection. It does not
classify them as privileged. `kernel_surface()` reports metadata-selected
user-client candidates, without proving runtime access.

`escape_surface()` retains its join but labels results as declaration candidates.
Its returned key-list column is now `entitlement_keys`. The schema-v6 SQL view
`v_sandbox_escape_surface` and its historical `privileged_entitlements` column
remain unchanged for raw-SQL compatibility; that legacy column contains every
joined entitlement key, not a verified privilege classification. Python consumers
using that helper's old dictionary key should switch to `entitlement_keys`.

## Full-Text Search

FTS5 indexes on files, daemons, and atoms. Available via CLI or API.

```bash
# Search files
icarus query intel.db --search "config"

# Search daemons
icarus query intel.db --search "nginx" --table daemons
```

```python
from icarus.core.query import IcarusQuery

with IcarusQuery("intel.db") as q:
    results = q.search("nginx", table="daemons")
    print(results.to_markdown())
```

## Raw SQL

The CLI requires exactly one query mode (`--sql`, `--search`, or `--stats`).
Raw SQL runs on a read-only connection that rejects writes, `ATTACH`, and
`DETACH`. Use `icarus exec` for deliberate database mutations.

Python callers may explicitly construct `IcarusQuery(path, writable=True)` and
use `execute()` followed by `commit()`. Guarded DML and DDL revoke old sanitizer
evidence in that same transaction; `rollback()` or closing without committing
discards both. Direct raw connection/cursor writes bypass this guarantee.
See [public write and transaction boundaries](../docs/PUBLIC_WRITES.md).

```bash
icarus query intel.db --sql "SELECT filename, size FROM files WHERE size > 100000000 ORDER BY size DESC LIMIT 10"
```

```python
from icarus.core.query import IcarusQuery

with IcarusQuery("intel.db") as q:
    results = q.execute("SELECT COUNT(*) as cnt, arch FROM binaries GROUP BY arch ORDER BY cnt DESC")
    print(results.to_markdown())
```

Terminal/API query results retain at most 100 rows and report when additional
rows were truncated. Add an SQL `LIMIT` when you need a smaller deterministic
result window.

## Observation Queries

```python
from icarus.core.query import IcarusQuery

with IcarusQuery("intel.db") as q:
    # Replace these illustrative IDs with IDs from your database.
    daemon_id = 1
    file_id = 1
    # All observations for a specific daemon
    q.observations_for("daemons", daemon_id)

    # Observations within a time window
    q.pattern_of_life("daemons", daemon_id, "2024-01-01", "2024-06-01")

    # First time an entity was observed
    q.first_seen("files", file_id)

    # Join ontology entities with their observations
    q.cross_graph_query("daemons", event_type="permission_change")

    # New observations between pipeline runs
    q.observation_diff(start_version_id=1, end_version_id=2)
```

## Stats

```bash
icarus query intel.db --stats
```

Illustrative output (counts depend on the database):
```
files: 2,045,000
binaries: 29,427
daemons: 0
entitlements: 0
frameworks: 25,078
observations: 0
```

## Common Patterns

**Largest files:**
```sql
SELECT path, size FROM files ORDER BY size DESC LIMIT 20
```

**Binary architecture distribution:**
```sql
SELECT arch, COUNT(*) as cnt FROM binaries GROUP BY arch ORDER BY cnt DESC
```

**Files by type:**
```sql
SELECT file_type, COUNT(*) as cnt FROM files GROUP BY file_type ORDER BY cnt DESC
```

**Explicit root-user declarations with no recorded sandbox profile:**
```sql
SELECT label, program, user_name FROM daemons WHERE sandbox_profile IS NULL AND user_name = 'root'
```

**Canonical entities spanning multiple sources (after `icarus resolve`):**
```sql
SELECT b.id, b.entity_type, b.canonical_key, b.score
FROM bags b
WHERE b.id IN (
  SELECT bag_id FROM bag_atoms ba JOIN atoms a ON a.id = ba.atom_id
  GROUP BY bag_id HAVING COUNT(DISTINCT a.source_version_id) >= 2
)
ORDER BY b.score DESC
```

**Why two atoms merged (audit the score and per-field features):**
```sql
SELECT entity_type, atom_a, atom_b, score, features
FROM match_candidates ORDER BY score DESC LIMIT 20
```

**Cross-version additions:**
```python
from icarus.core.diff import IcarusDiffer

with IcarusDiffer("v1.db", "v2.db") as d:
    results = d.full_diff()
    for category, diff in results.items():
        if hasattr(diff, 'added') and diff.added:
            print(f"{category}: {len(diff.added)} added")
```
