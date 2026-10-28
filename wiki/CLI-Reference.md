# CLI reference

Run `icarus COMMAND --help` for the installed command's options.

| Command | Purpose |
| --- | --- |
| `build` | Extract and sanitize a source snapshot. |
| `gui` | Browse an existing database locally. |
| `query` | Run bounded read-only queries. |
| `exec` | Execute and commit an intentional write. |
| `diff` | Compare frozen database snapshots. |
| `parser` | List parsers, validate manifests, and run self-tests. |
| `resolve` | Experimentally resolve entities across source databases. |

## `icarus build`

```bash
icarus build --source PATH --output PATH [--parser NAME] [--fresh] [--skip-hygeia] [--resolve]
```

| Option | Behavior |
| --- | --- |
| `--source, -s` | Source directory; required. |
| `--output, -o` | Output database; required. |
| `--parser, -p` | Installed parser name; otherwise use bounded auto-detection. |
| `--fresh` | Build into a sibling temporary database and replace the destination only after successful completion. |
| `--skip-hygeia` | Explicitly create raw output, recorded as skipped sanitization. |
| `--resolve` | Run experimental scored resolution within this build, after verification and before sanitization. |

Auto-detection shares a sample bounded to 5,000 entries and 4 MiB of source bytes.
If a budget is exhausted, select `--parser` explicitly. A normal build refuses
an existing output unless its checkpoint proves a compatible interrupted run;
it does not append a new source to an existing completed database.

```bash
icarus build -s /snapshots/linux -o linux.db --parser linux
icarus build -s /snapshots/cloudtrail -o trail.db --parser cloud/aws/cloudtrail
```

Keep sources immutable during a run and resume. See
[ingest recovery](../docs/INGEST_RECOVERY.md) for leases, checkpoint ownership,
legacy compatibility, and the limitations of phase-level replay.

## `icarus gui`

```bash
icarus gui DATABASE [--port PORT] [--no-browser] [--allow-unverified]
```

| Option | Behavior |
| --- | --- |
| `DATABASE` | Existing ICARUS database. |
| `--port` | Loopback port, 0–65535; default 0 selects an available port. |
| `--no-browser` | Print the session URL without opening a browser. |
| `--allow-unverified` | Inspect failed or unmarked output with a persistent unsafe-data warning. |

The explorer binds to `127.0.0.1`, uses a session capability, and exposes fixed
read-only queries. Keep the printed URL private. Stop with Ctrl+C. Verified and
explicitly skipped outputs are admitted by default; skipped output retains its
warning. See [local explorer](../docs/ONTOLOGY_EXPLORER.md) for resource and
security boundaries. This is a single-user local tool.

## `icarus query`

```bash
icarus query DATABASE (--sql QUERY | --search TERMS | --stats) [--table TABLE] [--allow-unverified]
```

| Option | Behavior |
| --- | --- |
| `DATABASE` | Existing ICARUS database. |
| `--sql` | Read-only SQL statement. |
| `--search` | FTS5 search expression. |
| `--stats` | Table row counts. |
| `--table` | FTS search table; requires `--search`, defaults to `files`. |
| `--allow-unverified` | Admit failed or unmarked data that may contain private information. |

Choose exactly one query mode. The connection is read-only, enables
`query_only`, and rejects `ATTACH`/`DETACH`. Results retain at most 100 rows
plus a truncation notice. Writes are refused (exit 2); failed or unmarked
sanitization is refused without an override (exit 3). Verified and explicitly
skipped artifacts are admitted by default.

```bash
icarus query intel.db --stats
icarus query intel.db --search "nginx" --table daemons
icarus query intel.db --sql "SELECT path, size FROM files ORDER BY size DESC LIMIT 20"
```

See [query reference](Query-Reference.md) for FTS tables and interpretation.

## `icarus exec`

```bash
icarus exec DATABASE --sql "STATEMENT"
```

This is an explicit read-write operation that commits. Guarded mutations revoke
existing sanitization evidence in the same transaction. The database must be
sanitized and verified again before it can be treated as verified output.
Transaction-control SQL and attachment bypasses are refused.

```bash
icarus exec working-copy.db --sql "UPDATE files SET marking = 'SENSITIVE' WHERE id = 1"
```

See [public writes](../docs/PUBLIC_WRITES.md) for transaction boundaries and
the exclusions for direct raw SQLite access.

## `icarus diff`

```bash
icarus diff OLD NEW [--output PATH] [--stix PATH] [--allow-unverified]
```

| Option | Behavior |
| --- | --- |
| `OLD`, `NEW` | Frozen database snapshots to compare. |
| `--output, -o` | Write a Markdown report; otherwise print it. |
| `--stix` | Also write a STIX 2.1 diff bundle. |
| `--allow-unverified` | Permit unsafe STIX export from failed or unmarked inputs. |

The output options are additive. The Markdown comparison and guarded STIX export
have different admission behavior; the override applies to STIX export.
Immutable reads require database files that include all committed state: finish
the writer and checkpoint WAL before taking the snapshots.

```bash
icarus diff before.db after.db -o changes.md --stix changes.json
```

## `icarus parser`

```bash
icarus parser list
icarus parser validate PATH_TO_MANIFEST
icarus parser test PARSER_NAME
```

`list` reports the installed registry, including tier and specificity.
`validate` checks a YAML manifest against the manifest schema.
`test` runs golden-output, idempotency, schema-conformance, and zero-PII gates
against the parser's declared fixtures. Built-in self-test fixtures ship in the
wheel, so `icarus parser test windows` does not require a source checkout.

Parser tiers and fixture results are bounded evidence, not a guarantee for every
input. See [parser ecosystem](Parser-Ecosystem.md).

## `icarus resolve`

**Experimental.** Atomize source databases, score candidate pairs, and group
matching atoms into canonical bags.

```bash
icarus resolve --out PATH [--entity-type TYPE] [--threshold FLOAT] [--atomize-only] [--allow-unverified] SOURCE [SOURCE ...]
```

| Option | Behavior |
| --- | --- |
| `--out, -o` | New output database; required. Existing output is refused. |
| `--entity-type` | `binaries`, `daemons`, `frameworks`, `kexts`, `files`, or `all` (default). |
| `--threshold` | Match-edge score cutoff in [0, 1]; default 0.85. |
| `--atomize-only` | Skip scoring and grouping; output sanitization remains mandatory. |
| `--allow-unverified` | Recover failed/unmarked inputs; output sanitization remains mandatory. |
| `SOURCE` | One or more distinct, frozen ICARUS databases. |

Verified and explicitly skipped source artifacts are admitted by default. Source
aliases, duplicate inputs, and nonempty source WALs are refused. Resolution holds
an output lease, builds into a temporary sibling file, finalizes source version
records, runs HYGEIA and final verification, then publishes the output. Failure
publishes no partial output. Input trust markers are not output evidence.

```bash
icarus resolve --out resolved.db host_a.db host_b.db
```

Candidate scores, including pairs below the threshold, are stored in
`match_candidates`. Group scores and membership remain inspectable in `bags`
and `bag_atoms`. These are model decisions, not established real-world identity.
See [schema reference](Schema-Reference.md) and
[resolver calibration](../docs/RESOLVER_CALIBRATION.md).
