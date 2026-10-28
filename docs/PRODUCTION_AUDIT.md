# ICARUS Production-Readiness Audit

Generated from a multi-agent adversarial audit of the framework: **62 agents** across 7 quality dimensions (correctness, robustness, input-security, API design, testing/CI, docs/packaging), each finding independently verified by a skeptical second agent before inclusion.

- **Raised:** 54  •  **Verified real:** 51  •  **Fixed:** 48 + the #93 daemon→binary edge (11 on `production-hardening`; 37 across `fix/parser-autodiscovery` #7 and `fix/audit-backlog` #8; the relationship edge on `feat/relationship-edges` #10)  •  **By design / documented:** 0  •  **Open backlog:** 2 open + #93 partially addressed

`fix/parser-autodiscovery` (#7) closed the registry/phantom-parser findings (#123, #183, #198, #210, #265). `fix/audit-backlog` (#8) closed the remaining differ/schema/STIX/security/resolver/docs findings. `feat/relationship-edges` (#10) landed the first real relationship edge (daemon→binary linking). Two findings remain fully deferred and #93 is now partially addressed — see "Remaining Open Backlog" at the bottom of this document.

Severity is the verifier's adjusted severity. `line` numbers reference the audited snapshot and may drift as the tree changes.

## High (5)

### ✅ fixed — Version record is created before the database exists, so the versions table is never populated on a fresh run
- **Where:** `icarus/core/pipeline.py:162`  ·  _core-correctness_
- **Problem:** run() calls self._create_version_record() at line 162 BEFORE the phase loop, but the output DB is created by the 'init' phase which runs inside that loop. _create_version_record() begins with `if not self.output.exists(): return` (line 107), so on any first-ever build the file does not yet exist an…
- **Fix:** Create the version record AFTER the init phase has created the DB and schema (e.g., call _create_version_record() at the end of phase 0, or have it initialize the schema first / drop the exists() guard). Also finalize the record even when resuming. Separately…

### ✅ fixed — A single malformed CloudTrail record aborts the entire database build
- **Where:** `icarus/parsers/cloud/cloudtrail.py:80`  ·  _robustness_
- **Problem:** In extract_entities the per-file try/except (lines 54-59) covers only read_text/json.loads. Everything after — `st = path.stat()` (65), `identity = record.get("userIdentity", {})` then `identity.get(...)` (80-81), and all the INSERTs (66-138) — runs with no exception guard. If any record has `userI…
- **Fix:** Wrap the per-record body in try/except that skips the bad record (and increments an error counter), guard `st = path.stat()` like the other parsers, and validate `isinstance(identity, dict)` before calling .get().

### ✅ fixed — Symlinks in the source tree are silently dereferenced: arbitrary file read outside source + hang on FIFO/devi…
- **Where:** `icarus/parsers/base.py:119`  ·  _input-security_
- **Problem:** Every parser walks with os.walk(..., followlinks defaults False) so symlinked DIRECTORIES are not traversed, but symlinked FILES are still returned in `filenames` and then blindly followed: parsers call `path.stat()` (linux.py:57, windows.py:56, sqlite_parser.py:39, json_parser.py:40, archive_parse…
- **Fix:** Before stat/hash/read, detect symlinks with `path.is_symlink()` / `os.lstat` and either skip them or record target metadata WITHOUT following (store is_symlink=1, symlink_target=os.readlink). Gate _safe_hash/_check_magic on `stat.S_ISREG(st.st_mode)` (use the…

### ✅ fixed — Generic JSON and CloudTrail parsers read entire untrusted files into memory with no size cap (OOM)
- **Where:** `icarus/parsers/generic/json_parser.py:51`  ·  _input-security_
- **Problem:** json_parser.py:51 does `json.loads(path.read_text(errors='replace'))` and cloudtrail.py does the same in BOTH extract (lines 55-57) and identify (line 30) with no size check at all. This is inconsistent with the rest of the codebase, which does cap reads (BaseParser._safe_hash skips >=50MB; the net…
- **Fix:** Guard with `path.stat().st_size` against a sane max (e.g. reuse a MAX_JSON_BYTES constant) before read_text; skip oversized files. For CloudTrail identify(), only sniff the first N KB / use a streaming check instead of full json.loads on every file. Cap the s…

### ✅ fixed — Archive parser enumerates ALL members before slicing [:50] — zip/tar-bomb memory & CPU exhaustion
- **Where:** `icarus/parsers/generic/archive_parser.py:94`  ·  _input-security_
- **Problem:** _list_archive (lines 87-97) calls `zf.namelist()[:50]` and `tf.getmembers()[:50]`. The `[:50]` slice happens AFTER the full member list is materialized. VERIFIED: getmembers() on a 100k-entry tar returns all 100,000 TarInfo objects before the slice — so the cap provides zero protection. A zip/tar w…
- **Fix:** Never materialize the full list: iterate lazily and stop at 50 — e.g. `for i, info in enumerate(zf.infolist()): if i>=50: break`, and for tar iterate with a bounded loop over `tf` / `tf.next()` capping iterations. Enforce a max member count and a max total-un…

## Medium (33)

### ✅ fixed — changed_entities() uses SQL `!=`, which is NULL-blind and silently misses all changes to/from NULL
- **Where:** `icarus/core/differ.py:145`  ·  _core-correctness_
- **Problem:** The comparison `WHERE n.[compare] != o.[compare]` (line 145) never evaluates TRUE when either side is NULL (in SQL, `NULL != x` is NULL, not TRUE). This is used by full_diff for files_changed on the sha256 column, and sha256 is legitimately NULL for files >50MB or unreadable (BaseParser._safe_hash …
- **Fix:** Use NULL-safe comparison, e.g. `WHERE n.[compare] IS NOT o.[compare]` (SQLite supports IS/IS NOT for NULL-safe equality), or `WHERE (n.[compare] IS NULL) != (o.[compare] IS NULL) OR n.[compare] != o.[compare]`.

### ✅ fixed — entitlement_diff diffs by autoincrement `id` across independent databases, masking real new entitlements
- **Where:** `icarus/core/differ.py:160`  ·  _core-correctness_
- **Problem:** entitlement_diff() computes new_entitlements = added_entities("entitlements", "id") (line 160). `id` is INTEGER PRIMARY KEY AUTOINCREMENT assigned independently in each DB, so id=N in the new DB has no relationship to id=N in the old DB. The LEFT JOIN ... WHERE o.id IS NULL therefore just returns r…
- **Fix:** Diff entitlements on a natural key, e.g. join on the owning binary's bundle_id plus entitlement key/value (as the new_dangerous subquery at lines 164-174 already does), not on the autoincrement id.

### ✅ fixed — structural_diff joins on non-unique columns, producing Cartesian-product false-positive 'moved/reassigned' ch…
- **Where:** `icarus/core/differ.py:199`  ·  _core-correctness_
- **Problem:** structural_diff joins binaries on executable_name (lines 197-199), sandbox_rules on operation+action (lines 216-219), and entitlements on key+value (lines 234-237) — none of which are unique. When duplicates exist the JOIN cross-products every old row against every new row and the `WHERE n.file_id …
- **Fix:** Join on a stable unique identity (e.g. binary's file path or bundle_id, entitlement's owning binary identity) or aggregate/deduplicate before comparing so a row is matched to exactly one counterpart.

### ✅ fixed — STIX SDOs omit required created/modified (and observed-data omits object_refs), producing spec-invalid bundles
- **Where:** `icarus/integrations/stix_export.py:84`  ·  _core-correctness_
- **Problem:** STIX 2.1 requires every SDO to carry `created` and `modified` timestamps. _daemon_to_sdo (line 60), _entitlement_to_sdo (line 73) and _observation_to_sdo (line 84) emit none of them. observed-data additionally requires `object_refs` (or the legacy `objects`), which _observation_to_sdo also omits. T…
- **Fix:** Add `created`/`modified` (e.g., derived from observed_time or the export time) to all SDOs, and give observed-data a valid `object_refs` pointing at the referenced SCO(s).

### ✅ fixed — diff_to_stix silently drops all 'changed' and 'structural' diff results
- **Where:** `icarus/integrations/stix_export.py:166`  ·  _core-correctness_
- **Problem:** diff_to_stix iterates full_diff() results but only emits objects for `.added` and `.removed` (lines 169-189). full_diff() also returns files_changed (populated `.changed`) and structural (populated `.structural`); both are never serialized. Separately, `item` here is a dict (DiffResult.added/remove…
- **Fix:** Iterate `.changed` and `.structural` as well and emit corresponding note/relationship objects; index into the item dict (e.g., item[diff_result.key_column]) instead of stringifying the whole dict.

### ✅ fixed — RAM-scaling PRAGMAs are applied only to the init connection that is immediately closed, so query/differ/resol…
- **Where:** `icarus/core/schema.py:543`  ·  _core-correctness_
- **Problem:** _apply_performance_pragmas() sets PRAGMA cache_size and mmap_size, but it is called (line 543) on the initialize_database connection that is closed a few lines later (line 561-562). cache_size and mmap_size are per-connection settings that are NOT persisted in the DB file (only journal_mode=WAL per…
- **Fix:** Apply the pragmas on every working connection (IcarusQuery/IcarusDiffer/EntityResolver __init__), and cap the target against available (not total) RAM with a sane ceiling.

### ✅ fixed — foreign_keys enforcement is never enabled on any write connection — schema's REFERENCES are silently unenforc…
- **Where:** `icarus/core/schema.py:76`  ·  _robustness_
- **Problem:** `PRAGMA foreign_keys = ON` is a per-connection, non-persistent setting, yet it only appears inside CORE_SCHEMA (which runs solely on fresh init, on a connection that is immediately closed) and in EntityResolver.__init__. Every parser (linux.py:42, windows.py:49, cloudtrail.py:44, all generic/*, bot…
- **Fix:** Enable `PRAGMA foreign_keys = ON` on every connection that writes — ideally via a single `open_db()` helper used by all parsers/pipeline/hygeia, or set it immediately after each `sqlite3.connect(...)`. Then decide whether existing orphan-tolerant code paths (…

### ✅ fixed — sqlite_parser leaks the source-DB connection on every unreadable/encrypted .db file
- **Where:** `icarus/parsers/generic/sqlite_parser.py:54`  ·  _robustness_
- **Problem:** `src_conn = sqlite3.connect(str(path))` (54) is closed at line 60, but the `SELECT ... FROM sqlite_master` at line 55 is what actually opens/validates the file and raises `sqlite3.DatabaseError` for a non-database, corrupt, or encrypted file. That exception is caught by `except sqlite3.DatabaseErro…
- **Fix:** Use `with sqlite3.connect(str(path)) as src_conn:` or wrap the open in try/finally so the source connection is always closed, including on DatabaseError.

### ✅ fixed — changed_entities uses `!=`, silently missing all NULL-to-value (and value-to-NULL) changes
- **Where:** `icarus/core/differ.py:145`  ·  _robustness_
- **Problem:** `WHERE n.[{compare}] != o.[{compare}]` follows SQL three-valued logic: when either side is NULL the predicate is NULL (not TRUE), so the row is never reported as changed. I confirmed a value that goes NULL->'abc' (or 'abc'->NULL) is missed by `!=` but caught by `IS NOT`. full_diff calls changed_ent…
- **Fix:** Use `IS NOT` (SQLite) / `IS DISTINCT FROM` semantics for the comparison so NULL transitions are detected.

### ✅ fixed — CloudTrail observation dedup ignores the unique eventID and collapses distinct events
- **Where:** `icarus/parsers/cloud/aws/cloudtrail.py:119`  ·  _parsers_
- **Problem:** The observation dedup key is (entity_table, entity_id, observed_at, event_type) = (daemons, daemon_id, eventTime, eventName) (cloudtrail.py:119-125). eventTime has one-second granularity and CloudTrail's unique per-event identifier (eventID) is ignored entirely. Two genuinely distinct events from t…
- **Fix:** Include record['eventID'] in the dedup key (and store it in properties), since it is unique per CloudTrail event.

### ✅ fixed — Conformance harness never validates event_types, and its schema check has a dead loop
- **Where:** `icarus/parsers/testing.py:94`  ·  _parsers_
- **Problem:** manifest.produces.event_types is part of the parser contract (exposed at manifest.py:52) but no test ever reads it. ParserTestHarness.test_schema_conformance puts 'observations' in the skip set (testing.py:94) and only checks entity-table membership, so declared-vs-emitted event_type drift is invis…
- **Fix:** Add an event_types conformance test: collect DISTINCT observations.event_type produced on the fixture and assert it is a subset of manifest.produces.event_types. Remove or repair the dead first loop.

### ◧ partially fixed — extract_relationships was a no-op in most parsers; relationship-backed view was always empty
- **Where:** `icarus/parsers/linux.py:111`  ·  _parsers_
- **Status (PR #10):** The daemon→binary edge is implemented — `base.py` gained a shared `link_daemons_to_binaries()`, `linux.py` now parses `ExecStart=` to populate `daemons.program` and links to the matching binary, and `macos.py` was refactored onto the same helper. The sandbox-escape-surface view is no longer always empty. Remaining: binaries↔entitlements and other relationship types, and whether the genuinely relationship-free parsers should drop the phase rather than return a hardcoded `{"linked": 0}`.
- **Problem:** BaseParser.extract_relationships documents linking daemons->binaries, binaries->entitlements, etc. (base.py:62-72), and the pipeline always runs a dedicated 'relationships' phase (core/pipeline.py:224-227). But it returns {'linked': 0} with no work in cloudtrail (cloud/aws/cloudtrail.py:147), all f…
- **Fix:** Implement linking for parsers that emit multiple entity types (e.g., match a linux daemon's ExecStart path to a binaries.file_id and set daemons.binary_id), or drop the phase for parsers that legitimately produce no relationships instead of returning a hardco…

### ✅ fixed — Generic SQLite parser opens untrusted DBs read-write (mutates source, creates -wal/-shm, may run recovery) an…
- **Where:** `icarus/parsers/generic/sqlite_parser.py:54`  ·  _input-security_
- **Problem:** Line 54 does `src_conn = sqlite3.connect(str(path))` on an untrusted source database in default READ-WRITE mode. VERIFIED: opening a WAL-mode source DB creates `-wal` and `-shm` sidecar files in the SOURCE tree, and a hot journal would trigger rollback/recovery — i.e. merely cataloging hostile inpu…
- **Fix:** Open read-only and non-mutating: `sqlite3.connect(f'file:{path}?mode=ro&immutable=1', uri=True)` (immutable prevents -wal/-shm creation and recovery). Wrap src_conn in try/finally or a `with closing(...)` so it always closes, including on DatabaseError. Use a…

### ✅ fixed — DeployScripts parser uses DOTALL regexes with lazy quantifiers on attacker-controlled scripts (quadratic back…
- **Where:** `icarus/parsers/network/deploy_scripts.py:46`  ·  _input-security_
- **Problem:** SSH_CONNECT_PATTERN (lines 46-51, `re.S` with two optional `.*?username...` / `.*?password...` groups), EXEC_CMD_PATTERN (65-67, `re.S` `(.+?)`), and HELPER_CMD_PATTERN (70-72, `re.S` `(.+?)`) are all DOTALL, so each lazy quantifier scans forward across newlines to end-of-file whenever the closing …
- **Fix:** Drop `re.S` where whole-line matching suffices, and bound the spans, e.g. `([^'\"]{0,500})` / `(.{0,500}?)`, so a missing terminator can't scan to EOF. Consider the `regex` module with a per-call timeout, and pre-cap the analyzed text length.

### ◻️ open — macOS/Apple ontology reused with wrong semantics by cross-platform parsers
- **Where:** `icarus/parsers/windows.py:21`  ·  _api-design_
- **Problem:** The 8-table schema is Mach-O/launchd/IOKit-shaped: binaries has bundle_id/team_id/linked_dylibs/has_pie/min_os_version/sdk_version/code_sign_flags (schema.py:103-123), daemons has plist_path/mach_services/sandbox_profile/keep_alive (schema.py:125-144), plus kexts/frameworks/entitlements/sandbox_*. …
- **Fix:** Either (a) rename the ontology to source-neutral concepts (e.g. binaries.linked_libs, services table with a service_path + platform discriminator, an identities table for cloud principals), or (b) add a mandatory 'kind'/'platform' discriminator column per ent…

### ✅ fixed — Atom/Bag/EventLog resolver subsystem is fully built but never wired into the pipeline (dead code)
- **Where:** `icarus/core/pipeline.py:220`  ·  _api-design_
- **Problem:** create_default_pipeline (pipeline.py:202-243) only registers phases init -> ingest -> relationships -> verify -> sanitize. Nothing ever calls EntityResolver (resolver.py:93) or its ingest_atom/create_bag/merge_bags/split_bag/resolve API, so the atoms, bags, bag_atoms, resolution_event_log tables pl…
- **Fix:** Either wire a 'resolve' phase into create_default_pipeline (ingest atoms during extract, run EntityResolver.resolve per entity_type after ingest), or, if resolution is intentionally deferred, move resolver.py + the atom/bag tables behind an explicitly-experim…

### ✅ fixed — resolver.resolve() advertises threshold + FTS blocking it never uses; docstring overstates behavior
- **Where:** `icarus/core/resolver.py:210`  ·  _api-design_
- **Problem:** resolve(entity_type, blocking_keys, threshold=0.8) accepts a threshold parameter that is never referenced in the body (resolver.py:210-246). Its docstring (line 213) claims 'Run full resolution: block -> score -> cluster -> merge', but the implementation does naive exact-key grouping — lowercase/st…
- **Fix:** Make resolve() actually use BlockingIndex.candidates_for for candidate generation and apply threshold as a score cutoff before create_bag/merge_bags; or, if exact blocking is the intended MVP, drop the threshold parameter and the BlockingIndex class from the …
- **Update (resolver-wiring increment):** the deferred "real" pipeline now exists — `EntityResolver.resolve_scored()` runs the actual block -> score -> cluster -> merge over atoms fed by `icarus.core.atomize`, every candidate is auditable via `match_candidates`/`bags.score`, and it is wired to users via `icarus resolve` (and optionally `icarus build --resolve`).

### ✅ fixed — No curated public API surface; examples document a registration recipe that does not exist
- **Where:** `icarus/__init__.py:3`  ·  _api-design_
- **Problem:** For a library others build on, the top-level package exports only __version__ (icarus/__init__.py:1-4) — no __all__ and no re-export of Pipeline, create_default_pipeline, IcarusQuery, BaseParser, or initialize_database. icarus/core/__init__.py's docstring says 'core — pipeline, schema, query, diffe…
- **Fix:** Define __all__ in icarus/__init__.py and re-export the intended public classes/functions; either make icarus.core re-export what its docstring promises or fix the docstring; and correct examples/custom_parser.py to show the real registration path (add to _ALL…

### ✅ fixed — EntityResolver.resolve() — the core resolution pipeline — has zero test coverage
- **Where:** `icarus/core/resolver.py:210`  ·  _testing-ci_
- **Problem:** resolve() (resolver.py:210-246) is the flagship block->cluster->merge orchestration method, yet `grep '.resolve(' tests/` returns nothing. Every branch is untested: the early `if not unresolved: return {'merges':0,...}` return (line 215-216), the blocking-key clustering loop (218-233), and the `len…
- **Fix:** Add tests that ingest several atoms with overlapping/distinct blocking-key values into a seeded resolver DB, call resolve(entity_type, blocking_keys), and assert the returned {'merges','atoms_resolved'} counts AND the resulting bag membership (e.g. two atoms …

### ✅ fixed — HYGEIA built-in PII fallback is structurally guaranteed untested; same tests cover different code by environm…
- **Where:** `icarus/integrations/hygeia.py:46`  ·  _testing-ci_
- **Problem:** sanitize_output() and verify_clean() branch on `_HAS_HYGEIA_PACKAGE` (hygeia.py:40, 99). The built-in fallback bodies (sanitize 46-89, verify 107-139) — the regex PII redaction/detection that is the pipeline's last-line privacy safety net — only run when the `hygeia` package is absent. But pyprojec…
- **Fix:** Parametrize the hygeia tests over both modes: monkeypatch `icarus.integrations.hygeia._HAS_HYGEIA_PACKAGE = False` (and its imported symbols) to force the fallback, then assert redaction of known-PII rows (email, /Users/x, C:\Users\x, SSN) and that verify_cle…

### ✅ fixed — Golden-output gate compares only row COUNTS, ignoring content and 3 of the golden file's own fields
- **Where:** `icarus/parsers/testing.py:60`  ·  _testing-ci_
- **Problem:** test_golden_output (testing.py:44-68) loads the golden file but reads only `golden['entity_counts']` (line 60) and asserts `actual_counts == expected` (line 61). The golden files carry `zero_pii`, `has_relationships`, and (for cloudtrail) `observation_count` (tests/golden/cloud_aws_cloudtrail.json)…
- **Fix:** Extend golden files with a deterministic content fingerprint (e.g. a sorted list of key columns per table, or a sha256 over `SELECT <stable cols> ORDER BY <key>`) and have test_golden_output compare that in addition to counts. Also assert the golden's declare…

### ✅ fixed — Production parsers (linux + all generic/*) have golden files wired but no harness test ever runs them; linux …
- **Where:** `tests/test_core.py:158`  ·  _testing-ci_
- **Problem:** ParserTestHarness is only instantiated for windows (test_harness.py:18) and cloudtrail (test_cloudtrail.py:104), so the four production quality gates (golden/idempotency/schema-conformance/zero-PII, run together via run_all) execute for just 2 of ~9 parsers. linux.yaml and all six generic/*.yaml ma…
- **Fix:** Add harness tests mirroring test_cloudtrail_harness_all_pass for the linux parser and each generic parser: load the manifest, build ParserTestHarness(parser, manifest, fixtures_dir), call run_all(), assert every HarnessResult.passed. This activates the alread…

### ✅ fixed — Security gate (bandit) skips B608 SQL-injection — the exact bug class this f-string-heavy SQL codebase is pro…
- **Where:** `pyproject.toml:69`  ·  _testing-ci_
- **Problem:** pyproject.toml:69 sets bandit `skips = ["B101","B110","B112","B404","B603","B607","B608"]`. B608 (hardcoded_sql_expressions / SQL injection) is disabled, yet this codebase builds SQL via f-strings pervasively: differ.py interpolates `[{table}]`/`[{key}]`, hygeia.py:53/69/113 does `f"SELECT rowid, {…
- **Fix:** Remove B608 (and ideally B101/B110/B112) from the skip list; where the flagged SQL is genuinely safe (table/column names validated via validate_table/validate_column or sourced from sqlite_master), add targeted `# nosec B608` with justification instead of a b…

### ◻️ open — mypy config disables body-checking and 5 core error codes, making the 'type' gate a near no-op
- **Where:** `pyproject.toml:65`  ·  _testing-ci_
- **Problem:** pyproject.toml sets `check_untyped_defs = false` (line 63) and `disallow_untyped_defs = false` (62), so mypy skips the bodies of the many untyped functions in this codebase entirely. On top of that, `disable_error_code = ["operator","attr-defined","var-annotated","index","assignment"]` (line 65) si…
- **Fix:** Turn on `check_untyped_defs = true`, drop the `disable_error_code` list (or pare it to a documented minimum), fix the resulting errors (annotate params, correct `confidence: Optional[float] = None`), and move toward `disallow_untyped_defs = true` incrementall…

### ✅ fixed — Differ: removed/changed positive paths and 2 of 3 structural-diff branches are untested
- **Where:** `icarus/core/differ.py:213`  ·  _testing-ci_
- **Problem:** structural_diff() emits three change types but only binary_file_moved is asserted (test_core.py:335). The sandbox_rule_reassigned branch (differ.py:213-229) and entitlement_reassigned branch (231-247) have no test. Separately, removed_entities() (118-134) and changed_entities() (136-154) are never …
- **Fix:** Add two-DB tests where: (a) a file exists only in old (assert removed_entities/full_diff files_removed == 1 with the right path); (b) same path, different sha256 (assert changed_entities returns old_value/new_value); (c) a sandbox_rule moves profile_id and (d…

### ✅ fixed — STIX diff export drops all structural changes and its test asserts only the envelope
- **Where:** `icarus/integrations/stix_export.py:166`  ·  _testing-ci_
- **Problem:** diff_to_stix (stix_export.py:156-193) iterates full_diff() results reading only `getattr(diff_result,'added',[])` and `getattr(diff_result,'removed',[])` (lines 169, 180) — it never references `.structural`, so the structural DiffResult (empty added/removed, populated structural) contributes zero o…
- **Fix:** Strengthen the test to assert the diff bundle contains a note object referencing the newly added daemon (non-empty objects, matching x_icarus_diff_category/x_icarus_diff_table), and add a case with a structural change asserting it appears. Then fix diff_to_st…

### ✅ fixed — Checkpoint DB is never cleared after success, so re-running build on the same output is a silent no-op
- **Where:** `icarus/core/pipeline.py:159`  ·  _core-correctness_
- **Problem:** The checkpoint DB (.{stem}_checkpoint.db) is written on every phase but never deleted. After a successful run all phases are marked 'complete'. On a subsequent `icarus build` to the same output with the default resume=True (no --fresh), get_last_checkpoint() returns the last index, start = last+1 >…
- **Fix:** Delete the checkpoint DB on successful completion (and validate stored phase_name matches self.phases[i].name before honoring a checkpoint on resume).

### ✅ fixed — Whole-file read_text of JSON with no size cap — OOM on large JSON / CloudTrail files
- **Where:** `icarus/parsers/generic/json_parser.py:51`  ·  _robustness_
- **Problem:** `json.loads(path.read_text(errors="replace"))` reads the entire file into memory (then json.loads roughly doubles it) with no size guard; cloudtrail.py does the same at lines 30 and 56, and in identify() reads every .json file in the tree fully. The base module defines MAX_HASH_FILE_SIZE=50MB and _…
- **Fix:** Skip or stream files above a sane cap before read_text (mirror the network parsers' size check), or parse incrementally (e.g. ijson) for large inputs.

### ✅ fixed — Diff Markdown report written with platform default encoding — crashes on Windows with non-ASCII paths
- **Where:** `icarus/__main__.py:66`  ·  _robustness_
- **Problem:** `Path(args.output).write_text(report)` passes no encoding, so it uses locale.getpreferredencoding — cp1252 on the documented Windows target. The report embeds filenames/paths/daemon labels verbatim from the scanned tree (differ.to_markdown emits `item.get(key_column)` etc.), which can contain any U…
- **Fix:** Pass `encoding="utf-8"` to write_text (here and any other text-report writers).

### ✅ fixed — Registry silently swallows ALL parser import failures (and lists 4 non-existent modules)
- **Where:** `icarus/parsers/__init__.py:47`  ·  _parsers_
- **Problem:** _ALL_PARSERS (lines 15-17, 27) references four modules that do not exist on disk — obsidian_parser, source_parser, node_parser, javascript_parser (no .py and no .yaml for any of them). The registration loop wraps the whole import+register in `except ImportError: pass` (line 47). This is not just de…
- **Fix:** Delete the four dead entries. Narrow the exception to ModuleNotFoundError for genuinely-optional local parsers and log a warning with the module name; let unexpected ImportError/AttributeError propagate (or at minimum log them) instead of `pass`.

### ✅ fixed — CloudTrail manifest declares normalized event_types but stores raw AWS eventName
- **Where:** `icarus/parsers/cloud/aws/cloudtrail.py:134`  ·  _parsers_
- **Problem:** cloud/aws/cloudtrail.yaml:20 declares produces.event_types = [api_call, console_login, assume_role, console_signin]. extract_entities reads the raw AWS field `event_name = record.get('eventName','')` (cloudtrail.py:103) and writes it verbatim as observations.event_type (cloudtrail.py:134). So the c…
- **Fix:** Either map eventName to the declared normalized taxonomy before insert (e.g., ConsoleLogin->console_login, Assume*->assume_role, else api_call), or change the manifest to declare that event_type carries the raw AWS eventName. Update the test to match whicheve…

### ✅ fixed — Ingest stats count rows visited, not entities inserted — non-idempotent and inflate versions.entity_count
- **Where:** `icarus/parsers/cloud/aws/cloudtrail.py:93`  ·  _parsers_
- **Problem:** Parsers increment their stats counters unconditionally even though rows are deduplicated by UNIQUE constraints / INSERT OR IGNORE / SELECT-before-INSERT. cloudtrail.py:93 does stats['daemons'] += 1 once per CloudTrail record, but daemons.label (the ARN) is UNIQUE, so on the shipped 6-record/4-ARN f…
- **Fix:** Increment stats only when an insert actually happened — check cursor.rowcount after INSERT OR IGNORE, or increment inside the existing `if not existing` dedup branches.

### ✅ fixed — Parser registry silently swallows ImportError, hiding broken and phantom parsers
- **Where:** `icarus/parsers/__init__.py:47`  ·  _api-design_
- **Problem:** The registration loop wraps each parser import in 'except ImportError: pass' (parsers/__init__.py:47) and each manifest load in 'except Exception: pass' (line 44), with no logging. Four entries in _ALL_PARSERS (obsidian_parser, source_parser, node_parser, javascript_parser at lines 15-17, 27-28) po…
- **Fix:** Log a warning (module + exception) on each swallowed ImportError/manifest error, and remove the phantom module entries from _ALL_PARSERS (or move optional parsers to a clearly-optional group). Consider distinguishing 'module intentionally absent' from 'module…

## Low (13)

### ✅ fixed — HYGEIA sanitize loads entire tables into memory via fetchall() — OOM on large databases
- **Where:** `icarus/integrations/hygeia.py:52`  ·  _robustness_
- **Problem:** The built-in sanitize_output does `conn.execute(f"SELECT rowid, {cols} FROM {table}").fetchall()` for every table, materializing all rows and all TEXT columns of that table in memory at once, then iterates. verify_clean (line 113) does the same. Sanitization runs as a mandatory pipeline phase over …
- **Fix:** Iterate the cursor directly (row-by-row) or page with LIMIT/OFFSET / rowid ranges instead of fetchall(), so memory stays bounded.

### ✅ fixed — Parser registry silently swallows all manifest-load failures, degrading auto-detection
- **Where:** `icarus/parsers/__init__.py:44`  ·  _robustness_
- **Problem:** During registry bootstrap, `load_manifest(_yaml_path)` is wrapped in `except Exception: pass`, discarding every error (YAML parse error, jsonschema ValidationError, or — since jsonschema is optional — the ImportError that validate_manifest_data raises when it is absent). A parser then registers wit…
- **Fix:** Do not swallow the error silently — at minimum log a warning naming the manifest and exception; catch specific expected exceptions rather than bare Exception, and surface manifest validation failures.

### ✅ fixed — privacy_stack anchors all project-level observations to file id 1 on fallback
- **Where:** `icarus/parsers/network/privacy_stack.py:330`  ·  _parsers_
- **Problem:** extract_entities looks up an anchor file row for /AGENTS.md or /HANDOFF.md and falls back to `anchor_id = project_row[0] if project_row else 1` (privacy_stack.py:330). Every ip_address, credential_found and endpoint observation (lines ~333-388) is then attached to that anchor. If neither doc is pre…
- **Fix:** When no anchor row is found, skip the project-level observation batch or create an explicit synthetic 'project' entity to anchor to, rather than defaulting entity_id to 1.

### ✅ fixed — HYGEIA interpolates table/column names taken from sqlite_master into f-string SQL without the validators used…
- **Where:** `icarus/integrations/hygeia.py:53`  ·  _input-security_
- **Problem:** The fallback sanitizer/verifier builds SQL by string-formatting identifiers pulled straight from the target DB's schema: `f"SELECT rowid, {', '.join(columns)} FROM {table}"` (line 53), `f"UPDATE {table} SET {col} = ? WHERE rowid = ?"` (lines 69,74), the verify SELECT (line 114), and `f"PRAGMA table…
- **Fix:** Reuse validate_table for table names and quote every identifier with double-quotes (escaping embedded quotes), or reject names not matching the identifier regex — mirroring differ.py/query.py.

### ✅ fixed — Differ opens the 'new' database read-write and ATTACHes the 'old' one, both potentially untrusted
- **Where:** `icarus/core/differ.py:95`  ·  _input-security_
- **Problem:** IcarusDiffer.__init__ does `sqlite3.connect(str(self.new_path))` in default read-write mode (line 92) and then `ATTACH DATABASE ? AS old_db` (line 95). The old/new paths come straight from the CLI (`icarus diff old new`, __main__.py:63) and may be ICARUS exports received from a third party (i.e. un…
- **Fix:** Open both databases immutable read-only via URI (`file:{path}?mode=ro&immutable=1`, uri=True) — connect the main one that way and ATTACH the other with the same `?mode=ro&immutable=1` URI — since diff never writes.

### ✅ fixed — Implicit-Optional type hints combined with a mypy config that disables the checks that catch them
- **Where:** `icarus/core/resolver.py:260`  ·  _api-design_
- **Problem:** Several annotations use implicit Optional: resolver.py:260 declares 'confidence: float = None' (default None violates the float hint) and pipeline.py:83 declares 'stats: dict = None'. Meanwhile pyproject.toml sets no_implicit_optional = false (line 64) and disable_error_code = ["operator", "attr-de…
- **Fix:** Change the implicit-Optional defaults to Optional[float]/Optional[dict], and re-enable no_implicit_optional plus the disabled error codes in pyproject (or justify each suppression narrowly with per-line ignores rather than a blanket disable).

### ✅ fixed — README claims '6 intelligence views' but the schema defines only 3
- **Where:** `README.md:308`  ·  _docs-packaging_
- **Problem:** README line 308 (Project Structure: 'query.py Query engine with 6 intelligence views') and line 358 (Changelog: 'query engine with 6 intelligence views') claim 6 views. The database defines exactly 3 views in schema.py VIEWS (lines 366-391): v_sandbox_escape_surface, v_kernel_attack_surface, v_test…
- **Fix:** Change '6 intelligence views' to '3 intelligence views' at README lines 308 and 358, or reword to '6 pre-built intelligence queries over 3 DB views' so the count matches schema.py.

### ✅ fixed — wiki Schema-Reference documents nonexistent 'versions' columns (uuid, created_at)
- **Where:** `wiki/Schema-Reference.md:92`  ·  _docs-packaging_
- **Problem:** The versions-table reference (wiki/Schema-Reference.md lines 90-95) lists columns 'uuid' (line 92) and 'created_at' (line 93). The actual schema (schema.py lines 219 and 223; schema/icarus_schema.sql lines 23 and 26) defines 'run_id' and 'started_at', and also a 'metadata' column that the doc omits…
- **Fix:** Rename uuid -> run_id and created_at -> started_at, and add the missing 'metadata' column, in the versions section of wiki/Schema-Reference.md.

### ✅ fixed — Typed package ships no py.typed marker (PEP 561)
- **Where:** `pyproject.toml:71`  ·  _docs-packaging_
- **Problem:** The package is fully type-hinted and ships a [tool.mypy] config (pyproject lines 58-65) with docs telling users to run 'mypy icarus/' (README line 256), yet there is no icarus/py.typed marker anywhere in the tree and no package-data entry to include one. Per PEP 561 an installed package without py.…
- **Fix:** Add an empty icarus/py.typed file and include it, e.g. add [tool.setuptools.package-data] with icarus = ["py.typed"] in pyproject.toml.

### ✅ fixed — Release metadata says '4 - Beta' while README calls v1.1.1 the stable/final release
- **Where:** `pyproject.toml:22`  ·  _docs-packaging_
- **Problem:** pyproject classifier 'Development Status :: 4 - Beta' (line 22, mirrored in egg-info/PKG-INFO line 10) contradicts the README Changelog which calls v1.1.1 the 'Final release' (line 354) and 'the first and current stable release' (line 356).
- **Fix:** Set the classifier to 'Development Status :: 5 - Production/Stable' to match the stated release status (or soften the README wording).

### ✅ fixed — Internal version/consistency incoherence: initialize_database docstring says v3, code stamps v4; docs disagre…
- **Where:** `icarus/core/schema.py:516`  ·  _api-design_
- **Problem:** initialize_database's docstring (schema.py:516) says it 'Handles fresh creation (v3) and migration from existing v2 databases', but SCHEMA_VERSION is 4 (line 67), the fresh path stamps schema_version '4' (line 547), and it also silently performs v3->v4 migration (lines 534-535) which the docstring …
- **Fix:** Update the initialize_database docstring to state fresh creation targets v4 and that v2->v3->v4 migration is applied automatically; reconcile the README to a single correct view count (3).

### ✅ fixed — schema.py initialize_database docstring says it creates v3, but it creates v4
- **Where:** `icarus/core/schema.py:516`  ·  _docs-packaging_
- **Problem:** The initialize_database docstring (line 516) reads 'Handles fresh creation (v3) and migration from existing v2 databases.' In reality SCHEMA_VERSION = 4 (line 67), fresh creation stamps schema_version=4 (lines 547-548), and the function migrates from BOTH v2 (lines 531-533, chaining v2->v3->v4) and…
- **Fix:** Update the docstring to: 'Handles fresh creation (v4) and migration from existing v2 and v3 databases.'

### ✅ fixed — parsers/__init__ registers four nonexistent parser modules
- **Where:** `icarus/parsers/__init__.py:15`  ·  _docs-packaging_
- **Problem:** _ALL_PARSERS references icarus.parsers.obsidian_parser (line 15), source_parser (line 16), node_parser (line 17), and javascript_parser (line 27); none of these .py modules or their .yaml manifests exist in the source tree. Each import fails and is silently swallowed by 'except ImportError: pass' (…
- **Fix:** Delete the four phantom tuples from _ALL_PARSERS (or add the missing modules if they were intended to ship).

---

## Historical backlog and current follow-up

This section records the original audit backlog. It is not a current completeness
claim. The October 2026 production pass also found source-identity, mutation-history,
build-ownership, and distribution-boundary problems; see issues #102, #103 and #106.
The source-neutral ontology design is tracked in #105.

### ◧ partially fixed — extract_relationships was a no-op in most parsers; relationship-backed view was always empty
- **Where:** `icarus/parsers/linux.py:111`  ·  _parsers_
- **Status:** Daemon-to-binary links exist for Linux/macOS. macOS entitlements
  already reference their owning binary during extraction; that edge is not an
  outstanding no-op. Sandbox profiles are cataloged, but SBPL rule parsing and
  broader relationship semantics require explicit parser support and validation.

### ◻️ open — macOS/Apple ontology reused with wrong semantics by cross-platform parsers
- **Where:** `icarus/parsers/windows.py:21`  ·  _api-design_
- **Current follow-up:** Issue #105 requires a source-neutral model and compatibility
  plan. Schema v6 already exists; a future shape change needs a new version.

### ✅ fixed — mypy skipped function bodies and disabled broad error classes
- **Where:** `pyproject.toml:65`  ·  _testing-ci_
- **Current status:** `check_untyped_defs = true`, no blanket disabled error codes,
  and explicit collection annotations in the public implementation. Local private
  plugins are outside the public distribution/type-check gate. Requiring annotations
  on every public function remains a separate API-quality increment.

