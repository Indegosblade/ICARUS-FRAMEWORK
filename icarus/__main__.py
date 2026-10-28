"""ICARUS CLI — python -m icarus"""

import argparse
import sys
from pathlib import Path


def _cleanup_build_temp(temp: Path, checkpoint: Path) -> None:
    """Remove a fresh-build temp database plus its side/checkpoint files."""
    for path in (temp, checkpoint):
        base = str(path)
        for suffix in ("", "-wal", "-shm"):
            Path(base + suffix).unlink(missing_ok=True)


def cmd_build(args):
    from icarus.core.build_lock import output_lease
    from icarus.core.detection import DetectionBudgetExceeded
    from icarus.parsers import detect_parser

    source = Path(args.source)
    if not source.exists():
        print(f"ERROR: Source path does not exist: {source}", file=sys.stderr)
        sys.exit(1)

    parser_name = args.parser
    if parser_name is None:
        try:
            parser_name = detect_parser(source)
        except DetectionBudgetExceeded as exc:
            print(f"ERROR: {exc}", file=sys.stderr)
            sys.exit(1)
        if parser_name is None:
            print(
                "ERROR: Could not auto-detect source type. Specify --parser",
                file=sys.stderr,
            )
            sys.exit(1)
        print(f"[ICARUS] Auto-detected parser: {parser_name}")

    output = Path(args.output)
    with output_lease(output):
        return _run_build(args, source, output, parser_name)


def _run_build(args, source: Path, output: Path, parser_name: str):
    """Run while the final output's process lease is held, including replacement."""
    import os
    import uuid

    from icarus.core.pipeline import create_default_pipeline
    from icarus.core.schema import open_db

    if args.fresh:
        # Atomic clean rebuild: build into a sibling temp DB in the same
        # directory, run ALL phases + verification gates against it, then
        # os.replace() onto the destination only on full success. On ANY
        # failure the destination is left byte-for-byte untouched and the temp
        # (with its side/checkpoint files) is removed. Never reuses/unions the
        # existing output.
        temp = output.parent / f"{output.name}.{uuid.uuid4().hex}.tmp"
        pipeline = create_default_pipeline(
            source=source,
            output=temp,
            parser_name=parser_name,
            skip_hygeia=args.skip_hygeia,
            resolve=args.resolve,
        )
        try:
            pipeline.run(resume=False)
            # Fold any WAL back into the main file so the single file we move is
            # self-contained, then drop any residual side files before replace.
            conn = open_db(temp)
            try:
                conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            finally:
                conn.close()
            for suffix in ("-wal", "-shm"):
                Path(str(temp) + suffix).unlink(missing_ok=True)
            os.replace(str(temp), str(output))
        except BaseException:
            _cleanup_build_temp(temp, pipeline.checkpoint_db)
            raise
        else:
            _cleanup_build_temp(temp, pipeline.checkpoint_db)
        print(f"[ICARUS] Wrote {output}")
        return

    # Default (resume) path. Refuse an existing output unless a valid,
    # fingerprint-matching in-progress checkpoint proves this is the same build
    # crashing and resuming. A fingerprint MISMATCH raises loudly (issue #45);
    # a present output with no such checkpoint is refused (issue #36).
    pipeline = create_default_pipeline(
        source=source,
        output=output,
        parser_name=parser_name,
        skip_hygeia=args.skip_hygeia,
        resolve=args.resolve,
    )
    if output.exists() and not pipeline.has_resumable_checkpoint():
        from icarus.core.pipeline import OutputExistsError

        raise OutputExistsError(
            f"Output database already exists: {output}. Refusing to reuse or "
            "union into it. Pass --fresh for a clean atomic rebuild, or "
            "remove/redirect the output."
        )
    pipeline.run(resume=True)


def cmd_query(args):
    import sqlite3

    from icarus.core.query import IcarusQuery
    from icarus.integrations.hygeia import (
        sanitization_allows_default_consumer,
        sanitization_status,
    )

    # Refuse every unverified posture by default.  A verified database has
    # current, structured post-gate evidence; --skip-hygeia is an explicit,
    # documented choice.  Failed and unmarked databases require an equally
    # explicit unsafe override.
    if (
        Path(args.database).exists()
        and not getattr(args, "allow_unverified", False)
        and not sanitization_allows_default_consumer(sanitization_status(args.database))
    ):
        print(
            "ERROR: this database is not sanitization-verified — it is not safe to "
            "query or share. Rebuild it (icarus build --fresh), or pass "
            "--allow-unverified to inspect it anyway.",
            file=sys.stderr,
        )
        sys.exit(3)

    # The default query connection is READ-ONLY (mode=ro + PRAGMA query_only).
    # Any attempt to mutate the database through --sql surfaces here as an
    # OperationalError whose message names the read-only barrier; report it as
    # a clear, actionable error instead of a traceback, and steer the user to
    # the explicit `icarus exec` command.
    try:
        with IcarusQuery(args.database) as q:
            if args.search is not None:
                result = q.search(args.search, table=args.table or "files")
            elif args.sql is not None:
                result = q.execute(args.sql)
            else:
                stats = q.stats()
                for table, count in stats.items():
                    print(f"{table}: {count:,}")
                return
            print(result.to_markdown())
    except sqlite3.OperationalError as e:
        msg = str(e).lower()
        if any(tok in msg for tok in ("readonly", "read-only", "query_only")):
            print(
                "ERROR: query is read-only; use `icarus exec <database> --sql \"...\"` "
                "to modify a database",
                file=sys.stderr,
            )
            sys.exit(2)
        # Other operational errors (e.g. malformed SQL, no such table) — report
        # cleanly rather than dumping a traceback.
        print(f"ERROR: query failed: {e}", file=sys.stderr)
        sys.exit(1)
    except sqlite3.DatabaseError as e:
        # A corrupt / unreadable / non-SQLite file. Report cleanly, no traceback.
        print(
            f"ERROR: could not read database {args.database!r}: {e} "
            "(is it a valid ICARUS database?)",
            file=sys.stderr,
        )
        sys.exit(1)


def cmd_exec(args):
    """Explicit mutation path — opens the database READ-WRITE and commits.

    Kept deliberately separate from `query` (which is read-only) so that any
    write to an ICARUS database is an unmistakable, opted-into action.
    """
    import sqlite3

    from icarus.core.query import IcarusQuery
    from icarus.integrations.hygeia import invalidate_sanitization

    print(
        f"NOTICE: opening {args.database!r} READ-WRITE — this will MODIFY the database.",
        file=sys.stderr,
    )
    try:
        with IcarusQuery(args.database, writable=True) as q:
            # Start before the user statement so DDL as well as DML and trust
            # invalidation commit or roll back together.
            q.conn.execute("BEGIN IMMEDIATE")
            cursor = q.conn.execute(args.sql)
            affected = cursor.rowcount
            invalidate_sanitization(q.conn)
            q.commit()
    except sqlite3.DatabaseError as e:
        print(f"ERROR: exec failed: {e}", file=sys.stderr)
        sys.exit(1)
    if affected < 0:
        print("Statement executed (rows affected: not reported for this statement).")
    else:
        print(f"Statement executed. Rows affected: {affected}.")


def cmd_diff(args):
    if args.stix:
        from icarus.integrations.stix_export import SanitizationTrustError, diff_to_stix

        try:
            bundle = diff_to_stix(
                Path(args.old),
                Path(args.new),
                Path(args.stix),
                allow_unverified=getattr(args, "allow_unverified", False),
            )
        except SanitizationTrustError as e:
            print(f"ERROR: {e}", file=sys.stderr)
            sys.exit(3)
        print(f"STIX bundle written to {args.stix} ({len(bundle['objects'])} objects)")

    from icarus.core.differ import IcarusDiffer
    with IcarusDiffer(args.old, args.new) as d:
        report = d.generate_report()
        if getattr(args, "output", None):
            Path(args.output).write_text(report, encoding="utf-8")
            print(f"Report written to {args.output}")
        else:
            print(report)


def cmd_parser(args):
    if args.parser_command == "validate":
        from icarus.parsers.manifest import validate_manifest
        manifest_path = Path(args.path)
        if not manifest_path.exists():
            print(f"ERROR: Manifest not found: {manifest_path}", file=sys.stderr)
            sys.exit(1)
        try:
            validate_manifest(manifest_path)
            print(f"PASS: {manifest_path}")
        except Exception as e:
            print(f"FAIL: {manifest_path}\n  {e}", file=sys.stderr)
            sys.exit(1)
    elif args.parser_command == "test":
        from icarus.parsers import get_parser, get_registry
        from icarus.parsers.testing import ParserTestHarness, resolve_test_resource
        parser_inst = get_parser(args.parser_name)
        manifest = get_registry().get_manifest(args.parser_name)
        if manifest is None:
            print(f"ERROR: No manifest for parser '{args.parser_name}'", file=sys.stderr)
            sys.exit(1)
        fixtures_dir = manifest.tests.get("fixtures_dir") if manifest.tests else None
        if not fixtures_dir:
            print("ERROR: No fixtures_dir in manifest", file=sys.stderr)
            sys.exit(1)
        fixtures_path = resolve_test_resource(fixtures_dir)
        print(f"Testing parser: {args.parser_name}")
        harness = ParserTestHarness(parser_inst, manifest, fixtures_path)
        results = harness.run_all()
        if not all(r.passed for r in results):
            sys.exit(1)
    elif args.parser_command == "list":
        from icarus.parsers import get_registry
        entries = get_registry().list_all()
        if not entries:
            print("No parsers registered.")
            return
        print(f"{'Name':<20} {'Tier':<12} {'Version':<10} {'Spec':<6} Description")
        print("-" * 80)
        for entry in entries:
            print(
                f"{entry['name']:<20} {entry['tier']:<12} {entry['version']:<10} "
                f"{entry['specificity']:<6} {entry['description']}"
            )
    else:
        print("Unknown parser command. Use: validate, list, test", file=sys.stderr)
        sys.exit(1)


def cmd_resolve(args):
    from icarus.core.resolution import resolve_sources

    if not 0.0 <= args.threshold <= 1.0:
        print(
            f"ERROR: --threshold must be in [0, 1], got {args.threshold}",
            file=sys.stderr,
        )
        sys.exit(1)

    entity_types = None if args.entity_type == "all" else [args.entity_type]
    out_path = Path(args.out)
    summary = resolve_sources(
        [Path(source) for source in args.sources], out_path,
        entity_types=entity_types, threshold=args.threshold, atomize_only=args.atomize_only,
        allow_unverified=getattr(args, "allow_unverified", False),
    )
    for index, source in enumerate(summary["sources"], start=1):
        detail = ", ".join(f"{key}={value}" for key, value in source["counts"].items())
        print(
            f"[{index}/{len(args.sources)}] {source['name']}: "
            f"{source['atoms']} atoms ({detail})"
        )
    print(
        f"Total atoms: {summary['total_atoms']} across {len(args.sources)} "
        f"source(s) -> {out_path}"
    )
    for entity_type, result in summary["resolutions"].items():
        print(
            f"[resolve] {entity_type}: clusters={result['clusters']} "
            f"merges={result['merges']} atoms_resolved={result['atoms_resolved']}"
        )
    if not args.atomize_only:
        print(
            f"Canonical entities: {summary['canonical_entities']} "
            f"({summary['cross_source_entities']} spanning >= 2 sources)"
        )


def cmd_gui(args):
    """Serve a capability-protected, read-only explorer on loopback only."""
    from icarus.gui.server import serve

    if not 0 <= args.port <= 65535:
        raise ValueError("--port must be in [0, 65535]")
    try:
        serve(Path(args.database), port=args.port, allow_unverified=args.allow_unverified,
              open_browser=not args.no_browser)
    except (OSError, ValueError) as exc:
        print(f"ERROR: explorer could not start: {exc}", file=sys.stderr)
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(
        prog="icarus",
        description="ICARUS — Modular intelligence framework for structured data analysis",
    )
    sub = parser.add_subparsers(dest="command")

    # build
    build_p = sub.add_parser("build", help="Build an intelligence database from a data source")
    build_p.add_argument(
        "--source", "-s", required=True, help="Path to data source directory")
    build_p.add_argument("--output", "-o", required=True, help="Output database path")
    build_p.add_argument(
        "--parser", "-p", default=None,
        help="Installed parser ID; see 'icarus parser list' (default: auto-detect)")
    build_p.add_argument(
        "--fresh", action="store_true",
        help="Build a new temporary database and replace the destination on success")
    build_p.add_argument(
        "--skip-hygeia", action="store_true",
        help="Skip HYGEIA sanitization (output will contain raw unsanitized data)")
    build_p.add_argument(
        "--resolve", action="store_true",
        help="EXPERIMENTAL: score and group entities within this build before sanitization")

    # gui (optional local read-only ontology explorer)
    gui_p = sub.add_parser("gui", help="Open the local read-only ontology explorer")
    gui_p.add_argument("database", help="Path to ICARUS database")
    gui_p.add_argument("--port", type=int, default=0, help="Loopback port (default: automatic)")
    gui_p.add_argument("--no-browser", action="store_true",
                       help="Print URL without opening a browser")
    gui_p.add_argument("--allow-unverified", action="store_true",
                       help="Inspect failed or unmarked output (unsafe; may contain private data)")

    # query
    query_p = sub.add_parser("query", help="Query an intelligence database")
    query_p.add_argument("database", help="Path to ICARUS database")
    query_mode = query_p.add_mutually_exclusive_group(required=True)
    query_mode.add_argument("--sql", help="Read-only SQL statement (results are capped)")
    query_mode.add_argument("--search", help="Full-text search query")
    query_mode.add_argument("--stats", action="store_true", help="Show table row counts")
    query_p.add_argument("--table", help="Table for --search FTS (default: files)")
    query_p.add_argument(
        "--allow-unverified", action="store_true",
        help="Query even if the database failed sanitization or is unmarked "
             "(unsafe; output may contain unsanitized data)")

    # exec (explicit read-WRITE mutation path; `query` is read-only)
    exec_p = sub.add_parser(
        "exec",
        help="Execute a write statement against a database (READ-WRITE; commits)")
    exec_p.add_argument("database", help="Path to ICARUS database to modify")
    exec_p.add_argument("--sql", required=True, help="SQL statement to execute and commit")

    # diff
    diff_p = sub.add_parser("diff", help="Compare two intelligence databases")
    diff_p.add_argument("old", help="Path to older database")
    diff_p.add_argument("new", help="Path to newer database")
    diff_p.add_argument("--output", "-o", help="Write report to file (default: stdout)")
    diff_p.add_argument("--stix", help="Export diff as STIX 2.1 bundle JSON")
    diff_p.add_argument(
        "--allow-unverified",
        action="store_true",
        help="Export STIX from failed or unmarked inputs (unsafe)",
    )

    # parser
    parser_p = sub.add_parser("parser", help="Parser management commands")
    parser_sub = parser_p.add_subparsers(dest="parser_command")
    validate_p = parser_sub.add_parser("validate", help="Validate a parser manifest")
    validate_p.add_argument("path", help="Path to parser.yaml manifest file")
    test_p = parser_sub.add_parser("test", help="Run parser test harness")
    test_p.add_argument("parser_name", help="Name of the parser to test")
    parser_sub.add_parser("list", help="List all registered parsers")

    # resolve
    from icarus.core.atomize import ATOM_PROJECTIONS
    resolve_p = sub.add_parser(
        "resolve",
        help="Atomize one or more source databases and resolve entities across them")
    resolve_p.add_argument(
        "--out", "-o", required=True, help="Output resolution database path")
    resolve_p.add_argument(
        "--entity-type", choices=list(ATOM_PROJECTIONS) + ["all"], default="all",
        help="Entity type to atomize and resolve (default: all)")
    resolve_p.add_argument(
        "--threshold", type=float, default=0.85,
        help="Score threshold in [0, 1] for a candidate pair to merge (default: 0.85)")
    resolve_p.add_argument(
        "--atomize-only", action="store_true",
        help="Stop after atomizing sources; skip scored resolution")
    resolve_p.add_argument(
        "--allow-unverified", action="store_true",
        help="Recover failed or unmarked inputs; new output sanitization is still mandatory")
    resolve_p.add_argument(
        "sources", nargs="+", help="One or more source ICARUS database paths")

    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        sys.exit(1)
    if args.command == "query" and args.table and args.search is None:
        parser.error("--table requires --search")

    try:
        {"build": cmd_build, "query": cmd_query, "exec": cmd_exec, "diff": cmd_diff,
         "parser": cmd_parser, "resolve": cmd_resolve, "gui": cmd_gui}[args.command](args)
    except FileNotFoundError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)
    except ValueError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        print("\nInterrupted.", file=sys.stderr)
        sys.exit(130)


if __name__ == "__main__":
    main()
