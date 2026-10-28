# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project aims to follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Version identity note: historical Git tags, GitHub releases, and `pyproject` versions
diverged during early development. The project is moving forward monotonically; see the
`4.0.0b1` beta line once released. Do not rely on pre-4.0 tags for reproducibility.

## [Unreleased]

Public-release readiness remediation toward the first public beta (`4.0.0b1`).

### Added
- `SECURITY.md`, `CONTRIBUTING.md`, and this `CHANGELOG.md` (public-project posture),
  plus a threat model (`docs/THREAT_MODEL.md`).
- Hostile-filesystem-input hardening and regression suite: in-root symlinks are
  cataloged but never dereferenced or traversed; FIFOs, non-UTF-8 names, deeply nested
  JSON, and compression bombs are skipped-with-warning rather than hanging or crashing
  (#43, #47).
- Credential detection in sanitization and a mandatory post-sanitize verification gate.
- `query --allow-unverified` to inspect a database whose sanitization failed (#77).

### Changed
- Cross-source resolution publishes a new database only after sanitization and its
  final verification gate succeed. Inputs must be distinct, checkpointed snapshots;
  existing outputs are refused. `--allow-unverified` permits input recovery while
  keeping output sanitization mandatory (#108).
- Atomization and resolver mutations revoke old sanitization evidence in the same
  transaction as their writes, including committed partial-failure results (#108).
- Pin HYGEIA to the reviewed 3.15.0 commit with error propagation and verified
  external-content FTS5 rebuilding. Development coverage and distribution-build
  tooling use the same validated versions locally and in the workflow.
- Maturity classifier corrected from `Production/Stable` to `Beta`; README states the
  Beta, source-available (non-OSI) posture explicitly.
- HYGEIA is now the canonical sanitizer and **fails closed** if it cannot load; findings
  record only a non-reversible fingerprint and location, never the raw secret (#41).
- Sanitization redaction is **column-scoped**: value-content patterns apply only to
  free-text/value columns, so structural path/filename data (version strings, GUID
  filenames) is neither corrupted nor treated as a false residual that aborts the build.
  A sanitizing build now completes on a real filesystem (#76).
- `query` is read-only by default; a database whose sanitization failed is stamped and
  refused unless `--allow-unverified` (#77). Auto-detect no longer full-walks a source
  just to choose a parser (#78).
- Packaging ships parser manifests, JSON Schema, and catalogs in built distributions
  (#37); foreign keys are enforced on every write path (#44); a future/malformed schema
  version is refused instead of silently relabeled (#39).

### Repository
- Merges are squash-only with automatic branch deletion; `main` is branch-protected
  (required CI checks, no force-push). Dependabot version-update PRs are disabled.
  `.mailmap` normalizes the author identity.

## [1.4.0] - 2026-07-03
- Experimental cross-build entity resolution (`icarus resolve`, `icarus build --resolve`).

## [1.3.0] - 2026-07-03
- Parser auto-discovery replaces the hardcoded registry; diff/query correctness and
  untrusted-input hardening; STIX timestamp/reference fixes; public-API curation.

## [1.2.0] - 2026-07-02
- `macos` parser (launchd/Mach-service/entitlement attack surface); schema v5; first
  production-readiness hardening pass.

## [1.1.1] - 2026-06-08
- First stable release: pipeline with checkpoint/resume, schema v4 + FTS5, query engine,
  cross-version differ, 8 production parsers, HYGEIA sanitization, STIX 2.1 export.

[Unreleased]: https://github.com/Indegosblade/icarus-framework/compare/main...HEAD
