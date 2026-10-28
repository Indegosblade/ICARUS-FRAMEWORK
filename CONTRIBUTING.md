# Contributing

ICARUS is beta, source-available software under
[PolyForm Noncommercial 1.0.0](LICENSE). Contributions use the same license.

## Development setup

Clone the repository and create a virtual environment. See
[Getting started](wiki/Getting-Started.md) for activation commands on Windows,
Linux, and macOS.

```bash
git clone https://github.com/Indegosblade/ICARUS-FRAMEWORK.git
cd ICARUS-FRAMEWORK
python -m pip install -e ".[dev]"
```

Use the development-tool versions pinned in `pyproject.toml`. Git is required
for the pinned HYGEIA dependency. Keep source datasets, private parsers, and
generated databases out of commits.

## Validate before publishing

Run local checks against the exact code you intend to push:

```bash
python -m ruff check .
python -m mypy icarus/
python -m bandit -r icarus/ -c pyproject.toml
python -m pytest tests/ -q
python -m build
```

The suite includes installed-package checks. Also exercise a built wheel in a
clean environment when changing packaging, runtime data, or dependencies.
Dependency review uses `pip-audit==2.10.1`; VCS packages are explicit audit skips,
so review pinned HYGEIA changes separately.

Compare regressions with the last passing revision. Do not push a branch or
update a pull request while known local failures remain. GitHub CI runs the
Python 3.10–3.13 platform matrix after quality/dependency gates and a macOS 3.12
preflight; it is confirmation after local validation, not the first debugging
environment. Keep negative reproductions and record the exact tested commit.

## Change and review process

1. Branch from current `main` and keep a change focused.
2. Link the issue and describe the concrete before/after behavior.
3. Add meaningful regression coverage for changed behavior and failure paths.
4. Update relevant command, API, recovery, and migration documentation.
5. Record local checks and their limitations; require the appropriate CI checks.
6. Squash-merge after review. Close issues with verified acceptance evidence.

The checked-in `wiki/` pages are the reviewable source for the live GitHub wiki.
Publish the same reviewed content there after the repository change lands,
converting repository-relative links to repository URLs and wiki links to page
URLs. Do not edit only the live copy and leave the source stale.

## Adding a parser

Implement `BaseParser` with a co-located YAML manifest. Run the declared fixture
gates with `icarus parser test NAME`: golden output, idempotency, schema
conformance, and zero-PII. A passing fixture corpus does not prove behavior for
every real source. See [parser development](about/PARSERS.md).

## Security

Report vulnerabilities privately according to [SECURITY.md](SECURITY.md), rather
than including sensitive details or data in a public issue.
