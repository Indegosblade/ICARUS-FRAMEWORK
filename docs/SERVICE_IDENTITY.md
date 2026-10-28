# Service identity declarations and query evidence

Issue #110 corrects a specific false positive. A Linux unit declaring
`User=nobody` was previously stored with `user_name=NULL`, and `root_daemons()`
treated that NULL as root. Linux extraction now preserves explicit `[Service]`
`User=` and `Group=` values. The query includes literal `root`, or UID `0` only
when the row's version provenance identifies the Linux parser. Missing identity
stays unknown. A missing sandbox-profile field means no profile was recorded,
not that a running process is unsandboxed.

The Linux parser reads at most 1,000,001 bytes and refuses identity extraction
above 1,000,000 bytes. Invalid UTF-8, embedded NUL, inaccessible/special inputs,
and over-limit values produce unknown identity rather than a partial root claim.
Individual values are capped at 4,096 characters without truncating them into a
different identity. Other file metadata is still cataloged under the existing
parser policy.

Parsing is section-aware and case-sensitive. Scalar assignments replace earlier
assignments; an empty value clears the setting. Full-line `#` and `;` comments
are skipped, and odd trailing-backslash continuations are joined before parsing
directives. That includes continuations on unrelated keys: an apparent
`User=root` on the next physical line can be part of an `Environment=` value.
Inline `#` text is not removed. These choices follow
[systemd.syntax](https://www.freedesktop.org/software/systemd/man/257/systemd.syntax.html)
and the scalar replacement/reset behavior in
[systemd's User/Group parser](https://github.com/systemd/systemd/blob/v258/src/core/load-fragment.c#L2297).

Values remain raw declarations. ICARUS does not strip their quotes, expand
specifiers, consult account databases, validate every systemd username form,
compose drop-ins/overrides, infer manager defaults, or inspect running processes.
For example, `%i`, `"root"`, and `root # text` remain distinguishable from the
literal `root` declaration and do not satisfy the root helper. A later empty
assignment remains NULL instead of becoming a default root value.

Continuation is tested before trimming trailing spaces. A backslash followed by
spaces/tabs does not continue the next line. At EOF, a pending continuation is
still parsed: `User=root` followed by a terminal backslash becomes the explicit
root declaration after that backslash is replaced with a space. These edge cases
follow [systemd's physical-line reader](https://github.com/systemd/systemd/blob/v258/src/basic/fileio.c)
and [configuration parser](https://github.com/systemd/systemd/blob/v258/src/shared/conf-parser.c).
The former preserves spaces, unlike its separate `read_stripped_line` helper;
the latter tests escapes on that input and explicitly parses pending text at EOF.

Configured identity is not effective identity. The official
[systemd.exec documentation](https://www.freedesktop.org/software/systemd/man/258/systemd.exec.html)
describes manager-dependent defaults, numeric IDs, and command prefixes that can
bypass a configured User/Group setting. ICARUS preserves the collected file's
declaration without claiming those runtime/context rules were evaluated.
Likewise, Apple's [launchd guide](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingLaunchdJobs.html)
distinguishes system daemons from per-user agents. A launch agent missing
`UserName` is not classified as root from its NULL field. Existing explicit
launchd user/group text remains available; this change does not infer a launch
domain or effective credentials.

The Linux manifest advances to 1.0.1 because the stored extraction changes.
Existing source rows are not rewritten or backfilled by queries. Rebuild to
collect the new fields. An interrupted 1.0.0 build fails the existing resume
fingerprint check against 1.0.1; use a fresh output or the explicit fresh-build
path instead of mixing old and new extraction semantics.

`root_daemons()` requires the current normalized schema, including `versions`
and `daemons.source_version_id` for the numeric-UID provenance check. Read-only
queries do not migrate old files. Rebuild an older database before using this
helper; raw SQL can still inspect whatever legacy columns are present.

The existing query methods remain available with evidence-limited titles.
Entitlement inventory does not classify arbitrary keys as privileged. The
Mach-service/entitlement join is a declaration candidate, not proof of access or
escalation; kernel user-client metadata is also a candidate, not a runtime
reachability test. Schema v6 and the raw views are unchanged. The Python
`escape_surface()` result aliases the historical `privileged_entitlements`
column to `entitlement_keys`; raw SQL keeps the legacy column name. See the
[query compatibility notes](../wiki/Query-Reference.md#configuration-evidence-and-compatibility).

Regression coverage in `tests/test_service_identity.py` includes the original
non-root false positive, explicit root and provenance-qualified UID 0, missing
and unresolved identities, section/repeated/reset directives, comments and
continuations, encoding/read bounds, provenance/idempotency, launch-agent
unknowns, and useful but unclassified Mach-service/entitlement joins. Existing
parser harness gates still validate the packaged Linux corpus.
