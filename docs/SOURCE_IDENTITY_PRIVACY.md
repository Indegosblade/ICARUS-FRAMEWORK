# Source identity privacy and legacy artifacts

New builds persist their source-identity secret only in the private checkpoint.
Computation also uses private pipeline memory; the secret is never returned in
`PipelineContext` or statistics.
The public version metadata contains a `source_identity` object with version
`1`, algorithm `hmac-sha256`, and a digest. The checkpoint's
`source_identity_key` must not be copied into a public database or a shared
bundle. Keep the entire checkpoint and its SQLite sidecars private.

The deprecated `source_identity_sha256` field is no longer accepted by public
verification. Final gates refuse that field instead of silently deleting
information an interrupted build may need for ownership-validated recovery.
Malformed/non-object version metadata and public copies of private resume material also
fail the gate.

## Audit version 2

The successful final audit now uses version `2`. Older verified markers are
classified as `unknown`, so default consumers require explicit remediation or
recovery before relying on them. A current audit also requires the current
canonical engine and no rejected source-identity material.

Audit metadata describes completed checks; it is not a signature or a defense
against an actor who can forge the database's metadata. The HMAC is a source
identity label, not a source-content hash, a snapshot of the source, or proof
that source contents stayed unchanged.

## Interrupted or ambiguous builds

Resume an interrupted build using its original immutable source and the
database/checkpoint pair. The resume path validates ownership before upgrading
legacy identity to the private-key protocol. A private key and intent are
persisted before a public HMAC is written; prepared/bound recovery handles a
failure between those writes.

Do not remove a checkpoint or rename/copy only its database to bypass an
ownership refusal. Both the full-filename checkpoint namespace and the older
stem-based namespace matter. An owned checkpoint, an unresolved prepared
intent, malformed ownership data, or orphan checkpoint sidecars require
resume/recovery first. A proven foreign checkpoint is preserved and ignored.
If the source for an incomplete build is unavailable, preserve the private pair
and recover from a suitable backup; this API cannot declare that build complete.

## Completed legacy output when its source is unavailable

`remediate_legacy_output()` accepts an existing completed legacy artifact without
requiring the original source. Eligibility requires coherent audit-version-1
verified-final evidence, every version marked complete, and no owned or
ambiguous checkpoint state. A completion timestamp alone is insufficient.
Failed, skipped, unmarked, and inconsistent artifacts are refused before data
changes. A coherent prior engine version is allowed only to establish that old
completion evidence; remediation always runs the current real canonical engine.

Close all writers and retain an offline backup before running it. Work on an
offline copy of the artifact directory with original basenames and private
sidecars retained, so ownership checks cannot be bypassed by a filename change.
Do not put that directory or its private checkpoints in a shared bundle.

For a completed artifact at `offline-copy/intel.db`, this command needs no source:

```bash
python -c "from pathlib import Path; from icarus.integrations.hygeia import remediate_legacy_output; result = remediate_legacy_output(Path('offline-copy/intel.db')); print('Remediated versions:', result['versions_remediated'])"
icarus query offline-copy/intel.db --stats
```

The operation revokes old trust before changing data. It removes only the
deprecated identity field from version metadata, preserves unrelated metadata
and entity rows, runs canonical sanitization and FTS rebuilding, then publishes
a new final audit. Other values may still be redacted by the normal sanitizer.
Without the source it does not invent a replacement source HMAC.

This is in-place remediation, not atomic publication. Failure or interruption
leaves the working artifact unverified; preserve it for inspection, fix the
cause, and begin again from the retained completed backup. Never restore an old
marker manually or share an artifact merely because the obsolete field vanished.
Only the successfully reverified database is the shareable result, subject to
the normal pattern-based sanitization and trusted-metadata limits.

Remediation changes only that working copy. It cannot retroactively make a
previously distributed legacy artifact private, remove recipients' copies, or
unshare files that were already sent. A new audit does not revoke older copies.
