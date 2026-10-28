# Filesystem ingest recovery

The Linux and Windows parsers resume an interrupted extraction from the last
committed batch. The pipeline's existing source/parser/config fingerprint and
original run identity still govern whether the build may resume. The source must
remain immutable throughout the interrupted build; source contents are not
rehashed to validate a resume. Change the source only with a fresh rebuild.

The parser owns the following transaction boundary:

```text
pending directory -> ordered filename -> all entity writes for that input
                                       + run provenance
                                       + next filename cursor and statistics
                                       -> one SQLite commit
```

Private `_icarus_ingest_state` and `_icarus_ingest_frontier` tables live in the
output database during extraction. They record the source, parser, original run,
pending directories, and current directory's last committed filename. A batch
commits after 50,000 work units (processed files or completed directories); normal
completion commits the final partial batch. Cursor state and rows commit on the
same connection, so a hard process exit cannot advance one without the other.
An exception rolls back the current batch. Resume replays only that uncommitted
batch and continues the pending frontier.

File names are ordered by raw filesystem encoding and stored as bytes, so the
cursor does not depend on operating-system directory enumeration order or lose
non-UTF-8 path bytes. Completed directories are not reopened. The active directory
is enumerated again, but completed filenames are skipped before file parsing and
hashing. Memory use is proportional to one directory's filename listing, rather
than the entire source tree.

Provenance is stamped in the same batch transaction as entity rows. This matters
for process termination: an outer Python `finally` block cannot run after a hard
exit. Resumed data retains the original version and observation time without
depending on that cleanup. A different source, parser, or active run is refused.
The private progress tables are removed after successful extraction and never
appear in a completed output.

The CLI and `Pipeline.run()` hold an OS-backed output lease before changing run
identity or checkpoint state. A competing ICARUS build fails before writing;
`--fresh` keeps the destination leased through final replacement. A persistent
hidden `.icarus.lock` sidecar stores no path or PID. Process termination releases
the operating-system lock automatically; do not delete a live sidecar. Direct
parser calls and unrelated external SQLite writers are outside this coordination
contract. macOS and other parsers retain phase-level replay until they explicitly
adopt an equivalent transaction contract; their multi-pass extraction is not
covered by the filesystem cursor.

`tests/test_ingest_progress.py` exercises an actual subprocess `os._exit`,
recovery without reopening completed directories, rollback after a partial
entity insert, statistics restoration, identity mismatch rejection, relative
source paths, and rejection of an abandoned iterator. Existing provenance,
parser accuracy, idempotency, hostile-input, and resume-fingerprint tests cover
compatibility with the surrounding pipeline.
