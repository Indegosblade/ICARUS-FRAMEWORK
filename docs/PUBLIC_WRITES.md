# Public writes and sanitization trust

Sanitization evidence describes a particular database state. A public write
must not publish new data with an old successful audit. Issue #114 closes two
paths that previously did that: `IcarusQuery(..., writable=True).execute()` followed
by `commit()`, and metadata updates through `initialize_database()`.

## Writable query contract

The default `IcarusQuery` remains read-only. Explicit writable use is:

```python
with IcarusQuery("intel.db", writable=True) as query:
    query.execute("INSERT INTO metadata VALUES (?, ?)", ("analysis_note", "reviewed locally"))
    query.commit()
```

`execute()` handles one statement. When SQLite authorizes a potentially mutating
operation, the library removes framework sanitizer markers in the same pending
transaction. The outer transaction is not committed by `execute()` or by leaving
the context. Call `commit()` to publish it; `rollback()` or closing the writable
query discards pending changes and their revocation together.

```text
execute -> explicit transaction -> statement savepoint
        -> statement + bounded result consumption + trust revocation
        -> release inner savepoint -> pending transaction
                                   -> commit: data and revocation become visible
                                   -> rollback/close: both revert
```

The outer transaction is essential for DDL as well as DML. Releasing an inner
[SQLite savepoint](https://www.sqlite.org/lang_savepoint.html) does not publish the
transaction, whereas releasing an outermost savepoint would commit it.
The guard uses SQLite's [authorizer action codes](https://www.sqlite.org/c3ref/set_authorizer.html),
not SQL-prefix guessing, and re-arms authorization for cached statements on each
call. Potential write statements are conservatively invalidating even when they
affect no rows; successful SELECTs and ordinary read-only PRAGMAs preserve trust.
The guarded interface owns the authorizer while executing; recursive guarded
execution from a SQL callback is rejected rather than sharing mutable guard state.

Result display remains bounded. The cursor is closed before releasing the
statement savepoint, including for DML with a large `RETURNING` result, so a
display cap does not leave an unfinished statement blocking transaction control.

A failed statement or failed revocation rolls back to its savepoint and leaves
earlier caller work pending. A SQLite operation explicitly using `OR ROLLBACK`
can roll back the entire transaction; that SQLite behavior is preserved. A
failed deferred-constraint commit leaves the transaction available for repair or
explicit rollback; other errors retain SQLite's reported transaction state.
Trust is not deleted in a separately committed preflight operation. Before a
successful commit, other connections still see the original data and its original
evidence; afterward they see the changed data without the old evidence.

SQL-level transaction/savepoint control and ATTACH/DETACH are rejected by this
guard. Use `commit()` and `rollback()` rather than SQL `COMMIT`/`ROLLBACK`.
Nontransactional commands such as VACUUM cannot run inside the guarded transaction.
Metadata triggers that prevent revocation cause a failed write, rather than an
apparently verified changed database. The CLI's explicit `icarus exec` path
retains its own transaction/revocation handling.

## Initializer metadata

`initialize_database(path, metadata=...)` accepts ordinary caller metadata.
The framework-owned `schema_version` and current sanitizer evidence keys are
rejected before opening/creating the output. Copying an old metadata dictionary
must not transfer a clean or skipped status to another database.

On an existing current-schema database, only effective value changes are written.
Those updates and evidence revocation commit together; a failed update restores
their previous state. Initialization without effective metadata changes preserves
an existing audit. Initialization is not a sanitization operation and never
creates a new verified claim from caller metadata.

## Boundaries

The guarantee covers public guarded `execute()` statements and their lifecycle.
Direct writes through the exposed raw `query.conn`, raw cursors, `executescript`,
or independent `sqlite3` connections bypass it. `commit()` cannot retroactively
protect a raw DDL/autocommit operation that was already published. Advanced raw
writers must manage revocation themselves or use the guarded interface. These
raw handles remain available for compatibility; the framework does not proxy
every SQLite connection/cursor operation.

Markers are mutable SQLite metadata, not authenticated attestations. A database
owner can forge them using unsupported raw writes. A changed database must pass
the normal sanitization/final-verification workflow before receiving fresh
framework evidence. Revocation protects against stale evidence; it does not
sanitize the newly written content.

`tests/test_public_write_trust.py` exercises real current-version audits, pending
visibility, repeated/cached writes, DDL, rollback/close and commit failures,
bounded RETURNING, SQL-control escape attempts, copied metadata, trigger-blocked
revocation, and unchanged/no-op initialization. Existing read-only and CLI tests
cover compatibility with the other query paths.
