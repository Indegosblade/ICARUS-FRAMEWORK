# SQLite row-carrier verification

HYGEIA 3.15.1 supplies the SQLite carrier catalog used by its canonical sanitizer,
its verifier, and ICARUS's scoped redaction and final content pass. The reserved
`sqlite_` prefix is tested literally. Legal SQLite-like and FTS-like application
names do not make a table internal or exempt it from scanning.

The catalog includes all column affinities and SQLite's complete `table_xinfo`
metadata, including generated and hidden columns. String cells and the existing
UTF-8/UTF-16 text-byte representations are checked. Numeric scalar cells are not
converted into invented text. This is the configured row-value policy, not a
decoder for every opaque format or a scanner for arbitrary secrets in SQL DDL.

Derived FTS storage is distinguished using a declared supported FTS module,
its storage options, and the actual column layout, with `table_list` ownership
metadata when available. Older SQLite uses the same explicit DDL/layout checks.
A shadow-like name or a reported shadow type alone is insufficient: a disabled
optional storage table can leave that name available for ordinary application
data. Readable FTS configuration rows remain carriers in their own right.

Generated values are scanned after ordinary source columns. If matching content
cannot be rewritten through a supported locator, sanitization fails closed.
Verification failures or unsupported metadata are never silently counted as a
clean table. ICARUS finding locators use a real SQLite rowid or NULL, rather than
copying an arbitrary user-defined `rowid` value into public audit metadata.

ICARUS still owns its column-scoped pattern policy and independently checks
residual content after canonical sanitization. Those passes now share the
inventory implementation; they are **not independent implementations of table
enumeration**. A shared catalog defect can affect both, so positive controls
cover ordinary carriers, name lookalikes, generated values, text-bearing BLOBs,
and genuine FTS storage. A verified artifact means the configured checks passed
on supported row carriers; it does not establish universal absence of secrets.

The immutable HYGEIA dependency pin must identify the reviewed catalog-capable
package. Older installations lacking that capability refuse sanitized builds.
