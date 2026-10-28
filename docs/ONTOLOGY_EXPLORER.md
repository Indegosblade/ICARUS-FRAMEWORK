# Local ontology explorer

Run `icarus gui intel.db` to inspect an existing ICARUS database in your browser.
The optional explorer requires no additional dependencies. It displays entity
collections, keyset-paginated inventories, FTS5 search, entity properties,
provenance, and recorded relationships. `--no-browser` prints the session URL
without opening a browser; `--port 8123` requests a particular loopback port.
The default chooses an available port. Stop the server with Ctrl+C.

The explorer reads the existing normalized model:

```text
local browser -> capability-protected loopback HTTP API
              -> fixed queries on a read-only SQLite connection
              -> entities + declared foreign keys + observations + provenance
```

Relationship inspection follows declared foreign keys, the polymorphic
`observations.entity_table/entity_id` link, and atom/bag membership. These are
recorded relationships, not inferred exploitability or inferred identity.
The `bags` collection includes historical empty bags retained for resolution
audit history; current canonical membership is recorded in `bag_atoms`.
The interface does not add or redefine ontology types, edit data, run builds,
provide arbitrary SQL, or implement Foundry-style operational workflows.

## Security and resource boundaries

The server binds only to `127.0.0.1`. Each launch creates a random 256-bit
capability, printed in a URL fragment. Fragments are not sent in HTTP requests.
The application removes the fragment from the current browser history entry and
keeps the capability in memory, sending it only as an Authorization header to
same-origin API requests. Keep the printed session URL private. A page reload
requires opening the complete printed URL again.

Every request requires the exact loopback Host header and rejects foreign
Origins and cross-site Fetch Metadata. API reads require the session capability;
there is no CORS permission. Responses disable caching and referrers, prevent
framing and MIME sniffing, and use a Content Security Policy allowing only the
bundled local script, stylesheet, and API. Database values enter the DOM through
`textContent`; no value is interpreted as HTML. External scripts, fonts,
telemetry, file downloads, and arbitrary local file serving are absent.

Connections use IcarusQuery's read-only SQLite mode, `query_only` guard, and
attachment restrictions, plus disabled trusted-schema behavior. The HTTP API
accepts only allowlisted table names, integer IDs/cursors, and bounded FTS
expressions. It exposes no SQL endpoint or write endpoint. Requests are handled
serially, socket operations time out after five seconds, and an absolute
eight-second connection deadline stops clients trickling incomplete headers.
SQL execution has a two-second progress-handler budget. Inventory pages contain at most 25 rows;
cell previews are capped at 1,024 characters. Detail views show at most 24
relationship groups, with ten objects per group. Responses are capped at 1 MB.

The same sanitization consumer policy as the CLI applies. Verified outputs and
explicit `--skip-hygeia` outputs may be inspected by default; skipped outputs
carry a persistent warning. Failed or unmarked outputs require
`--allow-unverified` and carry the same warning. The posture is checked again
on every API request. Viewing is not sanitization, and read-only access does not
prevent an authorized user from copying displayed private data.

This is a local, single-user inspection tool. The capability and origin checks
protect against unrelated websites reading localhost data; they do not protect
against malware or another process able to inspect this user's terminal,
browser memory, or operating-system account. Do not expose the port through a
proxy, port forward, or tunnel. A multi-user deployment requires a separate
authentication, authorization, audit, and isolation design.

`tests/test_gui.py` exercises the actual HTTP server: capability failures,
foreign Host/Origin rejection, response policies, pagination, FTS search,
provenance and relationships, input allowlists, missing entities, static-asset
boundaries, changed sanitization posture, and an unchanged database hash after
inspection. A raw-socket trickled-header test verifies that the absolute
deadline closes the connection and the server accepts subsequent requests.
Browser smoke testing complements these checks; HTTP tests alone
do not establish visual or interaction quality.
