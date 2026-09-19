# STIX identity policy

ICARUS exports deterministic STIX identifiers with UUIDv5 under the explicit
ICARUS namespace `28ad9e40-63a7-4de4-a1f0-20f7f1f3cd10`. The current policy is
`icarus-stix-identity-v1`. The policy string is part of every UUIDv5 seed, so a
future intentional identity-format change can introduce a new version without
silently colliding with v1 identifiers.

Each seed is canonical JSON: UTF-8 JSON with sorted keys, compact separators,
and Unicode NFC strings. Paths replace backslashes with slashes and apply POSIX
`.`/`..` normalization; path case is preserved. SHA-256 values are trimmed and
lowercased. SQLite primary and foreign keys are never seed material and are not
exported as observation identifiers.

| Exported object | v1 identity attributes |
| --- | --- |
| File SCO | normalized file path, plus SHA-256 when present |
| Binary file SCO | owning file identity, executable name, bundle ID when present, and architecture when present |
| Daemon infrastructure SDO | label and normalized plist path |
| Entitlement course-of-action SDO | owning binary identity and entitlement key |
| Observation (`observed-data` or `sighting`) | referenced entity STIX ID, normalized observed timestamp, and event type |

The attributes above define identity. Other exported attributes are content:
for example a file's size and type, a daemon's program/user, and an
entitlement's value can change without changing the object's logical identity.
STIX SDO `modified` records the observation time when available. Observation
identity intentionally includes the observed timestamp and event type: changing
either represents a distinct event, while duplicate database rows for the same
event deduplicate to one exported STIX object. `properties`, confidence, and
local version references are not currently exported, so they do not version an
observation identity.
