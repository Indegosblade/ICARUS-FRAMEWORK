# STIX identity policy

ICARUS exports deterministic STIX identifiers with UUIDv5 under the explicit
ICARUS namespace `28ad9e40-63a7-4de4-a1f0-20f7f1f3cd10`. The current policy is
`icarus-stix-identity-v2`. The policy string is part of every UUIDv5 seed.
Version 2 corrects v1's path and entitlement collision cases; it deliberately
does not reuse v1 identifiers. Future intentional identity-format changes can
likewise introduce a new version without silently colliding with prior IDs.

Each seed is canonical JSON: UTF-8 JSON with sorted keys and compact
separators. Domain strings, including paths, are preserved exactly as stored.
The schema permits distinct raw values such as `/tmp/../same` and `/same`, so
filesystem or Unicode normalization could merge separate rows into a conflicting
STIX identifier. SHA-256 values are trimmed and lowercased. SQLite primary and
foreign keys are never seed material and are not exported as observation
identifiers.

| Exported object | v2 identity attributes |
| --- | --- |
| File SCO | stored file path, plus SHA-256 when present |
| Binary file SCO | owning file identity, executable name, bundle ID when present, and architecture when present |
| Daemon infrastructure SDO | label and stored plist path |
| Entitlement course-of-action SDO | owning binary identity, entitlement key, and value |
| Observation (`observed-data` or `sighting`) | referenced entity STIX ID, normalized observed timestamp, and event type |

The attributes above define identity. Other exported attributes are content:
for example a file's size and type and a daemon's program/user can change
without changing the object's logical identity. An entitlement value is part of
its identity because the schema permits multiple values for the same binary/key;
including it prevents valid rows from colliding in one STIX object.
STIX SDO `modified` records the observation time when available. Observation
identity intentionally includes the observed timestamp and event type: changing
either represents a distinct event, while duplicate database rows for the same
event deduplicate to one exported STIX object. `properties`, confidence, and
local version references are not currently exported, so they do not version an
observation identity.
