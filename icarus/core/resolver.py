"""
ICARUS Entity Resolver — Atom/Bag/EventLog pattern for cross-source identity.

EXPERIMENTAL: the API and resolution behavior are still unstable and may
change. The subsystem IS wired to users: the ``icarus resolve`` CLI command
atomizes one or more source databases and resolves them into a shared output,
and ``icarus build --resolve`` optionally runs an in-build resolve phase (see
``icarus.core.pipeline.create_default_pipeline``). Direct use still requires
acknowledging the experimental flag: construct
``EntityResolver(db_path, experimental=True)``.

Entities from different sources may refer to the same real-world thing under
different identifiers. The resolver tracks immutable atoms (raw observations),
groups them into bags (resolved entities), and logs every resolution decision
in an append-only event log. Two resolution entry points are offered:
``resolve``, an exact-key-blocking MVP (identical normalized values or
nothing), and ``resolve_scored``, the full block -> score -> cluster -> merge
pipeline over atoms fed by ``icarus.core.atomize`` (see each method's own
docstring for details).
"""

import json
import math
import warnings
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple

from icarus.core.matching import candidate_pairs, cluster, score_pair
from icarus.core.schema import open_db

# Explicit experimental flag for the atom/bag/resolver subsystem: it is not
# wired into the default pipeline and its API/behavior are unstable.
__experimental__ = True


class EntityResolver:
    """Resolve entities across sources using the Atom/Bag/EventLog pattern.

    EXPERIMENTAL: not wired into ``create_default_pipeline``. Pass
    ``experimental=True`` to acknowledge the unstable API; omitting it emits a
    warning rather than failing, so existing callers keep working.
    """

    def __init__(self, db_path: str, *, experimental: bool = False):
        if not experimental:
            warnings.warn(
                "EntityResolver is an experimental, unwired subsystem "
                "(not part of create_default_pipeline); pass experimental=True "
                "to acknowledge its unstable API.",
                stacklevel=2,
            )
        self.experimental = experimental
        # open_db (audit #63/#68) enforces PRAGMA foreign_keys = ON and applies
        # the RAM-scaled cache/mmap pragmas on this working connection, instead
        # of a bare sqlite3.connect that silently left REFERENCES unenforced.
        self.conn = open_db(db_path)

    def ingest_atom(
        self, version_id: int, entity_type: str, source_key: str, properties: dict
    ) -> int:
        """Create an immutable atom. Returns atom_id."""
        now = datetime.now(timezone.utc).isoformat()
        cursor = self.conn.execute(
            "INSERT INTO atoms (source_version_id, entity_type, source_key, "
            "properties, created_at) VALUES (?, ?, ?, ?, ?)",
            (version_id, entity_type, source_key, json.dumps(properties), now),
        )
        self.conn.commit()
        atom_id = cursor.lastrowid
        assert atom_id is not None
        return atom_id

    def create_bag(
        self, entity_type: str, atom_ids: List[int], canonical_key: Optional[str] = None
    ) -> int:
        """Create a bag grouping one or more atoms. Returns bag_id."""
        atom_ids = list(dict.fromkeys(atom_ids))
        if not atom_ids:
            raise ValueError("create_bag requires at least one atom ID")
        placeholders = ",".join("?" for _ in atom_ids)
        rows = self.conn.execute(
            f"SELECT id, entity_type FROM atoms WHERE id IN ({placeholders})",  # nosec B608 - placeholders are generated from list length only
            atom_ids,
        ).fetchall()
        found = {row[0]: row[1] for row in rows}
        missing = [atom_id for atom_id in atom_ids if atom_id not in found]
        if missing:
            raise ValueError(f"Unknown atom IDs: {missing}")
        mismatched = [atom_id for atom_id in atom_ids if found[atom_id] != entity_type]
        if mismatched:
            raise ValueError(
                f"Atoms do not match entity type {entity_type!r}: {mismatched}"
            )
        assigned = self.conn.execute(
            f"SELECT atom_id FROM bag_atoms WHERE atom_id IN ({placeholders})",  # nosec B608 - placeholders are generated from list length only
            atom_ids,
        ).fetchall()
        if assigned:
            raise ValueError(
                f"Atoms already belong to a bag: {sorted(row[0] for row in assigned)}"
            )

        now = datetime.now(timezone.utc).isoformat()
        with self.conn:
            cursor = self.conn.execute(
                "INSERT INTO bags (entity_type, canonical_key, created_at, atom_count) "
                "VALUES (?, ?, ?, ?)",
                (entity_type, canonical_key, now, len(atom_ids)),
            )
            bag_id = cursor.lastrowid
            assert bag_id is not None

            self.conn.executemany(
                "INSERT INTO bag_atoms (bag_id, atom_id) VALUES (?, ?)",
                [(bag_id, atom_id) for atom_id in atom_ids],
            )
            self._log_event("create", bag_id, atom_ids, "initial bag creation")
        return bag_id

    def merge_bags(self, bag_ids: List[int], reason: str = "") -> int:
        """Merge multiple bags into one. Logs BEFORE modifying. Returns surviving bag_id."""
        bag_ids = list(dict.fromkeys(bag_ids))
        if len(bag_ids) < 2:
            raise ValueError("merge_bags requires at least 2 bag IDs")

        placeholders = ",".join("?" for _ in bag_ids)
        bags = self.conn.execute(
            f"SELECT id, entity_type FROM bags WHERE id IN ({placeholders})",  # nosec B608 - placeholders are generated from list length only
            bag_ids,
        ).fetchall()
        found = {row[0]: row[1] for row in bags}
        missing = [bag_id for bag_id in bag_ids if bag_id not in found]
        if missing:
            raise ValueError(f"Unknown bag IDs: {missing}")
        if len(set(found.values())) != 1:
            raise ValueError("Cannot merge bags with different entity types")

        surviving_id = bag_ids[0]

        all_atom_ids = []
        for bag_id in bag_ids:
            rows = self.conn.execute(
                "SELECT atom_id FROM bag_atoms WHERE bag_id = ?", (bag_id,)
            ).fetchall()
            all_atom_ids.extend(r[0] for r in rows)

        with self.conn:
            self._log_event("merge", surviving_id, all_atom_ids, reason)

            for bag_id in bag_ids[1:]:
                # bag_atoms has PRIMARY KEY(bag_id, atom_id): if the losing and
                # surviving bags already share an atom, a plain
                # "UPDATE ... SET bag_id" re-points that shared row onto a key
                # that already exists under surviving_id and raises
                # IntegrityError. INSERT OR IGNORE + delete-the-loser is safe
                # either way — a shared atom simply collapses to the one row
                # already present under surviving_id.
                self.conn.execute(
                    "INSERT OR IGNORE INTO bag_atoms (bag_id, atom_id) "
                    "SELECT ?, atom_id FROM bag_atoms WHERE bag_id = ?",
                    (surviving_id, bag_id),
                )
                self.conn.execute(
                    "DELETE FROM bag_atoms WHERE bag_id = ?",
                    (bag_id,),
                )
                self.conn.execute(
                    "UPDATE resolution_event_log SET bag_id = ? WHERE bag_id = ?",
                    (surviving_id, bag_id),
                )
                self.conn.execute("DELETE FROM bags WHERE id = ?", (bag_id,))

            total = self.conn.execute(
                "SELECT COUNT(*) FROM bag_atoms WHERE bag_id = ?", (surviving_id,)
            ).fetchone()[0]
            self.conn.execute(
                "UPDATE bags SET atom_count = ?, resolved_at = ? WHERE id = ?",
                (total, datetime.now(timezone.utc).isoformat(), surviving_id),
            )
        return surviving_id

    def split_bag(self, bag_id: int, atom_ids_to_remove: List[int], reason: str = "") -> int:
        """Remove atoms from a bag into a new bag. Does NOT delete original. Returns new bag_id."""
        atom_ids_to_remove = list(dict.fromkeys(atom_ids_to_remove))
        if not atom_ids_to_remove:
            raise ValueError("split_bag requires at least one atom ID")
        now = datetime.now(timezone.utc).isoformat()

        bag = self.conn.execute(
            "SELECT entity_type FROM bags WHERE id = ?", (bag_id,)
        ).fetchone()
        if bag is None:
            raise ValueError(f"Unknown bag ID: {bag_id}")
        members = {
            row[0]
            for row in self.conn.execute(
                "SELECT atom_id FROM bag_atoms WHERE bag_id = ?", (bag_id,)
            ).fetchall()
        }
        requested = set(atom_ids_to_remove)
        missing = sorted(requested - members)
        if missing:
            raise ValueError(f"Atoms are not members of bag {bag_id}: {missing}")
        if requested == members:
            raise ValueError("split_bag cannot remove every atom from the original bag")

        with self.conn:
            self._log_event("split", bag_id, atom_ids_to_remove, reason)
            cursor = self.conn.execute(
                "INSERT INTO bags (entity_type, created_at, atom_count) VALUES (?, ?, ?)",
                (bag[0], now, len(atom_ids_to_remove)),
            )
            new_bag_id = cursor.lastrowid
            assert new_bag_id is not None

            placeholders = ",".join("?" for _ in atom_ids_to_remove)
            self.conn.execute(
                f"UPDATE bag_atoms SET bag_id = ? "  # nosec B608 - placeholders are generated from list length only
                f"WHERE bag_id = ? AND atom_id IN ({placeholders})",
                [new_bag_id, bag_id, *atom_ids_to_remove],
            )

            remaining = len(members) - len(requested)
            self.conn.execute(
                "UPDATE bags SET atom_count = ?, resolved_at = ? WHERE id = ?",
                (remaining, now, bag_id),
            )
        return new_bag_id

    def resolve(
        self, entity_type: str, blocking_keys: List[str]
    ) -> Dict[str, Any]:
        """Group unresolved atoms by EXACT blocking key and bag each group.

        Exact-key-blocking MVP: for each unresolved atom of ``entity_type`` a
        cluster key is built by joining the lowercased, stripped values of
        ``blocking_keys`` found in its properties. Atoms sharing a cluster key
        go into one bag (its ``canonical_key`` is that cluster key); an atom
        with a unique key gets a singleton bag. Atoms with no value for any
        blocking key are left unresolved. There is no similarity scoring and no
        FTS-based candidate blocking.

        Returns ``{"merges": N, "atoms_resolved": M}`` where ``merges`` counts
        the multi-atom bags created and ``atoms_resolved`` counts atoms placed
        into any bag.
        """
        unresolved = self.unresolved_atoms(entity_type)
        if not unresolved:
            return {"merges": 0, "atoms_resolved": 0}

        clusters: Dict[str, List[int]] = {}
        for atom_id in unresolved:
            row = self.conn.execute(
                "SELECT properties FROM atoms WHERE id = ?", (atom_id,)
            ).fetchone()
            if not row:
                continue
            props = json.loads(row[0])
            key_parts = []
            for bk in blocking_keys:
                val = props.get(bk, "")
                if val:
                    key_parts.append(str(val).lower().strip())
            if key_parts:
                cluster_key = "|".join(key_parts)
                clusters.setdefault(cluster_key, []).append(atom_id)

        merges = 0
        atoms_resolved = 0
        for cluster_key, atom_ids in clusters.items():
            if len(atom_ids) >= 2:
                self.create_bag(entity_type, atom_ids, canonical_key=cluster_key)
                merges += 1
                atoms_resolved += len(atom_ids)
            else:
                self.create_bag(entity_type, atom_ids)
                atoms_resolved += 1

        return {"merges": merges, "atoms_resolved": atoms_resolved}

    def resolve_scored(
        self,
        entity_type: str,
        blocking_keys: Optional[List[str]] = None,
        *,
        threshold: float = 0.85,
    ) -> Dict[str, Any]:
        """The real **block -> score -> cluster -> merge** resolution.

        Where :meth:`resolve` is the exact-key-blocking MVP (identical values
        or nothing), this runs the full scored pipeline over the currently
        *unresolved* atoms of ``entity_type``:

        1. **block** — :func:`~icarus.core.matching.candidate_pairs` generates
           plausibly-same-entity atom pairs (restricted here to unresolved
           atoms on both ends).
        2. **score** — :func:`~icarus.core.matching.score_pair` assigns each
           candidate a similarity in ``[0, 1]``. *Every* scored candidate is
           persisted to ``match_candidates`` (score + JSON features) so the
           decision is auditable, not just the ones that clear the bar.
        3. **cluster** — :func:`~icarus.core.matching.cluster` union-finds the
           pairs scoring ``>= threshold`` into connected components, so a chain
           ``a~b~c`` merges even without a direct ``a~c`` edge.
        4. **merge** — each multi-atom component becomes one bag whose
           ``canonical_key`` is the ``source_key`` of its smallest-id member
           and whose ``bags.score`` is the mean of that component's in-cluster
           match-edge scores; a ``"resolve"`` event carrying that confidence is
           logged. Every still-unresolved atom outside all components gets a
           1-atom singleton bag (score left NULL).

        ``threshold`` is the score cutoff for a candidate to count as a match
        edge. Results are fully auditable via the ``match_candidates`` rows,
        ``bags.score``, and the resolution event log.

        Returns ``{"clusters": C, "merges": E, "atoms_resolved": N}`` where
        ``C`` is the number of multi-atom bags created, ``E`` the number of
        match edges above ``threshold``, and ``N`` the number of atoms that
        were unresolved when the call started.
        """
        if not math.isfinite(threshold) or not 0.0 <= threshold <= 1.0:
            raise ValueError("threshold must be between 0.0 and 1.0")
        unresolved = set(self.unresolved_atoms(entity_type))
        if not unresolved:
            return {"clusters": 0, "merges": 0, "atoms_resolved": 0}

        # Load properties (for scoring) and source_key (for the canonical key)
        # once per unresolved atom, filtering the full entity_type set in memory.
        props: Dict[int, dict] = {}
        source_keys: Dict[int, str] = {}
        for atom_id, source_key, properties in self.conn.execute(
            "SELECT id, source_key, properties FROM atoms WHERE entity_type = ?",
            (entity_type,),
        ).fetchall():
            if atom_id in unresolved:
                props[atom_id] = json.loads(properties)
                source_keys[atom_id] = source_key

        # ── block ── keep only candidates whose BOTH ends are unresolved.
        cands = {
            (a, b)
            for (a, b) in candidate_pairs(self.conn, entity_type, blocking_keys)
            if a in unresolved and b in unresolved
        }

        # ── score ── persist every candidate; a >= threshold pair is an edge.
        now = datetime.now(timezone.utc).isoformat()
        match_edges: List[Tuple[int, int, float]] = []
        for a, b in cands:
            score, features = score_pair(entity_type, props[a], props[b])
            self.conn.execute(
                "INSERT OR IGNORE INTO match_candidates "
                "(entity_type, atom_a, atom_b, score, features, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (entity_type, a, b, score, json.dumps(features), now),
            )
            if score >= threshold:
                match_edges.append((a, b, score))

        # ── cluster ── connected components of the above-threshold edges.
        components = cluster([(a, b) for (a, b, _) in match_edges])

        # ── merge ── one bag per multi-atom component; the rest are singletons.
        clustered: Set[int] = set()
        for component in components:
            member_scores = [
                s for (a, b, s) in match_edges if a in component and b in component
            ]
            confidence: Optional[float] = (
                sum(member_scores) / len(member_scores) if member_scores else None
            )
            ordered = sorted(component)
            canonical_key = source_keys[ordered[0]]
            bag_id = self.create_bag(entity_type, ordered, canonical_key=canonical_key)
            self.conn.execute(
                "UPDATE bags SET score = ? WHERE id = ?", (confidence, bag_id)
            )
            self._log_event(
                "resolve",
                bag_id,
                ordered,
                reason=f"scored cluster (threshold={threshold})",
                confidence=confidence,
            )
            clustered.update(component)

        for atom_id in sorted(unresolved - clustered):
            self.create_bag(entity_type, [atom_id])

        self.conn.commit()
        return {
            "clusters": len(components),
            "merges": len(match_edges),
            "atoms_resolved": len(unresolved),
        }

    def unresolved_atoms(self, entity_type: str) -> List[int]:
        """Atoms not assigned to any bag."""
        rows = self.conn.execute(
            "SELECT a.id FROM atoms a "
            "LEFT JOIN bag_atoms ba ON a.id = ba.atom_id "
            "WHERE a.entity_type = ? AND ba.bag_id IS NULL",
            (entity_type,),
        ).fetchall()
        return [r[0] for r in rows]

    def _log_event(
        self, event_type: str, bag_id: int, atom_ids: List[int], reason: str = "",
        confidence: Optional[float] = None, operator: str = "auto",
    ) -> None:
        """Append to resolution_event_log. Never update or delete."""
        now = datetime.now(timezone.utc).isoformat()
        self.conn.execute(
            "INSERT INTO resolution_event_log "
            "(event_type, bag_id, atom_ids, reason, confidence, operator, timestamp) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (event_type, bag_id, json.dumps(atom_ids), reason, confidence, operator, now),
        )

    def close(self) -> None:
        self.conn.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()
