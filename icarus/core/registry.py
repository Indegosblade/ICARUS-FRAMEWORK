"""ICARUS Parser Registry — discovery, versioning, and quality-tier management."""

from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional

from icarus.parsers.base import BaseParser
from icarus.parsers.manifest import ParserManifest


@dataclass(frozen=True)
class ParserRegistration:
    """One atomic parser implementation, manifest, and discovery origin."""

    parser_cls: type
    manifest: Optional[ParserManifest]
    origin: str


class ParserRegistry:
    """Registry for parser discovery, quality-tier management, and most-specific-wins contest.

    Most-specific-wins contest:
        When multiple parsers return True from identify(), the one with the lowest
        specificity_level in its manifest wins. If no manifest exists, specificity
        defaults to 50 (mid-range). Confidence is the tie-break: higher confidence wins.
    """

    def __init__(self):
        self._registrations: Dict[str, ParserRegistration] = {}

    def register(
        self,
        parser_cls: type,
        manifest: Optional[ParserManifest] = None,
        *,
        origin: Optional[str] = None,
    ) -> None:
        """Register an implementation and its metadata as one atomic record.

        Parser names are unique. A second registration is rejected rather than
        replacing an implementation while retaining metadata from the first.
        """
        inst = parser_cls()
        name = inst.name
        resolved_origin = origin or (
            f"Python class {parser_cls.__module__}.{parser_cls.__qualname__}"
        )
        if manifest is not None and manifest.parser_id != name:
            raise ValueError(
                f"Parser name {name!r} does not match manifest parser_id "
                f"{manifest.parser_id!r} from {resolved_origin}"
            )
        existing = self._registrations.get(name)
        if existing is not None:
            raise ValueError(
                f"Duplicate parser name {name!r}: already registered from "
                f"{existing.origin}; rejected {resolved_origin}"
            )
        self._registrations[name] = ParserRegistration(
            parser_cls=parser_cls,
            manifest=manifest,
            origin=resolved_origin,
        )

    def detect(self, source: Path) -> Optional[str]:
        """Run identify() contest. Most-specific-wins: lowest specificity_level.
        Tie-break: highest confidence. Returns parser name or None."""
        candidates = []
        for name, registration in self._registrations.items():
            try:
                if registration.parser_cls().identify(source):
                    manifest = registration.manifest
                    spec = manifest.specificity_level if manifest else 50
                    conf = manifest.confidence if manifest else 0.5
                    candidates.append((spec, -conf, name))
            except (PermissionError, OSError):
                continue
        if not candidates:
            return None
        candidates.sort()
        return candidates[0][2]

    def get(self, name: str) -> BaseParser:
        """Return a parser instance by name. Raises ValueError if unknown."""
        if name not in self._registrations:
            available = list(self._registrations.keys()) or ["(none registered)"]
            raise ValueError(f"Unknown parser: '{name}'. Available: {available}")
        return self._registrations[name].parser_cls()

    def get_manifest(self, name: str) -> Optional[ParserManifest]:
        """Return the registered manifest for a parser, or None if it has none."""
        registration = self._registrations.get(name)
        return registration.manifest if registration is not None else None

    def list_all(self) -> List[dict]:
        """Return metadata dicts for all registered parsers."""
        results = []
        for name, registration in self._registrations.items():
            inst = registration.parser_cls()
            manifest = registration.manifest
            results.append({
                "name": name,
                "tier": manifest.quality_tier if manifest else "unknown",
                "description": inst.description,
                "version": manifest.version if manifest else "unknown",
                "specificity": manifest.specificity_level if manifest else 50,
                "origin": registration.origin,
            })
        return results

    def list_production(self) -> List[dict]:
        """Return metadata for parsers in the production quality tier."""
        return [p for p in self.list_all() if p["tier"] == "production"]

    def list_candidate(self) -> List[dict]:
        """Return metadata for parsers in the candidate quality tier."""
        return [p for p in self.list_all() if p["tier"] == "candidate"]
