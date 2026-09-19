"""ICARUS parsers — pluggable data source modules.

Parsers are discovered automatically at import time; the engine references no
parser by name. Every concrete :class:`BaseParser` subclass found anywhere
under this package is registered — including local-only parsers placed in the
gitignored ``icarus/parsers/private/`` package — as is any parser advertised
through the ``icarus.parsers`` entry-point group by an installed distribution.
A parser's manifest is its sibling ``<module>.yaml`` when one is present.

Discovery failures (a broken or half-written local parser, an unloadable
manifest) are logged and skipped, never silently swallowed, so a bad plugin
degrades a single parser instead of hiding the whole registry.
"""

import importlib
import inspect
import logging
import pkgutil
from pathlib import Path
from typing import Iterator, Optional

from icarus.core.registry import ParserRegistry
from icarus.parsers.base import BaseParser
from icarus.parsers.manifest import ParserManifest, load_manifest

log = logging.getLogger("icarus.parsers")

_REGISTRY = ParserRegistry()
_PARSERS_DIR = Path(__file__).parent

# Framework infrastructure that lives in this package but is not a parser.
_SKIP_LEAF = {"base", "manifest", "testing", "macho"}
_SKIP_PKG = {"catalog", "schema"}


def _concrete_parsers(module: object) -> Iterator[type]:
    """Yield concrete BaseParser subclasses actually defined in ``module``."""
    for _, obj in inspect.getmembers(module, inspect.isclass):
        if (
            issubclass(obj, BaseParser)
            and obj is not BaseParser
            and not inspect.isabstract(obj)
            and obj.__module__ == getattr(module, "__name__", None)
        ):
            yield obj


def _manifest_for(module: object) -> Optional[ParserManifest]:
    """Load the sibling ``<module>.yaml`` manifest, or None if absent/invalid."""
    module_file = getattr(module, "__file__", None)
    if not module_file:
        return None
    manifest_path = Path(module_file).with_suffix(".yaml")
    if not manifest_path.exists():
        return None
    try:
        return load_manifest(manifest_path)
    except Exception as exc:  # bad YAML / missing jsonschema must warn, not crash import
        log.warning("Parser manifest %s failed to load: %s", manifest_path.name, exc)
        return None


def _register(
    parser_cls: type, manifest: Optional[ParserManifest], *, origin: str
) -> None:
    try:
        _REGISTRY.register(parser_cls, manifest, origin=origin)
    except Exception as exc:  # a parser whose __init__/name fails must not abort discovery
        log.warning(
            "Parser %s failed to register: %s",
            getattr(parser_cls, "__name__", parser_cls),
            exc,
        )


def _register_directory_parsers() -> None:
    """Walk this package tree and register every parser class found."""
    def _on_error(name: str) -> None:
        log.warning("Could not import parser package %s during discovery", name)

    modules = sorted(
        pkgutil.walk_packages(
            [str(_PARSERS_DIR)], prefix=__name__ + ".", onerror=_on_error
        ),
        key=lambda item: item.name,
    )
    for modinfo in modules:
        segments = modinfo.name.split(".")
        if modinfo.ispkg or segments[-1] in _SKIP_LEAF or _SKIP_PKG.intersection(segments):
            continue
        try:
            module = importlib.import_module(modinfo.name)
        except Exception as exc:  # a broken local parser must not break the framework
            log.warning("Skipping parser module %s: %s", modinfo.name, exc)
            continue
        manifest = _manifest_for(module)
        for cls in _concrete_parsers(module):
            module_file = getattr(module, "__file__", "unknown path")
            _register(
                cls,
                manifest,
                origin=f"module {module.__name__} ({module_file})",
            )


def _register_entrypoint_parsers() -> None:
    """Register parsers advertised via the ``icarus.parsers`` entry-point group."""
    try:
        from importlib.metadata import entry_points

        eps = sorted(
            entry_points(group="icarus.parsers"),
            key=lambda ep: (ep.name, ep.value),
        )
    except Exception as exc:  # older metadata backends / none installed
        log.debug("No entry-point parsers available: %s", exc)
        return
    for ep in eps:
        try:
            loaded = ep.load()
        except Exception as exc:
            log.warning("Skipping entry-point parser %s: %s", ep.name, exc)
            continue
        candidates = [loaded] if inspect.isclass(loaded) else list(_concrete_parsers(loaded))
        for cls in candidates:
            if inspect.isclass(cls) and issubclass(cls, BaseParser) and not inspect.isabstract(cls):
                distribution = getattr(getattr(ep, "dist", None), "name", "unknown distribution")
                _register(
                    cls,
                    None,
                    origin=f"entry point {distribution}:{ep.name} ({ep.value})",
                )


_register_directory_parsers()
_register_entrypoint_parsers()


def get_parser(name: str) -> BaseParser:
    """Get a parser instance by name."""
    return _REGISTRY.get(name)


def detect_parser(source: Path) -> Optional[str]:
    """Auto-detect parser for a source path. Returns parser name or None."""
    return _REGISTRY.detect(source)


def list_parsers() -> dict:
    """List all registered parsers with descriptions."""
    return {p["name"]: p["description"] for p in _REGISTRY.list_all()}


def get_registry() -> ParserRegistry:
    """Get the global parser registry."""
    return _REGISTRY
