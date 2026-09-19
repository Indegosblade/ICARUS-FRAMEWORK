"""Tests for Phase 3.2 — Parser registry."""

import json
import tempfile
from pathlib import Path

import pytest

CATALOG_DIR = Path(__file__).parent.parent / "icarus" / "parsers" / "catalog"


def _make_source_with_exe():
    """Create a temp dir with a fake .exe file (triggers Windows parser)."""
    d = tempfile.mkdtemp()
    (Path(d) / "test.exe").write_bytes(b"MZ" + b"\x00" * 100)
    return Path(d)


def _make_linux_source():
    """Create a temp dir with Linux markers."""
    d = tempfile.mkdtemp()
    (Path(d) / "etc").mkdir()
    (Path(d) / "etc" / "passwd").write_text("root:x:0:0:root:/root:/bin/bash\n")
    (Path(d) / "usr").mkdir()
    (Path(d) / "usr" / "bin").mkdir()
    return Path(d)


def test_registry_detect_windows():
    from icarus.parsers import detect_parser

    src = _make_source_with_exe()
    assert detect_parser(src) == "windows"


def test_registry_detect_linux():
    from icarus.parsers import detect_parser

    src = _make_linux_source()
    assert detect_parser(src) == "linux"


def test_registry_specificity_contest():
    """Two parsers both match; lower specificity_level wins."""
    from icarus.core.registry import ParserRegistry
    from icarus.parsers.base import BaseParser
    from icarus.parsers.manifest import ParserManifest

    class HighSpecParser(BaseParser):
        @property
        def name(self):
            return "high_spec"

        @property
        def description(self):
            return "high specificity"

        def identify(self, source):
            return True

        def extract_entities(self, source, db_path):
            return {}

        def extract_relationships(self, source, db_path):
            return {}

    class LowSpecParser(BaseParser):
        @property
        def name(self):
            return "low_spec"

        @property
        def description(self):
            return "low specificity"

        def identify(self, source):
            return True

        def extract_entities(self, source, db_path):
            return {}

        def extract_relationships(self, source, db_path):
            return {}

    registry = ParserRegistry()

    high_manifest = ParserManifest(
        parser_id="high_spec", version="1.0.0", spec_version="icarus-parser/1.0",
        author="test", license="MIT", quality_tier="production",
        description="high specificity", identify={"specificity_level": 80},
        consumes=[], produces={"entity_types": ["files"]},
        reliability="C", default_confidence=0.5,
    )
    low_manifest = ParserManifest(
        parser_id="low_spec", version="1.0.0", spec_version="icarus-parser/1.0",
        author="test", license="MIT", quality_tier="production",
        description="low specificity", identify={"specificity_level": 5},
        consumes=[], produces={"entity_types": ["files"]},
        reliability="C", default_confidence=0.5,
    )

    registry.register(HighSpecParser, high_manifest)
    registry.register(LowSpecParser, low_manifest)

    result = registry.detect(Path(tempfile.mkdtemp()))
    assert result == "low_spec"


def test_registry_list_production():
    from icarus.parsers import get_registry

    prod = get_registry().list_production()
    names = [p["name"] for p in prod]
    assert "windows" in names
    assert "linux" in names
    for p in prod:
        assert p["tier"] == "production"


def test_registry_get_unknown_raises():
    from icarus.parsers import get_parser

    with pytest.raises(ValueError, match="Unknown parser"):
        get_parser("nonexistent_parser_xyz")


def test_registry_catalog_parsers_exist():
    parsers_json = CATALOG_DIR / "parsers.json"
    devel_json = CATALOG_DIR / "parsers-devel.json"
    assert parsers_json.exists(), "parsers.json not found"
    assert devel_json.exists(), "parsers-devel.json not found"

    prod = json.loads(parsers_json.read_text())
    assert isinstance(prod, list)
    assert len(prod) >= 2

    devel = json.loads(devel_json.read_text())
    assert isinstance(devel, list)


def _manifest(parser_id):
    from icarus.parsers.manifest import ParserManifest

    return ParserManifest(
        parser_id=parser_id, version="1.0.0", spec_version="icarus-parser/1.0",
        author="test", license="MIT", quality_tier="production",
        description="fixture", identify={"specificity_level": 10},
        consumes=[], produces={"entity_types": ["files"]},
        reliability="C", default_confidence=0.5,
    )


def _parser_class(name, description):
    from icarus.parsers.base import BaseParser

    class FixtureParser(BaseParser):
        @property
        def name(self):
            return name

        @property
        def description(self):
            return description

        def identify(self, source):
            return True

        def extract_entities(self, source, db_path):
            return {}

        def extract_relationships(self, source, db_path):
            return {}

    return FixtureParser


def test_registry_rejects_builtin_entrypoint_collision_atomically():
    from icarus.core.registry import ParserRegistry

    registry = ParserRegistry()
    builtin = _parser_class("collision", "built in")
    plugin = _parser_class("collision", "plugin")
    manifest = _manifest("collision")
    registry.register(builtin, manifest, origin="module icarus.parsers.collision")

    with pytest.raises(ValueError) as exc_info:
        registry.register(plugin, None, origin="entry point example:collision")

    message = str(exc_info.value)
    assert "module icarus.parsers.collision" in message
    assert "entry point example:collision" in message
    assert registry.get("collision").description == "built in"
    assert registry.get_manifest("collision") is manifest


def test_registry_rejects_duplicate_manifestless_parsers():
    from icarus.core.registry import ParserRegistry

    registry = ParserRegistry()
    first = _parser_class("duplicate", "first")
    second = _parser_class("duplicate", "second")
    registry.register(first, origin="module first")

    with pytest.raises(ValueError, match="module first.*module second"):
        registry.register(second, origin="module second")

    assert registry.get("duplicate").description == "first"
    assert registry.get_manifest("duplicate") is None


def test_registry_rejects_manifest_parser_id_mismatch_without_mutating_state():
    from icarus.core.registry import ParserRegistry

    registry = ParserRegistry()
    parser = _parser_class("implementation-name", "fixture")

    with pytest.raises(ValueError, match="implementation-name.*manifest-name"):
        registry.register(parser, _manifest("manifest-name"), origin="module mismatch")

    with pytest.raises(ValueError, match="Unknown parser"):
        registry.get("implementation-name")
