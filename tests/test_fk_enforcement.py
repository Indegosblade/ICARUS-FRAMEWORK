"""Regression tests for foreign-key enforcement on every production write path."""

import ast
import importlib
import sqlite3
from pathlib import Path
from types import SimpleNamespace

import pytest

from icarus.core.pipeline import _verify_phase
from icarus.core.schema import initialize_database, open_db

PARSER_CASES = (
    ("icarus.parsers.windows", "WindowsParser"),
    ("icarus.parsers.linux", "LinuxParser"),
    ("icarus.parsers.macos", "MacosParser"),
    ("icarus.parsers.generic.archive_parser", "ArchiveParser"),
    ("icarus.parsers.generic.xml_parser", "XmlParser"),
    ("icarus.parsers.generic.sqlite_parser", "SqliteParser"),
    ("icarus.parsers.generic.binary_entropy_parser", "BinaryEntropyParser"),
    ("icarus.parsers.generic.json_parser", "JsonParser"),
    ("icarus.parsers.cloud.aws.cloudtrail", "CloudTrailParser"),
)


@pytest.mark.parametrize("module_name,class_name", PARSER_CASES)
def test_every_parser_entity_write_connection_enforces_foreign_keys(
    tmp_path, monkeypatch, module_name, class_name
):
    module = importlib.import_module(module_name)
    parser_class = getattr(module, class_name)
    source = tmp_path / "source"
    source.mkdir()
    db_path = tmp_path / "icarus.db"
    initialize_database(db_path)

    foreign_key_states = []

    def tracked_open_db(path, *args, **kwargs):
        conn = open_db(path, *args, **kwargs)
        foreign_key_states.append(conn.execute("PRAGMA foreign_keys").fetchone()[0])
        return conn

    monkeypatch.setattr(module, "open_db", tracked_open_db)
    parser_class().extract_entities(source, db_path)

    assert foreign_key_states
    assert set(foreign_key_states) == {1}


def test_verify_phase_rejects_existing_foreign_key_violation(tmp_path):
    db_path = tmp_path / "orphan.db"
    initialize_database(db_path)

    # Simulate corruption created by a legacy bare connection with FK checks off.
    conn = sqlite3.connect(str(db_path))
    conn.execute(
        "INSERT INTO binaries (file_id, bundle_id) VALUES (999999, 'orphan.binary')"
    )
    conn.commit()
    conn.close()

    parser = SimpleNamespace(verify=lambda _path: {"parser_check": "passed"})
    ctx = SimpleNamespace(output_db=db_path)
    with pytest.raises(ValueError, match=r"foreign key violation.*binaries"):
        _verify_phase(ctx, parser)


def test_verify_phase_records_clean_integrity_gate(tmp_path):
    db_path = tmp_path / "clean.db"
    initialize_database(db_path)

    parser = SimpleNamespace(verify=lambda _path: {"parser_check": "passed"})
    ctx = SimpleNamespace(output_db=db_path)

    assert _verify_phase(ctx, parser) == {
        "parser_check": "passed",
        "foreign_key_violations": 0,
    }


def _sqlite_connect_arguments(path: Path) -> list[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    arguments = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if (
            isinstance(func, ast.Attribute)
            and func.attr == "connect"
            and isinstance(func.value, ast.Name)
            and func.value.id == "sqlite3"
        ):
            arguments.append(ast.unparse(node.args[0]))
    return arguments


def test_no_parser_output_path_bypasses_open_db():
    parser_root = Path(__file__).parents[1] / "icarus" / "parsers"
    bare_connections = {
        path.relative_to(parser_root).as_posix(): _sqlite_connect_arguments(path)
        for path in parser_root.rglob("*.py")
        if _sqlite_connect_arguments(path)
    }

    # The sole raw parser connection reads an untrusted source SQLite file via
    # an immutable read-only URI. It is not an ICARUS output/write connection.
    assert bare_connections == {"generic/sqlite_parser.py": ["src_uri"]}


def test_pipeline_raw_connections_are_checkpoint_only():
    pipeline_path = Path(__file__).parents[1] / "icarus" / "core" / "pipeline.py"
    assert _sqlite_connect_arguments(pipeline_path) == [
        "str(self.checkpoint_db)",
        "str(self.checkpoint_db)",
        "str(self.checkpoint_db)",
        "str(self.checkpoint_db)",
        "str(self.checkpoint_db)",
    ]
