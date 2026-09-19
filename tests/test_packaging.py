"""Regression: built artifacts must ship parser manifests, the manifest JSON
Schema, and the parser catalogs — not only the .py files.

Guards the packaging defect where ``[tool.setuptools.package-data]`` declared only
``py.typed``, so the wheel and sdist shipped no ``*.yaml`` / ``*.json`` runtime data.
On such an install, ``icarus parser list`` reported every parser as tier "unknown"
and ``icarus parser validate`` raised FileNotFoundError on the schema, while CI stayed
green because it installs the project editable (files present on disk in the source
tree). These tests build the real artifacts and assert the data is present.
"""
import subprocess
import sys
import tarfile
import venv
import zipfile
from pathlib import Path

import pytest

pytest.importorskip("build", reason="`pip install build` to run packaging tests")

REPO_ROOT = Path(__file__).resolve().parent.parent

EXPECTED_YAML = {
    "icarus/parsers/linux.yaml",
    "icarus/parsers/macos.yaml",
    "icarus/parsers/windows.yaml",
    "icarus/parsers/cloud/aws/cloudtrail.yaml",
    "icarus/parsers/generic/archive_parser.yaml",
    "icarus/parsers/generic/binary_entropy_parser.yaml",
    "icarus/parsers/generic/json_parser.yaml",
    "icarus/parsers/generic/sqlite_parser.yaml",
    "icarus/parsers/generic/xml_parser.yaml",
}
EXPECTED_JSON = {
    "icarus/parsers/schema/parser_manifest.schema.json",
    "icarus/parsers/catalog/parsers.json",
    "icarus/parsers/catalog/parsers-devel.json",
}
EXPECTED = EXPECTED_YAML | EXPECTED_JSON
SELFTEST_ROOT = REPO_ROOT / "icarus" / "parsers" / "selftest"
EXPECTED_SELFTEST = {
    path.relative_to(REPO_ROOT).as_posix()
    for path in SELFTEST_ROOT.rglob("*")
    if path.is_file()
}


@pytest.fixture(scope="module")
def built_dists(tmp_path_factory):
    # `build` is a declared dev dependency, so a build that RUNS and FAILS is a real
    # failure, not a reason to skip: skipping a failed build would let a broken
    # package pass green — exactly the defect these tests guard. The module-level
    # importorskip only skips when the build tool itself is absent. Use build
    # isolation so the declared PEP 517 backend requirements are installed on every
    # runner; setup-python does not guarantee setuptools is present in the test env.
    out = tmp_path_factory.mktemp("dist")
    try:
        proc = subprocess.run(
            [
                sys.executable,
                "-m",
                "build",
                "--outdir",
                str(out),
                str(REPO_ROOT),
            ],
            capture_output=True, text=True,
        )
    except FileNotFoundError as exc:  # interpreter cannot run `-m build`
        pytest.fail(f"could not invoke `python -m build`: {exc}")
    if proc.returncode != 0:
        pytest.fail(
            f"building the distributions failed (exit {proc.returncode}):\n"
            f"STDOUT:\n{proc.stdout[-1500:]}\nSTDERR:\n{proc.stderr[-2000:]}"
        )
    whl = next(iter(out.glob("*.whl")), None)
    sdist = next(iter(out.glob("*.tar.gz")), None)
    assert whl and sdist, f"build succeeded but produced no wheel/sdist in {out}"
    return whl, sdist


def test_wheel_ships_parser_runtime_data(built_dists):
    whl, _ = built_dists
    names = set(zipfile.ZipFile(whl).namelist())
    missing = (EXPECTED | EXPECTED_SELFTEST) - names
    assert not missing, f"wheel is missing runtime data files: {sorted(missing)}"


def test_sdist_ships_parser_runtime_data(built_dists):
    _, sdist = built_dists
    with tarfile.open(sdist) as tf:
        # entries are prefixed with 'icarus_framework-<version>/'; strip it.
        names = {"/".join(n.split("/")[1:]) for n in tf.getnames()}
    missing = (EXPECTED | EXPECTED_SELFTEST) - names
    assert not missing, f"sdist is missing runtime data files: {sorted(missing)}"


def test_wheel_installed_parser_test_runs_outside_checkout(built_dists, tmp_path):
    """The advertised self-test must use wheel data, not the repository tests tree."""
    whl, _ = built_dists
    env_dir = tmp_path / "venv"
    venv.EnvBuilder(with_pip=True, system_site_packages=True).create(env_dir)
    python = env_dir / ("Scripts/python.exe" if sys.platform == "win32" else "bin/python")

    install = subprocess.run(
        [str(python), "-m", "pip", "install", "--no-deps", str(whl)],
        capture_output=True,
        text=True,
    )
    assert install.returncode == 0, install.stderr

    outside_checkout = tmp_path / "outside-checkout"
    outside_checkout.mkdir()
    proc = subprocess.run(
        [str(python), "-I", "-m", "icarus", "parser", "test", "windows"],
        cwd=outside_checkout,
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0, f"STDOUT:\n{proc.stdout}\nSTDERR:\n{proc.stderr}"
    assert proc.stdout.count("[PASS]") == 4
