"""Regression: built artifacts must ship parser manifests, the manifest JSON
Schema, and the parser catalogs — not only the .py files.

Guards the packaging defect where ``[tool.setuptools.package-data]`` declared only
``py.typed``, so the wheel and sdist shipped no ``*.yaml`` / ``*.json`` runtime data.
On such an install, ``icarus parser list`` reported every parser as tier "unknown"
and ``icarus parser validate`` raised FileNotFoundError on the schema, while CI stayed
green because it installs the project editable (files present on disk in the source
tree). These tests build the real artifacts and assert the data is present.
"""
import os
import shutil
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
EXPECTED |= {
    "icarus/gui/assets/index.html",
    "icarus/gui/assets/app.js",
    "icarus/gui/assets/style.css",
}
SELFTEST_ROOT = REPO_ROOT / "icarus" / "parsers" / "selftest"
EXPECTED_SELFTEST = {
    path.relative_to(REPO_ROOT).as_posix()
    for path in SELFTEST_ROOT.rglob("*")
    if path.is_file() and "__pycache__" not in path.parts
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
    # Exercise exclusion even on CI, where local-only plugins are absent. Build
    # from a disposable tree containing a synthetic private package; never copy
    # the developer's real private parsers into temporary release artifacts.
    source = tmp_path_factory.mktemp("package-source") / "icarus-framework"
    shutil.copytree(
        REPO_ROOT, source,
        ignore=shutil.ignore_patterns(
            ".git", ".venv", "venv", "env", "build", "dist", "*.egg-info",
            "__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache",
            "private", "prompts", "rootfs", "extracted", "reports", "output",
        ),
    )
    private = source / "icarus" / "parsers" / "private"
    private.mkdir()
    (private / "__init__.py").write_text("# synthetic local-only package\n")
    (private / "sentinel.yaml").write_text("private: synthetic-only\n")
    try:
        proc = subprocess.run(
            [
                sys.executable,
                "-m",
                "build",
                "--outdir",
                str(out),
                str(source),
            ],
            capture_output=True, text=True, timeout=300,
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
    with zipfile.ZipFile(whl) as archive:
        names = set(archive.namelist())
    missing = (EXPECTED | EXPECTED_SELFTEST) - names
    assert not missing, f"wheel is missing runtime data files: {sorted(missing)}"
    assert not any(name.startswith("icarus/parsers/private/") for name in names), (
        "wheel contains local-only private parser files"
    )
    assert not any("__pycache__/" in name or name.endswith(".pyc") for name in names)


def test_sdist_ships_parser_runtime_data(built_dists):
    _, sdist = built_dists
    with tarfile.open(sdist) as tf:
        # entries are prefixed with 'icarus_framework-<version>/'; strip it.
        names = {"/".join(n.split("/")[1:]) for n in tf.getnames()}
    missing = (EXPECTED | EXPECTED_SELFTEST) - names
    assert not missing, f"sdist is missing runtime data files: {sorted(missing)}"
    assert not any(name.startswith("icarus/parsers/private/") for name in names), (
        "sdist contains local-only private parser files"
    )
    assert not any("__pycache__/" in name or name.endswith(".pyc") for name in names)


def test_wheel_installed_parser_test_runs_outside_checkout(built_dists, tmp_path):
    """The advertised self-test must use wheel data, not the repository tests tree."""
    whl, _ = built_dists
    env_dir = tmp_path / "venv"
    # Runtime dependencies must come from the wheel's metadata. Inheriting the
    # developer environment can hide an undeclared dependency or a stale HYGEIA.
    venv.EnvBuilder(with_pip=True).create(env_dir)
    python = env_dir / ("Scripts/python.exe" if sys.platform == "win32" else "bin/python")

    install = subprocess.run(
        [str(python), "-m", "pip", "install", str(whl)],
        capture_output=True,
        text=True,
        timeout=300,
    )
    assert install.returncode == 0, install.stderr

    outside_checkout = tmp_path / "outside-checkout"
    outside_checkout.mkdir()
    # The installed module and distribution metadata must identify the same release.
    # Run isolated from the checkout so an editable install cannot mask a mismatch.
    version = subprocess.run(
        [str(python), "-I", "-c",
         "from importlib.metadata import version; import icarus; "
         "assert icarus.__version__ == version('icarus-framework') == '4.0.0b2'"],
        cwd=outside_checkout, capture_output=True, text=True, timeout=30,
    )
    assert version.returncode == 0, version.stderr
    for parser in (
        "windows", "linux", "macos", "cloud/aws/cloudtrail", "generic/json",
        "generic/xml", "generic/sqlite", "generic/archive", "generic/binary",
    ):
        proc = subprocess.run(
            [str(python), "-I", "-m", "icarus", "parser", "test", parser],
            cwd=outside_checkout,
            capture_output=True,
            text=True,
            timeout=120,
        )
        assert proc.returncode == 0, (
            f"{parser}: STDOUT:\n{proc.stdout}\nSTDERR:\n{proc.stderr}"
        )
        assert proc.stdout.count("[PASS]") == 4, f"{parser}: {proc.stdout}"

    gui_smoke = """
import faulthandler
faulthandler.enable()
faulthandler.dump_traceback_later(20)
import http.client
import json
import socket
import sys
import threading
from pathlib import Path
from icarus.core.schema import initialize_database
from icarus.gui.server import ExplorerServer

def forbidden_hostname_lookup(*args, **kwargs):
    raise AssertionError('Loopback startup must not call socket.getfqdn')

socket.getfqdn = forbidden_hostname_lookup
print('Installed GUI: initializing database', file=sys.stderr, flush=True)
database = Path('installed-gui.db')
initialize_database(database)
with ExplorerServer(database, allow_unverified=True) as server:
    assert server.server_name == '127.0.0.1'
    assert server.server_port == server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        for path in ('/', '/app.js', '/style.css', '/api/summary'):
            print('Installed GUI: GET ' + path, file=sys.stderr, flush=True)
            connection = http.client.HTTPConnection('127.0.0.1', server.server_port, timeout=5)
            try:
                headers = {}
                if path == '/api/summary':
                    headers['Authorization'] = 'Bearer ' + server.token
                connection.request('GET', path, headers=headers)
                response = connection.getresponse()
                body = response.read()
                assert response.status == 200 and body
                if path == '/api/summary':
                    assert json.loads(body)['tables']['files'] == 0
            finally:
                connection.close()
    finally:
        print('Installed GUI: shutting down server', file=sys.stderr, flush=True)
        server.shutdown()
        thread.join(timeout=5)
        assert not thread.is_alive()
faulthandler.cancel_dump_traceback_later()
print('Installed GUI: assets, authorized API, and shutdown passed', file=sys.stderr, flush=True)
"""
    # The explorer is loopback-only. A smoke client must not consult environment
    # or OS proxy discovery (which urllib performs before its socket timeout).
    # Poison proxy settings to exercise that boundary in the installed wheel.
    gui_env = os.environ.copy()
    for variable in (
        "http_proxy", "HTTP_PROXY", "https_proxy", "HTTPS_PROXY", "all_proxy", "ALL_PROXY",
    ):
        gui_env[variable] = "http://127.0.0.1:1"
    gui_env.update({"no_proxy": "", "NO_PROXY": ""})
    try:
        proc = subprocess.run(
            [str(python), "-I", "-c", gui_smoke], cwd=outside_checkout,
            env=gui_env, capture_output=True, text=True, timeout=30,
        )
    except subprocess.TimeoutExpired as exc:
        # TimeoutExpired may return bytes even with text=True. Keep the staged
        # progress and delayed thread dump, instead of losing the failure site.
        stdout = (
            exc.stdout.decode(errors="replace") if isinstance(exc.stdout, bytes) else exc.stdout
        )
        stderr = (
            exc.stderr.decode(errors="replace") if isinstance(exc.stderr, bytes) else exc.stderr
        )
        pytest.fail(f"Installed GUI exceeded 30 seconds:\nSTDOUT:\n{stdout}\nSTDERR:\n{stderr}")
    assert proc.returncode == 0, f"Installed GUI: {proc.stdout}\n{proc.stderr}"
