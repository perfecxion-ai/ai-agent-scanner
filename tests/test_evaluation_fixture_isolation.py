"""Synthetic harnesses must not load or reuse an operator evidence registry."""

import argparse
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace
from unittest.mock import Mock, patch

import pytest


ROOT = Path(__file__).resolve().parents[1]


def benchmark_module():
    spec = importlib.util.spec_from_file_location("isolated_queue_benchmark", ROOT / "scripts/benchmark-jobs.py")
    loaded = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(loaded)
    return loaded


@pytest.mark.parametrize("fixture", ["api", "real_lab", "offline_operator"])
def test_unit_fixtures_ignore_inherited_and_cached_operator_registry(tmp_path, fixture):
    private_path = str(tmp_path / "private-operator-profiles.json")
    program = r'''
import faulthandler
faulthandler.dump_traceback_later(8, repeat=True)
import sys
def phase(value):
    print("fixture-isolation-phase: " + value, file=sys.stderr, flush=True)

phase("import-support")
import importlib
import os
from pathlib import Path
import socket
import tempfile
from unittest.mock import patch
import pytest

private_path = os.environ["SCAN_EVIDENCE_PROFILES_FILE"]
original_open = os.open
def protected_open(path, *args, **kwargs):
    if os.fspath(path) == private_path:
        raise AssertionError("Operator registry must not be opened")
    return original_open(path, *args, **kwargs)

class OperatorRegistry:
    _profiles = {"operator-only": object()}
    def __getattr__(self, name):
        raise AssertionError("Cached operator registry must not be used")

def forbidden_reverse_dns(*args, **kwargs):
    raise AssertionError("Loopback fixture must not resolve a reverse DNS name")

name = sys.argv[1]
module_name = {
    "api": "tests.test_api_auth",
    "real_lab": "tests.test_beta_lab_workflow",
    "offline_operator": "tests.test_operator_workflow",
}[name]
phase("import-factory")
factory = getattr(importlib.import_module(module_name), name).__wrapped__
with patch.object(os, "open", protected_open), tempfile.TemporaryDirectory(prefix="scanner-isolation-") as directory:
    for cached in (False, True):
        label = "cached" if cached else "fresh"
        if cached:
            server = sys.modules["app"]
            operator_registry = OperatorRegistry()
            server._evidence_profiles = operator_registry
        fixture_directory = Path(directory) / str(cached)
        fixture_directory.mkdir()
        with pytest.MonkeyPatch.context() as changes:
            if name == "real_lab":
                changes.setattr(socket, "getfqdn", forbidden_reverse_dns)
                changes.setattr(socket, "gethostbyaddr", forbidden_reverse_dns)
            generator = factory(changes) if name == "api" else factory(changes, fixture_directory)
            try:
                phase(label + "-setup")
                server = next(generator)[0]
                phase(label + "-yielded")
                assert "SCAN_EVIDENCE_PROFILES_FILE" not in os.environ
                assert not server._evidence_profiles._profiles
            finally:
                phase(label + "-teardown")
                generator.close()
                phase(label + "-closed")
        assert os.environ["SCAN_EVIDENCE_PROFILES_FILE"] == private_path
        if cached:
            assert server._evidence_profiles is operator_registry
        phase(label + "-restored")
phase("done")
faulthandler.cancel_dump_traceback_later()
print("isolated-fixture-ok")
'''
    environment = {"PATH": os.defpath, "PYTHONDONTWRITEBYTECODE": "1",
                   "SCAN_EVIDENCE_PROFILES_FILE": private_path}
    try:
        completed = subprocess.run([sys.executable, "-c", program, fixture], cwd=ROOT, env=environment,
                                   capture_output=True, text=True, timeout=20, check=False)
    except subprocess.TimeoutExpired as exc:
        stderr = exc.stderr.decode("utf-8", errors="replace") if isinstance(exc.stderr, bytes) else exc.stderr or ""
        pytest.fail("Fixture isolation exceeded its 20-second deadline.\n" + stderr, pytrace=False)
    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert completed.stdout.strip() == "isolated-fixture-ok"
    assert "fixture-isolation-phase: done" in completed.stderr
    assert private_path not in completed.stdout + completed.stderr
    assert not Path(private_path).exists()


def test_queue_benchmark_ignores_inherited_registry_on_fresh_import(tmp_path):
    private_path = tmp_path / "private-operator-profiles.json"
    program = r'''
import importlib.util
import os
from pathlib import Path
import sys
from unittest.mock import patch
private_path = os.environ["SCAN_EVIDENCE_PROFILES_FILE"]
original_open = os.open
def protected_open(path, *args, **kwargs):
    if os.fspath(path) == private_path:
        raise AssertionError("Operator registry must not be opened")
    return original_open(path, *args, **kwargs)
spec = importlib.util.spec_from_file_location("queue_benchmark", Path("scripts/benchmark-jobs.py"))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
sys.argv = ["benchmark-jobs.py", "--jobs", "4", "--workers", "1", "--latency-ms", "0", "--timeout-seconds", "5"]
with patch.object(os, "open", protected_open):
    raise SystemExit(module.main())
'''
    environment = {"PATH": os.defpath, "PYTHONDONTWRITEBYTECODE": "1",
                   "SCAN_EVIDENCE_PROFILES_FILE": str(private_path)}
    completed = subprocess.run([sys.executable, "-c", program], cwd=ROOT, env=environment,
                               capture_output=True, text=True, timeout=20, check=False)
    assert completed.returncode == 0, completed.stdout + completed.stderr
    result = json.loads(completed.stdout)
    assert result["accepted"] and result["consistent_job_scan_report"]
    assert result["duplicate_claims"] == 0
    assert str(private_path) not in completed.stdout + completed.stderr
    assert not private_path.exists()


def test_queue_benchmark_rejects_cached_operator_registry_before_database_access(tmp_path, monkeypatch):
    enter = Mock(side_effect=AssertionError("Database access must not begin"))
    registry = SimpleNamespace(_profiles={"operator-only": object()})
    server = SimpleNamespace(_evidence_profiles=registry, app=SimpleNamespace(app_context=enter))
    monkeypatch.setitem(sys.modules, "app", server)
    private_path = str(tmp_path / "private-operator-profiles.json")
    monkeypatch.setenv("SCAN_EVIDENCE_PROFILES_FILE", private_path)
    with patch.object(sys, "path", sys.path.copy()):
        benchmark = benchmark_module()
    args = argparse.Namespace(jobs=4, workers=1, latency_ms=0, timeout_seconds=1)
    before = dict(os.environ)
    with patch.dict(os.environ):
        with pytest.raises(ValueError, match="empty evidence registry") as caught:
            benchmark.run(args, tmp_path / "never-created.sqlite")
        assert "SCAN_EVIDENCE_PROFILES_FILE" not in os.environ
        assert private_path not in str(caught.value)
        assert server._evidence_profiles is registry
        enter.assert_not_called()
    assert dict(os.environ) == before
    assert not (tmp_path / "never-created.sqlite").exists()
