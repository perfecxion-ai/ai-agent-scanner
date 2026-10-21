"""Safety checks for the optional browser harness, without Playwright installed."""

from contextlib import nullcontext
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace
from unittest.mock import patch

import pytest


def load_script(name):
    path = Path(__file__).resolve().parents[1] / "scripts" / name
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def fixture_module():
    return load_script("dashboard-browser-fixture.py")


@pytest.fixture
def smoke_module():
    return load_script("dashboard-browser-smoke.py")


def engine(database, dialect="sqlite", query=None):
    return SimpleNamespace(dialect=SimpleNamespace(name=dialect),
                           url=SimpleNamespace(database=database, query=query or {}))


@pytest.mark.parametrize("actual,dialect,query", [
    ("foreign.db", "sqlite", {}), (":memory:", "sqlite", {}), (None, "sqlite", {}),
    ("fixture.db", "postgresql", {}), ("fixture.db", "sqlite", {"uri": "true"}),
])
def test_fixture_rejects_wrong_engine_before_dispatcher(fixture_module, tmp_path, actual, dialect, query):
    expected = tmp_path / "fixture.db"
    actual = str(tmp_path / actual) if actual not in (None, ":memory:") else actual
    with pytest.raises(ValueError, match="owned temporary SQLite"):
        fixture_module.guard_database(engine(actual, dialect, query), expected)
    fixture_module.guard_database(engine(str(expected)), expected)


def test_fixture_rejects_nonempty_wrong_parent_and_symlink_directories(fixture_module, tmp_path, monkeypatch):
    monkeypatch.setattr(fixture_module.tempfile, "gettempdir", lambda: str(tmp_path))
    directory = tmp_path / "ai-scanner-browser-db-test"
    directory.mkdir()
    assert fixture_module.fixture_database(directory) == directory / "fixture.db"
    (directory / "existing.db").touch()
    with pytest.raises(ValueError, match="new empty"):
        fixture_module.fixture_database(directory)
    other = tmp_path / "other"
    other.mkdir()
    link = tmp_path / "ai-scanner-browser-db-link"
    link.symlink_to(other, target_is_directory=True)
    for invalid in (other, link, directory / "nested", Path("relative")):
        with pytest.raises(ValueError, match="new empty"):
            fixture_module.fixture_database(invalid)


def test_fixture_engine_guard_precedes_any_startup(fixture_module, tmp_path, monkeypatch):
    expected = tmp_path / "fixture.db"
    monkeypatch.setattr(fixture_module, "fixture_database", lambda directory: expected)
    calls = []
    fake = SimpleNamespace(app=SimpleNamespace(app_context=nullcontext), db=SimpleNamespace(engine=engine("foreign.db")),
                           start_job_dispatcher=lambda: calls.append("started"))
    monkeypatch.setitem(sys.modules, "app", fake)
    previous = dict(os.environ)
    with patch.dict(os.environ), patch.object(sys, "path", sys.path.copy()):
        with pytest.raises(ValueError, match="owned temporary SQLite"):
            fixture_module.main(tmp_path)
    assert calls == []
    assert dict(os.environ) == previous


def test_fixture_disables_inherited_evidence_registry_before_import(fixture_module, tmp_path, monkeypatch):
    monkeypatch.setenv("SCAN_EVIDENCE_PROFILES_FILE", "/not-accessed/operator-registry.json")
    monkeypatch.setattr(fixture_module, "fixture_database", lambda directory: tmp_path / "fixture.db")
    observed = []

    def context():
        observed.append(os.environ.get("SCAN_EVIDENCE_PROFILES_FILE"))
        return nullcontext()

    fake = SimpleNamespace(app=SimpleNamespace(app_context=context), db=SimpleNamespace(engine=engine("foreign.db")))
    monkeypatch.setitem(sys.modules, "app", fake)
    with patch.dict(os.environ), patch.object(sys, "path", sys.path.copy()):
        with pytest.raises(ValueError, match="owned temporary SQLite"):
            fixture_module.main(tmp_path)
    assert observed == [""]
    assert os.environ["SCAN_EVIDENCE_PROFILES_FILE"] == "/not-accessed/operator-registry.json"


@pytest.mark.parametrize("large,distinct,total,checks", [(False, False, 18, 7), (True, True, 110, 1), (True, False, 110, 1)])
def test_presentation_fixture_records_are_bounded_and_versioned(fixture_module, large, distinct, total, checks):
    from src.core.contracts import validate_scan_result
    from src.core.pipeline import to_sarif

    report = fixture_module.prompt_report("fixture-presentation", large=large, distinct=distinct)
    assert validate_scan_result(report) is report
    agent = report["agents"][0]
    assert len(agent["vulnerabilities"]) == total
    assert len(agent["checks"]) == checks
    assert len({finding["id"] for finding in agent["vulnerabilities"]}) == total
    assert len(to_sarif(report)["runs"][0]["results"]) == total
    assert max(len(finding["payload"]) for finding in agent["vulnerabilities"]) <= 20000
    assert report["summary"]["overall_risk_score"] == 70


def test_startup_handshake_validates_complete_bounded_messages(smoke_module):
    messages = [(dict(port=12345, control_key="a" * 48), None),
                (dict(port=True, control_key="a" * 48), ValueError),
                (dict(port=12345, control_key="short"), ValueError)]
    for message, error in messages:
        reader, writer = os.pipe()
        with os.fdopen(reader, "rb") as stream:
            try:
                os.write(writer, json.dumps(message).encode() + b"\n")
                if error:
                    with pytest.raises(error):
                        smoke_module.read_startup(stream, timeout=.1)
                else:
                    assert smoke_module.read_startup(stream, timeout=.1) == message
            finally:
                os.close(writer)


def test_startup_partial_line_times_out_and_oversized_message_fails(smoke_module):
    for payload, error in ((b'{"port":', TimeoutError), (b"x" * 4097, ValueError)):
        reader, writer = os.pipe()
        with os.fdopen(reader, "rb") as stream:
            try:
                os.write(writer, payload)
                with pytest.raises(error):
                    smoke_module.read_startup(stream, timeout=.02)
            finally:
                os.close(writer)


def test_startup_eof_fails_without_waiting(smoke_module):
    reader, writer = os.pipe()
    os.close(writer)
    with os.fdopen(reader, "rb") as stream:
        with pytest.raises(RuntimeError, match="before its startup handshake"):
            smoke_module.read_startup(stream, timeout=.1)


@pytest.mark.parametrize("forced", [False, True])
def test_fixture_parent_cleans_database_and_reaps_child_on_failure(smoke_module, monkeypatch, forced):
    class Process:
        def __init__(self, arguments, **kwargs):
            self.directory = Path(arguments[-1])
            self.directory.joinpath("fixture.db").touch()
            self.stdout = io.BytesIO()
            self.calls = []

        def terminate(self):
            self.calls.append("terminate")

        def kill(self):
            self.calls.append("kill")

        def wait(self, timeout):
            self.calls.append("wait")
            if forced and "kill" not in self.calls:
                raise subprocess.TimeoutExpired("fixture", timeout)

    monkeypatch.setattr(smoke_module.subprocess, "Popen", Process)
    monkeypatch.setattr(smoke_module, "read_startup", lambda stream: dict(port=1, control_key="a" * 48))
    with pytest.raises(AssertionError, match="deliberate"):
        with smoke_module.fixture_server(io.StringIO()) as (process, startup, directory):
            assert Path(directory).is_dir()
            raise AssertionError("deliberate")
    assert process.calls == (["terminate", "wait", "kill", "wait"] if forced else ["terminate", "wait"])
    assert process.stdout.closed
    assert not Path(directory).exists()


def test_fixture_parent_cleans_after_handshake_eof(smoke_module, monkeypatch):
    processes = []

    class Process:
        def __init__(self, arguments, **kwargs):
            self.directory = Path(arguments[-1])
            self.stdout = io.BytesIO()
            self.reaped = False
            processes.append(self)

        def terminate(self):
            pass

        def wait(self, timeout):
            self.reaped = True

    def eof(stream):
        raise RuntimeError("handshake EOF")

    monkeypatch.setattr(smoke_module.subprocess, "Popen", Process)
    monkeypatch.setattr(smoke_module, "read_startup", eof)
    with pytest.raises(RuntimeError, match="handshake EOF"):
        with smoke_module.fixture_server(io.StringIO()):
            pytest.fail("An incomplete startup cannot yield a server")
    assert len(processes) == 1 and processes[0].reaped and processes[0].stdout.closed
    assert not processes[0].directory.exists()


def test_browser_parent_canonicalizes_temporary_ancestor(smoke_module, fixture_module, tmp_path, monkeypatch):
    real_temp = tmp_path / "real-temp"
    real_temp.mkdir()
    alias = tmp_path / "temp-alias"
    alias.symlink_to(real_temp, target_is_directory=True)
    monkeypatch.setattr(smoke_module.tempfile, "gettempdir", lambda: str(alias))

    class Process:
        def __init__(self, arguments, **kwargs):
            self.directory = Path(arguments[-1])
            assert self.directory.parent == real_temp
            fixture_module.fixture_database(self.directory)
            self.stdout = io.BytesIO()

        def terminate(self):
            pass

        def wait(self, timeout):
            pass

    monkeypatch.setattr(smoke_module.subprocess, "Popen", Process)
    monkeypatch.setattr(smoke_module, "read_startup", lambda stream: dict(port=1, control_key="a" * 48))
    with smoke_module.fixture_server(io.StringIO()) as (_, _, directory):
        assert Path(directory).parent == real_temp
    assert alias.is_symlink() and not list(real_temp.iterdir())
