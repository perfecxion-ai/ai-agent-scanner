"""The acceptance command never accepts an operator database path."""

from contextlib import closing, contextmanager
import importlib.util
import io
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
from unittest.mock import Mock
from unittest.mock import patch

import pytest
from sqlalchemy import create_engine, inspect
from sqlalchemy.pool import StaticPool

from src.core import schema
from src.core.inventory_generation import TRIGGER_DEFINITIONS, register_inventory_metadata
from src.core.asset_group_storage import TRIGGER_DEFINITIONS as group_triggers, register_asset_group_metadata
from tests.historical_schema import historical_metadata


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "acceptance-backup-restore.py"
spec = importlib.util.spec_from_file_location("backup_acceptance", SCRIPT)
acceptance = importlib.util.module_from_spec(spec)
spec.loader.exec_module(acceptance)


@contextmanager
def owned_directory(case="v1"):
    with tempfile.TemporaryDirectory(prefix="ai-scanner-backup-") as root:
        directory = Path(root).resolve(strict=True) / case
        directory.mkdir(mode=0o700)
        yield directory


def test_snapshot_quotes_hostile_fixture_identifiers():
    with owned_directory() as directory:
        database = directory / "source.sqlite"
        with closing(sqlite3.connect(database)) as connection, connection:
            connection.execute('CREATE TABLE audit_event (id INTEGER)')
            connection.execute('INSERT INTO audit_event VALUES (1)')
            connection.execute('CREATE TABLE "odd""; DROP TABLE audit_event; --" (value TEXT)')
            connection.execute('INSERT INTO "odd""; DROP TABLE audit_event; --" VALUES (?)', ('retained',))
        rows = acceptance.snapshot(database)["rows"]
        assert rows['odd"; DROP TABLE audit_event; --'] == [('retained',)]
        assert rows['audit_event'] == [(1,)]


@pytest.mark.parametrize('version', [1, 2, 3, 4, 5, 6, 7])
def test_historical_seed_never_reads_live_orm_metadata(version):
    class UnavailableLiveMetadata:
        @property
        def metadata(self):
            raise AssertionError('Historical backup fixtures must not read live ORM metadata')
    server = SimpleNamespace(db=UnavailableLiveMetadata())
    with owned_directory('v' + str(version)) as directory:
        engine = create_engine('sqlite:///' + str(directory / 'source.sqlite'))
        try:
            acceptance.seed(server, engine, version)
            with engine.connect() as connection:
                assert connection.exec_driver_sql('SELECT version FROM schema_version').scalar_one() == version
                triggers = dict(connection.exec_driver_sql(
                    "SELECT name,sql FROM sqlite_master WHERE type='trigger'").all())
                assert triggers == (dict(TRIGGER_DEFINITIONS, **group_triggers) if version == 7 else
                                    TRIGGER_DEFINITIONS if version >= 5 else {})
                assert ('inventory_generation' in inspect(connection).get_table_names()) is (version >= 5)
                for table, name in [('scan_session', 'overall_risk_score'), ('discovered_agent', 'risk_score')]:
                    column = next(value for value in inspect(connection).get_columns(table) if value['name'] == name)
                    assert column['nullable'] is (version >= 4) and column['default'] is None
        finally:
            engine.dispose()


def test_current_seed_uses_initializer_and_installs_recognized_triggers(monkeypatch):
    metadata = historical_metadata(version=4)
    register_inventory_metadata(metadata)
    register_asset_group_metadata(metadata)
    server = SimpleNamespace(db=SimpleNamespace(metadata=metadata))
    initialized = []
    original = schema.initialize_schema
    def initialize(engine, candidate):
        initialized.append(candidate)
        return original(engine, candidate)
    monkeypatch.setattr(schema, 'initialize_schema', initialize)
    with owned_directory('v8') as directory:
        engine = create_engine('sqlite:///' + str(directory / 'source.sqlite'))
        try:
            acceptance.seed(server, engine, 8)
            assert initialized == [metadata]
            with engine.connect() as connection:
                assert connection.exec_driver_sql('SELECT version FROM schema_version').scalar_one() == schema.SCHEMA_VERSION
                assert dict(connection.exec_driver_sql(
                    "SELECT name,sql FROM sqlite_master WHERE type='trigger'").all()) == dict(TRIGGER_DEFINITIONS, **group_triggers)
                values = connection.exec_driver_sql('SELECT organization_id,generation FROM inventory_generation').all()
                assert len(values) == 1 and values[0][0] == 'backup-fixture' and len(values[0][1]) == 32
        finally:
            engine.dispose()


@pytest.mark.parametrize("optimized", [False, True])
def test_complete_disposable_command(optimized, monkeypatch, tmp_path):
    deployed = tmp_path / "must-not-open.sqlite"
    monkeypatch.setenv("DATABASE_URL", "sqlite:///" + str(deployed))
    monkeypatch.setenv("SCAN_MAX_HOSTS", "invalid inherited setting")
    monkeypatch.setenv("MAX_CONCURRENT_SCANS", "invalid inherited setting")
    result = subprocess.run([sys.executable, *(["-O"] if optimized else []), str(SCRIPT),
                             "--timeout-seconds", "5"], capture_output=True, text=True, timeout=90)
    output = json.loads(result.stdout)
    assert result.returncode == 0 and output["accepted"] is True, result.stdout
    assert [item["case"] for item in output["cases"]] == list(acceptance.CASES)
    assert all(item["accepted"] and len(item["assertions"]) >= 3 for item in output["cases"])
    assert not deployed.exists()


@pytest.mark.parametrize("optimized", [False, True])
def test_complete_command_with_symlinked_temp_ancestor(optimized, tmp_path):
    real_temp = tmp_path / "real-temp"
    real_temp.mkdir()
    alias = tmp_path / "temp-alias"
    alias.symlink_to(real_temp, target_is_directory=True)
    environment = dict(os.environ, TMPDIR=str(alias))
    result = subprocess.run([sys.executable, *(["-O"] if optimized else []), str(SCRIPT),
                             "--timeout-seconds", "5"], env=environment,
                            capture_output=True, text=True, timeout=90)
    output = json.loads(result.stdout)
    assert result.returncode == 0 and output["accepted"] is True, result.stdout
    assert len(output["cases"]) == len(acceptance.CASES)
    assert alias.is_symlink() and real_temp.is_dir()
    assert not list(real_temp.iterdir())


@pytest.mark.parametrize('table, identifier, column, value', [
    ('scan_session', 'completed', 'overall_risk_score', 0.0),
    ('discovered_agent', 'completed-snapshot', 'risk_score', 0.0),
    ('scan_session', 'assessed-zero', 'overall_risk_score', None),
    ('discovered_agent', 'assessed-zero-snapshot', 'risk_score', None),
    ('scan_session', 'retained-partial', 'overall_risk_score', None),
    ('discovered_agent', 'retained-partial-snapshot', 'risk_level', 'unknown'),
])
def test_acceptance_rejects_corrupted_unknown_zero_or_partial_cache(table, identifier, column, value):
    code = '''
import runpy
from src.core import schema
original = schema.initialize_schema
def corrupt(engine, metadata):
    original(engine, metadata)
    with engine.begin() as connection:
        connection.exec_driver_sql(STATEMENT, (VALUE, IDENTIFIER))
schema.initialize_schema = corrupt
'''
    statement = 'UPDATE ' + table + ' SET ' + column + ' = ? WHERE id = ?'
    code = ('STATEMENT = ' + repr(statement) + '\nVALUE = ' + repr(value)
            + '\nIDENTIFIER = ' + repr(identifier) + '\n' + code)
    code += 'raise SystemExit(runpy.run_path(' + repr(str(SCRIPT)) + ')["child_main"]())'
    environment = dict(os.environ, PYTHONPATH=str(SCRIPT.parents[1]))
    with owned_directory('v3') as directory:
        returncode, stdout = acceptance.child_output([sys.executable, '-c', code],
            {'directory': str(directory), 'case': 'v3', 'timeout': 5}, environment, 10)
        output = json.loads(stdout)
        assert returncode == 1 and output['accepted'] is False
        assert 'score caches lost canonical values' in output['failure']
        assert acceptance.snapshot(directory / 'source.sqlite') == acceptance.snapshot(directory / 'backup.sqlite')


@pytest.mark.parametrize('statement', [
    'DELETE FROM inventory_generation',
    "UPDATE inventory_generation SET generation='invalid-token'",
    "INSERT INTO inventory_generation (organization_id,generation) VALUES ('unowned','0123456789abcdef0123456789abcdef')",
], ids=['missing-owner', 'malformed-token', 'extra-owner'])
def test_acceptance_rejects_corrupted_inventory_generation(statement):
    code = 'STATEMENT = ' + repr(statement) + '\n'
    code += 'SCRIPT = ' + repr(str(SCRIPT)) + '\n'
    code += '''
import runpy
module = runpy.run_path(SCRIPT)
state = module['run_case'].__globals__
original = state['inventory_generation_state']
def corrupt(server, engine):
    with engine.begin() as connection:
        connection.exec_driver_sql(STATEMENT)
    return original(server, engine)
state['inventory_generation_state'] = corrupt
raise SystemExit(module['child_main']())
'''
    environment = dict(os.environ, PYTHONPATH=str(SCRIPT.parents[1]))
    with owned_directory('v5') as directory:
        returncode, stdout = acceptance.child_output([sys.executable, '-c', code],
            {'directory': str(directory), 'case': 'v5', 'timeout': 5}, environment, 10)
        output = json.loads(stdout)
        assert returncode == 1 and output['accepted'] is False
        assert 'Inventory generation ownership or token shape changed' in output['failure']
        assert acceptance.snapshot(directory / 'source.sqlite') == acceptance.snapshot(directory / 'backup.sqlite')


def test_owned_directory_alias_is_still_rejected(tmp_path):
    with owned_directory() as directory:
        alias = tmp_path / "case-alias"
        alias.symlink_to(directory, target_is_directory=True)
        with pytest.raises(RuntimeError, match="owned acceptance"):
            acceptance.owned_path(alias, "source.sqlite")


@pytest.mark.parametrize("value", ["0", "61", "nan", "inf"])
def test_timeout_bounds(value):
    result = subprocess.run([sys.executable, str(SCRIPT), "--timeout-seconds", value],
                            capture_output=True, text=True, timeout=5)
    assert result.returncode == 2


def test_cli_has_no_source_or_destination_paths(tmp_path):
    result = subprocess.run([sys.executable, str(SCRIPT), "--source", str(tmp_path / "deployed.sqlite")],
                            capture_output=True, text=True, timeout=5)
    assert result.returncode == 2 and not list(tmp_path.iterdir())


@pytest.mark.parametrize("url", ["sqlite:///:memory:", "sqlite:///file:fixture?mode=memory&uri=true",
                                 "sqlite:////tmp/other.sqlite", "sqlite:///relative.sqlite"])
def test_engine_guard_rejects_before_connect(url):
    with owned_directory() as directory:
        database = acceptance.owned_path(directory, "source.sqlite")
        engine = create_engine(url, poolclass=StaticPool)
        engine.connect = Mock(side_effect=AssertionError("Must not connect"))
        try:
            with pytest.raises(RuntimeError, match="owned temporary"):
                acceptance.guard_database(engine, database)
            engine.connect.assert_not_called()
            assert not database.exists()
        finally:
            engine.dispose()


def test_foreign_dialect_and_cached_app_rejected_before_seed(monkeypatch):
    with owned_directory() as directory:
        cached = create_engine("sqlite:///:memory:")
        cached.connect = Mock(side_effect=AssertionError("Must not connect"))
        context = Mock()
        context.__enter__ = Mock(return_value=None)
        context.__exit__ = Mock(return_value=False)
        server = SimpleNamespace(app=SimpleNamespace(app_context=lambda: context), db=SimpleNamespace(engine=cached),
                                 _evidence_profiles=SimpleNamespace(_profiles={}))
        monkeypatch.setitem(sys.modules, "app", server)
        seeded = Mock(side_effect=AssertionError("Must not seed"))
        monkeypatch.setattr(acceptance, "seed", seeded)
        environment, search_path = os.environ.copy(), sys.path.copy()
        with patch.dict(os.environ), patch.object(sys, "path", sys.path.copy()):
            with pytest.raises(RuntimeError, match="owned temporary"):
                acceptance.run_case(directory, "v1", 5)
        assert os.environ == environment and sys.path == search_path
        seeded.assert_not_called()
        cached.connect.assert_not_called()
        foreign = SimpleNamespace(dialect=SimpleNamespace(name="postgresql"),
                                  url=SimpleNamespace(database=str(directory / "source.sqlite"), query={}))
        with pytest.raises(RuntimeError, match="owned temporary"):
            acceptance.guard_database(foreign, directory / "source.sqlite")
        cached.dispose()


def test_cached_operator_registry_rejected_before_context_or_database(monkeypatch):
    enter = Mock(side_effect=AssertionError("Database access must not begin"))
    registry = SimpleNamespace(_profiles={"operator-only": object()})
    server = SimpleNamespace(app=SimpleNamespace(app_context=enter), _evidence_profiles=registry)
    monkeypatch.setitem(sys.modules, "app", server)
    with owned_directory() as directory:
        environment, search_path = os.environ.copy(), sys.path.copy()
        with patch.dict(os.environ), patch.object(sys, "path", sys.path.copy()):
            with pytest.raises(RuntimeError, match="empty evidence registry"):
                acceptance.run_case(directory, "v1", 5)
        assert os.environ == environment and sys.path == search_path
        assert server._evidence_profiles is registry
        enter.assert_not_called()
        assert not list(directory.iterdir())


def test_direct_child_ignores_inherited_operator_registry(tmp_path, monkeypatch):
    private_path = str(tmp_path / "private-operator-profiles.json")
    monkeypatch.setenv("SCAN_EVIDENCE_PROFILES_FILE", private_path)
    code = r'''
import os
import runpy
private_path = os.environ["SCAN_EVIDENCE_PROFILES_FILE"]
original_open = os.open
def protected_open(path, *args, **kwargs):
    if os.fspath(path) == private_path:
        raise AssertionError("Operator registry must not be opened")
    return original_open(path, *args, **kwargs)
os.open = protected_open
'''
    code += "raise SystemExit(runpy.run_path(" + repr(str(SCRIPT)) + ")[\"child_main\"]())"
    with owned_directory() as directory:
        returncode, stdout = acceptance.child_output([sys.executable, "-c", code],
            {"directory": str(directory), "case": "v1", "timeout": 5}, os.environ.copy(), 10)
        output = json.loads(stdout)
        assert returncode == 0 and output["accepted"] is True, output
        assert output["assertions"] == acceptance.expected_assertions("v1")
    assert os.environ["SCAN_EVIDENCE_PROFILES_FILE"] == private_path
    assert private_path not in stdout and not Path(private_path).exists()


def test_owned_paths_reject_foreign_nested_names_and_symlinks(tmp_path):
    with pytest.raises(RuntimeError, match="owned acceptance"):
        acceptance.owned_path(tmp_path, "source.sqlite")
    with owned_directory() as directory:
        for name in ("../source.sqlite", "operator.sqlite"):
            with pytest.raises(RuntimeError):
                acceptance.owned_path(directory, name)
        (directory / "source.sqlite").symlink_to(tmp_path / "absent.sqlite")
        with pytest.raises(RuntimeError, match="symlinks"):
            acceptance.owned_path(directory, "source.sqlite")


def test_readonly_copy_no_clobber_and_expired_deadline():
    with owned_directory() as directory:
        source = directory / "source.sqlite"
        with closing(sqlite3.connect(source)) as connection, connection:
            connection.execute("CREATE TABLE fixture (id INTEGER)")
            connection.execute("INSERT INTO fixture VALUES (42)")
        destination = directory / "backup.sqlite"
        destination.write_bytes(b"do not replace")
        with pytest.raises(FileExistsError):
            acceptance.copy_database(source, destination, time.monotonic() + 2)
        assert destination.read_bytes() == b"do not replace"
        restored = directory / "restore.sqlite"
        with pytest.raises(RuntimeError, match="deadline"):
            acceptance.copy_database(source, restored, time.monotonic() - 1)
        assert acceptance.snapshot(source)["rows"] == {"fixture": [(42,)]}


def test_missing_and_foreign_sources_do_not_create_destinations(tmp_path):
    with owned_directory() as directory:
        with pytest.raises(RuntimeError, match="Missing regular"):
            acceptance.copy_database(directory / "source.sqlite", directory / "backup.sqlite", time.monotonic() + 1)
        assert not list(directory.iterdir())
    with pytest.raises(RuntimeError, match="owned acceptance"):
        acceptance.copy_database(tmp_path / "source.sqlite", tmp_path / "backup.sqlite", time.monotonic() + 1)
    assert not list(tmp_path.iterdir())


@pytest.mark.parametrize("body", ["print('not json')", "print('{}')", "print('x' * 20000)",
                                "import time; time.sleep(5)", "raise SystemExit(3)"])
def test_bounded_child_output_and_reaping(body):
    started = time.monotonic()
    try:
        returncode, output = acceptance.child_output([sys.executable, "-c", body], {}, os.environ.copy(), 0.2)
        assert returncode != 0 or len(output) <= 16384
    except RuntimeError as exc:
        assert "timeout" in str(exc) or "exceeded" in str(exc)
    assert time.monotonic() - started < 3


@pytest.mark.parametrize("returncode,payload", [
    (0, {}), (0, {"case": "v1", "accepted": False, "assertions": ["a"] * 3}),
    (1, {"case": "v1", "accepted": True, "assertions": ["a"] * 3}),
    (0, {"case": "v2", "accepted": True, "assertions": ["a"] * 3}),
    (0, {"case": "v1", "accepted": True, "assertions": []}),
    (0, {"case": "v1", "accepted": True, "assertions": ["a"] * 7}),
])
def test_parent_rejects_false_positive_results(monkeypatch, returncode, payload):
    monkeypatch.setattr(acceptance, "child_output", lambda *_: (returncode, json.dumps(payload)))
    with owned_directory() as directory:
        assert acceptance.invoke_case(directory, "v1", 1)["accepted"] is False


@pytest.mark.parametrize("failure", [OSError("spawn failed"), RuntimeError("Child process timeout")])
def test_parent_cleans_directory_on_child_failure(monkeypatch, failure, capsys):
    paths = []
    def failed(directory, case, timeout):
        paths.append(Path(directory).parent)
        (Path(directory) / "source.sqlite").touch()
        return {"case": case, "accepted": False, "failure": str(failure)}
    monkeypatch.setattr(acceptance, "invoke_case", failed)
    monkeypatch.setattr(sys, "argv", [str(SCRIPT)])
    assert acceptance.main() == 1
    assert json.loads(capsys.readouterr().out)["accepted"] is False
    assert paths and all(not path.exists() for path in paths)


@pytest.mark.parametrize("mutation,accepted", [("normal", True), ("bypass_verification", False)])
def test_incomplete_restore_fails_before_initializer_and_dispatcher(mutation, accepted):
    code = ("import json, runpy, sys; m = runpy.run_path(" + repr(str(SCRIPT)) + "); "
            "g = m['run_case'].__globals__; "
            "g['exercise'] = lambda *a: (_ for _ in ()).throw(RuntimeError('Startup must not run')); ")
    if mutation == "bypass_verification":
        code += "g['verify_restored'] = lambda *a: None; "
    code += "raise SystemExit(m['child_main']())"
    with owned_directory("incomplete") as directory:
        returncode, stdout = acceptance.child_output([sys.executable, "-c", code],
            {"directory": str(directory), "case": "incomplete", "timeout": 5}, os.environ.copy(), 10)
        output = json.loads(stdout)
        assert output["accepted"] is accepted and returncode == (0 if accepted else 1), output
        original = acceptance.snapshot(directory / "source.sqlite")
        assert acceptance.snapshot(directory / "backup.sqlite") == original
        if accepted:
            assert acceptance.snapshot(directory / "old-copy.sqlite") == original


def test_actual_spawn_failure_reports_failed_case(monkeypatch):
    monkeypatch.setattr(acceptance.subprocess, "Popen", Mock(side_effect=OSError("spawn failed")))
    with owned_directory() as directory:
        assert acceptance.invoke_case(directory, "v1", 1) == {"case": "v1", "accepted": False, "failure": "OSError: spawn failed"}


@pytest.mark.parametrize("stdout", ["not-json", "{", "[]", "null"])
def test_parent_rejects_malformed_results(monkeypatch, stdout):
    monkeypatch.setattr(acceptance, "child_output", lambda *_: (0, stdout))
    with owned_directory() as directory:
        assert acceptance.invoke_case(directory, "v1", 1)["accepted"] is False


def test_child_failure_reason_is_preserved_but_bounded(monkeypatch):
    monkeypatch.setattr(acceptance, "child_output", lambda *_: (1, json.dumps(
        {"case": "v1", "accepted": False, "failure": "useful diagnostic " + "x" * 1000})))
    with owned_directory() as directory:
        output = acceptance.invoke_case(directory, "v1", 1)
        assert output["accepted"] is False and output["failure"].startswith("useful diagnostic")
        assert len(output["failure"]) == 512


def test_query_engine_rejected_even_for_exact_owned_filename():
    with owned_directory() as directory:
        database = directory / "source.sqlite"
        engine = create_engine("sqlite:///" + str(database) + "?mode=ro&uri=true")
        try:
            with pytest.raises(RuntimeError, match="owned temporary"):
                acceptance.guard_database(engine, database)
            assert not database.exists()
        finally:
            engine.dispose()


@pytest.mark.parametrize("payload", ["not-json", "[]", "{}"])
def test_invalid_private_protocol_returns_failure_without_importing_app(monkeypatch, capsys, payload):
    monkeypatch.setattr(sys, "stdin", io.StringIO(payload))
    assert acceptance.child_main() == 1
    output = json.loads(capsys.readouterr().out)
    assert output["accepted"] is False


def test_real_timeout_reaped_before_parent_removes_directory(monkeypatch, capsys):
    actual_child_output = acceptance.child_output
    actual_popen = subprocess.Popen
    processes, directories = [], []

    def popen(*args, **kwargs):
        process = actual_popen(*args, **kwargs)
        processes.append(process)
        return process

    def timeout(command, payload, environment, limit):
        directories.append(Path(payload["directory"]).parent)
        return actual_child_output([sys.executable, "-c", "import time; time.sleep(5)"], payload, environment, 0.05)

    monkeypatch.setattr(acceptance.subprocess, "Popen", popen)
    monkeypatch.setattr(acceptance, "child_output", timeout)
    monkeypatch.setattr(acceptance, "CASES", ("v1",))
    monkeypatch.setattr(sys, "argv", [str(SCRIPT)])
    assert acceptance.main() == 1
    assert json.loads(capsys.readouterr().out)["accepted"] is False
    assert processes and all(process.poll() is not None for process in processes)
    assert directories and all(not directory.exists() for directory in directories)


def test_temporary_directory_failure_still_reports_json(monkeypatch, capsys):
    monkeypatch.setattr(acceptance.tempfile, "TemporaryDirectory", Mock(side_effect=OSError("fixture failure")))
    monkeypatch.setattr(sys, "argv", [str(SCRIPT)])
    assert acceptance.main() == 1
    output = json.loads(capsys.readouterr().out)
    assert output["accepted"] is False and "fixture failure" in output["failure"]
