"""The public inventory gate owns its fixtures and fails closed on driver errors."""

from contextlib import closing, contextmanager
import importlib.util
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import tempfile
import time
from unittest.mock import Mock

import pytest
from sqlalchemy import create_engine


SCRIPT = Path(__file__).resolve().parents[1] / 'scripts' / 'acceptance-inventory.py'
spec = importlib.util.spec_from_file_location('inventory_acceptance', SCRIPT)
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)


@contextmanager
def owned():
    with tempfile.TemporaryDirectory(prefix='ai-scanner-inventory-') as raw:
        directory = Path(raw).resolve(strict=True)
        directory.chmod(0o700)
        yield directory


def private_values():
    return {name: 'synthetic-private-value-' + name + '-1738264910' for name in
            ('signing', 'operator', 'marker', 'issued', 'jwt0', 'jwt1', 'jwt2')}


@pytest.mark.parametrize('optimized', [False, True])
def test_complete_real_server_gate_isolated_from_operator_settings_and_alias_tmpdir(optimized, tmp_path):
    real = tmp_path / 'real-temp'
    real.mkdir()
    alias = tmp_path / 'temp-alias'
    alias.symlink_to(real, target_is_directory=True)
    operator = tmp_path / 'operator.sqlite'
    operator.write_bytes(b'Operator bytes must remain untouched')
    profile = tmp_path / 'operator-profile.json'
    profile.write_text('Must never be parsed', encoding='utf-8')
    environment = dict(os.environ, DATABASE_URL='sqlite:///' + str(operator),
                       SCAN_EVIDENCE_PROFILES_FILE=str(profile), SCAN_MAX_HOSTS='invalid inherited value',
                       MAX_CONCURRENT_SCANS='invalid inherited value', GUNICORN_CMD_ARGS='--workers 99',
                       HTTP_PROXY='http://invalid.invalid:1', HTTPS_PROXY='http://invalid.invalid:1',
                       TMPDIR=str(alias), OPERATOR_API_KEY='inherited-private-key-must-not-appear')
    result = subprocess.run([sys.executable, *(['-O'] if optimized else []), '-Werror', str(SCRIPT)],
                            env=environment, capture_output=True, text=True, timeout=160)
    output = json.loads(result.stdout)
    assert result.returncode == 0 and output['accepted'] is True, result.stdout
    assert result.stderr == ''
    assert output['format_version'] == gate.FORMAT_VERSION
    assert output['assertions'] == list(gate.REQUIRED_ASSERTIONS)
    assert output['observation_count'] == 10000
    assert output['fixture_scope'] == 'repeated_observations_of_12_synthetic_assets'
    assert output['schema_before'] == 4 and output['schema_after'] == output['schema_target'] == 8
    assert output['cache_policy_upgrade'] == {
        'scan_caches_reconciled': 12, 'observation_caches_reconciled': 10000,
        'original_stale_scan_caches_restored': 12, 'original_stale_observation_caches_restored': 10000}
    assert output['server_exits'] == [{'phase': 'initial', 'returncode': 0}, {'phase': 'restart', 'returncode': 0}]
    assert sum(value for name, value in output['traversal_counts'].items() if name.endswith(':all')) == 10000
    assert sum(value for name, value in output['traversal_counts'].items() if name.endswith(':high')) == 2500
    assert sum(value for name, value in output['traversal_counts'].items() if name.endswith(':minimal')) == 2500
    assert all(value == 0 for name, value in output['traversal_counts'].items() if name.endswith(':critical'))
    assert output['privacy']['required_values_checked'] == 7
    assert output['privacy']['surfaces_checked'] >= 5
    assert output['http_responses_checked'] >= 600
    assert operator.read_bytes() == b'Operator bytes must remain untouched'
    assert profile.read_text() == 'Must never be parsed'
    assert alias.is_symlink() and not list(real.iterdir())
    for private in (str(tmp_path), str(operator), str(profile), environment['OPERATOR_API_KEY']):
        assert private not in result.stdout + result.stderr


@pytest.mark.parametrize('arguments', [['--database', '/private/operator.sqlite'], ['--source', '/private/operator.sqlite'],
                                      ['--timeout-seconds', '0'], ['--timeout-seconds', 'nan'],
                                      ['--timeout-seconds', '301'], ['--timeout-seconds', 'infinity']])
def test_invalid_arguments_have_static_errors_without_echoing_paths(arguments):
    result = subprocess.run([sys.executable, str(SCRIPT), *arguments], capture_output=True, text=True, timeout=5)
    assert result.returncode == 2 and result.stderr == ''
    output = json.loads(result.stdout)
    assert output['accepted'] is False and output['failure_codes'] == ['invalid_arguments']
    assert '/private/operator.sqlite' not in result.stdout


def test_environment_is_an_allowlist_and_owned_engine_guard_precedes_connect(monkeypatch):
    with owned() as directory:
        monkeypatch.setenv('SCAN_EVIDENCE_PROFILES_FILE', '/private/never-open.json')
        monkeypatch.setenv('GUNICORN_CMD_ARGS', '--workers=99')
        monkeypatch.setenv('AWS_SHARED_CREDENTIALS_FILE', '/private/never-open.ini')
        environment = gate.fresh_environment(directory, private_values())
        assert not {'SCAN_EVIDENCE_PROFILES_FILE', 'GUNICORN_CMD_ARGS', 'AWS_SHARED_CREDENTIALS_FILE'} & environment.keys()
        assert environment['MAX_CONCURRENT_SCANS'] == '1'
        engine = create_engine('sqlite:///:memory:')
        engine.connect = Mock(side_effect=AssertionError('Operator engine must not connect'))
        try:
            with pytest.raises(gate.GateFailure, match='engine_not_owned_fixture'):
                gate.guard_engine(engine, gate.owned_database(directory))
            engine.connect.assert_not_called()
        finally:
            engine.dispose()


def test_cached_app_rejected_before_seed_or_configuration_access(monkeypatch):
    monkeypatch.setitem(sys.modules, 'app', object())
    with pytest.raises(gate.GateFailure, match='cached_app_before_fixture_import'):
        gate.seed(Path('/private/never-open'), private_values())


@pytest.mark.parametrize('kind', ['missing-secret', 'missing-file', 'unreadable', 'plaintext', 'encoded', 'public-mode'])
def test_privacy_checks_are_required_and_propagate_failures(kind, monkeypatch):
    with owned() as directory:
        surfaces = [directory / str(index) for index in range(5)]
        for path in surfaces:
            path.write_bytes(b'Public synthetic acceptance log')
            path.chmod(0o600)
        values = private_values()
        if kind == 'missing-secret':
            values.pop('issued')
        elif kind == 'missing-file':
            surfaces[0].unlink()
        elif kind == 'unreadable':
            read_bytes = Path.read_bytes
            def denied(path):
                if path == surfaces[0]:
                    raise OSError('Read deliberately failed')
                return read_bytes(path)
            monkeypatch.setattr(Path, 'read_bytes', denied)
        elif kind in {'plaintext', 'encoded'}:
            value = values['marker'].upper().encode() if kind == 'plaintext' else gate.base64.b64encode(values['marker'].encode())
            surfaces[0].write_bytes(value)
        else:
            surfaces[0].chmod(0o644)
        with pytest.raises(gate.GateFailure):
            gate.privacy_check(surfaces, values, b'Public stdout')


def test_unexpected_secret_in_http_response_is_not_hidden_by_field_projection():
    with pytest.raises(gate.GateFailure, match='private_value_in_http_response'):
        gate.assert_private_absent(json.dumps({'unexpected': private_values()['issued']}).encode(),
                                   private_values(), 'private_value_in_http_response')


@pytest.mark.parametrize('score', [False, 0, 0.0], ids=['invalid-bool', 'integer-zero', 'float-zero'])
def test_traversal_distinguishes_boolean_false_from_a_real_assessed_zero(score):
    expected = {'id': 'observation', 'asset_id': 'asset', 'name': 'Fixture', 'provider': 'fixture',
                'type': 'assistant', 'discovered_at': '2026-01-01T00:00:00', **gate.descriptor('zero')}
    response = {'success': True, 'agents': [{**expected, 'risk_score': score}], 'next_cursor': None,
                'coverage': {'evaluated_candidates': 1, 'projected_reports': 1,
                             'interpreted_source_bytes': 2, 'search_complete': True}}
    server = Mock()
    server.request.return_value = 200, response
    if type(score) is bool:
        with pytest.raises(gate.GateFailure, match='non_numeric_canonical_score'):
            gate.traversal(server, 'inventory-a', [expected], {})
    else:
        assert gate.traversal(server, 'inventory-a', [expected], {}) == 1


@pytest.mark.parametrize('where', ['json-unicode-escapes', 'header', 'auth-extra-field'])
def test_real_response_boundary_checks_decoded_json_headers_and_narrow_auth_exception(where):
    values = private_values()
    with owned() as directory, socket.socket() as listener:
        listener.bind(('127.0.0.1', 0))
        server = gate.Server(directory, {}, listener, 'initial', time.monotonic() + 20, values)
        escaped = ''.join('\\u%04x' % ord(mark) for mark in values['issued'])
        class Response:
            status = 200
            headers = {'Cache-Control': 'no-store', **({'X-Unexpected': values['marker']} if where == 'header' else {})}
            def read(self, size):
                if where == 'auth-extra-field':
                    return json.dumps({'success': True, 'token': 'unused-opaque-token', 'extra': values['issued']}).encode()
                return ('{"unexpected":"' + escaped + '"}').encode()
            def __enter__(self):
                return self
            def __exit__(self, *args):
                return False
        server.opener = Mock()
        server.opener.open.return_value = Response()
        with pytest.raises(gate.GateFailure):
            server.request('/api/auth/token' if where == 'auth-extra-field' else '/api/agents')


def test_server_timeout_after_spawn_still_assigns_and_reaps_the_child(monkeypatch):
    with owned() as directory, socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(('127.0.0.1', 0))
        listener.listen()
        actual_popen = subprocess.Popen
        children = []
        def spawn_then_timeout(command, **kwargs):
            child = actual_popen([sys.executable, '-c', 'import time; time.sleep(30)'], **kwargs)
            children.append(child)
            os.kill(os.getpid(), signal.SIGALRM)
            return child
        monkeypatch.setattr(gate.subprocess, 'Popen', spawn_then_timeout)
        server = gate.Server(directory, gate.fresh_environment(directory, private_values()), listener,
                             'initial', time.monotonic() + 20, private_values())
        try:
            with pytest.raises(gate.GateFailure, match='overall_timeout'):
                server.start()
        finally:
            server.stop()
        assert len(children) == 1 and children[0].returncode is not None
        assert server.log.closed
        with pytest.raises(ProcessLookupError):
            os.killpg(children[0].pid, 0)


def test_server_stop_reaps_and_closes_logs_when_wait_is_interrupted(monkeypatch):
    with owned() as directory, socket.socket() as listener:
        listener.bind(('127.0.0.1', 0))
        server = gate.Server(directory, {}, listener, 'initial', time.monotonic() + 20, private_values())
        server.process = Mock(pid=12345)
        server.process.poll.return_value = None
        server.process.wait.side_effect = [gate.GateFailure('overall_timeout'), -9]
        server.log = Mock()
        kill = Mock()
        monkeypatch.setattr(gate.os, 'killpg', kill)
        with pytest.raises(gate.GateFailure, match='overall_timeout'):
            server.stop()
        assert kill.call_args_list[-1].args == (12345, signal.SIGKILL)
        assert server.process.wait.call_count == 2
        server.log.close.assert_called_once()


@pytest.mark.parametrize('failure', ['analysis', 'privacy', 'cleanup', 'socket'])
def test_main_never_accepts_when_analysis_privacy_or_cleanup_fails(monkeypatch, capsys, failure):
    monkeypatch.delitem(sys.modules, 'app', raising=False)
    original_temporary = tempfile.TemporaryDirectory
    actual_directories = []
    def temporary(*args, **kwargs):
        instance = original_temporary(*args, **kwargs)
        actual_directories.append((instance, instance.cleanup))
        if failure == 'cleanup':
            instance.cleanup = Mock(side_effect=OSError('Synthetic cleanup failure'))
        return instance
    monkeypatch.setattr(gate.tempfile, 'TemporaryDirectory', temporary)
    monkeypatch.setattr(gate, 'seed', lambda directory, values: {})
    monkeypatch.setattr(gate, 'runtime_identity', lambda: {})
    def exercise(directory, environment, listener, values, output, deadline):
        output.pop('_expected')
        output['assertions'] = list(gate.REQUIRED_ASSERTIONS[:11])
        if failure == 'analysis':
            raise gate.GateFailure('synthetic_analysis_failure')
    monkeypatch.setattr(gate, 'execute', exercise)
    def privacy(*args):
        if failure == 'privacy':
            raise gate.GateFailure('synthetic_privacy_failure')
    monkeypatch.setattr(gate, 'privacy_check', privacy)
    # Required owned files exist even though this failure-path fixture deliberately
    # replaces the expensive real-server exercise, tested in full above.
    original_seed = gate.seed
    def seed_files(directory, values):
        for name in ('fixture.sqlite', 'fixture.sqlite.dispatcher.lock'):
            (directory / name).touch(mode=0o600)
        return original_seed(directory, values)
    monkeypatch.setattr(gate, 'seed', seed_files)
    if failure == 'socket':
        original_socket = socket.socket
        class FailingClose(original_socket):
            def close(self):
                super().close()
                raise OSError('Synthetic socket close failure')
        monkeypatch.setattr(gate.socket, 'socket', FailingClose)
    try:
        assert gate.main([]) == 1
        output = json.loads(capsys.readouterr().out)
        assert output['accepted'] is False and output['failure_codes']
    finally:
        for instance, cleanup in actual_directories:
            # Bypass only the injected failure and detach its real finalizer.
            instance.cleanup = cleanup
            cleanup()


def test_missing_server_extra_has_a_clear_nonzero_result(monkeypatch, capsys):
    actual = importlib.util.find_spec
    monkeypatch.setattr(gate.importlib.util, 'find_spec', lambda name: None if name == 'gunicorn' else actual(name))
    assert gate.main([]) == 1
    output = json.loads(capsys.readouterr().out)
    assert output['accepted'] is False and 'server extra' in output['hint']


@pytest.fixture
def policy_upgraded_fixture(monkeypatch):
    from src.core.inventory_generation import register_inventory_metadata
    from src.core.asset_group_storage import register_asset_group_metadata
    from src.core.schema import initialize_schema
    from tests.historical_schema import historical_metadata
    monkeypatch.setattr(gate, 'OBSERVATIONS', 12)
    with owned() as directory:
        engine = create_engine('sqlite:///' + str(directory / 'fixture.sqlite'))
        old = historical_metadata(version=4)
        current = historical_metadata(version=4)
        register_inventory_metadata(current)
        register_asset_group_metadata(current)
        expected = {organization: [] for organization in gate.ORGANIZATIONS}
        try:
            old.create_all(engine)
            with engine.begin() as transaction:
                transaction.execute(old.tables['schema_version'].insert().values(id=1, version=4))
                for organization in gate.ORGANIZATIONS:
                    for category in gate.CATEGORIES:
                        identifier = organization + '-' + category
                        report = gate.produce(identifier, category, private_values())
                        transaction.execute(old.tables['scan_session'].insert().values(
                            id=identifier, organization_id=organization, scan_name='Owned cache lifecycle',
                            scan_type=report['scan_type'], status=report['status'], target_scope={}, scan_config={},
                            overall_risk_score=99))
                        transaction.execute(old.tables['scan_result'].insert().values(scan_id=identifier, result=report))
                        observation = 'observation-' + identifier
                        transaction.execute(old.tables['discovered_agent'].insert().values(
                            id=observation, scan_id=identifier, agent_name='Owned cache lifecycle',
                            agent_type='assistant', discovery_method='synthetic', risk_score=99, risk_level='critical',
                            metadata={'asset_id': identifier + '-asset'}))
                        expected[organization].append({'id': observation, **gate.descriptor(category)})
                transaction.exec_driver_sql(gate.OPERATOR_INDEX)
            original, definitions = gate.archive(directory), gate.definitions(directory)
            initialize_schema(engine, current)
            yield directory, original, definitions, expected, engine, current
        finally:
            engine.dispose()


def test_policy_upgrade_is_checked_before_original_stale_caches_are_restored(policy_upgraded_fixture):
    directory, original, definitions, expected, _, _ = policy_upgraded_fixture
    assert gate.archive(directory) != original
    outcome = gate.verify_upgrade_and_restore(directory, original, definitions, expected)
    assert outcome == {'scan_caches_reconciled': 12, 'observation_caches_reconciled': 12,
                       'original_stale_scan_caches_restored': 12, 'original_stale_observation_caches_restored': 12}
    assert gate.archive(directory) == original


@pytest.mark.parametrize('statement,code', [
    ('UPDATE discovered_agent SET risk_score=99,risk_level=\'critical\'', 'upgrade_snapshot_cache_mismatch'),
    ('UPDATE scan_session SET overall_risk_score=99', 'upgrade_scan_cache_mismatch'),
    ("UPDATE discovered_agent SET agent_name='Changed outside cache'", 'upgrade_changed_noncache_rows_or_archived_json'),
    ("UPDATE scan_result SET result='{}'", 'upgrade_changed_noncache_rows_or_archived_json'),
    ('DROP INDEX operator_inventory_fixture', 'upgrade_changed_original_definitions'),
    ('CREATE INDEX unexpected_policy_index ON discovered_agent(agent_name)', 'upgrade_added_unexpected_definitions'),
], ids=['snapshot-cache', 'scan-cache', 'snapshot-noncache', 'archive-json', 'original-index', 'extra-index'])
def test_stale_cache_restoration_cannot_hide_a_bad_upgrade(policy_upgraded_fixture, statement, code):
    directory, original, definitions, expected, _, _ = policy_upgraded_fixture
    with closing(gate.connection(directory, write=True)) as database, database:
        database.execute(statement)
    with pytest.raises(gate.GateFailure, match='^' + code + '$'):
        gate.verify_upgrade_and_restore(directory, original, definitions, expected)


@pytest.mark.parametrize('fault', ['skipped', 'noncache-write'])
def test_stale_restore_requires_exact_original_rows(policy_upgraded_fixture, monkeypatch, fault):
    directory, original, definitions, expected, _, _ = policy_upgraded_fixture
    actual = gate.restore_stale_caches
    def restore(directory, original):
        if fault == 'noncache-write':
            actual(directory, original)
            with closing(gate.connection(directory, write=True)) as database, database:
                database.execute("UPDATE discovered_agent SET agent_name='Unexpected restoration write'")
    monkeypatch.setattr(gate, 'restore_stale_caches', restore)
    with pytest.raises(gate.GateFailure, match='^owned_stale_cache_restore_changed_original_rows$'):
        gate.verify_upgrade_and_restore(directory, original, definitions, expected)


def test_schema_six_restart_keeps_reintroduced_stale_caches_and_generations(policy_upgraded_fixture):
    from src.core.schema import initialize_schema
    directory, original, definitions, expected, engine, metadata = policy_upgraded_fixture
    gate.verify_upgrade_and_restore(directory, original, definitions, expected)
    generations, definitions = gate.check_schema(directory), gate.definitions(directory)
    initialize_schema(engine, metadata)
    assert gate.archive(directory) == original
    assert gate.check_schema(directory) == generations
    assert gate.definitions(directory) == definitions
