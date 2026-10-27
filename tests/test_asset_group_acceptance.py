"""Independent public gate, source-history oracle and publication tamper controls."""

from datetime import datetime, timedelta
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
from unittest.mock import Mock

import pytest
from sqlalchemy import insert, select, update

from tests.test_api_auth import api as api, headers


SCRIPT = Path(__file__).resolve().parents[1] / 'scripts/acceptance-asset-groups.py'
spec = importlib.util.spec_from_file_location('independent_asset_group_gate', SCRIPT)
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)


def private_values():
    return {name: 'owned-private-acceptance-value-' + name + '-e7981402' for name in
            ('signing', 'operator', 'marker', 'issued', 'jwt0', 'jwt1', 'jwt2')}


@pytest.mark.parametrize('optimized', [False, True])
def test_public_group_gate_runs_real_server_and_refuses_inherited_operator_inputs(optimized, tmp_path):
    operator, profile = tmp_path / 'operator.sqlite', tmp_path / 'operator-profile.json'
    operator.write_bytes(b'Owned operator sentinel remains unchanged')
    profile.write_text('Owned configuration sentinel must not be parsed')
    environment = dict(os.environ, DATABASE_URL='sqlite:///' + str(operator),
                       SCAN_EVIDENCE_PROFILES_FILE=str(profile), GUNICORN_CMD_ARGS='--workers=99',
                       SCAN_MAX_HOSTS='invalid inherited value', HTTP_PROXY='http://invalid.invalid:1',
                       OPERATOR_API_KEY='inherited-private-key-do-not-return-243831')
    result = subprocess.run([sys.executable, *(['-O'] if optimized else []), '-Werror', str(SCRIPT),
                             '--timeout-seconds', '180'], env=environment,
                            capture_output=True, text=True, timeout=200)
    output = json.loads(result.stdout)
    assert result.returncode == 0 and output['accepted'] is True, result.stdout
    assert result.stderr == ''
    assert output['format_version'] == gate.FORMAT_VERSION
    assert output['schema_before'] == 6 and output['schema_after'] == output['schema_target'] == 7
    assert output['observation_count'] == 10000
    assert output['assertions'] == list(gate.REQUIRED_ASSERTIONS)
    assert output['server_exits'] == [{'phase': 'initial', 'returncode': 0}, {'phase': 'restart', 'returncode': 0}]
    assert sum(row['observations'] for row in output['traversal_counts'].values()) == 10000
    assert all(row['groups'] == 8 for row in output['traversal_counts'].values())
    assert output['privacy']['required_values_checked'] == 7
    assert output['http_responses_checked'] >= 200
    assert operator.read_bytes() == b'Owned operator sentinel remains unchanged'
    assert profile.read_text() == 'Owned configuration sentinel must not be parsed'
    for value in (str(tmp_path), str(profile), str(operator), environment['OPERATOR_API_KEY']):
        assert value not in result.stdout + result.stderr


@pytest.mark.parametrize('arguments', [['--database', '/private/owned-sentinel'], ['--source', '/private/owned-sentinel'],
                                      ['--timeout-seconds', '0'], ['--timeout-seconds', 'nan'],
                                      ['--timeout-seconds', '301']])
def test_gate_arguments_are_bounded_and_errors_never_echo_private_paths(arguments):
    result = subprocess.run([sys.executable, str(SCRIPT), *arguments], capture_output=True, text=True, timeout=5)
    assert result.returncode == 2 and result.stderr == ''
    assert json.loads(result.stdout)['failure_codes'] == ['invalid_arguments']
    assert '/private/owned-sentinel' not in result.stdout


@pytest.mark.parametrize('category,score,confirmed', [('high', 70, True), ('zero', 0, False),
                                                   ('unscored', None, True), ('unknown', None, False)])
def test_fixture_produces_real_controlled_evidence_before_database_observations(category, score, confirmed):
    from src.core.contracts import confirmed_findings
    from src.core.risk_projection import project_report_risk
    report = gate.produce(category, private_values())
    asset = report['agents'][0]
    assert project_report_risk(report)[1][asset['id']]['risk_score'] == score
    assert bool(confirmed_findings({**asset, 'status': asset['security_status'], 'check_schema_version': '1.0'})) is confirmed
    text = json.dumps(report)
    assert private_values()['marker'] not in text and private_values()['issued'] not in text


@pytest.mark.parametrize('complete,cursor', [(True, 'unexpected'), (False, None), (False, '')])
def test_pagination_rejects_false_exhaustion_and_missing_continuation(complete, cursor):
    server = Mock()
    server.request.return_value = 200, {'success': True, 'asset_groups': [], 'next_cursor': cursor,
                                      'coverage': {'search_complete': complete}}
    with pytest.raises(gate.GateFailure, match='nonadvancing_or_false_completion'):
        gate.page_all(server, gate.ORGANIZATIONS[0], '/api/asset-groups', 'asset_groups')


def test_pagination_rejects_repeated_cursor_even_with_empty_advancing_pages():
    server = Mock()
    server.request.return_value = 200, {'success': True, 'asset_groups': [], 'next_cursor': 'same',
                                      'coverage': {'search_complete': False}}
    with pytest.raises(gate.GateFailure, match='nonadvancing_or_false_completion'):
        gate.page_all(server, gate.ORGANIZATIONS[0], '/api/asset-groups', 'asset_groups')
    assert server.request.call_count == 2


def test_blocked_build_requires_observed_current_generation_error_not_staleness(monkeypatch):
    database = Mock()
    database.execute.return_value.fetchone.side_effect = [
        ('old-generation', 'source_unavailable', 'current-generation'),
        ('current-generation', None, 'current-generation'),
        ('current-generation', 'source_unavailable', 'current-generation')]
    monkeypatch.setattr(gate.inventory, 'connection', lambda directory: database)
    monkeypatch.setattr(gate.time, 'sleep', Mock())
    server = Mock()
    gate.wait_blocked(server, Path('/owned-unused'), gate.ORGANIZATIONS[0])
    assert database.execute.call_count == server.remaining.call_count == 3
    assert database.close.call_count == 3


def test_blocked_build_wait_cannot_accept_when_background_never_reads_bad_source(monkeypatch):
    database = Mock()
    database.execute.return_value.fetchone.return_value = None
    monkeypatch.setattr(gate.inventory, 'connection', lambda directory: database)
    monkeypatch.setattr(gate.time, 'sleep', Mock())
    server = Mock()
    server.remaining.side_effect = [1, gate.GateFailure('overall_timeout')]
    with pytest.raises(gate.GateFailure, match='overall_timeout'):
        gate.wait_blocked(server, Path('/owned-unused'), gate.ORGANIZATIONS[0])
    assert database.execute.call_count == 1


@pytest.fixture
def published_sources(api):
    from src.core.asset_groups import AssetGroupProjector
    module, client = api
    for index, category in enumerate(('high', 'zero')):
        report = gate.produce(category, private_values())
        asset, scan_id = report['agents'][0], 'owned-acceptance-' + category
        module.db.session.add(module.ScanSession(id=scan_id, organization_id='tenant-a', scan_name='Owned source',
                              scan_type=report['scan_type'], status=report['status'], target_scope={}, scan_config={}))
        module.db.session.add(module.ScanResult(scan_id=scan_id, result=report))
        module.db.session.add(module.DiscoveredAgentModel(
            id='owned-snapshot-' + category, scan_id=scan_id, agent_name=asset['name'], agent_type=asset['type'],
            provider=asset['provider'], model_name=asset['model'], endpoint_url=asset['endpoint'],
            discovery_method='controlled-no-socket', metadata_json={'asset_id': asset['id']},
            risk_score=99, risk_level='critical', discovered_at=datetime(2026, 1, 1) + timedelta(seconds=index)))
    module.db.session.commit()
    projector = AssetGroupProjector(module.db.engine, module._asset_group_tables())
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        projector.step()
        response = client.get('/api/asset-groups', headers=headers(module))
        if response.status_code == 200:
            break
    assert response.status_code == 200, response.json
    assert response.json['asset_groups'][0]['latest_observation_risk']['risk_score'] == 0
    assert response.json['asset_groups'][0]['confirmation_history']['supported_occurrences'] == 18
    publication = module._asset_group_tables()['publication']
    saved = dict(module.db.session.execute(select(publication)).mappings().one())
    yield module, client, saved


@pytest.mark.parametrize('fault', ['changed-sealed-row', 'extra-unsealed-row', 'generation-retarget', 'policy-retarget'])
def test_actual_http_refuses_tampered_cache_after_active_publication_metadata_is_restored(published_sources, monkeypatch, fault):
    from src.core import asset_groups
    module, client, saved = published_sources
    tables, values = module._asset_group_tables(), {}
    index, publication = tables['index'], tables['publication']
    with module.db.engine.begin() as connection:
        head = dict(connection.execute(select(index).where(index.c.is_latest.is_(True))).mappings().one())
        if fault == 'changed-sealed-row':
            connection.execute(update(index).where(index.c.observation_id == head['observation_id'])
                               .values(group_supported_confirmation_count=0))
            assert connection.execute(select(index.c.publication_nonce).where(
                index.c.observation_id == head['observation_id'])).scalar_one() is None
        elif fault == 'extra-unsealed-row':
            extra = dict(head, observation_id='owned-cache-only-extra', is_latest=False, publication_nonce=None)
            connection.execute(insert(index).values(**extra))
        elif fault == 'generation-retarget':
            connection.exec_driver_sql('UPDATE discovered_agent SET agent_name=agent_name')
            values['active_generation'] = connection.execute(select(tables['generations'].c.generation)
                .where(tables['generations'].c.organization_id == 'tenant-a')).scalar_one()
        else:
            policy = 'f' * 64 if saved['active_policy'] != 'f' * 64 else 'a' * 64
            monkeypatch.setattr(asset_groups, 'ASSET_GROUP_POLICY', policy)
            values['active_policy'] = policy
        active = ('active_build_id', 'active_generation', 'active_nonce', 'active_policy',
                  'active_row_count', 'active_group_count')
        connection.execute(update(publication).where(publication.c.organization_id == 'tenant-a')
                           .values(**{name: values.get(name, saved[name]) for name in active}))
    module.db.session.expire_all()
    response = client.get('/api/asset-groups', headers=headers(module))
    assert response.status_code == 503
    assert response.json['code'] == 'asset_group_projection_unavailable'
    assert response.headers['Cache-Control'] == 'no-store'
    history = client.get('/api/asset-groups/' + head['group_id'] + '/history', headers=headers(module))
    assert history.status_code == 503 and history.json['code'] == 'asset_group_projection_unavailable'
    # No background repair runs in this HTTP test-client proof. Source views
    # remain usable; malformed cache data never becomes a source risk verdict.
    source = client.get('/api/agents?limit=1', headers=headers(module))
    assert source.status_code == 200 and source.json['agents'][0]['risk_score'] == 0


@pytest.mark.parametrize('failure', ['analysis', 'privacy', 'cleanup', 'signal'])
def test_gate_analysis_privacy_and_cleanup_failures_are_nonzero_and_static(monkeypatch, capsys, failure):
    monkeypatch.delitem(sys.modules, 'app', raising=False)
    original_temporary, actual = tempfile.TemporaryDirectory, []
    def temporary(*args, **kwargs):
        instance = original_temporary(*args, **kwargs)
        actual.append((instance, instance.cleanup))
        if failure == 'cleanup':
            instance.cleanup = Mock(side_effect=OSError('owned-private-cleanup-detail'))
        return instance
    monkeypatch.setattr(gate.tempfile, 'TemporaryDirectory', temporary)
    monkeypatch.setattr(gate.inventory, 'runtime_identity', lambda: {'driver_sha256': 'a' * 64})
    def seed(directory, values):
        for name in ('fixture.sqlite', 'fixture.sqlite.dispatcher.lock', 'initial.log', 'restart.log'):
            (directory / name).touch(mode=0o600)
        return {}
    monkeypatch.setattr(gate, 'seed', seed)
    def execute(directory, environment, listener, values, output, deadline, expected):
        output['assertions'] = list(gate.REQUIRED_ASSERTIONS[:12])
        values.update({name: private_values()[name] for name in ('jwt0', 'jwt1', 'jwt2')})
        if failure == 'analysis':
            raise gate.GateFailure('owned_analysis_failed')
    monkeypatch.setattr(gate, 'execute', execute)
    def privacy(*args):
        if failure == 'privacy':
            raise OSError('owned-private-privacy-detail')
    monkeypatch.setattr(gate.inventory, 'privacy_check', privacy)
    if failure == 'signal':
        original = gate.signal.setitimer
        def timer(which, seconds, *args):
            if seconds == 0:
                original(which, seconds, *args)
                raise OSError('owned-private-signal-detail')
            return original(which, seconds, *args)
        monkeypatch.setattr(gate.signal, 'setitimer', timer)
    try:
        assert gate.main([]) == 1
        text = capsys.readouterr().out
        output = json.loads(text)
        expected = {'analysis': 'owned_analysis_failed', 'privacy': 'privacy_check_failed',
                    'cleanup': 'fixture_cleanup_failed', 'signal': 'signal_cleanup_failed'}[failure]
        assert output['accepted'] is False and expected in output['failure_codes'] and 'owned-private' not in text
    finally:
        for instance, cleanup in actual:
            instance.cleanup = cleanup
            cleanup()
