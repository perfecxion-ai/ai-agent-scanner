"""Authenticated group views read canonical sources without repairing them on GET."""

from datetime import datetime, timedelta
import time

import pytest
from sqlalchemy import event, select

from src.core.asset_groups import AssetGroupProjector
from tests.test_api_auth import api as api, headers


def seed(module):
    for owner in ('tenant-a', 'tenant-b'):
        for index, path in enumerate(('/api/chat', '/api/chat', '/different')):
            scan_id = owner + '-' + str(index)
            agent = {'id': 'saved-agent', 'name': 'Owned fixture', 'type': 'assistant',
                     'provider': 'fixture', 'model': 'fixture-model',
                     'endpoint': 'https://fixture.invalid' + path, 'security_status': 'not_tested',
                     'checks': [], 'vulnerabilities': []}
            module.db.session.add(module.ScanSession(
                id=scan_id, organization_id=owner, scan_name='Owned group fixture',
                scan_type='discovery_only', status='completed', target_scope={}, scan_config={}))
            module.db.session.add(module.ScanResult(scan_id=scan_id, result={
                'schema_version': '1.0', 'scan_id': scan_id, 'scan_type': 'discovery_only',
                'status': 'completed', 'agents': [agent], 'security_results': [], 'risk_assessments': [],
                'summary': {'overall_risk_score': None}}))
            module.db.session.add(module.DiscoveredAgentModel(
                id=scan_id + '-snapshot', scan_id=scan_id, agent_name=agent['name'],
                agent_type=agent['type'], provider=agent['provider'], model_name=agent['model'],
                endpoint_url=agent['endpoint'], discovery_method='fixture',
                discovered_at=datetime(2026, 1, 1) + timedelta(seconds=index),
                metadata_json={'asset_id': agent['id']}, risk_score=99, risk_level='critical'))
    module.db.session.commit()


def publish(module):
    projector = AssetGroupProjector(module.db.engine, module._asset_group_tables())
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        projector.step()
        values = [module.app.test_client().get('/api/asset-groups', headers=headers(module, owner))
                  for owner in ('tenant-a', 'tenant-b')]
        if all(value.status_code == 200 for value in values):
            return
    pytest.fail('Owned group projection did not become available')


@pytest.mark.parametrize('path', ['/api/asset-groups', '/api/asset-groups/' + 'a' * 64 + '/history'])
def test_group_routes_require_authentication_before_reading_projection(api, monkeypatch, path):
    module, client = api

    def forbidden():
        raise AssertionError('Unauthenticated requests must not read a snapshot')

    monkeypatch.setattr(module, '_read_snapshot', forbidden)
    assert client.get(path).status_code == 401


@pytest.mark.parametrize('query', ['limit=0', 'limit=101', 'limit=1&limit=2', 'risk_level=invalid',
                                  'risk_level=high&risk_level=low',
                                  'agent_type=assistant', 'unknown=value', 'cursor=malformed'])
@pytest.mark.parametrize('path', ['/api/asset-groups', '/api/asset-groups/' + 'a' * 64 + '/history'])
def test_group_request_rejection_precedes_database_access(api, monkeypatch, path, query):
    module, client = api

    def forbidden():
        raise AssertionError('Invalid requests must not read a snapshot')

    monkeypatch.setattr(module, '_read_snapshot', forbidden)
    response = client.get(path + '?' + query, headers=headers(module))
    assert response.status_code == 400
    assert response.json['code'] in {'invalid_asset_group_request', 'invalid_cursor'}
    assert response.headers['Cache-Control'] == 'no-store'


@pytest.mark.parametrize('risk', ['high', 'unknown', ' HIGH '])
def test_history_still_rejects_risk_filters_before_database_access(api, monkeypatch, risk):
    module, client = api

    def forbidden():
        raise AssertionError('History filters must be rejected before reading sources')

    monkeypatch.setattr(module, '_read_snapshot', forbidden)
    response = client.get('/api/asset-groups/' + 'a' * 64 + '/history',
                          query_string={'risk_level': risk}, headers=headers(module))
    assert response.status_code == 400 and response.json['code'] == 'invalid_asset_group_request'


def test_group_reads_preserve_observation_ids_caches_sources_and_tenant_boundaries(api):
    module, client = api
    seed(module)
    pending = client.get('/api/asset-groups', headers=headers(module))
    assert pending.status_code == 503
    assert pending.json['code'] == 'asset_group_projection_unavailable'
    publish(module)
    before = module.db.session.execute(select(module.ScanResult)).scalars().all()
    raw = {row.scan_id: row.result for row in before}
    writes = []

    def record(_connection, _cursor, statement, _parameters, _context, _many):
        if statement.lstrip().split(None, 1)[0].upper() in {'INSERT', 'UPDATE', 'DELETE', 'REPLACE', 'CREATE', 'DROP'}:
            writes.append(statement)

    event.listen(module.db.engine, 'before_cursor_execute', record)
    try:
        groups = client.get('/api/asset-groups', headers=headers(module))
        assert groups.status_code == 200, groups.json
        assert groups.json['coverage']['indexed_observations'] == 3
        assert groups.json['coverage']['indexed_groups'] == 2
        own = groups.json['asset_groups']
        filtered = client.get('/api/asset-groups?risk_level=unknown', headers=headers(module))
        assert filtered.status_code == 200 and filtered.json['asset_groups'] == own
        assert client.get('/api/asset-groups?risk_level=high', headers=headers(module)).json['asset_groups'] == []
        assert sorted(value['observation_count'] for value in own) == [1, 2]
        for value in own:
            assert value['identity_status'] == 'grouped'
            assert value['latest_observation']['id'].startswith('tenant-a-')
            assert value['latest_observation_risk']['risk_score'] is None
            assert value['confirmation_history']['remediation_status'] == 'not_evaluated'
            history = client.get(value['confirmation_history']['url'], headers=headers(module))
            assert history.status_code == 200, history.json
            assert len(history.json['history']) == value['observation_count']
            assert all(item['observation_id'].startswith('tenant-a-') for item in history.json['history'])
        other = client.get('/api/asset-groups', headers=headers(module, 'tenant-b'))
        assert {value['id'] for value in own}.isdisjoint(value['id'] for value in other.json['asset_groups'])
        missing = client.get('/api/asset-groups/' + 'f' * 64 + '/history', headers=headers(module, 'tenant-b'))
        foreign = client.get('/api/asset-groups/' + own[0]['id'] + '/history', headers=headers(module, 'tenant-b'))
        assert missing.status_code == foreign.status_code == 404
        assert missing.json == foreign.json
        assert writes == []
    finally:
        event.remove(module.db.engine, 'before_cursor_execute', record)
    module.db.session.expire_all()
    assert {row.scan_id: row.result for row in module.db.session.execute(select(module.ScanResult)).scalars()} == raw
    assert all(row.risk_score == 99 and row.risk_level == 'critical'
               for row in module.db.session.execute(select(module.DiscoveredAgentModel)).scalars())


@pytest.mark.parametrize('function,path', [
    ('group_page', '/api/asset-groups'),
    ('group_history_page', '/api/asset-groups/' + 'a' * 64 + '/history'),
])
def test_unexpected_group_failures_return_static_diagnostics(api, monkeypatch, caplog, function, path):
    module, client = api

    def broken(*args):
        raise RuntimeError('synthetic-private-group-error')

    monkeypatch.setattr(module, function, broken)
    response = client.get(path, headers=headers(module))
    assert response.status_code == 503
    assert response.json == {'success': False, 'error': 'Asset grouping unavailable',
                             'code': 'asset_group_projection_unavailable'}
    assert 'synthetic-private-group-error' not in response.get_data(as_text=True) + caplog.text
