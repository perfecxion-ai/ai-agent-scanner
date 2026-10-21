"""Partial discovery is reusable inventory, never complete coverage."""

from copy import deepcopy

import pytest

from src.core.transport import ScanBudget, current_budget, scan_transport
from tests.test_api_auth import api as api, headers
from tests.test_pipeline import asset, engines, add_scan


async def source_scan(module, monkeypatch):
    discovery, security, risk = engines([asset()])
    monkeypatch.setattr(module, 'discovery_engine', discovery)
    monkeypatch.setattr(module, 'security_engine', security)
    monkeypatch.setattr(module, 'risk_assessor', risk)
    add_scan(module, 'source', mode='discovery_only')
    budget = ScanBudget()
    budget.failures = 1
    with scan_transport(budget):
        await module._execute_scan('source', 'discovery_only', {}, {})
    module.db.session.expire_all()
    assert module.db.session.get(module.ScanSession, 'source').status == 'partial'
    return security


def request_body(identifier='stable-asset'):
    return {'scan_type': 'security_only', 'scan_config': {
        'source_scan_id': 'source', 'model_overrides': {identifier: 'chosen-model'}}}


@pytest.mark.asyncio
async def test_partial_source_accepts_snapshot_id_and_preserves_coverage(api, monkeypatch):
    module, client = api
    security = await source_scan(module, monkeypatch)
    original = deepcopy(module.db.session.get(module.ScanResult, 'source').result)
    result = client.get('/api/scans/source/results', headers=headers(module)).json
    snapshot_id = result['results']['agents'][0]['id']
    assert snapshot_id != 'stable-asset'
    response = client.post('/api/scans', headers=headers(module), json=request_body(snapshot_id))
    assert response.status_code == 202, response.json
    scan = module.db.session.get(module.ScanSession, response.json['scan_id'])
    assert scan.scan_config['model_overrides'] == {'stable-asset': 'chosen-model'}
    await module._execute_scan(scan.id, 'security_only', {}, scan.scan_config)
    assert security.test_agents.call_args.args[0][0]['model'] == 'chosen-model'
    module.db.session.expire_all()
    report = module.db.session.get(module.ScanResult, scan.id).result
    assert report['source_inventory']['status'] == 'partial'
    assert report['source_inventory']['coverage_complete'] is False
    assert 'incomplete' in report['source_inventory']['warning']
    assert module.db.session.get(module.ScanResult, 'source').result == original


@pytest.mark.asyncio
@pytest.mark.parametrize('status', ['queued', 'running', 'cancelled', 'failed', 'interrupted'])
async def test_non_replayable_source_rejected_at_admission_and_worker(api, monkeypatch, status):
    module, client = api
    security = await source_scan(module, monkeypatch)
    source = module.db.session.get(module.ScanSession, 'source')
    source.status = status
    module.db.session.commit()
    assert client.post('/api/scans', headers=headers(module), json=request_body()).status_code == 400
    add_scan(module, 'attempt', mode='security_only')
    await module._execute_scan('attempt', 'security_only', {}, request_body()['scan_config'])
    security.test_agents.assert_not_called()
    module.db.session.expire_all()
    assert module.db.session.get(module.ScanSession, 'attempt').status == 'failed'


@pytest.mark.asyncio
@pytest.mark.parametrize('mutation', ['missing_finalization', 'report_status', 'snapshot_endpoint',
                                     'snapshot_id', 'redacted', 'report_invalid', 'agents_null',
                                     'metadata_null', 'snapshot_id_list'])
async def test_partial_source_requires_final_report_matching_inventory(api, monkeypatch, mutation):
    module, client = api
    await source_scan(module, monkeypatch)
    source = module.db.session.get(module.ScanSession, 'source')
    report = module.db.session.get(module.ScanResult, 'source')
    snapshot = module.DiscoveredAgentModel.query.filter_by(scan_id='source').one()
    value = deepcopy(report.result)
    if mutation == 'missing_finalization':
        source.completed_at = None
    elif mutation == 'report_status':
        value['status'] = 'completed'
    elif mutation == 'snapshot_endpoint':
        snapshot.endpoint_url = 'https://192.0.2.2'
    elif mutation == 'snapshot_id':
        snapshot.metadata_json = {'asset_id': 'other'}
    elif mutation == 'redacted':
        value['agents'][0]['endpoint_redacted'] = True
    elif mutation == 'report_invalid':
        value['summary'] = None
    elif mutation == 'agents_null':
        value['agents'] = None
    elif mutation == 'metadata_null':
        snapshot.metadata_json = None
    elif mutation == 'snapshot_id_list':
        snapshot.metadata_json = {'asset_id': []}
    report.result = value
    module.db.session.commit()
    response = client.post('/api/scans', headers=headers(module), json=request_body())
    assert response.status_code == 400, response.json
    assert module.ScanJob.query.count() == 0


@pytest.mark.asyncio
async def test_partial_source_rechecks_tenant_and_current_scope(api, monkeypatch):
    module, client = api
    security = await source_scan(module, monkeypatch)
    assert client.post('/api/scans', headers=headers(module, 'tenant-b'), json=request_body()).status_code == 404
    response = client.post('/api/scans', headers=headers(module), json=request_body())
    assert response.status_code == 202
    module.app.config['SCAN_ALLOWED_NETWORKS'] = ('198.51.100.0/24',)
    scan = module.db.session.get(module.ScanSession, response.json['scan_id'])
    await module._execute_scan(scan.id, 'security_only', {}, scan.scan_config)
    security.test_agents.assert_not_called()
    module.db.session.expire_all()
    assert module.db.session.get(module.ScanSession, scan.id).status == 'failed'


@pytest.mark.asyncio
async def test_snapshot_and_stable_id_cannot_select_one_asset_twice(api, monkeypatch):
    module, client = api
    await source_scan(module, monkeypatch)
    snapshot = module.DiscoveredAgentModel.query.one()
    body = request_body()
    body['scan_config']['model_overrides'][snapshot.id] = 'different-model'
    response = client.post('/api/scans', headers=headers(module), json=body)
    assert response.status_code == 400
    assert 'same source asset' in response.json['error']


@pytest.mark.asyncio
async def test_partial_source_template_and_schedule_policy_token(api, monkeypatch):
    module, client = api
    await source_scan(module, monkeypatch)
    definition = {**request_body(), 'scan_name': 'Partial inventory review'}
    response = client.post('/api/templates', headers=headers(module), json=definition)
    assert response.status_code == 201, response.json
    row = module.db.session.get(module.ScanTemplate, response.json['template']['id'])
    _, token = module._schedule_token(module._template_definition(row), 'tenant-a')
    assert token[1] == 'partial'


def test_server_request_timeout_is_owned_by_global_policy(api, monkeypatch):
    module, _ = api
    monkeypatch.setitem(module.app.config, 'SCAN_REQUEST_TIMEOUT_SECONDS', 75)
    observed = []
    async def execute(*args):
        observed.append(current_budget().request_timeout_seconds)
    monkeypatch.setattr(module, '_execute_scan', execute)
    module._run_scan_in_thread('fixture', 'discovery_only', {}, {})
    assert observed == [75]
