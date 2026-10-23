"""Model selections are authorized and copied from the saved source snapshot."""

from tests.claimed_execution import execute_scan

import pytest

from tests.test_api_auth import api as api, headers
from tests.test_pipeline import asset, engines, add_scan


@pytest.mark.asyncio
async def test_source_model_selection_survives_queue_without_mutating_source(api, monkeypatch):
    module, client = api
    discovery, security, risk = engines([asset()])
    monkeypatch.setattr(module, 'discovery_engine', discovery)
    monkeypatch.setattr(module, 'security_engine', security)
    monkeypatch.setattr(module, 'risk_assessor', risk)
    add_scan(module, 'source')
    await execute_scan(module, 'source', 'discovery_only', {}, {})
    config = {'source_scan_id': 'source', 'model_overrides': {'stable-asset': 'selected-model'}}
    response = client.post('/api/scans', headers=headers(module), json={
        'scan_type': 'security_only', 'scan_config': config})
    assert response.status_code == 202
    scan_id = response.json['scan_id']
    queued = module.db.session.get(module.ScanSession, scan_id)
    assert queued.scan_config['model_overrides'] == config['model_overrides']
    await execute_scan(module, scan_id, 'security_only', {}, queued.scan_config)
    assert security.test_agents.call_args.args[0][0]['model'] == 'selected-model'
    module.db.session.expire_all()
    assert 'model' not in module.db.session.get(module.ScanResult, 'source').result['agents'][0]
    assert module.db.session.get(module.ScanResult, scan_id).result['agents'][0]['model'] == 'selected-model'


@pytest.mark.asyncio
async def test_unknown_selection_never_enters_queue_and_foreign_source_is_hidden(api, monkeypatch):
    module, client = api
    discovery, security, risk = engines([asset()])
    monkeypatch.setattr(module, 'discovery_engine', discovery)
    monkeypatch.setattr(module, 'security_engine', security)
    monkeypatch.setattr(module, 'risk_assessor', risk)
    add_scan(module, 'source')
    await execute_scan(module, 'source', 'discovery_only', {}, {})
    request = {'scan_type': 'security_only', 'scan_config': {
        'source_scan_id': 'source', 'model_overrides': {'unknown': 'selected-model'}}}
    assert client.post('/api/scans', headers=headers(module), json=request).status_code == 400
    assert client.post('/api/scans', headers=headers(module, 'tenant-b'), json=request).status_code == 404
    assert module.ScanJob.query.filter(module.ScanJob.scan_id != 'source').count() == 0
