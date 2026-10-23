"""Actual tenant observations retain the same verdict in API and archive views."""

import json
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from src.core.pipeline import run_pipeline
from src.core.transport import ScanBudget, scan_transport
from src.risk.risk_assessor import RiskAssessment
from src.security.security_engine import SecurityTestEngine
from tests.test_api_auth import api as api, headers
from tests.test_api_risk_projection import outputs
from tests.test_historical_prompt_projection import assert_archive_unchanged, seed_archived
from tests.test_tenant_cli_workflow import cli_tenant_server as cli_tenant_server
from tests.test_tenant_controls import (
    configured_agent, prepared_environment as prepared_environment,
    OWNER_KEY, TESTED_KEY, OWNER_MARKER, TESTED_MARKER,
)


@pytest.mark.asyncio
@pytest.mark.parametrize('partial', [False, True])
async def test_real_tenant_score_matches_results_inventory_and_saved_pipeline(
        api, cli_tenant_server, monkeypatch, partial):
    module, client = api
    endpoint, state = cli_tenant_server
    for name in ('prompt_injection_tests', 'access_control_tests', 'data_privacy_tests'):
        monkeypatch.setattr('src.security.' + name + '.asyncio', SimpleNamespace(sleep=AsyncMock()))
    snapshots = []
    async def save(report):
        snapshots.append(json.loads(json.dumps(report)))
    with scan_transport(ScanBudget(allow_loopback=True)):
        final = await run_pipeline(None, SecurityTestEngine(), RiskAssessment(), None, 'security_only',
                                   agents=[configured_agent(endpoint)], checkpoint_callback=save)
    selected = next(item for item in snapshots if item['summary']['overall_risk_score'] == 90) if partial else final
    report = json.loads(json.dumps(selected))
    assert state['calls'] and report['agents'][0]['risk_score'] == 90
    seed_archived(module, report)
    for _ in range(2):
        module.db.session.remove()
        results, listed = outputs(module, client)
        assert results['summary']['overall_risk_score'] == 90
        assert results['pipeline'] == report
        for item in (results['agents'][0], listed):
            assert item['risk_score'] == 90
            assert item['risk_level'] == 'critical'
            assert item['risk_coverage_status'] == ('partial' if partial else 'sampled')
        filtered = client.get('/api/agents?risk_level=critical', headers=headers(module)).json['agents']
        assert [item['id'] for item in filtered] == ['fixture-snapshot']
        assert_archive_unchanged(module, client, report)
    encoded = json.dumps([results, listed, report])
    assert all(secret not in encoded for secret in (OWNER_KEY, TESTED_KEY, OWNER_MARKER, TESTED_MARKER))
