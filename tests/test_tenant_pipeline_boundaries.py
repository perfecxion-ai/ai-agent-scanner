"""Server admission guards precede credential lookup and checkpoint creation."""

from copy import deepcopy
from unittest.mock import AsyncMock

import pytest

from src.core import pipeline
from src.core.tenant_evidence import TenantEvidenceError, reject_private_tenant_inputs
from src.risk.risk_assessor import RiskAssessment
from src.security.security_engine import SecurityTestEngine


def target():
    return {'id': 'tenant-boundary-fixture', 'name': 'Tenant boundary fixture',
            'endpoint': 'https://fixture.example/v1/chat/completions',
            'provider': 'openai-compatible', 'model': 'fixture-model', 'metadata': {}}


@pytest.mark.asyncio
@pytest.mark.parametrize('scan_type', ['full', 'discovery_only', 'security_only'])
async def test_server_early_guard_rejects_before_resolution_or_checkpoint(monkeypatch, scan_type):
    agent = {**target(), 'tenant_evidence': {'schema_version': '1.0'},
             'api_key_env': 'TENANT_BOUNDARY_UNUSED_KEY'}
    discovery = type('Discovery', (), {'discover_agents': AsyncMock(return_value=[agent])})()
    security = SecurityTestEngine()
    security.test_agents = AsyncMock()
    sink = AsyncMock()

    def forbidden(*args, **kwargs):
        raise AssertionError('Server rejected input must not resolve a credential')

    monkeypatch.setattr(pipeline, 'resolve_api_key', forbidden)
    with pytest.raises(TenantEvidenceError):
        await pipeline.run_pipeline(
            discovery, security, RiskAssessment(), None, scan_type, agents=[agent],
            early_agent_validator=reject_private_tenant_inputs, checkpoint_callback=sink)
    sink.assert_not_awaited()
    security.test_agents.assert_not_awaited()


@pytest.mark.asyncio
async def test_guard_rechecks_validator_output_before_new_credentials(monkeypatch):
    looked_up = []

    def lookup(agent):
        assert 'tenant_evidence' not in agent
        looked_up.append(agent['id'])
        return None

    def validator(agents):
        changed = deepcopy(agents)
        changed[0]['tenant_evidence'] = {'schema_version': '1.0'}
        changed[0]['api_key_env'] = 'TENANT_BOUNDARY_UNUSED_KEY'
        return changed

    monkeypatch.setattr(pipeline, 'resolve_api_key', lookup)
    sink = AsyncMock()
    with pytest.raises(TenantEvidenceError):
        await pipeline.run_pipeline(
            None, SecurityTestEngine(), RiskAssessment(), None, 'security_only',
            agents=[target()], agent_validator=validator,
            early_agent_validator=reject_private_tenant_inputs, checkpoint_callback=sink)
    assert looked_up == ['tenant-boundary-fixture']
    sink.assert_not_awaited()


@pytest.mark.asyncio
async def test_invalid_tenant_input_stops_all_engine_testers_and_progress():
    security = SecurityTestEngine()
    testers = (security.prompt_tester, security.access_tester, security.privacy_tester)
    for tester in testers:
        tester.test_agent = AsyncMock()
    progress = AsyncMock()
    invalid = {**target(), 'id': 'invalid-fixture', 'tenant_evidence': {}}
    with pytest.raises(TenantEvidenceError):
        await security.test_agents([target(), invalid], progress_callback=progress)
    for tester in testers:
        tester.test_agent.assert_not_awaited()
    progress.assert_not_awaited()
