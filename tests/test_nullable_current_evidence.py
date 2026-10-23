"""Current HTTP-produced evidence remains eligible after a real schema upgrade."""

import json
from unittest.mock import AsyncMock

import pytest
from sqlalchemy import select

from src.core.pipeline import run_pipeline
from src.core.schema import initialize_schema
from src.core.transport import ScanBudget, scan_transport
from src.risk.risk_assessor import RiskAssessment
from src.security.security_engine import SecurityTestEngine
from tests.test_api_auth import api as api
from tests.test_nullable_score_migration import migration as migration, seed
from tests.test_prompt_request_reflection import (
    echo_target as echo_target, fixture_agent, pacing_and_isolation as pacing_and_isolation,
    pipeline as prompt_pipeline,
)
from tests.test_tenant_controls import (
    configured_agent, tenant_server as tenant_server,
    prepared_environment as prepared_environment,
)


@pytest.mark.asyncio
@pytest.mark.parametrize('partial', [False, True])
@pytest.mark.parametrize('objective,expected', [('prompt', 70.0), ('tenant', 90.0)])
async def test_actual_current_evidence_survives_cache_migration(
        migration, echo_target, tenant_server, monkeypatch, partial, objective, expected):
    module, engine = migration
    checkpoints = []
    if objective == 'prompt':
        endpoint, state = echo_target
        final = await prompt_pipeline(fixture_agent(endpoint, 'leak', monkeypatch), None, checkpoints)
    else:
        endpoint, state = tenant_server
        security = SecurityTestEngine()
        security.prompt_tester.test_agent = AsyncMock(return_value=[])
        security.access_tester.test_agent = AsyncMock(return_value=[])
        security.privacy_tester.test_agent = security.privacy_tester._test_tenant_isolation
        async def save(report):
            checkpoints.append(report)
        with scan_transport(ScanBudget(allow_loopback=True)):
            final = await run_pipeline(None, security, RiskAssessment(), None, 'security_only',
                                       agents=[configured_agent(endpoint)], checkpoint_callback=save)
    selected = next(item for item in checkpoints if item['summary']['overall_risk_score'] == expected) if partial else final
    assert state['calls'] and selected['agents'][0]['risk_score'] == expected
    assert selected['agents'][0]['risk_coverage_status'] == ('partial' if partial else 'sampled')
    archive = json.dumps(selected, indent=3)
    seed(engine, selected, metadata={'asset_id': selected['agents'][0]['id']})
    with engine.begin() as connection:
        connection.exec_driver_sql('UPDATE scan_result SET result=?', (archive,))
    initialize_schema(engine, module.db.metadata)
    with engine.connect() as connection:
        assert connection.scalar(select(module.ScanSession.overall_risk_score)) == expected
        assert connection.scalar(select(module.DiscoveredAgentModel.risk_score)) == expected
        assert connection.scalar(select(module.DiscoveredAgentModel.risk_level)) == ('high' if objective == 'prompt' else 'critical')
        assert connection.exec_driver_sql('SELECT result FROM scan_result').scalar_one() == archive
