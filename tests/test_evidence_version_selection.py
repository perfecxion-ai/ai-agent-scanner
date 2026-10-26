"""New checkpoint writers select one version without relabeling legacy data."""

from copy import deepcopy
import json
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from src.core.contracts import CheckRecord, validate_scan_result
from src.core.pipeline import run_pipeline
from src.core.risk_projection import project_report_risk
from src.security.security_engine import SecurityTestEngine
from tests.legacy_observation_fixtures import legacy_report


def asset(identifier='asset'):
    return dict(id=identifier, name='Fixture', provider='ollama', model='fixture',
                endpoint='http://192.0.2.1', type='assistant', metadata={})


def evidence(version, identifier='asset'):
    check = CheckRecord('fixture.sample', 'fixture.sample.check', 'fixture-v1',
                        'completed', 'inconclusive', 1, 1).to_dict()
    return dict(agent_id=identifier, status='completed', vulnerabilities=[], checks=[check],
                check_schema_version='1.0', check_evidence_schema_version=version, check_evidence=[])


async def execute(adapter, saved=None, agents=None):
    async def capture(value):
        saved.append((deepcopy(value), json.dumps(value, sort_keys=True)))
    risk = SimpleNamespace(assess_risks=AsyncMock(side_effect=AssertionError('No supported assessment')))
    value = await run_pipeline(None, adapter, risk, None, 'security_only',
                               agents=[asset()] if agents is None else agents,
                               checkpoint_callback=capture if saved is not None else None)
    risk.assess_risks.assert_not_called()
    return value


@pytest.mark.asyncio
async def test_normal_writer_uses_mixed_schema_before_its_first_checkpoint():
    saved = []
    result = await execute(SecurityTestEngine(), saved, [])
    assert saved
    for value, encoded in [*saved, (result, json.dumps(result, sort_keys=True))]:
        assert value['check_evidence_schema_version'] == '3.0'
        assert value['checkpoint']['version'] == '4.0'
        assert json.dumps(value, sort_keys=True) == encoded


@pytest.mark.asyncio
@pytest.mark.parametrize('version,checkpoint', [('1.0', '2.0'), ('2.0', '3.0'), ('3.0', '4.0')])
async def test_declared_adapter_preserves_one_supported_version(version, checkpoint):
    adapter = SimpleNamespace(check_evidence_schema_version=version,
                              test_agents=AsyncMock(return_value=[evidence(version)]))
    saved = []
    result = await execute(adapter, saved)
    assert result['check_evidence_schema_version'] == version
    assert result['checkpoint']['version'] == checkpoint
    assert all(value['check_evidence_schema_version'] == version for value, _ in saved)
    assert all(value['checkpoint']['version'] == checkpoint for value, _ in saved)
    assert all(json.dumps(value, sort_keys=True) == encoded for value, encoded in saved)


@pytest.mark.asyncio
@pytest.mark.parametrize('declared,returned', [
    ('1.0', '2.0'), ('2.0', '1.0'), ('1.0', '3.0'), ('3.0', '1.0'), ('2.0', '3.0'), ('3.0', '2.0'),
])
async def test_declared_adapter_cannot_switch_versions_after_baseline(declared, returned):
    adapter = SimpleNamespace(check_evidence_schema_version=declared,
                              test_agents=AsyncMock(return_value=[evidence(returned)]))
    saved = []
    with pytest.raises(ValueError, match='Mixed evidence versions'):
        await execute(adapter, saved)
    assert len(saved) == 2
    assert all(value['check_evidence_schema_version'] == declared for value, _ in saved)
    assert all(json.dumps(value, sort_keys=True) == encoded for value, encoded in saved)


@pytest.mark.asyncio
@pytest.mark.parametrize('declaration', [None, '', False, 2, [], {}, 'future-private-value-41712'])
async def test_bad_adapter_declaration_fails_before_any_checkpoint(declaration):
    adapter = SimpleNamespace(check_evidence_schema_version=declaration, test_agents=AsyncMock())
    saved = []
    with pytest.raises(ValueError, match='Unsupported adapter evidence declaration') as caught:
        await execute(adapter, saved)
    assert saved == []
    adapter.test_agents.assert_not_called()
    assert 'future-private-value-41712' not in str(caught.value)


@pytest.mark.asyncio
async def test_adapter_declaration_is_literal_and_cannot_execute_a_descriptor():
    class Adapter:
        test_agents = AsyncMock()
        @property
        def check_evidence_schema_version(self):
            raise AssertionError('SyntheticPrivateDeclaration41712')
    saved = []
    with pytest.raises(ValueError, match='^Unsupported adapter evidence declaration$'):
        await execute(Adapter(), saved)
    assert saved == []
    Adapter.test_agents.assert_not_called()


@pytest.mark.asyncio
@pytest.mark.parametrize('version', ['2.0', '3.0'])
async def test_undeclared_mixed_adapter_cannot_upgrade_an_acknowledged_baseline(version):
    adapter = SimpleNamespace(test_agents=AsyncMock(return_value=[evidence(version)]))
    saved = []
    with pytest.raises(ValueError, match='require an explicit declaration'):
        await execute(adapter, saved)
    assert len(saved) == 2
    assert all(value['checkpoint']['version'] == '1.0' for value, _ in saved)
    assert all('check_evidence_schema_version' not in value for value, _ in saved)
    assert all(json.dumps(value, sort_keys=True) == encoded for value, encoded in saved)


@pytest.mark.asyncio
async def test_legacy_adapter_keeps_its_existing_empty_baseline_negotiation():
    adapter = SimpleNamespace(test_agents=AsyncMock(return_value=[evidence('1.0')]))
    saved = []
    result = await execute(adapter, saved)
    assert saved[0][0]['checkpoint']['version'] == '1.0'
    assert result['check_evidence_schema_version'] == '1.0'
    assert result['checkpoint']['version'] == '2.0'


@pytest.mark.asyncio
@pytest.mark.parametrize('version', ['2.0', '3.0'])
async def test_noncheckpoint_forwarding_can_infer_one_supported_version(version):
    adapter = SimpleNamespace(test_agents=AsyncMock(return_value=[evidence(version)]))
    result = await execute(adapter)
    assert result['check_evidence_schema_version'] == version
    assert 'checkpoint' not in result


@pytest.mark.asyncio
@pytest.mark.parametrize('first,second', [('1.0', '2.0'), ('2.0', '3.0'), ('3.0', '2.0')])
async def test_noncheckpoint_adapter_cannot_mix_old_and_new_assets(first, second):
    adapter = SimpleNamespace(test_agents=AsyncMock(side_effect=[
        [evidence(first, 'first')], [evidence(second, 'second')]]))
    with pytest.raises(ValueError, match='Mixed evidence versions'):
        await execute(adapter, agents=[asset('first'), asset('second')])


@pytest.mark.parametrize('view', ['root', 'agent', 'security'])
def test_cross_view_version_mismatch_cannot_expose_historical_score(view):
    value = legacy_report('prompt-final')
    target = value if view == 'root' else value['agents' if view == 'agent' else 'security_results'][0]
    target['check_evidence_schema_version'] = '2.0'
    with pytest.raises(ValueError):
        validate_scan_result(value)
    summary, agents = project_report_risk(value)
    assert summary['overall_risk_score'] is None
    assert all(item['risk_score'] is None for item in agents.values())


@pytest.mark.parametrize('counter', [True, 1.0])
def test_security_view_counter_types_cannot_alias_valid_agent_receipts(counter):
    value = legacy_report('prompt-final')
    assert value['security_results'][0]['check_evidence'][0]['requests_attempted'] == 1
    value['security_results'][0]['check_evidence'][0]['requests_attempted'] = counter
    summary, agents = project_report_risk(value)
    assert summary['overall_risk_score'] is None
    assert all(item['risk_score'] is None for item in agents.values())


@pytest.mark.parametrize('field,value', [('endpoint', 'https://different.example/api/chat'),
                                        ('evidence_context_id', 'different-public-context')])
def test_legacy_confirmed_tenant_views_require_the_same_target_binding(field, value):
    report = legacy_report('subject-final')
    assert project_report_risk(report)[0]['overall_risk_score'] == 90
    report['security_results'][0][field] = value
    summary, agents = project_report_risk(report)
    assert summary['overall_risk_score'] is None
    assert all(item['risk_score'] is None for item in agents.values())


@pytest.mark.asyncio
@pytest.mark.parametrize('field,value', [('endpoint', 'https://different.example/api/chat'),
                                        ('evidence_context_id', 'different-public-context')])
async def test_live_mixed_tenant_views_require_the_same_target_binding(field, value):
    from src.core.transport import ScanBudget, scan_transport
    from src.risk.risk_assessor import RiskAssessment
    from tests.tenant_progress_fixture import tenant_progress_target, unfinished_tenant_engine

    with tenant_progress_target('attack_cleanup') as (agent, _):
        with scan_transport(ScanBudget(allow_loopback=True, max_requests=8)):
            report = await run_pipeline(None, unfinished_tenant_engine(), RiskAssessment(), None,
                                        'security_only', agents=[agent])
    assert report['check_evidence_schema_version'] == '3.0'
    assert project_report_risk(report)[0]['overall_risk_score'] == 90
    report['security_results'][0][field] = value
    summary, agents = project_report_risk(report)
    assert summary['overall_risk_score'] is None
    assert all(item['risk_score'] is None for item in agents.values())
