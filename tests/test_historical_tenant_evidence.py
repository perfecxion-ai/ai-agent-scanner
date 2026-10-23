"""Historical tenant positives remain archived claims, never current verdicts."""

from copy import deepcopy
import hashlib
import json

import pytest

from src.core.contracts import CheckRecord, confirmed_findings, risk_assessment_eligible
from src.core.tenant_probe_policy import TENANT_ATTACK_PROMPTS
from tests.controlled_access import result as controlled_result, target as access_target
from tests.test_tenant_controls import (
    configured_agent, prepared_environment as prepared_environment, run_tenant,
    tenant_server as tenant_server,
)


def historical_tenant(*, status='completed'):
    definition = {'semantics': 'nondisclosure-inconclusive-v2', 'prompts': list(TENANT_ATTACK_PROMPTS)}
    version = '1:' + hashlib.sha256(json.dumps(
        [definition, 'ollama', 'fixture-model'], sort_keys=True).encode()).hexdigest()
    rule = 'tenant_isolation_violation'
    check = CheckRecord(rule, rule + '.sample', version, 'completed', 'confirmed', 5, 5,
                        evidence_context_id='historical-tenant-v1').to_dict()
    finding = {key: check[key] for key in ('rule_id', 'probe_id', 'probe_version', 'evidence_context_id')}
    finding.update(id='historical-tenant-finding', vulnerability_type=rule,
                   severity='critical', evidence_status='confirmed')
    return dict(agent_id='fixture', endpoint='https://fixture.invalid/', provider='ollama',
                model='fixture-model', evidence_context_id='historical-tenant-v1', status=status,
                check_schema_version='1.0', checks=[check], vulnerabilities=[finding])


@pytest.mark.parametrize('status', ['completed', 'partial', 'failed'])
def test_old_finalized_tenant_claim_is_not_current_evidence(status):
    result = historical_tenant(status=status)
    original = deepcopy(result)
    assert confirmed_findings(result) == []
    assert not risk_assessment_eligible(result)
    assert result == original


@pytest.mark.asyncio
@pytest.mark.parametrize('companion', ['passed', 'confirmed'])
@pytest.mark.parametrize('claim', ['paired', 'finding_only', 'check_only', 'mismatched',
                                  'type_only', 'rule_only', 'unhashable_id'])
async def test_unsupported_tenant_positive_cannot_inherit_companion_numeric_risk(companion, claim):
    result = await controlled_result(access_target(provider='ollama'), disclose=companion == 'confirmed')
    selected = deepcopy(result['vulnerabilities'])
    assert risk_assessment_eligible(result)
    old = historical_tenant()
    if claim == 'finding_only':
        old['checks'] = []
    elif claim == 'check_only':
        old['vulnerabilities'] = []
    elif claim == 'mismatched':
        old['vulnerabilities'][0]['probe_version'] = 'unsupported-version'
    elif claim == 'type_only':
        old['checks'][0]['rule_id'] = old['vulnerabilities'][0]['rule_id'] = 'unrelated.fixture'
    elif claim == 'rule_only':
        old['vulnerabilities'][0]['vulnerability_type'] = 'unrelated.fixture'
    elif claim == 'unhashable_id':
        old['vulnerabilities'][0]['id'] = {'not': 'an occurrence identity'}
    result['checks'].extend(old['checks'])
    result['vulnerabilities'].extend(old['vulnerabilities'])
    original = deepcopy(result)
    assert confirmed_findings(result) == selected
    assert not risk_assessment_eligible(result)
    assert result == original


@pytest.mark.asyncio
@pytest.mark.parametrize('outcome', ['passed', 'inconclusive', 'heuristic'])
async def test_old_nonpositive_tenant_check_does_not_erase_supported_access(outcome):
    result = await controlled_result(access_target(provider='ollama'), disclose=False)
    check = historical_tenant()['checks'][0]
    check['outcome'] = outcome
    result['checks'].append(check)
    assert risk_assessment_eligible(result)


@pytest.mark.asyncio
async def test_supported_current_tenant_finding_remains_selectable_beside_old_claim(tenant_server):
    endpoint, _ = tenant_server
    current = await run_tenant(configured_agent(endpoint))
    selected = deepcopy(current['vulnerabilities'])
    old = historical_tenant()
    current['checks'].extend(old['checks'])
    current['vulnerabilities'].extend(old['vulnerabilities'])
    assert confirmed_findings(current) == selected
    assert not risk_assessment_eligible(current)
