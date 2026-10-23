"""Current prompt verdicts require receipts without rewriting archived claims."""

import asyncio
from copy import deepcopy
import hashlib
import json
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from src.core.contracts import (
    CheckRecord, collect_checks, collect_evidence, confirmed_findings,
    proves_absence, risk_assessment_eligible, validate_check_evidence,
)
from src.core.prompt_catalog import baseline_payloads
from src.core.transport import ScanBudget, scan_transport
from src.risk.risk_assessor import RiskAssessment
from src.security.prompt_injection_tests import PromptInjectionTester
from tests.controlled_access import result as controlled_result, target as access_target
from tests.test_prompt_evidence import (
    CATEGORY, agent, asset_for, target as target, valid_asset,
)


def historical_prompt(*, status='completed'):
    """Build the pre-receipt finalized-check shape with its original probe hash."""
    payloads = baseline_payloads()[CATEGORY][:5]
    definition = {'semantics': 'nondisclosure-inconclusive-v2', 'payloads': payloads}
    version = '1:' + hashlib.sha256(json.dumps(
        [definition, 'ollama', 'fixture-model'], sort_keys=True).encode()).hexdigest()
    rule = 'prompt_injection.' + CATEGORY
    check = CheckRecord(rule, rule + '.sample', version, 'completed', 'confirmed', 5, 5,
                        evidence_context_id='historical-fixture-v1').to_dict()
    finding = {key: check[key] for key in ('rule_id', 'probe_id', 'probe_version', 'evidence_context_id')}
    finding.update(id='historical-fixture-finding', agent_id='fixture',
                   vulnerability_type='prompt_injection', category=CATEGORY,
                   severity='high', evidence_status='confirmed', payload=payloads[0], status_code=200)
    return {'agent_id': 'fixture', 'provider': 'ollama', 'model': 'fixture-model',
            'status': status, 'check_schema_version': '1.0',
            'checks': [check], 'vulnerabilities': [finding]}


@pytest.mark.asyncio
@pytest.mark.parametrize('status', ['completed', 'partial', 'failed'])
async def test_original_prompt_probe_hash_does_not_establish_current_risk(status):
    evidence = historical_prompt(status=status)
    original = deepcopy(evidence)
    assert validate_check_evidence(evidence) is evidence
    assert confirmed_findings(evidence) == []
    assert not risk_assessment_eligible(evidence)
    for call in (RiskAssessment()._assess_agent_risk(evidence), RiskAssessment().assess_risks([evidence])):
        with pytest.raises(ValueError, match='^Current risk assessment requires supported evidence$'):
            await call
    assert evidence == original


@pytest.mark.asyncio
@pytest.mark.parametrize('companion', ['passed', 'confirmed'])
@pytest.mark.parametrize('claim', ['paired', 'finding_only', 'check_only', 'mismatched',
                                  'type_only', 'rule_only', 'unhashable_id'])
async def test_unsupported_prompt_positive_cannot_inherit_a_companion_assessment(companion, claim):
    evidence = await controlled_result(access_target(provider='ollama'), disclose=companion == 'confirmed')
    supported = deepcopy(evidence['vulnerabilities'])
    assert risk_assessment_eligible(evidence)
    old = historical_prompt()
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
    evidence['checks'].extend(old['checks'])
    evidence['vulnerabilities'].extend(old['vulnerabilities'])
    original = deepcopy(evidence)
    assert confirmed_findings(evidence) == supported
    assert not risk_assessment_eligible(evidence)
    with pytest.raises(ValueError, match='^Current risk assessment requires supported evidence$'):
        await RiskAssessment()._assess_agent_risk(evidence)
    assert evidence == original


@pytest.mark.asyncio
@pytest.mark.parametrize('outcome', ['inconclusive', 'heuristic', 'passed'])
@pytest.mark.parametrize('disclose', [False, True])
async def test_nonpositive_old_prompt_check_does_not_erase_supported_access_evidence(outcome, disclose):
    evidence = await controlled_result(access_target(provider='ollama'), disclose=disclose)
    old = historical_prompt()
    old['checks'][0]['outcome'] = outcome
    evidence['checks'].extend(old['checks'])
    assert risk_assessment_eligible(evidence)
    assert (await RiskAssessment()._assess_agent_risk(evidence))['overall_risk_score'] == (70 if disclose else 0)


@pytest.mark.asyncio
@pytest.mark.parametrize('suite', [None, 'protected-disclosure-v1'])
@pytest.mark.parametrize('request_limit', [1, 5])
async def test_actual_current_prompt_producer_remains_eligible(target, monkeypatch, suite, request_limit):
    endpoint, target_state = target
    item, tester = agent(endpoint), PromptInjectionTester(prompt_suite=suite)
    monkeypatch.setattr('src.security.prompt_injection_tests.asyncio',
                        SimpleNamespace(sleep=AsyncMock(), CancelledError=asyncio.CancelledError))
    with scan_transport(ScanBudget(allow_loopback=True, max_requests=request_limit)), collect_checks() as checks, \
            collect_evidence(item) as state:
        findings = await tester._test_injection_category(item, CATEGORY, tester.injection_payloads[CATEGORY])
    evidence = asset_for(item, state, checks, findings)
    evidence['status'] = 'completed' if request_limit == 5 else 'partial'
    original = deepcopy(evidence)
    assert len(findings) == len(state.receipts) == target_state['calls'] == request_limit
    assert {receipt['source_version'] for receipt in state.receipts} == {'2.0'}
    assert checks[0]['status'] == ('completed' if request_limit == 5 else 'failed')
    assert confirmed_findings(evidence) == findings
    assert risk_assessment_eligible(evidence)
    assert (await RiskAssessment()._assess_agent_risk(evidence))['overall_risk_score'] == 70
    assert evidence == original


@pytest.mark.parametrize('mutation', ['draft_source', 'unknown_source', 'empty_receipts',
                                     'missing_receipts', 'missing_version', 'stripped_contract',
                                     'unlinked_finding', 'unknown_probe', 'wrong_context'])
def test_invalid_or_removed_receipts_cannot_restore_finalized_fallback(mutation):
    evidence = valid_asset()
    receipt = evidence['check_evidence'][0]
    keys = ('rule_id', 'probe_id', 'probe_version', 'evidence_context_id')
    evidence['checks'] = [CheckRecord(**{key: receipt[key] for key in keys}, status='completed',
                                    outcome='confirmed', requests_attempted=1, responses_evaluated=1).to_dict()]
    if mutation in {'draft_source', 'unknown_source'}:
        receipt['source_version'] = '1.0' if mutation == 'draft_source' else 'future'
    elif mutation == 'empty_receipts':
        evidence['check_evidence'] = []
    elif mutation == 'missing_receipts':
        evidence.pop('check_evidence')
    elif mutation == 'missing_version':
        evidence.pop('check_evidence_schema_version')
    elif mutation == 'stripped_contract':
        for key in ('check_evidence', 'check_evidence_schema_version', 'check_evidence_run_id'):
            evidence.pop(key)
        evidence['vulnerabilities'][0].pop('check_evidence_id')
    elif mutation == 'unlinked_finding':
        evidence['vulnerabilities'][0].pop('check_evidence_id')
    elif mutation == 'unknown_probe':
        for record in [receipt, *evidence['checks'], *evidence['vulnerabilities']]:
            record['probe_version'] = '1:' + '0' * 64
    else:
        evidence['checks'][0]['evidence_context_id'] = 'different-context'
    original = deepcopy(evidence)
    assert not risk_assessment_eligible(evidence)
    assert confirmed_findings(evidence) == []
    assert evidence == original


@pytest.mark.parametrize('outcome', ['inconclusive', 'passed'])
def test_old_prompt_nondisclosure_cannot_resolve_the_original_claim(outcome):
    before = historical_prompt()
    finding = before['vulnerabilities'][0]
    quiet = deepcopy(before['checks'][0])
    quiet['outcome'] = outcome
    assert not proves_absence(quiet, finding, asset=before, previous_asset=before)


@pytest.mark.asyncio
async def test_standalone_collection_does_not_become_current_risk(target, monkeypatch):
    endpoint, _ = target
    item, tester = agent(endpoint), PromptInjectionTester()
    monkeypatch.setattr('src.security.prompt_injection_tests.asyncio',
                        SimpleNamespace(sleep=AsyncMock(), CancelledError=asyncio.CancelledError))
    with scan_transport(ScanBudget(allow_loopback=True)), collect_checks() as checks:
        findings = await tester._test_injection_category(item, CATEGORY, tester.injection_payloads[CATEGORY])
    assert len(findings) == 5 and checks[0]['outcome'] == 'confirmed'
    assert all('check_evidence_id' not in finding for finding in findings)
    evidence = dict(item, status='completed', check_schema_version='1.0', checks=checks, vulnerabilities=findings)
    assert confirmed_findings(evidence) == []
    assert not risk_assessment_eligible(evidence)
