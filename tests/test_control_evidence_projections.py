"""Every current verdict and resolution uses supported protected-access evidence."""

from copy import deepcopy
import hashlib
import json
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest

from src.core.contracts import (
    CheckpointError, CheckRecord, checked, confirmed_findings, proves_absence,
    record_interaction, risk_assessment_eligible,
)
from src.core.pipeline import run_pipeline, to_sarif
from src.core.risk_projection import project_report_risk
from src.core.transport import ScanBudget, scan_transport
from src.reporting.workflows import compare_reports
from src.risk.risk_assessor import RiskAssessment, risk_level_for_score
from src.security.security_engine import SecurityTestEngine
from tests.controlled_access import (
    ISSUED, MARKER, METHODS, REFERENCE, result as controlled_result, target, transport,
)
from tests.test_api_auth import api as api, headers
from tests.test_api_risk_projection import outputs, seed


def report(evidence, *, score=70, agent=None):
    source = target() if agent is None else agent
    public = {key: source[key] for key in ('id', 'name', 'provider', 'model', 'endpoint') if key in source}
    if agent is None:
        for key in ('provider', 'model'):
            public.pop(key, None)
            if key in evidence:
                public[key] = evidence[key]
    return {'schema_version': '1.0', 'check_schema_version': '1.0', 'scan_type': 'full',
            'status': 'completed', 'risk_assessment_status': 'completed',
            'summary': {'overall_risk_score': score}, 'agents': [{
                **public, 'security_status': evidence['status'],
                'checks': deepcopy(evidence['checks']), 'vulnerabilities': deepcopy(evidence['vulnerabilities']),
                'risk_score': score, 'risk_level': risk_level_for_score(score),
                'risk_coverage_status': 'sampled' if evidence['status'] == 'completed' else 'partial',
                'risk_scoring_policy': 'severity-floor-v2'}]}


def historical(evidence):
    copied = deepcopy(evidence)
    identity = ['18-header-variations-denied-control-v1', evidence['provider'], evidence['model']]
    version = '1:' + hashlib.sha256(json.dumps(identity, sort_keys=True).encode()).hexdigest()
    for record in copied['checks'] + copied['vulnerabilities']:
        record['probe_version'] = version
    return copied


def generic_confirmation():
    check = CheckRecord('fixture.disclosure', 'fixture.sample', 'fixture-v1',
                        'completed', 'confirmed', 1, 1).to_dict()
    finding = {key: check[key] for key in ('rule_id', 'probe_id', 'probe_version', 'evidence_context_id')}
    finding.update(evidence_status='confirmed', severity='high', vulnerability_type='fixture.disclosure')
    return check, finding


@pytest.fixture
async def evidence_pair():
    return await controlled_result(disclose=True), await controlled_result()


@pytest.mark.asyncio
@pytest.mark.parametrize('rule', METHODS)
async def test_actual_current_controlled_producers_keep_positive_and_zero_scores(rule):
    for disclose in (False, True):
        evidence = await controlled_result(rule=rule, disclose=disclose)
        assert risk_assessment_eligible(evidence)
        risk = await RiskAssessment()._assess_agent_risk(evidence)
        expected = (90 if rule == 'weak_credentials' else 70) if disclose else 0
        assert risk['overall_risk_score'] == expected
        assert project_report_risk(report(evidence, score=expected))[1]['fixture']['risk_score'] == expected
        assert len(confirmed_findings(evidence)) == len(evidence['vulnerabilities'])


@pytest.mark.asyncio
@pytest.mark.parametrize('disclose', [False, True])
async def test_exact_legacy_versions_cannot_supply_current_risk_or_direct_zero(disclose):
    evidence = historical(await controlled_result(disclose=disclose))
    original = deepcopy(evidence)
    assert not risk_assessment_eligible(evidence)
    assert confirmed_findings(evidence) == []
    summary, agents = project_report_risk(report(evidence, score=70 if disclose else 0))
    assert summary['overall_risk_score'] is None and agents['fixture']['risk_score'] is None
    for call in (RiskAssessment()._assess_agent_risk(evidence), RiskAssessment().assess_risks([evidence])):
        with pytest.raises(ValueError, match='^Current risk assessment requires supported evidence$'):
            await call
    assert evidence == original


@pytest.mark.asyncio
@pytest.mark.parametrize('mutation', [
    'missing_provider', 'missing_model', 'redacted_provider', 'redacted_model', 'wrong_provider',
    'wrong_model', 'missing_control_tag', 'old_control_tag', 'missing_context', 'wrong_context',
    'wrong_type', 'divergent_rule', 'insufficient_controls', 'excessive_pass_count',
])
async def test_unsupported_or_unbound_claims_fail_closed(evidence_pair, mutation):
    confirmed, passed = deepcopy(evidence_pair)
    chosen = passed if mutation == 'excessive_pass_count' else confirmed
    if mutation.startswith('missing_') and mutation.split('_', 1)[1] in {'provider', 'model'}:
        chosen.pop(mutation.split('_', 1)[1])
    elif mutation in {'redacted_provider', 'redacted_model', 'wrong_provider', 'wrong_model'}:
        chosen[mutation.split('_', 1)[1]] = '[redacted]' if mutation.startswith('redacted') else 'different'
    elif mutation in {'missing_control_tag', 'old_control_tag'}:
        for finding in chosen['vulnerabilities']:
            finding['control_status'] = None if mutation.startswith('missing') else 'denied_control'
    elif mutation in {'missing_context', 'wrong_context'}:
        for finding in chosen['vulnerabilities']:
            if mutation == 'missing_context':
                finding.pop('evidence_context_id')
            else:
                finding['evidence_context_id'] = 'different-resource-policy'
    elif mutation == 'wrong_type':
        for finding in chosen['vulnerabilities']:
            finding['vulnerability_type'] = 'other'
    elif mutation == 'divergent_rule':
        chosen['checks'][0]['rule_id'] = 'other'
        for finding in chosen['vulnerabilities']:
            finding['rule_id'] = 'other'
    else:
        count = 21 if mutation == 'excessive_pass_count' else 2
        chosen['checks'][0].update(requests_attempted=count, responses_evaluated=count)
    assert not risk_assessment_eligible(chosen)
    assert project_report_risk(report(chosen))[1]['fixture']['risk_score'] is None


@pytest.mark.asyncio
@pytest.mark.parametrize('companion', ['current_pass', 'other_confirmation', 'unlinked_claim'])
async def test_unsupported_positive_claim_poison_is_asset_local(evidence_pair, companion):
    confirmed, passed = deepcopy(evidence_pair)
    old = historical(confirmed)
    if companion == 'unlinked_claim':
        old['vulnerabilities'] = []
    if companion == 'other_confirmation':
        check, finding = generic_confirmation()
        old['checks'].append(check)
        old['vulnerabilities'].append(finding)
        assert confirmed_findings(old) == [finding]
    else:
        old['checks'].extend(passed['checks'])
    assert not risk_assessment_eligible(old)
    value = report(old)
    other = report(confirmed)['agents'][0]
    other['id'] = 'independent'
    value['agents'].append(other)
    summary, agents = project_report_risk(value)
    assert agents['fixture']['risk_score'] is None
    assert agents['independent']['risk_score'] == summary['overall_risk_score'] == 70


@pytest.mark.asyncio
async def test_unsupported_pass_does_not_poison_supported_confirmation_or_pass(evidence_pair):
    confirmed, passed = deepcopy(evidence_pair)
    for current in (confirmed, passed):
        current['checks'].extend(historical(passed)['checks'])
        assert risk_assessment_eligible(current)


@pytest.mark.asyncio
async def test_arbitrary_pass_neither_scores_zero_nor_resolves_a_finding():
    check, finding = generic_confirmation()
    check.update(outcome='passed', evidence_context_id='public-resource-policy')
    finding['evidence_context_id'] = 'public-resource-policy'
    evidence = {'status': 'completed', 'check_schema_version': '1.0', 'checks': [check], 'vulnerabilities': []}
    assert not risk_assessment_eligible(evidence)
    assert not proves_absence(check, finding, asset=target(), previous_asset=target(checks=[check]))


@pytest.mark.asyncio
@pytest.mark.parametrize('mutation', ['same_legacy', 'missing_previous_check', 'old_previous_check',
                                     'missing_old_model', 'missing_new_model', 'missing_old_provider',
                                     'different_context', 'extra_legacy_occurrence'])
async def test_lifecycle_requires_supported_prior_confirmation_and_bound_current_pass(evidence_pair, mutation):
    confirmed, passed = deepcopy(evidence_pair)
    before, after = report(confirmed), report(passed, score=0)
    assert compare_reports(before, after)['resolved']
    if mutation == 'same_legacy':
        before, after = report(historical(confirmed)), report(historical(passed), score=0)
    elif mutation == 'missing_previous_check':
        before['agents'][0]['checks'] = []
    elif mutation == 'old_previous_check':
        before['agents'][0]['checks'] = historical(confirmed)['checks']
    elif mutation.startswith('missing_'):
        which, key = mutation.split('_')[1:]
        (before if which == 'old' else after)['agents'][0].pop(key)
    elif mutation == 'different_context':
        after['agents'][0]['checks'][0]['evidence_context_id'] = 'another-policy'
    else:
        before['agents'][0]['vulnerabilities'].append(historical(confirmed)['vulnerabilities'][0])
    original = deepcopy((before, after))
    difference = compare_reports(before, after)
    assert difference['resolved'] == [] and difference['resolution_unverified']
    assert (before, after) == original


@pytest.mark.asyncio
async def test_explicit_none_model_is_supported_but_missing_original_context_is_not():
    agent = target(model=None)
    confirmed, passed = await controlled_result(agent, disclose=True), await controlled_result(agent)
    assert risk_assessment_eligible(confirmed) and risk_assessment_eligible(passed)
    before, after = report(confirmed, agent=agent), report(passed, score=0, agent=agent)
    assert compare_reports(before, after)['resolved']
    before['agents'][0].pop('model')
    assert not compare_reports(before, after)['resolved']


@pytest.mark.asyncio
@pytest.mark.parametrize('disclose', [False, True])
async def test_api_does_not_reinterpret_historical_access_claims(api, disclose):
    module, client = api
    value = report(historical(await controlled_result(disclose=disclose)), score=70 if disclose else 0)
    original = deepcopy(value)
    seed(module, value, alias='fixture', db_score=99)
    for _ in range(2):
        results, listed = outputs(module, client)
        assert results['summary']['overall_risk_score'] is None
        assert results['agents'][0]['risk_score'] is None and listed['risk_score'] is None
        assert results['pipeline'] == original
        assert client.get('/api/agents?risk_level=high', headers=headers(module)).json['agents'] == []
    assert module.db.session.get(module.ScanResult, 'fixture').result == original


@pytest.mark.asyncio
@pytest.mark.parametrize('collision', ['model', 'provider', 'context'])
@pytest.mark.parametrize('disclose', [False, True])
@pytest.mark.parametrize('checkpointed', [False, True])
async def test_redacted_context_never_exports_a_verdict_that_api_cannot_verify(
        collision, disclose, checkpointed, caplog):
    agent = target()
    if collision == 'provider':
        agent['metadata']['password'] = agent['provider']
    else:
        agent['evidence_context_id' if collision == 'context' else collision] = 'fixture-test'
    security = SecurityTestEngine()
    security.prompt_tester.test_agent = AsyncMock(return_value=[])
    security.access_tester.test_agent = security.access_tester._test_weak_credentials
    security.privacy_tester.test_agent = AsyncMock(return_value=[])
    saved = []

    async def capture(value):
        saved.append(deepcopy(value))

    with transport(disclose=disclose):
        final = await run_pipeline(None, security, RiskAssessment(), None, 'security_only', agents=[agent],
                                   checkpoint_callback=capture if checkpointed else None)
    for value in saved + [final]:
        assert value['summary']['overall_risk_score'] is None
        assert value['summary']['agents_risk_assessed'] == 0
        assert value['summary']['agents_risk_not_assessed'] == 1
        assert value['risk_assessments'] == []
        assert value['agents'][0]['risk_score'] is None
        assert project_report_risk(value)[1]['fixture']['risk_score'] is None
    assert final['risk_assessment_status'] == 'not_assessed'
    assert final['agents'][0]['checks'][0]['responses_evaluated'] == 7
    assert len(final['agents'][0]['vulnerabilities']) == (5 if disclose else 0)
    encoded = json.dumps([saved, final, to_sarif(final)]) + caplog.text
    assert all(value not in encoded for value in (MARKER, ISSUED, REFERENCE, 'fixture-test'))


@pytest.mark.asyncio
@pytest.mark.parametrize('valid', [False, True])
async def test_pipeline_binds_original_context_instead_of_tester_supplied_labels(valid):
    source = target(model='actual-model')
    copied = await controlled_result(source if valid else None)
    copied.update(provider='spoofed-provider', model='spoofed-model')
    security = SimpleNamespace(test_agents=AsyncMock(return_value=[copied]))
    result = await run_pipeline(None, security, RiskAssessment(), None, 'security_only', agents=[source])
    assert result['security_results'][0]['model'] == 'actual-model'
    assert result['agents'][0]['risk_score'] == (0 if valid else None)


@pytest.mark.asyncio
async def test_modern_direct_scorer_rejects_unknown_but_legacy_low_level_contract_remains():
    scorer = RiskAssessment()
    unknown = {'agent_id': 'fixture', 'status': 'completed', 'check_schema_version': '1.0',
               'checks': [], 'vulnerabilities': []}
    with pytest.raises(ValueError, match='supported evidence'):
        await scorer._assess_agent_risk(unknown)
    legacy = dict(unknown)
    legacy.pop('check_schema_version')
    assert (await scorer._assess_agent_risk(legacy))['overall_risk_score'] == 0


@pytest.mark.asyncio
@pytest.mark.parametrize('checkpointed', [False, True])
@pytest.mark.parametrize('all_groups', [False, True])
async def test_mixed_authentication_and_admin_checks_preserve_findings_after_path_redaction(
        checkpointed, all_groups):
    security = SecurityTestEngine()
    security.prompt_tester.test_agent = AsyncMock(return_value=[])
    security.privacy_tester.test_agent = AsyncMock(return_value=[])

    async def access(agent):
        rules = METHODS if all_groups else ('authentication_bypass', 'authorization_bypass')
        findings = []
        for rule in rules:
            findings.extend(await getattr(security.access_tester, METHODS[rule])(agent))
        return findings

    security.access_tester.test_agent = access
    saved = []

    async def capture(value):
        saved.append(deepcopy(value))

    with transport(disclose=True):
        final = await run_pipeline(None, security, RiskAssessment(), None, 'security_only', agents=[target()],
                                   checkpoint_callback=capture if checkpointed else None)
    findings = final['agents'][0]['vulnerabilities']
    assert len(findings) == (29 if all_groups else 19)
    assert findings[-1]['vulnerability_type'] == 'authorization_bypass'
    assert findings[-1]['path'] == '/[redacted]'
    assert findings[-1]['protected_path_index'] == 0
    expected = 90 if all_groups else 70
    assert final['summary']['overall_risk_score'] == expected
    assert project_report_risk(final)[1]['fixture']['risk_score'] == expected
    for value in saved + [final]:
        assert value['summary']['overall_risk_score'] == project_report_risk(value)[0]['overall_risk_score']
    assert all(secret not in json.dumps(saved + [final]) for secret in (MARKER, ISSUED, REFERENCE))


@pytest.mark.asyncio
@pytest.mark.parametrize('rule', METHODS)
@pytest.mark.parametrize('disclose', [False, True])
@pytest.mark.parametrize('checkpointed', [False, True])
async def test_each_actual_producer_has_matching_private_pipeline_and_api_verdicts(rule, disclose, checkpointed):
    security = SecurityTestEngine()
    security.prompt_tester.test_agent = AsyncMock(return_value=[])
    security.privacy_tester.test_agent = AsyncMock(return_value=[])
    security.access_tester.test_agent = getattr(security.access_tester, METHODS[rule])
    saved = []

    async def capture(value):
        saved.append(deepcopy(value))

    with transport(disclose=disclose):
        final = await run_pipeline(None, security, RiskAssessment(), None, 'security_only', agents=[target()],
                                   checkpoint_callback=capture if checkpointed else None)
    expected = (90 if rule == 'weak_credentials' else 70) if disclose else 0
    assert final['summary']['overall_risk_score'] == expected
    for value in saved + [final]:
        projection = project_report_risk(value)
        assert value['summary']['overall_risk_score'] == projection[0]['overall_risk_score']
        assert value['agents'][0]['risk_score'] == projection[1]['fixture']['risk_score']
    encoded = json.dumps([saved, final, to_sarif(final)])
    assert all(secret not in encoded for secret in (MARKER, ISSUED, REFERENCE))


@pytest.mark.asyncio
@pytest.mark.parametrize('issued', ['high', 'severity-floor-v2', 'sampled'])
@pytest.mark.parametrize('checkpointed', [False, True])
async def test_issued_credential_colliding_with_risk_metadata_cannot_export_numeric_verdict(issued, checkpointed):
    security = SecurityTestEngine()
    security.prompt_tester.test_agent = AsyncMock(return_value=[])
    security.privacy_tester.test_agent = AsyncMock(return_value=[])
    security.access_tester.test_agent = security.access_tester._test_authentication_bypass
    saved = []

    async def capture(value):
        saved.append(deepcopy(value))

    with patch('tests.controlled_access.ISSUED', issued), transport(disclose=True):
        final = await run_pipeline(None, security, RiskAssessment(), None, 'security_only', agents=[target()],
                                   checkpoint_callback=capture if checkpointed else None)
    assert len(final['agents'][0]['vulnerabilities']) == 18
    assert final['risk_assessment_status'] == 'not_assessed'
    assert final['risk_assessments'] == []
    assert final['summary']['agents_risk_assessed'] == 0
    assert final['summary']['agents_risk_not_assessed'] == 1
    for value in saved + [final]:
        canonical, assets = project_report_risk(value)
        assert value['summary']['overall_risk_score'] == canonical['overall_risk_score']
        assert value['agents'][0]['risk_score'] == assets['fixture']['risk_score']
        if value['security_results']:
            assert value['security_results'][0]['overall_risk_score'] == assets['fixture']['risk_score']
        assert to_sarif(value)['runs'][0]['properties']['summary'] == value['summary']
    assert final['agents'][0]['risk_score'] is None
    encoded = json.dumps([saved, final, to_sarif(final)])
    # 'high' may also occur as part of public identifiers, never as a raw value.
    assert '"' + issued + '"' not in encoded
    assert all(secret not in encoded for secret in (MARKER, REFERENCE))


@pytest.mark.asyncio
@pytest.mark.parametrize('checkpointed', [False, True])
async def test_metadata_redaction_preserves_other_asset_verdict_and_recomputes_summary(checkpointed):
    security = SecurityTestEngine()
    security.prompt_tester.test_agent = AsyncMock(return_value=[])
    security.privacy_tester.test_agent = AsyncMock(return_value=[])

    async def access(agent):
        method = '_test_authentication_bypass' if agent['id'] == 'first' else '_test_weak_credentials'
        return await getattr(security.access_tester, method)(agent)

    security.access_tester.test_agent = access
    saved = []

    async def capture(value):
        saved.append(deepcopy(value))

    with patch('tests.controlled_access.ISSUED', 'high'), transport(disclose=True):
        final = await run_pipeline(None, security, RiskAssessment(), None, 'security_only',
                                   agents=[target(id='first'), target(id='second', endpoint='http://192.0.2.2/resource')],
                                   checkpoint_callback=capture if checkpointed else None)
    assert [agent['risk_score'] for agent in final['agents']] == [None, 90]
    assert final['summary']['overall_risk_score'] == 90
    assert final['summary']['agents_risk_assessed'] == final['summary']['agents_risk_not_assessed'] == 1
    assert [assessment['agent_id'] for assessment in final['risk_assessments']] == ['second']
    for value in saved + [final]:
        summary, agents = project_report_risk(value)
        assert value['summary']['overall_risk_score'] == summary['overall_risk_score']
        assert all(agent['risk_score'] == agents[agent['id']]['risk_score'] for agent in value['agents'])


@pytest.mark.asyncio
@pytest.mark.parametrize('protected', ['protected_control_version', 'PROTECTED_PATH_INDEX', 'control_version'])
@pytest.mark.parametrize('source', ['same_canary', 'cross_canary', 'credential', 'validator_canary',
                                  'validator_credential', 'removed_source_canary', 'cross_credential',
                                  'probe_credential'])
@pytest.mark.parametrize('checkpointed', [False, True])
async def test_public_access_field_collision_is_rejected_before_any_scan_activity(
        protected, source, checkpointed, monkeypatch, caplog):
    agents = [target()]
    validator = None
    if source in {'same_canary', 'removed_source_canary'}:
        agents[0]['system_prompt_canary'] = protected
    if source == 'removed_source_canary':
        def validator(values):
            values[0].pop('system_prompt_canary')
            return values
    if source == 'cross_canary':
        agents.append(target(id='other', endpoint='http://192.0.2.2/resource', system_prompt_canary=protected))
    if source == 'credential':
        agents[0]['api_key_env'] = 'CONTROL_COLLISION_CREDENTIAL'
        monkeypatch.setenv('CONTROL_COLLISION_CREDENTIAL', protected)
    if source == 'cross_credential':
        agents.append(target(id='other', endpoint='http://192.0.2.2/resource',
                             api_key_env='CONTROL_COLLISION_CREDENTIAL'))
        monkeypatch.setenv('CONTROL_COLLISION_CREDENTIAL', protected)
    if source == 'validator_canary':
        def validator(values):
            values[0]['system_prompt_canary'] = protected
            return values
    if source == 'validator_credential':
        monkeypatch.setenv('CONTROL_COLLISION_CREDENTIAL', protected)

        def validator(values):
            values[0]['api_key_env'] = 'CONTROL_COLLISION_CREDENTIAL'
            return values
    security = SecurityTestEngine()
    if source == 'probe_credential':
        security.access_tester.weak_credentials[0] = ('fixture-user', protected)
    security.test_agents = AsyncMock(wraps=security.test_agents)
    sink = AsyncMock()
    budget = ScanBudget()
    with transport(disclose=True), scan_transport(budget), pytest.raises(
            ValueError, match='^Protected evidence conflicts with public access fields$') as failure:
        await run_pipeline(None, security, RiskAssessment(), None, 'security_only', agents=agents,
                           agent_validator=validator, checkpoint_callback=sink if checkpointed else None)
    assert budget.requests == 0
    security.test_agents.assert_not_called()
    sink.assert_not_called()
    assert protected not in str(failure.value) + caplog.text


@pytest.mark.asyncio
@pytest.mark.parametrize('checkpointed', [False, True])
async def test_late_public_access_field_collision_never_escapes_a_report(checkpointed, caplog):
    secret = 'protected_control_version'
    security = SecurityTestEngine()
    security.prompt_tester.test_agent = AsyncMock(return_value=[])
    security.privacy_tester.test_agent = AsyncMock(return_value=[])

    class LateSecret:
        @checked('fixture.late_secret', 'fixture-v1')
        async def check(self, agent):
            record_interaction(True)
            return [{'vulnerability_type': 'fixture.late_secret', 'evidence_status': 'confirmed',
                     'severity': 'high', 'api_key': secret}]

    security.access_tester.test_agent = LateSecret().check
    saved = []

    async def capture(value):
        saved.append(deepcopy(value))

    with transport(), pytest.raises(CheckpointError if checkpointed else ValueError) as failure:
        await run_pipeline(None, security, RiskAssessment(), None, 'security_only', agents=[target()],
                           checkpoint_callback=capture if checkpointed else None)
    assert secret not in json.dumps(saved) + str(failure.value) + caplog.text
    assert all(not value['agents'][0]['vulnerabilities'] for value in saved)
    if checkpointed:
        security.privacy_tester.test_agent.assert_not_called()


@pytest.mark.asyncio
async def test_discovery_without_new_access_fields_does_not_reject_unused_canary():
    agent = target(system_prompt_canary='protected_control_version')
    discovery = SimpleNamespace(discover_agents=AsyncMock(return_value=[agent]))
    result = await run_pipeline(discovery, None, None, None, 'discovery_only')
    assert result['agents'][0]['risk_score'] is None
    assert 'protected_control_version' not in json.dumps(result)
