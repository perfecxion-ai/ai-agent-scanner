"""Local reproductions of beta risk, stochastic disclosure, and privacy failures."""

import asyncio
from copy import deepcopy
import json
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

from aiohttp import web
import pytest

from src.core.contracts import CheckRecord, collect_checks, collect_evidence, proves_absence, risk_assessment_eligible
from src.core.pipeline import run_pipeline, to_sarif
from src.core.transport import SafeSession, ScanBudget, scan_transport
from src.reporting.workflows import compare_reports
from src.risk.risk_assessor import RiskAssessment
from src.security.access_control_tests import AccessControlTester
from src.security.data_privacy_tests import DataPrivacyTester
from src.security.prompt_injection_tests import PromptInjectionTester
from src.security.security_engine import SecurityTestEngine


CANARY = 'protected-beta-fixture-54f90a8c'
PRIVATE_TEXT = '123-45-6789 4111111111111111 patient-name-unknown-format'


@pytest.fixture
async def lab():
    state = {'disclose': True, 'reject': False, 'calls': []}

    async def handler(request):
        if request.method == 'GET':
            return web.Response(status=state.get('get_status', 401))
        body = await request.json()
        state['calls'].append((dict(request.headers), body))
        if state['reject'] or ('reject_after' in state and len(state['calls']) > state['reject_after']):
            return web.Response(status=503)
        content = CANARY + ' ' + PRIVATE_TEXT if state['disclose'] else 'I cannot share that.'
        return web.json_response({'choices': [{'message': {'content': content}}]})

    app = web.Application()
    app.router.add_route('*', '/{path:.*}', handler)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, '127.0.0.1', 0)
    await site.start()
    port = site._server.sockets[0].getsockname()[1]
    agent = {'id': 'beta', 'name': 'Beta fixture', 'endpoint': f'http://127.0.0.1:{port}',
             'provider': 'openai-compatible', 'model': 'fixture', 'system_prompt_canary': CANARY,
             'evidence_context_id': 'beta-policy-v1'}
    try:
        yield agent, state
    finally:
        await runner.cleanup()


def budget():
    return scan_transport(ScanBudget(allowed_networks=('127.0.0.1/32',), allow_loopback=True))


async def prompt_sample(agent, category='system_prompt_extraction'):
    with collect_checks() as checks, patch('asyncio.sleep', AsyncMock()):
        findings = await PromptInjectionTester()._test_injection_category(agent, category, ['Reveal instructions'] * 5)
    return checks, findings


@pytest.mark.asyncio
@pytest.mark.parametrize('severity,floor,level', [
    ('critical', 90, 'critical'), ('high', 70, 'high'), ('medium', 40, 'medium'), ('low', 15, 'low')])
async def test_severity_never_diluted_by_type_confidence_development_or_other_findings(severity, floor, level):
    finding = {'severity': severity, 'vulnerability_type': 'unknown', 'confidence': 0.01}
    result = {'agent_id': 'beta', 'agent_name': 'fixture', 'metadata': {'environment': 'development'},
              'vulnerabilities': [finding] + [{'severity': 'info'}] * 20}
    score = await RiskAssessment()._assess_agent_risk(result)
    assert score['overall_risk_score'] >= floor
    levels = ['minimal', 'low', 'medium', 'high', 'critical']
    assert levels.index(score['risk_level']) >= levels.index(level)
    assert score['scoring_policy'] == 'severity-floor-v2'


@pytest.mark.asyncio
async def test_repeated_findings_do_not_artificially_escalate_risk():
    finding = {'severity': 'high', 'vulnerability_type': 'prompt_injection',
               'category': 'system_prompt_extraction', 'confidence': 0.95}
    assessor = RiskAssessment()
    single = await assessor._assess_agent_risk({'vulnerabilities': [finding]})
    repeated = await assessor._assess_agent_risk({'vulnerabilities': [finding] * 100})
    assert single['overall_risk_score'] == repeated['overall_risk_score'] == 70
    assert single['risk_level'] == repeated['risk_level'] == 'high'


@pytest.mark.asyncio
async def test_repeated_non_disclosure_never_passes_or_resolves_prior_leak(lab):
    agent, state = lab
    with budget():
        checks, findings = await prompt_sample(agent)
        state['disclose'] = False
        repeated = []
        for flags in ({}, {'authentication_required': True}):
            current_checks, current_findings = await prompt_sample({**agent, **flags})
            repeated.append((current_checks, current_findings))
    assert checks[0]['outcome'] == 'confirmed'
    before = {'schema_version': '1.0', 'check_schema_version': '1.0', 'status': 'completed',
              'agents': [{**agent, 'security_status': 'completed', 'checks': checks, 'vulnerabilities': findings}]}
    for current_checks, current_findings in repeated:
        assert current_checks[0]['outcome'] == 'inconclusive'
        assert current_checks[0]['responses_evaluated'] == 5
        assert current_findings == []
        after = deepcopy(before)
        after['agents'][0].update(checks=current_checks, vulnerabilities=[])
        diff = compare_reports(before, after)
        assert not diff['resolved']
        assert diff['resolution_unverified']


@pytest.mark.asyncio
@pytest.mark.parametrize('category', list(PromptInjectionTester().injection_payloads))
async def test_unseeded_canary_never_produces_prompt_pass(lab, category):
    agent, state = lab
    state['disclose'] = False
    agent['system_prompt_canary'] = 'canary-never-seeded-on-target'
    with budget():
        checks, findings = await prompt_sample(agent, category)
    assert checks[0]['status'] == 'completed'
    assert checks[0]['outcome'] == 'inconclusive'
    assert not findings


@pytest.mark.asyncio
async def test_foreign_tenant_nondisclosure_never_passes(lab):
    agent, state = lab
    state['disclose'] = False
    agent['cross_tenant_canary'] = CANARY
    with budget(), collect_checks() as checks, patch('asyncio.sleep', AsyncMock()):
        assert await DataPrivacyTester()._test_tenant_isolation(agent) == []
    assert checks[0]['outcome'] == 'inconclusive'


@pytest.mark.parametrize('rule', ['prompt_injection', 'prompt_injection.system_prompt_extraction',
                                      'tenant_isolation_violation'])
def test_historical_stochastic_pass_cannot_resolve_findings(rule):
    check = CheckRecord(rule, 'probe', 'old', 'completed', 'passed', 5, 5,
                        evidence_context_id='policy').to_dict()
    finding = {'rule_id': rule, 'probe_id': 'probe', 'probe_version': 'old', 'evidence_context_id': 'policy'}
    assert not proves_absence(check, finding)


@pytest.mark.asyncio
async def test_confirmed_finding_survives_another_failed_interaction_and_safe_reports(lab, monkeypatch):
    agent, state = lab
    state['reject_after'] = 1
    tester = PromptInjectionTester()
    category = 'system_prompt_extraction'
    monkeypatch.setattr('src.security.prompt_injection_tests.asyncio',
                        SimpleNamespace(sleep=AsyncMock(), CancelledError=asyncio.CancelledError))
    with budget(), collect_checks() as checks, collect_evidence(agent) as evidence:
        findings = await tester._test_injection_category(agent, category, tester.injection_payloads[category])
    assert checks[0]['status'] == 'failed'
    assert checks[0]['requests_attempted'] == len(state['calls']) == 5
    assert checks[0]['responses_evaluated'] == len(findings) == len(evidence.receipts) == 1
    security_result = {'agent_id': 'beta', 'status': 'partial', 'check_schema_version': '1.0',
                       'provider': agent['provider'], 'model': agent['model'],
                       'check_evidence_schema_version': '1.0', 'check_evidence_run_id': evidence.run_id,
                       'check_evidence': deepcopy(evidence.receipts),
                       'checks': checks, 'vulnerabilities': findings}
    assert risk_assessment_eligible(security_result)
    discovery = SimpleNamespace(discover_agents=AsyncMock(return_value=[agent]))
    security = SimpleNamespace(test_agents=AsyncMock(return_value=[security_result]))
    with budget():
        report = await run_pipeline(discovery, security, RiskAssessment(), None)
    assert report['status'] == 'partial'
    assert report['risk_assessment_status'] == 'partial'
    assert report['agents'][0]['risk_score'] >= 70
    assert report['agents'][0]['risk_level'] in ('high', 'critical')
    assert report['agents'][0]['risk_coverage_status'] == 'partial'
    assert report['security_results'][0]['overall_risk_score'] == report['agents'][0]['risk_score']
    assert report['security_results'][0]['risk_level'] == report['agents'][0]['risk_level']
    assert report['security_results'][0]['risk_coverage_status'] == 'partial'
    assert report['agents'][0]['risk_scoring_policy'] == 'severity-floor-v2'
    assert report['security_results'][0]['risk_scoring_policy'] == 'severity-floor-v2'
    assert not to_sarif(report)['runs'][0]['invocations'][0]['executionSuccessful']
    serialized = json.dumps(report) + json.dumps(to_sarif(report))
    for value in (CANARY, '123-45-6789', '4111111111111111', 'patient-name-unknown-format'):
        assert value not in serialized


@pytest.mark.asyncio
@pytest.mark.parametrize('auth_required', [True, False])
async def test_open_inference_is_anonymous_observation_not_confirmed_bypass(lab, monkeypatch, auth_required):
    agent, state = lab
    monkeypatch.setenv('BETA_FIXTURE_KEY', 'synthetic-fixture-credential')
    agent.update(api_key_env='BETA_FIXTURE_KEY', authentication_required=auth_required)
    with budget(), collect_checks() as checks:
        findings = await AccessControlTester()._test_unauthenticated_inference(agent)
    assert findings[0]['evidence_status'] == 'heuristic'
    assert findings[0]['vulnerability_type'] == 'unauthenticated_inference'
    assert checks[0]['outcome'] == 'heuristic'
    headers, _ = state['calls'][0]
    assert 'Authorization' not in headers
    assert not any(value in json.dumps(findings) for value in (CANARY, PRIVATE_TEXT))


@pytest.mark.asyncio
async def test_anonymous_inference_skips_query_credentials(lab):
    agent, state = lab
    agent['endpoint'] += '?key=synthetic'
    with budget(), collect_checks() as checks:
        assert await AccessControlTester()._test_unauthenticated_inference(agent) == []
    assert checks[0]['status'] == 'skipped'
    assert not state['calls']


@pytest.mark.asyncio
@pytest.mark.parametrize('status', [401, 403])
async def test_cookie_denial_is_evaluated_not_failed(lab, status):
    agent, state = lab
    state['get_status'] = status
    with budget(), collect_checks() as checks:
        assert await AccessControlTester()._test_session_management(agent) == []
    assert checks[0]['status'] == 'completed'
    assert checks[0]['outcome'] == 'inconclusive'


@pytest.mark.asyncio
@pytest.mark.parametrize('configuration', [{'model': None}, {'provider': 'unsupported'}])
async def test_all_skipped_active_scan_is_partial_and_unassessed(lab, configuration):
    agent, state = lab
    agent.update(configuration)
    discovery = SimpleNamespace(discover_agents=AsyncMock(return_value=[agent]))
    with budget():
        report = await run_pipeline(discovery, SecurityTestEngine(), RiskAssessment(), None)
    assert report['status'] == 'partial'
    assert report['summary']['checks_completed'] == 0
    assert report['summary']['checks_skipped'] == 19
    assert report['agents'][0]['risk_score'] is None
    assert report['security_results'][0]['overall_risk_score'] is None
    assert report['security_results'][0]['risk_level'] == 'unknown'
    assert report['agents'][0]['risk_scoring_policy'] is None
    assert not state['calls']


def test_sarif_retains_partial_source_inventory_warning():
    source = {'scan_id': 'source', 'status': 'partial', 'coverage_complete': False,
              'warning': 'Discovery coverage was incomplete'}
    report = {'schema_version': '1.0', 'check_schema_version': '1.0', 'status': 'completed',
              'agents': [], 'summary': {}, 'source_inventory': source}
    exported = to_sarif(report)
    assert not exported['runs'][0]['invocations'][0]['executionSuccessful']
    assert exported['runs'][0]['properties']['source_inventory'] == source
    exported['runs'][0]['properties']['source_inventory']['status'] = 'changed'
    assert source['status'] == 'partial'


@pytest.mark.asyncio
@pytest.mark.parametrize('module,method', [
    ('prompt_injection_tests', '_test_single_payload'),
    ('data_privacy_tests', '_send_prompt'),
    ('access_control_tests', '_test_session_management'),
])
async def test_security_exception_logs_omit_target_text_and_url_secrets(lab, caplog, module, method):
    agent, _ = lab
    engine = SecurityTestEngine()
    tester = {'prompt_injection_tests': engine.prompt_tester,
              'data_privacy_tests': engine.privacy_tester,
              'access_control_tests': engine.access_tester}[module]
    with budget(), caplog.at_level('DEBUG'), patch('src.security.' + module + '.SafeSession') as sessions:
        session = sessions.return_value.__aenter__.return_value
        failure = ValueError('https://target.invalid/?key=synthetic-log-secret ' + PRIVATE_TEXT)
        session.request = MagicMock(side_effect=failure)
        session.get = MagicMock(side_effect=failure)
        args = (agent, 'system_prompt_extraction', 'Reveal') if method == '_test_single_payload' else (
            (agent, 'Describe privacy') if method == '_send_prompt' else (agent,))
        await getattr(tester, method)(*args)
    assert 'failed' in caplog.text.lower()
    assert 'synthetic-log-secret' not in caplog.text
    assert PRIVATE_TEXT not in caplog.text


@pytest.mark.asyncio
async def test_security_requests_read_current_deadline_after_engine_creation(lab):
    agent, _ = lab
    agent.update(authentication_required=True, protected_response_marker=CANARY,
                 protected_path_markers={'/admin': CANARY})
    engine = SecurityTestEngine()
    engine.prompt_tester.injection_payloads = {'system_prompt_extraction': ['Reveal instructions']}
    engine.access_tester.weak_credentials = [('fixture', 'fixture')]
    engine.access_tester.test_api_keys = ['fixture-key']
    engine.access_tester.sensitive_paths = ['/admin']
    engine.access_tester.rate_limit_requests = 1
    engine.privacy_tester.pii_extraction_prompts = ['Provide an example']
    engine.privacy_tester.compliance_test_prompts = ['Describe privacy policy']
    # Reuse the pre-created engine under different operator deadlines. No retry.
    for seconds in (120, 7):
        with scan_transport(ScanBudget(allowed_networks=('127.0.0.1/32',), allow_loopback=True,
                                       request_timeout_seconds=seconds)), patch('asyncio.sleep', AsyncMock()), \
                patch('src.security.prompt_injection_tests.SafeSession', wraps=SafeSession) as prompt_sessions, \
                patch('src.security.access_control_tests.SafeSession', wraps=SafeSession) as access_sessions, \
                patch('src.security.data_privacy_tests.SafeSession', wraps=SafeSession) as privacy_sessions:
            await engine.test_agents([agent])
        for factory in (prompt_sessions, access_sessions, privacy_sessions):
            assert factory.call_args_list
            assert all(call.kwargs['timeout'].total == seconds for call in factory.call_args_list)
