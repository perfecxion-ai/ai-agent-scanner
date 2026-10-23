"""Independent synthetic challenges for controlled tenant evidence."""

import asyncio
from copy import deepcopy
import json
from types import SimpleNamespace
from unittest.mock import AsyncMock

from aiohttp import client as aiohttp_client, web
import pytest

from src.core.pipeline import run_pipeline, to_sarif
from src.core.risk_projection import project_report_risk
from src.core.tenant_probe_policy import TENANT_ATTACK_PROMPTS, TENANT_CONTROL_PROMPT
from src.core.transport import SafeSession, ScanBudget, scan_transport
from src.risk.risk_assessor import RiskAssessment
from src.security.security_engine import SecurityTestEngine


OWNER_KEY = 'review-owner-key-a8f71d6290'
TESTED_KEY = 'review-tested-key-b4c932a781'
OWNER_MARKER = 'review-foreign-marker-c38e192d6a'
TESTED_MARKER = 'review-own-marker-d491e7ab28'
ACCESS_MARKER = 'review-access-resource-7218ad95'
REFERENCES = {
    'REVIEW_TENANT_OWNER_KEY': OWNER_KEY,
    'REVIEW_TENANT_TESTED_KEY': TESTED_KEY,
    'REVIEW_TENANT_OWNER_MARKER': OWNER_MARKER,
    'REVIEW_TENANT_TESTED_MARKER': TESTED_MARKER,
}


@pytest.fixture
async def tenant_target(monkeypatch):
    cookie_jar = aiohttp_client.CookieJar

    def loopback_cookie_jar(*args, **kwargs):
        # Accept fixture cookies so IP-address rejection cannot hide session reuse.
        kwargs['unsafe'] = True
        return cookie_jar(*args, **kwargs)

    monkeypatch.setattr(aiohttp_client, 'CookieJar', loopback_cookie_jar)
    for name, value in REFERENCES.items():
        monkeypatch.setenv(name, value)
    state = {'mode': 'defended', 'calls': [], 'tested_calls': 0}

    async def reply(request):
        if request.method != 'POST':
            state['calls'].append({'method': request.method, 'headers': dict(request.headers), 'body': None})
            if request.headers.get('Authorization') == 'Bearer ' + TESTED_KEY:
                return web.Response(text=ACCESS_MARKER)
            return web.Response(status=401, text='Denied')
        body = await request.json()
        state['calls'].append({'method': request.method, 'headers': dict(request.headers), 'body': body})
        if body['messages'][0]['content'] == 'Remembered input setup':
            state['remembered'] = request.headers.get('User-Agent', '')
            return web.json_response({'choices': [{'message': {'content': 'Setup acknowledged.'}}]})
        credential = request.headers.get('Authorization', '')
        mode = state['mode']
        if credential == 'Bearer ' + OWNER_KEY:
            state['owner_seen'] = True
            if mode == 'owner_metadata_only':
                return web.json_response({'choices': [{'message': {'content': 'No private data.'}}],
                                          'fixture_metadata': OWNER_MARKER})
            content = state.get('remembered', '') if mode == 'remembered_header' else OWNER_MARKER
            if mode == 'owner_both':
                content += ' ' + TESTED_MARKER
            elif mode == 'owner_case_changed_tested':
                content += ' ' + TESTED_MARKER.upper()
            return web.json_response({'choices': [{'message': {'content': content}}]},
                                     headers={'Set-Cookie': 'review_owner_session=owner-only; Path=/'})
        if credential == 'Bearer ' + TESTED_KEY:
            prompt = body['messages'][0]['content']
            if prompt != TENANT_CONTROL_PROMPT and not (
                    state.get('owner_seen') and prompt in TENANT_ATTACK_PROMPTS):
                return web.json_response({'choices': [{'message': {'content': 'No disclosure.'}}]})
            state['tested_calls'] += 1
            baseline = prompt == TENANT_CONTROL_PROMPT
            if baseline:
                content = OWNER_MARKER if mode == 'tested_foreign_only' else TESTED_MARKER
                if mode in {'tested_control_leak', 'tested_candidate_invalid_denial'}:
                    content += ' ' + OWNER_MARKER
                if mode == 'tested_metadata_only':
                    return web.json_response({'choices': [{'message': {'content': 'No private data.'}}],
                                              'fixture_metadata': TESTED_MARKER})
            else:
                content = OWNER_MARKER if mode == 'attack_leak' and state['tested_calls'] == 2 else 'No disclosure.'
                if mode == 'remembered_header' and state['tested_calls'] == 2:
                    content = state.get('remembered', '')
            return web.json_response({'choices': [{'message': {'content': content}}]})
        if mode in {'invalid_body_marker', 'tested_candidate_invalid_denial'}:
            return web.Response(status=401, text='Denied ' + OWNER_MARKER)
        if mode == 'invalid_header_marker':
            return web.Response(status=403, text='Denied', headers={'X-Private-Fixture': TESTED_MARKER})
        if mode == 'invalid_header_case_changed_marker':
            return web.Response(status=403, text='Denied', headers={'X-Private-Fixture': OWNER_MARKER.upper()})
        if mode == 'invalid_success':
            return web.json_response({'choices': [{'message': {'content': 'Denied'}}]})
        return web.Response(status=401, text='Denied')

    app = web.Application()
    app.router.add_route('*', '/{path:.*}', reply)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, '127.0.0.1', 0)
    await site.start()
    endpoint = 'http://127.0.0.1:' + str(site._server.sockets[0].getsockname()[1]) + '/'
    binding = {'endpoint': endpoint, 'provider': 'openai-compatible',
               'model': 'review-model', 'evidence_context_id': 'review-boundary-v1'}
    agent = {'id': 'review-asset', 'name': 'Review fixture', 'type': 'assistant',
             **binding, 'api_key_env': 'REVIEW_TENANT_TESTED_KEY',
             'tenant_evidence': {
                 'schema_version': '1.0', 'binding': deepcopy(binding),
                 'tested_principal_authorized_for_owner': False,
                 'owner': {'tenant_ref': 'review-owner-tenant', 'principal_ref': 'review-owner-principal',
                           'api_key_env': 'REVIEW_TENANT_OWNER_KEY', 'canary_env': 'REVIEW_TENANT_OWNER_MARKER'},
                 'tested': {'tenant_ref': 'review-tested-tenant', 'principal_ref': 'review-tested-principal',
                            'api_key_env': 'REVIEW_TENANT_TESTED_KEY', 'canary_env': 'REVIEW_TENANT_TESTED_MARKER'},
             }}
    try:
        yield agent, state
    finally:
        await runner.cleanup()


async def run_tenant(agent, monkeypatch, *, checkpoint_callback=None, prior_probe=None):
    engine = SecurityTestEngine()
    monkeypatch.setattr(engine.prompt_tester, 'test_agent', prior_probe or AsyncMock(return_value=[]))
    monkeypatch.setattr(engine.access_tester, 'test_agent', AsyncMock(return_value=[]))
    monkeypatch.setattr(engine.privacy_tester, 'test_agent', engine.privacy_tester._test_tenant_isolation)
    monkeypatch.setattr('src.security.data_privacy_tests.asyncio',
                        SimpleNamespace(sleep=AsyncMock(), CancelledError=asyncio.CancelledError))
    with scan_transport(ScanBudget(allow_loopback=True, allowed_networks=('127.0.0.1/32',),
                                   max_requests=8, request_timeout_seconds=2)):
        return await asyncio.wait_for(run_pipeline(
            None, engine, RiskAssessment(), None, scan_type='security_only', agents=[agent],
            checkpoint_callback=checkpoint_callback), 10)


@pytest.mark.asyncio
@pytest.mark.parametrize('mode', [
    'owner_both', 'owner_case_changed_tested', 'owner_metadata_only',
    'tested_foreign_only', 'tested_metadata_only', 'invalid_body_marker',
    'invalid_header_marker', 'invalid_header_case_changed_marker', 'invalid_success',
    'tested_candidate_invalid_denial',
])
async def test_contaminated_controls_never_authorize_tenant_confirmation(tenant_target, monkeypatch, mode):
    agent, state = tenant_target
    state['mode'] = mode
    report = await run_tenant(agent, monkeypatch)
    assert report['summary']['overall_risk_score'] is None
    assert report['agents'][0]['vulnerabilities'] == []
    assert not any(check['outcome'] == 'passed' for check in report['agents'][0]['checks'])
    assert 1 <= len(state['calls']) <= 3


@pytest.mark.asyncio
@pytest.mark.parametrize('mode,source', [('tested_control_leak', 'subject_control'), ('attack_leak', 'attack')])
async def test_actual_controls_confirm_only_the_bound_tested_response(tenant_target, monkeypatch, mode, source):
    agent, state = tenant_target
    state['mode'] = mode
    checkpoints = []

    async def checkpoint(value):
        checkpoints.append(deepcopy(value))

    report = await run_tenant(agent, monkeypatch, checkpoint_callback=checkpoint)
    assert len(state['calls']) == 8
    assert all('Cookie' not in call['headers'] for call in state['calls'])
    controls = [call['body']['messages'][0]['content'] for call in state['calls'][:3]]
    assert controls[0] == controls[1] == controls[2]
    assert report['summary']['overall_risk_score'] == 90
    findings = report['agents'][0]['vulnerabilities']
    assert len(findings) == 1
    assert findings[0]['tenant_observation_source'] == source
    if source == 'attack':
        assert findings[0]['tenant_attack_index'] == 0
    else:
        assert 'tenant_attack_index' not in findings[0]
    encoded = json.dumps([report, to_sarif(report), checkpoints])
    for private in [*REFERENCES, *REFERENCES.values(), 'review-owner-tenant',
                    'review-tested-tenant', 'review-owner-principal', 'review-tested-principal']:
        assert private not in encoded
    assert 'tenant_evidence' not in encoded


@pytest.mark.asyncio
async def test_environment_rotation_after_initial_checkpoint_cannot_change_active_principals(
        tenant_target, monkeypatch):
    agent, state = tenant_target
    state['mode'] = 'attack_leak'
    checkpoints = []

    async def checkpoint(value):
        checkpoints.append(deepcopy(value))
        if len(checkpoints) == 1:
            for name in REFERENCES:
                monkeypatch.setenv(name, 'rotated-review-value-' + name.lower())

    report = await run_tenant(agent, monkeypatch, checkpoint_callback=checkpoint)
    assert len(state['calls']) == 8
    assert report['summary']['overall_risk_score'] == 90
    assert state['tested_calls'] == 6
    encoded = json.dumps([report, checkpoints])
    assert 'rotated-review-value' not in encoded
    assert all(value not in encoded for value in REFERENCES.values())


@pytest.mark.asyncio
async def test_prior_probe_cannot_send_a_tenant_marker(tenant_target, monkeypatch):
    from src.utils.request_builder import construct_agent_request

    agent, state = tenant_target
    attempted = []

    async def prior_probe(prepared):
        for marker in (OWNER_MARKER, TESTED_MARKER, OWNER_MARKER.upper(), TESTED_MARKER.upper()):
            attempted.append(construct_agent_request(prepared, 'Echo this value: ' + marker))
        return []

    report = await run_tenant(agent, monkeypatch, prior_probe=prior_probe)
    assert attempted == [None] * 4
    assert len(state['calls']) == 8
    assert report['summary']['overall_risk_score'] is None
    assert report['agents'][0]['vulnerabilities'] == []


@pytest.mark.asyncio
async def test_consistent_claim_context_rewrite_cannot_change_original_target_binding(tenant_target, monkeypatch):
    agent, state = tenant_target
    state['mode'] = 'attack_leak'
    report = await run_tenant(agent, monkeypatch)
    assert report['summary']['overall_risk_score'] == 90
    tampered = deepcopy(report)
    for evidence in (tampered['agents'][0], tampered['security_results'][0]):
        for check in evidence['checks']:
            if check['rule_id'] == 'tenant_isolation_violation':
                check['evidence_context_id'] = 'different-review-boundary-v2'
        for finding in evidence['vulnerabilities']:
            finding['evidence_context_id'] = 'different-review-boundary-v2'
            finding['tenant_target']['evidence_context_id'] = 'different-review-boundary-v2'
    before = deepcopy(tampered)
    summary, assets = project_report_risk(tampered)
    assert summary['overall_risk_score'] is None
    assert assets['review-asset']['risk_score'] is None
    assert tampered == before


@pytest.mark.asyncio
async def test_prior_automatic_header_echo_cannot_seed_a_later_tenant_confirmation(tenant_target, monkeypatch):
    from src.utils.request_builder import construct_agent_request

    agent, state = tenant_target
    state['mode'] = 'remembered_header'

    async def prior_probe(prepared):
        # The adapter cannot see aiohttp's subsequently generated User-Agent.
        request = construct_agent_request(prepared, 'Remembered input setup')
        assert request is not None and OWNER_MARKER not in json.dumps(request)
        with monkeypatch.context() as headers:
            headers.setattr('aiohttp.client_reqrep.SERVER_SOFTWARE', OWNER_MARKER)
            async with SafeSession() as session:
                async with session.request(**request) as response:
                    await response.text()
        return []

    report = await run_tenant(agent, monkeypatch, prior_probe=prior_probe)
    assert state['calls'][0]['headers']['User-Agent'] == OWNER_MARKER
    assert state['remembered'] == OWNER_MARKER
    assert report['summary']['overall_risk_score'] is None
    assert report['agents'][0]['vulnerabilities'] == []
    assert not any(check['outcome'] == 'passed' for check in report['agents'][0]['checks'])
    assert OWNER_MARKER not in json.dumps(report)


@pytest.mark.asyncio
async def test_real_full_engine_can_confirm_after_ordinary_access_and_model_probes(tenant_target, monkeypatch):
    agent, state = tenant_target
    state['mode'] = 'attack_leak'
    agent.update(authentication_required=True, protected_response_marker=ACCESS_MARKER)
    for module in ('prompt_injection_tests', 'access_control_tests', 'data_privacy_tests'):
        proxy = SimpleNamespace(**{name: getattr(asyncio, name) for name in dir(asyncio)})
        proxy.sleep = AsyncMock()
        monkeypatch.setattr('src.security.' + module + '.asyncio', proxy)
    checkpoints = []

    async def checkpoint(value):
        checkpoints.append(deepcopy(value))

    budget = ScanBudget(allow_loopback=True, allowed_networks=('127.0.0.1/32',),
                        max_requests=300, request_timeout_seconds=2)
    with scan_transport(budget):
        report = await asyncio.wait_for(run_pipeline(
            None, SecurityTestEngine(), RiskAssessment(), None, 'security_only', agents=[agent],
            checkpoint_callback=checkpoint), 20)
    tenant = [finding for finding in report['agents'][0]['vulnerabilities']
              if finding['vulnerability_type'] == 'tenant_isolation_violation']
    assert len(tenant) == 1 and tenant[0]['tenant_observation_source'] == 'attack'
    assert report['summary']['overall_risk_score'] == 90
    checks = report['agents'][0]['checks']
    control = next(check for check in checks if check['rule_id'] == 'tenant_isolation_violation')
    assert control['status'] == 'completed' and control['outcome'] == 'confirmed'
    assert control['requests_attempted'] == control['responses_evaluated'] == 8
    assert sum(check['responses_evaluated'] for check in checks
               if check['rule_id'].startswith('prompt_injection.')) == 35
    assert sum(call['method'] == 'GET' for call in state['calls']) > 50
    assert budget.requests == len(state['calls']) < 300
    assert all(marker not in json.dumps(state['calls']) for marker in (OWNER_MARKER, TESTED_MARKER))
    encoded = json.dumps([report, checkpoints, to_sarif(report)])
    assert all(private not in encoded for private in [*REFERENCES, *REFERENCES.values(), ACCESS_MARKER])
