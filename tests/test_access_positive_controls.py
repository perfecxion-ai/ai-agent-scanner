"""Protected access verdicts require a reachable, seeded authorized resource."""

import asyncio
from copy import deepcopy
import hashlib
import json
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from aiohttp import http, web
import pytest

from src.core.contracts import collect_checks, proves_absence, risk_assessment_eligible
from src.core.pipeline import run_pipeline, to_sarif
from src.core.redaction import collect_secrets, redact_secrets
from src.core.transport import SafeSession, ScanBudget, scan_transport
from src.reporting.workflows import compare_reports
from src.security.access_control_tests import AccessControlTester


MARKER = 'protected-fixture-record-7d42f6c9'
ISSUED = 'issued-fixture-credential-91b6802a'
REFERENCE = 'ACCESS_FIXTURE_ISSUED_KEY'
METHODS = ('_test_authentication_bypass', '_test_weak_credentials',
           '_test_api_key_security', '_test_authorization_bypass')


@pytest.fixture
async def protected_target(monkeypatch):
    # No app import or operator evidence registry is needed by these fixtures.
    monkeypatch.delenv('SCAN_EVIDENCE_PROFILES_FILE', raising=False)
    monkeypatch.setenv(REFERENCE, ISSUED)
    state = {'mode': 'protected', 'requests': []}

    async def handler(request):
        headers = {key.lower(): value for key, value in request.headers.items()}
        state['requests'].append((request.method, request.path, headers))
        credential = next((value for key, value in headers.items()
                           if key in ('authorization', 'x-api-key', 'x-goog-api-key')), '')
        if state['mode'] in ('reflection', 'upper_reflection'):
            body = json.dumps(headers)
            if state['mode'] == 'upper_reflection':
                body = body.upper()
            return web.Response(status=401, text='Denied') if 'scanner-invalid-' in credential else web.Response(text=body)
        if state['mode'] == 'always_denied':
            return web.Response(status=401, text='Denied')
        if state['mode'] == 'cookie_required' and request.cookies.get('issued'):
            return web.Response(text=MARKER)
        if credential in ('Bearer ' + ISSUED, ISSUED):
            if state['mode'] == 'unseeded':
                return web.Response(text='An unrelated resource')
            if state['mode'] == 'baseline_error':
                return web.Response(status=503, text=MARKER)
            if state['mode'] == 'baseline_redirect':
                return web.Response(status=302, text=MARKER, headers={'Location': '/other'})
            if state['mode'] == 'later_path_unavailable' and request.path == '/api/admin':
                return web.Response(status=401, text='Denied')
            response = web.Response(text=MARKER)
            if state['mode'] == 'cookie_required':
                response.set_cookie('issued', 'synthetic-session-cookie')
            return response
        if 'scanner-invalid-' in credential:
            if state['mode'] == 'denial_leaks':
                return web.Response(status=403, text=MARKER)
            if state['mode'] == 'denial_unprotected':
                return web.Response(text='Public response')
            return web.Response(status=401, text='Denied')
        if state['mode'] in ('vulnerable', 'later_path_unavailable'):
            return web.Response(text=MARKER)
        if state['mode'] == 'public_probe':
            return web.Response(text='Public response')
        if state['mode'] == 'probe_failure':
            return web.Response(status=503, text='Unavailable')
        return web.Response(status=403, text='Denied')

    app = web.Application()
    app.router.add_route('*', '/{path:.*}', handler)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, '127.0.0.1', 0)
    await site.start()
    port = site._server.sockets[0].getsockname()[1]
    try:
        yield {'id': 'fixture', 'name': 'Fixture', 'provider': 'openai-compatible',
               'model': 'fixture-model', 'endpoint': f'http://127.0.0.1:{port}/resource',
               'authentication_required': True, 'protected_response_marker': MARKER,
               'protected_path_markers': {'/admin': MARKER},
               'api_key_env': REFERENCE, 'evidence_context_id': 'protected-access-v1'}, state
    finally:
        await runner.cleanup()


async def execute(agent, method, *, tester=None, max_requests=100):
    tester = tester or AccessControlTester()
    budget = ScanBudget(allowed_networks=('127.0.0.1/32',), allow_loopback=True,
                        max_requests=max_requests)
    with scan_transport(budget), collect_checks() as checks, patch('asyncio.sleep', AsyncMock()):
        findings = await getattr(tester, method)(agent)
    assert len(checks) == 1
    return checks[0], findings, budget


@pytest.mark.asyncio
@pytest.mark.parametrize('method', METHODS)
@pytest.mark.parametrize('mode,requests', [
    ('always_denied', 1), ('unseeded', 1), ('baseline_error', 1), ('baseline_redirect', 1),
    ('denial_leaks', 2), ('denial_unprotected', 2),
])
async def test_failed_controls_never_pass_or_confirm(protected_target, method, mode, requests):
    agent, state = protected_target
    state['mode'] = mode
    check, findings, budget = await execute(agent, method)
    assert findings == []
    assert check['status'] == 'failed'
    assert check['outcome'] == 'inconclusive'
    assert budget.requests == len(state['requests']) == requests
    assert not risk_assessment_eligible({'status': 'completed', 'check_schema_version': '1.0',
                                         'checks': [check], 'vulnerabilities': []})


@pytest.mark.asyncio
@pytest.mark.parametrize('method,requests', list(zip(METHODS, (20, 7, 32, 3))))
@pytest.mark.parametrize('mode', ['protected', 'cookie_required'])
async def test_sampled_pass_requires_both_controls_without_session_carryover(
        protected_target, method, requests, mode):
    agent, state = protected_target
    state['mode'] = mode
    check, findings, budget = await execute(agent, method)
    assert findings == []
    assert check['status'] == 'completed' and check['outcome'] == 'passed'
    assert check['requests_attempted'] == check['responses_evaluated'] == budget.requests == requests
    assert all(request[0] == 'GET' for request in state['requests'])
    assert len({request[1] for request in state['requests']}) == 1
    assert state['requests'][0][2]['authorization'] == 'Bearer ' + ISSUED
    assert 'scanner-invalid-' in state['requests'][1][2]['authorization']
    assert all(ISSUED not in str(headers) and 'cookie' not in headers
               for _, _, headers in state['requests'][1:])


@pytest.mark.asyncio
@pytest.mark.parametrize('method,count', list(zip(METHODS, (18, 5, 5, 1))))
async def test_controlled_disclosure_confirms_and_omits_baseline_secrets(
        protected_target, method, count, caplog):
    agent, state = protected_target
    state['mode'] = 'vulnerable'
    with caplog.at_level('DEBUG'):
        check, findings, _ = await execute(agent, method)
    assert check['status'] == 'completed' and check['outcome'] == 'confirmed'
    assert len(findings) == count
    assert all(finding['control_status'] == 'authorized_marker_verified_and_invalid_credential_denied'
               for finding in findings)
    exported = json.dumps([check, findings]) + caplog.text
    assert all(value not in exported for value in (MARKER, ISSUED, REFERENCE))


@pytest.mark.asyncio
@pytest.mark.parametrize('method', METHODS)
async def test_ordinary_success_without_marker_is_not_a_pass(protected_target, method):
    agent, state = protected_target
    state['mode'] = 'public_probe'
    check, findings, _ = await execute(agent, method)
    assert findings == [] and check['outcome'] == 'inconclusive'


@pytest.mark.asyncio
@pytest.mark.parametrize('method,attribute', [(METHODS[1], 'weak_credentials'), (METHODS[2], 'test_api_keys')])
async def test_empty_probe_sample_cannot_pass_from_controls_alone(protected_target, method, attribute):
    agent, state = protected_target
    tester = AccessControlTester()
    setattr(tester, attribute, [])
    check, findings, _ = await execute(agent, method, tester=tester)
    assert findings == [] and check['status'] == 'skipped' and check['outcome'] == 'not_evaluated'
    assert not state['requests']


@pytest.mark.asyncio
@pytest.mark.parametrize('method', METHODS)
@pytest.mark.parametrize('configuration', ['absent', 'unset', 'stale'])
async def test_missing_or_stale_issued_credentials_do_not_pass(
        protected_target, method, configuration, monkeypatch):
    agent, state = protected_target
    if configuration == 'absent':
        agent.pop('api_key_env')
    elif configuration == 'unset':
        monkeypatch.delenv(REFERENCE)
    else:
        monkeypatch.setenv(REFERENCE, 'stale-fixture-key')
    check, findings, budget = await execute(agent, method)
    assert findings == []
    assert check['outcome'] == ('inconclusive' if configuration == 'stale' else 'not_evaluated')
    assert budget.requests == len(state['requests']) == (1 if configuration == 'stale' else 0)
    assert REFERENCE not in json.dumps(check)


@pytest.mark.asyncio
@pytest.mark.parametrize('method', METHODS)
async def test_transport_failure_during_baseline_is_secret_safe(protected_target, method, caplog):
    agent, state = protected_target
    with patch('src.security.access_control_tests.SafeSession') as factory, caplog.at_level('DEBUG'):
        factory.return_value.__aenter__.side_effect = OSError(ISSUED + MARKER + REFERENCE)
        check, findings, _ = await execute(agent, method)
    assert check['status'] == 'failed' and check['outcome'] == 'inconclusive'
    assert findings == [] and not state['requests']
    assert all(value not in json.dumps(check) + caplog.text for value in (MARKER, ISSUED, REFERENCE))


@pytest.mark.asyncio
@pytest.mark.parametrize('method', METHODS)
async def test_shared_budget_includes_baseline_and_denied_control(protected_target, method):
    agent, state = protected_target
    check, findings, budget = await execute(agent, method, max_requests=1)
    assert budget.requests == len(state['requests']) == 1
    assert budget.rejections >= 1
    assert findings == [] and check['status'] == 'failed' and check['outcome'] == 'inconclusive'


@pytest.mark.asyncio
@pytest.mark.parametrize('provider,header', [('anthropic', 'x-api-key'), ('google', 'x-goog-api-key'),
                                           ('gemini', 'x-goog-api-key'), ('ollama', 'authorization')])
async def test_baseline_and_denied_control_use_the_same_provider_header(protected_target, provider, header):
    agent, state = protected_target
    agent['provider'] = provider
    check, _, _ = await execute(agent, '_test_weak_credentials')
    assert check['outcome'] == 'passed'
    assert ISSUED in state['requests'][0][2][header]
    assert 'scanner-invalid-' in state['requests'][1][2][header]


@pytest.mark.asyncio
@pytest.mark.parametrize('source', ['endpoint', 'normalized_endpoint', 'query', 'credential', 'public_name',
                                   'reference', 'weak_basic', 'weak_key', 'weak_key_header', 'bypass_header'])
async def test_reflected_public_or_request_marker_refused_before_http(protected_target, source, monkeypatch):
    agent, state = protected_target
    tester = AccessControlTester()
    method = '_test_authentication_bypass'
    if source == 'endpoint':
        agent['endpoint'] += '/' + MARKER
    elif source == 'normalized_endpoint':
        agent['endpoint'] += '/' + '%70' + MARKER[1:]
    elif source == 'query':
        agent['endpoint'] += '?marker=' + MARKER
    elif source == 'credential':
        monkeypatch.setenv(REFERENCE, 'key-' + MARKER)
    elif source == 'public_name':
        agent['name'] = MARKER
    elif source == 'reference':
        agent['protected_response_marker'] = REFERENCE
    elif source == 'weak_basic':
        tester.weak_credentials = [('fixture', MARKER)]
        method = '_test_weak_credentials'
    elif source == 'weak_key':
        tester.test_api_keys = [MARKER]
        method = '_test_api_key_security'
    elif source == 'weak_key_header':
        agent['protected_response_marker'] = 'Bearer 123456789'
        method = '_test_api_key_security'
    else:
        agent['protected_response_marker'] = 'InvalidScheme token'
    check, findings, budget = await execute(agent, method, tester=tester)
    assert not state['requests'] and budget.requests == 0
    expected = 'not_evaluated' if source in ('weak_key_header', 'bypass_header') else 'inconclusive'
    assert findings == [] and check['outcome'] == expected


@pytest.mark.asyncio
@pytest.mark.parametrize('method', METHODS)
@pytest.mark.parametrize('marker', [http.SERVER_SOFTWARE, 'ai-agent-scanner',
                                   'User-Agent: ai-agent-scanner', 'Accept-Encoding: identity',
                                   'user-agent": "ai-agent-scanner', 'AI-AGENT-SCANNER'])
async def test_transport_header_reflection_cannot_confirm(protected_target, method, marker):
    agent, state = protected_target
    state['mode'] = 'upper_reflection' if marker == 'AI-AGENT-SCANNER' else 'reflection'
    agent.update(protected_response_marker=marker, protected_path_markers={'/admin': marker})
    check, findings, _ = await execute(agent, method)
    assert findings == [] and check['outcome'] in ('inconclusive', 'not_evaluated')
    assert not state['requests']
    assert all(marker not in json.dumps(headers) for _, _, headers in state['requests'])


@pytest.mark.asyncio
@pytest.mark.parametrize('method', METHODS)
@pytest.mark.parametrize('source', ['host', 'request_line'])
async def test_wire_host_and_request_line_cannot_be_protected_markers(protected_target, method, source):
    agent, state = protected_target
    marker = ('Host: ' + agent['endpoint'].split('/')[2] if source == 'host' else
              'GET /admin HTTP/1.1' if method == METHODS[3] else 'GET /resource HTTP/1.1')
    agent.update(protected_response_marker=marker, protected_path_markers={'/admin': marker})
    check, findings, _ = await execute(agent, method)
    assert findings == [] and check['outcome'] == 'not_evaluated' and not state['requests']


@pytest.mark.asyncio
@pytest.mark.parametrize('method', METHODS)
@pytest.mark.parametrize('marker', ['a' * 15, 'a' * 129, 'private fixture marker',
                                   'private-fixture-marker\n', 'private-fixture-marker/record',
                                   'private-fixture-marker\u00e9'])
async def test_invalid_marker_grammar_is_skipped_without_io(protected_target, method, marker):
    agent, state = protected_target
    agent.update(protected_response_marker=marker, protected_path_markers={'/admin': marker})
    check, findings, _ = await execute(agent, method)
    assert findings == [] and not state['requests']
    assert check['status'] == 'skipped' and check['outcome'] == 'not_evaluated'
    assert marker not in check['reason']


@pytest.mark.asyncio
async def test_probe_session_entry_failure_after_valid_controls_cannot_pass(protected_target):
    agent, _ = protected_target
    original_enter = SafeSession.__aenter__
    entries = 0

    async def enter(session):
        nonlocal entries
        entries += 1
        if entries > 2:
            raise OSError('Synthetic session-entry failure')
        return await original_enter(session)

    with patch.object(SafeSession, '__aenter__', enter):
        check, findings, _ = await execute(agent, '_test_authentication_bypass')
    assert entries == 20
    assert findings == [] and check['status'] == 'failed' and check['outcome'] == 'inconclusive'


@pytest.mark.asyncio
@pytest.mark.parametrize('stage,evaluated', [('probe_entry', 2), ('first_pacing', 3), ('final_pacing', 20)])
async def test_cancellation_after_successful_controls_never_passes(protected_target, stage, evaluated):
    agent, state = protected_target
    original_enter = SafeSession.__aenter__
    entries = 0
    pacing = 0

    async def enter(session):
        nonlocal entries
        entries += 1
        if stage == 'probe_entry' and entries == 3:
            raise asyncio.CancelledError
        return await original_enter(session)

    async def sleep(delay):
        nonlocal pacing
        if delay == 0.5:
            pacing += 1
            if ((stage == 'first_pacing' and pacing == 1)
                    or (stage == 'final_pacing' and pacing == 18)):
                raise asyncio.CancelledError

    budget = ScanBudget(allowed_networks=('127.0.0.1/32',), allow_loopback=True)
    with scan_transport(budget), collect_checks() as checks, patch.object(SafeSession, '__aenter__', enter), \
            patch('asyncio.sleep', sleep), pytest.raises(asyncio.CancelledError):
        await AccessControlTester()._test_authentication_bypass(agent)
    assert len(checks) == 1
    assert checks[0]['status'] == 'failed' and checks[0]['outcome'] == 'inconclusive'
    assert checks[0]['responses_evaluated'] == len(state['requests']) == evaluated
    assert checks[0]['requests_attempted'] == evaluated


@pytest.mark.parametrize('header', ['Bearer ', 'Basic '])
def test_empty_probe_credential_cannot_corrupt_report_redaction(header):
    secrets = collect_secrets({'Authorization': header})
    assert '' not in secrets
    document = {'schema_version': '1.0', 'status': 'completed'}
    assert redact_secrets(document, secrets | {''}) == document


def report(agent, check, findings):
    return {'schema_version': '1.0', 'check_schema_version': '1.0', 'status': 'completed',
            'scan_type': 'full', 'summary': {}, 'agents': [{
                **agent, 'security_status': 'completed', 'checks': [check], 'vulnerabilities': findings}]}


@pytest.mark.asyncio
@pytest.mark.parametrize('method', METHODS)
async def test_later_always_denied_run_cannot_resolve_confirmed_findings(protected_target, method):
    agent, state = protected_target
    state['mode'] = 'vulnerable'
    previous, findings, _ = await execute(agent, method)
    state['mode'] = 'always_denied'
    current, absent, _ = await execute(agent, method)
    diff = compare_reports(report(agent, previous, findings), report(agent, current, absent))
    assert not diff['resolved'] and len(diff['resolution_unverified']) >= 1
    assert all(not proves_absence(current, finding) for finding in findings)


@pytest.mark.asyncio
@pytest.mark.parametrize('method', METHODS)
async def test_legacy_probe_versions_cannot_resolve_current_findings_or_reverse(protected_target, method):
    agent, state = protected_target
    tester = AccessControlTester()
    legacy = {
        METHODS[0]: '18-header-variations-denied-control-v1',
        METHODS[1]: tester.weak_credentials[:5],
        METHODS[2]: [tester.test_api_keys[:5], 'six-header-variations-v1'],
        METHODS[3]: ['admin-path-sample-v1', tester.sensitive_paths[:8]],
    }[method]
    identity = [legacy, agent['provider'], agent['model']]
    if method == METHODS[3]:
        identity.append(['/admin'])
    legacy_version = '1:' + hashlib.sha256(json.dumps(identity, sort_keys=True).encode()).hexdigest()
    state['mode'] = 'vulnerable'
    confirmed, findings, _ = await execute(agent, method)
    state['mode'] = 'protected'
    passed, _, _ = await execute(agent, method)
    assert confirmed['probe_version'] == passed['probe_version'] != legacy_version
    assert proves_absence(passed, findings[0])
    legacy_pass = dict(passed, probe_version=legacy_version)
    legacy_finding = dict(findings[0], probe_version=legacy_version)
    assert not proves_absence(legacy_pass, findings[0])
    assert not proves_absence(passed, legacy_finding)
    assert not compare_reports(report(agent, confirmed, [legacy_finding]), report(agent, passed, []))['resolved']


@pytest.mark.asyncio
async def test_later_path_control_failure_preserves_earlier_confirmation(protected_target):
    agent, state = protected_target
    agent['protected_path_markers']['/api/admin'] = MARKER
    state['mode'] = 'later_path_unavailable'
    check, findings, _ = await execute(agent, '_test_authorization_bypass')
    assert check['status'] == 'failed' and check['outcome'] == 'confirmed'
    assert len(findings) == 1 and findings[0]['path'] == '/admin'


@pytest.mark.asyncio
async def test_actual_check_results_stay_private_in_pipeline_and_sarif(protected_target):
    agent, state = protected_target
    original = deepcopy(agent)
    state['mode'] = 'vulnerable'
    check, findings, _ = await execute(agent, '_test_authentication_bypass')
    result = {'agent_id': agent['id'], 'status': 'completed', 'check_schema_version': '1.0',
              'checks': [check], 'vulnerabilities': findings}
    security = SimpleNamespace(test_agents=AsyncMock(return_value=[result]))
    discovery = SimpleNamespace(discover_agents=AsyncMock(return_value=[agent]))
    pipeline = await run_pipeline(discovery, security, None, None)
    encoded = json.dumps([pipeline, to_sarif(pipeline)])
    assert all(value not in encoded for value in (MARKER, ISSUED, REFERENCE))
    assert agent == original
