"""Actual HTTP tenant controls, private provenance, and bounded sample semantics."""

import asyncio
from copy import deepcopy
import json
from types import SimpleNamespace
from unittest.mock import AsyncMock

from aiohttp import web
import pytest

from src.core.contracts import collect_checks, confirmed_findings, proves_absence, risk_assessment_eligible
from src.core.tenant_evidence import tenant_evidence_context, tenant_evidence_tainted
from src.core.tenant_probe_policy import TENANT_CONTROL_PROMPT, TENANT_MAX_REQUESTS, tenant_target
from src.core.transport import SafeSession, ScanBudget, scan_transport
from src.security.data_privacy_tests import DataPrivacyTester


OWNER_KEY = 'synthetic-owner-key-a83c1e947c'
TESTED_KEY = 'synthetic-tested-key-f42d39a731'
OWNER_MARKER = 'owner-record-canary-a83c1e947c'
TESTED_MARKER = 'tested-record-canary-f42d39a731'


def configured_agent(endpoint):
    item = dict(id='tenant-fixture', name='Tenant fixture', endpoint=endpoint, provider='ollama',
                model='fixture-model', api_key_env='TENANT_FIXTURE_TESTED_KEY',
                evidence_context_id='tenant-fixture-v1')
    item['tenant_evidence'] = dict(
        schema_version='1.0', tested_principal_authorized_for_owner=False,
        binding=tenant_target(endpoint, item['provider'], item['model'], item['evidence_context_id']),
        owner=dict(tenant_ref='tenant-owner', principal_ref='principal-owner',
                   api_key_env='TENANT_FIXTURE_OWNER_KEY', canary_env='TENANT_FIXTURE_OWNER_CANARY'),
        tested=dict(tenant_ref='tenant-tested', principal_ref='principal-tested',
                    api_key_env='TENANT_FIXTURE_TESTED_KEY', canary_env='TENANT_FIXTURE_TESTED_CANARY'))
    return item


@pytest.fixture(autouse=True)
def prepared_environment(monkeypatch):
    for reference, value in [('OWNER_KEY', OWNER_KEY), ('TESTED_KEY', TESTED_KEY),
                             ('OWNER_CANARY', OWNER_MARKER), ('TESTED_CANARY', TESTED_MARKER)]:
        monkeypatch.setenv('TENANT_FIXTURE_' + reference, value)
    monkeypatch.setattr('src.security.data_privacy_tests.asyncio',
                        SimpleNamespace(sleep=AsyncMock(), CancelledError=asyncio.CancelledError))


@pytest.fixture
async def tenant_server():
    state = dict(mode='leak', calls=[], blocked=asyncio.Event(), release=asyncio.Event(), remembered=False)

    async def handler(request):
        body = await request.json()
        prompt = body['messages'][0]['content']
        key = request.headers.get('Authorization', '').removeprefix('Bearer ')
        state['calls'].append(dict(key=key, prompt=prompt, cookie=request.headers.get('Cookie')))
        if OWNER_MARKER in request.headers.get('X-Synthetic-Reflection', ''):
            state['remembered'] = True
        mode, headers, status, metadata = state['mode'], {}, 200, None
        if mode == 'always_denied':
            return web.Response(status=403, text='Denied')
        if key == OWNER_KEY:
            text = OWNER_MARKER
            if mode == 'remembered' and not state['remembered']:
                text = 'No seeded record'
            if mode == 'owner_unseeded':
                text = 'No protected record'
            elif mode == 'owner_metadata':
                text, metadata = 'No generated record', OWNER_MARKER
            elif mode == 'owner_both':
                text += ' ' + TESTED_MARKER
            elif mode == 'owner_case_both':
                text += ' ' + TESTED_MARKER.upper()
            elif mode == 'owner_header':
                headers['X-Record'] = TESTED_MARKER
        elif key == TESTED_KEY and prompt == TENANT_CONTROL_PROMPT:
            text = TESTED_MARKER
            if mode == 'tested_unseeded':
                text = 'No protected record'
            elif mode == 'tested_metadata':
                text, metadata = 'No generated record', TESTED_MARKER
            elif mode == 'tested_foreign_only':
                text = OWNER_MARKER
            elif mode == 'tested_both':
                text += ' ' + OWNER_MARKER
        elif key != TESTED_KEY:
            status, text = 403, 'Denied'
            if mode == 'invalid_allowed':
                status = 200
            elif mode == 'invalid_body':
                text = OWNER_MARKER
            elif mode == 'invalid_case':
                text = TESTED_MARKER.upper()
            elif mode == 'invalid_metadata':
                metadata = OWNER_MARKER
            elif mode == 'invalid_header':
                headers['X-Record'] = TESTED_MARKER
            if state.get('invalid_contaminated'):
                text = OWNER_MARKER
        else:
            if mode == 'stall' and len(state['calls']) > 4:
                state['blocked'].set()
                await state['release'].wait()
            if mode == 'late_fail' and len(state['calls']) > 4:
                return web.Response(status=503, text='Unavailable')
            text = 'Cannot disclose foreign records' if mode in {'secure', 'tested_both', 'attack_metadata'} else OWNER_MARKER
            if mode == 'attack_metadata':
                metadata = OWNER_MARKER
        data = {'message': {'content': text}}
        if metadata is not None:
            data['metadata'] = metadata
        response = web.json_response(data, status=status, headers=headers)
        response.set_cookie('session', 'synthetic-session-cookie')
        return response

    app = web.Application()
    app.router.add_post('/api/chat', handler)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, '127.0.0.1', 0)
    await site.start()
    try:
        yield f'http://127.0.0.1:{site._server.sockets[0].getsockname()[1]}', state
    finally:
        state['release'].set()
        await runner.cleanup()


async def run_tenant(item, *, budget=None, tester=None):
    budget = budget or ScanBudget(allow_loopback=True)
    with tenant_evidence_context([item]), scan_transport(budget), collect_checks() as checks:
        findings = await (tester or DataPrivacyTester())._test_tenant_isolation(item)
    return dict(agent_id=item['id'], endpoint=item['endpoint'], provider=item['provider'], model=item['model'],
                evidence_context_id=item['evidence_context_id'], check_schema_version='1.0',
                status='partial' if checks[0]['status'] == 'failed' else 'completed',
                checks=checks, vulnerabilities=findings)


@pytest.mark.asyncio
@pytest.mark.parametrize('mode, count, source', [('leak', 5, 'attack'), ('tested_both', 1, 'subject_control')])
async def test_actual_controlled_disclosure_has_current_bound_evidence(tenant_server, mode, count, source):
    endpoint, state = tenant_server
    state['mode'] = mode
    budget = ScanBudget(allow_loopback=True)
    result = await run_tenant(configured_agent(endpoint), budget=budget)
    assert len(result['vulnerabilities']) == count
    assert confirmed_findings(result) == result['vulnerabilities']
    assert risk_assessment_eligible(result)
    assert {finding['tenant_observation_source'] for finding in result['vulnerabilities']} == {source}
    assert result['checks'][0]['requests_attempted'] == result['checks'][0]['responses_evaluated'] == TENANT_MAX_REQUESTS
    assert budget.requests == len(state['calls']) == 8 and budget.failures == 0
    assert [call['key'] for call in state['calls'][:2]] == [OWNER_KEY, TESTED_KEY]
    assert state['calls'][2]['key'] not in {OWNER_KEY, TESTED_KEY}
    assert all(call['key'] == TESTED_KEY for call in state['calls'][3:])
    assert all(call['cookie'] is None for call in state['calls'])
    serialized = json.dumps(result)
    assert all(secret not in serialized for secret in (OWNER_KEY, TESTED_KEY, OWNER_MARKER, TESTED_MARKER,
                                                       state['calls'][2]['key']))
    assert all(marker.casefold() not in json.dumps(state['calls']).casefold()
               for marker in (OWNER_MARKER, TESTED_MARKER))


@pytest.mark.asyncio
@pytest.mark.parametrize('mode, calls', [
    ('always_denied', 1), ('owner_unseeded', 1), ('owner_metadata', 1), ('owner_both', 1),
    ('owner_case_both', 1), ('owner_header', 1), ('tested_unseeded', 2), ('tested_metadata', 2),
    ('tested_foreign_only', 2), ('invalid_allowed', 3), ('invalid_body', 3), ('invalid_case', 3),
    ('invalid_metadata', 3), ('invalid_header', 3),
])
async def test_failed_or_contaminated_controls_never_start_attacks(tenant_server, mode, calls):
    endpoint, state = tenant_server
    state['mode'] = mode
    result = await run_tenant(configured_agent(endpoint))
    assert result['vulnerabilities'] == [] and not risk_assessment_eligible(result)
    assert result['checks'][0]['status'] == 'failed' and result['checks'][0]['outcome'] == 'inconclusive'
    assert len(state['calls']) == calls


@pytest.mark.asyncio
@pytest.mark.parametrize('mode', ['secure', 'attack_metadata'])
async def test_nondisclosure_and_metadata_do_not_pass_or_resolve(tenant_server, mode):
    endpoint, state = tenant_server
    item = configured_agent(endpoint)
    old = await run_tenant(item)
    state['calls'].clear()
    state['mode'] = mode
    result = await run_tenant(item)
    assert result['checks'][0]['status'] == 'completed' and result['checks'][0]['outcome'] == 'inconclusive'
    assert result['vulnerabilities'] == [] and not risk_assessment_eligible(result)
    assert len(state['calls']) == 8
    assert not proves_absence(result['checks'][0], old['vulnerabilities'][0], asset=result, previous_asset=old)


@pytest.mark.asyncio
async def test_later_http_errors_keep_confirmed_tenant_evidence_partial(tenant_server):
    endpoint, state = tenant_server
    state['mode'] = 'late_fail'
    result = await run_tenant(configured_agent(endpoint))
    assert result['status'] == 'partial' and len(state['calls']) == 8
    assert result['checks'][0]['responses_evaluated'] == 4
    assert len(confirmed_findings(result)) == 1 and risk_assessment_eligible(result)


@pytest.mark.asyncio
@pytest.mark.parametrize('maximum', [1, 2, 3, 4])
async def test_existing_shared_request_budget_is_not_reset(tenant_server, maximum):
    endpoint, state = tenant_server
    budget = ScanBudget(allow_loopback=True, max_requests=maximum)
    result = await run_tenant(configured_agent(endpoint), budget=budget)
    assert budget.requests == len(state['calls']) == maximum
    assert result['checks'][0]['status'] == 'failed'
    assert risk_assessment_eligible(result) is (maximum == 4)


@pytest.mark.asyncio
async def test_subject_control_confirmation_requires_the_completed_denied_control(tenant_server):
    endpoint, state = tenant_server
    state.update(mode='tested_both', invalid_contaminated=True)
    result = await run_tenant(configured_agent(endpoint))
    assert len(state['calls']) == 3 and result['vulnerabilities'] == []
    assert not risk_assessment_eligible(result)


@pytest.mark.asyncio
async def test_subject_control_confirmation_can_survive_exhausted_attack_budget(tenant_server):
    endpoint, state = tenant_server
    state['mode'] = 'tested_both'
    result = await run_tenant(configured_agent(endpoint), budget=ScanBudget(allow_loopback=True, max_requests=3))
    assert len(state['calls']) == 3 and result['checks'][0]['responses_evaluated'] == 3
    assert result['checks'][0]['status'] == 'failed'
    assert len(confirmed_findings(result)) == 1 and risk_assessment_eligible(result)


@pytest.mark.asyncio
async def test_pinned_credentials_survive_environment_rotation(tenant_server, monkeypatch):
    endpoint, state = tenant_server
    item = configured_agent(endpoint)
    with tenant_evidence_context([item]):
        monkeypatch.setenv('TENANT_FIXTURE_OWNER_KEY', 'rotated-owner-key-ea83f2710b')
        monkeypatch.setenv('TENANT_FIXTURE_TESTED_KEY', 'rotated-tested-key-14c892ab73')
        result = await run_tenant(item)
    assert risk_assessment_eligible(result) and len(state['calls']) == 8


@pytest.mark.asyncio
@pytest.mark.parametrize('mutation', [
    'missing_target', 'extra_target_key', 'wrong_endpoint', 'wrong_provider', 'wrong_model', 'wrong_context',
    'coordinated_context', 'missing_expected_context', 'redacted_target', 'old_version', 'missing_control',
    'bad_control_version', 'invalid_status', 'bad_source', 'bad_index', 'too_few_controls', 'too_many_requests',
    'missing_id', 'mismatched_labels', 'source_counter_mismatch',
])
async def test_current_finding_requires_original_binding_and_controls(tenant_server, mutation):
    endpoint, _ = tenant_server
    result = await run_tenant(configured_agent(endpoint))
    result['vulnerabilities'] = result['vulnerabilities'][:1]
    finding, check = result['vulnerabilities'][0], result['checks'][0]
    if mutation == 'missing_target':
        finding.pop('tenant_target')
    elif mutation == 'extra_target_key':
        finding['tenant_target']['principal_ref'] = 'unexpected'
    elif mutation.startswith('wrong_'):
        field = mutation.removeprefix('wrong_')
        finding['tenant_target']['evidence_context_id' if field == 'context' else field] = 'changed'
    elif mutation == 'coordinated_context':
        check['evidence_context_id'] = finding['evidence_context_id'] = 'changed-v2'
        finding['tenant_target']['evidence_context_id'] = 'changed-v2'
    elif mutation == 'missing_expected_context':
        result.pop('evidence_context_id')
    elif mutation == 'redacted_target':
        finding['tenant_target']['endpoint'] = '[redacted]'
    elif mutation == 'old_version':
        check['probe_version'] = finding['probe_version'] = '1:historical'
    elif mutation == 'missing_control':
        finding.pop('control_status')
    elif mutation == 'bad_control_version':
        finding['tenant_control_version'] = True
    elif mutation == 'invalid_status':
        finding['status_code'] = 403
    elif mutation == 'bad_source':
        finding['tenant_observation_source'] = 'metadata'
    elif mutation == 'bad_index':
        finding['tenant_attack_index'] = True
    elif mutation == 'too_few_controls':
        check.update(requests_attempted=2, responses_evaluated=2, status='failed', reason='Incomplete controls')
    elif mutation == 'too_many_requests':
        check.update(requests_attempted=9, responses_evaluated=8, status='failed', reason='Extra request')
    elif mutation == 'missing_id':
        finding.pop('id')
    elif mutation == 'mismatched_labels':
        finding['vulnerability_type'] = 'unrelated.fixture'
    elif mutation == 'source_counter_mismatch':
        finding['tenant_attack_index'] = 4
        check.update(requests_attempted=4, responses_evaluated=4, status='failed', reason='Incomplete sample')
    original = deepcopy(result)
    assert confirmed_findings(result) == [] and not risk_assessment_eligible(result)
    assert result == original


@pytest.mark.asyncio
async def test_session_default_request_material_is_rejected_before_transmission(tenant_server, monkeypatch):
    import aiohttp
    endpoint, state = tenant_server
    original_session = aiohttp.ClientSession

    def session(*args, **kwargs):
        kwargs['headers'] = {'X-Synthetic-Reflection': OWNER_MARKER.upper()}
        return original_session(*args, **kwargs)

    monkeypatch.setattr('src.core.transport.aiohttp.ClientSession', session)
    result = await run_tenant(configured_agent(endpoint))
    assert len(state['calls']) == 0
    assert result['vulnerabilities'] == [] and not risk_assessment_eligible(result)


def inject_automatic_header(monkeypatch, *, request_number):
    """Inject below session/adapter preflight, where actual capture is required."""
    import aiohttp
    original = aiohttp.ClientRequest.update_auto_headers
    calls = 0

    def update(request, skip):
        nonlocal calls
        original(request, skip)
        calls += 1
        if calls == request_number:
            request.headers['X-Synthetic-Reflection'] = OWNER_MARKER

    monkeypatch.setattr(aiohttp.ClientRequest, 'update_auto_headers', update)


@pytest.mark.asyncio
async def test_actual_automatic_header_taints_without_confirmation(tenant_server, monkeypatch):
    endpoint, state = tenant_server
    inject_automatic_header(monkeypatch, request_number=1)
    result = await run_tenant(configured_agent(endpoint))
    assert len(state['calls']) == 1 and state['remembered']
    assert result['vulnerabilities'] == [] and not risk_assessment_eligible(result)


@pytest.mark.asyncio
async def test_earlier_transmitted_marker_cannot_seed_a_later_tenant_confirmation(tenant_server, monkeypatch):
    endpoint, state = tenant_server
    item = configured_agent(endpoint)
    state['mode'] = 'remembered'
    inject_automatic_header(monkeypatch, request_number=1)
    with tenant_evidence_context([item]), scan_transport(ScanBudget(allow_loopback=True)):
        async with SafeSession() as session:
            async with session.request('POST', endpoint + '/api/chat',
                                       headers={'Authorization': 'Bearer ' + TESTED_KEY},
                                       json={'model': 'fixture-model', 'messages': [{'role': 'user', 'content': 'Earlier probe'}]}) as response:
                await response.text()
        assert state['remembered'] and tenant_evidence_tainted(item)
        with collect_checks() as checks:
            assert await DataPrivacyTester()._test_tenant_isolation(item) == []
    assert len(state['calls']) == 1
    assert checks[0]['status'] == 'skipped' and checks[0]['outcome'] == 'not_evaluated'
    assert checks[0]['requests_attempted'] == 0


@pytest.mark.asyncio
async def test_later_taint_does_not_discard_an_earlier_valid_confirmation(tenant_server, monkeypatch):
    endpoint, state = tenant_server
    inject_automatic_header(monkeypatch, request_number=5)
    result = await run_tenant(configured_agent(endpoint))
    assert len(state['calls']) == result['checks'][0]['requests_attempted'] == 5
    assert result['checks'][0]['responses_evaluated'] == 4 and result['checks'][0]['status'] == 'failed'
    assert len(confirmed_findings(result)) == 1 and risk_assessment_eligible(result)


@pytest.mark.asyncio
async def test_interrupted_tenant_check_does_not_invent_a_finalized_finding(tenant_server):
    endpoint, state = tenant_server
    item = configured_agent(endpoint)
    state['mode'] = 'stall'
    with tenant_evidence_context([item]), scan_transport(ScanBudget(allow_loopback=True)), collect_checks() as checks:
        task = asyncio.create_task(DataPrivacyTester()._test_tenant_isolation(item))
        try:
            await asyncio.wait_for(state['blocked'].wait(), timeout=5)
        finally:
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
    assert len(state['calls']) == 5
    assert checks[0]['status'] == 'failed' and checks[0]['outcome'] == 'inconclusive'
    assert checks[0]['responses_evaluated'] == 4


@pytest.mark.asyncio
async def test_missing_actual_request_snapshot_cannot_confirm(tenant_server, monkeypatch):
    endpoint, state = tenant_server
    monkeypatch.setattr('src.core.transport.RequestCapture.seal', lambda *_: None)
    result = await run_tenant(configured_agent(endpoint))
    assert len(state['calls']) == 1
    assert result['vulnerabilities'] == [] and not risk_assessment_eligible(result)
