"""Prompt receipts require actual evaluated responses and preserve unfinished evidence."""

import asyncio
from copy import deepcopy
import hashlib
import json
from types import SimpleNamespace
from unittest.mock import AsyncMock
import uuid

from aiohttp import web
import pytest

from src.core.contracts import (
    CHECK_INTERRUPTED_REASON, CheckpointError, collect_checks, collect_evidence,
    confirmed_findings, evidence_findings, observe_evidence, risk_assessment_eligible,
    publish_prompt_evidence, record_prompt_response, unfinished_evidence_checks, validate_check_evidence,
    validate_checkpoint_report, validate_scan_result,
)
from src.core.prompt_catalog import baseline_payloads, candidate_payloads
from src.core.prompt_evidence_policy import prompt_probe_payloads
from src.core.request_evidence import (
    RequestTrace, current_trace, evaluate_response, response_token, trace_requests,
)
from src.core.transport import BoundedResponse, SafeSession, ScanBudget, scan_transport
from src.security.prompt_injection_tests import PromptInjectionTester


CANARY = 'synthetic-observation-canary-7a92ef'
CATEGORY = 'system_prompt_extraction'


def agent(endpoint='http://127.0.0.1:1'):
    return {'id': 'fixture', 'name': 'Fixture', 'provider': 'ollama', 'model': 'fixture-model',
            'endpoint': endpoint, 'system_prompt_canary': CANARY, 'evidence_context_id': 'fixture-v1'}


def asset_for(item, state, checks, findings=None):
    return dict(item, provider=item.get('provider'), model=item.get('model'), status='partial', check_schema_version='1.0',
                check_evidence_schema_version='1.0', check_evidence_run_id=state.run_id,
                check_evidence=deepcopy(state.receipts), checks=deepcopy(checks),
                vulnerabilities=deepcopy(state.findings if findings is None else findings))


def valid_asset():
    item = agent()
    payloads = baseline_payloads()[CATEGORY][:5]
    rule = 'prompt_injection.' + CATEGORY
    identity = [{'semantics': 'nondisclosure-inconclusive-v2', 'payloads': payloads}, 'ollama', 'fixture-model']
    version = '1:' + hashlib.sha256(json.dumps(identity, sort_keys=True).encode()).hexdigest()
    finding_id, receipt_id, run_id = (str(uuid.uuid4()) for _ in range(3))
    provenance = dict(rule_id=rule, probe_id=rule + '.sample', probe_version=version,
                      evidence_context_id='fixture-v1')
    finding = dict(provenance, id=finding_id, agent_id='fixture', check_evidence_id=receipt_id,
                   vulnerability_type='prompt_injection', category=CATEGORY, severity='high',
                   evidence_status='confirmed', status_code=200, payload=payloads[0])
    receipt = dict(provenance, id=receipt_id, run_id=run_id, agent_id='fixture', finding_id=finding_id,
                   sample_index=0, sequence=1, request_ordinal=1, requests_attempted=1, responses_evaluated=1,
                   source='protected_system_canary_match', source_version='2.0')
    return dict(item, status='partial', check_schema_version='1.0', check_evidence_schema_version='1.0',
                check_evidence_run_id=run_id, check_evidence=[receipt], vulnerabilities=[finding], checks=[])


def valid_report():
    asset = valid_asset()
    asset.update(security_status='partial', observations=[])
    security = deepcopy(asset)
    security['agent_id'] = security.pop('id')
    security.pop('security_status')
    return dict(schema_version='1.0', check_schema_version='1.0', check_evidence_schema_version='1.0',
                agents=[asset], security_results=[security], risk_assessments=[], summary={}, status='partial',
                checkpoint={'version': '2.0', 'sequence': 1, 'coverage': 'confirmed_observations_and_finalized_checks'})


@pytest.fixture(autouse=True)
def no_pacing(monkeypatch):
    monkeypatch.setattr('asyncio.sleep', AsyncMock())


@pytest.fixture
async def target():
    state = {'calls': 0, 'mode': 'leak', 'release': asyncio.Event(), 'blocked': asyncio.Event()}

    async def handler(request):
        state['calls'] += 1
        body = await request.json()
        if state['mode'] == 'stall' and state['calls'] > 1:
            state['blocked'].set()
            await state['release'].wait()
        if state['mode'] == 'denied':
            return web.Response(status=403, text=CANARY)
        if state['mode'] == 'late' and state['calls'] <= 2:
            return web.Response(status=503, text=CANARY)
        payload = body['messages'][0]['content'] if 'messages' in body else body['contents'][0]['parts'][0]['text']
        text = CANARY if state['mode'] in {'leak', 'stall', 'late'} else (
            payload if state['mode'] == 'reflection' else 'I cannot reveal that.')
        if request.path.endswith(':generateContent'):
            return web.json_response({'candidates': [{'content': {'parts': [{'text': text}]}}]})
        return web.json_response({'message': {'content': text}, 'private_metadata': CANARY})

    app = web.Application()
    app.router.add_post('/api/chat', handler)
    app.router.add_post('/v1beta/models/fixture-model:generateContent', handler)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, '127.0.0.1', 0)
    await site.start()
    try:
        yield f'http://127.0.0.1:{site._server.sockets[0].getsockname()[1]}', state
    finally:
        state['release'].set()
        await runner.cleanup()


@pytest.mark.asyncio
@pytest.mark.parametrize('observer_enabled', [False, True])
async def test_actual_category_emits_matching_receipts_before_final_return(target, observer_enabled):
    endpoint, target_state = target
    item, tester, events = agent(endpoint), PromptInjectionTester(), []

    async def sink(receipt, finding):
        assert checks == []
        assert current_trace() is None
        assert receipt['requests_attempted'] == target_state['calls']
        events.append((receipt, finding))
        receipt['sequence'] = 999
        finding['severity'] = 'low'

    with scan_transport(ScanBudget(allow_loopback=True)), collect_checks() as checks, \
            collect_evidence(item, sink if observer_enabled else None) as state:
        findings = await tester._test_injection_category(item, CATEGORY, tester.injection_payloads[CATEGORY])
    result = asset_for(item, state, checks, findings)
    assert validate_check_evidence(result) is result
    assert len(evidence_findings(result)) == len(state.receipts) == len(findings) == 5
    assert target_state['calls'] == checks[0]['requests_attempted'] == checks[0]['responses_evaluated'] == 5
    assert checks[0]['status'] == 'completed' and checks[0]['outcome'] == 'confirmed'
    assert len(events) == (5 if observer_enabled else 0)
    assert [receipt['sequence'] for receipt in state.receipts] == [1, 2, 3, 4, 5]
    assert unfinished_evidence_checks(result) == set()
    assert risk_assessment_eligible(result)


@pytest.mark.asyncio
@pytest.mark.parametrize('provider', ['gemini', 'google'])
async def test_native_gemini_endpoint_preserves_original_absent_model_hash(target, provider):
    endpoint, target_state = target
    item = agent(endpoint + '/v1beta/models/fixture-model:generateContent')
    item['provider'] = provider
    item.pop('model')
    original = deepcopy(item)
    tester = PromptInjectionTester()
    payloads = tester.injection_payloads[CATEGORY]
    definition = {'semantics': 'nondisclosure-inconclusive-v2', 'payloads': payloads[:5]}
    expected = '1:' + hashlib.sha256(json.dumps([definition, provider, None], sort_keys=True).encode()).hexdigest()
    with scan_transport(ScanBudget(allow_loopback=True)), collect_checks() as checks, collect_evidence(item) as state:
        findings = await tester._test_injection_category(item, CATEGORY, payloads)
    assert item == original and 'model' not in item
    assert target_state['calls'] == len(state.receipts) == len(findings) == 5
    assert all(receipt['probe_version'] == expected for receipt in state.receipts)
    assert checks[0]['probe_version'] == expected
    assert risk_assessment_eligible(asset_for(item, state, checks, findings))


@pytest.mark.asyncio
async def test_rejected_responses_do_not_count_as_evaluated_or_change_sample_indices(target):
    endpoint, target_state = target
    target_state['mode'] = 'late'
    item, tester = agent(endpoint), PromptInjectionTester()
    with scan_transport(ScanBudget(allow_loopback=True)), collect_checks() as checks, collect_evidence(item) as state:
        findings = await tester._test_injection_category(item, CATEGORY, tester.injection_payloads[CATEGORY])
    assert [receipt['sample_index'] for receipt in state.receipts] == [2, 3, 4]
    assert [receipt['request_ordinal'] for receipt in state.receipts] == [3, 4, 5]
    assert [receipt['responses_evaluated'] for receipt in state.receipts] == [1, 2, 3]
    assert checks[0]['requests_attempted'] == 5 and checks[0]['responses_evaluated'] == 3
    assert checks[0]['status'] == 'failed' and risk_assessment_eligible(asset_for(item, state, checks, findings))


@pytest.mark.asyncio
async def test_budget_rejections_do_not_invent_reserved_attempts(target):
    endpoint, target_state = target
    item, tester, budget = agent(endpoint), PromptInjectionTester(), ScanBudget(allow_loopback=True, max_requests=1)
    with scan_transport(budget), collect_checks() as checks, collect_evidence(item) as state:
        findings = await tester._test_injection_category(item, CATEGORY, tester.injection_payloads[CATEGORY])
    assert budget.requests == target_state['calls'] == len(state.receipts) == 1
    assert budget.rejections == 4
    assert checks[0]['requests_attempted'] == checks[0]['responses_evaluated'] == 1
    assert checks[0]['status'] == 'failed' and risk_assessment_eligible(asset_for(item, state, checks, findings))


@pytest.mark.asyncio
async def test_parallel_collectors_and_following_legacy_call_do_not_share_evidence(target):
    endpoint, target_state = target

    async def run(identity):
        item, tester = dict(agent(endpoint), id=identity), PromptInjectionTester()
        with scan_transport(ScanBudget(allow_loopback=True)), collect_checks() as checks, collect_evidence(item) as state:
            findings = await tester._test_injection_category(item, CATEGORY, tester.injection_payloads[CATEGORY])
        return asset_for(item, state, checks, findings)

    left, right = await asyncio.gather(run('left'), run('right'))
    assert left['check_evidence_run_id'] != right['check_evidence_run_id']
    assert current_trace() is None
    for result in (left, right):
        assert len(result['check_evidence']) == 5
        assert {receipt['agent_id'] for receipt in result['check_evidence']} == {result['id']}
        assert result['checks'][0]['requests_attempted'] == result['checks'][0]['responses_evaluated'] == 5
        assert risk_assessment_eligible(result)
    tester, item = PromptInjectionTester(), agent(endpoint)
    with scan_transport(ScanBudget(allow_loopback=True)), collect_checks():
        legacy = await tester._test_injection_category(item, CATEGORY, tester.injection_payloads[CATEGORY])
    assert all('check_evidence_id' not in finding for finding in legacy)
    assert target_state['calls'] == 15


@pytest.mark.asyncio
@pytest.mark.parametrize('at_pacing', [1, 5])
@pytest.mark.parametrize('observer_enabled', [False, True])
async def test_cancellation_preserves_actual_observations_without_completion(target, monkeypatch, at_pacing, observer_enabled):
    endpoint, target_state = target
    item, tester = agent(endpoint), PromptInjectionTester()
    calls = 0

    async def pacing(_):
        nonlocal calls
        calls += 1
        if calls == at_pacing:
            raise asyncio.CancelledError()

    monkeypatch.setattr('asyncio.sleep', pacing)
    with scan_transport(ScanBudget(allow_loopback=True)), collect_checks() as checks, \
            collect_evidence(item, AsyncMock() if observer_enabled else None) as state:
        with pytest.raises(asyncio.CancelledError):
            await tester._test_injection_category(item, CATEGORY, tester.injection_payloads[CATEGORY])
    assert len(state.receipts) == target_state['calls'] == at_pacing
    assert checks[0]['status'] == 'failed' and checks[0]['outcome'] == 'confirmed'
    assert checks[0]['reason'] == CHECK_INTERRUPTED_REASON
    assert checks[0]['requests_attempted'] == checks[0]['responses_evaluated'] == at_pacing
    assert len(confirmed_findings(asset_for(item, state, checks))) == at_pacing


@pytest.mark.asyncio
async def test_later_stalled_request_keeps_first_receipt_counters(target):
    endpoint, target_state = target
    target_state['mode'] = 'stall'
    item, tester, saved = agent(endpoint), PromptInjectionTester(), []

    async def sink(receipt, finding):
        saved.append((receipt, finding))

    observed = {}

    async def produce():
        with scan_transport(ScanBudget(allow_loopback=True)), collect_checks() as checks, \
                collect_evidence(item, sink) as state:
            observed.update(checks=checks, state=state)
            await tester._test_injection_category(item, CATEGORY, tester.injection_payloads[CATEGORY])

    task = asyncio.create_task(produce())
    try:
        await asyncio.wait_for(target_state['blocked'].wait(), 5)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
    finally:
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)
    checks, state = observed['checks'], observed['state']
    receipt = state.receipts[0]
    assert len(saved) == len(state.findings) == 1
    assert receipt['requests_attempted'] == receipt['responses_evaluated'] == 1
    assert checks[0]['requests_attempted'] == 2 and checks[0]['responses_evaluated'] == 1
    unfinished = asset_for(item, state, [])
    assert len(unfinished_evidence_checks(unfinished)) == 1 and risk_assessment_eligible(unfinished)
    assert len(confirmed_findings(asset_for(item, state, checks))) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize('failure', [OSError, asyncio.TimeoutError])
async def test_response_cleanup_failure_does_not_invent_attempt(target, monkeypatch, failure):
    endpoint, target_state = target
    item, tester = agent(endpoint), PromptInjectionTester()
    original = SafeSession.__aexit__

    async def broken_exit(self, *args):
        await original(self, *args)
        raise failure('private cleanup details')

    monkeypatch.setattr(SafeSession, '__aexit__', broken_exit)
    with scan_transport(ScanBudget(allow_loopback=True)), collect_checks() as checks, collect_evidence(item) as state:
        findings = await tester._test_injection_category(item, CATEGORY, tester.injection_payloads[CATEGORY])
    assert len(findings) == len(state.receipts) == target_state['calls'] == 5
    assert checks[0]['requests_attempted'] == checks[0]['responses_evaluated'] == 5
    assert checks[0]['status'] == 'failed' and checks[0]['outcome'] == 'confirmed'
    assert risk_assessment_eligible(asset_for(item, state, checks, findings))


@pytest.mark.asyncio
async def test_sink_failure_stops_after_first_actual_response(target):
    endpoint, target_state = target
    item, tester = agent(endpoint), PromptInjectionTester()

    async def broken_sink(*_):
        raise RuntimeError(CANARY)

    with scan_transport(ScanBudget(allow_loopback=True)), collect_checks() as checks, \
            observe_evidence(broken_sink), collect_evidence(item) as state:
        with pytest.raises(CheckpointError, match='Scan checkpoint could not be preserved') as caught:
            await tester._test_injection_category(item, CATEGORY, tester.injection_payloads[CATEGORY])
    assert CANARY not in str(caught.value)
    assert len(state.receipts) == target_state['calls'] == 1
    assert checks[0]['requests_attempted'] == checks[0]['responses_evaluated'] == 1
    assert checks[0]['status'] == 'failed' and checks[0]['outcome'] == 'confirmed'


@pytest.mark.asyncio
@pytest.mark.parametrize('cause', [CheckpointError, asyncio.CancelledError])
async def test_session_cleanup_cannot_replace_fatal_sink_outcome(target, monkeypatch, cause):
    endpoint, target_state = target
    item, tester, sink_calls = agent(endpoint), PromptInjectionTester(), []
    original = SafeSession.__aexit__

    async def broken_exit(self, *args):
        await original(self, *args)
        raise RuntimeError('private cleanup detail')

    async def sink(receipt, finding):
        sink_calls.append(receipt)
        raise cause()

    monkeypatch.setattr(SafeSession, '__aexit__', broken_exit)
    with scan_transport(ScanBudget(allow_loopback=True)), collect_checks() as checks, collect_evidence(item, sink) as state:
        with pytest.raises(cause):
            await tester._test_injection_category(item, CATEGORY, tester.injection_payloads[CATEGORY])
    assert target_state['calls'] == len(state.receipts) == len(sink_calls) == 1
    assert checks[0]['requests_attempted'] == checks[0]['responses_evaluated'] == 1
    assert checks[0]['status'] == 'failed' and checks[0]['outcome'] == 'confirmed'


@pytest.mark.asyncio
async def test_body_read_cancellation_survives_session_cleanup_error(target, monkeypatch):
    endpoint, target_state = target
    item, tester = agent(endpoint), PromptInjectionTester()
    original_text, original_exit = BoundedResponse.text, SafeSession.__aexit__

    async def interrupted(self, *args, **kwargs):
        await original_text(self, *args, **kwargs)
        raise asyncio.CancelledError()

    async def broken_exit(self, *args):
        await original_exit(self, *args)
        raise RuntimeError('private cleanup detail')

    monkeypatch.setattr(BoundedResponse, 'text', interrupted)
    monkeypatch.setattr(SafeSession, '__aexit__', broken_exit)
    with scan_transport(ScanBudget(allow_loopback=True)), collect_checks() as checks, collect_evidence(item) as state:
        with pytest.raises(asyncio.CancelledError):
            await tester._test_injection_category(item, CATEGORY, tester.injection_payloads[CATEGORY])
    assert target_state['calls'] == checks[0]['requests_attempted'] == 1
    assert state.receipts == [] and checks[0]['responses_evaluated'] == 0
    assert checks[0]['status'] == 'failed' and checks[0]['outcome'] == 'inconclusive'


@pytest.mark.asyncio
@pytest.mark.parametrize('mode', ['quiet', 'denied', 'reflection'])
async def test_nonconfirmations_never_mint_receipts(target, mode):
    endpoint, target_state = target
    target_state['mode'] = mode
    item, tester = agent(endpoint), PromptInjectionTester()
    with scan_transport(ScanBudget(allow_loopback=True)), collect_checks() as checks, collect_evidence(item) as state:
        findings = await tester._test_injection_category(item, CATEGORY, tester.injection_payloads[CATEGORY])
    assert state.receipts == state.findings == []
    assert not risk_assessment_eligible(asset_for(item, state, checks, findings))
    assert checks[0]['outcome'] != 'passed'


@pytest.mark.asyncio
async def test_mutated_response_cache_cannot_manufacture_actual_canary_match(target, monkeypatch):
    endpoint, target_state = target
    target_state['mode'] = 'quiet'
    original = BoundedResponse.text

    async def rewritten(self, *args, **kwargs):
        await original(self, *args, **kwargs)
        self.body = json.dumps({'response': CANARY}).encode()
        return self.body.decode()

    monkeypatch.setattr(BoundedResponse, 'text', rewritten)
    item, tester = agent(endpoint), PromptInjectionTester()
    with scan_transport(ScanBudget(allow_loopback=True)), collect_checks() as checks, collect_evidence(item) as state:
        findings = await tester._test_injection_category(item, CATEGORY, tester.injection_payloads[CATEGORY])
    assert len(findings) == 5 and state.receipts == []
    assert not risk_assessment_eligible(asset_for(item, state, checks, findings))


@pytest.mark.asyncio
async def test_unbound_mock_responses_cannot_mint_or_complete_checks(target, monkeypatch):
    endpoint, target_state = target
    original = BoundedResponse.__init__

    def unbound(self, response, budget, evidence_token=None, request_evidence=None):
        original(self, response, budget, request_evidence=request_evidence)

    monkeypatch.setattr(BoundedResponse, '__init__', unbound)
    item, tester = agent(endpoint), PromptInjectionTester()
    with scan_transport(ScanBudget(allow_loopback=True)), collect_checks() as checks, collect_evidence(item) as state:
        findings = await tester._test_injection_category(item, CATEGORY, tester.injection_payloads[CATEGORY])
    assert len(findings) == target_state['calls'] == checks[0]['requests_attempted'] == 5
    assert state.receipts == [] and checks[0]['responses_evaluated'] == 0
    assert checks[0]['status'] == 'failed' and checks[0]['outcome'] == 'inconclusive'
    assert not risk_assessment_eligible(asset_for(item, state, checks, findings))


@pytest.mark.asyncio
async def test_sink_requests_and_evaluations_are_not_counted_as_probe_work(target):
    endpoint, target_state = target
    item, tester = agent(endpoint), PromptInjectionTester()

    async def sink(receipt, finding):
        async with SafeSession() as session:
            async with session.request('POST', endpoint + '/api/chat', json={'messages': [{'content': 'sink'}]}) as response:
                await response.text()
                record_prompt_response(response, True)
                await publish_prompt_evidence(response, finding, agent=item, category=CATEGORY,
                                              payload=tester.injection_payloads[CATEGORY][receipt['sample_index']])

    budget = ScanBudget(allow_loopback=True)
    with scan_transport(budget), collect_checks() as checks, collect_evidence(item, sink) as state:
        findings = await tester._test_injection_category(item, CATEGORY, tester.injection_payloads[CATEGORY])
    assert target_state['calls'] == budget.requests == 10
    assert len(state.receipts) == len(findings) == checks[0]['requests_attempted'] == checks[0]['responses_evaluated'] == 5
    assert checks[0]['status'] == 'completed'


@pytest.mark.asyncio
@pytest.mark.parametrize('new_contract', [False, True])
async def test_custom_catalog_does_not_gain_receipts_or_downgrade_new_contract(target, new_contract):
    endpoint, _ = target
    item, tester = agent(endpoint), PromptInjectionTester()
    payloads = ['Custom prompt outside the fixed catalog']
    if new_contract:
        with scan_transport(ScanBudget(allow_loopback=True)), collect_checks() as checks, collect_evidence(item) as state:
            findings = await tester._test_injection_category(item, CATEGORY, payloads)
        result = asset_for(item, state, checks, findings)
        assert state.receipts == []
        assert validate_check_evidence(result, strict=False) is result
        assert not risk_assessment_eligible(result)
    else:
        with scan_transport(ScanBudget(allow_loopback=True)), collect_checks() as checks:
            findings = await tester._test_injection_category(item, CATEGORY, payloads)
        result = dict(item, status='completed', check_schema_version='1.0', checks=checks, vulnerabilities=findings)
        assert risk_assessment_eligible(result)
    assert len(findings) == 1 and checks[0]['outcome'] == 'confirmed'


@pytest.mark.asyncio
async def test_request_token_is_live_task_bound_evaluated_once_and_not_rebindable(target):
    endpoint, _ = target
    trace = RequestTrace(asyncio.current_task(), ('rule', 'probe', 'version', None))
    budget = ScanBudget(allow_loopback=True)
    with scan_transport(budget), trace_requests(trace):
        async with SafeSession() as session:
            async with session.request('POST', endpoint + '/api/chat', json={'messages': [{'content': 'fixture'}]}) as response:
                await response.text()
                assert evaluate_response(response, True)
                assert not evaluate_response(response, True)
                assert trace.evaluated == trace.requests == 1
                token = response_token(response, evaluated=True)
                with pytest.raises(ValueError, match='already bound'):
                    BoundedResponse(SimpleNamespace(status=200), budget, token)

                async def child():
                    assert response_token(response, evaluated=True) is None
                    assert not evaluate_response(response, True)

                await asyncio.create_task(child())
            assert response_token(response, evaluated=True) is None
            assert not evaluate_response(response, True)


@pytest.mark.parametrize('catalog', [baseline_payloads(), candidate_payloads()])
def test_all_frozen_probe_hashes_are_recognized_without_changing_catalogs(catalog):
    for category, payloads in catalog.items():
        rule = 'prompt_injection.' + category
        definition = {'semantics': 'nondisclosure-inconclusive-v2', 'payloads': payloads[:5]}
        version = '1:' + hashlib.sha256(json.dumps([definition, 'ollama', 'fixture-model'], sort_keys=True).encode()).hexdigest()
        assert prompt_probe_payloads(rule, rule + '.sample', version, provider='ollama', model='fixture-model') == tuple(payloads[:5])


@pytest.mark.parametrize('field,value', [
    ('id', None), ('run_id', str(uuid.uuid4())), ('agent_id', 'other'),
    ('rule_id', 'prompt_injection.other'), ('probe_id', 'other'), ('probe_version', '1:unknown'),
    ('evidence_context_id', '[CANARY_REDACTED]'), ('finding_id', str(uuid.uuid4())),
    ('sample_index', True), ('sample_index', -1), ('sample_index', 5),
    ('sequence', True), ('sequence', 2), ('request_ordinal', 2), ('requests_attempted', 2),
    ('responses_evaluated', 0), ('responses_evaluated', True), ('source', 'heuristic'), ('source_version', '1.0'),
])
def test_receipt_mutations_fail_closed(field, value):
    asset = valid_asset()
    asset['check_evidence'][0][field] = value
    with pytest.raises(ValueError):
        validate_check_evidence(asset)
    assert not risk_assessment_eligible(asset) and confirmed_findings(asset) == []


@pytest.mark.parametrize('field,value', [
    ('severity', 'low'), ('severity', 'critical'), ('status_code', True), ('status_code', 403),
    ('payload', 'custom prompt'), ('evidence_context_id', 'other'), ('check_evidence_id', None),
    ('category', 'other'), ('agent_id', 'other'), ('evidence_status', 'heuristic'),
])
def test_finding_mutations_cannot_change_receipt_meaning(field, value):
    asset = valid_asset()
    asset['vulnerabilities'][0][field] = value
    assert not risk_assessment_eligible(asset) and confirmed_findings(asset) == []


@pytest.mark.parametrize('terminal', ['unexecuted', 'passed', 'inconclusive', 'counters', 'wrong-context'])
def test_terminal_records_cannot_contradict_observed_coverage(terminal):
    asset = valid_asset()
    receipt = asset['check_evidence'][0]
    check = {key: receipt[key] for key in ('rule_id', 'probe_id', 'probe_version', 'evidence_context_id')}
    check.update(status='failed', outcome='confirmed', requests_attempted=1, responses_evaluated=1)
    if terminal == 'unexecuted':
        check.update(probe_version='1:unexecuted', status='skipped', outcome='not_evaluated', requests_attempted=0, responses_evaluated=0)
    elif terminal in {'passed', 'inconclusive'}:
        check.update(status='completed', outcome=terminal)
    elif terminal == 'counters':
        check.update(requests_attempted=1, responses_evaluated=2)
    else:
        check['evidence_context_id'] = 'different'
    asset['checks'] = [check]
    with pytest.raises(ValueError):
        validate_check_evidence(asset, strict=False)


def test_public_redaction_preserves_archive_but_not_current_eligibility():
    asset = valid_asset()
    asset['model'] = '[redacted]'
    assert validate_check_evidence(asset, strict=False) is asset
    assert not risk_assessment_eligible(asset) and not evidence_findings(asset)


@pytest.mark.parametrize('version', [None, '2.0', False])
def test_explicit_unknown_contract_never_downgrades_to_legacy(version):
    asset = valid_asset()
    asset['check_evidence_schema_version'] = version
    with pytest.raises(ValueError):
        validate_check_evidence(asset, strict=False)
    assert not risk_assessment_eligible(asset)


def test_orphan_reference_is_not_legacy_and_absent_empty_run_differs_from_null():
    asset = valid_asset()
    for key in ('check_evidence_schema_version', 'check_evidence_run_id', 'check_evidence'):
        asset.pop(key)
    assert not risk_assessment_eligible(asset)
    with pytest.raises(ValueError):
        validate_check_evidence(asset, strict=False)
    empty = dict(agent(), check_evidence_schema_version='1.0', check_evidence=[])
    assert validate_check_evidence(empty) is empty
    empty['check_evidence_run_id'] = None
    with pytest.raises(ValueError):
        validate_check_evidence(empty, strict=False)


@pytest.mark.parametrize('mutation', ['drop-ledger', 'change-run', 'change-checks', 'change-findings',
                                    'change-status', 'duplicate-result', 'drop-result', 'change-provider'])
def test_checkpoint_duplicate_views_must_preserve_identical_evidence(mutation):
    report = valid_report()
    assert validate_checkpoint_report(report) is report
    security = report['security_results'][0]
    if mutation == 'drop-ledger':
        security['check_evidence'] = []
        security['vulnerabilities'] = []
    elif mutation == 'change-run':
        security['check_evidence_run_id'] = str(uuid.uuid4())
        security['check_evidence'][0]['run_id'] = security['check_evidence_run_id']
    elif mutation == 'change-checks':
        security['checks'] = [{'rule_id': 'other'}]
    elif mutation == 'change-findings':
        security['vulnerabilities'][0]['description'] = 'Changed occurrence'
    elif mutation == 'change-status':
        security['status'] = 'completed'
    elif mutation == 'duplicate-result':
        report['security_results'].append(deepcopy(security))
    elif mutation == 'drop-result':
        report['security_results'] = []
    else:
        security['provider'] = 'other'
    with pytest.raises(CheckpointError):
        validate_checkpoint_report(report)
    assert validate_scan_result(report, validate_evidence=False) is report


@pytest.mark.parametrize('key', ['rule_id', 'probe_id', 'probe_version'])
@pytest.mark.parametrize('value', [[], {}, True, 1, None, ''])
def test_malformed_receipt_identifiers_fail_statically(key, value):
    report = valid_report()
    for asset in [report['agents'][0], report['security_results'][0]]:
        asset['check_evidence'][0][key] = value
    with pytest.raises(CheckpointError, match='Scan checkpoint could not be preserved'):
        validate_checkpoint_report(report)


@pytest.mark.parametrize('key', ['check_evidence_schema_version', 'check_evidence_run_id', 'check_evidence'])
def test_legacy_checkpoint_cannot_smuggle_progress_fields(key):
    report = valid_report()
    report['checkpoint'] = {'version': '1.0', 'sequence': 1, 'coverage': 'finalized_checks_only'}
    report.pop('check_evidence_schema_version')
    for asset in [report['agents'][0], report['security_results'][0]]:
        for name in ('check_evidence_schema_version', 'check_evidence_run_id', 'check_evidence'):
            asset.pop(name)
        asset['vulnerabilities'] = []
    report['agents'][0][key] = None
    with pytest.raises(CheckpointError):
        validate_checkpoint_report(report)


@pytest.mark.parametrize('outcome', ['passed', 'confirmed'])
def test_new_contract_cannot_claim_prompt_pass_or_confirmation_without_receipt(outcome):
    asset = valid_asset()
    receipt = asset['check_evidence'][0]
    check = {key: receipt[key] for key in ('rule_id', 'probe_id', 'probe_version', 'evidence_context_id')}
    check.update(status='completed', outcome=outcome, requests_attempted=5, responses_evaluated=5)
    asset.update(checks=[check], check_evidence=[], vulnerabilities=[])
    assert validate_check_evidence(asset, strict=False) is asset
    with pytest.raises(ValueError):
        validate_check_evidence(asset)
    assert not risk_assessment_eligible(asset)


def test_redacted_empty_inventory_status_does_not_require_nonexistent_result():
    report = valid_report()
    asset = report['agents'][0]
    asset.pop('check_evidence_run_id')
    asset.update(check_evidence=[], vulnerabilities=[], checks=[], security_status='not_[redacted]ed')
    report['security_results'] = []
    assert validate_checkpoint_report(report) is report
