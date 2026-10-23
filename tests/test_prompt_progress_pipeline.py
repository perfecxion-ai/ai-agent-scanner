"""Prompt observations survive interruption without completed-check claims."""

import asyncio
from copy import deepcopy
import json
import socket
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from src.core.contracts import (
    CheckpointError, confirmed_findings, risk_assessment_eligible, validate_checkpoint_report,
)
from src.core.pipeline import _CheckpointState, run_pipeline, to_sarif
from src.core.risk_projection import project_report_risk
from src.risk.risk_assessor import RiskAssessment
from src.security.security_engine import SecurityTestEngine
from tests.controlled_access import result as controlled_result
from tests.request_provenance_fixture import declared_wire_request


CANARY = 'prompt-receipt-fixture-canary-473829'


def asset(identifier='fixture', **changes):
    return {'id': identifier, 'name': 'Fixture', 'type': 'assistant', 'provider': 'ollama',
            'model': 'fixture-model', 'endpoint': 'http://192.0.2.1:11434',
            'discovery_method': 'fixture', 'metadata': {}, 'system_prompt_canary': CANARY,
            'evidence_context_id': 'receipt-fixture-context-v1', **changes}


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError('Receipt tests must not access a network')
    monkeypatch.setattr(socket.socket, 'connect', forbidden)
    monkeypatch.setattr(socket, 'getaddrinfo', forbidden)


def producer(monkeypatch, *, pause=None, leak_at=(1,), output=CANARY):
    """Use the complete frozen producer and request builder, not invented evidence."""
    state = SimpleNamespace(requests=0, entered=asyncio.Event(), release=asyncio.Event(), leak_at=leak_at)

    async def wait_at(stage, ordinal):
        if pause == stage and ordinal == (2 if stage == 'request' else 1):
            state.entered.set()
            await state.release.wait()

    class Response:
        status = 200

        def __init__(self, ordinal, request_info):
            self.ordinal = ordinal
            self.content = self
            self.request_info = request_info

        async def iter_chunked(self, size):
            disclose = state.leak_at(self.ordinal) if callable(state.leak_at) else self.ordinal in state.leak_at
            yield json.dumps({'response': output if disclose else 'Refused'}).encode()

    class Request:
        def __init__(self, session, method, url, kwargs):
            self.session, self.method, self.url, self.kwargs = session, method, url, kwargs

        async def __aenter__(self):
            state.requests += 1
            self.ordinal = state.requests
            await wait_at('request', self.ordinal)
            body, info = declared_wire_request(self.method, self.url,
                                              headers=self.kwargs.get('headers'), json_body=self.kwargs.get('json'))
            for trace in self.session.traces:
                context = trace.trace_config_ctx(trace_request_ctx=self.kwargs['trace_request_ctx'])
                for callback in trace.on_request_headers_sent:
                    await callback(self.session, context, SimpleNamespace(
                        method=self.method, url=info.url, headers=info.headers))
                for callback in trace.on_request_chunk_sent:
                    await callback(self.session, context, SimpleNamespace(
                        method=self.method, url=info.url, chunk=body))
            return Response(self.ordinal, info)

        async def __aexit__(self, *args):
            await wait_at('response_cleanup', self.ordinal)
            return False

    class Session:
        def __init__(self, *, connector, **kwargs):
            self.ordinal = 0
            self.connector = connector
            self.traces = kwargs.get('trace_configs', [])

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            try:
                await wait_at('session_cleanup', self.ordinal)
                return False
            finally:
                await self.connector.close()

        def request(self, method, url, **kwargs):
            self.ordinal = state.requests + 1
            return Request(self, method, url, kwargs)

    async def pacing(_):
        await wait_at('pacing', state.requests)

    # The real bounded transport reserves requests, captures response bytes and
    # owns private receipt tokens; only its socket-facing client is substituted.
    monkeypatch.setattr('src.core.transport.aiohttp.ClientSession', Session)
    monkeypatch.setattr('src.security.prompt_injection_tests.asyncio.sleep', pacing)
    security = SecurityTestEngine()
    security.access_tester.test_agent = AsyncMock(return_value=[])
    security.privacy_tester.test_agent = AsyncMock(return_value=[])
    return security, state


async def run(security, saved=None, *, target=None, risk=None, sink=None):
    async def capture(report):
        validate_checkpoint_report(report)
        saved.append(deepcopy(report))
    callback = sink if sink is not None else capture if saved is not None else None
    return await run_pipeline(None, security, risk or RiskAssessment(), None, 'security_only',
                              agents=[target or asset()], checkpoint_callback=callback)


def assert_private(report):
    assert CANARY not in json.dumps(report)
    assert 'private-receipt-error' not in json.dumps(report)


@pytest.mark.asyncio
@pytest.mark.parametrize('stage', ['pacing', 'request', 'response_cleanup', 'session_cleanup'])
async def test_first_confirmation_is_durable_before_next_await(monkeypatch, stage):
    security, state = producer(monkeypatch, pause=stage)
    saved = []
    task = asyncio.create_task(run(security, saved))
    await asyncio.wait_for(state.entered.wait(), 2)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    report = saved[-1]
    assert report['checkpoint']['version'] == '2.0'
    assert report['checkpoint']['coverage'] == 'confirmed_observations_and_finalized_checks'
    assert report['status'] == 'partial'
    assert report['summary']['overall_risk_score'] == 70
    assert report['summary']['vulnerabilities_found'] == 1
    assert report['summary']['checks_unfinished'] == 1
    item = report['agents'][0]
    assert item['risk_coverage_status'] == 'partial'
    assert len(item['check_evidence']) == 1
    assert item['check_evidence'][0]['requests_attempted'] == 1
    assert item['check_evidence'][0]['responses_evaluated'] == 1
    assert not any(check['rule_id'] == 'prompt_injection.system_prompt_extraction' for check in item['checks'])
    assert len(confirmed_findings({**item, 'status': item['security_status'], 'check_schema_version': '1.0'})) == 1
    assert project_report_risk(report)[1]['fixture']['risk_score'] == 70
    assert_private(saved)
    sarif = to_sarif(report)['runs'][0]
    assert sarif['invocations'][0]['executionSuccessful'] is False
    assert len(sarif['results']) == 1
    assert sarif['properties']['check_evidence'][0]['check_evidence'] == item['check_evidence']
    security.access_tester.test_agent.assert_not_called()


@pytest.mark.asyncio
@pytest.mark.parametrize('checkpointed', [False, True])
async def test_completed_producer_keeps_exact_occurrences_and_receipts(monkeypatch, checkpointed):
    security, state = producer(monkeypatch, leak_at=(1, 2, 5))
    saved = [] if checkpointed else None
    report = await run(security, saved)
    item = report['agents'][0]
    assert state.requests == 35
    assert report['status'] == 'completed'
    assert report['summary']['overall_risk_score'] == 70
    assert report['summary']['checks_unfinished'] == 0
    assert len(item['vulnerabilities']) == len(item['check_evidence']) == 3
    assert len({finding['id'] for finding in item['vulnerabilities']}) == 3
    assert {receipt['finding_id'] for receipt in item['check_evidence']} == {
        finding['id'] for finding in item['vulnerabilities']}
    assert item['checks'][0]['outcome'] == 'confirmed'
    assert item['checks'][0]['requests_attempted'] == item['checks'][0]['responses_evaluated'] == 5
    assert report['security_results'][0]['check_evidence'] == item['check_evidence']
    assert project_report_risk(report)[1]['fixture']['risk_score'] == 70
    if saved:
        previous = next(value for value in saved if value['agents'][0]['check_evidence'])
        receipt = previous['agents'][0]['check_evidence'][0]
        finding = previous['agents'][0]['vulnerabilities'][0]
        assert receipt in item['check_evidence'] and finding in item['vulnerabilities']
    assert_private(report)


@pytest.mark.asyncio
async def test_receipt_sink_failure_stops_the_producer(monkeypatch):
    security, state = producer(monkeypatch)
    saved = []

    async def sink(report):
        if report['agents'][0]['check_evidence']:
            raise RuntimeError('private-receipt-error ' + CANARY)
        saved.append(deepcopy(report))

    with pytest.raises(CheckpointError, match='^Scan checkpoint could not be preserved$'):
        await run(security, sink=sink)
    assert state.requests == 1
    assert saved[-1]['summary']['vulnerabilities_found'] == 0
    assert_private(saved)
    security.access_tester.test_agent.assert_not_called()


@pytest.mark.asyncio
async def test_receipt_is_committed_before_scorer_stalls(monkeypatch):
    security, state = producer(monkeypatch)
    saved, entered = [], asyncio.Event()

    async def stalled(_):
        entered.set()
        await asyncio.Event().wait()

    task = asyncio.create_task(run(security, saved, risk=SimpleNamespace(assess_risks=stalled)))
    await asyncio.wait_for(entered.wait(), 2)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert state.requests == 1
    assert saved[-1]['summary']['vulnerabilities_found'] == 1
    assert saved[-1]['summary']['overall_risk_score'] is None
    assert saved[-1]['summary']['checks_unfinished'] == 1
    assert_private(saved)


@pytest.mark.asyncio
@pytest.mark.parametrize('checkpointed', [False, True])
async def test_later_tester_failure_preserves_observation(monkeypatch, checkpointed):
    security, _ = producer(monkeypatch)
    original = security.prompt_tester._test_injection_category
    calls = 0

    async def fail_after_category(*args):
        nonlocal calls
        calls += 1
        if calls == 2:
            raise RuntimeError('private-receipt-error ' + CANARY)
        return await original(*args)

    monkeypatch.setattr(security.prompt_tester, '_test_injection_category', fail_after_category)
    report = await run(security, [] if checkpointed else None)
    assert report['status'] == 'partial'
    assert report['summary']['overall_risk_score'] == 70
    assert len(report['agents'][0]['vulnerabilities']) == 1
    assert len(report['agents'][0]['check_evidence']) == 1
    assert_private(report)


@pytest.mark.asyncio
@pytest.mark.parametrize('checkpointed', [False, True])
@pytest.mark.parametrize('field', ['model', 'evidence_context_id'])
async def test_redacted_context_keeps_evidence_without_public_risk(monkeypatch, checkpointed, field):
    security, _ = producer(monkeypatch)
    target = asset(api_key='fixture-model') if field == 'model' else asset(evidence_context_id=CANARY)
    report = await run(security, [] if checkpointed else None, target=target)
    item = report['agents'][0]
    assert len(item['vulnerabilities']) == len(item['check_evidence']) == 1
    assert item['risk_score'] is None
    assert report['summary']['overall_risk_score'] is None
    assert project_report_risk(report)[1]['fixture']['risk_score'] is None
    assert len(to_sarif(report)['runs'][0]['results']) == 1
    if field == 'model':
        assert 'fixture-model' not in json.dumps(report)
    assert_private(report)


@pytest.mark.asyncio
@pytest.mark.parametrize('mutation', [
    'root_version', 'asset_version', 'missing_root', 'missing_receipt', 'missing_asset_version', 'orphan_reference',
    'removed_asset_contract',
])
async def test_unsupported_receipt_versions_cannot_fall_back_to_final_checks(monkeypatch, mutation):
    security, _ = producer(monkeypatch)
    report = await run(security)
    item = report['agents'][0]
    if mutation == 'root_version':
        report['check_evidence_schema_version'] = 'future'
    elif mutation == 'asset_version':
        item['check_evidence_schema_version'] = 'future'
    elif mutation == 'missing_root':
        report.pop('check_evidence_schema_version')
    elif mutation == 'missing_asset_version':
        item.pop('check_evidence_schema_version')
    elif mutation == 'orphan_reference':
        for key in ('check_evidence_schema_version', 'check_evidence_run_id', 'check_evidence'):
            item.pop(key)
    elif mutation == 'removed_asset_contract':
        for value in (item, report['security_results'][0]):
            for key in ('check_evidence_schema_version', 'check_evidence_run_id', 'check_evidence'):
                value.pop(key)
            for finding in value['vulnerabilities']:
                finding.pop('check_evidence_id')
    else:
        item['check_evidence'] = []
    summary, projected = project_report_risk(report)
    assert summary['overall_risk_score'] is None
    assert projected['fixture']['risk_score'] is None
    assert item['checks'][0]['outcome'] == 'confirmed'


@pytest.mark.asyncio
async def test_unknown_receipt_version_does_not_hide_other_supported_assets(monkeypatch):
    security, _ = producer(monkeypatch)
    report = await run(security)
    report['check_evidence_schema_version'] = 'future'
    other = await controlled_result(disclose=True)
    report['agents'].append({
        **other, 'id': 'other', 'security_status': other['status'],
        'risk_score': 70, 'risk_level': 'high', 'risk_coverage_status': 'sampled',
        'risk_scoring_policy': 'severity-floor-v2',
    })
    summary, projected = project_report_risk(report)
    assert projected['fixture']['risk_score'] is None
    assert projected['other']['risk_score'] == summary['overall_risk_score'] == 70


@pytest.mark.asyncio
@pytest.mark.parametrize('secret', ['check_evidence_run_id', 'CHECK_EVIDENCE_SCHEMA_VERSION'])
async def test_new_public_field_collision_stops_before_io_or_checkpoint(monkeypatch, secret):
    security, state = producer(monkeypatch)
    saved = []
    with pytest.raises(ValueError, match='^Protected evidence conflicts with public evidence fields$'):
        await run(security, saved, target=asset(system_prompt_canary=secret))
    assert state.requests == 0
    assert saved == []


@pytest.mark.asyncio
async def test_quiet_samples_never_claim_pass_or_zero(monkeypatch):
    security, state = producer(monkeypatch, leak_at=())
    report = await run(security, [])
    assert state.requests == 35
    assert report['summary']['overall_risk_score'] is None
    assert report['summary']['checks_unfinished'] == 0
    assert report['agents'][0]['check_evidence'] == []
    assert all(check['outcome'] != 'passed' for check in report['agents'][0]['checks'])


@pytest.mark.asyncio
@pytest.mark.parametrize('provided', [
    {'check_evidence_run_id': '2d177495-1845-4523-a37b-3c48113a642f'},
    {'check_evidence': []}, {'check_evidence_schema_version': '1.0'},
])
async def test_adapter_missing_receipt_contract_is_not_repaired(provided):
    evidence = await controlled_result()
    evidence.update(provided)
    adapter = SimpleNamespace(test_agents=AsyncMock(return_value=[evidence]))
    target = asset(provider=evidence['provider'], model=evidence['model'])
    with pytest.raises(ValueError, match='^Invalid prompt observation evidence$'):
        await run(adapter, target=target)


@pytest.mark.asyncio
@pytest.mark.parametrize('missing', ['check_evidence_schema_version', 'check_evidence'])
async def test_adapter_valid_receipt_cannot_supply_missing_required_metadata(monkeypatch, missing):
    security, _ = producer(monkeypatch)
    evidence = deepcopy((await run(security))['security_results'][0])
    evidence.pop(missing)
    adapter = SimpleNamespace(test_agents=AsyncMock(return_value=[evidence]))
    with pytest.raises(ValueError, match='^Invalid prompt observation evidence$'):
        await run(adapter)


@pytest.mark.asyncio
@pytest.mark.parametrize('mutation', ['probe_version', 'run_id', 'schema_version'])
async def test_adapter_raw_receipts_require_supported_provenance(monkeypatch, mutation):
    security, _ = producer(monkeypatch)
    evidence = deepcopy((await run(security))['security_results'][0])
    if mutation == 'probe_version':
        for value in (evidence['check_evidence'][0], evidence['vulnerabilities'][0], evidence['checks'][0]):
            value['probe_version'] = '1:' + '0' * 64
    elif mutation == 'run_id':
        evidence['check_evidence_run_id'] = '[redacted]'
        evidence['check_evidence'][0]['run_id'] = '[redacted]'
    else:
        evidence['check_evidence_schema_version'] = 'future'
    adapter = SimpleNamespace(test_agents=AsyncMock(return_value=[evidence]))
    with pytest.raises(ValueError, match='^Invalid prompt observation evidence$'):
        await run(adapter)


@pytest.mark.asyncio
@pytest.mark.parametrize('checkpointed', [False, True])
async def test_real_engine_custom_catalog_is_visible_but_unassessed(monkeypatch, checkpointed):
    security, state = producer(monkeypatch)
    security.prompt_tester.injection_payloads = {'system_prompt_extraction': ['Custom fixture prompt']}
    report = await run(security, [] if checkpointed else None)
    assert state.requests == 1
    assert len(report['agents'][0]['vulnerabilities']) == 1
    assert report['agents'][0]['check_evidence'] == []
    assert report['summary']['overall_risk_score'] is None
    assert project_report_risk(report)[1]['fixture']['risk_score'] is None


@pytest.mark.asyncio
@pytest.mark.parametrize('new_first', [False, True])
async def test_mixed_adapter_modes_fail_before_scoring(monkeypatch, new_first):
    security, _ = producer(monkeypatch)
    modern = deepcopy((await run(security))['security_results'][0])
    legacy = {key: deepcopy(value) for key, value in modern.items()
              if key not in {'check_evidence_schema_version', 'check_evidence_run_id', 'check_evidence'}}
    for finding in legacy['vulnerabilities']:
        finding.pop('check_evidence_id')
    legacy['agent_id'] = 'legacy'
    for finding in legacy['vulnerabilities']:
        finding['agent_id'] = 'legacy'
    results = [modern, legacy] if new_first else [legacy, modern]
    adapter = SimpleNamespace(test_agents=AsyncMock(side_effect=[[item] for item in results]))
    risk = SimpleNamespace(assess_risks=AsyncMock())
    with pytest.raises(ValueError, match='^Mixed evidence contracts are not supported by this adapter$'):
        await run_pipeline(None, adapter, risk, None, 'security_only',
                           agents=[asset(item['agent_id']) for item in results])
    risk.assess_risks.assert_not_called()


@pytest.mark.asyncio
async def test_cross_category_receipts_preserve_acknowledged_order(monkeypatch):
    security, _ = producer(monkeypatch, leak_at=(1, 6))
    saved = []
    report = await run(security, saved)
    assert len(report['agents'][0]['check_evidence']) == 2
    changed = deepcopy(report)
    changed['agents'][0]['check_evidence'].reverse()
    changed['security_results'][0]['check_evidence'].reverse()
    # Each category is valid in isolation; persistence still requires the exact
    # acknowledged scan-local prefix, not merely the same set of receipts.
    validate_checkpoint_report(changed, final=True)
    state = _CheckpointState([asset()], RiskAssessment(), 'security_only', None, set(), AsyncMock(),
                             evidence_enabled=True)
    state.last = deepcopy(report)
    with pytest.raises(CheckpointError):
        state._preserves_previous(changed)


@pytest.mark.asyncio
@pytest.mark.parametrize('outcome', ['confirmed', 'passed'])
async def test_unsupported_prompt_positive_cannot_hide_beside_current_access_pass(monkeypatch, outcome):
    security, _ = producer(monkeypatch)
    report = await run(security, target=asset(provider='openai-compatible'))
    access = await controlled_result()
    assert risk_assessment_eligible(access)
    item, result = report['agents'][0], report['security_results'][0]
    check = deepcopy(item['checks'][0])
    check['outcome'] = outcome
    for value in (item, result):
        value['checks'] = deepcopy(access['checks']) + [deepcopy(check)]
        value['check_evidence'] = []
        value['vulnerabilities'] = []
    item.update(risk_score=0, risk_level='minimal')
    report['summary']['overall_risk_score'] = 0
    assert not risk_assessment_eligible(result)
    assert project_report_risk(report)[1]['fixture']['risk_score'] is None
