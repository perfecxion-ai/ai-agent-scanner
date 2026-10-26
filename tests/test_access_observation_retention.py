"""Real GET producers publish supported access facts before later interruption."""

import asyncio
import base64
from contextlib import asynccontextmanager, nullcontext
from copy import deepcopy
import json
import os
from unittest.mock import AsyncMock

from aiohttp.client_reqrep import ClientRequest
import pytest

from src.core.access_probe_policy import PROTECTED_ACCESS_PATHS, protected_access_probe
from src.core.contracts import (
    CheckpointError, collect_checks, collect_evidence, confirmed_findings, current_trace,
    ensure_evidence_active, risk_assessment_eligible, validate_check_evidence,
)
from src.core.transport import SafeSession, ScanBudget, scan_transport
from src.core.pipeline import run_pipeline
from src.risk.risk_assessor import RiskAssessment
from src.security import access_control_tests as producer
from src.security.access_control_tests import AccessControlTester
from src.security.security_engine import SecurityTestEngine
from tests.access_progress_fixture import METHODS, REFERENCE, access_progress_target


COUNTS = {'authentication_bypass': (20, 20, 18), 'weak_credentials': (7, 7, 5),
          'weak_api_key': (32, 7, 5), 'authorization_bypass': (24, 24, 8)}


@pytest.fixture(autouse=True)
def isolated_registry(monkeypatch):
    monkeypatch.setenv('SCAN_EVIDENCE_PROFILES_FILE', '/tmp/aiscan-operator-registry-must-not-exist.json')


async def execute(agent, rule, *, schema='3.0', sink=None, holder=None):
    budget = ScanBudget(allow_loopback=True, allowed_networks=('127.0.0.1/32',), max_requests=100,
                        request_timeout_seconds=20)
    context = collect_evidence(agent, sink, schema_version=schema) if schema is not None else nullcontext(None)
    with scan_transport(budget), collect_checks() as checks, context as evidence:
        if holder is not None:
            holder['evidence'], holder['checks'], holder['budget'] = evidence, checks, budget
        findings = await getattr(AccessControlTester(), METHODS[rule])(agent)
    result = {key: agent[key] for key in ('id', 'provider', 'model', 'endpoint', 'evidence_context_id')}
    result.update(agent_id=agent['id'], check_schema_version='1.0', checks=checks,
                  status='completed' if checks[0]['status'] == 'completed' else 'partial', vulnerabilities=findings)
    if evidence is not None:
        result.update(check_evidence_schema_version=schema, check_evidence_run_id=evidence.run_id,
                      check_evidence=deepcopy(evidence.receipts))
    return result, budget, evidence


def assert_private_absent(value, state):
    encoded = json.dumps(value, sort_keys=True).casefold()
    for private in (state.marker, state.issued, state.generated, REFERENCE):
        forms = (private, base64.b64encode(private.encode()).decode())
        assert all(form.casefold() not in encoded for form in forms)


@pytest.mark.asyncio
@pytest.mark.parametrize('rule', METHODS)
@pytest.mark.parametrize('mode', ['protected', 'vulnerable'])
async def test_modern_actual_http_counts_controls_and_receipts(rule, mode):
    async with access_progress_target(mode) as (agent, state):
        acknowledged = []
        async def sink(receipt, finding):
            assert current_trace() is None
            acknowledged.append((deepcopy(receipt), deepcopy(finding), len(state.calls)))
        result, budget, evidence = await execute(agent, rule, sink=sink)
        protected, vulnerable, positives = COUNTS[rule]
        expected_requests = protected if mode == 'protected' else vulnerable
        assert len(state.calls) == budget.requests == expected_requests
        assert result['checks'][0]['requests_attempted'] == result['checks'][0]['responses_evaluated'] == expected_requests
        assert result['checks'][0]['status'] == 'completed'
        assert result['checks'][0]['outcome'] == ('passed' if mode == 'protected' else 'confirmed')
        validate_check_evidence(result)
        assert risk_assessment_eligible(result)
        assert len(evidence.receipts) == len(result['vulnerabilities']) == len(acknowledged) == (0 if mode == 'protected' else positives)
        assert len(confirmed_findings(result)) == len(evidence.receipts)
        delays = {'authentication_bypass': [0.5] * 18, 'weak_credentials': [1] * 5,
                  'weak_api_key': [0.3] * 30 if mode == 'protected' else [],
                  'authorization_bypass': [0.5] * 8}[rule]
        assert [call.args[0] for call in state.pacing.await_args_list] == delays
        for receipt, finding, calls in acknowledged:
            assert receipt['source'] == 'controlled_access_response' and receipt['source_version'] == '1.0'
            assert receipt['finding_id'] == finding['id'] and finding['check_evidence_id'] == receipt['id']
            assert receipt['responses_evaluated'] == receipt['requests_attempted'] == receipt['request_ordinal'] == calls
            assert receipt['control_proof']['status_codes'] == [200, 403]
            assert finding['protected_control_version'] == 3
        if acknowledged:
            assert acknowledged[0][0]['request_ordinal'] == 3
            assert acknowledged[0][0]['control_proof']['request_ordinals'] == [1, 2]
        if rule == 'authorization_bypass' and mode == 'vulnerable':
            assert [value[0]['protected_path_index'] for value in acknowledged] == list(range(8))
            assert [value[0]['control_proof']['request_ordinals'] for value in acknowledged] == [
                [3 * index + 1, 3 * index + 2] for index in range(8)]
            assert [value['path'] for value in state.calls] == [path for path in PROTECTED_ACCESS_PATHS for _ in range(3)]
        assert_private_absent([result, acknowledged], state)


@pytest.mark.asyncio
@pytest.mark.parametrize('rule', METHODS)
@pytest.mark.parametrize('schema', [None, '1.0', '2.0'])
async def test_explicit_legacy_context_keeps_v3_without_access_receipts(rule, schema):
    async with access_progress_target('vulnerable') as (agent, state):
        result, budget, evidence = await execute(agent, rule, schema=schema)
        assert len(state.calls) == budget.requests == COUNTS[rule][1]
        assert len(result['vulnerabilities']) == COUNTS[rule][2]
        assert evidence is None or evidence.receipts == []
        assert all('check_evidence_id' not in finding for finding in result['vulnerabilities'])
        assert protected_access_probe(result['checks'][0], provider=agent['provider'], model=agent['model']) is not None
        assert risk_assessment_eligible(result)


@pytest.mark.asyncio
@pytest.mark.parametrize('rule', METHODS)
@pytest.mark.parametrize('provider,model,credential_header', [
    ('anthropic', 'fixture-model', 'x-api-key'), ('gemini', None, 'x-goog-api-key'),
    ('ollama', None, 'Authorization')])
async def test_modern_controls_preserve_provider_headers_and_explicit_native_model_none(rule, provider, model, credential_header):
    async with access_progress_target('vulnerable') as (agent, state):
        agent.update(provider=provider, model=model)
        result, budget, evidence = await execute(agent, rule)
        assert len(state.calls) == budget.requests == COUNTS[rule][1]
        assert len(evidence.receipts) == COUNTS[rule][2]
        expected = ('Bearer ' if credential_header == 'Authorization' else '') + state.issued
        assert state.calls[0]['headers'][credential_header] == expected
        assert all(receipt['access_target']['model'] == model and receipt['access_target']['provider'] == provider
                   for receipt in evidence.receipts)
        assert risk_assessment_eligible(result)


@pytest.mark.asyncio
@pytest.mark.parametrize('rule,issued,requests', [('weak_credentials', 'admin:admin', 7),
                                                ('weak_api_key', 'test-key', 27)])
async def test_modern_intentional_weak_sample_can_equal_the_pinned_issued_credential(rule, issued, requests):
    async with access_progress_target('protected', issued=issued) as (agent, state):
        result, budget, evidence = await execute(agent, rule)
        assert len(state.calls) == budget.requests == requests
        assert len(result['vulnerabilities']) == len(evidence.receipts) == 1
        assert evidence.receipts[0]['sample_index'] == 0
        assert risk_assessment_eligible(result)
        assert_private_absent(result, state)


@pytest.mark.asyncio
async def test_normal_engine_preserves_public_agent_marker_preflight_before_any_controls():
    async with access_progress_target('protected') as (agent, state):
        agent['name'] = state.marker
        engine = SecurityTestEngine()
        engine.prompt_tester.test_agent = AsyncMock(return_value=[])
        engine.privacy_tester.test_agent = AsyncMock(return_value=[])
        for method in ('_test_unauthenticated_inference', '_test_rate_limiting', '_test_session_management'):
            setattr(engine.access_tester, method, AsyncMock(return_value=[]))
        budget = ScanBudget(allow_loopback=True, allowed_networks=('127.0.0.1/32',), max_requests=100)
        with scan_transport(budget):
            result = await run_pipeline(None, engine, RiskAssessment(), None, 'security_only', agents=[agent])
        assert state.calls == [] and budget.requests == 0
        assert result['check_evidence_schema_version'] == '3.0'
        assert result['summary']['overall_risk_score'] is None
        assert result['agents'][0]['name'] == '[redacted]'
        assert result['agents'][0]['vulnerabilities'] == result['agents'][0]['check_evidence'] == []
        assert_private_absent(result, state)


@pytest.mark.asyncio
@pytest.mark.parametrize('rule', METHODS)
@pytest.mark.parametrize('mode,requests', [('unseeded', 1), ('authorized-error', 1),
                                          ('denied-success', 2), ('denied-leak', 2)])
async def test_actual_broken_controls_stop_before_any_positive_observation(rule, mode, requests):
    async with access_progress_target(mode) as (agent, state):
        result, budget, evidence = await execute(agent, rule)
        # Authorization repeats its existing bounded per-path controls after an
        # ordinary failed baseline, without sending any unauthorized probe.
        expected = requests * 8 if rule == 'authorization_bypass' else requests
        assert len(state.calls) == budget.requests == expected
        assert evidence.receipts == evidence.findings == result['vulnerabilities'] == []
        assert result['checks'][0]['status'] == 'failed' and result['checks'][0]['outcome'] == 'inconclusive'
        assert not risk_assessment_eligible(result)


@pytest.mark.asyncio
@pytest.mark.parametrize('rule', METHODS)
@pytest.mark.parametrize('mode', ['probe-error', 'probe-denial-leak', 'probe-header-leak'])
async def test_nonpositive_response_containing_marker_never_confirms_or_passes(rule, mode):
    async with access_progress_target(mode) as (agent, state):
        result, budget, evidence = await execute(agent, rule)
        assert len(state.calls) == budget.requests == COUNTS[rule][0]
        assert evidence.receipts == result['vulnerabilities'] == []
        assert result['checks'][0]['outcome'] == 'inconclusive'
        assert not risk_assessment_eligible(result)


@pytest.mark.asyncio
@pytest.mark.parametrize('rule', METHODS)
async def test_acknowledged_leak_survives_later_actual_503_responses(rule):
    async with access_progress_target('leak-error') as (agent, state):
        acknowledged = []
        async def sink(receipt, finding):
            acknowledged.append((deepcopy(receipt), deepcopy(finding)))
        result, budget, evidence = await execute(agent, rule, sink=sink)
        assert len(state.calls) == budget.requests == (27 if rule == 'weak_api_key' else COUNTS[rule][0])
        assert len(acknowledged) == len(evidence.receipts) == len(result['vulnerabilities']) == 1
        assert evidence.receipts[0] == acknowledged[0][0]
        assert result['vulnerabilities'][0] == acknowledged[0][1]
        assert result['checks'][0]['status'] == 'failed' and result['checks'][0]['outcome'] == 'confirmed'
        assert risk_assessment_eligible(result)


@pytest.mark.asyncio
async def test_fresh_path_controls_reuse_the_original_pinned_key_after_receipt():
    async with access_progress_target('vulnerable') as (agent, state):
        original = state.issued
        async def sink(receipt, finding):
            os.environ[REFERENCE] = 'replacement-environment-key-must-not-be-used'
        result, _, evidence = await execute(agent, 'authorization_bypass', sink=sink)
        assert len(state.calls) == 24 and len(evidence.receipts) == 8
        assert all(state.calls[index]['headers']['Authorization'] == 'Bearer ' + original for index in range(0, 24, 3))
        assert risk_assessment_eligible(result)


@pytest.mark.asyncio
@pytest.mark.parametrize('rule', METHODS)
@pytest.mark.parametrize('kind', ['marker', 'credential'])
async def test_actual_transport_injection_cannot_create_a_receipt(monkeypatch, rule, kind):
    mode = 'reflection' if kind == 'marker' else 'hidden-credential'
    async with access_progress_target(mode) as (agent, state):
        original = ClientRequest.update_auto_headers
        def inject(request, skip):
            original(request, skip)
            request.headers['X-Reflected-Marker' if kind == 'marker' else 'X-Extra-Issued-Key'] = (
                state.marker if kind == 'marker' else state.issued)
        monkeypatch.setattr(ClientRequest, 'update_auto_headers', inject)
        result, _, evidence = await execute(agent, rule)
        assert len(state.calls) == 1
        assert evidence.receipts == result['vulnerabilities'] == []
        assert not risk_assessment_eligible(result)


@pytest.mark.asyncio
@pytest.mark.parametrize('rule', METHODS)
async def test_acknowledged_first_leak_survives_later_actual_stall_and_cancellation(rule):
    async with access_progress_target('leak-stall') as (agent, state):
        holder, acknowledged = {}, []
        async def sink(receipt, finding):
            acknowledged.append((deepcopy(receipt), deepcopy(finding)))
        task = asyncio.create_task(execute(agent, rule, sink=sink, holder=holder))
        try:
            await asyncio.wait_for(state.entered.wait(), 3)
            assert len(state.calls) == 4 and len(acknowledged) == 1
            before = deepcopy(acknowledged)
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
            assert acknowledged == before
            evidence = holder['evidence']
            assert evidence.receipts == [before[0][0]] and evidence.findings == [before[0][1]]
            assert before[0][0]['request_ordinal'] == before[0][0]['requests_attempted'] == before[0][0]['responses_evaluated'] == 3
            assert_private_absent(before, state)
        finally:
            if not task.done():
                task.cancel()
                with pytest.raises(asyncio.CancelledError):
                    await task


@pytest.mark.asyncio
@pytest.mark.parametrize('rule', METHODS)
@pytest.mark.parametrize('cleanup', ['response', 'session'])
async def test_publication_precedes_real_response_and_session_cleanup(monkeypatch, rule, cleanup):
    async with access_progress_target('vulnerable') as (agent, state):
        published = []
        class CleanupSession(SafeSession):
            @asynccontextmanager
            async def request(self, *args, **kwargs):
                async with super().request(*args, **kwargs) as response:
                    ordinal = len(state.calls)
                    yield response
                if cleanup == 'response' and ordinal == 3:
                    assert published
                    raise OSError('Owned response cleanup failure')
            async def __aexit__(self, *args):
                await super().__aexit__(*args)
                if cleanup == 'session' and len(state.calls) == 3:
                    assert published
                    raise OSError('Owned session cleanup failure')
        monkeypatch.setattr(producer, 'SafeSession', CleanupSession)
        async def sink(receipt, finding):
            published.append((deepcopy(receipt), deepcopy(finding)))
        result, _, evidence = await execute(agent, rule, sink=sink)
        assert len(state.calls) == COUNTS[rule][1]
        assert published and published[0][0]['request_ordinal'] == 3
        assert evidence.receipts[0] == published[0][0]
        assert published[0][1] in result['vulnerabilities']
        assert result['checks'][0]['status'] == 'failed' and result['checks'][0]['outcome'] == 'confirmed'
        assert risk_assessment_eligible(result)


@pytest.mark.asyncio
@pytest.mark.parametrize('failure', ['sink', 'cancel'])
@pytest.mark.parametrize('rule', METHODS)
async def test_delivery_failure_is_fatal_despite_both_cleanup_failures(monkeypatch, rule, failure):
    async with access_progress_target('vulnerable') as (agent, state):
        class CleanupSession(SafeSession):
            @asynccontextmanager
            async def request(self, *args, **kwargs):
                async with super().request(*args, **kwargs) as response:
                    try:
                        yield response
                    finally:
                        if len(state.calls) == 3:
                            raise OSError('Owned secondary response cleanup failure')
            async def __aexit__(self, *args):
                await super().__aexit__(*args)
                if len(state.calls) == 3:
                    raise OSError('Owned secondary session cleanup failure')
        monkeypatch.setattr(producer, 'SafeSession', CleanupSession)
        async def sink(receipt, finding):
            if failure == 'cancel':
                raise asyncio.CancelledError()
            raise RuntimeError('Owned checkpoint delivery failure')
        with pytest.raises(asyncio.CancelledError if failure == 'cancel' else CheckpointError):
            await execute(agent, rule, sink=sink)
        assert len(state.calls) == 3


@pytest.mark.asyncio
async def test_typed_active_rejection_never_enters_legacy_scalar_evaluation(monkeypatch):
    async with access_progress_target('vulnerable') as (agent, state):
        original = producer.observe_access_response
        async def observe(response, **kwargs):
            if kwargs['phase'] == 'probe':
                kwargs['sample_index'] = True
            return await original(response, **kwargs)
        monkeypatch.setattr(producer, 'observe_access_response', observe)
        monkeypatch.setattr(producer, 'verify_access_response', lambda *args, **kwargs: pytest.fail('Legacy fallback'))
        result, _, evidence = await execute(agent, 'authentication_bypass')
        assert len(state.calls) == 20
        assert result['vulnerabilities'] == evidence.receipts == []
        assert not risk_assessment_eligible(result)
        ensure_evidence_active()


@pytest.mark.asyncio
async def test_missing_modern_observation_cannot_downgrade_after_controls(monkeypatch):
    async with access_progress_target('vulnerable') as (agent, state):
        original = producer.observe_access_response
        async def observe(response, **kwargs):
            return None if kwargs['phase'] == 'probe' else await original(response, **kwargs)
        monkeypatch.setattr(producer, 'observe_access_response', observe)
        monkeypatch.setattr(producer, 'verify_access_response', lambda *args, **kwargs: pytest.fail('Legacy fallback'))
        with pytest.raises(CheckpointError):
            await execute(agent, 'authentication_bypass')
        assert len(state.calls) == 3
