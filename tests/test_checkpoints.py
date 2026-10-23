"""Finalized-check durability contracts use synthetic in-process interactions."""

import asyncio
from copy import deepcopy
import json
import socket
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from src.core import contracts, pipeline
from src.core.contracts import CheckpointError, checked, record_interaction, validate_checkpoint_report
from src.risk.risk_assessor import RiskAssessment
from src.security.security_engine import SecurityTestEngine
from tests.controlled_access import target as controlled_target, transport as controlled_transport
from tests.test_prompt_progress_pipeline import producer


CANARY = 'synthetic-checkpoint-canary-84625'


def asset(identifier='fixture'):
    return {'id': identifier, 'name': 'fixture', 'type': 'assistant', 'provider': 'ollama',
            'model': 'fixture-model', 'endpoint': 'http://192.0.2.1:11434',
            'discovery_method': 'fixture', 'metadata': {}, 'system_prompt_canary': CANARY}


@pytest.fixture(autouse=True)
def isolated(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError('Checkpoint tests must not access a network')
    monkeypatch.setattr(socket.socket, 'connect', forbidden)
    monkeypatch.setattr(socket, 'getaddrinfo', forbidden)
    monkeypatch.setattr('asyncio.sleep', AsyncMock())


def engine(monkeypatch, *, disclose=True):
    result, state = producer(monkeypatch, leak_at=lambda ordinal: disclose and (ordinal - 1) % 5 == 0,
                             output=CANARY)
    result.fixture_state = state
    result.prompt_tester.injection_payloads = {
        'system_prompt_extraction': result.prompt_tester.injection_payloads['system_prompt_extraction']}
    return result


async def run(security, sink, *, risk=None, agents=None, validator=None):
    return await pipeline.run_pipeline(None, security, risk or RiskAssessment(), None, 'security_only',
                                       agents=agents or [asset()], agent_validator=validator,
                                       checkpoint_callback=sink)


def capture(saved):
    async def sink(report):
        validate_checkpoint_report(report)
        saved.append(deepcopy(report))
    return sink


@pytest.mark.asyncio
@pytest.mark.parametrize('termination', ['failure', 'timeout', 'cancellation'])
async def test_finalized_confirmation_survives_later_stage_termination(monkeypatch, termination):
    security, saved = engine(monkeypatch), []
    entered = asyncio.Event()

    async def later(agent):
        entered.set()
        if termination == 'failure':
            raise RuntimeError('private-stage-detail')
        await asyncio.Event().wait()

    security.access_tester.test_agent = later
    if termination == 'failure':
        final = await run(security, capture(saved))
        assert final['status'] == 'partial'
        assert final['summary']['overall_risk_score'] == 70
    else:
        task = asyncio.create_task(run(security, capture(saved)))
        await asyncio.wait_for(entered.wait(), 1)
        if termination == 'timeout':
            with pytest.raises((TimeoutError, asyncio.TimeoutError)):
                await asyncio.wait_for(task, 0.01)
        else:
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
    last = saved[-1]
    assert last['status'] == 'partial'
    assert last['summary']['overall_risk_score'] == 70
    assert last['summary']['vulnerabilities_found'] == 1
    assert last['agents'][0]['risk_coverage_status'] == 'partial'
    assert last['agents'][0]['checks'][0]['status'] == 'completed'
    assert last['agents'][0]['checks'][0]['outcome'] == 'confirmed'
    assert all(item not in json.dumps(saved) for item in (CANARY, 'private-stage-detail'))
    assert pipeline.to_sarif(last)['runs'][0]['properties']['checkpoint'] == last['checkpoint']
    security.privacy_tester.test_agent.assert_not_called()


@pytest.mark.asyncio
async def test_callback_failure_stops_following_categories_and_assets(monkeypatch):
    security, saved = engine(monkeypatch), []
    security.prompt_tester.injection_payloads['instruction_bypass'] = SecurityTestEngine().prompt_tester.injection_payloads[
        'instruction_bypass']
    calls = 0
    original = security.prompt_tester._test_single_payload

    async def counted(*args):
        nonlocal calls
        calls += 1
        return await original(*args)

    security.prompt_tester._test_single_payload = counted

    async def sink(report):
        if report['summary']['vulnerabilities_found']:
            raise RuntimeError(CANARY)
        saved.append(deepcopy(report))

    with pytest.raises(CheckpointError, match='^Scan checkpoint could not be preserved$'):
        await run(security, sink, agents=[asset(), asset('next')])
    assert calls == 1
    assert len(saved) == 2
    security.access_tester.test_agent.assert_not_called()


@pytest.mark.asyncio
@pytest.mark.parametrize('failure', ['exception', 'stall'])
async def test_new_evidence_saved_before_shared_scorer_can_fail(monkeypatch, failure):
    security, saved = engine(monkeypatch), []
    entered = asyncio.Event()

    async def assess(values):
        entered.set()
        if failure == 'exception':
            raise RuntimeError(CANARY)
        await asyncio.Event().wait()

    task = asyncio.create_task(run(security, capture(saved), risk=SimpleNamespace(assess_risks=assess)))
    await asyncio.wait_for(entered.wait(), 1)
    if failure == 'exception':
        with pytest.raises(CheckpointError):
            await task
    else:
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
    assert saved[-1]['summary']['vulnerabilities_found'] == 1
    assert saved[-1]['summary']['overall_risk_score'] is None
    assert saved[-1]['summary']['checks_unfinished'] == 1
    assert len(saved[-1]['agents'][0]['check_evidence']) == 1
    security.access_tester.test_agent.assert_not_called()


@pytest.mark.asyncio
async def test_quiet_check_preserves_successful_score_without_rescoring(monkeypatch):
    security, saved = engine(monkeypatch), []
    security.prompt_tester.injection_payloads['instruction_bypass'] = SecurityTestEngine().prompt_tester.injection_payloads[
        'instruction_bypass']
    security.fixture_state.leak_at = (1,)
    risk = RiskAssessment()
    risk.assess_risks = AsyncMock(wraps=risk.assess_risks)
    final = await run(security, capture(saved), risk=risk)
    risk.assess_risks.assert_awaited_once()
    scored = next(index for index, report in enumerate(saved) if report['summary']['overall_risk_score'] == 70)
    assert all(report['summary']['overall_risk_score'] == 70 for report in saved[scored:])
    assert final['summary']['overall_risk_score'] == 70


@pytest.mark.asyncio
async def test_new_confirmation_durable_but_not_given_stale_score_when_rescoring_stalls(monkeypatch):
    security, saved = engine(monkeypatch), []
    security.prompt_tester.injection_payloads['instruction_bypass'] = SecurityTestEngine().prompt_tester.injection_payloads[
        'instruction_bypass']
    risk = RiskAssessment()
    original = risk.assess_risks
    calls = 0
    stalled = asyncio.Event()

    async def assess(values):
        nonlocal calls
        calls += 1
        if calls == 1:
            return await original(values)
        stalled.set()
        await asyncio.Event().wait()

    risk.assess_risks = assess
    task = asyncio.create_task(run(security, capture(saved), risk=risk))
    await asyncio.wait_for(stalled.wait(), 1)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert any(report['summary']['overall_risk_score'] == 70 for report in saved)
    assert saved[-1]['summary']['vulnerabilities_found'] == 2
    assert saved[-1]['summary']['overall_risk_score'] is None
    assert sum(check['outcome'] == 'confirmed' for check in saved[-1]['agents'][0]['checks']) == 1
    assert saved[-1]['summary']['checks_unfinished'] == 1
    security.access_tester.test_agent.assert_not_called()


@pytest.mark.asyncio
async def test_mutating_sink_cannot_rewrite_ledger_or_final_result(monkeypatch):
    saved = []

    async def sink(report):
        saved.append(deepcopy(report))
        report['agents'].clear()
        report['security_results'].clear()
        report['checkpoint']['sequence'] = -1

    final = await run(engine(monkeypatch), sink, agents=[asset(), asset('second')])
    assert [item['id'] for item in final['agents']] == ['fixture', 'second']
    assert all([item['id'] for item in report['agents']] == ['fixture', 'second'] for report in saved)
    assert [report['checkpoint']['sequence'] for report in saved] == list(range(1, len(saved) + 1))
    assert final['checkpoint'] == saved[-1]['checkpoint']
    assert final['summary']['vulnerabilities_found'] == 2


@pytest.mark.asyncio
async def test_concurrent_scans_isolate_observers_and_share_no_accumulator(monkeypatch):
    security = engine(monkeypatch)
    first, second = [], []
    entered = asyncio.Event()
    count = 0

    def sink(saved):
        async def accept(report):
            nonlocal count
            saved.append(deepcopy(report))
            if report['checkpoint']['sequence'] == 1:
                count += 1
                if count == 2:
                    entered.set()
                await asyncio.wait_for(entered.wait(), 1)
        return accept

    finals = await asyncio.gather(run(security, sink(first), agents=[asset('one')]),
                                  run(security, sink(second), agents=[asset('two')]))
    for saved, final, identifier in zip((first, second), finals, ('one', 'two')):
        assert all(report['agents'][0]['id'] == identifier for report in saved + [final])
        assert final['summary']['vulnerabilities_found'] == 1
        assert final['summary']['overall_risk_score'] == 70


@pytest.mark.asyncio
async def test_duplicate_observer_notification_does_not_repeat_scoring_or_writes(monkeypatch):
    security, saved = engine(monkeypatch), []
    original = pipeline._CheckpointState.accept

    async def repeated(self, index, check, findings):
        await original(self, index, check, findings)
        await original(self, index, check, findings)

    monkeypatch.setattr(pipeline._CheckpointState, 'accept', repeated)
    risk = RiskAssessment()
    risk.assess_risks = AsyncMock(wraps=risk.assess_risks)
    final = await run(security, capture(saved), risk=risk)
    risk.assess_risks.assert_awaited_once()
    assert len(saved) == 6
    assert final['summary']['vulnerabilities_found'] == 1


@pytest.mark.asyncio
async def test_identical_finding_occurrences_survive_checkpoint_and_final_replay(monkeypatch):
    class LegacyOccurrences:
        @checked('fixture.finalized_disclosure', ['legacy duplicate occurrences'])
        async def check(self, agent):
            record_interaction(True)
            record_interaction(True)
            finding = {'evidence_status': 'confirmed', 'severity': 'high',
                       'vulnerability_type': 'fixture.finalized_disclosure'}
            return [deepcopy(finding), deepcopy(finding)]

        async def test_agents(self, agents):
            with contracts.collect_checks() as checks:
                findings = await self.check(agents[0])
            return [{'agent_id': agents[0]['id'], 'status': 'completed',
                     'check_schema_version': '1.0', 'checks': checks, 'vulnerabilities': findings}]

    saved = []
    final = await run(LegacyOccurrences(), capture(saved))
    assert final['summary']['vulnerabilities_found'] == 2
    assert len(final['agents'][0]['vulnerabilities']) == 2
    assert final['agents'][0]['vulnerabilities'][0] == final['agents'][0]['vulnerabilities'][1]
    assert all(report['summary']['vulnerabilities_found'] == 2 for report in saved[2:])
    assert len(pipeline.to_sarif(final)['runs'][0]['results']) == 2


@pytest.mark.asyncio
async def test_validator_injected_secrets_are_collected_before_first_checkpoint(monkeypatch):
    saved = []
    target = asset()
    del target['system_prompt_canary']

    def validator(values):
        values[0]['system_prompt_canary'] = CANARY
        values[0]['name'] = CANARY
        return values

    final = await run(engine(monkeypatch), capture(saved), agents=[target], validator=validator)
    assert final['summary']['vulnerabilities_found'] == 1
    assert CANARY not in json.dumps(saved + [final])
    assert saved[0]['agents'][0]['name'] == '[redacted]'


@pytest.mark.asyncio
@pytest.mark.parametrize('bound', ['count', 'report_bytes', 'total_bytes'])
async def test_checkpoint_resource_limits_fail_before_later_probes(monkeypatch, bound):
    security, saved = engine(monkeypatch), []
    if bound == 'count':
        monkeypatch.setattr(pipeline, 'MAX_CHECKPOINTS', 1)
    elif bound == 'report_bytes':
        monkeypatch.setattr(pipeline, 'MAX_CHECKPOINT_BYTES', 1)
    else:
        monkeypatch.setattr(pipeline, 'MAX_CHECKPOINT_TOTAL_BYTES', 1)
    with pytest.raises(CheckpointError):
        await run(security, capture(saved))
    assert len(saved) == (1 if bound == 'count' else 0)
    security.access_tester.test_agent.assert_not_called()
    assert not saved or saved[-1]['summary']['vulnerabilities_found'] == 0


@pytest.mark.asyncio
async def test_cumulative_limit_counts_previously_acknowledged_report_bytes(monkeypatch):
    security, saved = engine(monkeypatch), []
    security.test_agents = AsyncMock()

    async def sink(report):
        saved.append(deepcopy(report))
        size = len(json.dumps(report, ensure_ascii=True, allow_nan=False, separators=(',', ':')).encode('utf-8'))
        monkeypatch.setattr(pipeline, 'MAX_CHECKPOINT_TOTAL_BYTES', size + 1)

    with pytest.raises(CheckpointError):
        await run(security, sink)
    assert len(saved) == 1
    security.test_agents.assert_not_called()


@pytest.mark.asyncio
async def test_duplicate_asset_ids_rejected_before_checkpoint_or_security(monkeypatch):
    security = engine(monkeypatch)
    security.test_agents = AsyncMock()
    sink = AsyncMock()
    with pytest.raises(CheckpointError):
        await run(security, sink, agents=[asset(), asset()])
    security.test_agents.assert_not_called()
    sink.assert_not_called()


@pytest.mark.asyncio
async def test_redaction_colliding_distinct_asset_ids_rejected_before_persistence(monkeypatch):
    first, second = asset(CANARY), asset('another-protected-fixture-marker')
    second['system_prompt_canary'] = second['id']
    security = engine(monkeypatch)
    security.test_agents = AsyncMock()
    sink = AsyncMock()
    with pytest.raises(CheckpointError):
        await run(security, sink, agents=[first, second])
    security.test_agents.assert_not_called()
    sink.assert_not_called()


@pytest.mark.asyncio
async def test_predicted_probe_secrets_are_pinned_before_first_checkpoint(monkeypatch):
    target = controlled_target(id='admin-service', system_prompt_canary=CANARY)
    security, saved = engine(monkeypatch), []
    security.prompt_tester.test_agent = AsyncMock(return_value=[])
    security.access_tester.test_agent = security.access_tester._test_weak_credentials
    with controlled_transport(disclose=True):
        final = await run(security, capture(saved), agents=[target])
    assert all(report['agents'][0]['id'] == '[redacted]-service' for report in saved + [final])
    assert final['summary']['overall_risk_score'] == 90
    assert 'admin' not in json.dumps(saved + [final])


@pytest.mark.asyncio
async def test_unexpected_secret_redaction_drift_fails_closed(monkeypatch):
    security, saved = engine(monkeypatch), []

    class UnexpectedSecret:
        @checked('weak_credentials', 'checkpoint-secret-drift')
        async def test_agent(self, agent):
            record_interaction(True)
            return [{'id': 'late-finding', 'evidence_status': 'confirmed', 'severity': 'critical',
                     'vulnerability_type': 'weak_credentials', 'password': 'late-private-value'}]

    security.access_tester.test_agent = UnexpectedSecret().test_agent
    with pytest.raises(CheckpointError):
        await run(security, capture(saved), agents=[asset('late-private-value-service')])
    assert saved[-1]['summary']['overall_risk_score'] == 70
    assert saved[-1]['summary']['vulnerabilities_found'] == 1
    security.privacy_tester.test_agent.assert_not_called()


@pytest.mark.asyncio
async def test_unfinished_pass_alone_does_not_become_assessed_zero(monkeypatch):
    class Passing:
        @checked('authentication_bypass', 'checkpoint-pass-fixture', oracle=lambda agent: True)
        async def check(self, agent):
            record_interaction(True, decisive=True)
            return []

        async def test_agents(self, agents):
            findings = await self.check(agents[0])
            await asyncio.Event().wait()
            return findings

    saved = []
    with pytest.raises((TimeoutError, asyncio.TimeoutError)):
        await asyncio.wait_for(run(Passing(), capture(saved)), 0.01)
    assert saved[-1]['agents'][0]['checks'][0]['outcome'] == 'passed'
    assert saved[-1]['agents'][0]['security_status'] == 'partial'
    assert saved[-1]['summary']['overall_risk_score'] is None


@pytest.mark.asyncio
async def test_no_confirmation_timeout_stays_unknown(monkeypatch):
    security, saved = engine(monkeypatch, disclose=False), []

    async def stall(agent):
        await asyncio.Event().wait()

    security.access_tester.test_agent = stall
    with pytest.raises((TimeoutError, asyncio.TimeoutError)):
        await asyncio.wait_for(run(security, capture(saved)), 0.01)
    assert saved[-1]['summary']['vulnerabilities_found'] == 0
    assert saved[-1]['summary']['overall_risk_score'] is None
    assert saved[-1]['agents'][0]['checks'][0]['outcome'] == 'inconclusive'


@pytest.mark.asyncio
async def test_checkpoint_validator_rejects_invalid_envelope_and_nonfinite_values(monkeypatch):
    saved = []
    await run(engine(monkeypatch), capture(saved))
    valid = saved[-1]
    for key, value in [('sequence', True), ('sequence', 0), ('sequence', contracts.MAX_CHECKPOINTS + 1),
                       ('version', 'future'), ('coverage', 'complete')]:
        invalid = deepcopy(valid)
        invalid['checkpoint'][key] = value
        with pytest.raises(CheckpointError):
            validate_checkpoint_report(invalid)
    invalid = deepcopy(valid)
    invalid['summary']['overall_risk_score'] = float('nan')
    with pytest.raises(CheckpointError):
        validate_checkpoint_report(invalid)
