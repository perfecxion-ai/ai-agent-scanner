"""Independent compatibility and adversarial access observation acceptance."""

import asyncio
from contextlib import asynccontextmanager
from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import json
import multiprocessing
import os
import signal
import stat
from unittest.mock import Mock

import aiohttp
import pytest
from sqlalchemy import create_engine, insert, select

from src.core import contracts
from src.core.contracts import (
    CheckpointError, collect_checks, collect_evidence, confirmed_findings,
    risk_assessment_eligible, validate_checkpoint_report,
)
from src.core.jobs import JobDispatcher, JobStore, snapshot_id
from src.core.pipeline import run_pipeline
from src.core.risk_projection import project_report_risk
from src.core.transport import SafeSession, ScanBudget, scan_transport
from src.risk.risk_assessor import RiskAssessment
from src.security import access_control_tests as producer
from tests.access_progress_independent_fixture import (
    ISSUED, MARKER, METHODS, WORKER_OPERATOR_KEY, WORKER_SIGNING_KEY, access_checkpoint_worker,
    access_progress_target, privacy_values, selected_access_engine,
)
from tests.legacy_access_v3_fixtures import (
    LEGACY_ACCESS_V3_NAMES, LEGACY_ACCESS_V3_REVISION, legacy_access_v3_archive,
    legacy_access_v3_manifest, legacy_access_v3_report,
)
from tests.test_api_auth import api as api, headers


@pytest.mark.parametrize('name', LEGACY_ACCESS_V3_NAMES)
def test_original_finalized_v3_archives_remain_supported_and_byte_exact(name):
    raw, report = legacy_access_v3_archive(name), legacy_access_v3_report(name)
    expected = legacy_access_v3_manifest()['archives'][name]
    assert legacy_access_v3_manifest()['producer_revision'] == LEGACY_ACCESS_V3_REVISION
    assert hashlib.sha256(raw).hexdigest() == expected['sha256']
    original = deepcopy(report)
    assert report['check_evidence_schema_version'] == '2.0' and report['checkpoint']['version'] == '3.0'
    validate_checkpoint_report(report, final=True)
    assert risk_assessment_eligible(report['security_results'][0])
    summary, assets = project_report_risk(report)
    asset = report['agents'][0]
    assert summary['overall_risk_score'] == assets[asset['id']]['risk_score'] == expected['original_score']
    assert assets[asset['id']]['risk_level'] == expected['original_level']
    assert assets[asset['id']]['risk_coverage_status'] == expected['original_coverage']
    assert asset['check_evidence_run_id'] == expected['run_id']
    assert [finding['id'] for finding in asset['vulnerabilities']] == expected['finding_ids']
    assert [receipt['id'] for receipt in asset['check_evidence']] == expected['receipt_ids']
    assert report == original and legacy_access_v3_archive(name) == raw


@pytest.fixture
async def genuine_access_progress():
    with access_progress_target('authentication_bypass', 'complete', tls=False) as (agent, state):
        async def checkpoint(report):
            validate_checkpoint_report(report)
        with scan_transport(ScanBudget(allow_loopback=True, max_requests=80, max_response_bytes=16384)):
            report = await run_pipeline(None, selected_access_engine('authentication_bypass'), RiskAssessment(),
                                        None, 'security_only', agents=[agent], checkpoint_callback=checkpoint)
        assert len(state.calls) == 20 and report['summary']['overall_risk_score'] == 70
        assert len(report['agents'][0]['check_evidence']) == 1
        validate_checkpoint_report(report, final=True)
        yield report


@pytest.mark.asyncio
@pytest.mark.parametrize('mutation', ['proof-allowed-denial', 'proof-reversed', 'bool-ordinal', 'float-evaluated',
                                     'wrong-target', 'wrong-run', 'duplicate-receipt', 'unknown-source-version',
                                     'receipt-removed', 'unlinked-positive'])
async def test_malformed_modern_receipt_cannot_become_a_scalar_fallback(genuine_access_progress, mutation):
    before = genuine_access_progress
    original = deepcopy(before)
    after = deepcopy(before)
    for value in after['agents'] + after['security_results']:
        receipt = value['check_evidence'][0]
        if mutation == 'proof-allowed-denial':
            receipt['control_proof']['status_codes'][1] = 200
        elif mutation == 'proof-reversed':
            receipt['control_proof']['request_ordinals'] = [2, 1]
        elif mutation == 'bool-ordinal':
            receipt['request_ordinal'] = True
        elif mutation == 'float-evaluated':
            receipt['responses_evaluated'] = 3.0
        elif mutation == 'wrong-target':
            receipt['access_target']['endpoint'] += '/other'
            value['vulnerabilities'][0]['access_target'] = deepcopy(receipt['access_target'])
        elif mutation == 'wrong-run':
            receipt['run_id'] = 'b248af4e-b6f3-4371-b196-1ac9387a6542'
        elif mutation == 'duplicate-receipt':
            value['check_evidence'].append(deepcopy(receipt))
        elif mutation == 'unknown-source-version':
            receipt['source_version'] = 'unrecognized'
        elif mutation == 'receipt-removed':
            value['check_evidence'] = []
        else:
            value['vulnerabilities'][0].pop('check_evidence_id')
    assert not risk_assessment_eligible(after['security_results'][0])
    assert confirmed_findings(after['security_results'][0]) == []
    assert project_report_risk(after)[0]['overall_risk_score'] is None
    with pytest.raises((CheckpointError, ValueError)):
        validate_checkpoint_report(after, final=True)
    assert before == original and project_report_risk(before)[0]['overall_risk_score'] == 70


@pytest.mark.asyncio
@pytest.mark.parametrize('declaration', ['absent', 'old-ledger1', 'old-ledger2'])
async def test_modern_hash_cannot_downgrade_when_its_ledger_is_removed(genuine_access_progress, declaration):
    report = deepcopy(genuine_access_progress)
    for value in report['agents'] + report['security_results']:
        value.pop('check_evidence_run_id')
        value.pop('check_evidence')
        if declaration == 'absent':
            value.pop('check_evidence_schema_version')
        else:
            value['check_evidence_schema_version'] = '1.0' if declaration.endswith('1') else '2.0'
        for finding in value['vulnerabilities']:
            finding.pop('check_evidence_id')
    assert confirmed_findings(report['security_results'][0]) == []
    assert not risk_assessment_eligible(report['security_results'][0])
    assert project_report_risk(report)[0]['overall_risk_score'] is None


@pytest.mark.asyncio
@pytest.mark.parametrize('fault', ['wrong-task', 'changed-model', 'wrong-phase', 'wrong-sample', 'reuse', 'closed'])
async def test_live_witness_refuses_wrong_context_or_reused_capability(monkeypatch, fault):
    original = contracts.observe_access_response
    attempts = []
    completed_response = None
    async def intercept(response, **kwargs):
        nonlocal completed_response
        if fault == 'closed' and completed_response is not None and len(attempts) == 1:
            assert completed_response._request_active is False
            attempts.append(True)
            return await original(completed_response, **kwargs)
        if kwargs['phase'] != 'probe' or attempts:
            return await original(response, **kwargs)
        attempts.append(True)
        modified = deepcopy({key: value for key, value in kwargs.items() if key != 'agent'})
        modified['agent'] = deepcopy(kwargs['agent'])
        if fault == 'wrong-task':
            return await asyncio.create_task(original(response, **modified))
        if fault == 'changed-model':
            modified['agent']['model'] = 'different-owned-model'
        elif fault == 'wrong-phase':
            modified['phase'] = 'authorized_control'
        elif fault == 'wrong-sample':
            modified['sample_index'] = 1
        elif fault in {'reuse', 'closed'}:
            first = await original(response, **kwargs)
            assert first.valid and len(first.findings) == 1
            if fault == 'closed':
                completed_response = response
                return first
        return await original(response, **modified)
    monkeypatch.setattr(producer, 'observe_access_response', intercept)
    with access_progress_target('authentication_bypass', 'complete', tls=False) as (agent, state):
        with scan_transport(ScanBudget(allow_loopback=True, max_requests=80, max_response_bytes=16384)):
            report = await run_pipeline(None, selected_access_engine('authentication_bypass'), RiskAssessment(),
                                        None, 'security_only', agents=[agent])
        assert attempts and len(state.calls) >= 3
        asset = report['agents'][0]
        assert len(asset['check_evidence']) == len(asset['vulnerabilities']) == (1 if fault in {'reuse', 'closed'} else 0)
        assert asset['risk_score'] == (70 if fault in {'reuse', 'closed'} else None)
        check = next(check for check in asset['checks'] if check['rule_id'] == 'authentication_bypass')
        assert check['outcome'] != 'passed' and check['status'] != 'completed'


@pytest.mark.asyncio
async def test_later_actual_wire_taint_cannot_remove_an_acknowledged_access_receipt(monkeypatch):
    actual = aiohttp.ClientRequest.update_auto_headers
    requests = 0
    def add_later_marker(request, skip):
        nonlocal requests
        actual(request, skip)
        requests += 1
        if requests == 4:
            request.headers['X-Owned-Later-Taint'] = MARKER
    monkeypatch.setattr(aiohttp.ClientRequest, 'update_auto_headers', add_later_marker)
    acknowledged = []
    async def persist(report):
        if report['agents'][0].get('check_evidence'):
            acknowledged.append(deepcopy(report))
    with access_progress_target('authentication_bypass', 'complete', tls=False) as (agent, state):
        with scan_transport(ScanBudget(allow_loopback=True, max_requests=80, max_response_bytes=16384)):
            report = await run_pipeline(None, selected_access_engine('authentication_bypass'), RiskAssessment(),
                                        None, 'security_only', agents=[agent], checkpoint_callback=persist)
        assert len(state.calls) == 4 and state.calls[3]['headers']['X-Owned-Later-Taint'] == MARKER
        assert acknowledged and report['summary']['overall_risk_score'] == 70
        assert report['agents'][0]['risk_coverage_status'] == 'partial'
        assert report['agents'][0]['check_evidence'] == acknowledged[0]['agents'][0]['check_evidence']
        assert report['agents'][0]['vulnerabilities'] == acknowledged[0]['agents'][0]['vulnerabilities']


@pytest.mark.asyncio
@pytest.mark.parametrize('rule', METHODS)
async def test_receipt_is_delivered_before_response_cleanup_and_survives_cleanup_error(monkeypatch, rule):
    acknowledged = []
    with access_progress_target(rule, 'complete', tls=False) as (agent, state):
        class CleanupFailure(SafeSession):
            @asynccontextmanager
            async def request(self, *args, **kwargs):
                ordinal = None
                try:
                    async with super().request(*args, **kwargs) as response:
                        ordinal = len(state.calls)
                        yield response
                finally:
                    if ordinal == 3:
                        assert acknowledged, 'Evidence was deferred until after response cleanup'
                        raise OSError('Owned secondary cleanup error')
        monkeypatch.setattr(producer, 'SafeSession', CleanupFailure)
        async def persist(report):
            if report['agents'][0].get('check_evidence'):
                acknowledged.append(deepcopy(report))
        with scan_transport(ScanBudget(allow_loopback=True, max_requests=80, max_response_bytes=16384)):
            report = await run_pipeline(None, selected_access_engine(rule), RiskAssessment(), None, 'security_only',
                                        agents=[agent], checkpoint_callback=persist)
        expected = 90 if rule == 'weak_credentials' else 70
        assert acknowledged and report['summary']['overall_risk_score'] == expected
        assert report['agents'][0]['risk_coverage_status'] == 'partial'
        assert report['agents'][0]['check_evidence'] == acknowledged[0]['agents'][0]['check_evidence']
        assert report['agents'][0]['vulnerabilities'] == acknowledged[0]['agents'][0]['vulnerabilities']


@pytest.mark.asyncio
@pytest.mark.parametrize('cancelled', [False, True])
async def test_failed_receipt_sink_stops_probes_and_wins_over_cleanup(monkeypatch, cancelled):
    deliveries = []
    with access_progress_target('authentication_bypass', 'complete', tls=False) as (agent, state):
        class CleanupFailure(SafeSession):
            @asynccontextmanager
            async def request(self, *args, **kwargs):
                ordinal = None
                try:
                    async with super().request(*args, **kwargs) as response:
                        ordinal = len(state.calls)
                        yield response
                finally:
                    if ordinal == 3:
                        raise OSError('Owned cleanup must not hide sink failure')
        monkeypatch.setattr(producer, 'SafeSession', CleanupFailure)
        async def failing_sink(receipt, finding):
            deliveries.append((receipt, finding))
            if cancelled:
                raise asyncio.CancelledError
            raise RuntimeError('Owned private receipt sink failure')
        with scan_transport(ScanBudget(allow_loopback=True, max_requests=80, max_response_bytes=16384)), \
                collect_checks(), collect_evidence(agent, failing_sink):
            with pytest.raises(asyncio.CancelledError if cancelled else CheckpointError):
                await getattr(selected_access_engine('authentication_bypass').access_tester,
                              METHODS['authentication_bypass'])(agent)
        assert len(deliveries) == 1 and len(state.calls) == 3


def _read_recovered_access_api(module, client, engine, report, scan_id, score, level):
    """Read the actual recovered private database without admitting a new scan."""
    module.db.session.remove()
    engines, original = module.db.engines, module.db.engine
    assert original is not engine and original.url.database == ':memory:'
    request_headers = headers(module)
    private = {request_headers['Authorization'], request_headers['Authorization'].removeprefix('Bearer '),
               module.app.config['SECRET_KEY'], module.app.config['OPERATOR_API_KEY']}
    outputs = []

    def read(path):
        module.db.session.remove()
        response = client.get(path, headers=request_headers)
        assert response.status_code == 200
        value = response.get_json()
        outputs.append({'body': value, 'headers': dict(response.headers)})
        return value

    try:
        engines[None] = engine
        result = read('/api/scans/' + scan_id + '/results')['results']
        assert result['pipeline'] == report
        assert result['summary']['overall_risk_score'] == score
        assert result['summary']['risk_assessment_status'] == 'partial'
        assert len(result['agents']) == 1
        snapshot = result['agents'][0]
        assert snapshot['id'] == snapshot_id(scan_id, 0)
        assert snapshot['risk_score'] == score and snapshot['risk_level'] == level
        assert snapshot['vulnerabilities'] == report['agents'][0]['vulnerabilities']
        assert snapshot['risk_coverage_status'] == 'partial'
        assert read('/api/scans/' + scan_id + '/status')['status'] == 'interrupted'
        for suffix in ('', '&limit=1'):
            inventory = read('/api/agents?risk_level=' + level + suffix)
            assert inventory['next_cursor'] is None and inventory['coverage']['search_complete'] is True
            assert len(inventory['agents']) == 1
            assert inventory['agents'][0]['risk_score'] == score
            assert inventory['agents'][0]['risk_level'] == level
            assert inventory['agents'][0]['risk_coverage_status'] == 'partial'
        assert read('/api/scans/' + scan_id + '/report?format=json') == report
        run = read('/api/scans/' + scan_id + '/report?format=sarif')['runs'][0]
        assert run['properties']['summary']['overall_risk_score'] == score
        assert run['properties']['producer_identity'] == report['producer_identity']
        assert run['properties']['check_evidence'][0]['check_evidence'] == report['agents'][0]['check_evidence']
        assert not run['invocations'][0]['executionSuccessful'] and len(run['results']) == 1
        assert run['results'][0]['properties']['vulnerability_id'] == report['agents'][0]['vulnerabilities'][0]['id']
        events = read('/api/scans/' + scan_id + '/audit')['events']
        assert [(event['event'], event['status']) for event in events if event['event'] == 'terminal'] == [
            ('terminal', 'interrupted')]
    finally:
        module.db.session.remove()
        engines[None] = original
    assert module.db.engine is original
    return outputs, private


@pytest.mark.skipif(os.name != 'posix', reason='The supported dispatcher requires POSIX')
@pytest.mark.parametrize('rule,score,level', [('authentication_bypass', 70, 'high'),
                                            ('weak_credentials', 90, 'critical')])
def test_sigkill_after_committed_access_receipt_preserves_exact_evidence_without_replay(
        api, tmp_path, caplog, rule, score, level):
    module, client = api
    owned = tmp_path.resolve() / 'owned-access-recovery'
    owned.mkdir(mode=0o700)
    database, log = owned / 'access.sqlite', owned / 'worker.log'
    descriptor = os.open(database, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    os.close(descriptor)
    engine = create_engine('sqlite:///' + str(database))
    module.initialize_schema(engine, module.db.metadata)
    store = JobStore(engine, module.ScanJob.__table__, module.ScanSession.__table__,
                     module.ScanResult.__table__, module.AuditEvent.__table__)
    scan_id = 'owned-access-recovery-scan'
    with engine.begin() as connection:
        connection.execute(insert(store.scans).values(
            id=scan_id, organization_id='tenant-a', scan_name='Owned library access recovery',
            scan_type='security_only', status='queued', target_scope={}, scan_config={}))
        connection.execute(insert(store.jobs).values(scan_id=scan_id, status='queued'))
    process = receiver = sender = None
    try:
        with access_progress_target(rule, 'kill', tls=False) as (agent, state):
            context = multiprocessing.get_context('spawn')
            receiver, sender = context.Pipe(duplex=False)
            process = context.Process(target=access_checkpoint_worker,
                                      args=(str(database), agent, sender, str(log), rule))
            process.start()
            sender.close()
            sender = None
            assert receiver.poll(15), 'Owned worker did not acknowledge a committed access receipt'
            label, sequence, receipt_id, finding_id = receiver.recv()
            assert label == 'committed' and process.is_alive()
            assert state.blocked.wait(5) and len(state.calls) == 4
            assert state.calls[0]['credential'] == ISSUED
            assert state.calls[1]['credential'].startswith('scanner-invalid-')
            with engine.connect() as connection:
                before = connection.scalar(select(store.results.c.result))
                snapshots = connection.execute(select(module.DiscoveredAgentModel.__table__)).mappings().all()
                assert connection.scalar(select(store.jobs.c.status)) == 'running'
                assert connection.scalar(select(store.scans.c.overall_risk_score)) == score
                owner = connection.scalar(select(store.jobs.c.owner))
                audit_before = connection.execute(select(store.audit)).mappings().all()
            assert before['checkpoint']['sequence'] >= sequence and before['checkpoint']['version'] == '4.0'
            assert before['check_evidence_schema_version'] == '3.0'
            assert before['summary']['overall_risk_score'] == score
            assert before['summary']['checks_unfinished'] == 1
            asset = before['agents'][0]
            assert len(asset['check_evidence']) == len(asset['vulnerabilities']) == 1
            receipt, finding = asset['check_evidence'][0], asset['vulnerabilities'][0]
            assert receipt['id'] == receipt_id and finding['id'] == finding_id
            assert receipt['source'] == 'controlled_access_response' and receipt['rule_id'] == rule
            assert receipt['request_ordinal'] == receipt['requests_attempted'] == receipt['responses_evaluated'] == 3
            assert receipt['control_proof'] == {'request_ordinals': [1, 2], 'status_codes': [200, 403]}
            assert receipt['finding_id'] == finding['id'] and finding['check_evidence_id'] == receipt['id']
            assert snapshots[0]['risk_score'] == score and snapshots[0]['risk_level'] == level
            # A malformed append must fail before it can replace an acknowledged
            # positive with unknown caches, even from the genuine current owner.
            malformed = deepcopy(before)
            malformed['checkpoint']['sequence'] += 1
            for view in malformed['agents'] + malformed['security_results']:
                extra = deepcopy(view['vulnerabilities'][0])
                extra['id'] = '6f2a5c3e-4c9a-40ea-a1e2-b34f15d97e08'
                extra.pop('check_evidence_id')
                view['vulnerabilities'].append(extra)
            with pytest.raises(CheckpointError):
                store.save_checkpoint(scan_id, malformed, module.DiscoveredAgentModel.__table__,
                                      module._snapshot_rows(scan_id, malformed, datetime.now(timezone.utc)), owner=owner)
            with engine.connect() as connection:
                assert connection.scalar(select(store.results.c.result)) == before
                assert connection.execute(select(module.DiscoveredAgentModel.__table__)).mappings().all() == snapshots
                assert connection.execute(select(store.audit)).mappings().all() == audit_before
                assert connection.scalar(select(store.scans.c.overall_risk_score)) == score
            competitor = JobDispatcher(store, Mock(), workers=1)
            with pytest.raises(RuntimeError, match='Another dispatcher'):
                competitor.start()
            process.kill()
            process.join(timeout=5)
            assert process.exitcode == -signal.SIGKILL and not process.is_alive()
            calls_at_kill = len(state.calls)
            replay = Mock(side_effect=AssertionError('Interrupted access probes must not replay'))
            restarted = JobDispatcher(store, replay, workers=1, poll_seconds=0.01)
            try:
                restarted.start()
                with engine.connect() as connection:
                    recovered = connection.scalar(select(store.results.c.result))
                    after = connection.execute(select(module.DiscoveredAgentModel.__table__)).mappings().all()
                    assert connection.scalar(select(store.jobs.c.status)) == 'interrupted'
                    assert connection.scalar(select(store.scans.c.overall_risk_score)) == score
                    terminal = connection.execute(select(store.audit.c.event, store.audit.c.status)).all()
                assert recovered['status'] == 'interrupted'
                for field in ('producer_identity', 'agents', 'security_results', 'risk_assessments', 'summary', 'checkpoint'):
                    assert recovered[field] == before[field]
                assert after == snapshots
                assert [event for event in terminal if event[0] == 'terminal'] == [('terminal', 'interrupted')]
                assert store.recover() == 0 and store.claim('unused-access-restart-worker') is None
                summary, assets = project_report_risk(recovered)
                assert summary['overall_risk_score'] == assets[agent['id']]['risk_score'] == score
                assert assets[agent['id']]['risk_coverage_status'] == 'partial'
                api_outputs, api_private = _read_recovered_access_api(
                    module, client, engine, recovered, scan_id, score, level)
                private = privacy_values(state, extra={WORKER_SIGNING_KEY, WORKER_OPERATOR_KEY, *api_private})
                public = json.dumps(recovered) + json.dumps(api_outputs) + caplog.text
                assert all(value.casefold() not in public.casefold() for value in private)
                assert MARKER not in json.dumps(state.calls)
                for path in (database, database.with_name(database.name + '.dispatcher.lock'), log):
                    assert stat.S_IMODE(path.stat().st_mode) == 0o600
                    raw = path.read_bytes().lower()
                    assert all(value.encode().lower() not in raw for value in private)
                assert stat.S_IMODE(owned.stat().st_mode) == 0o700
                assert not state.errors and len(state.calls) == calls_at_kill
                replay.assert_not_called()
            finally:
                restarted.stop()
            assert len(state.calls) == calls_at_kill
            replay.assert_not_called()
    finally:
        if receiver is not None:
            receiver.close()
        if sender is not None:
            sender.close()
        if process is not None:
            if process.is_alive():
                process.kill()
                process.join(timeout=5)
            process.close()
        engine.dispose()
