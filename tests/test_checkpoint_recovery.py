"""Kill an actual dispatcher process only after its checkpoint commit returns."""

import asyncio
from datetime import datetime, timezone
import json
import multiprocessing
import os
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import pytest
from sqlalchemy import MetaData, create_engine, insert, select

from src.core.contracts import checked, record_interaction
from src.core.jobs import JobDispatcher, JobStore, current_claim_owner
from src.core.pipeline import run_pipeline, to_sarif
from src.core.risk_projection import project_report_risk
from src.risk.risk_assessor import RiskAssessment
from src.security.security_engine import SecurityTestEngine
from tests.test_api_auth import api as api


PRIVATE_CANARY = 'synthetic-checkpoint-recovery-canary'


class RecoveryTester:
    @checked('prompt_injection.system_prompt_extraction', ['recovery-fixture'],
             oracle=lambda agent: True)
    async def complete(self, agent):
        record_interaction(True, decisive=True)
        return [{
            'vulnerability_type': 'prompt_injection', 'severity': 'high',
            'description': 'Protected fixture ' + agent['system_prompt_canary'],
            'evidence_status': 'confirmed',
        }]

    async def test_agent(self, agent):
        await self.complete(agent)
        await asyncio.Event().wait()


def checkpoint_process(database, acknowledgement):
    # Never inherit operator configuration into this disposable process fixture.
    os.environ['DATABASE_URL'] = 'sqlite:///:memory:'
    os.environ['SECRET_KEY'] = 'checkpoint-process-signing-key-' * 4
    os.environ['OPERATOR_API_KEY'] = 'checkpoint-process-operator-key'
    os.environ['OPERATOR_ORGANIZATION_ID'] = 'tenant-a'
    os.environ.pop('SCAN_EVIDENCE_PROFILES_FILE', None)
    from app import _snapshot_rows

    engine = create_engine('sqlite:///' + database)
    metadata = MetaData()
    metadata.reflect(bind=engine)
    store = JobStore(engine, metadata.tables['scan_job'], metadata.tables['scan_session'],
                     metadata.tables['scan_result'], metadata.tables['audit_event'])
    asset = {
        'id': 'recovery-asset', 'name': 'Recovery fixture', 'type': 'assistant',
        'provider': 'ollama', 'model': 'fixture-model',
        'endpoint': 'http://192.0.2.1:11434', 'discovery_method': 'fixture', 'metadata': {},
        'system_prompt_canary': PRIVATE_CANARY, 'evidence_context_id': 'recovery-fixture-v1',
    }
    discovery = SimpleNamespace(discover_agents=AsyncMock(return_value=[asset]))
    security = SecurityTestEngine()
    security.prompt_tester = RecoveryTester()

    def run(scan_id, cancelled):
        announced = False
        observed_at = datetime.now(timezone.utc)

        async def persist(report):
            nonlocal announced
            report['scan_id'] = scan_id
            accepted = store.save_checkpoint(
                scan_id, report, metadata.tables['discovered_agent'],
                _snapshot_rows(scan_id, report, observed_at), owner=current_claim_owner(scan_id))
            if not accepted:
                raise RuntimeError('Fixture checkpoint rejected')
            if report['summary']['overall_risk_score'] == 70 and not announced:
                announced = True
                acknowledgement.send(('committed', report['checkpoint']['sequence']))

        asyncio.run(run_pipeline(discovery, security, RiskAssessment(), None,
                                 checkpoint_callback=persist))

    dispatcher = JobDispatcher(store, run, workers=1, poll_seconds=0.01)
    dispatcher.start()
    # Parent kills this process; no graceful shutdown can mask missing durability.
    asyncio.run(asyncio.Event().wait())


@pytest.mark.skipif(os.name != 'posix', reason='Supported dispatcher requires POSIX')
def test_killed_dispatcher_preserves_acknowledged_evidence_without_replay(api, tmp_path):
    module, _ = api
    database = tmp_path / 'checkpoint-recovery.db'
    descriptor = os.open(database, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    os.close(descriptor)
    engine = create_engine('sqlite:///' + str(database))
    module.initialize_schema(engine, module.db.metadata)
    store = JobStore(engine, module.ScanJob.__table__, module.ScanSession.__table__,
                     module.ScanResult.__table__, module.AuditEvent.__table__)
    with engine.begin() as connection:
        connection.execute(insert(store.scans).values(
            id='recovery-scan', organization_id='tenant-a', scan_name='Recovery fixture',
            scan_type='full', status='queued', target_scope={}, scan_config={}))
        connection.execute(insert(store.jobs).values(scan_id='recovery-scan', status='queued'))
    context = multiprocessing.get_context('spawn')
    receiver, sender = context.Pipe(duplex=False)
    process = context.Process(target=checkpoint_process, args=(str(database), sender))
    process.start()
    sender.close()
    try:
        assert receiver.poll(15), 'Child did not acknowledge a committed checkpoint'
        acknowledgement, sequence = receiver.recv()
        assert acknowledgement == 'committed'
        assert process.is_alive()
        with engine.connect() as connection:
            before = connection.scalar(select(store.results.c.result))
            snapshots = connection.execute(select(module.DiscoveredAgentModel.__table__)).mappings().all()
            assert connection.scalar(select(store.jobs.c.status)) == 'running'
        assert before['checkpoint']['sequence'] == sequence
        assert before['summary']['overall_risk_score'] == 70
        assert before['summary']['vulnerabilities_found'] == 1
        assert len(snapshots) == 1
        competitor = JobDispatcher(store, Mock(), workers=1)
        with pytest.raises(RuntimeError, match='Another dispatcher'):
            competitor.start()
        process.kill()
        process.join(timeout=5)
        assert not process.is_alive()
        assert process.exitcode != 0
        replay = Mock(side_effect=AssertionError('Interrupted probes must not replay'))
        restarted = JobDispatcher(store, replay, workers=1, poll_seconds=0.01)
        try:
            restarted.start()
            with engine.connect() as connection:
                recovered = connection.scalar(select(store.results.c.result))
                after = connection.execute(select(module.DiscoveredAgentModel.__table__)).mappings().all()
                events = connection.execute(select(store.audit.c.event, store.audit.c.status)).all()
                assert connection.scalar(select(store.jobs.c.status)) == 'interrupted'
                assert connection.scalar(select(store.scans.c.overall_risk_score)) == 70
            assert recovered['status'] == 'interrupted'
            for field in ('agents', 'security_results', 'risk_assessments', 'summary', 'checkpoint'):
                assert recovered[field] == before[field]
            assert after == snapshots
            assert [event for event in events if event[0] == 'terminal'] == [('terminal', 'interrupted')]
            assert store.recover() == 0
            replay.assert_not_called()
            summary, agents = project_report_risk(recovered)
            assert summary['overall_risk_score'] == 70
            assert agents['recovery-asset']['risk_level'] == 'high'
            assert agents['recovery-asset']['risk_coverage_status'] == 'partial'
            sarif = to_sarif(recovered)['runs'][0]
            assert len(sarif['results']) == 1
            assert not sarif['invocations'][0]['executionSuccessful']
            assert PRIVATE_CANARY not in json.dumps(recovered)
            assert PRIVATE_CANARY.encode() not in database.read_bytes()
        finally:
            restarted.stop()
    finally:
        receiver.close()
        if process.is_alive():
            process.kill()
            process.join(timeout=5)
        process.close()
        engine.dispose()
