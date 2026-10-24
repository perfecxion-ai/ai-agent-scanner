"""Owned library workers retain actual tenant HTTP evidence after SIGKILL.

This exercises JobDispatcher persistence directly. It does not admit private
tenant inputs through the server API or establish CLI process-crash recovery.
"""

import asyncio
import base64
from contextlib import contextmanager
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import multiprocessing
import os
import signal
import stat
import threading
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import pytest
from sqlalchemy import MetaData, create_engine, insert, select

from src.core.jobs import JobDispatcher, JobStore, current_claim_owner, snapshot_id
from src.core.pipeline import run_pipeline, to_sarif
from src.core.risk_projection import project_report_risk
from src.core.tenant_probe_policy import TENANT_CONTROL_PROMPT, tenant_target
from src.core.transport import ScanBudget, scan_transport
from src.risk.risk_assessor import RiskAssessment
from src.security.security_engine import SecurityTestEngine
from tests.test_api_auth import api as api, headers


OWNER_KEY = 'owned-recovery-owner-key-a4d79c320f18e6b5'
TESTED_KEY = 'owned-recovery-subject-key-df325a71e0948bc6'
OWNER_MARKER = 'owned-recovery-owner-record-598d1af043c27be6'
TESTED_MARKER = 'owned-recovery-subject-record-24fb730dc1e9a685'
ENVIRONMENT = {
    'TENANT_RECOVERY_OWNER_KEY': OWNER_KEY,
    'TENANT_RECOVERY_OWNER_MARKER': OWNER_MARKER,
    'TENANT_RECOVERY_SUBJECT_KEY': TESTED_KEY,
    'TENANT_RECOVERY_SUBJECT_MARKER': TESTED_MARKER,
}
LABELS = ('private-recovery-owner-tenant-f4092c68', 'private-recovery-owner-principal-ae158b23',
          'private-recovery-subject-tenant-b46ca3f0', 'private-recovery-subject-principal-c53f704a')
SCAN_ID = 'owned-tenant-recovery-scan'
ASSET_ID = 'owned-tenant-recovery-asset'
CHILD_SIGNING_KEY = 'tenant-recovery-signing-key-' * 4
CHILD_OPERATOR_KEY = 'tenant-recovery-operator-key'


def _configured_agent(endpoint):
    item = dict(id=ASSET_ID, name='Owned tenant recovery fixture', type='assistant',
                provider='ollama', model='owned-recovery-model', endpoint=endpoint,
                api_key_env='TENANT_RECOVERY_SUBJECT_KEY', discovery_method='owned-fixture', metadata={},
                evidence_context_id='owned-tenant-recovery-v1')
    item['tenant_evidence'] = dict(
        schema_version='1.0', tested_principal_authorized_for_owner=False,
        binding=tenant_target(endpoint, item['provider'], item['model'], item['evidence_context_id']),
        owner=dict(tenant_ref=LABELS[0], principal_ref=LABELS[1],
                   api_key_env='TENANT_RECOVERY_OWNER_KEY', canary_env='TENANT_RECOVERY_OWNER_MARKER'),
        tested=dict(tenant_ref=LABELS[2], principal_ref=LABELS[3],
                    api_key_env='TENANT_RECOVERY_SUBJECT_KEY', canary_env='TENANT_RECOVERY_SUBJECT_MARKER'))
    return item


@contextmanager
def _owned_tenant_target(mode):
    state = dict(calls=[], blocked=threading.Event(), release=threading.Event(), errors=[],
                 response_private_values=[])

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def do_POST(self):
            body = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
            prompt = body['messages'][0]['content']
            key = self.headers.get('Authorization', '').removeprefix('Bearer ')
            state['calls'].append(dict(method=self.command, path=self.path, body=body,
                                       headers=dict(self.headers), credential=key))
            ordinal = len(state['calls'])
            if self.path != '/api/chat' or body['model'] != 'owned-recovery-model':
                state['errors'].append('Unexpected owned fixture request')
                self.send_error(400)
                return
            if key == OWNER_KEY and prompt == TENANT_CONTROL_PROMPT:
                text, status = OWNER_MARKER, 200
            elif key == TESTED_KEY and prompt == TENANT_CONTROL_PROMPT:
                text, status = TESTED_MARKER + (' ' + OWNER_MARKER if mode == 'subject' else ''), 200
            elif key != TESTED_KEY:
                text, status = 'Owned invalid credential denied', 403
            else:
                if ordinal == (4 if mode == 'subject' else 5):
                    state['blocked'].set()
                    if not state['release'].wait(30):
                        state['errors'].append('Owned stalled request exceeded test bound')
                text, status = OWNER_MARKER, 200
            data = {'message': {'content': text}}
            if status == 200:
                values = (OWNER_KEY, TESTED_KEY, *ENVIRONMENT, *LABELS)
                encoded = [encoded for value in values for encoded in (
                    base64.b64encode(value.encode()).decode(),
                    ''.join('%%%02X' % byte for byte in value.encode()))]
                state['response_private_values'].extend(encoded)
                data['private_metadata'] = {'values': list(values), 'encoded': encoded}
            raw = json.dumps(data).encode()
            try:
                self.send_response(status)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Content-Length', str(len(raw)))
                self.send_header('X-Private-Fixture-Reference', LABELS[0])
                self.end_headers()
                self.wfile.write(raw)
            except (BrokenPipeError, ConnectionResetError):
                pass  # The parent deliberately kills the client while this response is held.

    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    server.daemon_threads = False  # server_close joins each released request handler.
    thread = threading.Thread(target=lambda: server.serve_forever(poll_interval=0.01), daemon=True)
    thread.start()
    try:
        yield 'http://127.0.0.1:' + str(server.server_address[1]), state
    finally:
        state['release'].set()
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)
        assert not thread.is_alive()


def _tenant_checkpoint_process(database, endpoint, acknowledgement, log_path):
    # The library fixture owns both database and lock; no operator profile is read.
    os.umask(0o077)
    os.environ.clear()
    os.environ.update(ENVIRONMENT)
    os.environ.update(DATABASE_URL='sqlite:///:memory:',
                      SECRET_KEY=CHILD_SIGNING_KEY, OPERATOR_API_KEY=CHILD_OPERATOR_KEY,
                      OPERATOR_ORGANIZATION_ID='tenant-a')
    descriptor = os.open(log_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    os.dup2(descriptor, 1)
    os.dup2(descriptor, 2)
    os.close(descriptor)
    from app import _snapshot_rows
    import src.security.data_privacy_tests as privacy

    async def no_pacing(_):
        return None

    privacy.asyncio = SimpleNamespace(sleep=no_pacing, CancelledError=asyncio.CancelledError)
    engine = create_engine('sqlite:///' + database)
    metadata = MetaData()
    metadata.reflect(bind=engine)
    store = JobStore(engine, metadata.tables['scan_job'], metadata.tables['scan_session'],
                     metadata.tables['scan_result'], metadata.tables['audit_event'])
    asset = _configured_agent(endpoint)

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
                raise RuntimeError('Owned tenant checkpoint rejected')
            if report['summary']['overall_risk_score'] == 90 and not announced:
                current = report['agents'][0]
                assert len(current['check_evidence']) == len(current['vulnerabilities']) == 1
                assert report['summary']['checks_unfinished'] == 1
                assert not any(check['rule_id'] == 'tenant_isolation_violation' for check in current['checks'])
                announced = True
                acknowledgement.send(('committed', report['checkpoint']['sequence']))

        security = SecurityTestEngine()
        security.prompt_tester.test_agent = AsyncMock(return_value=[])
        security.access_tester.test_agent = AsyncMock(return_value=[])
        security.privacy_tester.test_agent = security.privacy_tester._test_tenant_isolation
        with scan_transport(ScanBudget(allowed_networks=('127.0.0.1/32',), allow_loopback=True,
                                       max_requests=8, max_response_bytes=16384,
                                       request_timeout_seconds=20)):
            asyncio.run(run_pipeline(None, security, RiskAssessment(), None, 'security_only',
                                     agents=[asset], checkpoint_callback=persist))

    dispatcher = JobDispatcher(store, run, workers=1, poll_seconds=0.01)
    dispatcher.start()
    asyncio.run(asyncio.Event().wait())


def _private_variants(values):
    variants = set(values)
    for value in values:
        variants.add(base64.b64encode(value.encode()).decode())
        variants.add(''.join('%%%02X' % byte for byte in value.encode()))
    return variants


def _authenticated_recovery_reads(module, client, engine, recovered):
    """Read the genuine recovered fixture through Flask with its owned engine."""
    module.db.session.remove()
    engines = module.db.engines
    original = engines[None]
    assert original.url.database == ':memory:' and original is not engine
    outputs = []
    request_headers = headers(module)
    private = {request_headers['Authorization'], request_headers['Authorization'].removeprefix('Bearer '),
               module.app.config['SECRET_KEY'], module.app.config['OPERATOR_API_KEY']}

    def read(path):
        module.db.session.remove()
        response = client.get(path, headers=request_headers)
        assert response.status_code == 200, 'Recovered fixture API read failed'
        payload = response.get_json()
        outputs.append({'body': payload, 'headers': dict(response.headers)})
        return response, payload

    try:
        engines[None] = engine
        assert module.db.engine is engine
        _, body = read('/api/scans/' + SCAN_ID + '/results')
        result = body['results']
        assert result['pipeline'] == recovered
        assert result['scan_info']['status'] == 'interrupted'
        assert result['summary']['overall_risk_score'] == 90
        assert result['summary']['risk_assessment_status'] == 'partial'
        assert len(result['agents']) == 1
        snapshot = result['agents'][0]
        assert snapshot['id'] == snapshot_id(SCAN_ID, 0) and snapshot['asset_id'] == ASSET_ID
        assert snapshot['vulnerabilities'] == recovered['agents'][0]['vulnerabilities']
        assert snapshot['risk_score'] == 90 and snapshot['risk_level'] == 'critical'
        assert snapshot['risk_coverage_status'] == 'partial'

        _, status = read('/api/scans/' + SCAN_ID + '/status')
        assert status['status'] == 'interrupted'
        assert status['agents_discovered'] == status['vulnerabilities_found'] == 1
        _, listed = read('/api/scans')
        assert listed['total'] == len(listed['scans']) == 1
        assert listed['scans'][0]['scan_id'] == SCAN_ID and listed['scans'][0]['status'] == 'interrupted'

        for suffix, limit in (('', 100), ('&limit=1', 1)):
            _, inventory = read('/api/agents?risk_level=critical' + suffix)
            assert len(inventory['agents']) == 1 and inventory['next_cursor'] is None
            assert inventory['coverage']['search_complete'] is True
            assert inventory['coverage']['page_limit'] == limit
            observed = inventory['agents'][0]
            assert observed['id'] == snapshot_id(SCAN_ID, 0) and observed['asset_id'] == ASSET_ID
            assert observed['risk_score'] == 90 and observed['risk_level'] == 'critical'
            assert observed['risk_coverage_status'] == observed['risk_assessment_status'] == 'partial'

        downloaded, original_json = read('/api/scans/' + SCAN_ID + '/report?format=json')
        assert downloaded.headers['Cache-Control'] == 'no-store' and original_json == recovered
        downloaded, sarif = read('/api/scans/' + SCAN_ID + '/report?format=sarif')
        assert downloaded.headers['Cache-Control'] == 'no-store'
        run = sarif['runs'][0]
        assert run['properties']['producer_identity'] == recovered['producer_identity']
        assert run['properties']['scan_status'] == 'interrupted'
        assert run['properties']['summary']['overall_risk_score'] == 90
        assert run['properties']['check_evidence'][0]['check_evidence'] == recovered['agents'][0]['check_evidence']
        assert not run['invocations'][0]['executionSuccessful'] and len(run['results']) == 1
        assert run['results'][0]['properties']['vulnerability_id'] == recovered['agents'][0]['vulnerabilities'][0]['id']

        _, audit = read('/api/scans/' + SCAN_ID + '/audit')
        assert [(item['event'], item['status']) for item in audit['events'] if item['event'] == 'terminal'] == [
            ('terminal', 'interrupted')]
    finally:
        module.db.session.remove()
        engines[None] = original
    assert module.db.engine is original
    return outputs, private


@pytest.mark.skipif(os.name != 'posix', reason='Supported dispatcher requires POSIX')
@pytest.mark.parametrize('mode,blocked_at,request_ordinal', [('subject', 4, 2), ('attack', 5, 4)])
def test_sigkill_retains_actual_tenant_receipt_and_recovers_once_without_probe_replay(
        api, tmp_path, caplog, mode, blocked_at, request_ordinal):
    module, client = api
    owned = tmp_path.resolve() / 'owned-tenant-recovery'
    owned.mkdir(mode=0o700)
    database = owned / 'tenant.db'
    log_path = owned / 'worker.log'
    lock_path = database.with_name(database.name + '.dispatcher.lock')
    descriptor = os.open(database, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    os.close(descriptor)
    engine = create_engine('sqlite:///' + str(database))
    module.initialize_schema(engine, module.db.metadata)
    store = JobStore(engine, module.ScanJob.__table__, module.ScanSession.__table__,
                     module.ScanResult.__table__, module.AuditEvent.__table__)
    with engine.begin() as connection:
        connection.execute(insert(store.scans).values(
            id=SCAN_ID, organization_id='tenant-a', scan_name='Owned library tenant recovery',
            scan_type='security_only', status='queued', target_scope={}, scan_config={}))
        connection.execute(insert(store.jobs).values(scan_id=SCAN_ID, status='queued'))
    process = None
    receiver = sender = None
    try:
        with _owned_tenant_target(mode) as (endpoint, target):
            context = multiprocessing.get_context('spawn')
            receiver, sender = context.Pipe(duplex=False)
            process = context.Process(target=_tenant_checkpoint_process,
                                      args=(str(database), endpoint, sender, str(log_path)))
            process.start()
            sender.close()
            sender = None
            assert receiver.poll(15), 'Owned worker did not acknowledge a committed tenant receipt'
            acknowledgement, sequence = receiver.recv()
            assert acknowledgement == 'committed' and process.is_alive()
            assert target['blocked'].wait(5), 'Worker did not reach the later genuine HTTP stall'
            assert len(target['calls']) == blocked_at
            assert [call['credential'] for call in target['calls'][:2]] == [OWNER_KEY, TESTED_KEY]
            assert target['calls'][2]['credential'] not in {OWNER_KEY, TESTED_KEY}
            assert all(call['credential'] == TESTED_KEY for call in target['calls'][3:])
            assert not target['errors']
            with engine.connect() as connection:
                before = connection.scalar(select(store.results.c.result))
                snapshots = connection.execute(select(module.DiscoveredAgentModel.__table__)).mappings().all()
                assert connection.scalar(select(store.jobs.c.status)) == 'running'
                assert connection.scalar(select(store.scans.c.overall_risk_score)) == 90
            assert before['checkpoint']['sequence'] == sequence
            assert before['checkpoint']['version'] == '3.0'
            assert before['check_evidence_schema_version'] == '2.0'
            assert before['summary']['overall_risk_score'] == 90
            assert before['summary']['vulnerabilities_found'] == 1
            assert before['summary']['checks_unfinished'] == 1
            producer = before['producer_identity']
            assert producer['component'] == 'library' and producer['source']['status'] == 'available'
            receipt = before['agents'][0]['check_evidence'][0]
            finding = before['agents'][0]['vulnerabilities'][0]
            assert receipt['source'] == 'controlled_tenant_response'
            assert receipt['tenant_observation_source'] == ('subject_control' if mode == 'subject' else 'attack')
            assert receipt['request_ordinal'] == request_ordinal
            assert receipt['requests_attempted'] == receipt['responses_evaluated'] == (3 if mode == 'subject' else 4)
            assert receipt['control_proof'] == {'request_ordinals': [1, 2, 3], 'status_codes': [200, 200, 403]}
            assert receipt['finding_id'] == finding['id'] and finding['check_evidence_id'] == receipt['id']
            assert len(snapshots) == 1 and snapshots[0]['id'] == snapshot_id(SCAN_ID, 0)
            assert snapshots[0]['risk_score'] == 90 and snapshots[0]['risk_level'] == 'critical'
            competitor = JobDispatcher(store, Mock(), workers=1)
            with pytest.raises(RuntimeError, match='Another dispatcher'):
                competitor.start()
            process.kill()
            process.join(timeout=5)
            assert not process.is_alive() and process.exitcode == -signal.SIGKILL
            calls_at_kill = len(target['calls'])
            replay = Mock(side_effect=AssertionError('Interrupted tenant probes must not replay'))
            restarted = JobDispatcher(store, replay, workers=1, poll_seconds=0.01)
            try:
                restarted.start()
                with engine.connect() as connection:
                    recovered = connection.scalar(select(store.results.c.result))
                    after = connection.execute(select(module.DiscoveredAgentModel.__table__)).mappings().all()
                    events = connection.execute(select(store.audit.c.event, store.audit.c.status)).all()
                    assert connection.scalar(select(store.jobs.c.status)) == 'interrupted'
                    assert connection.scalar(select(store.scans.c.overall_risk_score)) == 90
                assert recovered['status'] == 'interrupted'
                for field in ('producer_identity', 'agents', 'security_results', 'risk_assessments', 'summary', 'checkpoint'):
                    assert recovered[field] == before[field]
                assert after == snapshots
                assert [event for event in events if event[0] == 'terminal'] == [('terminal', 'interrupted')]
                assert store.recover() == 0
                assert store.claim('unused-restart-worker') is None
                summary, assets = project_report_risk(recovered)
                assert summary['overall_risk_score'] == 90
                assert assets[ASSET_ID]['risk_level'] == 'critical'
                assert assets[ASSET_ID]['risk_coverage_status'] == 'partial'
                sarif = to_sarif(recovered)['runs'][0]
                assert len(sarif['results']) == 1 and not sarif['invocations'][0]['executionSuccessful']
                assert sarif['properties']['producer_identity'] == producer
                assert len(target['calls']) == calls_at_kill
                replay.assert_not_called()
                api_outputs, api_private = _authenticated_recovery_reads(module, client, engine, recovered)
                with engine.connect() as connection:
                    assert connection.scalar(select(store.results.c.result)) == recovered
                    assert connection.execute(select(module.DiscoveredAgentModel.__table__)).mappings().all() == after
                private = {OWNER_KEY, TESTED_KEY, OWNER_MARKER, TESTED_MARKER, *ENVIRONMENT, *LABELS,
                           CHILD_SIGNING_KEY, CHILD_OPERATOR_KEY, *api_private}
                private.update(call['credential'] for call in target['calls'] if call['credential'])
                variants = _private_variants(private)
                assert target['response_private_values'] and set(target['response_private_values']) <= variants
                serialized = (json.dumps(recovered) + json.dumps(sarif) + json.dumps(api_outputs)
                              + json.dumps([dict(row) for row in after], default=str) + caplog.text)
                assert all(value.casefold() not in serialized.casefold() for value in variants)
                for path in (database, lock_path, log_path):
                    assert stat.S_IMODE(path.stat().st_mode) == 0o600
                    raw = path.read_bytes().lower()
                    assert all(value.encode().lower() not in raw for value in variants)
                assert stat.S_IMODE(owned.stat().st_mode) == 0o700
            finally:
                restarted.stop()
            replay.assert_not_called()
            assert len(target['calls']) == calls_at_kill
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
