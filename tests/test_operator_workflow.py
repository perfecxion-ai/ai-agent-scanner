"""Real offline operator workflow, without provider calls or scanner substitutes."""

import importlib
import json
import socket
import subprocess
import sys
import time
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import create_engine


@pytest.fixture
def offline_operator(monkeypatch, tmp_path):
    operator_key = 'synthetic-operator-workflow-key'
    monkeypatch.delenv('SCAN_EVIDENCE_PROFILES_FILE', raising=False)
    monkeypatch.setenv('SECRET_KEY', 'synthetic-workflow-signing-key-' * 2)
    monkeypatch.setenv('OPERATOR_API_KEY', operator_key)
    monkeypatch.setenv('DATABASE_URL', 'sqlite:///:memory:')
    module = sys.modules.get('app') or importlib.import_module('app')
    attempted = []
    original_socket = socket.socket

    class LocalSocket(original_socket):
        def __init__(self, family=socket.AF_INET, *args, **kwargs):
            # asyncio creates an internal AF_UNIX socketpair for its event loop.
            if family != socket.AF_UNIX:
                attempted.append('network socket')
                raise AssertionError('Network sockets are forbidden in this workflow')
            super().__init__(family, *args, **kwargs)

    def forbidden(*args, **kwargs):
        attempted.append('DNS or process execution')
        raise AssertionError('DNS and process execution are forbidden in this workflow')

    monkeypatch.setattr(socket, 'socket', LocalSocket)
    monkeypatch.setattr(socket, 'getaddrinfo', forbidden)
    monkeypatch.setattr(subprocess, 'Popen', forbidden)
    assert module._job_dispatcher is None, 'Do not replace an existing dispatcher'
    monkeypatch.setattr(module, '_evidence_profiles', module.load_evidence_profiles(None))
    monkeypatch.setattr(module, '_job_dispatcher', None)
    repository = tmp_path / 'repository'
    repository.mkdir()
    synthetic_secret = 'sk-' + 'SYNTHETICWORKFLOWSECRET' * 2
    canary = 'SYNTHETIC-LOCAL-SOURCE-CANARY-12345'
    (repository / 'agent.py').write_text(
        'raise AssertionError("Source fixture must never execute")\n'
        f'import openai\nAPI_KEY = "{synthetic_secret}"\nCANARY = "{canary}"\n')
    for key, value in {
        'TESTING': True, 'SECRET_KEY': 'synthetic-workflow-signing-key-' * 2,
        'OPERATOR_API_KEY': operator_key, 'OPERATOR_ORGANIZATION_ID': 'offline-operator',
        'SCAN_ALLOWED_PATH_ROOTS': (str(repository),), 'SCAN_ALLOWED_NETWORKS': (),
        'SCAN_ALLOW_LOOPBACK': False, 'MAX_CONCURRENT_SCANS': 1,
        'SCAN_TIMEOUT_SECONDS': 5,
    }.items():
        monkeypatch.setitem(module.app.config, key, value)
    database = tmp_path / 'operator.sqlite'
    with module.app.app_context():
        previous = module.db.engine
        # Inspect only. Never connect to or dispose a foreign cached engine.
        assert previous.dialect.name == 'sqlite' and previous.url.database == ':memory:'
        assert not previous.url.query
        module.db.session.remove()
        engine = create_engine('sqlite:///' + str(database))
        assert engine.dialect.name == 'sqlite' and not engine.url.query
        assert engine.url.database == str(database.resolve()) and not database.exists()
        module.db.engines[None] = engine
        dispatcher = None
        try:
            dispatcher = module.start_job_dispatcher()
            assert dispatcher.ready and database.is_file()
            yield module, module.app.test_client(), repository, operator_key, synthetic_secret, canary
        finally:
            try:
                if dispatcher:
                    dispatcher.stop(timeout=2)
                    assert not dispatcher._thread.is_alive()
                    assert all(future.done() for future, _ in dispatcher._active.values())
                    assert dispatcher._ownership.handle is None
                    assert dispatcher.service.stopped
                    assert not dispatcher.service.future or dispatcher.service.future.done()
            finally:
                module.db.session.remove()
                module.db.engines[None] = previous
                engine.dispose()
        assert attempted == []


def wait_for(module, fetch, predicate):
    deadline = time.monotonic() + 8
    while time.monotonic() < deadline:
        module.db.session.remove()
        response = fetch()
        assert response.status_code == 200, response.json
        if predicate(response.json):
            return response.json
        time.sleep(0.02)
    pytest.fail('Offline operator workflow did not reach its expected terminal state')


def test_offline_operator_template_schedule_and_reports(offline_operator):
    module, client, repository, operator_key, synthetic_secret, canary = offline_operator
    assert client.get('/').status_code == 200
    assert client.get('/health/ready').status_code == 200
    assert client.get('/api/scans').status_code == 401
    assert client.post('/api/auth/token', json={'api_key': 'wrong-key'}).status_code == 401
    login = client.post('/api/auth/token', json={'api_key': operator_key})
    assert login.status_code == 200 and login.headers['Cache-Control'] == 'no-store'
    headers = {'Authorization': 'Bearer ' + login.json['token']}
    responses = []

    def request(method, path, *, status=200, body=None):
        module.db.session.remove()
        response = client.open(path, method=method, headers=headers, json=body)
        assert response.status_code == status, response.json
        responses.append(response.get_data(as_text=True))
        return response.json

    template = request('POST', '/api/templates', status=201, body={
        'scan_name': 'Offline repository assessment', 'scan_type': 'full',
        'target_scope': {'repositories': [str(repository)]}, 'scan_config': {},
    })['template']
    assert request('GET', '/api/scans')['total'] == 0
    run_path = f'/api/templates/{template["id"]}/run'
    # A saved recipe cannot bypass a later server-policy change.
    module.app.config['SCAN_ALLOWED_PATH_ROOTS'] = ()
    request('POST', run_path, status=400, body={'revision': template['revision']})
    assert request('GET', '/api/scans')['total'] == 0
    module.app.config['SCAN_ALLOWED_PATH_ROOTS'] = (str(repository),)
    manual_id = request('POST', run_path, status=202, body={'revision': template['revision']})['scan_id']

    def inspect_completed(scan_id):
        wait_for(module, lambda: client.get(f'/api/scans/{scan_id}/status', headers=headers),
                 lambda data: data['status'] in module.TERMINAL_STATES)
        status = request('GET', f'/api/scans/{scan_id}/status')
        assert status['status'] == 'partial' and status['agents_discovered'] == 1
        result = request('GET', f'/api/scans/{scan_id}/results')['results']
        report = request('GET', f'/api/scans/{scan_id}/report?format=json')
        assert result['pipeline'] == report
        assert report['summary']['agents_discovered'] == report['summary']['agents_skipped'] == 1
        assert report['summary']['agents_tested'] == report['summary']['vulnerabilities_found'] == 0
        assert report['summary']['overall_risk_score'] is None
        assert report['risk_assessment_status'] == 'not_run' and report['risk_assessments'] == []
        agent = report['agents'][0]
        assert agent['provider'] == 'openai' and agent['endpoint'] is None
        assert agent['security_status'] == 'skipped' and agent['vulnerabilities'] == []
        assert agent['risk_score'] is None and agent['risk_level'] == 'unknown'
        assert agent['checks'] and all(check['status'] == 'skipped' for check in agent['checks'])
        assert all(check['outcome'] != 'confirmed' for check in agent['checks'])
        sarif = request('GET', f'/api/scans/{scan_id}/report?format=sarif')
        assert sarif['version'] == '2.1.0' and sarif['runs'][0]['results'] == []
        assert sarif['runs'][0]['invocations'][0]['executionSuccessful'] is False
        assert sarif['runs'][0]['properties']['summary'] == report['summary']
        audit = request('GET', f'/api/scans/{scan_id}/audit')['events']
        assert [event['event'] for event in audit] == ['admitted', 'claimed', 'terminal']
        assert audit[-1]['status'] == 'partial'
        return report

    manual_report = inspect_completed(manual_id)
    schedule = request('POST', '/api/schedules', status=201, body={
        'template_id': template['id'], 'template_revision': template['revision'],
        'interval_seconds': 60, 'total_runs': 1,
    })['schedule']
    schedule_path = f'/api/schedules/{schedule["id"]}'
    assert schedule['state'] == 'disabled' and schedule['admitted_runs'] == 0
    assert request('GET', schedule_path + '/occurrences')['total'] == 0
    assert request('GET', '/api/scans')['total'] == 1
    enabled = request('POST', schedule_path + '/enable', body={'revision': schedule['revision']})['schedule']
    assert enabled['state'] == 'enabled' and enabled['admitted_runs'] == 0
    assert datetime.fromisoformat(enabled['next_due_at']) > datetime.now(timezone.utc)
    assert request('GET', '/api/scans')['total'] == 1
    # Move only the disposable schedule's due time; run the actual service callbacks.
    with module._admission_lock:
        row = module.db.session.get(module.ScanSchedule, schedule['id'])
        row.next_due_at = datetime.now(timezone.utc) - timedelta(seconds=1)
        module.db.session.commit()
    module._job_dispatcher.wake()
    completed = wait_for(module, lambda: client.get(schedule_path, headers=headers),
                         lambda data: data['schedule']['state'] == 'completed')['schedule']
    assert completed['admitted_runs'] == 1 and completed['outstanding_scan_id'] is None
    assert completed['next_due_at'] is None
    occurrences = request('GET', schedule_path + '/occurrences')
    assert occurrences['total'] == 1 and occurrences['occurrences'][0]['ordinal'] == 1
    scheduled_id = occurrences['occurrences'][0]['scan_id']
    assert scheduled_id != manual_id
    scheduled_report = inspect_completed(scheduled_id)
    assert request('GET', '/api/scans')['total'] == 2
    assert len({row.id for row in module.DiscoveredAgentModel.query.all()}) == 2
    request('DELETE', schedule_path)
    request('DELETE', f'/api/templates/{template["id"]}')
    assert request('GET', f'/api/scans/{manual_id}/report') == manual_report
    assert request('GET', f'/api/scans/{scheduled_id}/report') == scheduled_report
    serialized = json.dumps(responses)
    assert all(secret not in serialized for secret in (operator_key, synthetic_secret, canary, login.json['token']))
