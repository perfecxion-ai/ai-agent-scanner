"""Actual queued HTTP assessments use owned SQLite, transport and checkpoints."""

from copy import deepcopy
import json
import time

import pytest
from sqlalchemy import create_engine

from src.core.evidence_profiles import EvidenceProfiles
from src.core.http_application_policy import HTTP_PUBLIC_FIELDS, HTTP_PROMPT_RULES
from src.core.http_application_runtime import get_http_target
from tests.test_api_auth import api as api, headers
from tests.test_http_application_core import application as application, MARKER, KEY
from tests.test_server_http_profiles import CANARY_ENV, CREDENTIAL_ENV, IDENTIFIER, body, document


@pytest.fixture
def server_api(api, tmp_path, monkeypatch):
    module, client = api
    for key, value in {'SCAN_ALLOWED_NETWORKS': ('127.0.0.1/32',), 'SCAN_ALLOW_LOOPBACK': True,
        'SCAN_TIMEOUT_SECONDS': 60, 'SCAN_REQUEST_TIMEOUT_SECONDS': 2,
        'SCAN_MAX_REQUESTS': 35, 'SCAN_MAX_RESPONSE_BYTES': 65536,
        'MAX_CONCURRENT_SCANS': 2}.items():
        monkeypatch.setitem(module.app.config, key, value)
    database = tmp_path.resolve() / 'owned-http-jobs.sqlite'
    assert not database.exists()
    previous = module.db.engine
    assert previous.url.database == ':memory:' and module._job_dispatcher is None
    engine = create_engine('sqlite:///' + str(database))
    module.db.session.remove()
    module.db.engines[None] = engine
    dispatcher = None
    try:
        dispatcher = module.start_job_dispatcher()
        assert dispatcher.ready
        yield module, client
    finally:
        if dispatcher:
            dispatcher.stop(timeout=5)
            assert not dispatcher._thread.is_alive()
            assert all(future.done() for future, _ in dispatcher._active.values())
            assert dispatcher._ownership.handle is None
        module.db.session.remove()
        module.db.engines[None] = previous
        engine.dispose()


def install(module, monkeypatch, endpoint, *, bearer=False):
    monkeypatch.setenv(CANARY_ENV, MARKER)
    monkeypatch.setenv(CREDENTIAL_ENV, KEY)
    loaded = EvidenceProfiles.from_document(document(endpoint, bearer=bearer))
    monkeypatch.setattr(module, '_evidence_profiles', loaded)
    return loaded


def submit(module, client, loaded, **options):
    response = client.post('/api/scans', headers=headers(module), json=body(loaded, **options))
    assert response.status_code == 202, response.json
    return response.json['scan_id']


def wait_for(module, predicate, timeout=60):
    stop = time.monotonic() + timeout
    while time.monotonic() < stop:
        module.db.session.remove()
        if predicate():
            return
        time.sleep(0.02)
    module.db.session.remove()
    assert predicate(), 'Owned queued HTTP work did not reach the expected state'


def terminal(module, scan_id, *, timeout=60):
    wait_for(module, lambda: module.db.session.get(module.ScanSession, scan_id).status
             in {'completed', 'partial', 'failed', 'cancelled', 'interrupted'}, timeout=timeout)
    return deepcopy(module.db.session.get(module.ScanResult, scan_id).result)


@pytest.mark.parametrize('mode', ['leak', 'quiet', 'denied', 'off-pointer'])
def test_actual_queued_http_reports_inventory_groups_and_privacy(server_api, application, monkeypatch, caplog, mode):
    module, client = server_api
    # Full-sample semantics use the supported work cap under coverage.
    monkeypatch.setitem(module.app.config, 'SCAN_TIMEOUT_SECONDS', 180)
    endpoint, state = application
    state['mode'] = 'leak' if mode == 'off-pointer' else mode
    loaded = install(module, monkeypatch, endpoint, bearer=True)
    state['expected_key'] = KEY
    if mode == 'off-pointer':
        changed = document(endpoint, bearer=True)
        changed['http_targets'][IDENTIFIER]['http_target']['response_text_pointer'] = '/missing'
        loaded = EvidenceProfiles.from_document(changed)
        monkeypatch.setattr(module, '_evidence_profiles', loaded)
    scan_id = submit(module, client, loaded)
    report = terminal(module, scan_id, timeout=185)
    expected = 70 if mode == 'leak' else None
    assert report['summary']['overall_risk_score'] == expected
    assert set(check['rule_id'] for check in report['agents'][0]['checks']) == set(HTTP_PROMPT_RULES)
    assert len(report['agents'][0]['checks']) == 7
    assert report['status'] == ('completed' if mode in ('leak', 'quiet') else 'partial')
    if mode in ('leak', 'quiet'):
        assert len(state['requests']) == 35
    assert all(request[0] == '/custom/assistant' and set(request[2]) == {'question'}
               for request in state['requests'])
    snapshot = module.DiscoveredAgentModel.query.filter_by(scan_id=scan_id).one()
    assert all(snapshot.metadata_json[key] == report['agents'][0][key] for key in HTTP_PUBLIC_FIELDS)
    inventory = client.get('/api/agents', headers=headers(module)).json
    assert inventory['agents'][0]['risk_score'] == expected
    wait_for(module, lambda: bool(client.get('/api/asset-groups', headers=headers(module)).json.get('asset_groups')))
    groups = client.get('/api/asset-groups', headers=headers(module)).json
    assert groups['asset_groups'][0]['latest_observation_risk']['risk_score'] == expected
    captures = [report, inventory, groups]
    for path in ('results', 'audit', 'report?format=json', 'report?format=sarif', 'status'):
        response = client.get('/api/scans/' + scan_id + '/' + path, headers=headers(module))
        assert response.status_code == 200
        captures.append(response.json)
    scan = module.db.session.get(module.ScanSession, scan_id)
    captures.extend([scan.scan_config, snapshot.metadata_json, snapshot.vulnerabilities,
        [{'event': row.event, 'status': row.status} for row in module.AuditEvent.query.filter_by(scan_id=scan_id)]])
    encoded = json.dumps(captures) + caplog.text
    assert all(private not in encoded for private in (MARKER, KEY, CANARY_ENV, CREDENTIAL_ENV))
    assert get_http_target(report['agents'][0]) is None


@pytest.mark.parametrize('action', ['timeout', 'cancel'])
def test_queued_stall_retains_acknowledged_receipt_without_replay(server_api, application, monkeypatch, action):
    module, client = server_api
    endpoint, state = application
    state['mode'] = 'leak-then-stall'
    loaded = install(module, monkeypatch, endpoint)
    scan_id = submit(module, client, loaded, **({'timeout_seconds': 1} if action == 'timeout' else {}))
    try:
        assert state['stalled'].wait(4)
        wait_for(module, lambda: (module.db.session.get(module.ScanResult, scan_id) is not None
            and module.db.session.get(module.ScanResult, scan_id).result['summary']['overall_risk_score'] == 70))
        acknowledged = deepcopy(module.db.session.get(module.ScanResult, scan_id).result['agents'][0]['check_evidence'])
        if action == 'cancel':
            assert client.post('/api/scans/' + scan_id + '/cancel', headers=headers(module)).status_code == 202
        report = terminal(module, scan_id)
        assert report['status'] == ('failed' if action == 'timeout' else 'cancelled')
        assert report['summary']['overall_risk_score'] == 70
        assert report['agents'][0]['check_evidence'] == acknowledged
        requests = len(state['requests'])
        assert module._get_job_store().recover() == 0
        assert len(state['requests']) == requests
        assert client.get('/api/scans/' + scan_id + '/report?format=sarif', headers=headers(module)).status_code == 200
    finally:
        state['release'].set()


def test_worker_context_pins_values_while_other_jobs_have_separate_contexts(server_api, application, monkeypatch):
    module, client = server_api
    monkeypatch.setitem(module.app.config, 'SCAN_TIMEOUT_SECONDS', 180)
    endpoint, state = application
    state['mode'] = 'leak-then-stall'
    loaded = install(module, monkeypatch, endpoint, bearer=True)
    state['expected_key'] = KEY
    first = submit(module, client, loaded)
    try:
        assert state['stalled'].wait(4)
        # Changing the reference after the first worker prepared must not change
        # that worker's principal or marker. A second worker uses fresh values.
        rotated_key, rotated_marker = KEY + '-rotated', MARKER + '-rotated'
        state['expected_key'] = None
        state['mode'] = 'leak'
        monkeypatch.setenv(CREDENTIAL_ENV, rotated_key)
        monkeypatch.setenv(CANARY_ENV, rotated_marker)
        second = submit(module, client, loaded, max_requests=1)
        second_report = terminal(module, second)
        assert second_report['summary']['overall_risk_score'] is None
        assert second_report['agents'][0]['check_evidence'] == []
        assert module.db.session.get(module.ScanJob, first).owner == module.db.session.get(module.ScanJob, second).owner
        state['release'].set()
        first_report = terminal(module, first, timeout=185)
        assert first_report['summary']['overall_risk_score'] == 70
        assert first_report['status'] == 'completed'
        authorizations = [request[1].get('Authorization') for request in state['requests']]
        assert authorizations.count('Bearer ' + KEY) == 35
        assert authorizations.count('Bearer ' + rotated_key) == 1
    finally:
        state['expected_key'] = None
        state['release'].set()
