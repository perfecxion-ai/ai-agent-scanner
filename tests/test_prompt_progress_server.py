"""Real server execution retains an unfinished prompt receipt in private SQLite."""

from copy import deepcopy
import json
import threading
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from src.core.contracts import CheckpointError
from src.core.jobs import worker_claim
from src.core.pipeline import to_sarif
from tests.prompt_progress_fixture import CANARY, disclosure_target, unfinished_prompt_engine
from tests.test_api_auth import api as api, headers
from tests.test_job_checkpoints import file_api as file_api, projection, save
from tests.test_jobs import result, state


def execute_unfinished(file_api, monkeypatch, interruption, during_acknowledgement=None):
    module, _, fixture = file_api
    store, _, _ = fixture
    cancelled = threading.Event()
    acknowledged = []

    def after_response():
        current = result(store, 'checkpoint')
        assert current['summary']['overall_risk_score'] == 70
        assert current['summary']['checks_unfinished'] == 1
        assert current['summary']['checks_completed'] == 0
        acknowledged.append(current)
        if during_acknowledgement is not None:
            during_acknowledgement(current)
        if interruption == 'cancel':
            assert store.cancel('checkpoint') == 'cancel_requested'
            cancelled.set()

    monkeypatch.setitem(module.app.config, 'SCAN_ALLOWED_NETWORKS', ('127.0.0.1/32',))
    monkeypatch.setitem(module.app.config, 'SCAN_ALLOW_LOOPBACK', True)
    monkeypatch.setattr(module, 'security_engine', unfinished_prompt_engine(after_response))
    with disclosure_target() as (agent, calls):
        # The oracle is private fixture input, not an API field or persisted
        # source report. Protected profile admission has its own acceptance tests.
        monkeypatch.setattr(module, 'discovery_engine', SimpleNamespace(
            discover_agents=AsyncMock(return_value=[agent])))
        with worker_claim('checkpoint', 'worker'):
            module._run_scan_in_thread('checkpoint', 'full', {}, {'timeout_seconds': 1}, cancelled)
        assert len(calls) == 1
        assert CANARY not in json.dumps(calls)
    assert len(acknowledged) == 1
    return acknowledged[0]


@pytest.mark.parametrize('interruption', ['deadline', 'cancel'])
def test_server_apis_retain_actual_unfinished_receipt(file_api, monkeypatch, caplog, interruption):
    module, client, fixture = file_api
    store, _, _ = fixture
    before = execute_unfinished(file_api, monkeypatch, interruption)
    expected = 'failed' if interruption == 'deadline' else 'cancelled'
    persisted = result(store, 'checkpoint')
    assert state(store, 'checkpoint') == persisted['status'] == expected
    for key in ('agents', 'security_results', 'risk_assessments', 'summary', 'checkpoint'):
        assert persisted[key] == before[key]
    asset = persisted['agents'][0]
    assert len(asset['check_evidence']) == len(asset['vulnerabilities']) == 1
    receipt = asset['check_evidence'][0]
    assert receipt['finding_id'] == asset['vulnerabilities'][0]['id']
    assert receipt['requests_attempted'] == receipt['responses_evaluated'] == 1
    assert not any(check['rule_id'] == receipt['rule_id'] for check in asset['checks'])
    stored_projection = projection(fixture)
    assert stored_projection[0]['overall_risk_score'] == 70
    assert stored_projection[2].count('terminal') == 1
    for _ in range(2):
        module.db.session.remove()
        for path in ('/api/scans/checkpoint/results', '/api/agents', '/api/agents?risk_level=high'):
            response = client.get(path, headers=headers(module))
            assert response.status_code == 200, response.json
            value = response.json['results'] if path.endswith('/results') else response.json
            assert len(value['agents']) == 1
            assert value['agents'][0]['risk_score'] == 70
            assert value['agents'][0]['risk_level'] == 'high'
            assert value['agents'][0]['risk_coverage_status'] == 'partial'
            if path.endswith('/results'):
                assert value['summary']['overall_risk_score'] == 70
                assert value['pipeline'] == persisted
            assert CANARY not in json.dumps(response.json)
        assert store.recover() == 0
    sarif = to_sarif(persisted)['runs'][0]
    assert not sarif['invocations'][0]['executionSuccessful']
    assert sarif['properties']['check_evidence'][0]['check_evidence'] == asset['check_evidence']
    assert len(sarif['results']) == 1
    assert CANARY not in json.dumps(persisted) + json.dumps(sarif) + caplog.text


@pytest.mark.parametrize('mutation', [
    'remove_receipt', 'change_receipt', 'duplicate_receipt', 'change_run',
    'remove_finding', 'wrong_terminal_counter', 'security_result_disagreement',
    'security_result_run_disagreement',
])
def test_file_backed_store_rejects_regressing_actual_receipts(file_api, monkeypatch, mutation):
    _, _, fixture = file_api
    store, _, _ = fixture
    checked = []

    def reject_while_running(before):
        assert state(store, 'checkpoint') == 'running'
        assert before['status'] == 'partial'
        prior_projection = projection(fixture)
        incoming = deepcopy(before)
        incoming['checkpoint']['sequence'] += 1
        agent = incoming['agents'][0]
        security = incoming['security_results'][0]
        if mutation == 'remove_receipt':
            agent['check_evidence'] = security['check_evidence'] = []
        elif mutation == 'change_receipt':
            agent['check_evidence'][0]['sequence'] = 2
            security['check_evidence'][0]['sequence'] = 2
        elif mutation == 'duplicate_receipt':
            agent['check_evidence'].append(deepcopy(agent['check_evidence'][0]))
            security['check_evidence'] = deepcopy(agent['check_evidence'])
        elif mutation == 'change_run':
            for item in (agent, security):
                item['check_evidence_run_id'] = 'c14d77ce-6fa3-436b-85a5-4f5b018517cc'
                item['check_evidence'][0]['run_id'] = item['check_evidence_run_id']
        elif mutation == 'remove_finding':
            agent['vulnerabilities'] = security['vulnerabilities'] = []
        elif mutation == 'wrong_terminal_counter':
            receipt = agent['check_evidence'][0]
            check = {key: receipt[key] for key in ('rule_id', 'probe_id', 'probe_version', 'evidence_context_id')}
            check.update(status='failed', outcome='confirmed', requests_attempted=0, responses_evaluated=0, reason=None)
            agent['checks'].append(check)
            security['checks'] = deepcopy(agent['checks'])
        elif mutation == 'security_result_disagreement':
            security['check_evidence'] = []
            security['vulnerabilities'] = []
        else:
            security['check_evidence_run_id'] = 'c14d77ce-6fa3-436b-85a5-4f5b018517cc'
            security['check_evidence'][0]['run_id'] = security['check_evidence_run_id']
        if mutation == 'change_run':
            # A valid new identity still cannot replace an acknowledged run.
            assert save(fixture, incoming) is False
        else:
            with pytest.raises(CheckpointError, match='Scan checkpoint could not be preserved'):
                save(fixture, incoming)
        assert result(store, 'checkpoint') == before
        assert projection(fixture) == prior_projection
        checked.append(True)

    execute_unfinished(file_api, monkeypatch, 'cancel', reject_while_running)
    assert checked == [True]
