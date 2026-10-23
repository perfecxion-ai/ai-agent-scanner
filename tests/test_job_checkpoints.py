"""Checkpoint persistence uses real file-backed SQLite and explicit claims."""

import json
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from datetime import datetime, timezone

import pytest
from sqlalchemy import create_engine, event, select, update
from sqlalchemy.exc import OperationalError

from src.core.contracts import CheckpointError, CheckRecord
from src.core.jobs import current_claim_owner, snapshot_id, worker_claim
from tests.test_api_auth import api as api, headers
from tests.test_jobs import enqueue, result, state, store as store


def report(sequence=1, *, scan_id='checkpoint', finding=True):
    check = CheckRecord('authorization_bypass', 'auth.sample', '2', 'completed',
                        'confirmed' if finding else 'inconclusive', 2, 2).to_dict()
    findings = [{'id': 'finding-1', 'rule_id': check['rule_id'], 'probe_id': check['probe_id'],
                 'probe_version': '2', 'evidence_status': 'confirmed', 'severity': 'high'}] if finding else []
    agent = dict(id='asset-1', name='Fixture', type='assistant', provider='fixture', model='test',
                 endpoint='http://192.0.2.1', discovery_method='fixture', security_status='partial',
                 checks=[check], vulnerabilities=findings, observations=[], risk_score=70 if finding else None,
                 risk_level='high' if finding else 'unknown', risk_scoring_policy='severity-floor-v2' if finding else None,
                 risk_coverage_status='partial' if finding else 'not_assessed')
    return dict(schema_version='1.0', check_schema_version='1.0', scan_id=scan_id, status='partial',
                checkpoint=dict(version='1.0', sequence=sequence, coverage='finalized_checks_only'),
                agents=[agent], security_results=[], risk_assessments=[], risk_assessment_status='partial' if finding else 'not_assessed',
                summary=dict(agents_discovered=1, vulnerabilities_found=len(findings), critical_risks=0,
                             overall_risk_score=70 if finding else None))


@pytest.fixture
def checkpoint_store(store, api):
    module, _ = api
    agents = module.DiscoveredAgentModel.__table__.to_metadata(store.scans.metadata)
    agents.create(store.engine)
    enqueue(store, 'checkpoint')
    assert store.claim('worker') == 'checkpoint'
    return store, agents, module


def save(fixture, value, *, owner='worker', final=False):
    store, agents, module = fixture
    rows = module._snapshot_rows('checkpoint', value, datetime.now(timezone.utc))
    method = store.save_result if final else store.save_checkpoint
    return method('checkpoint', value, agents, rows, owner=owner)


def projection(fixture):
    store, agents, _ = fixture
    with store.engine.connect() as connection:
        return (dict(connection.execute(select(store.scans)).mappings().one()),
                list(connection.execute(select(agents)).mappings()),
                list(connection.execute(select(store.audit.c.event)).scalars()))


def test_checkpoint_atomic_projection_and_stable_ids(checkpoint_store):
    store, _, _ = checkpoint_store
    value = report()
    assert save(checkpoint_store, value)
    first = projection(checkpoint_store)
    assert state(store, 'checkpoint') == 'running'
    assert result(store, 'checkpoint') == value
    assert first[0]['vulnerabilities_found'] == 1
    assert first[0]['overall_risk_score'] == 70
    assert first[1][0]['id'] == snapshot_id('checkpoint', 0)
    assert first[2] == ['claimed']
    newer = report(2)
    newer['agents'][0]['checks'].append(CheckRecord('fixture.other', 'fixture.other', '1',
                                                   'completed', 'inconclusive', 1, 1).to_dict())
    assert save(checkpoint_store, newer)
    second = projection(checkpoint_store)
    assert len(second[1]) == 1
    assert second[1][0]['discovered_at'] == first[1][0]['discovered_at']
    assert second[2] == ['claimed']
    newer['status'] = 'completed'
    assert save(checkpoint_store, newer, final=True)
    assert state(store, 'checkpoint') == 'completed'
    assert projection(checkpoint_store)[2] == ['claimed', 'terminal']
    assert result(store, 'checkpoint')['checkpoint']['sequence'] == 2


@pytest.mark.parametrize('owner', [None, '', 'stale', 'x' * 65])
def test_checkpoint_requires_actual_claim_owner(checkpoint_store, owner):
    assert not save(checkpoint_store, report(), owner=owner)
    assert result(checkpoint_store[0], 'checkpoint') is None
    assert projection(checkpoint_store)[1] == []


@pytest.mark.parametrize('mutation', ['same', 'older', 'drop_finding', 'changed_provenance', 'drop_check',
                                     'changed_outcome', 'drop_asset', 'reordered_assets', 'changed_endpoint'])
def test_checkpoint_rejects_stale_or_regressing_evidence(checkpoint_store, mutation):
    value = report(2)
    if mutation == 'reordered_assets':
        value['agents'].append({**deepcopy(value['agents'][0]), 'id': 'asset-2'})
        value['summary'].update(agents_discovered=2, vulnerabilities_found=2)
    assert save(checkpoint_store, value)
    newer = deepcopy(value)
    newer['checkpoint']['sequence'] = 3
    if mutation in ('same', 'older'):
        newer['checkpoint']['sequence'] = 2 if mutation == 'same' else 1
    elif mutation == 'drop_finding':
        newer['agents'][0]['vulnerabilities'] = []
    elif mutation == 'changed_provenance':
        newer['agents'][0]['vulnerabilities'][0]['probe_version'] = '3'
    elif mutation == 'drop_check':
        newer['agents'][0]['checks'] = []
    elif mutation == 'changed_outcome':
        newer['agents'][0]['checks'][0]['outcome'] = 'inconclusive'
    elif mutation == 'drop_asset':
        newer['agents'] = []
    elif mutation == 'reordered_assets':
        newer['agents'].reverse()
    else:
        newer['agents'][0]['endpoint'] = 'http://192.0.2.2'
    assert not save(checkpoint_store, newer)
    assert result(checkpoint_store[0], 'checkpoint') == value


@pytest.mark.parametrize('mutation', ['boolean', 'oversized', 'nonfinite', 'completed', 'extra_key'])
def test_checkpoint_envelope_is_strict_and_bounded(checkpoint_store, mutation):
    value = report()
    if mutation == 'boolean':
        value['checkpoint']['sequence'] = True
    elif mutation == 'oversized':
        value['padding'] = 'x' * (8 * 1024 * 1024)
    elif mutation == 'nonfinite':
        value['summary']['overall_risk_score'] = float('nan')
    elif mutation == 'completed':
        value['status'] = 'completed'
    else:
        value['checkpoint']['owner'] = 'worker'
    with pytest.raises(CheckpointError, match='Scan checkpoint could not be preserved'):
        save(checkpoint_store, value)
    assert result(checkpoint_store[0], 'checkpoint') is None


@pytest.mark.parametrize('action', ['finish', 'recover', 'cancel_finish', 'cancel_result'])
def test_terminal_paths_preserve_acknowledged_evidence(checkpoint_store, action):
    store, _, _ = checkpoint_store
    value = report()
    assert save(checkpoint_store, value)
    if action.startswith('cancel'):
        assert store.cancel('checkpoint') == 'cancel_requested'
        value = report(2)
        assert save(checkpoint_store, value)
        assert state(store, 'checkpoint') == 'cancel_requested'
    if action == 'recover':
        assert store.recover() == 1
        expected = 'interrupted'
        assert store.claim('next-worker') is None
    elif action == 'cancel_result':
        value['status'] = 'completed'
        assert save(checkpoint_store, value, final=True)
        expected = 'cancelled'
    else:
        store.finish('checkpoint', 'Scan deadline exceeded', owner='worker')
        expected = 'cancelled' if action.startswith('cancel') else 'failed'
    persisted = result(store, 'checkpoint')
    assert persisted['status'] == state(store, 'checkpoint') == expected
    assert persisted['agents'] == value['agents']
    assert persisted['summary']['overall_risk_score'] == 70
    assert projection(checkpoint_store)[0]['vulnerabilities_found'] == 1
    assert projection(checkpoint_store)[2].count('terminal') == 1
    assert not save(checkpoint_store, report(3))


@pytest.mark.parametrize('mutation', ['old_sequence', 'missing_checkpoint', 'removed_finding', 'changed_check'])
def test_final_result_cannot_erase_checkpoint(checkpoint_store, mutation):
    original = report(2)
    assert save(checkpoint_store, original)
    final = deepcopy(original)
    final['status'] = 'completed'
    if mutation == 'old_sequence':
        final['checkpoint']['sequence'] = 1
    elif mutation == 'missing_checkpoint':
        final.pop('checkpoint')
    elif mutation == 'removed_finding':
        final['agents'][0]['vulnerabilities'] = []
    else:
        final['agents'][0]['checks'][0]['evidence_context_id'] = 'different-context'
    if mutation == 'missing_checkpoint':
        with pytest.raises(CheckpointError):
            save(checkpoint_store, final, final=True)
    else:
        assert not save(checkpoint_store, final, final=True)
    assert result(checkpoint_store[0], 'checkpoint') == original
    assert state(checkpoint_store[0], 'checkpoint') == 'running'


def test_checkpoint_rolls_back_all_projection_writes(checkpoint_store):
    store, _, _ = checkpoint_store
    original = report()
    assert save(checkpoint_store, original)
    before = projection(checkpoint_store)

    def fail_report(connection, cursor, statement, parameters, context, many):
        if statement.startswith('INSERT INTO scan_result'):
            raise RuntimeError('synthetic-private-database-error')

    event.listen(store.engine, 'before_cursor_execute', fail_report)
    try:
        with pytest.raises(RuntimeError, match='synthetic-private'):
            save(checkpoint_store, report(2))
    finally:
        event.remove(store.engine, 'before_cursor_execute', fail_report)
    assert projection(checkpoint_store) == before
    assert result(store, 'checkpoint') == original


def test_stale_worker_cannot_finalize_replacement_claim(checkpoint_store):
    store, _, _ = checkpoint_store
    assert save(checkpoint_store, report())
    with store.engine.begin() as connection:
        connection.execute(update(store.jobs).values(owner='replacement'))
    store.finish('checkpoint', 'Stale worker failed', owner='worker')
    assert state(store, 'checkpoint') == 'running'
    assert not save(checkpoint_store, report(2))
    assert not save(checkpoint_store, {**report(), 'status': 'completed'}, final=True)


def test_claim_context_is_scoped_and_reset_after_exception():
    assert current_claim_owner('a') is None
    with pytest.raises(RuntimeError), worker_claim('a', 'owner-a'):
        assert current_claim_owner('a') == 'owner-a'
        assert current_claim_owner('b') is None
        with worker_claim('b', 'owner-b'):
            assert current_claim_owner('b') == 'owner-b'
        assert current_claim_owner('a') == 'owner-a'
        raise RuntimeError('fixture')
    assert current_claim_owner('a') is None


def test_sqlite_write_contention_is_bounded_and_timeout_restored(checkpoint_store):
    store, _, _ = checkpoint_store
    assert save(checkpoint_store, report())
    with store.engine.connect() as blocker:
        blocker.exec_driver_sql('BEGIN IMMEDIATE')
        start = time.monotonic()
        with pytest.raises(OperationalError, match='locked'):
            save(checkpoint_store, report(2))
        elapsed = time.monotonic() - start
        blocker.rollback()
    assert elapsed < 2.5
    with store.engine.connect() as connection:
        assert connection.exec_driver_sql('PRAGMA busy_timeout').scalar_one() == 5000
    assert result(store, 'checkpoint')['checkpoint']['sequence'] == 1


def test_checkpoint_and_cancel_race_preserves_both_outcomes(checkpoint_store):
    store, _, _ = checkpoint_store
    assert save(checkpoint_store, report())
    ready = threading.Barrier(2)

    def checkpoint():
        ready.wait(3)
        return save(checkpoint_store, report(2))

    def cancel():
        ready.wait(3)
        return store.cancel('checkpoint')

    with ThreadPoolExecutor(max_workers=2) as pool:
        write, cancellation = pool.submit(checkpoint), pool.submit(cancel)
        assert write.result(timeout=3)
        assert cancellation.result(timeout=3) == 'cancel_requested'
    assert state(store, 'checkpoint') == 'cancel_requested'
    assert result(store, 'checkpoint')['checkpoint']['sequence'] == 2
    store.finish('checkpoint', owner='worker')
    assert result(store, 'checkpoint')['status'] == 'cancelled'


@pytest.fixture
def file_api(api, monkeypatch, tmp_path):
    module, client = api
    module.db.session.remove()
    engine = create_engine(f"sqlite:///{tmp_path / 'api-checkpoints.db'}")
    with engine.connect() as connection:
        connection.exec_driver_sql('PRAGMA journal_mode=WAL')
    module.db.metadata.create_all(engine)
    monkeypatch.setitem(module.db.engines, None, engine)
    store = module._get_job_store()
    enqueue(store, 'checkpoint')
    assert store.claim('worker') == 'checkpoint'
    fixture = (store, module.DiscoveredAgentModel.__table__, module)
    yield module, client, fixture
    module.db.session.remove()
    engine.dispose()


@pytest.mark.parametrize('route', ['results', 'agents'])
def test_api_reads_one_revision_during_concurrent_checkpoint(file_api, route):
    module, client, fixture = file_api
    store, _, _ = fixture
    first = report(finding=False)
    assert save(fixture, first)
    second = report(2, finding=True)
    second['agents'][0]['checks'] = first['agents'][0]['checks'] + [
        {**second['agents'][0]['checks'][0], 'probe_id': 'auth.other'}]
    second['agents'][0]['vulnerabilities'][0]['probe_id'] = 'auth.other'
    fired = False

    def interleave(connection, cursor, statement, parameters, context, many):
        nonlocal fired
        boundary = 'FROM scan_session' if route == 'results' else 'FROM discovered_agent'
        if not fired and statement.startswith('SELECT') and boundary in statement:
            fired = True
            assert save(fixture, second)

    event.listen(store.engine, 'after_cursor_execute', interleave)
    try:
        path = '/api/scans/checkpoint/results' if route == 'results' else '/api/agents'
        response = client.get(path, headers=headers(module))
    finally:
        event.remove(store.engine, 'after_cursor_execute', interleave)
    assert fired
    assert response.status_code == 200, response.json
    value = response.json['results'] if route == 'results' else response.json
    assert value['agents'][0]['risk_score'] is None
    if route == 'results':
        assert value['summary']['vulnerabilities_found'] == 0
        assert value['pipeline']['checkpoint']['sequence'] == 1
        assert value['agents'][0]['vulnerabilities'] == []
    assert result(store, 'checkpoint')['checkpoint']['sequence'] == 2
    assert 'worker' not in json.dumps(response.json)


@pytest.mark.asyncio
@pytest.mark.parametrize('failure', ['sink_exception', 'sink_rejection', 'write_budget'])
async def test_server_checkpoint_failure_stops_pipeline_with_static_error(file_api, monkeypatch, caplog, failure):
    module, _, fixture = file_api
    store, _, _ = fixture
    continued = []

    async def pipeline(*args, checkpoint_callback, **kwargs):
        await checkpoint_callback(report())
        continued.append('probe-after-checkpoint')
        return {**report(), 'status': 'completed'}

    monkeypatch.setattr(module, 'run_pipeline', pipeline)
    monkeypatch.setattr(module, '_get_job_store', lambda: store)
    if failure == 'write_budget':
        monkeypatch.setattr(module, 'MAX_CHECKPOINT_TOTAL_BYTES', 1)
    elif failure == 'sink_rejection':
        monkeypatch.setattr(store, 'save_checkpoint', lambda *args, **kwargs: False)
    else:
        def fail(*args, **kwargs):
            raise RuntimeError('synthetic-secret-in-database-error')
        monkeypatch.setattr(store, 'save_checkpoint', fail)
    with worker_claim('checkpoint', 'worker'):
        await module._execute_scan('checkpoint', 'full', {}, {})
    assert continued == []
    assert state(store, 'checkpoint') == 'failed'
    assert result(store, 'checkpoint')['error'] == 'Scan execution failed'
    assert 'synthetic-secret' not in caplog.text
    assert 'synthetic-secret' not in json.dumps(result(store, 'checkpoint'))


@pytest.mark.asyncio
async def test_server_finalization_failure_preserves_committed_evidence(file_api, monkeypatch, caplog):
    module, _, fixture = file_api
    store, _, _ = fixture

    async def pipeline(*args, checkpoint_callback, **kwargs):
        value = report()
        await checkpoint_callback(value)
        value['agents'][0]['vulnerabilities'] = []
        value['status'] = 'completed'
        return value

    monkeypatch.setattr(module, 'run_pipeline', pipeline)
    with worker_claim('checkpoint', 'worker'):
        await module._execute_scan('checkpoint', 'full', {}, {})
    persisted = result(store, 'checkpoint')
    assert persisted['status'] == 'failed'
    assert persisted['agents'][0]['vulnerabilities'] == report()['agents'][0]['vulnerabilities']
    assert persisted['summary']['overall_risk_score'] == 70
    assert projection(fixture)[0]['vulnerabilities_found'] == 1
    assert caplog.messages == ['Scan execution failed']


@pytest.mark.asyncio
async def test_unclaimed_direct_server_execution_cannot_probe(file_api, monkeypatch):
    module, _, fixture = file_api
    store, _, _ = fixture
    calls = []

    async def pipeline(*args, **kwargs):
        calls.append(True)

    monkeypatch.setattr(module, 'run_pipeline', pipeline)
    await module._execute_scan('checkpoint', 'full', {}, {})
    assert calls == []
    assert state(store, 'checkpoint') == 'running'
    assert result(store, 'checkpoint') is None


@pytest.mark.asyncio
async def test_server_cumulative_limit_retains_last_committed_evidence(file_api, monkeypatch, caplog):
    module, _, fixture = file_api
    store, _, _ = fixture
    first = report()
    rows = module._snapshot_rows('checkpoint', first, datetime.now(timezone.utc))
    encoded = json.dumps([first, [{key: value for key, value in row.items()
                                  if key != 'discovered_at'} for row in rows]],
                         sort_keys=True, allow_nan=False, separators=(',', ':'))
    monkeypatch.setattr(module, 'MAX_CHECKPOINT_TOTAL_BYTES', len(encoded.encode('utf-8')) * 3 // 2)
    completed_callbacks = []

    async def pipeline(*args, checkpoint_callback, **kwargs):
        await checkpoint_callback(first)
        completed_callbacks.append(1)
        await checkpoint_callback(report(2))
        completed_callbacks.append(2)
        return {**report(2), 'status': 'completed'}

    monkeypatch.setattr(module, 'run_pipeline', pipeline)
    with worker_claim('checkpoint', 'worker'):
        await module._execute_scan('checkpoint', 'full', {}, {})
    assert completed_callbacks == [1]
    persisted = result(store, 'checkpoint')
    assert persisted['checkpoint']['sequence'] == 1
    assert persisted['agents'] == first['agents']
    assert persisted['status'] == 'failed'
    assert projection(fixture)[0]['overall_risk_score'] == 70
    assert caplog.messages == ['Scan execution failed']
