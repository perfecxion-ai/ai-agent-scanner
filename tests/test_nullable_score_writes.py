"""Real SQLite writers preserve unknown, supported zero and partial evidence."""

from copy import deepcopy
from datetime import datetime, timezone

import pytest
from sqlalchemy import event, insert, select, update

from tests.test_api_auth import api as api
from tests.test_historical_prompt_projection import access_asset
from tests.test_jobs import enqueue, result, state, store as store
from tests.test_prompt_legacy_compatibility import legacy_prompt_report
from tests.test_historical_tenant_projection import legacy_tenant_report


async def document(kind, *, partial=False):
    if kind in {'legacy_prompt', 'legacy_tenant'}:
        value = legacy_prompt_report() if kind == 'legacy_prompt' else legacy_tenant_report()
        agent = value['agents'][0]
    else:
        agent = await access_asset(disclose=kind == 'confirmed', identifier='asset-1')
        value = {'schema_version': '1.0', 'check_schema_version': '1.0', 'agents': [agent],
                 'summary': {'overall_risk_score': agent['risk_score']}}
        if kind == 'unknown':
            agent.update(checks=[], vulnerabilities=[], risk_score=None, risk_level='unknown',
                         risk_scoring_policy=None, risk_coverage_status='not_assessed')
            value['summary']['overall_risk_score'] = None
    agent.update(type='assistant', discovery_method='fixture',
                 security_status='partial' if partial else 'completed')
    if kind != 'unknown':
        agent['risk_coverage_status'] = 'partial' if partial else 'sampled'
    value.update(scan_id='persist', status='partial' if partial else 'completed',
                 scan_type='security_only', security_results=[], risk_assessments=[],
                 risk_assessment_status='not_assessed' if kind == 'unknown' else 'partial' if partial else 'completed')
    value['summary'].update(agents_discovered=1, vulnerabilities_found=len(agent['vulnerabilities']),
                            critical_risks=0)
    return value


@pytest.fixture
def score_store(store, api):
    module, _ = api
    agents = module.DiscoveredAgentModel.__table__.to_metadata(store.scans.metadata)
    agents.create(store.engine)
    enqueue(store, 'persist')
    assert store.claim('owner') == 'persist'
    return store, agents, module


def cached(fixture):
    store, agents, _ = fixture
    with store.engine.connect() as connection:
        return (connection.scalar(select(store.scans.c.overall_risk_score)),
                connection.execute(select(agents.c.risk_score, agents.c.risk_level)).one())


@pytest.mark.asyncio
@pytest.mark.parametrize('kind,partial,expected', [
    ('unknown', False, None), ('unknown', True, None),
    ('zero', False, 0.0), ('zero', True, None),
    ('confirmed', False, 70.0), ('confirmed', True, 70.0),
    ('legacy_prompt', False, None), ('legacy_prompt', True, None),
    ('legacy_tenant', False, None), ('legacy_tenant', True, None),
])
async def test_terminal_writer_caches_only_supported_evidence(score_store, kind, partial, expected):
    store, agents, module = score_store
    output = await document(kind, partial=partial)
    original = deepcopy(output)
    snapshots = module._snapshot_rows('persist', output, datetime.now(timezone.utc))
    assert snapshots[0]['risk_score'] == expected
    assert snapshots[0]['risk_level'] == ('unknown' if expected is None else 'high' if expected else 'minimal')
    # A direct store caller cannot promote its own snapshot scalar over the report.
    snapshots[0].update(risk_score=99.0, risk_level='critical')
    original_snapshots = deepcopy(snapshots)
    assert store.save_result('persist', output, agents, snapshots, owner='owner')
    assert cached(score_store) == (expected, (expected, 'unknown' if expected is None else 'high' if expected else 'minimal'))
    assert snapshots == original_snapshots and output == original
    assert result(store, 'persist') == original


@pytest.mark.asyncio
async def test_new_rows_start_unknown_without_zero_defaults(api):
    module, _ = api
    module.db.session.add(module.ScanSession(
        id='new-null-scan', organization_id='tenant-a', scan_name='Fixture', scan_type='full',
        status='queued', target_scope={}, scan_config={}))
    module.db.session.add(module.DiscoveredAgentModel(
        id='new-null-agent', scan_id='new-null-scan', agent_name='Fixture', agent_type='assistant',
        discovery_method='fixture'))
    module.db.session.commit()
    module.db.session.expire_all()
    assert module.db.session.get(module.ScanSession, 'new-null-scan').overall_risk_score is None
    assert module.db.session.get(module.DiscoveredAgentModel, 'new-null-agent').risk_score is None
    for column in (module.ScanSession.__table__.c.overall_risk_score,
                   module.DiscoveredAgentModel.__table__.c.risk_score):
        assert column.nullable is True and column.default is None and column.server_default is None


@pytest.mark.asyncio
@pytest.mark.parametrize('operation', ['finish', 'cancel', 'recover'])
async def test_terminal_paths_repair_unknown_scan_cache(score_store, operation):
    store, _, _ = score_store
    output = await document('unknown')
    with store.engine.begin() as connection:
        connection.execute(insert(store.results).values(scan_id='persist', result=output))
        connection.execute(update(store.scans).values(overall_risk_score=99.0))
    if operation == 'finish':
        store.finish('persist', 'Synthetic failure', owner='owner')
    elif operation == 'cancel':
        assert store.cancel('persist') == 'cancel_requested'
        store.finish('persist', owner='owner')
    else:
        assert store.recover() == 1
    with store.engine.connect() as connection:
        assert connection.scalar(select(store.scans.c.overall_risk_score)) is None
    assert state(store, 'persist') in {'failed', 'cancelled', 'interrupted'}


@pytest.mark.asyncio
async def test_cache_and_archive_updates_roll_back_with_terminal_event(score_store):
    store, agents, module = score_store
    output = await document('confirmed', partial=True)
    snapshots = module._snapshot_rows('persist', output, datetime.now(timezone.utc))
    with store.engine.begin() as connection:
        connection.execute(update(store.scans).values(overall_risk_score=0.0))
    def fail(connection, cursor, statement, parameters, context, many):
        if statement.startswith('INSERT INTO audit_event'):
            raise RuntimeError('Synthetic terminal rollback')
    event.listen(store.engine, 'before_cursor_execute', fail)
    try:
        with pytest.raises(RuntimeError, match='Synthetic terminal rollback'):
            store.save_result('persist', output, agents, snapshots, owner='owner')
    finally:
        event.remove(store.engine, 'before_cursor_execute', fail)
    with store.engine.connect() as connection:
        assert connection.scalar(select(store.scans.c.overall_risk_score)) == 0.0
        assert connection.execute(select(agents)).all() == []
    assert result(store, 'persist') is None and state(store, 'persist') == 'running'
    assert store.save_result('persist', output, agents, snapshots, owner='owner')
    assert cached(score_store) == (70.0, (70.0, 'high'))
