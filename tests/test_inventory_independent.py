"""Independent inventory traversal and cursor isolation with owned SQLite data."""

import asyncio
import json
import time
from copy import deepcopy
from datetime import datetime, timedelta

import pytest
from sqlalchemy import create_engine, event, insert, text
from itsdangerous import TimestampSigner

from src.core.contracts import CheckRecord
from tests.controlled_access import result as controlled_result
from tests.test_api_auth import api as api, headers


RISK_FIELDS = (
    'risk_score', 'risk_level', 'risk_coverage_status', 'risk_scoring_policy',
    'risk_assessment_status', 'security_status',
)
HIGH = dict(zip(RISK_FIELDS, (70, 'high', 'partial', 'severity-floor-v2', 'partial', 'partial')))
ZERO = dict(zip(RISK_FIELDS, (0, 'minimal', 'sampled', 'severity-floor-v2', 'completed', 'completed')))


def unknown(security='unknown'):
    return dict(zip(RISK_FIELDS, (None, 'unknown', 'not_assessed', None, 'not_assessed', security)))


def sources():
    current = asyncio.run(controlled_result())
    zero = {'id': 'zero', 'name': 'Assessed zero', **ZERO,
            **{key: current[key] for key in ('provider', 'model', 'checks')},
            'vulnerabilities': []}
    check = CheckRecord('fixture.disclosure', 'fixture.probe', '1', 'completed',
                        'confirmed', 1, 1).to_dict()
    high = {'id': 'high', 'name': 'Confirmed partial', **HIGH, 'checks': [check],
            'vulnerabilities': [{'rule_id': 'fixture.disclosure', 'probe_id': 'fixture.probe',
                                 'probe_version': '1', 'severity': 'high',
                                 'evidence_status': 'confirmed'}]}
    legacy = {**deepcopy(high), 'id': 'legacy', 'security_status': 'completed',
              'risk_coverage_status': 'sampled'}
    legacy.pop('risk_scoring_policy')
    unassessed = {'id': 'unassessed', 'name': 'No assessment',
                  'security_status': 'not_tested', 'checks': [], 'vulnerabilities': []}
    return {'zero': zero, 'high': high, 'legacy': legacy, 'unassessed': unassessed}


def archive(agents):
    return {'schema_version': '1.0', 'check_schema_version': '1.0',
            'status': 'partial', 'risk_assessment_status': 'partial',
            'agents': list(agents), 'summary': {'overall_risk_score': 70}}


def populate(module, count=10000):
    """Mix organizations, scans, ties, aliases, and deliberately wrong SQL caches."""
    templates = sources()
    scans, reports, observations, expected = {}, {}, [], []
    for number in range(count):
        org = 'tenant-a' if number % 5 < 3 else 'tenant-b'
        scan = 'inventory-' + str(number % 20)
        if scan not in scans:
            scans[scan] = {'id': scan, 'organization_id': org, 'scan_name': scan,
                           'scan_type': 'full', 'status': 'partial',
                           'target_scope': {}, 'scan_config': {}, 'overall_risk_score': 99}
            reports[scan] = [deepcopy(value) for value in templates.values()]
        identifier = 'observation-%05d' % number
        kind = 'assistant' if number % 3 == 0 else 'worker'
        when = datetime(2024, 1, 1) + timedelta(seconds=number // 7)
        case = number % 8
        alias = ('high', 'zero', 'legacy', 'unassessed', None, identifier, identifier, 'high')[case]
        metadata = {'asset_id': alias}
        risk = (HIGH, ZERO, unknown('completed'), unknown('not_tested'),
                unknown(), HIGH, ZERO, HIGH)[case]
        if case == 4:
            metadata = {'asset_id': ['high']}
        elif case in {5, 6}:
            metadata = [] if case == 5 else {}
            agent = deepcopy(templates['high' if case == 5 else 'zero'])
            agent['id'] = identifier
            reports[scan].append(agent)
        observations.append({'id': identifier, 'scan_id': scan, 'agent_name': identifier,
                             'agent_type': kind, 'provider': 'fixture', 'discovery_method': 'fixture',
                             'risk_score': 99 if risk['risk_score'] != 70 else 0,
                             'risk_level': 'critical', 'metadata': metadata, 'discovered_at': when})
        expected.append({'id': identifier, 'asset_id': alias, 'type': kind,
                         'organization': org, 'scan': scan, 'when': when, **risk})
    module.db.session.execute(insert(module.ScanSession.__table__), list(scans.values()))
    module.db.session.execute(insert(module.ScanResult.__table__), [
        {'scan_id': key, 'result': archive(agents)} for key, agents in reports.items()])
    module.db.session.execute(insert(module.DiscoveredAgentModel.__table__), observations)
    module.db.session.commit()
    return sorted(expected, key=lambda item: (-item['when'].timestamp(), item['id']))


def page(module, client, query=None, *, org='tenant-a'):
    response = client.get('/api/agents', query_string=query or {}, headers=headers(module, org))
    assert response.status_code == 200, response.json
    value = response.json
    assert value['success'] is True
    assert type(value['coverage']['search_complete']) is bool
    assert value['coverage']['search_complete'] is (value['next_cursor'] is None)
    assert value['coverage']['projected_report_bytes'] <= value['coverage']['interpreted_source_bytes'] <= 16 * 1024 * 1024
    return value


def traverse(module, client, query=None, *, org='tenant-a'):
    query = dict(query or {})
    found, cursors = [], set()
    for _ in range(1000):
        body = page(module, client, query, org=org)
        found.extend(body['agents'])
        cursor = body['next_cursor']
        if cursor is None:
            return found
        assert isinstance(cursor, str) and cursor not in cursors
        cursors.add(cursor)
        query['cursor'] = cursor
    pytest.fail('Inventory traversal failed to terminate within its finite fixture')


def compare_rows(actual, expected):
    assert [item['id'] for item in actual] == [item['id'] for item in expected]
    assert len({item['id'] for item in actual}) == len(actual)
    for got, wanted in zip(actual, expected):
        assert got['asset_id'] == wanted['asset_id']
        assert got['type'] == wanted['type']
        assert {field: got[field] for field in RISK_FIELDS} == {
            field: wanted[field] for field in RISK_FIELDS}


def test_ten_thousand_observations_have_exhaustive_canonical_filtered_traversal(api):
    module, client = api
    expected = populate(module)
    assert len(expected) == 10000
    assert sum(item['organization'] == 'tenant-a' for item in expected) == 6000
    for org, filters in [
        ('tenant-a', {}), ('tenant-b', {'risk_level': 'high'}),
        ('tenant-a', {'risk_level': 'unknown', 'agent_type': 'assistant'}),
        ('tenant-b', {'risk_level': 'minimal', 'agent_type': 'worker'}),
    ]:
        wanted = [item for item in expected if item['organization'] == org and all(
            item['type' if key == 'agent_type' else key] == value for key, value in filters.items())]
        compare_rows(traverse(module, client, {'limit': 100, **filters}, org=org), wanted)
    assert 'observation-00000' in {item['id'] for item in traverse(
        module, client, {'risk_level': 'high', 'limit': 100})}


@pytest.mark.parametrize('value', ['0', '101', '-1', '1.5', 'true', '', ' 1', '1e2'])
def test_inventory_rejects_invalid_limit_before_sql(api, value):
    module, client = api
    statements = []
    def observed(connection, cursor, statement, parameters, context, executemany):
        statements.append(statement)
    event.listen(module.db.engine, 'before_cursor_execute', observed)
    try:
        response = client.get('/api/agents', query_string={'limit': value}, headers=headers(module))
    finally:
        event.remove(module.db.engine, 'before_cursor_execute', observed)
    assert response.status_code == 400
    assert statements == []


@pytest.mark.parametrize('value', ['', 'invalid', 'x' * 9000, 'e30.e30.invalid'])
def test_inventory_rejects_invalid_cursor_before_sql(api, value):
    module, client = api
    statements = []
    def observed(connection, cursor, statement, parameters, context, executemany):
        statements.append(statement)
    event.listen(module.db.engine, 'before_cursor_execute', observed)
    try:
        response = client.get('/api/agents', query_string={'cursor': value}, headers=headers(module))
    finally:
        event.remove(module.db.engine, 'before_cursor_execute', observed)
    assert response.status_code == 400
    assert statements == []


@pytest.mark.parametrize('change', ['tenant', 'limit', 'risk_level', 'agent_type', 'signature'])
def test_cursor_cannot_cross_its_signed_query_scope(api, change):
    module, client = api
    populate(module, 60)
    query = {'limit': 1, 'risk_level': 'high', 'agent_type': 'worker'}
    first = page(module, client, query)
    assert first['next_cursor']
    query['cursor'] = first['next_cursor']
    org = 'tenant-a'
    if change == 'tenant':
        org = 'tenant-b'
    elif change == 'signature':
        query['cursor'] = query['cursor'][:-8] + 'tampered'
    else:
        query[change] = {'limit': 2, 'risk_level': 'minimal', 'agent_type': 'assistant'}[change]
    statements = []
    def observed(connection, cursor, statement, parameters, context, executemany):
        statements.append(statement)
    event.listen(module.db.engine, 'before_cursor_execute', observed)
    try:
        response = client.get('/api/agents', query_string=query, headers=headers(module, org))
    finally:
        event.remove(module.db.engine, 'before_cursor_execute', observed)
    assert response.status_code == 400, response.json
    assert statements == []


@pytest.mark.parametrize('change', [
    'observation-update', 'observation-delete', 'observation-insert',
    'report-update', 'report-delete', 'session-owner', 'session-insert',
])
def test_committed_source_mutations_make_cursor_stale(api, change):
    module, client = api
    populate(module, 60)
    if change == 'session-insert':
        module.db.session.add(module.DiscoveredAgentModel(
            id='orphan-observation', scan_id='new-scan', agent_name='Owned orphan fixture',
            agent_type='worker', discovery_method='fixture'))
        module.db.session.commit()
    query = {'limit': 1}
    cursor = page(module, client, query)['next_cursor']
    assert cursor
    observation = module.db.session.get(module.DiscoveredAgentModel, 'observation-00000')
    if change == 'observation-update':
        observation.agent_type = 'changed'
    elif change == 'observation-delete':
        module.db.session.delete(observation)
    elif change == 'observation-insert':
        module.db.session.add(module.DiscoveredAgentModel(
            id='new-observation', scan_id=observation.scan_id, agent_name='Added fixture',
            agent_type='worker', discovery_method='fixture'))
    elif change == 'report-update':
        report = module.db.session.get(module.ScanResult, observation.scan_id)
        value = deepcopy(report.result)
        value['unused_revision'] = 'changed'
        report.result = value
    elif change == 'report-delete':
        module.db.session.delete(module.db.session.get(module.ScanResult, observation.scan_id))
    elif change == 'session-owner':
        module.db.session.get(module.ScanSession, observation.scan_id).organization_id = 'tenant-b'
    else:
        module.db.session.add(module.ScanSession(
            id='new-scan', organization_id='tenant-a', scan_name='Added scan',
            scan_type='full', status='completed', target_scope={}, scan_config={}))
    module.db.session.commit()
    response = client.get('/api/agents', query_string={**query, 'cursor': cursor}, headers=headers(module))
    assert response.status_code == 409, response.json
    assert response.json['code'] == 'stale_cursor'


@pytest.mark.parametrize('change', ['other-organization', 'rollback'])
def test_unrelated_or_rolled_back_mutation_preserves_cursor(api, change):
    module, client = api
    expected = populate(module, 60)
    first = page(module, client, {'limit': 1})
    cursor = first['next_cursor']
    assert cursor
    identifier = 'observation-00004' if change == 'other-organization' else 'observation-00000'
    module.db.session.get(module.DiscoveredAgentModel, identifier).agent_name = 'Changed name'
    module.db.session.flush()
    if change == 'rollback':
        module.db.session.rollback()
    else:
        module.db.session.commit()
    rest = traverse(module, client, {'limit': 1, 'cursor': cursor})
    compare_rows(first['agents'] + rest, [item for item in expected if item['organization'] == 'tenant-a'])


def test_normalized_risk_filter_can_continue_with_same_cursor(api):
    module, client = api
    populate(module, 60)
    first = page(module, client, {'limit': 1, 'risk_level': ' HIGH '})
    assert first['next_cursor']
    second = page(module, client, {'limit': 1, 'risk_level': 'high', 'cursor': first['next_cursor']})
    assert {row['id'] for row in first['agents']}.isdisjoint(row['id'] for row in second['agents'])


@pytest.mark.parametrize('source,malformation', [
    ('report', 'syntax'), ('report', 'oversized'), ('report', 'depth'),
    ('metadata', 'syntax'), ('metadata', 'oversized'), ('metadata', 'depth'),
])
def test_unreadable_sources_are_unavailable_instead_of_unknown_passes(api, source, malformation):
    module, client = api
    populate(module, 1)
    if malformation == 'syntax':
        raw = '{broken'
    elif malformation == 'oversized':
        raw = ' ' * (8 * 1024 * 1024) + '{}'
    else:
        nested = 0
        for _ in range(64):
            nested = [nested]
        raw = json.dumps({'padding': nested})
    if source == 'report':
        statement = 'UPDATE scan_result SET result=:raw WHERE scan_id=:identifier'
        identifier = 'inventory-0'
    else:
        statement = 'UPDATE discovered_agent SET metadata=:raw WHERE id=:identifier'
        identifier = 'observation-00000'
    module.db.session.execute(text(statement), {'raw': raw, 'identifier': identifier})
    module.db.session.commit()
    response = client.get('/api/agents', query_string={'risk_level': 'high'}, headers=headers(module))
    assert response.status_code == 503, response.json
    assert response.json['code'] == 'inventory_projection_unavailable'
    assert not response.json.get('agents')


def test_single_request_candidate_work_is_capped_with_honest_sparse_continuation(api):
    module, client = api
    populate(module, 1000)
    module.db.session.execute(module.DiscoveredAgentModel.__table__.update().values(
        metadata={'asset_id': 'missing-canonical-asset'}))
    module.db.session.commit()
    first = page(module, client, {'limit': 100, 'risk_level': 'high'})
    assert first['agents'] == []
    assert first['coverage']['evaluated_candidates'] == 500
    assert first['coverage']['projected_reports'] <= 32
    assert first['coverage']['projected_report_bytes'] <= 16 * 1024 * 1024
    assert first['coverage']['search_complete'] is False
    assert first['next_cursor']
    last = page(module, client, {'limit': 100, 'risk_level': 'high', 'cursor': first['next_cursor']})
    assert last['agents'] == []
    assert last['coverage']['search_complete'] is True
    assert last['coverage']['evaluated_candidates'] == 100


@pytest.mark.parametrize('change', ['expired', 'future', 'signing-key'])
def test_cursor_expiry_and_signing_key_rotation_fail_before_sql(api, monkeypatch, change):
    module, client = api
    populate(module, 60)
    now = int(time.time())
    monkeypatch.setattr(TimestampSigner, 'get_timestamp', lambda self: now + (1000 if change == 'future' else 0))
    first = page(module, client, {'limit': 1})
    assert first['next_cursor']
    monkeypatch.setattr(TimestampSigner, 'get_timestamp', lambda self: now + (1000 if change == 'expired' else 0))
    if change == 'signing-key':
        monkeypatch.setitem(module.app.config, 'SECRET_KEY', 'rotated-fixture-signing-key-' * 4)
    statements = []
    def observed(connection, cursor, statement, parameters, context, executemany):
        statements.append(statement)
    event.listen(module.db.engine, 'before_cursor_execute', observed)
    try:
        response = client.get('/api/agents', query_string={
            'limit': 1, 'cursor': first['next_cursor']}, headers=headers(module))
    finally:
        event.remove(module.db.engine, 'before_cursor_execute', observed)
    assert response.status_code == 400, response.json
    assert response.json['code'] == 'invalid_cursor'
    assert statements == []


def test_projection_policy_change_invalidates_cursor_before_sql(api, monkeypatch):
    from src.core import inventory
    module, client = api
    populate(module, 60)
    first = page(module, client, {'limit': 1})
    assert first['next_cursor']
    monkeypatch.setattr(inventory, 'PROJECTION_POLICY', 'independent-new-policy')
    statements = []
    def observed(connection, cursor, statement, parameters, context, executemany):
        statements.append(statement)
    event.listen(module.db.engine, 'before_cursor_execute', observed)
    try:
        response = client.get('/api/agents', query_string={
            'limit': 1, 'cursor': first['next_cursor']}, headers=headers(module))
    finally:
        event.remove(module.db.engine, 'before_cursor_execute', observed)
    assert response.status_code == 409, response.json
    assert response.json['code'] == 'stale_cursor'
    assert statements == []


def independent_scans(module, count, *, padding=0):
    high = sources()['high']
    for number in range(count):
        scan = 'separate-scan-%03d' % number
        report = archive([deepcopy(high)])
        if padding:
            report['unused_padding'] = 'x' * padding
        module.db.session.add(module.ScanSession(
            id=scan, organization_id='tenant-a', scan_name=scan, scan_type='full',
            status='partial', target_scope={}, scan_config={}))
        module.db.session.add(module.ScanResult(scan_id=scan, result=report))
        module.db.session.add(module.DiscoveredAgentModel(
            id='separate-observation-%03d' % number, scan_id=scan, agent_name=scan,
            agent_type='assistant', discovery_method='fixture',
            metadata_json={'asset_id': 'high'}, discovered_at=datetime(2024, 1, 1)))
    module.db.session.commit()


def test_report_projection_cap_returns_continuation_without_missing_observations(api):
    module, client = api
    independent_scans(module, 40)
    first = page(module, client, {'limit': 100})
    assert first['coverage']['projected_reports'] == 32
    assert first['coverage']['evaluated_candidates'] == len(first['agents']) == 32
    assert first['next_cursor']
    last = page(module, client, {'limit': 100, 'cursor': first['next_cursor']})
    assert last['coverage']['projected_reports'] == len(last['agents']) == 8
    assert last['coverage']['search_complete'] is True
    got = first['agents'] + last['agents']
    assert [row['id'] for row in got] == ['separate-observation-%03d' % n for n in range(40)]
    assert all({field: row[field] for field in RISK_FIELDS} == HIGH for row in got)


def test_report_byte_cap_advances_without_skipping_next_source(api):
    module, client = api
    independent_scans(module, 3, padding=6 * 1024 * 1024)
    first = page(module, client, {'limit': 100})
    assert first['coverage']['projected_reports'] == len(first['agents']) == 2
    assert first['coverage']['projected_report_bytes'] <= 16 * 1024 * 1024
    assert first['next_cursor']
    last = page(module, client, {'limit': 100, 'cursor': first['next_cursor']})
    assert last['coverage']['projected_reports'] == len(last['agents']) == 1
    assert last['coverage']['search_complete'] is True
    assert [row['id'] for row in first['agents'] + last['agents']] == [
        'separate-observation-%03d' % n for n in range(3)]


@pytest.mark.parametrize('typed', [False, True], ids=['tenant-order', 'tenant-type-order'])
def test_actual_candidate_query_uses_ownership_and_observation_indexes(api, typed):
    module, client = api
    populate(module, 1000)
    statements = []
    def observed(connection, cursor, statement, parameters, context, executemany):
        if 'discovered_agent' in statement and 'ORDER BY' in statement and 'LIMIT' in statement:
            statements.append((statement, parameters))
    event.listen(module.db.engine, 'before_cursor_execute', observed)
    try:
        page(module, client, {'limit': 1, **({'agent_type': 'worker'} if typed else {})})
    finally:
        event.remove(module.db.engine, 'before_cursor_execute', observed)
    assert statements, 'No bounded candidate query was observed'
    with module.db.engine.connect() as connection:
        details = [row[3] for sql, parameters in statements for row in connection.exec_driver_sql(
            'EXPLAIN QUERY PLAN ' + sql, parameters)]
    assert any('ix_inventory_scan_session_org_id' in item for item in details), details
    observation_index = 'ix_inventory_observation_scan_type_order' if typed else 'ix_inventory_observation_scan_order'
    assert any(observation_index in item for item in details), details


@pytest.fixture
def inventory_file_api(api, tmp_path, monkeypatch):
    module, client = api
    engine = create_engine('sqlite:///' + str(tmp_path / 'owned-inventory.sqlite'))
    try:
        with engine.connect() as connection:
            connection.exec_driver_sql('PRAGMA journal_mode=WAL')
        module.initialize_schema(engine, module.db.metadata)
        with monkeypatch.context() as scoped:
            module.db.session.remove()
            scoped.setitem(module.db.engines, None, engine)
            try:
                yield module, client, engine
            finally:
                module.db.session.remove()
    finally:
        engine.dispose()


def test_generation_candidates_and_reports_share_one_real_read_snapshot(inventory_file_api):
    module, client, engine = inventory_file_api
    expected = populate(module, 60)
    wanted = [row for row in expected if row['organization'] == 'tenant-a'][:1]
    changed_scan = wanted[0]['scan']
    report = deepcopy(module.db.session.get(module.ScanResult, changed_scan).result)
    report['risk_assessment_status'] = 'not_assessed'
    module.db.session.remove()
    committed = []
    def after_generation(connection, cursor, statement, parameters, context, executemany):
        if not committed and statement.lstrip().upper().startswith('SELECT') and 'FROM inventory_generation' in statement:
            committed.append(True)
            with engine.begin() as writer:
                writer.execute(text('UPDATE scan_result SET result=:raw WHERE scan_id=:scan'),
                               {'raw': json.dumps(report), 'scan': changed_scan})
    event.listen(engine, 'after_cursor_execute', after_generation)
    try:
        first = page(module, client, {'limit': 1})
    finally:
        event.remove(engine, 'after_cursor_execute', after_generation)
    assert committed == [True]
    compare_rows(first['agents'], wanted)
    assert first['next_cursor']
    stale = client.get('/api/agents', query_string={'limit': 1, 'cursor': first['next_cursor']},
                       headers=headers(module))
    assert stale.status_code == 409, stale.json
    refreshed = page(module, client, {'limit': 1})
    assert refreshed['agents'][0]['risk_score'] is None


def test_metadata_bytes_share_the_request_source_budget(api):
    module, client = api
    independent_scans(module, 3)
    module.db.session.execute(module.DiscoveredAgentModel.__table__.update().values(
        metadata={'asset_id': 'high', 'unused_padding': 'x' * (6 * 1024 * 1024)}))
    module.db.session.commit()
    first = page(module, client, {'limit': 100})
    assert len(first['agents']) == 2
    assert first['coverage']['interpreted_source_bytes'] > 12 * 1024 * 1024
    assert first['next_cursor']
    final = page(module, client, {'limit': 100, 'cursor': first['next_cursor']})
    assert len(final['agents']) == 1
    assert final['coverage']['search_complete'] is True
    assert [row['id'] for row in first['agents'] + final['agents']] == [
        'separate-observation-%03d' % n for n in range(3)]


@pytest.mark.parametrize('field', ['alias', 'name'])
def test_single_unreturnable_observation_is_unavailable(api, field):
    module, client = api
    populate(module, 1)
    row = module.db.session.get(module.DiscoveredAgentModel, 'observation-00000')
    if field == 'alias':
        row.metadata_json = {'asset_id': 'x' * (1024 * 1024)}
    else:
        row.agent_name = 'x' * (1024 * 1024)
    module.db.session.commit()
    response = client.get('/api/agents', headers=headers(module))
    assert response.status_code == 503, response.json
    assert response.json['code'] == 'inventory_projection_unavailable'
    assert len(response.data) < 1024


def test_response_budget_keeps_the_unreturned_matching_observation_for_next_page(api):
    module, client = api
    populate(module, 2)
    module.db.session.execute(module.DiscoveredAgentModel.__table__.update().values(
        metadata={'asset_id': 'x' * (600 * 1024)}))
    module.db.session.commit()
    response = client.get('/api/agents', headers=headers(module))
    assert response.status_code == 200, response.json
    assert len(response.data) <= 1024 * 1024
    first = response.json
    assert len(first['agents']) == 1
    assert first['next_cursor']
    response = client.get('/api/agents', query_string={'cursor': first['next_cursor']}, headers=headers(module))
    assert response.status_code == 200, response.json
    assert len(response.data) <= 1024 * 1024
    final = response.json
    assert len(final['agents']) == 1
    assert final['coverage']['search_complete'] is True
    assert [row['id'] for row in first['agents'] + final['agents']] == [
        'observation-00000', 'observation-00001']


def test_deadline_failure_is_explicit_and_clears_owned_sqlite_progress_handler(api, monkeypatch):
    from src.core import inventory
    module, client = api
    populate(module, 1)
    clock = [0.0]
    original = inventory.project_report_risk
    def stalled_projection(value):
        result = original(value)
        clock[0] = inventory.PAGE_TIMEOUT_SECONDS + 1
        return result
    monkeypatch.setattr(inventory.time, 'monotonic', lambda: clock[0])
    monkeypatch.setattr(inventory, 'project_report_risk', stalled_projection)
    response = client.get('/api/agents', headers=headers(module))
    assert response.status_code == 503, response.json
    assert response.json['code'] == 'inventory_projection_unavailable'
    assert not response.json.get('agents')
    with module.db.engine.connect() as connection:
        total = connection.exec_driver_sql(
            'WITH RECURSIVE n(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM n WHERE x<10000) '
            'SELECT SUM(x) FROM n').scalar_one()
    assert total == 50005000


@pytest.mark.parametrize('source', ['observation', 'session'])
def test_ownership_moves_invalidate_both_organizations(api, source):
    module, client = api
    populate(module, 60)
    cursors = {org: page(module, client, {'limit': 1}, org=org)['next_cursor']
               for org in ('tenant-a', 'tenant-b')}
    assert all(cursors.values())
    if source == 'observation':
        module.db.session.get(module.DiscoveredAgentModel, 'observation-00000').scan_id = 'inventory-4'
    else:
        module.db.session.get(module.ScanSession, 'inventory-0').organization_id = 'tenant-b'
    module.db.session.commit()
    for org, cursor in cursors.items():
        response = client.get('/api/agents', query_string={'limit': 1, 'cursor': cursor},
                              headers=headers(module, org))
        assert response.status_code == 409, response.json
