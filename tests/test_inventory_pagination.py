"""Pagination preserves ordering and evidence semantics under finite work limits."""

import base64
from datetime import datetime, timedelta
import json

import pytest
from sqlalchemy import Column, DateTime, MetaData, String, Table, Text, create_engine, select, text
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session
from werkzeug.datastructures import MultiDict

from src.core import inventory
from tests.test_api_auth import api as api, headers
from tests.test_api_risk_projection import report, seed


@pytest.fixture
def stored():
    metadata = MetaData()
    observations = Table('observations', metadata,
                         Column('id', String, primary_key=True), Column('scan_id', String),
                         Column('agent_name', String), Column('agent_type', String),
                         Column('provider', String), Column('discovered_at', DateTime), Column('metadata', Text))
    scans = Table('scans', metadata, Column('id', String, primary_key=True), Column('organization_id', String))
    reports = Table('reports', metadata, Column('scan_id', String, primary_key=True), Column('result', Text))
    generations = Table('generations', metadata,
                        Column('organization_id', String, primary_key=True), Column('generation', String))
    engine = create_engine('sqlite:///:memory:')
    metadata.create_all(engine)
    try:
        with Session(engine) as session:
            session.execute(generations.insert(), [{'organization_id': 'tenant-a', 'generation': 'a' * 32},
                                                   {'organization_id': 'tenant-b', 'generation': 'b' * 32}])
            session.commit()
            yield session, observations, scans, reports, generations
    finally:
        engine.dispose()


def add(stored, count, *, scan_id='scan', tenant='tenant-a', kind='assistant', value=None, start=0):
    session, observations, scans, reports, _ = stored
    if not session.scalar(select(scans.c.id).where(scans.c.id == scan_id)):
        session.execute(scans.insert().values(id=scan_id, organization_id=tenant))
        if value is not None:
            session.execute(reports.insert().values(scan_id=scan_id, result=json.dumps(value)))
    session.execute(observations.insert(), [dict(
        id=f'{scan_id}-{index:04}', scan_id=scan_id, agent_name='Fixture', agent_type=kind, provider='fixture',
        discovered_at=datetime(2020, 1, 1) + timedelta(seconds=index // 3), metadata='{}',
    ) for index in range(start, start + count)])
    session.commit()


def page(stored, **args):
    session, *tables = stored
    parsed = inventory.parse_inventory_request(MultiDict(args), 'tenant-a', 'fixture-secret')
    return inventory.inventory_page(session, parsed, 'fixture-secret', *tables)


def rewrite(cursor, **changes):
    unsigned = inventory._signer('fixture-secret').unsign(cursor)
    value = json.loads(base64.urlsafe_b64decode(unsigned + b'=' * (-len(unsigned) % 4)))
    value.update(changes)
    return inventory._signer('fixture-secret').sign(base64.urlsafe_b64encode(
        json.dumps(value).encode()).rstrip(b'=')).decode()


@pytest.mark.parametrize('limit', ['', '0', '-1', '101', '1.0', ' 2', '2 ', '+2', '1e1', '9' * 500],
                         ids=['blank', 'zero', 'negative', 'over-cap', 'float', 'leading-space',
                              'trailing-space', 'plus', 'exponent', 'huge'])
def test_limit_is_a_bounded_positive_decimal(limit):
    with pytest.raises(inventory.InventoryError) as caught:
        inventory.parse_inventory_request(MultiDict({'limit': limit}), 'tenant-a', 'fixture-secret')
    assert caught.value.status == 400


@pytest.mark.parametrize('name', ['limit', 'cursor', 'risk_level', 'agent_type'])
def test_duplicate_parameters_are_rejected(name):
    with pytest.raises(inventory.InventoryError):
        inventory.parse_inventory_request(MultiDict([(name, '1'), (name, '1')]), 'tenant-a', 'fixture-secret')


def test_filters_are_normalized_and_invalid_values_rejected():
    parsed = inventory.parse_inventory_request(MultiDict({'agent_type': ' assistant ', 'risk_level': ' HIGH '}), 'x', 'key')
    assert (parsed.agent_type, parsed.risk_level, parsed.limit) == ('assistant', 'high', 100)
    for args in ({'risk_level': 'unsupported'}, {'agent_type': 'a' * 101}, {'agent_type': 'a\nline'}):
        with pytest.raises(inventory.InventoryError):
            inventory.parse_inventory_request(MultiDict(args), 'x', 'key')


def test_keyset_ties_and_tenant_type_boundaries_have_no_missing_or_duplicate_rows(stored):
    add(stored, 111)
    add(stored, 20, scan_id='other-type', kind='mcp')
    add(stored, 15, scan_id='other-tenant', tenant='tenant-b')
    rows, cursor = [], None
    while True:
        args = {'limit': '7', 'agent_type': 'assistant'}
        if cursor:
            args['cursor'] = cursor
        result = page(stored, **args)
        rows.extend(result['agents'])
        cursor = result['next_cursor']
        assert result['coverage']['search_complete'] == (cursor is None)
        if cursor is None:
            break
    expected = sorted((f'scan-{index:04}' for index in range(111)), key=lambda value: (
        -(int(value[-4:]) // 3), value))
    assert [row['id'] for row in rows] == expected
    assert len(set(row['id'] for row in rows)) == 111


def test_mixed_legacy_timestamp_pages_follow_exact_raw_sqlite_order(stored):
    stamps = ['2026-01-01 00:00:00.000000', '2026-01-01 00:00:00',
              '2026-01-01T00:00:00', '2026-01-01 00:00:00.123',
              '2026-01-01 00:00:00+00:00', '2026-01-01T00:00:00Z',
              '2026-01-01T00:00:00-04:00', '2026-01-01 00:00:00.1']
    add(stored, 2 * len(stamps))
    session = stored[0]
    for index in range(2 * len(stamps)):
        session.connection().exec_driver_sql('UPDATE observations SET discovered_at=? WHERE id=?',
                                            (stamps[index // 2], f'scan-{index:04}'))
    session.commit()
    expected = session.connection().exec_driver_sql(
        'SELECT id FROM observations ORDER BY discovered_at DESC,id').scalars().all()
    actual, cursor = [], None
    for _ in range(len(expected)):
        result = page(stored, limit='1', **({'cursor': cursor} if cursor else {}))
        actual.extend(row['id'] for row in result['agents'])
        cursor = result['next_cursor']
        if cursor is None:
            break
    assert actual == expected
    assert cursor is None


def test_sparse_filter_progresses_after_500_candidates_and_finds_oldest_high(stored):
    value = report(70, partial=True)
    value['agents'][0]['id'] = 'scan-0000'
    add(stored, 601, value=value)
    first = page(stored, risk_level='high')
    assert first['agents'] == []
    assert first['coverage']['evaluated_candidates'] == 500
    assert first['coverage']['search_complete'] is False
    second = page(stored, risk_level='high', cursor=first['next_cursor'])
    assert [row['id'] for row in second['agents']] == ['scan-0000']
    assert second['agents'][0]['risk_score'] == 70
    assert second['coverage']['evaluated_candidates'] == 101
    assert second['coverage']['search_complete'] is True
    assert second['next_cursor'] is None


@pytest.mark.parametrize('change,status', [({'organization': 'tenant-b'}, 400), ({'limit': 2}, 400),
                                        ({'agent_type': 'mcp'}, 400), ({'risk_level': 'high'}, 400),
                                        ({'ordering': 'other'}, 400), ({'policy': 'older'}, 409)])
def test_cursor_scope_and_policy_are_validated_without_a_session(stored, change, status):
    add(stored, 2)
    cursor = page(stored, limit='1')['next_cursor']
    with pytest.raises(inventory.InventoryError) as caught:
        inventory.parse_inventory_request(MultiDict({'limit': '1', 'cursor': rewrite(cursor, **change)}),
                                          'tenant-a', 'fixture-secret')
    assert caught.value.status == status


@pytest.mark.parametrize('kind', ['tampered', 'expired', 'future', 'rotated-key', 'blank'])
def test_cursor_integrity_and_time_binding(stored, monkeypatch, kind):
    add(stored, 2)
    with monkeypatch.context() as scoped:
        if kind in {'expired', 'future'}:
            offset = -inventory.CURSOR_MAX_AGE_SECONDS - 10 if kind == 'expired' else 100
            now = inventory._signer('fixture-secret').get_timestamp()
            scoped.setattr(inventory.TimestampSigner, 'get_timestamp', lambda _: now + offset)
        cursor = page(stored, limit='1')['next_cursor']
    secret = 'fixture-secret'
    if kind == 'tampered':
        cursor = cursor[:-3] + 'abc'
    elif kind == 'rotated-key':
        secret = 'changed-secret'
    elif kind == 'blank':
        cursor = ''
    with pytest.raises(inventory.InventoryError) as caught:
        inventory.parse_inventory_request(MultiDict({'limit': '1', 'cursor': cursor}), 'tenant-a', secret)
    assert caught.value.status == 400


def test_legal_utf8_maximum_cursor_roundtrips_with_the_original_scope_and_key():
    organization = chr(0x1f600) * 64
    kind = chr(0x1f601) * 100
    identifier = chr(0x1f602) * 64
    stamp = '2026-01-01T00:00:00.' + '1' * 38 + '+00:00'
    assert len(stamp.encode()) == 64
    parsed = inventory.parse_inventory_request(MultiDict({'agent_type': kind}), organization, 'fixture-secret')
    cursor = inventory._cursor(parsed, 'a' * 32, (stamp, identifier), 'fixture-secret')
    assert len(cursor) <= 4096
    continued = inventory.parse_inventory_request(MultiDict({'agent_type': kind, 'cursor': cursor}),
                                                 organization, 'fixture-secret')
    assert continued.organization == organization and continued.agent_type == kind
    assert continued.after == (stamp, identifier)


def test_an_unreturnable_cursor_is_never_emitted(stored, monkeypatch):
    add(stored, 2)
    monkeypatch.setattr(inventory, 'MAX_CURSOR_BYTES', 8)
    with pytest.raises(inventory.InventoryError) as caught:
        page(stored, limit='1')
    assert caught.value.status == 503


def test_changed_generation_requires_restart(stored):
    add(stored, 2)
    first = page(stored, limit='1')
    session, *_, generations = stored
    session.execute(generations.update().where(generations.c.organization_id == 'tenant-a').values(generation='c' * 32))
    session.commit()
    with pytest.raises(inventory.InventoryError) as caught:
        page(stored, limit='1', cursor=first['next_cursor'])
    assert caught.value.status == 409


def test_reports_are_projected_once_and_missing_reports_also_bound_work(stored, monkeypatch):
    add(stored, 99, value={})
    calls = []
    actual = inventory.project_report_risk
    monkeypatch.setattr(inventory, 'project_report_risk', lambda value: (calls.append(value), actual(value))[1])
    assert len(page(stored)['agents']) == 99
    assert len(calls) == 1
    for index in range(33):
        add(stored, 1, scan_id=f'extra-{index:02}')
    first = page(stored, risk_level='high')
    assert first['coverage']['projected_reports'] == 32
    assert first['coverage']['evaluated_candidates'] > 0
    assert first['next_cursor']


@pytest.mark.parametrize('column', ['metadata', 'result'])
@pytest.mark.parametrize('raw', ['{', '[' * 65 + '0' + ']' * 65, '"' + 'x' * (8 * 1024 * 1024) + '"', 'NaN'],
                         ids=['malformed', 'deep', 'oversize', 'constant'])
def test_unreadable_sources_are_unavailable_instead_of_unknown_or_silent_skip(stored, column, raw):
    add(stored, 1, value={})
    session, observations, _, reports, _ = stored
    table = observations if column == 'metadata' else reports
    session.execute(table.update().values({column: raw}))
    session.commit()
    with pytest.raises(inventory.InventoryError) as caught:
        page(stored, risk_level='high')
    assert (caught.value.status, caught.value.code, caught.value.message) == (
        503, 'inventory_projection_unavailable', 'Inventory projection unavailable')


def test_report_byte_budget_stops_before_fetching_an_unconsumed_report(stored):
    padding = {'padding': 'x' * (6 * 1024 * 1024)}
    for index in range(3):
        add(stored, 1, scan_id=f'scan-{index}', value=padding)
    first = page(stored, risk_level='high')
    assert first['agents'] == []
    assert first['coverage']['projected_reports'] == 2
    assert first['coverage']['evaluated_candidates'] == 2
    assert first['coverage']['projected_report_bytes'] <= inventory.MAX_REPORT_BYTES
    assert first['next_cursor']
    second = page(stored, risk_level='high', cursor=first['next_cursor'])
    assert second['coverage']['evaluated_candidates'] == 1
    assert second['coverage']['search_complete'] is True


def test_combined_source_budget_counts_metadata_and_continues_without_loss(stored):
    add(stored, 3, value={})
    session, observations, *_ = stored
    raw = json.dumps({'padding': 'x' * (6 * 1024 * 1024)})
    session.execute(observations.update().values(metadata=raw))
    session.commit()
    first = page(stored)
    assert [row['id'] for row in first['agents']] == ['scan-0000', 'scan-0001']
    assert first['coverage']['interpreted_source_bytes'] == 2 * len(raw.encode()) + 2
    assert first['coverage']['interpreted_source_bytes'] <= inventory.MAX_SOURCE_BYTES
    second = page(stored, cursor=first['next_cursor'])
    assert [row['id'] for row in second['agents']] == ['scan-0002']
    assert second['coverage']['search_complete'] is True


def test_response_budget_stops_before_a_matching_row_and_preserves_the_row(stored):
    add(stored, 3)
    session, observations, *_ = stored
    session.execute(observations.update().values(metadata=json.dumps({'asset_id': '\uffff' * 100000})))
    session.commit()
    seen, cursor = [], None
    while True:
        result = page(stored, **({'cursor': cursor} if cursor else {}))
        assert len(json.dumps({'success': True, **result}).encode()) <= inventory.MAX_RESPONSE_BYTES
        assert len(result['agents']) == 1
        assert result['coverage']['evaluated_candidates'] == 1
        seen.extend(row['id'] for row in result['agents'])
        cursor = result['next_cursor']
        if cursor is None:
            break
    assert seen == ['scan-0000', 'scan-0001', 'scan-0002']


def test_a_single_unreturnable_alias_fails_explicitly(stored):
    add(stored, 1)
    session, observations, *_ = stored
    session.execute(observations.update().values(metadata=json.dumps({'asset_id': 'x' * inventory.MAX_RESPONSE_BYTES})))
    session.commit()
    with pytest.raises(inventory.InventoryError) as caught:
        page(stored)
    assert caught.value.status == 503


@pytest.mark.parametrize('field', ['id', 'scan_id', 'agent_name', 'agent_type', 'provider', 'discovered_at'])
def test_sqlite_unbounded_scalar_fields_fail_without_becoming_normal_observations(stored, field):
    add(stored, 1)
    session, observations, scans, *_ = stored
    raw = 'x' * (2 * 1024 * 1024)
    if field == 'scan_id':
        session.execute(scans.update().values(id=raw))
    # Driver SQL permits intentionally invalid DateTime values without invoking
    # SQLAlchemy's legitimate Python-datetime binding requirement.
    session.connection().exec_driver_sql(f'UPDATE observations SET {field} = ?', (raw,))
    session.commit()
    with pytest.raises(inventory.InventoryError) as caught:
        page(stored)
    assert caught.value.status == 503


@pytest.mark.parametrize('metadata,expected', [({}, 70), ({'asset_id': ''}, None),
                                             ({'asset_id': None}, None), ({'asset_id': []}, None),
                                             (None, 70), ([], 70)])
def test_only_absent_aliases_or_nondict_metadata_fall_back_to_the_snapshot(stored, metadata, expected):
    value = report(70, partial=True)
    value['agents'][0]['id'] = 'scan-0000'
    add(stored, 1, value=value)
    session, observations, *_ = stored
    session.execute(observations.update().values(metadata=json.dumps(metadata)))
    session.commit()
    result = page(stored)['agents'][0]
    assert result['risk_score'] == expected
    assert result['asset_id'] == ('scan-0000' if expected == 70 else None)


def test_empty_tenant_has_no_cursor_and_missing_generation_with_rows_fails_closed(stored):
    session, _, _, _, generations = stored
    result = page(stored)
    assert result['agents'] == [] and result['next_cursor'] is None
    assert result['coverage']['search_complete'] is True
    add(stored, 1)
    session.execute(generations.delete())
    session.commit()
    with pytest.raises(inventory.InventoryError) as caught:
        page(stored)
    assert caught.value.status == 503


def test_sqlite_progress_deadline_is_cleared_after_interrupt(stored):
    session = stored[0]
    with pytest.raises(OperationalError), inventory._query_deadline(session, 0):
        session.execute(text(
            'WITH RECURSIVE n(x) AS (VALUES(0) UNION ALL SELECT x+1 FROM n WHERE x<100000) SELECT sum(x) FROM n'))
    assert session.scalar(select(1)) == 1


def test_api_rejects_scope_mismatch_before_opening_read_snapshot(api, monkeypatch):
    module, client = api
    seed(module, report())
    row = module.db.session.get(module.DiscoveredAgentModel, 'fixture-snapshot')
    module.db.session.add(module.DiscoveredAgentModel(
        id='second', scan_id=row.scan_id, agent_name='Second', agent_type='assistant',
        discovery_method='fixture', metadata_json={}))
    module.db.session.commit()
    first = client.get('/api/agents?limit=1', headers=headers(module)).json
    assert first['next_cursor']
    monkeypatch.setattr(module, '_read_snapshot', lambda: pytest.fail('Invalid cursor opened SQL snapshot'))
    response = client.get('/api/agents', query_string={'limit': 2, 'cursor': first['next_cursor']},
                          headers=headers(module))
    assert response.status_code == 400
    assert response.json == {'success': False, 'code': 'invalid_cursor',
                             'error': 'Invalid or expired inventory cursor'}
