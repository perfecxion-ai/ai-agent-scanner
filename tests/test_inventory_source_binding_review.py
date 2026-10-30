"""Independent observation binding regressions over unchanged captured sources."""

from copy import deepcopy
import json
import time

import pytest
from sqlalchemy import select, update
from sqlalchemy.orm import Session
from werkzeug.datastructures import MultiDict

from src.core import inventory
from src.core import asset_group_projection as sources
from src.core.asset_group_risk import RISK_FIELDS
from src.core.risk_projection import project_report_risk
from tests.legacy_access_v3_fixtures import legacy_access_v3_archive, legacy_access_v3_report
from tests.test_api_auth import api as api, headers
from tests.test_api_risk_projection import seed as api_seed
from tests.test_asset_groups import database as database, seed, source_rows


SECRET = 'owned-independent-observation-review-signing-key'


def captured(database, name='captured', *, kind='high', count=1):
    document = legacy_access_v3_report(kind)
    seed(database, name, report=document, count=count)
    engine, tables = database
    with engine.begin() as connection:
        connection.execute(update(tables['reports']).where(tables['reports'].c.scan_id == name)
                           .values(result=legacy_access_v3_archive(kind).decode()))
    return document


def direct_page(database, **query):
    engine, tables = database
    parsed = inventory.parse_inventory_request(MultiDict(query), 'tenant-a', SECRET)
    with Session(engine) as session:
        return inventory.inventory_page(session, parsed, SECRET, *[
            tables[name] for name in ('observations', 'scans', 'reports', 'generations')])


def read_sources(database):
    engine, tables = database
    with engine.connect() as connection:
        rows = connection.execute(select(*sources.observation_columns(tables['observations']))
                                  .order_by(tables['observations'].c.id)).all()
        reader = sources.SourceReader(connection, tables, time.monotonic() + 10)
        return {row.id: reader.observation(row, 'tenant-a') for row in rows}


def facts(row):
    return {name: row[name] for name in RISK_FIELDS}


def raw_source_rows(database):
    engine, _ = database
    with engine.connect() as connection:
        return {name: connection.exec_driver_sql('SELECT * FROM ' + name).all()
                for name in ('discovered_agent', 'scan_session', 'scan_result', 'inventory_generation')}


def api_captured(module, client, kind='high'):
    document = legacy_access_v3_report(kind)
    agent = document['agents'][0]
    api_seed(module, document, alias=agent['id'])
    snapshot = module.db.session.get(module.DiscoveredAgentModel, 'fixture-snapshot')
    snapshot.provider, snapshot.model_name, snapshot.endpoint_url = (
        agent['provider'], agent['model'], agent['endpoint'])
    module.db.session.commit()
    positive = client.get('/api/agents', headers=headers(module))
    assert positive.status_code == 200 and positive.json['agents'][0]['risk_score'] == 70
    return document


@pytest.mark.parametrize('kind,score', [('high', 70), ('partial', 70), ('zero', 0)])
@pytest.mark.parametrize('selector', ['exact', 'normalized-http', 'unmerged-cloud'])
def test_genuine_captured_risk_survives_valid_snapshot_selectors(database, kind, score, selector):
    report = captured(database, kind=kind)
    agent = report['agents'][0]
    engine, tables = database
    if selector != 'exact':
        value = ({'endpoint_url': agent['endpoint'].replace('http://', 'HTTP://') + '/'}
                 if selector == 'normalized-http' else {'metadata': json.dumps({
                     'asset_id': agent['id'], 'cloud': 'gcp', 'resource_id': 'incomplete'})})
        with engine.begin() as connection:
            connection.execute(update(tables['observations']).values(**value))
    before = source_rows(database)
    expected = project_report_risk(report)[1][agent['id']]
    assert expected['risk_score'] == score
    body = direct_page(database)
    assert len(body['agents']) == 1 and facts(body['agents'][0]) == expected
    source = read_sources(database)['captured-00000']
    assert source.risk == expected
    assert source.identity.status == ('unmerged' if selector == 'unmerged-cloud' else 'grouped')
    assert body['coverage']['search_complete'] is True
    assert source_rows(database) == before


@pytest.mark.parametrize('kind', ['high', 'zero', 'partial'])
@pytest.mark.parametrize('field,value', [
    ('provider', 'different-provider'), ('model_name', 'different-model'),
    ('endpoint_url', 'http://192.0.2.222/different-target'),
])
def test_mismatched_snapshot_cannot_borrow_the_archived_targets_score(database, kind, field, value):
    report = captured(database, kind=kind)
    engine, tables = database
    with engine.begin() as connection:
        connection.execute(update(tables['observations']).values(**{field: value}))
    before = source_rows(database)
    body = direct_page(database)
    assert body['agents'][0]['risk_score'] is None
    assert body['agents'][0]['risk_level'] == 'unknown'
    source = read_sources(database)['captured-00000']
    assert source.identity.reason == 'snapshot_target_mismatch'
    assert facts(body['agents'][0]) == source.risk
    assert direct_page(database, risk_level='high')['agents'] == []
    assert len(direct_page(database, risk_level='unknown')['agents']) == 1
    # The original target still has its supported assessment; only this snapshot is unbound.
    assert project_report_risk(report)[1][report['agents'][0]['id']]['risk_score'] == (0 if kind == 'zero' else 70)
    assert source_rows(database) == before


@pytest.mark.parametrize('where', ['metadata', 'report-root', 'report-nested'])
def test_duplicate_json_members_refuse_a_successful_inventory_page(database, where):
    report = captured(database)
    engine, tables = database
    with engine.begin() as connection:
        if where == 'metadata':
            raw = '{"asset_id":"wrong-target","asset_id":' + json.dumps(report['agents'][0]['id']) + '}'
            connection.execute(update(tables['observations']).values(metadata=raw))
        else:
            original = legacy_access_v3_archive('high').decode()
            raw = ('{"agents":[],' + original.lstrip()[1:] if where == 'report-root'
                   else '{"unused":{"selector":1,"selector":2},' + original.lstrip()[1:])
            connection.execute(update(tables['reports']).values(result=raw))
    before = source_rows(database)
    with pytest.raises(inventory.InventoryError) as direct:
        direct_page(database)
    assert (direct.value.status, direct.value.code, direct.value.message) == (
        503, 'inventory_projection_unavailable', 'Inventory projection unavailable')
    with pytest.raises(inventory.InventoryError) as grouped:
        read_sources(database)
    assert grouped.value.status == 503
    assert source_rows(database) == before


@pytest.mark.parametrize('field,value', [
    ('provider', b'ollama'), ('model_name', b'owned-model'), ('endpoint_url', b'http://192.0.2.1/'),
    ('provider', 'p' * 101), ('model_name', 'm' * 256), ('endpoint_url', 'e' * 4097),
    ('provider', 'p' * 401), ('model_name', 'm' * 1021), ('endpoint_url', 'e' * 16385),
    ('provider', 'bad\x00provider'), ('model_name', 'bad\nmodel'), ('endpoint_url', 'bad\x7fendpoint'),
], ids=['provider-blob', 'model-blob', 'endpoint-blob', 'provider-char-limit', 'model-char-limit',
        'endpoint-char-limit', 'provider-byte-limit', 'model-byte-limit', 'endpoint-byte-limit',
        'provider-nul', 'model-newline', 'endpoint-del'])
def test_invalid_selector_storage_cannot_be_interpreted_as_an_absent_selector(database, field, value):
    captured(database)
    engine, tables = database
    with engine.begin() as connection:
        # Preserve SQLite's physical type to distinguish genuine NULL from a refused value.
        connection.exec_driver_sql('UPDATE discovered_agent SET ' + field + ' = ?', (value,))
    before = source_rows(database)
    with pytest.raises(inventory.InventoryError) as direct:
        direct_page(database)
    assert direct.value.status == 503 and direct.value.code == 'inventory_projection_unavailable'
    with pytest.raises(inventory.InventoryError) as grouped:
        read_sources(database)
    assert grouped.value.status == 503
    assert source_rows(database) == before


@pytest.mark.parametrize('field', ['provider', 'model_name', 'endpoint_url'])
def test_genuine_null_selector_is_an_unbound_observation_not_a_storage_failure(database, field):
    captured(database)
    engine, tables = database
    with engine.begin() as connection:
        connection.execute(update(tables['observations']).values(**{field: None}))
    before = source_rows(database)
    body = direct_page(database)
    source = read_sources(database)['captured-00000']
    assert body['coverage']['search_complete'] is True
    assert body['agents'][0]['risk_score'] is None and source.risk['risk_score'] is None
    assert facts(body['agents'][0]) == source.risk
    assert source_rows(database) == before


def test_duplicate_archived_aliases_stay_unknown_without_rewriting_the_archive(database):
    report = captured(database)
    report['agents'].append(deepcopy(report['agents'][0]))
    engine, tables = database
    with engine.begin() as connection:
        connection.execute(update(tables['reports']).values(result=json.dumps(report)))
    before = source_rows(database)
    body = direct_page(database)
    source = read_sources(database)['captured-00000']
    assert body['agents'][0]['risk_score'] is None and source.risk['risk_score'] is None
    assert source.identity.reason == 'unmatched_asset_alias'
    assert source_rows(database) == before


def test_raw_timestamp_order_and_sparse_progress_survive_target_binding(database):
    captured(database, count=601)
    engine, tables = database
    stamps = ['2026-01-01 00:00:00.000000', '2026-01-01T00:00:00Z',
              '2026-01-01T00:00:00-04:00', '2026-01-01 00:00:00.1']
    with engine.begin() as connection:
        for number in range(601):
            connection.exec_driver_sql('UPDATE discovered_agent SET discovered_at = ? WHERE id = ?',
                                       (stamps[number % len(stamps)], 'captured-' + str(number).zfill(5)))
        ordered = connection.exec_driver_sql(
            'SELECT id FROM discovered_agent ORDER BY discovered_at DESC, id ASC').scalars().all()
        connection.execute(update(tables['observations']).where(tables['observations'].c.id != ordered[-1])
                           .values(provider='unbound-provider'))
    before = raw_source_rows(database)
    first = direct_page(database, risk_level='high')
    assert first['agents'] == []
    assert first['coverage']['evaluated_candidates'] == 500
    assert first['coverage']['search_complete'] is False and first['next_cursor']
    second = direct_page(database, risk_level='high', cursor=first['next_cursor'])
    assert [row['id'] for row in second['agents']] == ordered[-1:]
    assert second['coverage']['evaluated_candidates'] == 101
    assert second['coverage']['search_complete'] is True and second['next_cursor'] is None
    actual, cursor = [], None
    for _ in range(10):
        body = direct_page(database, limit='100', **({'cursor': cursor} if cursor else {}))
        actual.extend(row['id'] for row in body['agents'])
        cursor = body['next_cursor']
        if cursor is None:
            break
    assert cursor is None and actual == ordered
    assert raw_source_rows(database) == before


def test_interpreted_source_budget_emits_only_acknowledged_candidates(database, monkeypatch):
    captured(database, count=3)
    metadata_size = len(json.dumps({'asset_id': 'owned-access-v3'}).encode())
    report_size = len(legacy_access_v3_archive('high'))
    monkeypatch.setattr(inventory, 'MAX_SOURCE_BYTES', report_size + 2 * metadata_size - 1)
    before = source_rows(database)
    result = direct_page(database)
    assert len(result['agents']) == 1 and result['coverage']['evaluated_candidates'] == 1
    assert result['coverage']['search_complete'] is False and result['next_cursor']
    assert result['coverage']['interpreted_source_bytes'] == report_size + metadata_size
    assert result['agents'][0]['risk_score'] == 70
    rows = list(result['agents'])
    for _ in range(3):
        if result['next_cursor'] is None:
            break
        result = direct_page(database, cursor=result['next_cursor'])
        rows.extend(result['agents'])
    assert result['next_cursor'] is None and [row['id'] for row in rows] == [
        'captured-00000', 'captured-00001', 'captured-00002']
    assert source_rows(database) == before


@pytest.mark.parametrize('target', ['metadata', 'report'])
def test_http_duplicate_json_failure_has_no_success_or_complete_coverage_claim(api, target):
    module, client = api
    document = api_captured(module, client)
    if target == 'metadata':
        raw = '{"asset_id":"owned-untrusted-first","asset_id":' + json.dumps(document['agents'][0]['id']) + '}'
        table, column, key, identifier = 'discovered_agent', 'metadata', 'id', 'fixture-snapshot'
    else:
        raw = '{"agents":[],' + legacy_access_v3_archive('high').decode().lstrip()[1:]
        table, column, key, identifier = 'scan_result', 'result', 'scan_id', 'fixture'
    with module.db.engine.begin() as connection:
        connection.exec_driver_sql('UPDATE ' + table + ' SET ' + column + ' = ? WHERE ' + key + ' = ?',
                                   (raw, identifier))
    response = client.get('/api/agents', headers=headers(module))
    assert response.status_code == 503
    assert response.json == {'success': False, 'code': 'inventory_projection_unavailable',
                             'error': 'Inventory projection unavailable'}
    with module.db.engine.connect() as connection:
        assert connection.exec_driver_sql('SELECT ' + column + ' FROM ' + table + ' WHERE ' + key + ' = ?',
                                          (identifier,)).scalar_one() == raw


def test_http_unbound_observation_does_not_erase_original_supported_report(api):
    module, client = api
    document = api_captured(module, client, 'partial')
    module.db.session.get(module.DiscoveredAgentModel, 'fixture-snapshot').model_name = 'different-owned-model'
    module.db.session.commit()
    response = client.get('/api/agents', headers=headers(module))
    assert response.status_code == 200
    assert response.json['agents'][0]['risk_score'] is None
    assert response.json['agents'][0]['risk_level'] == 'unknown'
    original = client.get('/api/scans/fixture/results', headers=headers(module))
    assert original.status_code == 200
    assert original.json['results']['pipeline'] == document
    assert original.json['results']['agents'][0]['risk_score'] == 70
    assert original.json['results']['summary']['overall_risk_score'] == 70
