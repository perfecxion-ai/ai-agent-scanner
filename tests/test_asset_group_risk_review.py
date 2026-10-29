"""Independent regressions for source-bound filtering and cache refusal."""

import pytest
from sqlalchemy import create_engine, event, insert, select, update
from sqlalchemy.orm import Session
from werkzeug.datastructures import MultiDict

from src.core import asset_group_projection as sources
from src.core.asset_groups import AssetGroupProjector
from src.core.inventory import InventoryError, inventory_page, parse_inventory_request
from src.core.schema import initialize_schema
from tests.historical_schema import historical_metadata
from tests.legacy_access_v3_fixtures import legacy_access_v3_report
from tests.test_asset_group_schema import (
    current_metadata, fingerprint, publish as publish_cache, row as cache_row, seed_source,
)
from tests.test_asset_groups import (
    SECRET, database as database, page, publish, seed, source_rows,
)


def singleton_report(kind):
    report = legacy_access_v3_report(kind)
    report['agents'][0]['metadata'].update(cloud='gcp', resource_id='incomplete')
    return report


def unknown_report():
    report = legacy_access_v3_report('zero')
    report.update(risk_assessment_status='not_assessed', risk_assessments=[])
    report['summary']['overall_risk_score'] = None
    for agent in report['agents']:
        agent.update(risk_score=None, risk_level='unknown', risk_scoring_policy=None,
                     risk_coverage_status='not_assessed')
    return report


def unknown_facts():
    return dict(risk_score=None, risk_level='unknown', risk_coverage_status='not_assessed',
                risk_assessment_status='not_assessed', risk_scoring_policy=None,
                security_status='completed')


def test_filter_seeks_matching_singletons_beyond_500_other_groups(database, monkeypatch):
    seed(database, 'many-zero', report=singleton_report('zero'), count=650, stamp=2)
    seed(database, 'few-high', report=singleton_report('high'), count=3, stamp=1)
    publish(database)
    engine, tables = database
    before = source_rows(database)
    opened, statements = [], []
    original = sources.SourceReader.observation

    def track(reader, row, organization):
        opened.append(row.scan_id)
        return original(reader, row, organization)

    def capture(connection, cursor, statement, parameters, context, many):
        if (statement.startswith('SELECT ') and 'asset_group_index.risk_level = ?' in statement
                and 'asset_group_index.is_latest = 1' in statement):
            statements.append((statement, parameters))

    monkeypatch.setattr(sources.SourceReader, 'observation', track)
    event.listen(engine, 'before_cursor_execute', capture)
    try:
        result, visited, cursor = [], set(), None
        for _ in range(5):
            args = [('risk_level', 'high'), ('limit', '1')]
            if cursor is not None:
                args.append(('cursor', cursor))
            response = page(database, args)
            assert response['coverage']['indexed_groups'] == 653
            assert response['coverage']['evaluated_candidates'] <= 1
            result.extend(response['asset_groups'])
            cursor = response['next_cursor']
            if cursor is None:
                assert response['coverage']['search_complete'] is True
                break
            assert cursor not in visited
            visited.add(cursor)
        else:
            pytest.fail('Filtered singleton traversal did not finish')
    finally:
        event.remove(engine, 'before_cursor_execute', capture)
    assert len(result) == len({item['id'] for item in result}) == 3
    assert all(item['latest_observation_risk']['risk_score'] == 70 for item in result)
    assert opened == ['few-high'] * 3
    assert len(statements) == 3
    with engine.connect() as connection:
        for statement, parameters in statements:
            details = [row[3] for row in connection.exec_driver_sql('EXPLAIN QUERY PLAN ' + statement, parameters)]
            assert any('USING INDEX ix_asset_group_head_risk_page' in detail and 'risk_level=?' in detail
                       for detail in details), details
            assert not any('USE TEMP B-TREE' in detail for detail in details), details
            if 'asset_group_index.observed_at_us < ?' in statement:
                assert 'asset_group_index.observed_at_us <= ?' in statement
                assert any('observed_at_us<?' in detail for detail in details), details
    assert source_rows(database) == before


def test_group_target_binding_does_not_change_observation_alias_projection(database):
    seed(database, 'target-mismatch')
    engine, tables = database
    with engine.begin() as connection:
        connection.execute(update(tables['observations']).values(endpoint_url='https://other.invalid/api'))
    publish(database)
    before = source_rows(database)
    assert page(database, [('risk_level', 'high')])['asset_groups'] == []
    grouped = page(database, [('risk_level', 'unknown')])['asset_groups']
    assert len(grouped) == 1
    assert grouped[0]['unmerged_reason'] == 'snapshot_target_mismatch'
    assert grouped[0]['latest_observation_risk']['risk_score'] is None
    parsed = parse_inventory_request(MultiDict([('risk_level', 'high')]), 'tenant-a', SECRET)
    with Session(engine) as session:
        observed = inventory_page(session, parsed, SECRET, tables['observations'], tables['scans'],
                                  tables['reports'], tables['generations'])
    assert len(observed['agents']) == 1
    assert observed['agents'][0]['risk_score'] == 70
    assert source_rows(database) == before


@pytest.mark.parametrize('recursive', [False, True])
def test_coherent_nonmatching_edit_and_publication_restore_cannot_hide_high(database, recursive):
    seed(database, 'original-high')
    publish(database)
    engine, tables = database
    with engine.begin() as connection:
        connection.exec_driver_sql('PRAGMA recursive_triggers=' + str(int(recursive)))
        original = dict(connection.execute(select(tables['publication'])).mappings().one())
        connection.execute(update(tables['index']).values(**unknown_facts()))
        connection.execute(update(tables['publication']).values(**original))
    for risk_level in ('high', 'unknown', 'minimal'):
        with pytest.raises(InventoryError) as failure:
            page(database, [('risk_level', risk_level)])
        assert failure.value.status == 503
        assert failure.value.code == 'asset_group_projection_unavailable'


def test_other_owner_tamper_preserves_filtered_cursor_for_unchanged_owner(database):
    seed(database, 'own-high', report=singleton_report('high'), count=3)
    seed(database, 'other-high', organization='tenant-b')
    publish(database)
    publish(database, organization='tenant-b')
    engine, tables = database
    before = source_rows(database)
    first = page(database, [('risk_level', 'high'), ('limit', '1')])
    assert first['next_cursor']
    with engine.begin() as connection:
        other = dict(connection.execute(select(tables['publication']).where(
            tables['publication'].c.organization_id == 'tenant-b')).mappings().one())
        connection.execute(update(tables['index']).where(
            tables['index'].c.organization_id == 'tenant-b').values(**unknown_facts()))
        connection.execute(update(tables['publication']).where(
            tables['publication'].c.organization_id == 'tenant-b').values(**other))
    second = page(database, [('risk_level', 'high'), ('limit', '1'), ('cursor', first['next_cursor'])])
    assert len(second['asset_groups']) == 1
    assert second['asset_groups'][0]['id'] != first['asset_groups'][0]['id']
    assert second['asset_groups'][0]['latest_observation_risk']['risk_score'] == 70
    with pytest.raises(InventoryError) as failure:
        page(database, [('risk_level', 'unknown')], organization='tenant-b')
    assert failure.value.status == 503
    assert source_rows(database) == before


@pytest.mark.parametrize('column', ['risk_score', 'risk_scoring_policy'])
def test_oversized_nonnull_staging_fact_cannot_publish_as_unknown(database, column):
    seed(database, 'unassessed', report=unknown_report())
    engine, tables = database
    projector = AssetGroupProjector(engine, tables)
    first = projector.step()
    assert first.processed_rows == 1 and not first.published
    with engine.begin() as connection:
        connection.exec_driver_sql('UPDATE asset_group_index SET ' + column + '=?', ('x' * (1024 * 1024),))
        assert connection.exec_driver_sql('SELECT typeof(' + column + '),length(' + column + ') FROM asset_group_index').one() == ('text', 1024 * 1024)
    for _ in range(8):
        projector._next_poll = 0
        progress = projector.step()
        assert not progress.published
        if progress.state == 'blocked':
            break
    else:
        pytest.fail('Malformed staging descriptor was not blocked')
    with engine.connect() as connection:
        publication = connection.execute(select(tables['publication'])).mappings().one()
        assert publication['active_build_id'] is None
        assert publication['error_code'] == 'source_unavailable'
    with pytest.raises(InventoryError) as failure:
        page(database, [('risk_level', 'unknown')])
    assert failure.value.status == 503


def test_schema_seven_preserves_active_and_staging_rows_but_refuses_unbuilt_risk(tmp_path):
    engine = create_engine('sqlite:///' + str(tmp_path / 'owned-seven-active-and-staging.sqlite'))
    try:
        old = historical_metadata(version=7)
        old.create_all(engine)
        with engine.begin() as connection:
            connection.execute(insert(old.tables['schema_version']).values(id=1, version=7))
            seed_source(connection, old, owner='tenant-a', suffix='a')
            seed_source(connection, old, owner='tenant-b', suffix='b')
            publish_cache(connection, old, owner='tenant-a')
            staging = cache_row(owner='tenant-b', build='f' * 32, observation='observation-b')
            staging.update(scan_id='scan-b', report_asset_id='alias-b')
            connection.execute(insert(old.tables['asset_group_index']).values(**staging))
            connection.execute(insert(old.tables['asset_group_publication']).values(
                organization_id='tenant-b', processed_count=1, building_build_id='f' * 32,
                building_generation='d' * 32, building_policy='e' * 64,
                after_scan_id='scan-b', after_observation_id='observation-b'))
        before = fingerprint(engine)
        metadata = current_metadata()
        initialize_schema(engine, metadata)
        after = fingerprint(engine)
        for name, rows in before[1].items():
            expected = ([(1, 8)] if name == 'schema_version' else
                        [tuple(row) + (None,) * 6 for row in rows] if name == 'asset_group_index' else rows)
            assert after[1][name] == expected
        assert len(after[1]['asset_group_index']) == 2
        assert any(row[19] is not None for row in after[1]['asset_group_index'])
        assert any(row[19] is None for row in after[1]['asset_group_index'])
        assert any(row[1] is not None for row in after[1]['asset_group_publication'])
        assert any(row[7] is not None for row in after[1]['asset_group_publication'])
        tables = {key: metadata.tables[name] for key, name in {
            'index': 'asset_group_index', 'publication': 'asset_group_publication',
            'observations': 'discovered_agent', 'scans': 'scan_session',
            'reports': 'scan_result', 'generations': 'inventory_generation',
        }.items()}
        for owner in ('tenant-a', 'tenant-b'):
            with pytest.raises(InventoryError) as failure:
                page((engine, tables), [('risk_level', 'high')], organization=owner)
            assert failure.value.status == 503
        initialize_schema(engine, metadata)
        assert fingerprint(engine) == after
    finally:
        engine.dispose()
