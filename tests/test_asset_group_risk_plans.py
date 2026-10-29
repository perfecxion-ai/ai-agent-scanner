"""Risk seeks remain selective across valid index orders and timestamp shapes."""

import pytest
from sqlalchemy import event

from src.core import asset_group_projection as sources
from src.core.asset_group_storage import INDEX_DEFINITIONS
from tests.test_asset_group_risk import singleton_report
from tests.test_asset_groups import database as database, page, publish, seed, source_rows


@pytest.mark.parametrize('order', [('page', 'risk'), ('risk', 'page')], ids=['risk-created-last', 'page-created-last'])
@pytest.mark.parametrize('nonmatching_stamp', [0, 1, 2], ids=['older', 'tied', 'newer'])
def test_risk_prefix_and_continuation_range_survive_index_order(database, monkeypatch, order, nonmatching_stamp):
    seed(database, 'nonmatching', report=singleton_report('zero'), count=650, stamp=nonmatching_stamp)
    seed(database, 'matching', report=singleton_report(), count=6, stamp=1)
    publish(database)
    engine, _ = database
    original_sources = source_rows(database)
    with engine.begin() as connection:
        connection.exec_driver_sql('DROP INDEX ix_asset_group_head_page')
        connection.exec_driver_sql('DROP INDEX ix_asset_group_head_risk_page')
        for name in order:
            connection.exec_driver_sql(INDEX_DEFINITIONS[
                'ix_asset_group_head_risk_page' if name == 'risk' else 'ix_asset_group_head_page'])
    # Discard cached DBAPI statements so EXPLAIN observes this creation order.
    engine.dispose()
    statements, reopened = [], []
    original = sources.SourceReader.observation

    def observe(self, row, organization):
        reopened.append(row.id)
        return original(self, row, organization)

    def capture(connection, cursor, statement, parameters, context, many):
        if statement.startswith('SELECT ') and 'asset_group_index.risk_level = ?' in statement:
            statements.append((statement, parameters))

    monkeypatch.setattr(sources.SourceReader, 'observation', observe)
    event.listen(engine, 'before_cursor_execute', capture)
    found, cursor = [], None
    try:
        for _ in range(4):
            query = [('limit', '2'), ('risk_level', 'high')]
            if cursor:
                query.append(('cursor', cursor))
            response = page(database, query)
            found.extend(response['asset_groups'])
            cursor = response['next_cursor']
            if cursor is None:
                assert response['coverage']['search_complete'] is True
                break
        else:
            pytest.fail('Owned risk traversal did not finish')
    finally:
        event.remove(engine, 'before_cursor_execute', capture)
    identifiers = [item['latest_observation']['id'] for item in found]
    assert sorted(identifiers) == ['matching-' + str(index).zfill(5) for index in range(6)]
    assert len({item['id'] for item in found}) == 6
    assert all(item['latest_observation_risk']['risk_score'] == 70 for item in found)
    assert reopened == identifiers
    assert source_rows(database) == original_sources
    assert len(statements) == 3
    with engine.connect() as connection:
        observed_version = connection.exec_driver_sql('SELECT sqlite_version()').scalar_one()
        options = connection.exec_driver_sql('PRAGMA compile_options').scalars().all()
        for index, (statement, parameters) in enumerate(statements):
            details = [row[3] for row in connection.exec_driver_sql('EXPLAIN QUERY PLAN ' + statement, parameters)]
            diagnostic = {'sqlite_version': observed_version, 'compile_options': options,
                          'index_order': order, 'nonmatching_stamp': nonmatching_stamp, 'plan': details}
            assert 'asset_group_index.is_latest = 1' in statement, diagnostic
            assert any('INDEX ix_asset_group_head_risk_page (' in detail and 'risk_level=?' in detail
                       and 'is_latest=?' in detail and 'publication_nonce=?' in detail for detail in details), diagnostic
            assert not any('TEMP B-TREE' in detail for detail in details), diagnostic
            if index:
                assert 'asset_group_index.observed_at_us <= ?' in statement, diagnostic
                assert any('observed_at_us<?' in detail for detail in details), diagnostic
