"""Prepared reads retain per-observation ownership, bounds and source checks."""

import time

import pytest
from sqlalchemy import event, update

from src.core import asset_group_projection as sources
from src.core.inventory import InventoryError
from tests.test_asset_groups import database as database, history, page, publish, seed


def test_history_reuses_only_the_statement_with_fresh_bindings_each_page(database):
    seed(database, 'owned', count=4)
    publish(database)
    group = page(database)['asset_groups'][0]['id']
    statements, bindings = [], []

    def capture(connection, statement, multiparams, parameters, execution_options):
        if 'group_observation_id' in parameters:
            statements.append(statement)
            bindings.append(dict(parameters))

    engine, _ = database
    event.listen(engine, 'before_execute', capture)
    try:
        first = history(database, group, [('limit', '2')])
        second = history(database, group, [('limit', '2'), ('cursor', first['next_cursor'])])
    finally:
        event.remove(engine, 'before_execute', capture)
    records = first['history'] + second['history']
    assert [item['observation_id'] for item in records] == [f'owned-{index:05}' for index in range(4)]
    assert all(item['classification'] == 'supported_confirmation' for item in records)
    assert first['next_cursor'] and second['next_cursor'] is None
    assert len(statements) == 4
    assert statements[0] is statements[1]
    assert statements[2] is statements[3] and statements[2] is not statements[0]
    assert bindings == [{'group_observation_id': item['observation_id'], 'group_scan_id': 'owned',
                         'group_organization_id': 'tenant-a'} for item in records]


@pytest.mark.parametrize('observation,scan,organization', [
    ('owned-00000', 'owned', 'tenant-b'),
    ('owned-00000', 'other', 'tenant-a'),
    ('other-00000', 'other', 'tenant-a'),
    ('other-00000', 'owned', 'tenant-b'),
    ("owned-00000' OR 1=1 --", 'owned', 'tenant-a'),
    ('owned-00000', 'owned', "tenant-a' OR 1=1 --"),
])
def test_warmed_statement_does_not_reuse_prior_identity_or_ownership(database, observation, scan, organization):
    seed(database, 'owned')
    seed(database, 'other', organization='tenant-b')
    engine, tables = database
    with engine.connect() as connection:
        reader = sources.SourceReader(connection, tables, time.monotonic() + 5)
        assert reader.observation_row('owned-00000', 'owned', 'tenant-a').id == 'owned-00000'
        assert reader.observation_row(observation, scan, organization) is None
        assert reader.observation_row('other-00000', 'other', 'tenant-b').id == 'other-00000'


@pytest.mark.parametrize('column,size,field', [
    ('agent_name', 1021, 'agent_name'),
    ('provider', 401, 'provider'),
    ('model_name', 1021, 'model_name'),
    ('endpoint_url', 16385, 'endpoint_url'),
])
def test_prepared_read_bounds_source_text_before_materialization(database, column, size, field):
    seed(database, 'owned')
    engine, tables = database
    with engine.begin() as connection:
        connection.execute(update(tables['observations']).values({column: 'x' * size}))
    with engine.connect() as connection:
        reader = sources.SourceReader(connection, tables, time.monotonic() + 5)
        record = reader.observation_row('owned-00000', 'owned', 'tenant-a')
        assert getattr(record, field) is None
        assert getattr(record, field + '_is_null') is False
        with pytest.raises(InventoryError) as error:
            reader.observation(record, 'tenant-a')
        assert error.value.status == 503


def test_reused_statement_reads_changed_row_instead_of_caching_results(database):
    seed(database, 'owned')
    engine, tables = database
    with engine.begin() as connection:
        reader = sources.SourceReader(connection, tables, time.monotonic() + 5)
        original = reader.observation_row('owned-00000', 'owned', 'tenant-a')
        assert reader.observation(original, 'tenant-a').supported_count == 1
        changed_endpoint = 'https://different-owned.invalid/resource'
        connection.execute(update(tables['observations']).values(endpoint_url=changed_endpoint))
        changed = reader.observation_row('owned-00000', 'owned', 'tenant-a')
        assert changed.endpoint_url == changed_endpoint
        result = reader.observation(changed, 'tenant-a')
        assert result.identity.reason == 'snapshot_target_mismatch'
        assert result.supported_count is None and result.risk['risk_score'] is None


def test_prepared_read_obeys_expired_budget_without_querying(database):
    engine, tables = database

    def forbidden(*args, **kwargs):
        raise AssertionError('An expired source read must not issue a query')

    with engine.connect() as connection:
        reader = sources.SourceReader(connection, tables, time.monotonic() - 1)
        event.listen(engine, 'before_execute', forbidden)
        try:
            with pytest.raises(sources.PageBudget):
                reader.observation_row('owned-00000', 'owned', 'tenant-a')
        finally:
            event.remove(engine, 'before_execute', forbidden)
