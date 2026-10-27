"""Generation invalidation follows committed observation and canonical source changes."""

import re
from copy import deepcopy
from datetime import datetime, timedelta

import pytest
from sqlalchemy import Index, create_engine, delete, event, insert, inspect, select, update

from src.core import schema
from src.core.inventory_generation import (
    INDEX_DEFINITIONS, TABLE_NAME, TRIGGER_DEFINITIONS, InventorySchemaError,
    register_inventory_metadata,
)
from tests.historical_schema import historical_metadata
from tests.test_api_auth import api as api


@pytest.fixture
def database(api, tmp_path):
    module, _ = api
    engine = create_engine('sqlite:///' + str(tmp_path / 'generation.sqlite'))
    yield module, engine
    engine.dispose()


def token_state(connection):
    return dict(connection.exec_driver_sql(
        'SELECT organization_id,generation FROM inventory_generation').all())


def fingerprint(engine):
    with engine.connect() as connection:
        definitions = connection.exec_driver_sql(
            'SELECT type,name,tbl_name,sql FROM sqlite_master ORDER BY name').all()
        rows = {}
        for name in sorted(inspect(connection).get_table_names()):
            quoted = connection.dialect.identifier_preparer.quote(name)
            rows[name] = connection.exec_driver_sql('SELECT * FROM ' + quoted).all()
        return definitions, rows


def scan_values(identifier, owner):
    return dict(id=identifier, organization_id=owner, scan_name=identifier,
                scan_type='security_only', target_scope={}, scan_config={})


def observation_values(identifier, scan):
    return dict(id=identifier, scan_id=scan, agent_name=identifier, agent_type='assistant',
                discovery_method='fixture', metadata={'asset_id': identifier})


def seed_owned(engine, metadata):
    with engine.begin() as connection:
        connection.execute(insert(metadata.tables['scan_session']), [
            scan_values('scan-a', 'tenant-a'), scan_values('scan-b', 'tenant-b')])
        connection.execute(insert(metadata.tables['discovered_agent']), [
            observation_values('asset-a', 'scan-a'), observation_values('asset-b', 'scan-b')])
    with engine.connect() as connection:
        return token_state(connection)


def assert_changed(before, after, owners):
    assert set(before) == set(after)
    for owner in before:
        assert bool(before[owner] != after[owner]) is bool(owner in owners)
    assert all(re.fullmatch('[0-9a-f]{32}', value) for value in after.values())


def test_fresh_registration_and_restart_are_exact_and_do_not_churn(database):
    from src.core.asset_group_storage import TRIGGER_DEFINITIONS as group_triggers
    module, engine = database
    metadata = module.db.metadata
    assert register_inventory_metadata(metadata) is metadata.tables[TABLE_NAME]
    schema.initialize_schema(engine, metadata)
    with engine.connect() as connection:
        assert token_state(connection) == {}
        assert dict(connection.exec_driver_sql(
            "SELECT name,sql FROM sqlite_master WHERE type='trigger'").all()) == dict(TRIGGER_DEFINITIONS, **group_triggers)
        indexes = dict(connection.exec_driver_sql(
            "SELECT name,sql FROM sqlite_master WHERE type='index'").all())
        assert {name: indexes[name] for name in INDEX_DEFINITIONS} == INDEX_DEFINITIONS
    seed_owned(engine, metadata)
    before = fingerprint(engine)
    schema.initialize_schema(engine, metadata)
    assert fingerprint(engine) == before


def test_schema_four_upgrade_reconciles_only_caches_and_preserves_archives_and_operator_indexes(database):
    module, engine = database
    old = historical_metadata(version=4)
    old.create_all(engine)
    with engine.begin() as connection:
        connection.execute(insert(old.tables['schema_version']).values(id=1, version=4))
        connection.execute(insert(old.tables['scan_session']), [
            dict(scan_values('scan-a', 'tenant-a'), overall_risk_score=99.0),
            dict(scan_values('scan-b', 'tenant-b'), overall_risk_score=None)])
        connection.execute(insert(old.tables['discovered_agent']), [
            dict(observation_values('asset-a', 'scan-a'), risk_score=99.0, risk_level='critical'),
            dict(observation_values('asset-b', 'scan-b'), risk_score=None, risk_level='unknown')])
        connection.execute(insert(old.tables['scan_result']).values(scan_id='scan-a', result={}))
        connection.exec_driver_sql('UPDATE scan_result SET result=?', (b'{uninterpretable\xff',))
        connection.exec_driver_sql(
            "CREATE INDEX operator_partial ON discovered_agent (agent_name COLLATE NOCASE DESC) WHERE risk_level='critical'")
    prior_definitions, prior_rows = fingerprint(engine)
    statements = []
    def observe(_connection, _cursor, statement, _parameters, _context, _many):
        statements.append(statement)
    event.listen(engine, 'before_cursor_execute', observe)
    try:
        schema.initialize_schema(engine, module.db.metadata)
    finally:
        event.remove(engine, 'before_cursor_execute', observe)
    definitions, rows = fingerprint(engine)
    expected = deepcopy(prior_rows)
    expected['schema_version'] = [(1, schema.SCHEMA_VERSION)]
    for name, values in [('scan_session', {'overall_risk_score': None}),
                         ('discovered_agent', {'risk_score': None, 'risk_level': 'unknown'})]:
        columns = list(old.tables[name].columns.keys())
        expected[name] = [tuple(values.get(column, value) for column, value in zip(columns, row, strict=True))
                          for row in expected[name]]
    from tests.asset_group_schema_assertions import without_group_rows
    assert {name: value for name, value in without_group_rows(rows).items() if name != TABLE_NAME} == expected
    assert set(rows[TABLE_NAME][i][0] for i in range(len(rows[TABLE_NAME]))) == {'tenant-a', 'tenant-b'}
    assert all(re.fullmatch('[0-9a-f]{32}', row[1]) for row in rows[TABLE_NAME])
    assert set(prior_definitions) <= set(definitions)
    assert not any('DROP TABLE' in statement or '_aiscan_v4_' in statement for statement in statements)
    cache_updates = [statement for statement in statements if statement.upper().startswith(
        ('UPDATE SCAN_SESSION', 'UPDATE DISCOVERED_AGENT'))]
    assert len(cache_updates) == 2
    assert any('SET overall_risk_score=' in statement for statement in cache_updates)
    assert any('SET risk_score=?, risk_level=' in statement for statement in cache_updates)


@pytest.mark.parametrize('version', [1, 2, 3])
def test_older_upgrades_apply_nullable_migration_before_generation(database, version):
    module, engine = database
    old = historical_metadata(version=version)
    old.create_all(engine)
    with engine.begin() as connection:
        connection.execute(insert(old.tables['schema_version']).values(id=1, version=version))
        connection.execute(insert(old.tables['scan_session']).values(
            **scan_values('scan-a', 'tenant-a'), overall_risk_score=99.0))
        connection.execute(insert(old.tables['discovered_agent']).values(
            **observation_values('asset-a', 'scan-a'), risk_score=99.0, risk_level='critical'))
    schema.initialize_schema(engine, module.db.metadata)
    with engine.connect() as connection:
        assert connection.exec_driver_sql('SELECT version FROM schema_version').scalar_one() == schema.SCHEMA_VERSION
        assert connection.exec_driver_sql('SELECT overall_risk_score FROM scan_session').scalar_one() is None
        assert connection.exec_driver_sql('SELECT risk_score,risk_level FROM discovered_agent').one() == (None, 'unknown')
        assert set(token_state(connection)) == {'tenant-a'}


@pytest.mark.parametrize('table_name,operation', [(name, operation) for name in
                         ['discovered_agent', 'scan_result'] for operation in ['insert', 'update', 'delete']])
def test_core_source_writes_invalidate_only_the_owning_tenant(database, table_name, operation):
    module, engine = database
    schema.initialize_schema(engine, module.db.metadata)
    seed_owned(engine, module.db.metadata)
    table = module.db.metadata.tables[table_name]
    if table_name == 'scan_result' and operation != 'insert':
        with engine.begin() as connection:
            connection.execute(insert(table).values(scan_id='scan-a', result={'status': 'partial'}))
    with engine.begin() as connection:
        before = token_state(connection)
        if table_name == 'discovered_agent':
            if operation == 'insert':
                connection.execute(insert(table).values(**observation_values('added', 'scan-a')))
            elif operation == 'update':
                connection.execute(update(table).where(table.c.id == 'asset-a').values(metadata={'asset_id': 'new-alias'}))
            else:
                connection.execute(delete(table).where(table.c.id == 'asset-a'))
        elif operation == 'insert':
            connection.execute(insert(table).values(scan_id='scan-a', result={'status': 'partial'}))
        elif operation == 'update':
            connection.execute(update(table).where(table.c.scan_id == 'scan-a').values(result={'status': 'completed'}))
        else:
            connection.execute(delete(table).where(table.c.scan_id == 'scan-a'))
        assert_changed(before, token_state(connection), {'tenant-a'})


@pytest.mark.parametrize('table_name', ['discovered_agent', 'scan_result'])
def test_core_source_move_invalidates_both_tenants(database, table_name):
    module, engine = database
    schema.initialize_schema(engine, module.db.metadata)
    seed_owned(engine, module.db.metadata)
    table = module.db.metadata.tables[table_name]
    with engine.begin() as connection:
        if table_name == 'scan_result':
            connection.execute(insert(table).values(scan_id='scan-a', result={}))
        before = token_state(connection)
        connection.execute(update(table).where(table.c.scan_id == 'scan-a').values(scan_id='scan-b'))
        assert_changed(before, token_state(connection), {'tenant-a', 'tenant-b'})


def test_orm_alias_and_archive_writes_invalidate_generations(api):
    module, _ = api
    session = module.db.session
    session.add(module.ScanSession(**scan_values('orm', 'tenant-a')))
    session.add(module.DiscoveredAgentModel(id='orm-asset', scan_id='orm', agent_name='ORM fixture',
                agent_type='assistant', discovery_method='fixture'))
    session.add(module.ScanResult(scan_id='orm', result={'status': 'partial'}))
    session.commit()
    table = module.db.metadata.tables[TABLE_NAME]
    first = session.scalar(select(table.c.generation))
    session.get(module.DiscoveredAgentModel, 'orm-asset').metadata_json = {'asset_id': 'changed'}
    session.commit()
    second = session.scalar(select(table.c.generation))
    assert second != first
    session.get(module.ScanResult, 'orm').result = {'status': 'completed'}
    session.commit()
    assert session.scalar(select(table.c.generation)) != second


def test_session_ownership_and_id_moves_invalidate_old_and_new_orgs(database):
    module, engine = database
    schema.initialize_schema(engine, module.db.metadata)
    seed_owned(engine, module.db.metadata)
    scans = module.db.metadata.tables['scan_session']
    assets = module.db.metadata.tables['discovered_agent']
    with engine.begin() as connection:
        before = token_state(connection)
        connection.execute(update(scans).where(scans.c.id == 'scan-a').values(organization_id='tenant-b'))
        assert_changed(before, token_state(connection), {'tenant-a', 'tenant-b'})
        connection.execute(insert(assets).values(**observation_values('orphan', 'future-id')))
        before = token_state(connection)
        connection.execute(update(scans).where(scans.c.id == 'scan-a').values(id='future-id', organization_id='tenant-a'))
        assert_changed(before, token_state(connection), {'tenant-a', 'tenant-b'})
        assert connection.scalar(select(assets.c.scan_id).where(assets.c.id == 'asset-a')) == 'scan-a'


def test_orphan_visibility_changes_when_session_is_inserted_or_deleted(database):
    module, engine = database
    schema.initialize_schema(engine, module.db.metadata)
    seed_owned(engine, module.db.metadata)
    scans = module.db.metadata.tables['scan_session']
    assets = module.db.metadata.tables['discovered_agent']
    reports = module.db.metadata.tables['scan_result']
    with engine.begin() as connection:
        before = token_state(connection)
        connection.execute(insert(assets).values(**observation_values('orphan', 'late')))
        connection.execute(insert(reports).values(scan_id='late', result={}))
        assert token_state(connection) == before
        connection.execute(insert(scans).values(**scan_values('late', 'tenant-a')))
        assert_changed(before, token_state(connection), {'tenant-a'})
        before = token_state(connection)
        connection.execute(delete(scans).where(scans.c.id == 'late'))
        assert_changed(before, token_state(connection), {'tenant-a'})
        assert connection.scalar(select(assets.c.id).where(assets.c.id == 'orphan')) == 'orphan'
        before = token_state(connection)
        connection.execute(delete(assets).where(assets.c.id == 'orphan'))
        connection.execute(delete(reports).where(reports.c.scan_id == 'late'))
        assert token_state(connection) == before


def test_progress_only_updates_do_not_invalidate_and_source_rollback_restores_token(database):
    module, engine = database
    schema.initialize_schema(engine, module.db.metadata)
    seed_owned(engine, module.db.metadata)
    scans = module.db.metadata.tables['scan_session']
    assets = module.db.metadata.tables['discovered_agent']
    with engine.begin() as connection:
        before = token_state(connection)
        connection.execute(update(scans).where(scans.c.id == 'scan-a').values(
            progress=70.0, status='running', scan_name='Renamed run'))
        assert token_state(connection) == before
        connection.execute(update(scans).where(scans.c.id == 'scan-a').values(
            id='scan-a', organization_id='tenant-a'))
        assert token_state(connection) == before
    before = fingerprint(engine)
    with engine.connect() as connection:
        transaction = connection.begin()
        old_tokens = token_state(connection)
        connection.execute(update(assets).where(assets.c.id == 'asset-a').values(agent_type='tool'))
        assert_changed(old_tokens, token_state(connection), {'tenant-a'})
        transaction.rollback()
    assert fingerprint(engine) == before


@pytest.mark.parametrize('mutation', ['missing_trigger', 'altered_trigger', 'extra_trigger',
                                    'missing_index', 'altered_index'])
def test_current_definition_tampering_is_rejected_without_further_mutation(database, mutation):
    module, engine = database
    schema.initialize_schema(engine, module.db.metadata)
    seed_owned(engine, module.db.metadata)
    trigger = next(iter(TRIGGER_DEFINITIONS))
    index = next(iter(INDEX_DEFINITIONS))
    with engine.begin() as connection:
        if mutation in ('missing_trigger', 'altered_trigger'):
            connection.exec_driver_sql('DROP TRIGGER ' + trigger)
            if mutation == 'altered_trigger':
                connection.exec_driver_sql('CREATE TRIGGER ' + trigger +
                    ' AFTER INSERT ON discovered_agent BEGIN SELECT 1; END')
        elif mutation == 'extra_trigger':
            connection.exec_driver_sql(
                'CREATE TRIGGER operator_trigger AFTER INSERT ON scan_result BEGIN SELECT 1; END')
        else:
            connection.exec_driver_sql('DROP INDEX ' + index)
            if mutation == 'altered_index':
                connection.exec_driver_sql('CREATE INDEX ' + index + ' ON scan_session (scan_name)')
    before = fingerprint(engine)
    with pytest.raises(schema.SchemaError):
        schema.initialize_schema(engine, module.db.metadata)
    assert fingerprint(engine) == before


@pytest.mark.parametrize('reserved_name', ['ix_inventory_observation_scan_order',
                                         'IX_INVENTORY_OBSERVATION_SCAN_ORDER'])
def test_reserved_index_collision_rolls_back_before_version_four_changes(database, reserved_name):
    module, engine = database
    old = historical_metadata(version=4)
    old.create_all(engine)
    with engine.begin() as connection:
        connection.execute(insert(old.tables['schema_version']).values(id=1, version=4))
        connection.execute(insert(old.tables['scan_session']).values(**scan_values('old', 'tenant-a')))
        connection.exec_driver_sql('CREATE INDEX ' + reserved_name + ' ON scan_session (scan_name)')
    before = fingerprint(engine)
    with pytest.raises(schema.SchemaError, match='Reserved inventory index'):
        schema.initialize_schema(engine, module.db.metadata)
    assert fingerprint(engine) == before


@pytest.mark.parametrize('reserved_name', ['ix_inventory_observation_scan_order',
                                         'IX_INVENTORY_OBSERVATION_SCAN_ORDER'])
def test_metadata_registration_rejects_reserved_index_collisions(reserved_name):
    metadata = historical_metadata(version=4)
    Index(reserved_name, metadata.tables['scan_session'].c.scan_name)
    with pytest.raises(InventorySchemaError, match='Reserved inventory index'):
        register_inventory_metadata(metadata)


def test_generation_install_failure_rolls_back_tables_indexes_triggers_and_stamp(database):
    module, engine = database
    old = historical_metadata(version=4)
    old.create_all(engine)
    with engine.begin() as connection:
        connection.execute(insert(old.tables['schema_version']).values(id=1, version=4))
        connection.execute(insert(old.tables['scan_session']).values(**scan_values('old', 'tenant-a')))
    before = fingerprint(engine)
    def fail_install(_connection, _cursor, statement, _parameters, _context, _many):
        if statement.startswith('CREATE TRIGGER aiscan_inventory_report_insert'):
            raise RuntimeError('Synthetic generation installation interruption')
    event.listen(engine, 'before_cursor_execute', fail_install)
    try:
        with pytest.raises(RuntimeError, match='Synthetic generation'):
            schema.initialize_schema(engine, module.db.metadata)
    finally:
        event.remove(engine, 'before_cursor_execute', fail_install)
    assert fingerprint(engine) == before


@pytest.mark.parametrize('filtered', [False, True])
def test_ten_thousand_observation_plan_uses_owner_and_candidate_indexes(database, filtered):
    module, engine = database
    old = historical_metadata(version=4)
    old.create_all(engine)
    scans, assets = old.tables['scan_session'], old.tables['discovered_agent']
    with engine.begin() as connection:
        connection.execute(insert(old.tables['schema_version']).values(id=1, version=4))
        connection.execute(insert(scans), [
            scan_values('scan-' + str(number), 'tenant-a' if number % 2 == 0 else 'tenant-b')
            for number in range(40)])
        start = datetime(2026, 1, 1)
        rows = []
        for number in range(10000):
            values = observation_values('asset-' + str(number), 'scan-' + str(number % 40))
            values.update(agent_type='assistant' if number % 3 else 'gateway',
                          discovered_at=start + timedelta(seconds=number))
            rows.append(values)
        connection.execute(insert(assets), rows)
    schema.initialize_schema(engine, module.db.metadata)
    statement = select(assets.c.id, assets.c.scan_id, assets.c.agent_name, assets.c.agent_type,
                       assets.c.provider, assets.c.discovered_at).select_from(
                           assets.join(scans, assets.c.scan_id == scans.c.id)).where(
                               scans.c.organization_id == 'tenant-a')
    if filtered:
        statement = statement.where(assets.c.agent_type == 'gateway')
    statement = statement.order_by(assets.c.discovered_at.desc(), assets.c.id).limit(501)
    sql = str(statement.compile(engine, compile_kwargs={'literal_binds': True}))
    with engine.connect() as connection:
        steps = [row[3] for row in connection.exec_driver_sql('EXPLAIN QUERY PLAN ' + sql)]
        plan = ' '.join(steps)
        assert 'ix_inventory_scan_session_org_id' in plan
        candidate_searches = [step for step in steps
                              if step.startswith('SEARCH discovered_agent ') and 'scan_id=?' in step]
        if filtered:
            assert any('ix_inventory_observation_scan_type_order' in step and 'agent_type=?' in step
                       for step in candidate_searches)
        else:
            # Both indexes begin with scan_id. SQLite may choose either for an
            # unfiltered join, which still requires the global ordering below.
            assert any(name in step for step in candidate_searches for name in
                       ('ix_inventory_observation_scan_order', 'ix_inventory_observation_scan_type_order'))
        # The join still sorts observations across scans; LIMIT bounds fetched rows,
        # not all SQLite work for this global ordering.
        assert 'USE TEMP B-TREE FOR ORDER BY' in plan
        found = connection.execute(statement).all()
        assert len(found) == 501
        assert all(int(row.scan_id.removeprefix('scan-')) % 2 == 0 for row in found)
