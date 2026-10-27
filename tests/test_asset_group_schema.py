"""Derived group storage upgrades preserve source records and invalidate writes."""

import pytest
from sqlalchemy import Index, create_engine, delete, event, insert, inspect, select, update
from sqlalchemy.orm import Session, registry

from src.core import schema
from src.core.asset_group_storage import (
    ACTIVE_FIELDS, COLUMNS, INDEX_DEFINITIONS, INDEX_TABLE, PUBLICATION_TABLE,
    TABLE_NAMES, TRIGGER_DEFINITIONS, AssetGroupSchemaError, register_asset_group_metadata,
)
from src.core.inventory_generation import register_inventory_metadata
from tests.historical_schema import SCHEMA_FIVE_TRIGGERS, historical_metadata


def current_metadata():
    # Fixed nullable source definitions have no runtime ORM or live triggers.
    metadata = historical_metadata(version=4)
    register_inventory_metadata(metadata)
    register_asset_group_metadata(metadata)
    return metadata


@pytest.fixture
def database(tmp_path):
    engine = create_engine('sqlite:///' + str(tmp_path / 'owned-groups.sqlite'))
    yield engine, current_metadata()
    engine.dispose()


def fingerprint(engine):
    with engine.connect() as connection:
        definitions = connection.exec_driver_sql(
            'SELECT type,name,tbl_name,sql FROM sqlite_master ORDER BY name').all()
        rows = {}
        for name in sorted(inspect(connection).get_table_names()):
            quoted = connection.dialect.identifier_preparer.quote(name)
            rows[name] = connection.exec_driver_sql('SELECT * FROM ' + quoted + ' ORDER BY 1,2').all()
        return definitions, rows


def seed_source(connection, metadata, *, owner='tenant-a', suffix='a'):
    scans, observations, reports = (metadata.tables[name] for name in ('scan_session', 'discovered_agent', 'scan_result'))
    connection.execute(insert(scans).values(
        id='scan-' + suffix, organization_id=owner, scan_name='Owned fixture', scan_type='discovery_only',
        status='completed', target_scope={}, scan_config={}, overall_risk_score=0.0))
    connection.execute(insert(observations).values(
        id='observation-' + suffix, scan_id='scan-' + suffix, agent_name='Owned fixture', agent_type='assistant',
        provider='ollama', model_name=None, endpoint_url='http://192.0.2.1:11434/',
        discovery_method='fixture', metadata={'asset_id': 'alias-' + suffix},
        risk_score=0.0, risk_level='minimal', vulnerabilities=[]))
    # Exact archived spacing remains untouched by the schema7-only upgrade.
    connection.exec_driver_sql('INSERT INTO scan_result(scan_id,result) VALUES (?,?)',
                               ('scan-' + suffix, '{ "original": [1, 2], "synthetic": true }'))


def row(*, owner='tenant-a', build='a' * 32, observation='observation-a', group='c' * 64, nonce=None,
        generation='d' * 32, policy='e' * 64):
    return dict(organization_id=owner, build_id=build, observation_id=observation,
                scan_id='scan-a', report_asset_id='alias-a', group_id=group, identity_status='grouped',
                unmerged_reason=None, target={'kind': 'http_target', 'provider': 'ollama', 'model': None,
                                             'evidence_context_id': None, 'endpoint': 'http://192.0.2.1:11434/'},
                observed_at_us=1, agent_type='assistant', is_latest=True, history_complete=True,
                group_history_complete=True, supported_confirmation_count=0, archived_claim_count=0,
                group_observation_count=1, group_supported_confirmation_count=0,
                group_archived_claim_count=0, publication_nonce=nonce,
                source_generation=generation, projection_policy=policy)


def publish(connection, metadata, *, owner='tenant-a', build='a' * 32, observation='observation-a', nonce='b' * 32,
            generation='d' * 32, policy='e' * 64):
    index, publication = metadata.tables[INDEX_TABLE], metadata.tables[PUBLICATION_TABLE]
    connection.execute(insert(index), row(owner=owner, build=build, observation=observation,
                                         generation=generation, policy=policy))
    # A genuine publisher seals staging rows before installing the active pointer.
    connection.execute(update(index).where(index.c.organization_id == owner,
                                           index.c.build_id == build).values(publication_nonce=nonce))
    active = dict(active_build_id=build, active_generation=generation, active_nonce=nonce,
                  active_policy=policy, active_row_count=1, active_group_count=1)
    connection.execute(insert(publication).values(organization_id=owner, processed_count=1, **active))
    return active


def test_fresh_registration_is_exact_and_restart_never_churns(database):
    engine, metadata = database
    assert register_asset_group_metadata(metadata) == (metadata.tables[INDEX_TABLE], metadata.tables[PUBLICATION_TABLE])
    schema.initialize_schema(engine, metadata)
    with engine.connect() as connection:
        assert connection.scalar(select(metadata.tables['schema_version'].c.version)) == 7
        triggers = dict(connection.exec_driver_sql("SELECT name,sql FROM sqlite_master WHERE type='trigger'").all())
        assert triggers == {**SCHEMA_FIVE_TRIGGERS, **TRIGGER_DEFINITIONS}
        indexes = dict(connection.exec_driver_sql("SELECT name,sql FROM sqlite_master WHERE type='index'").all())
        assert all(indexes[name] == definition for name, definition in INDEX_DEFINITIONS.items())
        assert connection.execute(select(metadata.tables[INDEX_TABLE])).all() == []
        assert connection.execute(select(metadata.tables[PUBLICATION_TABLE])).all() == []
    before = fingerprint(engine)
    schema.initialize_schema(engine, metadata)
    assert fingerprint(engine) == before


def test_schema_six_upgrade_preserves_every_existing_byte_and_cache(database):
    engine, metadata = database
    old = historical_metadata(version=5)
    old.create_all(engine)
    with engine.begin() as connection:
        connection.execute(insert(old.tables['schema_version']).values(id=1, version=6))
        seed_source(connection, old)
        connection.exec_driver_sql('CREATE INDEX operator_kept ON discovered_agent (provider) WHERE model_name IS NULL')
    before_definitions, before_rows = fingerprint(engine)
    schema.initialize_schema(engine, metadata)
    definitions, rows = fingerprint(engine)
    for name in before_rows:
        assert rows[name] == ([(1, 7)] if name == 'schema_version' else before_rows[name])
    assert set(rows) - set(before_rows) == TABLE_NAMES
    assert [entry for entry in definitions if entry in before_definitions] == before_definitions
    assert len(definitions) - len(before_definitions) == 10  # 2 tables,2 primary indexes,3 indexes,3 triggers.
    assert rows[INDEX_TABLE] == rows[PUBLICATION_TABLE] == []
    after = fingerprint(engine)
    schema.initialize_schema(engine, metadata)
    assert fingerprint(engine) == after


@pytest.mark.parametrize('old_version', [1, 2, 3, 4, 5])
def test_known_older_upgrade_order_still_reaches_seven(database, old_version):
    engine, metadata = database
    old = historical_metadata(version=old_version)
    old.create_all(engine)
    with engine.begin() as connection:
        connection.execute(insert(old.tables['schema_version']).values(id=1, version=old_version))
        seed_source(connection, old)
    schema.initialize_schema(engine, metadata)
    with engine.connect() as connection:
        assert connection.scalar(select(metadata.tables['schema_version'].c.version)) == 7
        assert connection.scalar(select(metadata.tables['scan_result'].c.result)) == {'original': [1, 2], 'synthetic': True}
        assert connection.scalar(select(metadata.tables['discovered_agent'].c.id)) == 'observation-a'
        assert connection.scalar(select(metadata.tables['discovered_agent'].c.risk_score)) is None


@pytest.mark.parametrize('mutation', ['insert-unsealed', 'insert-sealed', 'update', 'delete', 'move-owner', 'move-build'])
@pytest.mark.parametrize('recursive', [False, True])
def test_cache_mutations_invalidate_and_old_publication_cannot_restore_trust(database, mutation, recursive):
    engine, metadata = database
    schema.initialize_schema(engine, metadata)
    index, publication = metadata.tables[INDEX_TABLE], metadata.tables[PUBLICATION_TABLE]
    with engine.begin() as connection:
        connection.exec_driver_sql('PRAGMA recursive_triggers = ' + ('ON' if recursive else 'OFF'))
        original = publish(connection, metadata)
        other = publish(connection, metadata, owner='tenant-b', build='f' * 32, observation='observation-b', nonce='1' * 32)
        selected = index.c.organization_id == 'tenant-a'
        if mutation.startswith('insert'):
            value = row(observation='extra-observation', group='2' * 64,
                        nonce=original['active_nonce'] if mutation == 'insert-sealed' else None)
            connection.execute(insert(index), value)
        elif mutation == 'delete':
            connection.execute(delete(index).where(selected))
        elif mutation == 'move-owner':
            connection.execute(update(index).where(selected).values(organization_id='tenant-c'))
        elif mutation == 'move-build':
            connection.execute(update(index).where(selected).values(build_id='3' * 32))
        else:
            connection.execute(update(index).where(selected).values(group_supported_confirmation_count=99))
        active = connection.execute(select(publication).where(publication.c.organization_id == 'tenant-a')).mappings().one()
        assert all(active[name] is None for name in ACTIVE_FIELDS)
        unaffected = connection.execute(select(publication).where(publication.c.organization_id == 'tenant-b')).mappings().one()
        assert {name: unaffected[name] for name in ACTIVE_FIELDS} == other
        connection.execute(update(publication).where(publication.c.organization_id == 'tenant-a').values(**original))
        scoped = connection.execute(select(index.c.publication_nonce).where(selected, index.c.build_id == 'a' * 32)).scalars().all()
        total, sealed = len(scoped), sum(value == original['active_nonce'] for value in scoped)
        assert not (total == sealed == original['active_row_count'])


def test_staging_updates_and_sealing_leave_existing_active_build_unchanged(database):
    engine, metadata = database
    schema.initialize_schema(engine, metadata)
    index, publication = metadata.tables[INDEX_TABLE], metadata.tables[PUBLICATION_TABLE]
    with engine.begin() as connection:
        original = publish(connection, metadata)
        connection.execute(insert(index), row(build='f' * 32))
        connection.execute(update(index).where(index.c.build_id == 'f' * 32).values(group_observation_count=2))
        connection.execute(update(index).where(index.c.build_id == 'f' * 32).values(publication_nonce='4' * 32))
        active = connection.execute(select(publication)).mappings().one()
        assert {name: active[name] for name in ACTIVE_FIELDS} == original
        assert connection.scalar(select(index.c.publication_nonce).where(index.c.build_id == 'f' * 32)) == '4' * 32


def test_orm_cache_update_invalidates_and_transaction_rollback_restores(database):
    engine, metadata = database
    schema.initialize_schema(engine, metadata)
    index, publication = metadata.tables[INDEX_TABLE], metadata.tables[PUBLICATION_TABLE]
    with engine.begin() as connection:
        original = publish(connection, metadata)
    before = fingerprint(engine)
    mapper = registry()

    class CacheRow:
        pass

    mapper.map_imperatively(CacheRow, index)
    with Session(engine) as session:
        value = session.get(CacheRow, ('tenant-a', 'a' * 32, 'observation-a'))
        value.is_latest = False
        session.flush()
        assert session.scalar(select(publication.c.active_build_id)) is None
        assert session.scalar(select(index.c.publication_nonce)) is None
        session.rollback()
    assert fingerprint(engine) == before
    with engine.connect() as connection:
        assert connection.scalar(select(publication.c.active_build_id)) == original['active_build_id']
    mapper.dispose()


@pytest.mark.parametrize('mutation', ['missing-trigger', 'altered-trigger', 'extra-trigger', 'missing-index',
                                      'altered-index', 'unknown-unique', 'extra-column', 'head-duplicate'])
def test_unsupported_current_layout_is_rejected_without_changes(database, mutation):
    engine, metadata = database
    schema.initialize_schema(engine, metadata)
    with engine.begin() as connection:
        if mutation == 'missing-trigger':
            connection.exec_driver_sql('DROP TRIGGER aiscan_asset_group_index_delete')
        elif mutation == 'altered-trigger':
            connection.exec_driver_sql('DROP TRIGGER aiscan_asset_group_index_delete')
            connection.exec_driver_sql('CREATE TRIGGER aiscan_asset_group_index_delete AFTER DELETE ON asset_group_index BEGIN SELECT 1; END')
        elif mutation == 'extra-trigger':
            connection.exec_driver_sql('CREATE TRIGGER unrecognized AFTER INSERT ON asset_group_publication BEGIN SELECT 1; END')
        elif mutation == 'missing-index':
            connection.exec_driver_sql('DROP INDEX ix_asset_group_history')
        elif mutation == 'altered-index':
            connection.exec_driver_sql('DROP INDEX ix_asset_group_history')
            connection.exec_driver_sql('CREATE INDEX ix_asset_group_history ON asset_group_index (group_id)')
        elif mutation == 'unknown-unique':
            connection.exec_driver_sql('CREATE UNIQUE INDEX unrecognized_unique ON asset_group_publication (error_code)')
        elif mutation == 'extra-column':
            connection.exec_driver_sql('ALTER TABLE asset_group_index ADD COLUMN unexpected TEXT')
        else:
            connection.exec_driver_sql('DROP INDEX ux_asset_group_head')
            connection.exec_driver_sql('CREATE UNIQUE INDEX ux_asset_group_head ON asset_group_index (organization_id,build_id,group_id)')
    before = fingerprint(engine)
    with pytest.raises(schema.SchemaError):
        schema.initialize_schema(engine, metadata)
    assert fingerprint(engine) == before


@pytest.mark.parametrize('index_name', list(INDEX_DEFINITIONS))
def test_old_layout_reserved_index_collisions_fail_before_install(database, index_name):
    engine, metadata = database
    old = historical_metadata(version=5)
    old.create_all(engine)
    with engine.begin() as connection:
        connection.execute(insert(old.tables['schema_version']).values(id=1, version=6))
        connection.exec_driver_sql('CREATE INDEX ' + index_name + ' ON discovered_agent (provider)')
    before = fingerprint(engine)
    with pytest.raises(schema.SchemaError):
        schema.initialize_schema(engine, metadata)
    assert fingerprint(engine) == before


def test_install_failure_rolls_back_new_tables_indexes_triggers_and_stamp(database):
    engine, metadata = database
    old = historical_metadata(version=5)
    old.create_all(engine)
    with engine.begin() as connection:
        connection.execute(insert(old.tables['schema_version']).values(id=1, version=6))
        seed_source(connection, old)
    before = fingerprint(engine)

    def fail(connection, cursor, statement, parameters, context, many):
        if statement.startswith('CREATE TRIGGER aiscan_asset_group_index_update'):
            raise RuntimeError('Owned synthetic migration interruption')

    event.listen(engine, 'before_cursor_execute', fail)
    try:
        with pytest.raises(RuntimeError, match='Owned synthetic migration interruption'):
            schema.initialize_schema(engine, metadata)
    finally:
        event.remove(engine, 'before_cursor_execute', fail)
    assert fingerprint(engine) == before


def test_only_one_head_per_build_and_group_is_enforced(database):
    from sqlalchemy.exc import IntegrityError

    engine, metadata = database
    schema.initialize_schema(engine, metadata)
    index = metadata.tables[INDEX_TABLE]
    with engine.begin() as connection:
        connection.execute(insert(index), row())
    with pytest.raises(IntegrityError), engine.begin() as connection:
        connection.execute(insert(index), row(observation='other-observation'))
    with engine.begin() as connection:
        connection.execute(insert(index), row(observation='other-observation', build='f' * 32))


@pytest.mark.parametrize('mutation', ['column', 'pk', 'reserved-index'])
def test_metadata_registration_rejects_conflicting_definitions(mutation):
    metadata = current_metadata()
    table = metadata.tables[INDEX_TABLE]
    if mutation == 'column':
        table.c.group_id.nullable = True
    elif mutation == 'pk':
        table.primary_key._columns.remove(table.c.observation_id)
    else:
        selected = next(index for index in table.indexes if index.name == 'ix_asset_group_history')
        table.indexes.remove(selected)
        Index('ix_asset_group_history', metadata.tables['discovered_agent'].c.provider)
    with pytest.raises(AssetGroupSchemaError):
        register_asset_group_metadata(metadata)


def test_frozen_table_descriptors_have_no_server_defaults_or_foreign_keys(database):
    _, metadata = database
    for name, expected in COLUMNS.items():
        table = metadata.tables[name]
        assert [(column.name, str(column.type).upper(), column.nullable) for column in table.columns] == list(expected)
        assert all(column.server_default is None for column in table.columns)
        assert not table.foreign_keys
    assert len(INDEX_DEFINITIONS) == len(TRIGGER_DEFINITIONS) == 3
    assert schema.VERSION_SEVEN_TABLES - schema.VERSION_SIX_TABLES == TABLE_NAMES


@pytest.mark.parametrize('field', ['generation', 'policy'])
def test_publication_metadata_alone_cannot_retarget_sealed_rows(database, field):
    engine, metadata = database
    schema.initialize_schema(engine, metadata)
    index, publication = metadata.tables[INDEX_TABLE], metadata.tables[PUBLICATION_TABLE]
    generations, reports = metadata.tables['inventory_generation'], metadata.tables['scan_result']
    with engine.begin() as connection:
        seed_source(connection, metadata)
        original_generation = connection.scalar(select(generations.c.generation))
        original = publish(connection, metadata, generation=original_generation)
        if field == 'generation':
            # The source row count stays1; only the archived report changes.
            connection.execute(update(reports).values(result={'synthetic': 'changed-source'}))
            current_generation = connection.scalar(select(generations.c.generation))
            assert current_generation != original_generation
            connection.execute(update(publication).values(active_generation=current_generation))
            current_policy = original['active_policy']
        else:
            current_generation, current_policy = original_generation, 'f' * 64
            connection.execute(update(publication).values(active_policy=current_policy))
        cached = connection.execute(select(index)).mappings().one()
        assert cached['publication_nonce'] == original['active_nonce']
        assert cached['source_generation'] == original_generation
        assert cached['projection_policy'] == original['active_policy']
        matching = connection.execute(select(index.c.observation_id).where(
            index.c.organization_id == 'tenant-a', index.c.build_id == original['active_build_id'],
            index.c.publication_nonce == original['active_nonce'],
            index.c.source_generation == current_generation,
            index.c.projection_policy == current_policy)).all()
        assert matching == []
