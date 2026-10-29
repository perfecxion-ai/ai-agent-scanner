"""Frozen schema-7 source and populated cache preservation across schema 8."""

from contextlib import closing
import sqlite3

import pytest
from sqlalchemy import create_engine, event, insert, inspect, select

from src.core import schema
from src.core.asset_group_storage import RISK_COLUMNS, SCHEMA_SEVEN_COLUMNS
from tests.historical_schema import SCHEMA_SEVEN_GROUP_COLUMNS, historical_metadata
from tests.test_asset_group_schema import current_metadata, fingerprint, publish, seed_source


def frozen_source(engine):
    old = historical_metadata(version=7)
    old.create_all(engine)
    with engine.begin() as connection:
        connection.execute(insert(old.tables['schema_version']).values(id=1, version=7))
        seed_source(connection, old)
        publish(connection, old)
        connection.exec_driver_sql('CREATE INDEX operator_source_kept ON discovered_agent (provider)')
        connection.exec_driver_sql('CREATE INDEX operator_group_kept ON asset_group_index (scan_id) WHERE history_complete = 1')
    return fingerprint(engine)


def assert_preserved(engine, before):
    definitions, rows = fingerprint(engine)
    old_definitions, old_rows = before
    for name, previous in old_rows.items():
        if name == 'schema_version':
            assert rows[name] == [(1, 8)]
        elif name == 'asset_group_index':
            assert rows[name] == [tuple(value) + (None,) * 6 for value in previous]
        else:
            assert rows[name] == previous
    assert set(rows) == set(old_rows)
    previous = {row[1]: row for row in old_definitions}
    current = {row[1]: row for row in definitions}
    assert set(current) - set(previous) == {'ix_asset_group_head_risk_page'}
    assert all(current[name] == value for name, value in previous.items() if name != 'asset_group_index')
    added_sql = ', ' + ', '.join(name + ' ' + kind for name, kind, _ in RISK_COLUMNS)
    marker = 'projection_policy VARCHAR(64) NOT NULL'
    assert previous['asset_group_index'][3].count(marker) == 1
    assert current['asset_group_index'][3] == previous['asset_group_index'][3].replace(marker, marker + added_sql, 1)
    with engine.connect() as connection:
        columns = inspect(connection).get_columns('asset_group_index')
        assert [(value['name'], str(value['type']).upper(), value['nullable']) for value in columns] == (
            list(SCHEMA_SEVEN_GROUP_COLUMNS['asset_group_index']) + list(RISK_COLUMNS))
        assert all(value['default'] is None for value in columns)


def test_frozen_schema_seven_has_no_risk_fields_and_matches_recognized_baseline():
    old = historical_metadata(version=7)
    assert SCHEMA_SEVEN_COLUMNS == SCHEMA_SEVEN_GROUP_COLUMNS
    assert list(old.tables['asset_group_index'].columns.keys()) == [
        column for column, _, _ in SCHEMA_SEVEN_GROUP_COLUMNS['asset_group_index']]
    assert not set(name for name, _, _ in RISK_COLUMNS) & set(old.tables['asset_group_index'].columns.keys())


def test_schema_seven_nullable_addition_preserves_populated_sources_and_cache(tmp_path):
    engine = create_engine('sqlite:///' + str(tmp_path / 'frozen-seven.sqlite'))
    try:
        before = frozen_source(engine)
        schema.initialize_schema(engine, current_metadata())
        assert_preserved(engine, before)
        after = fingerprint(engine)
        schema.initialize_schema(engine, current_metadata())
        assert fingerprint(engine) == after
    finally:
        engine.dispose()


@pytest.mark.parametrize('failure_point', ['risk_score', 'security_status', 'risk_index', 'stamp'])
def test_schema_seven_upgrade_rolls_back_every_added_column_index_and_stamp(tmp_path, failure_point):
    engine = create_engine('sqlite:///' + str(tmp_path / 'rollback-seven.sqlite'))
    try:
        before = frozen_source(engine)

        def fail(connection, cursor, statement, parameters, context, many):
            target = ('ALTER TABLE asset_group_index ADD COLUMN ' + failure_point
                      if failure_point in {'risk_score', 'security_status'} else
                      'CREATE INDEX ix_asset_group_head_risk_page' if failure_point == 'risk_index' else
                      'UPDATE schema_version')
            if statement.startswith(target):
                raise RuntimeError('Owned schema 8 interruption')

        event.listen(engine, 'before_cursor_execute', fail)
        try:
            with pytest.raises(RuntimeError, match='Owned schema 8 interruption'):
                schema.initialize_schema(engine, current_metadata())
        finally:
            event.remove(engine, 'before_cursor_execute', fail)
        assert fingerprint(engine) == before
    finally:
        engine.dispose()


def test_stopped_schema_seven_backup_restores_then_adds_nullable_derived_columns(tmp_path):
    source, restored = tmp_path / 'source-seven.sqlite', tmp_path / 'restored-seven.sqlite'
    engine = create_engine('sqlite:///' + str(source))
    try:
        before = frozen_source(engine)
    finally:
        engine.dispose()
    with closing(sqlite3.connect(source.as_uri() + '?mode=ro', uri=True)) as origin:
        with closing(sqlite3.connect(restored)) as target:
            origin.backup(target)
    recovered = create_engine('sqlite:///' + str(restored))
    original = create_engine('sqlite:///' + str(source))
    try:
        assert fingerprint(recovered) == before
        schema.initialize_schema(recovered, current_metadata())
        assert_preserved(recovered, before)
        assert fingerprint(original) == before
        with recovered.connect() as connection:
            assert connection.scalar(select(current_metadata().tables['asset_group_publication'].c.active_policy)) == 'e' * 64
    finally:
        recovered.dispose()
        original.dispose()
