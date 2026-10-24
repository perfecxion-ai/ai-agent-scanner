"""Independent real SQLite checks for conservative nullable cache upgrades."""

from copy import deepcopy
import json

import pytest
from sqlalchemy import String, create_engine, event, insert

from src.core.schema import SCHEMA_VERSION, SchemaError, initialize_schema
from tests.historical_schema import historical_metadata
from tests.controlled_access import result as access_result
from tests.test_control_evidence_projections import report as access_report
from tests.test_api_auth import api as api


@pytest.fixture
def old_database(api, tmp_path):
    module, _ = api
    engine = create_engine('sqlite:///' + str(tmp_path / 'review.db'))
    old = historical_metadata(version=3)
    old.create_all(engine)
    with engine.begin() as connection:
        connection.execute(insert(old.tables['schema_version']).values(id=1, version=3))
    yield module, engine, old
    engine.dispose()


def seed(old_database, raw, *, metadata=b'{"asset_id":"fixture"}', row_id='snapshot'):
    _, engine, old = old_database
    with engine.begin() as connection:
        connection.execute(insert(old.tables['scan_session']).values(
            id='scan', organization_id='tenant-a', scan_name='Review fixture', scan_type='security_only',
            status='completed', target_scope={}, scan_config={}, overall_risk_score=99))
        connection.execute(insert(old.tables['discovered_agent']).values(
            id=row_id, scan_id='scan', agent_name='Review fixture', agent_type='assistant',
            discovery_method='fixture', risk_score=99, risk_level='critical'))
        connection.exec_driver_sql('UPDATE discovered_agent SET metadata=? WHERE id=?', (metadata, row_id))
        connection.exec_driver_sql('INSERT INTO scan_result(scan_id,result) VALUES (?,?)', ('scan', raw))


def cache(engine):
    with engine.connect() as connection:
        return (connection.exec_driver_sql('SELECT overall_risk_score FROM scan_session').scalar_one(),
                connection.exec_driver_sql('SELECT risk_score,risk_level FROM discovered_agent').one())


def snapshot(engine):
    with engine.connect() as connection:
        schema = connection.exec_driver_sql('SELECT type,name,tbl_name,sql FROM sqlite_master ORDER BY name').all()
        data = {name: connection.exec_driver_sql('SELECT * FROM "' + name + '" ORDER BY 1').all()
                for kind, name, _, _ in schema if kind == 'table' and not name.startswith('sqlite_')}
        return schema, data


@pytest.mark.parametrize('raw', [b'{', b'null', b'42', b'[]', b'"text"', b'\xff\xfe',
                                 b'[' * 2000 + b'0' + b']' * 2000,
                                 b' ' * (8 * 1024 * 1024 + 1)],
                         ids=['broken', 'null', 'number', 'array', 'string', 'invalid-utf8',
                              'depth-2000', 'oversized'])
def test_invalid_or_oversized_archives_become_unknown_without_rewriting_bytes(old_database, raw):
    module, engine, _ = old_database
    seed(old_database, raw)
    initialize_schema(engine, module.db.metadata)
    assert cache(engine) == (None, (None, 'unknown'))
    with engine.connect() as connection:
        assert connection.exec_driver_sql('SELECT CAST(result AS BLOB) FROM scan_result').scalar_one() == raw
        assert connection.exec_driver_sql('SELECT version FROM schema_version').scalar_one() == SCHEMA_VERSION


@pytest.mark.asyncio
@pytest.mark.parametrize('raw_metadata,row_id,expected', [
    (b'{"asset_id":false}', 'fixture', None),
    (b'{"asset_id":0}', 'fixture', None),
    (b'{"asset_id":null}', 'fixture', None),
    (b'{"asset_id":[]}', 'fixture', None),
    (b'{"asset_id":""}', 'fixture', None),
    (b'{}', 'fixture', 70),
    (b'[]', 'fixture', 70),
    (b'null', 'fixture', 70),
    (b'{"asset_id":"fixture"}', 'other-row', 70),
])
async def test_alias_shape_matches_current_api_fallback_rules(old_database, raw_metadata, row_id, expected):
    module, engine, _ = old_database
    actual = access_report(await access_result(disclose=True), score=70)
    raw = json.dumps(actual).encode()
    seed(old_database, raw, metadata=raw_metadata, row_id=row_id)
    initialize_schema(engine, module.db.metadata)
    assert cache(engine) == (70, (expected, 'high' if expected is not None else 'unknown'))
    with engine.connect() as connection:
        assert connection.exec_driver_sql('SELECT CAST(metadata AS BLOB) FROM discovered_agent').scalar_one() == raw_metadata


@pytest.mark.asyncio
async def test_duplicate_database_aliases_keep_the_same_supported_assessed_zero(old_database):
    module, engine, old = old_database
    actual = access_report(await access_result(), score=0)
    raw = json.dumps(actual).encode()
    seed(old_database, raw)
    with engine.begin() as connection:
        connection.execute(insert(old.tables['discovered_agent']).values(
            id='second-snapshot', scan_id='scan', agent_name='Second snapshot', agent_type='assistant',
            discovery_method='fixture', risk_score=99, risk_level='critical', metadata={'asset_id': 'fixture'}))
    initialize_schema(engine, module.db.metadata)
    with engine.connect() as connection:
        assert connection.exec_driver_sql('SELECT overall_risk_score FROM scan_session').scalar_one() == 0
        assert connection.exec_driver_sql('SELECT risk_score,risk_level FROM discovered_agent ORDER BY id').all() == [
            (0, 'minimal'), (0, 'minimal')]
        assert connection.exec_driver_sql('SELECT CAST(result AS BLOB) FROM scan_result').scalar_one() == raw


@pytest.mark.asyncio
async def test_duplicate_report_asset_ids_cannot_populate_a_current_cache(old_database):
    module, engine, _ = old_database
    actual = access_report(await access_result(disclose=True), score=70)
    actual['agents'].append(deepcopy(actual['agents'][0]))
    seed(old_database, json.dumps(actual).encode())
    initialize_schema(engine, module.db.metadata)
    assert cache(engine) == (None, (None, 'unknown'))


@pytest.mark.asyncio
@pytest.mark.parametrize('raw_metadata', [
    b'{', b'\xff\xfe', b'[' * 2000 + b'0' + b']' * 2000,
    b'{"asset_id":"fixture","padding":"' + b'X' * (8 * 1024 * 1024) + b'"}',
], ids=['broken', 'invalid-utf8', 'depth-2000', 'oversized'])
async def test_invalid_metadata_cannot_gain_fallback_risk(old_database, raw_metadata):
    module, engine, _ = old_database
    actual = access_report(await access_result(disclose=True), score=70)
    seed(old_database, json.dumps(actual).encode(), metadata=raw_metadata, row_id='fixture')
    initialize_schema(engine, module.db.metadata)
    assert cache(engine) == (70, (None, 'unknown'))
    with engine.connect() as connection:
        assert connection.exec_driver_sql('SELECT CAST(metadata AS BLOB) FROM discovered_agent').scalar_one() == raw_metadata


def test_partial_index_and_quoted_operator_index_survive_table_rebuild(old_database):
    module, engine, _ = old_database
    seed(old_database, b'null')
    sql = 'CREATE INDEX "review ""odd"" index" ON scan_session(overall_risk_score) WHERE status IN (\'completed\',\'partial\')'
    with engine.begin() as connection:
        connection.exec_driver_sql(sql)
        before = connection.exec_driver_sql('SELECT name,sql FROM sqlite_master WHERE type=\'index\' ORDER BY name').all()
    initialize_schema(engine, module.db.metadata)
    with engine.connect() as connection:
        after = dict(connection.exec_driver_sql(
            'SELECT name,sql FROM sqlite_master WHERE type=\'index\' ORDER BY name').all())
    assert {name: after[name] for name, _ in before} == dict(before)
    assert set(after) - {name for name, _ in before} == {
        'ix_inventory_scan_session_org_id', 'ix_inventory_observation_scan_order',
        'ix_inventory_observation_scan_type_order', 'sqlite_autoindex_inventory_generation_1'}


@pytest.mark.parametrize('unique', [False, True])
def test_expression_index_is_rejected_before_any_change(old_database, unique):
    module, engine, _ = old_database
    seed(old_database, b'null')
    with engine.begin() as connection:
        connection.exec_driver_sql('CREATE ' + ('UNIQUE ' if unique else '') + 'INDEX expression_index ON scan_session(lower(scan_name))')
    before = snapshot(engine)
    with pytest.raises(SchemaError):
        initialize_schema(engine, module.db.metadata)
    assert snapshot(engine) == before


def test_index_recreation_failure_rolls_back_all_schema_and_rows(old_database):
    module, engine, _ = old_database
    seed(old_database, b'null')
    with engine.begin() as connection:
        connection.exec_driver_sql('CREATE INDEX review_restore_failure ON scan_session(overall_risk_score)')
    before = snapshot(engine)
    def fail(connection, cursor, statement, parameters, context, many):
        if statement.startswith('CREATE INDEX review_restore_failure'):
            raise RuntimeError('review index recreation failure')
    event.listen(engine, 'before_cursor_execute', fail)
    try:
        with pytest.raises(RuntimeError, match='review index recreation failure'):
            initialize_schema(engine, module.db.metadata)
    finally:
        event.remove(engine, 'before_cursor_execute', fail)
    assert snapshot(engine) == before


def test_fresh_current_schema_rejects_nonnullable_score_layout(old_database):
    module, engine, _ = old_database
    with engine.begin() as connection:
        connection.exec_driver_sql('UPDATE schema_version SET version=4')
    before = snapshot(engine)
    with pytest.raises(SchemaError):
        initialize_schema(engine, module.db.metadata)
    assert snapshot(engine) == before


@pytest.mark.parametrize('kind', ['without_rowid', 'strict', 'nocase', 'rtrim'])
def test_unsupported_sqlite_table_semantics_reject_before_writes(api, tmp_path, kind):
    module, _ = api
    engine = create_engine('sqlite:///' + str(tmp_path / 'semantics.db'))
    old = historical_metadata(version=3)
    if kind == 'without_rowid':
        old.tables['scan_session'].dialect_options['sqlite']['with_rowid'] = False
    elif kind == 'strict':
        old.tables['schema_version'].dialect_options['sqlite']['strict'] = True
    else:
        old.tables['scan_session'].c.id.type = String(64, collation=kind.upper())
    old.create_all(engine)
    with engine.begin() as connection:
        connection.execute(insert(old.tables['schema_version']).values(id=1, version=3))
    seed((module, engine, old), b'null')
    before, writes = snapshot(engine), []
    def observe(connection, cursor, statement, parameters, context, many):
        if statement.lstrip().split()[0].upper() in {'CREATE', 'ALTER', 'DROP', 'INSERT', 'UPDATE', 'DELETE'}:
            writes.append(statement.split()[0])
    event.listen(engine, 'before_cursor_execute', observe)
    try:
        with pytest.raises(SchemaError):
            initialize_schema(engine, module.db.metadata)
        assert not writes
        assert snapshot(engine) == before
    finally:
        event.remove(engine, 'before_cursor_execute', observe)
        engine.dispose()
