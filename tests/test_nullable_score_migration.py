"""Historical SQLite risk caches migrate without rewriting archived evidence."""

from copy import deepcopy
import json

import pytest
from sqlalchemy import create_engine, event, insert, inspect, select

from src.core import schema
from src.core.stored_risk import MAX_STORED_RISK_BYTES
from tests.historical_schema import historical_metadata
from tests.test_api_auth import api as api
from tests.test_historical_prompt_projection import access_asset
from tests.test_prompt_legacy_compatibility import legacy_prompt_report
from tests.test_historical_tenant_projection import legacy_tenant_report


@pytest.fixture
def migration(api, tmp_path):
    module, _ = api
    engine = create_engine('sqlite:///' + str(tmp_path / 'synthetic-migration.sqlite'))
    yield module, engine
    engine.dispose()


async def actual_report(*, disclose=True, partial=False):
    asset = await access_asset(disclose=disclose, identifier='asset')
    asset.update(security_status='partial' if partial else 'completed',
                 risk_coverage_status='partial' if partial else 'sampled')
    return {'schema_version': '1.0', 'check_schema_version': '1.0',
            'scan_type': 'security_only', 'status': 'partial' if partial else 'completed',
            'risk_assessment_status': 'partial' if partial else 'completed',
            'agents': [asset], 'summary': {'overall_risk_score': asset['risk_score']}}


def seed(engine, report=None, *, version=3, metadata=None, status='completed', definitions=None):
    old = definitions if definitions is not None else historical_metadata(version=version)
    old.create_all(engine)
    with engine.begin() as connection:
        connection.execute(insert(old.tables['schema_version']).values(id=1, version=version))
        connection.execute(insert(old.tables['scan_session']).values(
            id='fixture', organization_id='synthetic', scan_name='Retained fixture',
            scan_type='security_only', status=status, target_scope={}, scan_config={},
            overall_risk_score=99.0))
        connection.execute(insert(old.tables['discovered_agent']).values(
            id='snapshot', scan_id='fixture', agent_name='Retained snapshot', agent_type='assistant',
            discovery_method='fixture', metadata=metadata if metadata is not None else {'asset_id': 'asset'},
            risk_score=99.0, risk_level='critical', vulnerabilities=[{'retained': 'original'}]))
        if report is not None:
            connection.execute(insert(old.tables['scan_result']).values(scan_id='fixture', result=report))
    return old


def raw_state(engine):
    with engine.connect() as connection:
        definitions = connection.exec_driver_sql(
            'SELECT type,name,tbl_name,sql FROM sqlite_master ORDER BY name').all()
        tables = {}
        for name in sorted(inspect(connection).get_table_names()):
            quoted = connection.dialect.identifier_preparer.quote(name)
            tables[name] = connection.exec_driver_sql('SELECT * FROM ' + quoted).all()
        return definitions, tables


def scalar_state(module, engine):
    with engine.connect() as connection:
        return (connection.scalar(select(module.ScanSession.overall_risk_score)),
                connection.execute(select(module.DiscoveredAgentModel.risk_score,
                                          module.DiscoveredAgentModel.risk_level)).one())


@pytest.mark.asyncio
@pytest.mark.parametrize('version', [1, 2, 3])
@pytest.mark.parametrize('disclose,partial,expected', [(False, False, 0.0), (True, False, 70.0),
                                                    (True, True, 70.0), (False, True, None)])
async def test_historical_cache_uses_actual_supported_evidence(migration, version, disclose, partial, expected):
    module, engine = migration
    report = await actual_report(disclose=disclose, partial=partial)
    old = seed(engine, report, version=version)
    with engine.begin() as connection:
        pretty = json.dumps(report, ensure_ascii=False, indent=3)
        connection.exec_driver_sql('UPDATE scan_result SET result=?', (pretty,))
        prior_report = connection.exec_driver_sql('SELECT result FROM scan_result').scalar_one()
        prior_agents = connection.exec_driver_sql('SELECT id,metadata,vulnerabilities FROM discovered_agent').all()
    schema.initialize_schema(engine, module.db.metadata)
    expected_level = 'unknown' if expected is None else 'high' if expected else 'minimal'
    assert scalar_state(module, engine) == (expected, (expected, expected_level))
    for table_name, score_name in [('scan_session', 'overall_risk_score'), ('discovered_agent', 'risk_score')]:
        columns = {column['name']: column for column in inspect(engine).get_columns(table_name)}
        assert columns[score_name]['nullable'] is True and columns[score_name]['default'] is None
        assert len(columns) == len(old.tables[table_name].columns)
    with engine.connect() as connection:
        assert connection.exec_driver_sql('SELECT result FROM scan_result').scalar_one() == prior_report
        assert connection.exec_driver_sql('SELECT id,metadata,vulnerabilities FROM discovered_agent').all() == prior_agents
        assert connection.exec_driver_sql('SELECT version FROM schema_version').scalar_one() == 4
    accepted = raw_state(engine)
    schema.initialize_schema(engine, module.db.metadata)
    assert raw_state(engine) == accepted


@pytest.mark.parametrize('kind', ['missing', 'old_prompt', 'old_tenant', 'unversioned'])
def test_unassessed_history_becomes_sql_null_without_deleting_history(migration, kind):
    module, engine = migration
    report = None if kind == 'missing' else legacy_tenant_report() if kind == 'old_tenant' else legacy_prompt_report()
    if kind == 'unversioned':
        report.pop('check_schema_version')
    seed(engine, report)
    with engine.connect() as connection:
        preserved = connection.exec_driver_sql('SELECT result FROM scan_result').all()
    schema.initialize_schema(engine, module.db.metadata)
    assert scalar_state(module, engine) == (None, (None, 'unknown'))
    with engine.connect() as connection:
        assert connection.exec_driver_sql('SELECT result FROM scan_result').all() == preserved


@pytest.mark.asyncio
@pytest.mark.parametrize('status', ['running', 'cancel_requested', 'interrupted', 'cancelled'])
async def test_retained_partial_evidence_survives_noncompleted_session_state(migration, status):
    module, engine = migration
    seed(engine, await actual_report(partial=True), status=status)
    schema.initialize_schema(engine, module.db.metadata)
    assert scalar_state(module, engine) == (70.0, (70.0, 'high'))
    with engine.connect() as connection:
        assert connection.scalar(select(module.ScanSession.status)) == status


@pytest.mark.asyncio
@pytest.mark.parametrize('metadata,identifier,expected', [
    ({'asset_id': 'asset'}, 'asset', 70.0), ({}, 'snapshot', 70.0),
    ('valid scalar metadata', 'snapshot', 70.0), (['valid array metadata'], 'snapshot', 70.0),
    ({'asset_id': []}, 'snapshot', None), ({'asset_id': ''}, 'snapshot', None),
    ({'asset_id': None}, 'snapshot', None), ({'asset_id': 'unmatched'}, 'asset', None),
])
async def test_snapshot_aliases_match_current_api_semantics(migration, metadata, identifier, expected):
    module, engine = migration
    report = await actual_report()
    report['agents'][0]['id'] = identifier
    seed(engine, report, metadata=metadata)
    schema.initialize_schema(engine, module.db.metadata)
    assert scalar_state(module, engine) == (70.0, (expected, 'high' if expected is not None else 'unknown'))


@pytest.mark.asyncio
async def test_duplicate_db_aliases_follow_same_canonical_asset(migration):
    module, engine = migration
    old = seed(engine, await actual_report())
    with engine.begin() as connection:
        connection.execute(insert(old.tables['discovered_agent']).values(
            id='second', scan_id='fixture', agent_name='Second snapshot', agent_type='assistant',
            discovery_method='fixture', metadata={'asset_id': 'asset'}, risk_score=99.0))
    schema.initialize_schema(engine, module.db.metadata)
    with engine.connect() as connection:
        assert connection.execute(select(module.DiscoveredAgentModel.risk_score)).all() == [(70.0,), (70.0,)]


@pytest.mark.asyncio
async def test_invalid_summary_does_not_erase_independently_supported_asset(migration):
    module, engine = migration
    report = legacy_tenant_report()
    report['agents'].append((await actual_report())['agents'][0])
    original = deepcopy(report)
    seed(engine, report)
    schema.initialize_schema(engine, module.db.metadata)
    assert scalar_state(module, engine) == (None, (70.0, 'high'))
    with engine.connect() as connection:
        assert connection.scalar(select(module.ScanResult.result)) == original


@pytest.mark.asyncio
async def test_orphaned_snapshot_cannot_borrow_an_unowned_report(migration):
    module, engine = migration
    report = await actual_report()
    old = seed(engine, report)
    with engine.begin() as connection:
        connection.execute(insert(old.tables['scan_result']).values(scan_id='orphan', result=report))
        connection.execute(insert(old.tables['discovered_agent']).values(
            id='orphan-snapshot', scan_id='orphan', agent_name='Orphan fixture', agent_type='assistant',
            discovery_method='fixture', metadata={'asset_id': 'asset'}, risk_score=99.0, risk_level='critical'))
        reports = connection.exec_driver_sql('SELECT * FROM scan_result ORDER BY scan_id').all()
    schema.initialize_schema(engine, module.db.metadata)
    with engine.connect() as connection:
        assert connection.execute(select(module.DiscoveredAgentModel.risk_score,
                                         module.DiscoveredAgentModel.risk_level).where(
                                             module.DiscoveredAgentModel.id == 'orphan-snapshot')).one() == (None, 'unknown')
        assert connection.exec_driver_sql('SELECT * FROM scan_result ORDER BY scan_id').all() == reports


@pytest.mark.asyncio
@pytest.mark.parametrize('column,kind', [(column, kind) for column in ('report', 'metadata')
                                        for kind in ('oversized', 'deep', 'bad_json', 'bad_utf8')])
async def test_uninterpretable_material_is_bounded_and_preserved(migration, column, kind, monkeypatch):
    module, engine = migration
    seed(engine, await actual_report())
    raw = {'oversized': b'{"padding":"' + b'x' * MAX_STORED_RISK_BYTES + b'"}',
           'deep': b'[' * 2000 + b'0' + b']' * 2000,
           'bad_json': b'{broken', 'bad_utf8': b'"\xff"'}[kind]
    table, field = ('scan_result', 'result') if column == 'report' else ('discovered_agent', 'metadata')
    quoted_table = engine.dialect.identifier_preparer.quote(table)
    quoted_field = engine.dialect.identifier_preparer.quote(field)
    with engine.begin() as connection:
        connection.exec_driver_sql('UPDATE ' + quoted_table + ' SET ' + quoted_field + '=?', (raw,))
    observed = []
    decode = schema._decode
    def bounded_decode(value):
        observed.append(len(value) if isinstance(value, bytes) else None)
        return decode(value)
    monkeypatch.setattr(schema, '_decode', bounded_decode)
    schema.initialize_schema(engine, module.db.metadata)
    assert all(length is None or length <= MAX_STORED_RISK_BYTES for length in observed)
    expected_summary = None if column == 'report' else 70.0
    assert scalar_state(module, engine) == (expected_summary, (None, 'unknown'))
    with engine.connect() as connection:
        assert connection.exec_driver_sql('SELECT ' + quoted_field + ' FROM ' + quoted_table).scalar_one() == raw


@pytest.mark.parametrize('definition', [
    'CREATE INDEX retained ON scan_session (scan_name COLLATE NOCASE DESC)',
    "CREATE INDEX retained ON scan_session (scan_name) WHERE status = 'completed'",
])
def test_accepted_index_sql_is_replayed_exactly(migration, definition):
    module, engine = migration
    seed(engine)
    with engine.begin() as connection:
        connection.exec_driver_sql(definition)
        before = connection.exec_driver_sql("SELECT sql FROM sqlite_master WHERE name='retained'").scalar_one()
    schema.initialize_schema(engine, module.db.metadata)
    with engine.connect() as connection:
        assert connection.exec_driver_sql("SELECT sql FROM sqlite_master WHERE name='retained'").scalar_one() == before


@pytest.mark.parametrize('definition', [
    'CREATE UNIQUE INDEX unsupported ON scan_session (scan_name)',
    'CREATE UNIQUE INDEX unsupported ON scan_session (lower(scan_name))',
    'CREATE INDEX unsupported ON scan_session (lower(scan_name))',
    "CREATE INDEX unsupported ON scan_session (lower(scan_name)) WHERE status = 'completed'",
])
def test_unrecognized_index_semantics_rejected_before_writes(migration, definition):
    module, engine = migration
    seed(engine)
    with engine.begin() as connection:
        connection.exec_driver_sql(definition)
    before = raw_state(engine)
    with pytest.raises(schema.SchemaError):
        schema.initialize_schema(engine, module.db.metadata)
    assert raw_state(engine) == before


@pytest.mark.parametrize('kind', ['without_rowid', 'column_collation', 'conflict_policy'])
def test_unpreserved_table_options_rejected_without_normalizing_layout(migration, kind):
    module, engine = migration
    old = historical_metadata()
    table = old.tables['scan_session']
    if kind == 'without_rowid':
        table.dialect_options['sqlite']['with_rowid'] = False
    elif kind == 'column_collation':
        table.c.scan_name.type.collation = 'NOCASE'
    else:
        table.c.scan_name.dialect_options['sqlite']['on_conflict_not_null'] = 'IGNORE'
    seed(engine, definitions=old)
    before = raw_state(engine)
    with pytest.raises(schema.SchemaError, match='Unsupported table options or collations'):
        schema.initialize_schema(engine, module.db.metadata)
    assert raw_state(engine) == before


def test_keyword_text_in_benign_quoted_default_free_ddl_comments_is_ignored(migration):
    module, engine = migration
    seed(engine)
    with engine.begin() as connection:
        connection.exec_driver_sql('PRAGMA writable_schema=ON')
        connection.exec_driver_sql(
            "UPDATE sqlite_master SET sql=replace(sql, 'scan_name VARCHAR', "
            "'scan_name /* WITHOUT ROWID COLLATE STRICT CONFLICT */ VARCHAR') WHERE name='scan_session'")
        connection.exec_driver_sql('PRAGMA writable_schema=OFF')
    schema.initialize_schema(engine, module.db.metadata)
    assert scalar_state(module, engine) == (None, (None, 'unknown'))


@pytest.mark.parametrize('stage', ['create', 'copy', 'drop', 'rename', 'index', 'cache', 'stamp'])
def test_every_rebuild_stage_rolls_back_schema_rows_and_version(migration, stage):
    module, engine = migration
    seed(engine)
    with engine.begin() as connection:
        connection.exec_driver_sql('CREATE INDEX retained ON discovered_agent (scan_id)')
    before = raw_state(engine)
    def fail(connection, cursor, statement, parameters, context, many):
        statement = statement.strip()
        prefixes = {'create': 'CREATE TABLE _aiscan_v4_', 'copy': 'INSERT INTO _aiscan_v4_',
                    'drop': 'DROP TABLE discovered_agent', 'rename': 'ALTER TABLE _aiscan_v4_',
                    'index': 'CREATE INDEX retained', 'cache': 'UPDATE scan_session SET overall_risk_score',
                    'stamp': 'UPDATE schema_version SET version'}
        if statement.startswith(prefixes[stage]):
            raise RuntimeError('Synthetic migration interruption')
    event.listen(engine, 'before_cursor_execute', fail)
    try:
        with pytest.raises(RuntimeError, match='Synthetic migration interruption'):
            schema.initialize_schema(engine, module.db.metadata)
    finally:
        event.remove(engine, 'before_cursor_execute', fail)
    assert raw_state(engine) == before
    schema.initialize_schema(engine, module.db.metadata)
