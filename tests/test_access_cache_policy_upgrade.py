"""A recognized policy-only upgrade refreshes caches without rewriting evidence."""

from copy import deepcopy
import json

import pytest
from sqlalchemy import create_engine, event, insert, inspect

from src.core import schema
from src.core.inventory_generation import TRIGGER_DEFINITIONS
from src.core.risk_projection import project_report_risk
from src.core.stored_risk import MAX_STORED_RISK_BYTES
from tests.historical_schema import SCHEMA_FIVE_TRIGGERS, historical_metadata
from tests.asset_group_schema_assertions import assert_group_extension, without_group_rows
from tests.legacy_access_fixtures import legacy_access_archive, legacy_access_report
from tests.legacy_observation_fixtures import legacy_archive, legacy_report
from tests.test_api_auth import api as api
from tests.test_backup_restore_acceptance import acceptance


@pytest.fixture
def database(api, tmp_path):
    module, _ = api
    engine = create_engine('sqlite:///' + str(tmp_path.resolve() / 'owned-cache-upgrade.sqlite'))
    try:
        yield module, engine
    finally:
        engine.dispose()


def state(engine):
    with engine.connect() as connection:
        definitions = connection.exec_driver_sql(
            'SELECT type,name,tbl_name,sql FROM sqlite_master ORDER BY name').all()
        rows = {}
        for name in inspect(connection).get_table_names():
            quoted = connection.dialect.identifier_preparer.quote(name)
            rows[name] = sorted(connection.exec_driver_sql('SELECT * FROM ' + quoted).all(), key=repr)
        return definitions, rows


def seed(engine, documents, *, version=5):
    metadata = historical_metadata(version=version)
    metadata.create_all(engine)
    with engine.begin() as connection:
        if version:
            connection.execute(insert(metadata.tables['schema_version']).values(id=1, version=version))
        for name, document, raw, score, level in documents:
            asset = document['agents'][0] if isinstance(document, dict) and document.get('agents') else {}
            connection.execute(insert(metadata.tables['scan_session']).values(
                id=name, organization_id=name, scan_name='Owned policy fixture', scan_type='security_only',
                status='completed', progress=37.0, target_scope={'retained': True}, scan_config={'retained': True},
                overall_risk_score=score))
            connection.execute(insert(metadata.tables['discovered_agent']).values(
                id='snapshot-' + name, scan_id=name, agent_name='Owned policy fixture', agent_type='fixture',
                discovery_method='synthetic', risk_score=score, risk_level=level,
                vulnerabilities=[{'retained': 'archive snapshot'}], metadata={'asset_id': asset.get('id', 'missing')}))
            if 'scan_result' in metadata.tables and raw is not None:
                connection.execute(insert(metadata.tables['scan_result']).values(scan_id=name, result={}))
                connection.exec_driver_sql('UPDATE scan_result SET result=? WHERE scan_id=?', (raw, name))
        connection.exec_driver_sql(
            "CREATE INDEX retained_operator_index ON discovered_agent (agent_name COLLATE NOCASE DESC) "
            "WHERE risk_level='critical'")
    return metadata


def caches(engine):
    with engine.connect() as connection:
        scans = dict(connection.exec_driver_sql('SELECT id,overall_risk_score FROM scan_session').all())
        assets = {name: (score, level) for name, score, level in connection.exec_driver_sql(
            'SELECT id,risk_score,risk_level FROM discovered_agent').all()}
        generations = dict(connection.exec_driver_sql(
            'SELECT organization_id,generation FROM inventory_generation').all())
    return scans, assets, generations


def without_cache_rows(rows, metadata):
    result = deepcopy(rows)
    for name, omitted in [('scan_session', {'overall_risk_score'}),
                          ('discovered_agent', {'risk_score', 'risk_level'})]:
        columns = list(metadata.tables[name].columns.keys())
        result[name] = [tuple(value for column, value in zip(columns, row, strict=True) if column not in omitted)
                        for row in result[name]]
    result.pop('inventory_generation', None)
    result.pop('schema_version', None)
    return result


def test_policy_refresh_preserves_old_archives_and_supported_current_caches(database):
    module, engine = database
    documents = []
    expected = {}
    for name in ('zero', 'high', 'partial', 'mixed'):
        report = legacy_access_report(name)
        documents.append(('legacy-' + name, report, legacy_access_archive(name),
                          report['agents'][0]['risk_score'], report['agents'][0]['risk_level']))
        # Ignored legacy passes cannot erase independently supported prompt and
        # tenant observations on the mixed historical asset.
        expected['legacy-' + name] = (90.0, 'critical') if name == 'mixed' else (None, 'unknown')
    for name, disclose, partial in [('zero', False, False), ('high', True, False), ('partial', True, True)]:
        report = acceptance.controlled_report('current-' + name, disclose=disclose, partial=partial)
        documents.append(('current-' + name, report, json.dumps(report, indent=3),
                          report['agents'][0]['risk_score'], report['agents'][0]['risk_level']))
        expected['current-' + name] = (70.0, 'high') if disclose else (0.0, 'minimal')
    report = legacy_report('subject-partial-final')
    documents.append(('tenant', report, legacy_archive('subject-partial-final'), 90.0, 'critical'))
    expected['tenant'] = (90.0, 'critical')
    metadata = seed(engine, documents)
    prior_definitions, prior_rows = state(engine)
    _, _, prior_generations = caches(engine)
    statements = []
    def observe(_connection, _cursor, statement, _parameters, _context, _many):
        statements.append(statement)
    event.listen(engine, 'before_cursor_execute', observe)
    try:
        schema.initialize_schema(engine, module.db.metadata)
    finally:
        event.remove(engine, 'before_cursor_execute', observe)
    definitions, rows = state(engine)
    scan_scores, asset_scores, generations = caches(engine)
    assert_group_extension(prior_definitions, definitions)
    assert without_cache_rows(without_group_rows(rows), metadata) == without_cache_rows(prior_rows, metadata)
    assert rows['schema_version'] == [(1, schema.SCHEMA_VERSION)]
    assert scan_scores == {name: value[0] for name, value in expected.items()}
    assert asset_scores == {'snapshot-' + name: value for name, value in expected.items()}
    assert {owner for owner in generations if generations[owner] != prior_generations[owner]} == {
        'legacy-zero', 'legacy-high', 'legacy-partial'}
    writes = [value for value in statements if value.upper().startswith('UPDATE ')]
    assert len(writes) == 7  # Three scan caches, three snapshots and the final version stamp.
    assert all(' SET overall_risk_score=' in value or ' SET risk_score=' in value
               or 'UPDATE schema_version SET version=' in value for value in writes)
    accepted = state(engine)
    statements.clear()
    event.listen(engine, 'before_cursor_execute', observe)
    try:
        schema.initialize_schema(engine, module.db.metadata)
    finally:
        event.remove(engine, 'before_cursor_execute', observe)
    assert state(engine) == accepted
    assert not any(value.upper().startswith(('UPDATE ', 'INSERT ', 'DELETE ', 'CREATE ', 'DROP ', 'ALTER '))
                   for value in statements)
    for _, report, _, _, _ in documents:
        summary, _ = project_report_risk(report)
        name = next(name for name, item, *_ in documents if item is report)
        assert summary['overall_risk_score'] == expected[name][0]


@pytest.mark.parametrize('stage', ['scan', 'snapshot', 'stamp'])
def test_policy_refresh_failure_rolls_back_scalars_generations_and_version(database, stage):
    module, engine = database
    report = legacy_access_report('high')
    seed(engine, [('retained', report, legacy_access_archive('high'), 70.0, 'high')])
    before = state(engine)
    def fail(_connection, _cursor, statement, _parameters, _context, _many):
        prefix = {'scan': 'UPDATE scan_session', 'snapshot': 'UPDATE discovered_agent',
                  'stamp': 'UPDATE schema_version'}[stage]
        if statement.startswith(prefix):
            raise RuntimeError('Injected policy refresh failure')
    event.listen(engine, 'before_cursor_execute', fail)
    try:
        with pytest.raises(RuntimeError, match='Injected policy refresh failure'):
            schema.initialize_schema(engine, module.db.metadata)
    finally:
        event.remove(engine, 'before_cursor_execute', fail)
    assert state(engine) == before
    schema.initialize_schema(engine, module.db.metadata)
    assert caches(engine)[:2] == ({'retained': None}, {'snapshot-retained': (None, 'unknown')})


@pytest.mark.parametrize('raw', [b'{invalid', b'\xff', b'[]', b'[' * 65 + b']' * 65,
                              b' ' * (MAX_STORED_RISK_BYTES + 1)],
                         ids=['invalid-json', 'invalid-utf8', 'non-report', 'too-deep', 'too-large'])
def test_bounded_unreadable_archive_stays_exact_and_caches_become_unknown(database, raw):
    module, engine = database
    seed(engine, [('retained', None, raw, 70.0, 'high')])
    before = state(engine)
    schema.initialize_schema(engine, module.db.metadata)
    assert caches(engine)[:2] == ({'retained': None}, {'snapshot-retained': (None, 'unknown')})
    assert state(engine)[1]['scan_result'] == before[1]['scan_result']


@pytest.mark.parametrize('version', range(6))
def test_frozen_layouts_zero_through_five_upgrade_without_rewriting_unrelated_fields(database, version):
    module, engine = database
    metadata = seed(engine, [('retained', None, None, 99.0, 'critical')], version=version)
    before = state(engine)
    if version == 5:
        assert dict((name, sql) for kind, name, _table, sql in before[0] if kind == 'trigger') == SCHEMA_FIVE_TRIGGERS
        assert SCHEMA_FIVE_TRIGGERS == TRIGGER_DEFINITIONS
    schema.initialize_schema(engine, module.db.metadata)
    _, rows = state(engine)
    assert caches(engine)[:2] == ({'retained': None}, {'snapshot-retained': (None, 'unknown')})
    retained = without_cache_rows(rows, metadata)
    original = without_cache_rows(before[1], metadata)
    assert all(retained[name] == values for name, values in original.items())
    assert rows['schema_version'] == [(1, schema.SCHEMA_VERSION)]


def test_refresh_updates_only_the_changed_level_and_preserves_unchanged_owner(database):
    module, engine = database
    report = legacy_report('subject-partial-final')
    seed(engine, [('changed', report, legacy_archive('subject-partial-final'), 90.0, 'high'),
                  ('unchanged', report, legacy_archive('subject-partial-final'), 90.0, 'critical')])
    before = caches(engine)
    statements = []
    def observe(_connection, _cursor, statement, _parameters, _context, _many):
        if statement.startswith('UPDATE discovered_agent'):
            statements.append(statement)
    event.listen(engine, 'before_cursor_execute', observe)
    try:
        schema.initialize_schema(engine, module.db.metadata)
    finally:
        event.remove(engine, 'before_cursor_execute', observe)
    after = caches(engine)
    assert len(statements) == 1 and 'SET risk_level=' in statements[0] and 'SET risk_score=' not in statements[0]
    assert after[2]['changed'] != before[2]['changed']
    assert after[2]['unchanged'] == before[2]['unchanged']


def test_scan_only_refresh_does_not_invalidate_observation_generation(database):
    module, engine = database
    report = legacy_report('subject-partial-final')
    seed(engine, [('retained', report, legacy_archive('subject-partial-final'), 90.0, 'critical')])
    with engine.begin() as connection:
        connection.exec_driver_sql('UPDATE scan_session SET overall_risk_score=99')
    before = caches(engine)
    schema.initialize_schema(engine, module.db.metadata)
    after = caches(engine)
    assert after[:2] == ({'retained': 90.0}, {'snapshot-retained': (90.0, 'critical')})
    assert after[2] == before[2]


@pytest.mark.parametrize('raw', [b'{invalid', b'\xff', b'[' * 65 + b']' * 65,
                              b' ' * (MAX_STORED_RISK_BYTES + 1), b'{"asset_id":null}'],
                         ids=['invalid-json', 'invalid-utf8', 'too-deep', 'too-large', 'invalid-alias'])
def test_unreadable_snapshot_metadata_never_borrows_its_scan_score(database, raw):
    module, engine = database
    report = legacy_report('subject-partial-final')
    seed(engine, [('retained', report, legacy_archive('subject-partial-final'), 90.0, 'critical')])
    with engine.begin() as connection:
        connection.exec_driver_sql('UPDATE discovered_agent SET metadata=?', (raw,))
    before = state(engine)
    schema.initialize_schema(engine, module.db.metadata)
    assert caches(engine)[:2] == ({'retained': 90.0}, {'snapshot-retained': (None, 'unknown')})
    metadata_index = list(module.DiscoveredAgentModel.__table__.columns.keys()).index('metadata')
    assert state(engine)[1]['discovered_agent'][0][metadata_index] == before[1]['discovered_agent'][0][metadata_index]
