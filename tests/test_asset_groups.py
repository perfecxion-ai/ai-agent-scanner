"""Independent source-backed grouping, publication and continuation regressions."""

from copy import deepcopy
from datetime import datetime, timezone
import json
import threading
import time

import pytest
from sqlalchemy import Column, DateTime, MetaData, String, Table, Text, create_engine, event, insert, select, update
from sqlalchemy.orm import Session
from werkzeug.datastructures import MultiDict

from src.core import asset_group_projection as sources
from src.core.asset_group_storage import install_asset_group_storage, register_asset_group_metadata
from src.core.asset_groups import (
    AssetGroupProjector, group_history_page, group_page,
    parse_group_history_request, parse_group_request,
)
from src.core.inventory import InventoryError
from src.core.inventory_generation import install_inventory_generation, register_inventory_metadata
from tests.legacy_access_v3_fixtures import legacy_access_v3_report
from tests.legacy_access_fixtures import legacy_access_report


SECRET = 'owned-asset-group-cursor-signing-key'


@pytest.fixture
def database(tmp_path):
    engine = create_engine('sqlite:///' + str(tmp_path / 'groups.sqlite'))
    metadata = MetaData()
    scans = Table('scan_session', metadata, Column('id', String(64), primary_key=True),
                  Column('organization_id', String(64), nullable=False))
    observations = Table('discovered_agent', metadata, Column('id', String(64), primary_key=True),
        Column('scan_id', String(64), nullable=False), Column('agent_name', String(255), nullable=False),
        Column('agent_type', String(100), nullable=False), Column('provider', String(100)),
        Column('model_name', String(255)), Column('endpoint_url', Text), Column('metadata', Text),
        Column('discovered_at', DateTime, nullable=False))
    reports = Table('scan_result', metadata, Column('scan_id', String(64), primary_key=True), Column('result', Text))
    generations = register_inventory_metadata(metadata)
    index, publication = register_asset_group_metadata(metadata)
    tables = dict(index=index, publication=publication, observations=observations, scans=scans,
                  reports=reports, generations=generations)
    metadata.create_all(engine)
    with engine.begin() as connection:
        install_inventory_generation(connection, metadata)
        install_asset_group_storage(connection, metadata)
    try:
        yield engine, tables
    finally:
        engine.dispose()


def seed(database, name, *, organization='tenant-a', report='high', stamp=1, aliases=None, count=1):
    engine, tables = database
    document = legacy_access_v3_report(report) if isinstance(report, str) else deepcopy(report)
    agent = document['agents'][0]
    with engine.begin() as connection:
        connection.execute(insert(tables['scans']).values(id=name, organization_id=organization))
        connection.execute(insert(tables['reports']).values(scan_id=name, result=json.dumps(document)))
        rows = []
        for ordinal in range(count):
            rows.append(dict(id=name + '-' + str(ordinal).zfill(5), scan_id=name, agent_name=agent['name'],
                agent_type=agent['type'], provider=agent.get('provider'), model_name=agent.get('model'),
                endpoint_url=agent.get('endpoint'), metadata=json.dumps(
                    {'asset_id': agent['id']} if aliases is None else aliases),
                discovered_at=datetime(2026, 1, 1, 0, 0, stamp, tzinfo=timezone.utc)))
        connection.execute(insert(tables['observations']), rows)
    return document


def publish(database, *, projector=None, organization='tenant-a', maximum=100):
    engine, tables = database
    projector = projector or AssetGroupProjector(engine, tables)
    for _ in range(maximum):
        progress = projector.step()
        if progress.published and progress.organization_id == organization:
            return projector
        # Fast owned gates need not wait on the production idle polling interval.
        projector._next_poll = 0
    raise AssertionError('Owned group publication did not finish')


def page(database, args=(), *, organization='tenant-a'):
    engine, tables = database
    parsed = parse_group_request(MultiDict(args), organization, SECRET)
    with engine.connect() as connection, connection.begin():
        connection.exec_driver_sql('BEGIN')
        with Session(bind=connection) as session:
            return group_page(session, parsed, SECRET, tables)


def history(database, group, args=(), *, organization='tenant-a'):
    engine, tables = database
    parsed = parse_group_history_request(MultiDict(args), organization, group, SECRET)
    with engine.connect() as connection, connection.begin():
        connection.exec_driver_sql('BEGIN')
        with Session(bind=connection) as session:
            return group_history_page(session, parsed, SECRET, tables)


def source_rows(database):
    engine, tables = database
    with engine.connect() as connection:
        return {name: connection.execute(select(tables[name])).all()
                for name in ('observations', 'scans', 'reports', 'generations')}


def test_repeated_source_support_is_immutable_and_reader_local(database, monkeypatch):
    seed(database, 'repeated', count=3)
    engine, tables = database
    calls = []
    original = sources._supported_source

    def validate(report, agent):
        calls.append(agent['id'])
        return original(report, agent)

    monkeypatch.setattr(sources, '_supported_source', validate)
    with engine.connect() as connection:
        rows = connection.execute(select(*sources.observation_columns(tables['observations']))
                                  .order_by(tables['observations'].c.id)).all()
        reader = sources.SourceReader(connection, tables, time.monotonic() + 5)
        observations = [reader.observation(row, 'tenant-a') for row in rows]
        report = reader.reports['repeated'].report
        unchanged = deepcopy(report)
        assert calls == ['owned-access-v3']
        assert all(item.supported_count == 1 and item.history_complete for item in observations)
        assert all(isinstance(item.supported, frozenset) for item in observations)
        assert all(item.supported is observations[0].supported for item in observations)
        assert reader.observation(rows[0], 'tenant-a').supported_count == 1
        assert report == unchanged
        # A new read cannot inherit evidence facts from another source snapshot.
        fresh = sources.SourceReader(connection, tables, time.monotonic() + 5)
        assert fresh.observation(rows[0], 'tenant-a').supported_count == 1
        assert calls == ['owned-access-v3', 'owned-access-v3']


def test_warmed_support_memo_does_not_skip_snapshot_binding(database, monkeypatch):
    seed(database, 'mixed-binding', count=2)
    engine, tables = database
    with engine.begin() as connection:
        connection.execute(update(tables['observations']).where(
            tables['observations'].c.id == 'mixed-binding-00001').values(endpoint_url='https://wrong.example/resource'))
    calls = []
    original = sources._supported_source

    def validate(report, agent):
        calls.append(agent['id'])
        return original(report, agent)

    monkeypatch.setattr(sources, '_supported_source', validate)
    with engine.connect() as connection:
        rows = connection.execute(select(*sources.observation_columns(tables['observations']))
                                  .order_by(tables['observations'].c.id)).all()
        reader = sources.SourceReader(connection, tables, time.monotonic() + 5)
        valid, mismatched = [reader.observation(row, 'tenant-a') for row in rows]
    assert calls == ['owned-access-v3']
    assert valid.supported_count == 1 and valid.risk['risk_score'] == 70
    assert mismatched.supported_count is None and mismatched.risk['risk_score'] is None
    assert mismatched.identity.reason == 'snapshot_target_mismatch'


def test_new_reader_revalidates_changed_source_with_same_alias(database, monkeypatch):
    seed(database, 'changed')
    engine, tables = database
    calls = []
    original = sources._supported_source

    def validate(report, agent):
        calls.append(agent['id'])
        return original(report, agent)

    monkeypatch.setattr(sources, '_supported_source', validate)
    with engine.connect() as connection:
        row = connection.execute(select(*sources.observation_columns(tables['observations']))).one()
        reader = sources.SourceReader(connection, tables, time.monotonic() + 5)
        assert reader.observation(row, 'tenant-a').supported_count == 1
    with engine.begin() as connection:
        connection.execute(update(tables['reports']).values(result=json.dumps(legacy_access_v3_report('zero'))))
    with engine.connect() as connection:
        fresh = sources.SourceReader(connection, tables, time.monotonic() + 5)
        projected = fresh.observation(row, 'tenant-a')
        assert projected.supported_count == 0 and projected.risk['risk_score'] == 0
    assert calls == ['owned-access-v3', 'owned-access-v3']


def test_production_stage_head_lookup_uses_exact_partial_unique_index(database):
    seed(database, 'head-lookup', count=2)
    engine, tables = database
    statements, head_counts = [], []

    def capture(connection, cursor, statement, parameters, context, executemany):
        if statement.startswith('SELECT asset_group_index.') and 'asset_group_index.group_id = ?' in statement:
            statements.append((statement, parameters))
        elif statement.startswith('SELECT count(') and 'asset_group_index.is_latest ' in statement:
            head_counts.append((statement, parameters))

    event.listen(engine, 'before_cursor_execute', capture)
    try:
        publish(database)
        groups = page(database)['asset_groups']
    finally:
        event.remove(engine, 'before_cursor_execute', capture)
    assert len(statements) >= 2
    assert len(head_counts) >= 2
    assert any('sum(asset_group_index.group_observation_count)' in statement for statement, _ in head_counts)
    assert any('sum(' not in statement for statement, _ in head_counts)
    # Explain the executed second lookup, when the first observation is already
    # the head. Reconstructing an ideal query would miss a production mismatch.
    statement, parameters = statements[1]
    with engine.connect() as connection:
        plan = connection.exec_driver_sql('EXPLAIN QUERY PLAN ' + statement, parameters).all()
    details = [row[3] for row in plan]
    assert any('USING INDEX ux_asset_group_head (organization_id=? AND build_id=? AND group_id=?)' in item
               for item in details), details
    with engine.connect() as connection:
        for statement, parameters in head_counts:
            details = [row[3] for row in connection.exec_driver_sql('EXPLAIN QUERY PLAN ' + statement, parameters)]
            assert 'asset_group_index.is_latest = 1' in statement
            if 'sum(' not in statement:
                assert any('INDEX ux_asset_group_head (organization_id=? AND build_id=?)' in item
                           for item in details), details
            # A sum needs row payloads, so SQLite can prefer another bounded
            # index on tiny fixtures. Equality keeps the partial index eligible.
            else:
                assert any('SEARCH asset_group_index USING INDEX ' in item
                           and '(organization_id=? AND build_id=?)' in item for item in details), details
    assert groups[0]['observation_count'] == 2


def test_latest_zero_is_separate_from_prior_confirmed_history(database):
    high = seed(database, 'old-high', stamp=1)
    seed(database, 'new-zero', report='zero', stamp=2)
    before = source_rows(database)
    publish(database)
    group = page(database)['asset_groups'][0]
    assert group['observation_count'] == 2
    assert group['latest_observation']['scan_id'] == 'new-zero'
    assert group['latest_observation_risk']['risk_score'] == 0
    assert group['confirmation_history'] == {
        'complete': True, 'supported_occurrences': 1, 'archived_claims': 0,
        'remediation_status': 'not_evaluated', 'url': '/api/asset-groups/' + group['id'] + '/history'}
    items = history(database, group['id'])['history']
    assert [item['classification'] for item in items] == ['observation', 'supported_confirmation']
    assert items[1]['finding_id'] == high['agents'][0]['vulnerabilities'][0]['id']
    assert source_rows(database) == before
    assert 'risk_score' not in group


def test_latest_unknown_does_not_erase_old_supported_occurrence(database):
    seed(database, 'old-high', stamp=1)
    unknown = legacy_access_v3_report('zero')
    unknown['risk_assessment_status'] = 'not_assessed'
    unknown['summary']['overall_risk_score'] = None
    for asset in unknown['agents']:
        asset.update(risk_score=None, risk_level='unknown', risk_scoring_policy=None, risk_coverage_status='not_assessed')
    unknown['risk_assessments'] = []
    seed(database, 'new-unknown', report=unknown, stamp=2)
    publish(database)
    group = page(database)['asset_groups'][0]
    assert group['latest_observation_risk']['risk_score'] is None
    assert group['confirmation_history']['supported_occurrences'] == 1


def test_unscored_valid_confirmation_still_has_supported_history(database):
    unscored = legacy_access_v3_report('high')
    unscored.update(risk_assessment_status='failed', risk_assessments=[])
    unscored['summary']['overall_risk_score'] = None
    seed(database, 'unscored', report=unscored)
    publish(database)
    group = page(database)['asset_groups'][0]
    assert group['latest_observation_risk']['risk_score'] is None
    assert group['confirmation_history']['supported_occurrences'] == 1
    assert history(database, group['id'])['history'][0]['classification'] == 'supported_confirmation'


def test_known_obsolete_access_findings_are_complete_archived_claims(database):
    document = legacy_access_report('high')
    seed(database, 'obsolete', report=document)
    publish(database)
    group = page(database)['asset_groups'][0]
    assert group['latest_observation_risk']['risk_score'] is None
    assert group['confirmation_history']['complete'] is True
    assert group['confirmation_history']['supported_occurrences'] == 0
    assert group['confirmation_history']['archived_claims'] == 1
    assert history(database, group['id'])['history'][0]['classification'] == 'archived_claim'


def test_complete_history_separates_supported_and_recorded_claims(database):
    document = legacy_access_v3_report('high')
    # This is an explicitly archived unit record, not manufactured response evidence.
    claim = {'id': 'owned-unsupported-claim', 'vulnerability_type': 'legacy_record',
             'evidence_status': 'confirmed', 'severity': 'high'}
    document['agents'][0]['vulnerabilities'].append(claim)
    document['security_results'][0]['vulnerabilities'].append(deepcopy(claim))
    seed(database, 'mixed-claims', report=document)
    publish(database)
    group = page(database)['asset_groups'][0]
    assert group['confirmation_history']['complete'] is True
    assert group['confirmation_history']['supported_occurrences'] == 1
    assert group['confirmation_history']['archived_claims'] == 1


def test_unmergeable_identity_keeps_its_own_exact_source_evidence(database):
    document = legacy_access_v3_report('high')
    document['agents'][0]['metadata'].update(cloud='gcp', resource_id='incomplete')
    seed(database, 'singleton', report=document)
    publish(database)
    group = page(database)['asset_groups'][0]
    assert group['identity_status'] == 'unmerged' and group['target'] is None
    assert group['latest_observation_risk']['risk_score'] == 70
    assert group['confirmation_history']['supported_occurrences'] == 1


def test_same_cloud_resource_does_not_authorize_wrong_snapshot_endpoint(database):
    document = legacy_access_v3_report('high')
    metadata = {'cloud': 'gcp', 'resource_id': 'projects/owned-project/locations/us-central1/endpoints/owned-endpoint'}
    document['agents'][0]['metadata'].update(metadata)
    seed(database, 'cloud', report=document, aliases={**metadata, 'asset_id': document['agents'][0]['id']})
    engine, tables = database
    with engine.begin() as connection:
        connection.execute(update(tables['observations']).values(endpoint_url='https://wrong.example/resource'))
    publish(database)
    group = page(database)['asset_groups'][0]
    assert group['identity_status'] == 'unmerged'
    assert group['latest_observation_risk']['risk_score'] is None
    assert history(database, group['id'])['history'][0]['classification'] == 'observation'


@pytest.mark.parametrize('alias', [None, '', 7, False])
def test_explicit_malformed_alias_never_borrows_report_evidence(database, alias):
    seed(database, 'unmatched', aliases={'asset_id': alias})
    publish(database)
    group = page(database)['asset_groups'][0]
    assert group['identity_status'] == 'unmerged' and group['target'] is None
    assert group['latest_observation_risk']['risk_score'] is None
    assert group['confirmation_history']['complete'] is False
    assert group['confirmation_history']['supported_occurrences'] is None
    assert history(database, group['id'])['history'][0]['classification'] == 'observation'


def test_mismatched_snapshot_cannot_borrow_another_target_findings(database):
    seed(database, 'wrong-target')
    engine, tables = database
    with engine.begin() as connection:
        connection.execute(update(tables['observations']).values(endpoint_url='https://different.example/resource'))
    publish(database)
    group = page(database)['asset_groups'][0]
    assert group['identity_status'] == 'unmerged'
    assert group['latest_observation_risk']['risk_score'] is None
    assert history(database, group['id'])['history'][0]['finding_id'] is None


def test_tenant_scope_and_bounded_group_traversal(database):
    seed(database, 'a', count=3)
    seed(database, 'bad-alias', aliases={'asset_id': None})
    seed(database, 'other', organization='tenant-b')
    publish(database)
    publish(database, organization='tenant-b')
    ids, cursor = [], None
    while True:
        result = page(database, [('limit', '1')] + ([('cursor', cursor)] if cursor else []))
        ids.extend(item['id'] for item in result['asset_groups'])
        cursor = result['next_cursor']
        if cursor is None:
            break
    assert len(set(ids)) == len(ids) == 2
    assert not set(ids) & {item['id'] for item in page(database, organization='tenant-b')['asset_groups']}


def test_history_cursor_preserves_every_original_finding_ordinal(database):
    document = seed(database, 'mixed', report='mixed')
    publish(database)
    group = page(database)['asset_groups'][0]
    items, cursor = [], None
    for _ in range(20):
        result = history(database, group['id'], [('limit', '2')] + ([('cursor', cursor)] if cursor else []))
        items.extend(result['history'])
        cursor = result['next_cursor']
        if cursor is None:
            break
    expected = document['agents'][0]['vulnerabilities']
    assert [item['finding_ordinal'] for item in items] == list(range(len(expected)))
    assert [item['finding_id'] for item in items] == [item['id'] for item in expected]
    assert all(item['classification'] == 'supported_confirmation' for item in items)


@pytest.mark.parametrize('field', ['active_generation', 'active_policy'])
def test_publication_reset_cannot_bless_stale_sealed_rows(database, field, monkeypatch):
    seed(database, 'high')
    publish(database)
    engine, tables = database
    with engine.begin() as connection:
        if field == 'active_generation':
            connection.execute(update(tables['reports']).values(result=json.dumps(legacy_access_v3_report('zero'))))
            value = connection.execute(select(tables['generations'].c.generation)).scalar_one()
        else:
            value = '0' * 64
            monkeypatch.setattr('src.core.asset_groups.ASSET_GROUP_POLICY', value)
        connection.execute(update(tables['publication']).values(**{field: value}))
    with pytest.raises(InventoryError) as failure:
        page(database)
    assert failure.value.status == 503


def test_history_does_not_reopen_an_exhausted_boundary_source(database, monkeypatch):
    old = seed(database, 'old', report='high', stamp=1)
    new = seed(database, 'new', report='zero', stamp=2)
    publish(database)
    group = page(database)['asset_groups'][0]
    # One full source fits, while two do not. A completed boundary must be skipped.
    budget = max(len(json.dumps(value).encode()) for value in (old, new)) + 100
    monkeypatch.setattr('src.core.asset_group_projection.MAX_SOURCE_BYTES', budget)
    first = history(database, group['id'], [('limit', '1')])
    cursor = first['next_cursor']
    assert cursor and first['history'][0]['classification'] == 'observation'
    second = history(database, group['id'], [('limit', '1'), ('cursor', cursor)])
    assert len(second['history']) == 1 and second['next_cursor'] is None
    assert second['history'][0]['classification'] == 'supported_confirmation'


def test_mutated_row_stays_unsealed_after_publication_metadata_restore(database):
    seed(database, 'high')
    publish(database)
    engine, tables = database
    with engine.begin() as connection:
        publication = dict(connection.execute(select(tables['publication'])).mappings().one())
        connection.execute(update(tables['index']).values(group_supported_confirmation_count=0))
        connection.execute(update(tables['publication']).values(**publication))
    with pytest.raises(InventoryError) as failure:
        page(database)
    assert failure.value.status == 503


def test_first_blocked_owner_does_not_starve_later_valid_owner(database):
    seed(database, 'bad', organization='a-owner')
    seed(database, 'good', organization='z-owner')
    engine, tables = database
    with engine.begin() as connection:
        connection.execute(update(tables['reports']).where(tables['reports'].c.scan_id == 'bad').values(result='{'))
    publish(database, organization='z-owner')
    assert page(database, organization='z-owner')['asset_groups'][0]['latest_observation_risk']['risk_score'] == 70
    with pytest.raises(InventoryError):
        page(database, organization='a-owner')


def test_restart_resumes_private_build_and_cleanup_remains_bounded(database):
    seed(database, 'bulk', count=1100)
    engine, tables = database
    initial = AssetGroupProjector(engine, tables)
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        first = initial.step()
        initial._next_poll = 0
        assert first.processed_rows <= 500 and not first.published
        if first.processed_rows:
            break
    else:
        raise AssertionError('No private build prefix was staged')
    with engine.connect() as connection:
        publication = connection.execute(select(tables['publication'])).mappings().one()
        assert publication['active_build_id'] is None and publication['building_build_id']
        assert 0 < publication['processed_count'] < 1100
    with pytest.raises(InventoryError):
        page(database)
    publish(database, projector=AssetGroupProjector(engine, tables))
    assert page(database)['asset_groups'][0]['observation_count'] == 1100
    with engine.begin() as connection:
        connection.execute(update(tables['reports']).values(result=json.dumps(legacy_access_v3_report('zero'))))
    projector = AssetGroupProjector(engine, tables)
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        step = projector.step()
        assert step.processed_rows <= 500 and step.cleaned_rows <= 500
        projector._next_poll = 0
        if step.published:
            break
    else:
        raise AssertionError('Changed source did not republish')
    assert page(database)['asset_groups'][0]['latest_observation_risk']['risk_score'] == 0


def test_cancelled_step_and_gets_never_write_source_or_cache(database):
    seed(database, 'high')
    engine, tables = database
    stop = threading.Event()
    stop.set()
    assert AssetGroupProjector(engine, tables).step(stop).state == 'cancelled'
    publish(database)
    before = source_rows(database)
    with engine.connect() as connection:
        index_before = connection.execute(select(tables['index'])).all()
    group = page(database)['asset_groups'][0]
    history(database, group['id'])
    assert source_rows(database) == before
    with engine.connect() as connection:
        assert connection.execute(select(tables['index'])).all() == index_before


@pytest.mark.parametrize('args', [[('agent_type', 'assistant')], [('risk_level', 'high')], [('limit', ' 1')],
                                 [('limit', '0')], [('limit', '101')], [('limit', '1'), ('limit', '2')]])
def test_invalid_request_rejects_without_sql(args):
    with pytest.raises(InventoryError) as failure:
        parse_group_request(MultiDict(args), 'tenant-a', SECRET)
    assert failure.value.status == 400


def test_scope_and_source_changes_make_continuation_invalid(database):
    seed(database, 'first', aliases={'asset_id': None})
    seed(database, 'second')
    publish(database)
    cursor = page(database, [('limit', '1')])['next_cursor']
    with pytest.raises(InventoryError) as failure:
        parse_group_request(MultiDict({'limit': '1', 'cursor': cursor}), 'tenant-b', SECRET)
    assert failure.value.status == 400
    engine, tables = database
    with engine.begin() as connection:
        connection.execute(update(tables['reports']).where(tables['reports'].c.scan_id == 'first')
                           .values(result=json.dumps(legacy_access_v3_report('zero'))))
    with pytest.raises(InventoryError) as failure:
        page(database, [('limit', '1'), ('cursor', cursor)])
    assert failure.value.status == 409
