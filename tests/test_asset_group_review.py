"""Independent bounded-source and continuation regressions for target groups."""

from datetime import datetime, timedelta
import json
import time

import pytest
from sqlalchemy import create_engine, insert, select
from sqlalchemy.orm import Session
from werkzeug.datastructures import MultiDict

from src.core import asset_group_projection as sources
from src.core.asset_group_storage import register_asset_group_metadata
from src.core.asset_groups import (
    AssetGroupProjector, group_history_page, group_page,
    parse_group_history_request, parse_group_request,
)
from src.core.inventory_generation import register_inventory_metadata
from src.core.schema import initialize_schema
from tests.historical_schema import historical_metadata
from tests.legacy_access_v3_fixtures import legacy_access_v3_archive, legacy_access_v3_report


@pytest.fixture
def review_database(tmp_path):
    metadata = historical_metadata(version=4)
    generation = register_inventory_metadata(metadata)
    index, publication = register_asset_group_metadata(metadata)
    engine = create_engine('sqlite:///' + str(tmp_path / 'owned-review.sqlite'))
    initialize_schema(engine, metadata)
    tables = {'index': index, 'publication': publication, 'generations': generation,
              'observations': metadata.tables['discovered_agent'], 'scans': metadata.tables['scan_session'],
              'reports': metadata.tables['scan_result']}
    yield engine, tables
    engine.dispose()


def seed_repeated_sources(engine, tables):
    report = legacy_access_v3_report('high')
    raw = legacy_access_v3_archive('high').decode()
    agent = report['agents'][0]
    metadata = {'asset_id': agent['id']}
    with engine.begin() as connection:
        for ordinal in range(2):
            scan, observation = 'review-scan-' + str(ordinal), 'review-observation-' + str(ordinal)
            connection.execute(insert(tables['scans']).values(
                id=scan, organization_id='review-owner', scan_name='Owned source', scan_type='security_only',
                status='completed', target_scope={}, scan_config={}, overall_risk_score=99))
            connection.exec_driver_sql('INSERT INTO scan_result(scan_id,result) VALUES (?,?)', (scan, raw))
            connection.execute(insert(tables['observations']).values(
                id=observation, scan_id=scan, agent_name=agent['name'], agent_type=agent['type'],
                provider=agent.get('provider'), model_name=agent.get('model'), endpoint_url=agent.get('endpoint'),
                discovery_method='owned-review', metadata=metadata, risk_score=99, risk_level='critical',
                discovered_at=datetime(2026, 1, 1) + timedelta(seconds=ordinal), vulnerabilities=[]))
    return len(raw.encode()), len(json.dumps(metadata).encode()), len(agent['vulnerabilities'])


def wait_for_publication(engine, tables):
    projector = AssetGroupProjector(engine, tables)
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        progress = projector.step()
        if progress.published:
            return
        if not progress.did_work:
            time.sleep(0.002)
    pytest.fail('Owned review publication did not complete')


def read_page(engine, tables, arguments, group=None):
    secret = 'owned-review-signing-secret'
    with engine.connect() as connection, connection.begin():
        connection.exec_driver_sql('BEGIN')
        with Session(bind=connection) as session:
            if group is None:
                return group_page(session, parse_group_request(arguments, 'review-owner', secret), secret, tables)
            parsed = parse_group_history_request(arguments, 'review-owner', group, secret)
            return group_history_page(session, parsed, secret, tables)


@pytest.mark.parametrize('limit', ['1', '100'])
def test_exhausted_history_boundary_does_not_consume_next_pages_source_budget(review_database, monkeypatch, limit):
    engine, tables = review_database
    report_bytes, metadata_bytes, findings = seed_repeated_sources(engine, tables)
    # One source fits. Two distinct near-limit sources would likewise exceed the
    # production16MiB combined budget, despite each fitting its8MiB bound.
    monkeypatch.setattr(sources, 'MAX_SOURCE_BYTES', report_bytes + metadata_bytes * 2 + 16)
    wait_for_publication(engine, tables)
    groups = read_page(engine, tables, MultiDict())['asset_groups']
    assert len(groups) == 1 and groups[0]['confirmation_history']['supported_occurrences'] == findings * 2
    group, cursor, references = groups[0]['id'], None, []
    for _ in range(findings * 2 + 4):
        arguments = MultiDict({'limit': limit, **({'cursor': cursor} if cursor else {})})
        page = read_page(engine, tables, arguments, group)
        references.extend((item['observation_id'], item['finding_ordinal']) for item in page['history'])
        if page['next_cursor'] is None:
            break
        assert page['next_cursor'] != cursor, 'A completed boundary must advance rather than loop forever'
        assert page['history'], 'Reopening an exhausted boundary must not spend the entire next page budget'
        cursor = page['next_cursor']
    else:
        pytest.fail('History traversal did not finish')
    assert len(references) == len(set(references)) == findings * 2
    assert {item[0] for item in references} == {'review-observation-0', 'review-observation-1'}


def test_timestamp_is_bounded_in_sql_before_python_materialization(review_database):
    engine, tables = review_database
    seed_repeated_sources(engine, tables)
    with engine.begin() as connection:
        connection.exec_driver_sql('UPDATE discovered_agent SET discovered_at=? WHERE id=?',
                                   ('not-a-date-' + 'x' * (65536 - len('not-a-date-')), 'review-observation-0'))
    with engine.connect() as connection:
        record = connection.execute(select(*sources.observation_columns(tables['observations'])).where(
            tables['observations'].c.id == 'review-observation-0')).one()
        assert record.timestamp_bytes == 65536
        assert record.stored_timestamp is None


def test_cloud_resource_identity_does_not_override_saved_endpoint_binding(review_database):
    from src.core.risk_projection import project_report_risk

    engine, tables = review_database
    seed_repeated_sources(engine, tables)
    report = legacy_access_v3_report('high')
    agent = report['agents'][0]
    # Add only public inventory identity to genuine finalized control evidence.
    # The endpoint/probes/control records/findings and their IDs remain original.
    cloud = {'cloud': 'aws', 'resource_id': 'arn:aws:sagemaker:us-east-1:123456789012:endpoint/review'}
    agent['metadata'] = cloud
    assert project_report_risk(report)[1][agent['id']]['risk_score'] == 70
    with engine.begin() as connection:
        connection.execute(tables['reports'].update().values(result=report))
        connection.execute(tables['observations'].update().values(
            metadata={**cloud, 'asset_id': agent['id']}, endpoint_url='https://wrong-endpoint.invalid/resource'))
    with engine.connect() as connection:
        row = connection.execute(select(*sources.observation_columns(tables['observations'])).where(
            tables['observations'].c.id == 'review-observation-0')).one()
        value = sources.SourceReader(connection, tables, time.monotonic() + 5).observation(row, 'review-owner')
    assert value.identity.status == 'unmerged'
    assert value.identity.reason == 'snapshot_target_mismatch'
    assert value.risk['risk_score'] is None


@pytest.mark.parametrize('invalid_owner', ['', 'a' * 257, 'a' * 65, 'a\ninvalid', 'a[redacted]',
                                         'http://user:password@example.test/'])
def test_malformed_earlier_owner_cannot_starve_valid_organizations(review_database, invalid_owner):
    engine, tables = review_database
    seed_repeated_sources(engine, tables)
    with engine.begin() as connection:
        report = legacy_access_v3_report('high')
        agent = report['agents'][0]
        connection.execute(tables['scans'].insert().values(
            id='bad-owner-scan', organization_id=invalid_owner, scan_name='Owned invalid namespace',
            scan_type='security_only', status='completed', target_scope={}, scan_config={}))
        connection.execute(tables['reports'].insert().values(scan_id='bad-owner-scan', result=report))
        connection.execute(tables['observations'].insert().values(
            id='bad-owner-observation', scan_id='bad-owner-scan', agent_name=agent['name'], agent_type=agent['type'],
            provider=agent.get('provider'), model_name=agent.get('model'), endpoint_url=agent.get('endpoint'),
            discovery_method='owned-review', metadata={'asset_id': agent['id']},
            discovered_at=datetime(2026, 1, 1)))
        # The normal source-write triggers create the malformed owner entry;
        # no invalidation metadata is forged or rewritten by this fixture.
        before = {name: connection.execute(select(tables[name]).order_by(tables[name].c.id
                  if name != 'reports' else tables[name].c.scan_id)).all()
                  for name in ('observations', 'scans', 'reports')}
    projector, states = AssetGroupProjector(engine, tables), []
    # Advance retry time without waiting for real backoff. This tests repeated
    # eligible maintenance passes, not whether a configured throttle elapses.
    for _ in range(20):
        projector._next_poll = 0
        progress = projector.step()
        states.append(progress.state)
        if progress.published and progress.organization_id == 'review-owner':
            break
    else:
        pytest.fail('Malformed owner starved valid tenant: ' + repr(states))
    with engine.connect() as connection:
        assert connection.scalar(select(tables['publication'].c.active_build_id).where(
            tables['publication'].c.organization_id == 'review-owner')) is not None
        assert connection.execute(select(tables['generations'].c.organization_id).where(
            tables['generations'].c.organization_id == invalid_owner)).scalar_one() == invalid_owner
        after = {name: connection.execute(select(tables[name]).order_by(tables[name].c.id
                 if name != 'reports' else tables[name].c.scan_id)).all()
                 for name in ('observations', 'scans', 'reports')}
        assert after == before
