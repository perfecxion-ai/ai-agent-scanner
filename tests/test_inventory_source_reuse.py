"""Repeated observations reuse structure while validating each fresh source."""

from copy import deepcopy
import json
from types import SimpleNamespace

import pytest
from sqlalchemy import update
from sqlalchemy.orm import Session

from src.core import asset_group_projection as sources
from src.core import inventory
from tests.legacy_access_v3_fixtures import legacy_access_v3_report
from tests.test_asset_groups import database as database, seed
from tests.test_inventory_source_binding import observed


def bound_source(kind='high'):
    source = sources.ReportSource.from_value(legacy_access_v3_report(kind))
    alias = 'owned-access-v3'
    agent = source.agents[alias]
    row = SimpleNamespace(id='observation-one', provider=agent.get('provider'),
                          model_name=agent.get('model'), endpoint_url=agent.get('endpoint'))
    return source, agent, row, {'asset_id': alias}


def test_repeated_grouped_source_validates_each_snapshot_but_normalizes_original_once(monkeypatch):
    source, agent, row, metadata = bound_source()
    assert source.risks[agent['id']]['risk_score'] == 70
    calls = []
    original = sources.target_group_identity

    def identity(value, **kwargs):
        calls.append((value is agent, kwargs['observation_id']))
        return original(value, **kwargs)

    monkeypatch.setattr(sources, 'target_group_identity', identity)
    results = []
    for number in range(4):
        row.id = 'observation-' + str(number)
        results.append(sources.bind_observation_source(row, metadata, source, 'tenant-a'))
    assert all(result.risk['risk_score'] == 70 and result.identity.status == 'grouped' for result in results)
    assert len({result.identity.group_id for result in results}) == 1
    assert [identifier for is_original, identifier in calls if is_original] == ['observation-0']
    assert [identifier for is_original, identifier in calls if not is_original] == [
        'observation-0', 'observation-1', 'observation-2', 'observation-3']


@pytest.mark.parametrize('field,value', [
    ('provider', 'other-provider'), ('model_name', None), ('endpoint_url', 'https://other.invalid/'),
])
def test_cached_original_cannot_bypass_changed_snapshot_selectors(field, value):
    source, _, row, metadata = bound_source()
    assert sources.bind_observation_source(row, metadata, source, 'tenant-a').risk['risk_score'] == 70
    setattr(row, field, value)
    row.id = 'changed-snapshot'
    result = sources.bind_observation_source(row, metadata, source, 'tenant-a')
    assert result.risk['risk_score'] is None
    assert result.identity.status == 'unmerged' and result.identity.reason == 'snapshot_target_mismatch'


@pytest.mark.parametrize('metadata_change', [
    {'endpoint_redacted': True},
    {'cloud': 'gcp', 'resource_id': 'projects/owned/locations/us-central1/endpoints/changed'},
])
def test_cached_original_still_interprets_each_rows_metadata(metadata_change):
    source, _, row, metadata = bound_source()
    grouped = sources.bind_observation_source(row, metadata, source, 'tenant-a')
    assert grouped.identity.status == 'grouped' and grouped.risk['risk_score'] == 70
    metadata.update(metadata_change)
    row.id = 'changed-metadata-one'
    first = sources.bind_observation_source(row, metadata, source, 'tenant-a')
    row.id = 'changed-metadata-two'
    second = sources.bind_observation_source(row, metadata, source, 'tenant-a')
    assert first.identity.status == second.identity.status == 'unmerged'
    assert first.identity.group_id != second.identity.group_id
    # Group incompleteness does not erase an otherwise bound archived finding.
    assert first.risk['risk_score'] == second.risk['risk_score'] == 70


def test_cached_grouped_source_still_validates_observation_and_owner():
    source, _, row, metadata = bound_source()
    first = sources.bind_observation_source(row, metadata, source, 'tenant-a')
    second = sources.bind_observation_source(row, metadata, source, 'tenant-b')
    assert first.identity.status == second.identity.status == 'grouped'
    assert first.identity.group_id != second.identity.group_id
    row.id = 'invalid\nobservation'
    with pytest.raises(ValueError):
        sources.bind_observation_source(row, metadata, source, 'tenant-a')


def test_returned_group_identity_cannot_mutate_the_cached_original_target():
    source, _, row, metadata = bound_source()
    first = sources.bind_observation_source(row, metadata, source, 'tenant-a')
    assert first.identity.status == 'grouped' and first.risk['risk_score'] == 70
    expected = deepcopy(first.identity)
    first.identity.target['endpoint'] = 'https://changed.invalid/'
    row.id = 'observation-two'
    second = sources.bind_observation_source(row, metadata, source, 'tenant-a')
    assert second.identity == expected and second.risk['risk_score'] == 70


def test_unmerged_original_ids_are_never_reused_for_other_observations():
    source, _, row, metadata = bound_source()
    report = deepcopy(source.report)
    report['agents'][0]['metadata'].update(cloud='gcp', resource_id='incomplete')
    source = sources.ReportSource.from_value(report)
    assert source.risks[metadata['asset_id']]['risk_score'] == 70
    first = sources.bind_observation_source(row, metadata, source, 'tenant-a')
    row.id = 'observation-two'
    second = sources.bind_observation_source(row, metadata, source, 'tenant-a')
    assert first.identity.status == second.identity.status == 'unmerged'
    assert first.identity.reason == second.identity.reason == 'cloud_identity_incomplete'
    assert first.identity.group_id != second.identity.group_id
    assert first.risk['risk_score'] == second.risk['risk_score'] == 70


def test_inventory_rereads_changed_reports_and_metadata_on_later_pages(database):
    seed(database, 'owned', count=2)
    first = observed(database)
    assert [item['risk_score'] for item in first['agents']] == [70, 70]
    engine, tables = database
    with engine.begin() as connection:
        connection.execute(update(tables['reports']).values(result=json.dumps(legacy_access_v3_report('zero'))))
    assert [item['risk_score'] for item in observed(database)['agents']] == [0, 0]
    with engine.begin() as connection:
        connection.execute(update(tables['observations']).where(tables['observations'].c.id == 'owned-00001')
                           .values(metadata='{"asset_id":"unmatched"}'))
    assert [item['risk_score'] for item in observed(database)['agents']] == [0, None]


def test_prepared_source_reads_bind_each_identifier_and_current_byte_cap(database, monkeypatch):
    seed(database, 'owned', count=2)
    engine, tables = database
    metadata = tables['observations'].c.metadata
    selector = tables['observations'].c.id
    with Session(engine) as session:
        statements = []
        execute = session.execute

        def capture(statement, *args, **kwargs):
            statements.append(statement)
            return execute(statement, *args, **kwargs)

        monkeypatch.setattr(session, 'execute', capture)
        reader = inventory._SourceStatements(session)
        first = reader.read(metadata, selector, 'owned-00000')
        assert first[0] > 1 and isinstance(first[1], bytes)
        refused = reader.read(metadata, selector, 'owned-00001', allowance=first[0] - 1)
        assert refused == (first[0], None)
        assert reader.read(metadata, selector, 'absent') is None
        assert reader.read(metadata, selector, 'owned-00000', allowance=first[0]) == first
        assert len({id(statement) for statement in statements}) == 1
        # Reusing SQL structure must never retain the prior fetched value.
        execute(update(tables['observations']).where(selector == 'owned-00000').values(metadata='{}'))
        assert reader.read(metadata, selector, 'owned-00000', allowance=2) == (2, b'{}')
        monkeypatch.setattr(inventory, 'MAX_STORED_RISK_BYTES', 1)
        assert reader.read(metadata, selector, 'owned-00000', allowance=100) == (2, None)
