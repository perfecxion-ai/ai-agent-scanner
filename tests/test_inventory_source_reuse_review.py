"""Independent identity-cache isolation and fresh bounded SQL read controls."""

from copy import deepcopy
import json
from types import SimpleNamespace

import pytest
from sqlalchemy import update
from sqlalchemy.orm import Session
from werkzeug.datastructures import MultiDict

from src.core import asset_group_projection as sources
from src.core import inventory
from src.core.http_application_policy import HTTP_PUBLIC_FIELDS
from tests.legacy_access_v3_fixtures import legacy_access_v3_report
from tests.test_asset_groups import database as database, seed, source_rows
from tests.test_http_application_core import application as application, assess


def page(database):
    engine, tables = database
    request = inventory.parse_inventory_request(MultiDict(), 'tenant-a', 'owned-cache-review-key')
    with Session(engine) as session:
        return inventory.inventory_page(session, request, 'owned-cache-review-key', *[
            tables[name] for name in ('observations', 'scans', 'reports', 'generations')])


def row(agent, identifier):
    return SimpleNamespace(id=identifier, provider=agent.get('provider'), model_name=agent.get('model'),
                           endpoint_url=agent.get('endpoint'))


def test_prepared_sources_keep_colliding_identifiers_and_utf8_allowances_separate(database, monkeypatch):
    document = seed(database, 'shared', count=2)
    engine, tables = database
    text = json.dumps({'asset_id': document['agents'][0]['id'], 'padding': chr(0x1f600) * 12}, ensure_ascii=False)
    with engine.begin() as connection:
        connection.execute(update(tables['observations']).where(tables['observations'].c.id == 'shared-00000')
                           .values(id='shared', metadata=text))
    metadata_bytes = len(text.encode())
    assert metadata_bytes > len(text)
    with Session(engine) as session:
        execute, calls = session.execute, []
        def observed(statement, parameters=None, *args, **kwargs):
            calls.append((statement, dict(parameters or {})))
            return execute(statement, parameters, *args, **kwargs)
        monkeypatch.setattr(session, 'execute', observed)
        reader = inventory._SourceStatements(session)
        meta_column, report_column = tables['observations'].c.metadata, tables['reports'].c.result
        meta_id, report_id = tables['observations'].c.id, tables['reports'].c.scan_id
        first = reader.read(meta_column, meta_id, 'shared', allowance=metadata_bytes)
        archived = reader.read(report_column, report_id, 'shared')
        assert first == (metadata_bytes, text.encode())
        assert json.loads(archived[1]) == document
        assert reader.read(meta_column, meta_id, 'shared', allowance=metadata_bytes - 1) == (metadata_bytes, None)
        assert reader.read(meta_column, meta_id, 'missing', allowance=metadata_bytes) is None
        assert reader.read(meta_column, meta_id, 'shared', allowance=metadata_bytes) == first
        assert calls[0][0] is calls[2][0] is calls[3][0] is calls[4][0]
        assert calls[0][0] is not calls[1][0]
        assert calls[2][1]['inventory_source_allowance'] == metadata_bytes - 1
        assert calls[3][1]['inventory_source_identifier'] == 'missing'
        # A warm statement must still read changed bytes using the new allowance.
        session.connection().exec_driver_sql('UPDATE discovered_agent SET metadata=? WHERE id=?', ('{}', 'shared'))
        assert reader.read(meta_column, meta_id, 'shared', allowance=2) == (2, b'{}')
        monkeypatch.setattr(inventory, 'MAX_STORED_RISK_BYTES', 1)
        assert reader.read(meta_column, meta_id, 'shared', allowance=metadata_bytes) == (2, None)
        assert calls[-1][1]['inventory_source_allowance'] == 1


def test_grouped_original_reuse_is_scoped_to_owner_and_unique_alias(monkeypatch):
    # These are public identity components, with no synthesized assessment claims.
    agents = {name: {'id': name, 'provider': 'ollama', 'model': 'model-' + name,
                     'endpoint': 'https://app.example.test/resource'} for name in ('alpha', 'beta')}
    source = sources.ReportSource(None, agents, {})
    calls, original = [], sources.target_group_identity
    def identity(value, **kwargs):
        calls.append((any(value is agent for agent in agents.values()), kwargs['organization_id'],
                      kwargs['observation_id']))
        return original(value, **kwargs)
    monkeypatch.setattr(sources, 'target_group_identity', identity)
    selections = [('tenant-a', 'alpha'), ('tenant-a', 'alpha'), ('tenant-a', 'beta'), ('tenant-b', 'alpha')]
    values = [sources.bind_observation_source(row(agents[alias], 'row-' + str(number)),
              {'asset_id': alias}, source, owner) for number, (owner, alias) in enumerate(selections)]
    assert all(value.identity.status == 'grouped' for value in values)
    assert values[0].identity == values[1].identity
    assert values[0].identity.target is not values[1].identity.target
    assert len({value.identity.group_id for value in values}) == 3
    assert set(source._grouped_identities) == {('tenant-a', 'alpha'), ('tenant-a', 'beta'), ('tenant-b', 'alpha')}
    assert len([entry for entry in calls if entry[0]]) == 3
    assert [entry[2] for entry in calls if not entry[0]] == ['row-0', 'row-1', 'row-2', 'row-3']


@pytest.mark.parametrize('cause', ['missing-endpoint', 'unknown-provider', 'cloud-incomplete'])
def test_unmerged_originals_never_cache_another_rows_singleton(cause):
    agent = {'id': 'alias', 'provider': 'ollama', 'model': None, 'endpoint': 'https://app.example.test/chat'}
    if cause == 'missing-endpoint':
        agent['endpoint'] = None
    elif cause == 'unknown-provider':
        agent['provider'] = 'unknown'
    else:
        agent['metadata'] = {'cloud': 'gcp', 'resource_id': 'incomplete'}
    source = sources.ReportSource(None, {'alias': agent}, {})
    values = [sources.bind_observation_source(row(agent, identifier), {'asset_id': 'alias'}, source, 'tenant-a')
              for identifier in ('one', 'two')]
    assert all(value.identity.status == 'unmerged' for value in values)
    assert values[0].identity.group_id != values[1].identity.group_id
    assert source._grouped_identities == {}


def test_duplicate_aliases_cannot_inherit_another_decoded_sources_cache():
    document = legacy_access_v3_report('high')
    alias = document['agents'][0]['id']
    valid = sources.ReportSource.from_value(document)
    first = sources.bind_observation_source(row(document['agents'][0], 'first'), {'asset_id': alias}, valid, 'tenant-a')
    assert first.risk['risk_score'] == 70 and len(valid._grouped_identities) == 1
    ambiguous = deepcopy(document)
    ambiguous['agents'].append(deepcopy(ambiguous['agents'][0]))
    duplicate = sources.ReportSource.from_value(ambiguous)
    result = sources.bind_observation_source(row(document['agents'][0], 'second'),
                                             {'asset_id': alias}, duplicate, 'tenant-a')
    assert result.identity.reason == 'unmatched_asset_alias' and result.risk['risk_score'] is None
    assert duplicate._grouped_identities == {}


def test_later_request_reinterprets_the_original_report_and_each_metadata_row(database, monkeypatch):
    seed(database, 'owned', count=2)
    before = source_rows(database)
    decoded, original = [], sources.ReportSource.from_value
    def observed(value):
        result = original(value)
        decoded.append(result)
        return result
    monkeypatch.setattr(sources.ReportSource, 'from_value', observed)
    assert [item['risk_score'] for item in page(database)['agents']] == [70, 70]
    assert source_rows(database) == before
    engine, tables = database
    with engine.begin() as connection:
        connection.execute(update(tables['reports']).values(result=json.dumps(legacy_access_v3_report('zero'))))
        connection.execute(update(tables['observations']).where(tables['observations'].c.id == 'owned-00001')
                           .values(metadata='{"asset_id":"different"}'))
    changed = source_rows(database)
    assert [item['risk_score'] for item in page(database)['agents']] == [0, None]
    assert len(decoded) == 2 and decoded[0] is not decoded[1]
    assert source_rows(database) == changed


@pytest.mark.asyncio
@pytest.mark.parametrize('field', HTTP_PUBLIC_FIELDS)
async def test_warm_grouped_identity_does_not_bypass_per_row_http_adapter_binding(application, field):
    endpoint, _ = application
    document = await assess(endpoint, maximum=1)
    before = deepcopy(document)
    agent = document['agents'][0]
    source = sources.ReportSource.from_value(document)
    metadata = {'asset_id': agent['id'], **{name: deepcopy(agent[name]) for name in HTTP_PUBLIC_FIELDS}}
    first = sources.bind_observation_source(row(agent, 'valid-one'), metadata, source, 'tenant-a')
    assert first.identity.status == 'grouped' and first.risk['risk_score'] == 70
    mismatched = deepcopy(metadata)
    mismatched[field] = None
    second = sources.bind_observation_source(row(agent, 'changed-two'), mismatched, source, 'tenant-a')
    assert second.identity.reason == 'snapshot_target_mismatch' and second.risk['risk_score'] is None
    third = sources.bind_observation_source(row(agent, 'valid-three'), metadata, source, 'tenant-a')
    assert third.risk['risk_score'] == 70 and third.identity == first.identity
    assert document == before
