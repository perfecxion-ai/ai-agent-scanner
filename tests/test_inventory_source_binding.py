"""Observation risk uses the same saved target binding as group projections."""

from copy import deepcopy
import time
from types import SimpleNamespace

import pytest
from sqlalchemy import select, update
from sqlalchemy.orm import Session
from werkzeug.datastructures import MultiDict

from src.core import asset_group_projection as sources
from src.core import inventory
from src.core.asset_group_risk import RISK_FIELDS
from tests.legacy_access_v3_fixtures import legacy_access_v3_report
from tests.test_asset_groups import SECRET, database as database, seed, source_rows


def observed(database, **filters):
    engine, tables = database
    parsed = inventory.parse_inventory_request(MultiDict(filters), 'tenant-a', SECRET)
    with Session(engine) as session:
        return inventory.inventory_page(session, parsed, SECRET, tables['observations'], tables['scans'],
                                        tables['reports'], tables['generations'])


def grouped_source(database):
    engine, tables = database
    with engine.connect() as connection:
        reader = sources.SourceReader(connection, tables, time.monotonic() + 5)
        row = connection.execute(select(*sources.observation_columns(tables['observations']))).one()
        return reader.observation(row, 'tenant-a')


@pytest.mark.parametrize('field,value', [
    ('provider', 'different-provider'), ('provider', None),
    ('model_name', 'different-model'), ('model_name', None),
    ('endpoint_url', 'https://other.invalid/resource'), ('endpoint_url', None),
])
def test_mismatched_snapshot_selectors_keep_the_row_with_unknown_risk(database, field, value):
    report = seed(database, 'owned')
    engine, tables = database
    with engine.begin() as connection:
        connection.execute(update(tables['observations']).values({field: value}))
    unchanged = source_rows(database)
    expected = grouped_source(database)
    assert expected.identity.reason == 'snapshot_target_mismatch'
    assert expected.risk['risk_score'] is None
    assert observed(database, risk_level='high')['agents'] == []
    result = observed(database, risk_level='unknown')['agents']
    assert len(result) == 1
    assert result[0]['id'] == 'owned-00000'
    assert result[0]['asset_id'] == report['agents'][0]['id']
    assert {key: result[0][key] for key in RISK_FIELDS} == expected.risk
    assert source_rows(database) == unchanged


@pytest.mark.parametrize('kind,score', [('high', 70), ('partial', 70), ('zero', 0)])
def test_normalized_http_endpoint_retains_supported_source_risk(database, kind, score):
    report = seed(database, 'owned', report=kind)
    endpoint = report['agents'][0]['endpoint']
    assert endpoint.startswith('http://') and not endpoint.endswith('/')
    engine, tables = database
    with engine.begin() as connection:
        connection.execute(update(tables['observations']).values(endpoint_url='HTTP://' + endpoint[len('http://'):] + '/'))
    expected = grouped_source(database)
    assert expected.identity.status == 'grouped'
    result = observed(database)['agents'][0]
    assert result['risk_score'] == score
    assert {key: result[key] for key in RISK_FIELDS} == expected.risk


@pytest.mark.parametrize('cloud', ['incomplete', 'different-resource'])
def test_unmergeable_cloud_metadata_does_not_erase_valid_bound_risk(database, cloud):
    report = legacy_access_v3_report('high')
    if cloud == 'incomplete':
        report['agents'][0]['metadata'].update(cloud='gcp', resource_id='incomplete')
        metadata = {'asset_id': report['agents'][0]['id']}
    else:
        report['agents'][0]['metadata'].update(
            cloud='gcp', resource_id='projects/owned/locations/us-central1/endpoints/source')
        metadata = {'asset_id': report['agents'][0]['id'], 'cloud': 'gcp',
                    'resource_id': 'projects/owned/locations/us-central1/endpoints/snapshot'}
    seed(database, 'owned', report=report, aliases=metadata)
    expected = grouped_source(database)
    assert expected.identity.status == 'unmerged'
    result = observed(database)['agents'][0]
    assert result['risk_score'] == 70
    assert {key: result[key] for key in RISK_FIELDS} == expected.risk


@pytest.mark.parametrize('alias', ['x' * 257, 'https://example.invalid/alias?view=private', '[redacted]', 'private\nidentifier'])
def test_unsafe_or_oversized_aliases_never_bind_supported_risk(database, alias):
    report = legacy_access_v3_report('high')
    seed(database, 'owned', report=report, aliases={'asset_id': alias})
    expected = grouped_source(database)
    assert expected.asset_id is None and expected.risk['risk_score'] is None
    result = observed(database)['agents'][0]
    # Existing inventory display and response limits are independent of risk attribution.
    assert result['asset_id'] == alias
    assert {key: result[key] for key in RISK_FIELDS} == expected.risk


@pytest.mark.parametrize('alias,accepted', [
    ('safe-alias', True), ('x' * 257, False),
    ('https://example.invalid/alias?view=private', False),
    ('[redacted]', False), ('private\nidentifier', False),
])
def test_alias_guard_runs_before_the_shared_assessed_risk_lookup(alias, accepted):
    original = sources.ReportSource.from_value(legacy_access_v3_report('high'))
    assessed = original.risks['owned-access-v3']
    assert assessed['risk_score'] == 70
    # Inject facts only into this binding component, without claiming a new
    # protected producer execution or changing any frozen receipt identity.
    source = sources.ReportSource(None, {alias: {'id': alias}}, {alias: assessed})
    row = SimpleNamespace(id='owned-observation', provider=None, model_name=None, endpoint_url=None)
    result = sources.bind_observation_source(row, {'asset_id': alias}, source, 'tenant-a')
    assert (result.asset_id == alias) is accepted
    assert result.risk['risk_score'] == (70 if accepted else None)


def test_duplicate_report_alias_cannot_select_either_claim(database):
    report = legacy_access_v3_report('high')
    report['agents'].append(deepcopy(report['agents'][0]))
    seed(database, 'owned', report=report)
    result = observed(database)['agents'][0]
    assert result['risk_score'] is None
    assert {key: result[key] for key in RISK_FIELDS} == grouped_source(database).risk


@pytest.mark.parametrize('column', ['result', 'metadata'])
@pytest.mark.parametrize('nested', [False, True])
def test_duplicate_json_members_are_incomplete_instead_of_current_verdicts(database, column, nested):
    seed(database, 'owned')
    engine, tables = database
    table = tables['reports'] if column == 'result' else tables['observations']
    raw = '{"duplicate":1,"duplicate":2}'
    if nested:
        raw = '{"nested":[' + raw + ']}'
    with engine.begin() as connection:
        connection.execute(update(table).values({column: raw}))
    unchanged = source_rows(database)
    with pytest.raises(inventory.InventoryError) as failure:
        observed(database, risk_level='high')
    assert (failure.value.status, failure.value.code) == (503, 'inventory_projection_unavailable')
    assert source_rows(database) == unchanged
    with pytest.raises(inventory.InventoryError) as failure:
        grouped_source(database)
    assert failure.value.status == 503


@pytest.mark.parametrize('field,raw', [
    ('model_name', 'x' * 256), ('endpoint_url', 'x' * 4097),
    ('model_name', 'x' * 2048), ('endpoint_url', 'x' * 20000),
    ('model_name', b'bytes'), ('endpoint_url', b'bytes'),
])
def test_refused_selector_scalars_cannot_be_interpreted_as_missing(database, field, raw):
    seed(database, 'owned')
    engine, _ = database
    with engine.begin() as connection:
        connection.exec_driver_sql('UPDATE discovered_agent SET ' + field + '=?', (raw,))
    with pytest.raises(inventory.InventoryError) as failure:
        observed(database)
    assert (failure.value.status, failure.value.code) == (503, 'inventory_projection_unavailable')
    with pytest.raises(inventory.InventoryError) as failure:
        grouped_source(database)
    assert failure.value.status == 503


def test_shared_timestamp_and_error_imports_remain_compatible():
    from src.core.inventory_common import InventoryError, _timestamp
    assert inventory.InventoryError is sources.InventoryError is InventoryError
    assert inventory._timestamp is sources._timestamp is _timestamp


def test_successful_read_preserves_all_saved_source_bytes(database):
    seed(database, 'owned', count=3)
    before = source_rows(database)
    result = observed(database)
    assert len(result['agents']) == 3
    assert all(item['risk_score'] == 70 for item in result['agents'])
    assert result['coverage']['projected_reports'] == 1
    assert result['coverage']['projected_report_bytes'] > 0
    assert source_rows(database) == before
