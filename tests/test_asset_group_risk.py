"""Indexed group risk remains bound to the latest canonical saved observation."""

import base64
import json
import time

import pytest
from sqlalchemy import event, select, update
from werkzeug.datastructures import MultiDict

from src.core import asset_group_projection as sources
from src.core import asset_groups as groups
from src.core.asset_group_risk import RISK_FIELDS, RISK_LEVELS
from src.core.asset_group_storage import ACTIVE_FIELDS
from src.core.inventory import InventoryError
from src.core.risk_projection import project_report_risk
from tests.legacy_access_fixtures import legacy_access_report
from tests.legacy_access_v3_fixtures import legacy_access_v3_report
from tests.test_asset_groups import (
    SECRET, database as database, history, page, publish, seed, source_rows,
)


def singleton_report(kind='high'):
    document = legacy_access_v3_report(kind)
    # Public identity is deliberately incomplete; its exact saved evidence remains valid.
    document['agents'][0]['metadata'].update(cloud='gcp', resource_id='incomplete')
    return document


@pytest.mark.parametrize('level,score', [
    ('minimal', 0), ('low', 15), ('medium', 45), ('high', 70), ('critical', 90), ('unknown', None),
])
def test_each_risk_filter_matches_exact_canonical_latest_descriptor(database, level, score):
    document = legacy_access_v3_report('high' if level in {'high', 'critical'} else 'zero')
    if score is None:
        document['risk_assessment_status'] = 'not_assessed'
        document['summary']['overall_risk_score'] = None
    else:
        # These unit records exercise level bands, without creating response evidence.
        document['agents'][0].update(risk_score=score, risk_level=level)
        document['summary']['overall_risk_score'] = score
    expected = project_report_risk(document)[1][document['agents'][0]['id']]
    assert expected['risk_level'] == level and expected['risk_score'] == score
    seed(database, 'bands', report=document)
    before = source_rows(database)
    publish(database)
    for requested in RISK_LEVELS:
        result = page(database, [('risk_level', ' ' + requested.upper() + ' ')])
        assert result['coverage']['search_complete'] is True and result['next_cursor'] is None
        assert len(result['asset_groups']) == int(requested == level)
        if requested == level:
            assert result['asset_groups'][0]['latest_observation_risk'] == expected
    engine, tables = database
    with engine.connect() as connection:
        cached = connection.execute(select(tables['index'])).mappings().one()
        assert {name: cached[name] for name in RISK_FIELDS} == expected
        assert connection.exec_driver_sql('SELECT typeof(risk_score) FROM asset_group_index').scalar_one() == (
            'null' if score is None else 'real')
    assert source_rows(database) == before


@pytest.mark.parametrize('latest', ['zero', 'unassessed', 'obsolete'])
def test_risk_filter_never_matches_an_earlier_high_from_history(database, latest):
    earlier = seed(database, 'earlier', stamp=1)['agents'][0]
    document = legacy_access_report('high') if latest == 'obsolete' else legacy_access_v3_report('zero')
    if latest == 'obsolete':
        for name in ('provider', 'model', 'endpoint', 'evidence_context_id'):
            document['agents'][0][name] = earlier[name]
    if latest == 'unassessed':
        document['risk_assessment_status'] = 'not_assessed'
    seed(database, 'latest', stamp=2, report=document)
    publish(database)
    assert page(database, [('risk_level', 'high')])['asset_groups'] == []
    group = page(database, [('risk_level', 'minimal' if latest == 'zero' else 'unknown')])['asset_groups'][0]
    assert group['observation_count'] == 2
    assert group['confirmation_history']['supported_occurrences'] == 1
    entries = history(database, group['id'])['history']
    assert any(entry['classification'] == 'supported_confirmation' for entry in entries)


def test_partial_confirmation_and_unmerged_targets_keep_current_high_risk(database):
    seed(database, 'partial', report=singleton_report('partial'), count=3)
    publish(database)
    result = page(database, [('risk_level', 'high')])
    assert len(result['asset_groups']) == 3
    assert all(value['identity_status'] == 'unmerged' for value in result['asset_groups'])
    assert all(value['latest_observation_risk']['risk_coverage_status'] == 'partial'
               and value['latest_observation_risk']['risk_score'] == 70 for value in result['asset_groups'])


def test_indexed_sparse_pages_reopen_only_matches_and_use_ordered_risk_index(database, monkeypatch):
    seed(database, 'nonmatches', report=singleton_report('zero'), count=601)
    seed(database, 'matches', report=singleton_report(), count=4)
    seed(database, 'older-matches', report=singleton_report(), count=2, stamp=0)
    seed(database, 'foreign', organization='tenant-b', report=singleton_report(), count=2)
    publish(database)
    engine, _ = database
    opened, statements = [], []
    original = sources.SourceReader.observation

    def observe(self, row, organization):
        opened.append(row.id)
        return original(self, row, organization)

    def capture(connection, cursor, statement, parameters, context, many):
        if statement.startswith('SELECT ') and 'asset_group_index.risk_level = ?' in statement:
            statements.append((statement, parameters))

    monkeypatch.setattr(sources.SourceReader, 'observation', observe)
    event.listen(engine, 'before_cursor_execute', capture)
    try:
        cursor, found = None, []
        while True:
            args = [('limit', '2'), ('risk_level', 'high')]
            if cursor:
                args.append(('cursor', cursor))
            response = page(database, args)
            found.extend(value['latest_observation']['id'] for value in response['asset_groups'])
            cursor = response['next_cursor']
            if cursor is None:
                assert response['coverage']['search_complete'] is True
                break
    finally:
        event.remove(engine, 'before_cursor_execute', capture)
    assert sorted(found) == (['matches-' + str(index).zfill(5) for index in range(4)]
                             + ['older-matches-' + str(index).zfill(5) for index in range(2)])
    assert opened == found
    assert len(statements) >= 2
    with engine.connect() as connection:
        continuation_plans = []
        for statement, parameters in statements:
            details = [row[3] for row in connection.exec_driver_sql('EXPLAIN QUERY PLAN ' + statement, parameters)]
            assert 'asset_group_index.is_latest = 1' in statement
            assert any('INDEX ix_asset_group_head_risk_page (' in detail and 'risk_level=?' in detail
                       and 'organization_id=?' in detail and 'publication_nonce=?' in detail for detail in details), details
            assert not any('TEMP B-TREE' in detail for detail in details), details
            if 'asset_group_index.observed_at_us <= ?' in statement:
                continuation_plans.append(details)
        assert continuation_plans
        assert all(any('INDEX ix_asset_group_head_risk_page (' in detail and 'observed_at_us<?' in detail
                       for detail in details) for details in continuation_plans), continuation_plans


def test_risk_filter_cursor_binds_normalized_filter_and_all_current_scopes(database):
    seed(database, 'many', report=singleton_report(), count=3)
    publish(database)
    first = page(database, [('limit', '1'), ('risk_level', ' HIGH ')])
    cursor = first['next_cursor']
    assert cursor
    second = page(database, [('limit', '1'), ('risk_level', 'high'), ('cursor', cursor)])
    assert second['asset_groups'][0]['id'] != first['asset_groups'][0]['id']
    for args, organization in [
            ([('limit', '1'), ('risk_level', 'unknown'), ('cursor', cursor)], 'tenant-a'),
            ([('limit', '1'), ('cursor', cursor)], 'tenant-a'),
            ([('limit', '2'), ('risk_level', 'high'), ('cursor', cursor)], 'tenant-a'),
            ([('limit', '1'), ('risk_level', 'high'), ('cursor', cursor)], 'tenant-b')]:
        with pytest.raises(InventoryError) as failure:
            page(database, args, organization=organization)
        assert failure.value.status == 400
    engine, tables = database
    with engine.begin() as connection:
        connection.execute(update(tables['observations']).where(tables['observations'].c.scan_id == 'many')
                           .values(agent_name='Changed source name'))
    with pytest.raises(InventoryError) as failure:
        page(database, [('limit', '1'), ('risk_level', 'high'), ('cursor', cursor)])
    assert failure.value.status == 409


def test_signed_legacy_cursor_still_reports_old_policy_as_stale(database):
    seed(database, 'many', report=singleton_report(), count=2)
    publish(database)
    cursor = page(database, [('limit', '1')])['next_cursor']
    raw = groups._signer(SECRET).unsign(cursor)
    payload = json.loads(base64.urlsafe_b64decode(raw + b'=' * (-len(raw) % 4)))
    payload.pop('risk_level')
    payload['policy'] = '0' * 64
    legacy = groups._signer(SECRET).sign(base64.urlsafe_b64encode(
        json.dumps(payload).encode()).rstrip(b'=')).decode()
    with pytest.raises(InventoryError) as failure:
        groups.parse_group_request(MultiDict({'limit': '1', 'cursor': legacy}), 'tenant-a', SECRET)
    assert failure.value.status == 409


@pytest.mark.parametrize('field', RISK_FIELDS)
def test_filtered_out_cache_tampering_cannot_be_hidden_by_restoring_publication(database, field):
    seed(database, 'confirmed')
    publish(database)
    engine, tables = database
    with engine.begin() as connection:
        publication = connection.execute(select(tables['publication'])).mappings().one()
        active = {name: publication[name] for name in ACTIVE_FIELDS}
        # A changed filter fact must fail before the matching-candidate query runs.
        replacement = {'risk_score': None, 'risk_level': 'unknown', 'risk_coverage_status': 'not_assessed',
                       'risk_assessment_status': 'not_assessed', 'risk_scoring_policy': None,
                       'security_status': 'unknown'}[field]
        connection.execute(update(tables['index']).values({field: replacement}))
        connection.execute(update(tables['publication']).values(**active))
    with pytest.raises(InventoryError) as failure:
        page(database, [('risk_level', 'high')])
    assert failure.value.status == 503


@pytest.mark.parametrize('field,replacement', [
    ('risk_score', 71), ('risk_level', 'critical'), ('risk_coverage_status', 'partial'),
    ('risk_assessment_status', 'partial'), ('risk_scoring_policy', 'unknown-policy'), ('security_status', 'failed'),
])
def test_candidate_reopen_compares_every_cached_canonical_fact(database, monkeypatch, field, replacement):
    seed(database, 'confirmed')
    publish(database)
    original = sources.SourceReader.observation

    def changed(self, row, organization):
        source = original(self, row, organization)
        source.risk = dict(source.risk, **{field: replacement})
        return source

    monkeypatch.setattr(sources.SourceReader, 'observation', changed)
    with pytest.raises(InventoryError) as failure:
        page(database, [('risk_level', 'high')])
    assert failure.value.status == 503


@pytest.mark.parametrize('field,value', [
    ('risk_score', 'x' * 1025), ('risk_scoring_policy', 'x' * 65), ('risk_level', None),
], ids=['text-score', 'oversized-policy', 'missing-level'])
def test_sealing_and_reopen_refuse_incomplete_or_withheld_unknown_descriptor(database, field, value):
    seed(database, 'unknown', report=legacy_access_report('high'))
    engine, tables = database
    projector = groups.AssetGroupProjector(engine, tables)
    assert projector.step().processed_rows == 1
    with engine.begin() as connection:
        # SQL bypasses affinity conversion to exercise SQLite's physical storage boundary.
        connection.exec_driver_sql('UPDATE asset_group_index SET ' + field + ' = ?', (value,))
        cached = connection.execute(select(*groups._cache_columns(tables['index']))).one()
        reader = sources.SourceReader(connection, tables, time.monotonic() + 5)
        with pytest.raises(InventoryError) as failure:
            groups._reopen(reader, cached, 'tenant-a')
        assert failure.value.status == 503
    projector._next_poll = 0
    projector._after_organization = None
    assert projector.step().state == 'blocked'
    with engine.connect() as connection:
        assert connection.scalar(select(tables['index'].c.publication_nonce)) is None
        assert connection.scalar(select(tables['publication'].c.active_build_id)) is None
    with pytest.raises(InventoryError) as failure:
        page(database, [('risk_level', 'high')])
    assert failure.value.status == 503


def test_nonmatching_unreadable_source_blocks_full_publication(database):
    seed(database, 'confirmed')
    seed(database, 'nonmatching', report='zero')
    engine, tables = database
    with engine.begin() as connection:
        connection.execute(update(tables['reports']).where(tables['reports'].c.scan_id == 'nonmatching')
                           .values(result='{invalid'))
    projector = groups.AssetGroupProjector(engine, tables)
    assert projector.step().state == 'blocked'
    with pytest.raises(InventoryError) as failure:
        page(database, [('risk_level', 'high')])
    assert failure.value.status == 503
