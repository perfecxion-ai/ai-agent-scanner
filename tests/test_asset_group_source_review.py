"""Independent prepared-source isolation and cumulative byte-budget checks."""

import json
import time

import pytest
from sqlalchemy import event, update

from src.core import asset_group_projection as sources
from tests.test_asset_groups import database as database, seed


def test_report_and_metadata_with_same_identifier_remain_distinct_sources(database):
    document = seed(database, 'owned')
    engine, tables = database
    with engine.begin() as connection:
        connection.execute(update(tables['observations']).values(id='owned'))
        reader = sources.SourceReader(connection, tables, time.monotonic() + 5)
        row = reader.observation_row('owned', 'owned', 'tenant-a')
        result = reader.observation(row, 'tenant-a')
        assert result.supported_count == 1
        assert result.risk['risk_score'] == 70
        assert reader.source_bytes == len(json.dumps(document).encode()) + len(
            json.dumps({'asset_id': document['agents'][0]['id']}).encode())


def test_remaining_public_budget_withholds_second_report_and_preserves_accounting(database, monkeypatch):
    document = seed(database, 'first')
    seed(database, 'second')
    report_bytes = len(json.dumps(document).encode())
    metadata_bytes = len(json.dumps({'asset_id': document['agents'][0]['id']}).encode())
    first_cost = report_bytes + metadata_bytes
    monkeypatch.setattr(sources, 'MAX_SOURCE_BYTES', first_cost * 2 - 1)
    engine, tables = database
    with engine.begin() as connection:
        reader = sources.SourceReader(connection, tables, time.monotonic() + 5)
        first = reader.observation_row('first-00000', 'first', 'tenant-a')
        assert reader.observation(first, 'tenant-a').supported_count == 1
        assert reader.source_bytes == first_cost
        second = reader.observation_row('second-00000', 'second', 'tenant-a')
        captured = []

        def capture(connection, statement, multiparams, parameters, execution_options):
            if parameters.get('group_source_identifier') == 'second':
                captured.append((statement, dict(parameters)))

        event.listen(connection, 'before_execute', capture)
        try:
            with pytest.raises(sources.PageBudget):
                reader.observation(second, 'tenant-a')
        finally:
            event.remove(connection, 'before_execute', capture)
        assert reader.source_bytes == first_cost
        assert set(reader.reports) == {'first'}
        assert len(captured) == 1
        statement, parameters = captured[0]
        assert parameters['group_source_allowance'] == report_bytes - 1
        length, withheld, is_null = connection.execute(statement, parameters).one()
        assert length == report_bytes and withheld is None and is_null is False


@pytest.mark.parametrize('kind', ['report', 'metadata'])
def test_warm_source_allowance_uses_utf8_bytes_instead_of_character_count(database, kind):
    seed(database, 'owned')
    engine, tables = database
    column, selector, identifier = (
        (tables['reports'].c.result, tables['reports'].c.scan_id, 'owned') if kind == 'report'
        else (tables['observations'].c.metadata, tables['observations'].c.id, 'owned-00000'))
    payload = json.dumps({'value': '\u00e9' * 16}, ensure_ascii=False)
    encoded = payload.encode()
    assert len(encoded) > len(payload)
    with engine.begin() as connection:
        reader = sources.SourceReader(connection, tables, time.monotonic() + 5)
        assert reader._raw(column, selector, identifier, sources.MAX_STORED_RISK_BYTES)[0]
        connection.execute(update(column.table).where(selector == identifier).values({column.key: payload}))
        with pytest.raises(sources.PageBudget):
            reader._raw(column, selector, identifier, len(payload))
        assert reader._raw(column, selector, identifier, len(encoded)) == (True, encoded, len(encoded))
