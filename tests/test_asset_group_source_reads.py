"""Prepared source reads keep current selectors, byte caps and null semantics."""

import json
import threading
import time

import pytest
from sqlalchemy import delete, event, update

from src.core import asset_group_projection as sources
from src.core.inventory import InventoryError
from tests.test_asset_groups import database as database, seed


def source_columns(tables, kind):
    if kind == 'report':
        return tables['reports'].c.result, tables['reports'].c.scan_id
    return tables['observations'].c.metadata, tables['observations'].c.id


def identifier(kind, name):
    return name if kind == 'report' else name + '-00000'


def write_source(connection, tables, kind, name, value):
    column, selector = source_columns(tables, kind)
    connection.execute(update(column.table).where(selector == identifier(kind, name)).values({column.key: value}))


@pytest.mark.parametrize('kind', ['report', 'metadata'])
def test_raw_statement_rebinds_selectors_and_decreasing_or_growing_allowances(database, kind):
    seed(database, 'first')
    seed(database, 'second')
    engine, tables = database
    first, second = '{"payload":"first"}', '{"payload":"second-longer"}'
    with engine.begin() as connection:
        write_source(connection, tables, kind, 'first', first)
        write_source(connection, tables, kind, 'second', second)
    statements, bindings = [], []

    def capture(connection, statement, multiparams, parameters, execution_options):
        if 'group_source_identifier' in parameters:
            statements.append(statement)
            bindings.append(dict(parameters))

    event.listen(engine, 'before_execute', capture)
    try:
        with engine.connect() as connection:
            reader = sources.SourceReader(connection, tables, time.monotonic() + 5)
            column, selector = source_columns(tables, kind)
            assert reader._raw(column, selector, identifier(kind, 'first'), 100) == (True, first.encode(), len(first))
            with pytest.raises(sources.PageBudget):
                reader._raw(column, selector, identifier(kind, 'second'), len(second) - 1)
            assert reader._raw(column, selector, identifier(kind, 'second'), len(second)) == (
                True, second.encode(), len(second))
            with pytest.raises(sources.PageBudget):
                reader._raw(column, selector, identifier(kind, 'first'), 0)
            assert reader._raw(column, selector, identifier(kind, 'first'), sources.MAX_STORED_RISK_BYTES + 1) == (
                True, first.encode(), len(first))
    finally:
        event.remove(engine, 'before_execute', capture)
    assert len(statements) == 5 and all(statement is statements[0] for statement in statements)
    assert bindings == [{'group_source_identifier': identifier(kind, name), 'group_source_allowance': allowance}
                        for name, allowance in [('first', 100), ('second', len(second) - 1),
                                                ('second', len(second)), ('first', 0),
                                                ('first', sources.MAX_STORED_RISK_BYTES)]]


def test_raw_statements_stay_separate_for_each_source_and_reader(database):
    document = seed(database, 'owned')
    engine, tables = database
    with engine.connect() as connection:
        reader = sources.SourceReader(connection, tables, time.monotonic() + 5)
        source = reader.observation(reader.observation_row('owned-00000', 'owned', 'tenant-a'), 'tenant-a')
        assert source.supported_count == 1 and source.risk['risk_score'] == 70
        assert len(reader._raw_statements) == 2
        statements = list(reader._raw_statements.values())
        assert statements[0] is not statements[1]
        report_bytes = len(json.dumps(document).encode())
        metadata_bytes = len(json.dumps({'asset_id': document['agents'][0]['id']}).encode())
        assert reader.source_bytes == report_bytes + metadata_bytes
        second = sources.SourceReader(connection, tables, time.monotonic() + 5)
        other = second.observation(second.observation_row('owned-00000', 'owned', 'tenant-a'), 'tenant-a')
        assert other.supported_count == 1 and second.source_bytes == reader.source_bytes
        assert all(first is not later for first in statements for later in second._raw_statements.values())


@pytest.mark.parametrize('kind', ['report', 'metadata'])
@pytest.mark.parametrize('value,raw,size', [(None, None, 0), ('null', b'null', 4), ('', b'', 0)])
def test_warmed_raw_statement_distinguishes_sql_null_json_null_empty_and_missing(database, kind, value, raw, size):
    seed(database, 'owned')
    engine, tables = database
    with engine.begin() as connection:
        reader = sources.SourceReader(connection, tables, time.monotonic() + 5)
        column, selector = source_columns(tables, kind)
        assert reader._raw(column, selector, identifier(kind, 'owned'), sources.MAX_STORED_RISK_BYTES)[0] is True
        write_source(connection, tables, kind, 'owned', value)
        assert reader._raw(column, selector, identifier(kind, 'owned'), size) == (True, raw, size)
        assert reader._raw(column, selector, identifier(kind, 'missing'), 0) == (False, None, 0)
        if value == '':
            with pytest.raises(InventoryError):
                sources.decode_source(raw)
        else:
            assert sources.decode_source(raw) is None


@pytest.mark.parametrize('kind', ['report', 'metadata'])
@pytest.mark.parametrize('oversized', [False, True])
def test_raw_case_withholds_values_exceeding_current_allowance_or_absolute_cap(database, kind, oversized):
    seed(database, 'owned')
    engine, tables = database
    value = 'x' * (sources.MAX_STORED_RISK_BYTES + 1 if oversized else 64)
    allowance = sources.MAX_STORED_RISK_BYTES * 2 if oversized else len(value) - 1
    captured = []

    def capture(connection, statement, multiparams, parameters, execution_options):
        if 'group_source_identifier' in parameters:
            captured.append((statement, dict(parameters)))

    with engine.begin() as connection:
        reader = sources.SourceReader(connection, tables, time.monotonic() + 5)
        column, selector = source_columns(tables, kind)
        reader._raw(column, selector, identifier(kind, 'owned'), sources.MAX_STORED_RISK_BYTES)
        write_source(connection, tables, kind, 'owned', value)
        event.listen(engine, 'before_execute', capture)
        try:
            with pytest.raises(InventoryError if oversized else sources.PageBudget):
                reader._raw(column, selector, identifier(kind, 'owned'), allowance)
        finally:
            event.remove(engine, 'before_execute', capture)
        assert len(captured) == 1
        statement, parameters = captured[0]
        length, withheld, is_null = connection.execute(statement, parameters).one()
        assert length == len(value) and withheld is None and is_null is False
        assert parameters['group_source_allowance'] == min(allowance, sources.MAX_STORED_RISK_BYTES)


@pytest.mark.parametrize('kind', ['report', 'metadata'])
@pytest.mark.parametrize('value', [None, 'null', '{}', 'missing', '', '{'])
def test_changed_source_cannot_borrow_a_warmed_sources_confirmation(database, kind, value):
    seed(database, 'first')
    seed(database, 'second')
    engine, tables = database
    with engine.begin() as connection:
        reader = sources.SourceReader(connection, tables, time.monotonic() + 5)
        first = reader.observation_row('first-00000', 'first', 'tenant-a')
        assert reader.observation(first, 'tenant-a').supported_count == 1
        second = reader.observation_row('second-00000', 'second', 'tenant-a')
        column, selector = source_columns(tables, kind)
        if value == 'missing':
            connection.execute(delete(column.table).where(selector == identifier(kind, 'second')))
        else:
            write_source(connection, tables, kind, 'second', value)
            second = reader.observation_row('second-00000', 'second', 'tenant-a')
        if value in {'', '{'} or value == 'missing' and kind == 'metadata':
            with pytest.raises(InventoryError):
                reader.observation(second, 'tenant-a')
        else:
            result = reader.observation(second, 'tenant-a')
            assert result.supported_count is None and result.risk['risk_score'] is None
            assert result.history_complete is False


@pytest.mark.parametrize('warm', [False, True])
@pytest.mark.parametrize('stopped', [False, True])
def test_cold_and_warm_raw_reads_stop_before_sql_after_budget_or_stop(database, warm, stopped):
    seed(database, 'owned')
    engine, tables = database
    stop = threading.Event()

    def forbidden(*args, **kwargs):
        raise AssertionError('Stopped or expired source reads must not query')

    with engine.connect() as connection:
        reader = sources.SourceReader(connection, tables, time.monotonic() + 5, stop)
        column, selector = source_columns(tables, 'metadata')
        if warm:
            assert reader._raw(column, selector, 'owned-00000', sources.MAX_STORED_RISK_BYTES)[0] is True
        if stopped:
            stop.set()
        else:
            reader.deadline = time.monotonic() - 1
        event.listen(engine, 'before_execute', forbidden)
        try:
            with pytest.raises(sources.PageBudget):
                reader._raw(column, selector, 'owned-00000', sources.MAX_STORED_RISK_BYTES)
        finally:
            event.remove(engine, 'before_execute', forbidden)
