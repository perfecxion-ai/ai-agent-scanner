"""Independent checks of reused source selectors and cooperative read budgets."""

import threading
import time

import pytest
from sqlalchemy import delete, event, update

from src.core import asset_group_projection as sources
from src.core.inventory import InventoryError
from tests.test_asset_groups import database as database, seed


@pytest.mark.parametrize('warm', [False, True])
@pytest.mark.parametrize('budget', ['expired', 'stopped'])
def test_exhausted_reader_never_executes_cold_or_warm_statement(database, warm, budget):
    seed(database, 'owned')
    engine, tables = database
    stop = threading.Event()
    with engine.connect() as connection:
        reader = sources.SourceReader(connection, tables, time.monotonic() + 5, stop)
        if warm:
            assert reader.observation_row('owned-00000', 'owned', 'tenant-a') is not None
        if budget == 'expired':
            reader.deadline = time.monotonic() - 1
        else:
            stop.set()

        def forbidden(*args, **kwargs):
            raise AssertionError('An exhausted reader executed SQL')

        event.listen(connection, 'before_execute', forbidden)
        try:
            with pytest.raises(sources.PageBudget):
                reader.observation_row('owned-00000', 'owned', 'tenant-a')
        finally:
            event.remove(connection, 'before_execute', forbidden)


def test_warm_selector_observes_scan_owner_reassignment(database):
    seed(database, 'owned')
    engine, tables = database
    with engine.begin() as connection:
        reader = sources.SourceReader(connection, tables, time.monotonic() + 5)
        assert reader.observation_row('owned-00000', 'owned', 'tenant-a') is not None
        connection.execute(update(tables['scans']).where(tables['scans'].c.id == 'owned')
                           .values(organization_id='tenant-b'))
        assert reader.observation_row('owned-00000', 'owned', 'tenant-a') is None
        assert reader.observation_row('owned-00000', 'owned', 'tenant-b') is not None


def test_warm_selector_observes_observation_scan_reassignment(database):
    seed(database, 'owned')
    seed(database, 'replacement', organization='tenant-b')
    engine, tables = database
    with engine.begin() as connection:
        reader = sources.SourceReader(connection, tables, time.monotonic() + 5)
        assert reader.observation_row('owned-00000', 'owned', 'tenant-a') is not None
        connection.execute(update(tables['observations']).where(
            tables['observations'].c.id == 'owned-00000').values(scan_id='replacement'))
        assert reader.observation_row('owned-00000', 'owned', 'tenant-a') is None
        assert reader.observation_row('owned-00000', 'replacement', 'tenant-a') is None
        assert reader.observation_row('owned-00000', 'replacement', 'tenant-b') is not None


def test_warm_selector_does_not_return_deleted_observation(database):
    seed(database, 'owned')
    engine, tables = database
    with engine.begin() as connection:
        reader = sources.SourceReader(connection, tables, time.monotonic() + 5)
        assert reader.observation_row('owned-00000', 'owned', 'tenant-a') is not None
        connection.execute(delete(tables['observations']).where(tables['observations'].c.id == 'owned-00000'))
        assert reader.observation_row('owned-00000', 'owned', 'tenant-a') is None


def test_warm_reader_checks_changed_metadata_size_before_materializing(database, monkeypatch):
    seed(database, 'owned')
    engine, tables = database
    with engine.begin() as connection:
        reader = sources.SourceReader(connection, tables, time.monotonic() + 5)
        row = reader.observation_row('owned-00000', 'owned', 'tenant-a')
        assert reader.observation(row, 'tenant-a').supported_count == 1
        oversized = 'x' * (sources.MAX_STORED_RISK_BYTES + 1)
        connection.execute(update(tables['observations']).where(
            tables['observations'].c.id == 'owned-00000').values(metadata=oversized))
        row = reader.observation_row('owned-00000', 'owned', 'tenant-a')
        assert row.metadata_bytes == len(oversized)

        def forbidden(*args, **kwargs):
            raise AssertionError('Oversized metadata was requested from the database')

        monkeypatch.setattr(reader, '_raw', forbidden)
        with pytest.raises(InventoryError) as error:
            reader.observation(row, 'tenant-a')
        assert error.value.status == 503


def test_warm_reader_rechecks_provider_before_reusing_supported_facts(database):
    seed(database, 'owned')
    engine, tables = database
    with engine.begin() as connection:
        reader = sources.SourceReader(connection, tables, time.monotonic() + 5)
        row = reader.observation_row('owned-00000', 'owned', 'tenant-a')
        assert reader.observation(row, 'tenant-a').supported_count == 1
        connection.execute(update(tables['observations']).where(
            tables['observations'].c.id == 'owned-00000').values(provider='different-provider'))
        row = reader.observation_row('owned-00000', 'owned', 'tenant-a')
        projected = reader.observation(row, 'tenant-a')
        assert projected.identity.reason == 'snapshot_target_mismatch'
        assert projected.supported_count is None
        assert projected.risk['risk_score'] is None
