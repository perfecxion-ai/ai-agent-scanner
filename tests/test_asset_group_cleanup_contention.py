"""A valid cursor survives bounded obsolete-cache cleanup contention."""

import sqlite3
import threading
import time

import pytest
from sqlalchemy import func, insert, select

from src.core import asset_groups
from src.core.inventory import InventoryError
from tests.test_asset_groups import database as database, history, page, publish, seed, source_rows


def sqlite_errors(error):
    originals, seen = [], set()
    while error is not None and id(error) not in seen:
        seen.add(id(error))
        original = getattr(error, 'orig', error)
        if isinstance(original, sqlite3.OperationalError):
            originals.append(original)
        error = error.__context__
    return originals


@pytest.mark.parametrize('mode', ['reserved-only', 'cleanup-without-spill', 'cleanup-with-spill'])
def test_cleanup_contention_preserves_the_same_history_cursor(database, monkeypatch, mode):
    seed(database, 'owned-source', count=3)
    publish(database)
    engine, tables = database
    group = page(database)['asset_groups'][0]['id']
    first = history(database, group, [('limit', '1')])
    cursor = first['next_cursor']
    assert cursor
    continuation = [('limit', '1'), ('cursor', cursor)]
    expected = history(database, group, continuation)
    complete = history(database, group)['history']
    original_sources = source_rows(database)
    with engine.begin() as connection:
        assert connection.exec_driver_sql('PRAGMA journal_mode').scalar_one() == 'delete'
        publication = dict(connection.execute(select(tables['publication'])).mappings().one())
        original = dict(connection.execute(select(tables['index'])).mappings().first())
        old_build = 'f' * 32 if publication['active_build_id'] != 'f' * 32 else 'e' * 32
        obsolete = [{**original, 'build_id': old_build, 'observation_id': f'owned-old-{ordinal:04}',
                     'source_generation': '0' * 32, 'publication_nonce': None,
                     'is_latest': False, 'group_observation_count': 0} for ordinal in range(80)]
        connection.execute(insert(tables['index']), obsolete)

    # Keep the production writer's half-second cooperative deadline and 50 ms
    # SQLite busy cap. Only the owned reader gets a shorter test deadline.
    monkeypatch.setattr(asset_groups, 'READ_SECONDS', 0.1)
    ready, release = threading.Event(), threading.Event()
    result = {}

    def cleanup():
        try:
            with engine.connect() as connection:
                connection.exec_driver_sql('PRAGMA cache_size=1')
                connection.exec_driver_sql('PRAGMA cache_spill=' + (
                    'ON' if mode == 'cleanup-with-spill' else 'OFF'))
                connection.commit()
                deadline = time.monotonic() + asset_groups.BACKGROUND_SECONDS
                with asset_groups._database_deadline(connection, deadline):
                    connection.exec_driver_sql('BEGIN IMMEDIATE')
                    result['cache_size'] = connection.exec_driver_sql('PRAGMA cache_size').scalar_one()
                    result['spill'] = connection.exec_driver_sql('PRAGMA cache_spill').scalar_one()
                    result['deleted'] = (0 if mode == 'reserved-only' else
                        asset_groups.AssetGroupProjector(engine, tables)._cleanup(
                            connection, 'tenant-a', [publication['active_build_id']]))
                    ready.set()
                    if not release.wait(max(0, deadline - time.monotonic())):
                        raise AssertionError('Owned reader did not finish inside the maintenance deadline')
                    connection.commit()
        except BaseException as error:
            result['error'] = error
        finally:
            ready.set()

    writer = threading.Thread(target=cleanup, name='owned-group-cleanup', daemon=True)
    writer.start()
    during = None
    try:
        assert ready.wait(3), 'Owned cleanup did not reach its bounded hold point'
        assert 'error' not in result, repr(result.get('error'))
        if mode == 'cleanup-with-spill':
            with pytest.raises(InventoryError) as failure:
                history(database, group, continuation)
            error = failure.value
            assert error.status == 503 and error.code == 'asset_group_projection_unavailable'
            originals = sqlite_errors(error)
            assert originals, 'The refusal must originate from actual SQLite contention'
            for original in originals:
                if hasattr(original, 'sqlite_errorcode'):
                    assert original.sqlite_errorcode == 5
                else:
                    # Python 3.10 does not expose SQLite exception result codes.
                    assert original.args == ('database is locked',)
        else:
            during = history(database, group, continuation)
    finally:
        release.set()
        writer.join(3)
        assert not writer.is_alive(), 'Owned cleanup thread did not stop'

    assert 'error' not in result, repr(result.get('error'))
    assert result['cache_size'] == 1
    assert bool(result['spill']) == (mode == 'cleanup-with-spill')
    assert result['deleted'] == (0 if mode == 'reserved-only' else 80)
    if during is not None:
        assert during['history'] == expected['history']
        assert during['coverage'] == expected['coverage']

    # Retry the exact original cursor. No rebuild or cursor restart is needed.
    assert continuation == [('limit', '1'), ('cursor', cursor)]
    after = history(database, group, continuation)
    assert after['history'] == expected['history']
    assert after['coverage'] == expected['coverage']
    assert history(database, group)['history'] == complete
    assert source_rows(database) == original_sources
    with engine.connect() as connection:
        assert dict(connection.execute(select(tables['publication'])).mappings().one()) == publication
        count = connection.execute(select(func.count()).select_from(tables['index']).where(
            tables['index'].c.build_id == old_build)).scalar_one()
        assert count == (80 if mode == 'reserved-only' else 0)
