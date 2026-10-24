"""Independent cursor checks against SQLite's unchanged stored timestamp order."""

import pytest

from tests.test_api_auth import api as api, headers


STAMPS = [
    '2026-01-01 00:00:00.000000',
    '2026-01-01 00:00:00',
    '2026-01-01T00:00:00',
    '2026-01-01 00:00:00.123',
    '2026-01-01 00:00:00+00:00',
    '2025-12-31 23:30:00-02:00',
    '2026-01-01 01:00:00+02:00',
    '2026-01-01T00:00:00.120000+01:30',
    '2026-01-01X00:00:00',
    '2026-01-01.12:34:56',
    '2026-01-01,12:34:56',
]


def seed(module, stamps):
    module.db.session.add(module.ScanSession(
        id='mixed-time-fixture', organization_id='tenant-a', scan_name='Mixed timestamp fixture',
        scan_type='discovery_only', status='completed', target_scope={}, scan_config={}))
    for number in range(len(stamps)):
        module.db.session.add(module.DiscoveredAgentModel(
            id='time-observation-%03d' % number, scan_id='mixed-time-fixture', agent_name='Fixture',
            agent_type='assistant' if number % 2 else 'worker', discovery_method='fixture'))
    module.db.session.commit()
    with module.db.engine.begin() as connection:
        for number, stamp in enumerate(stamps):
            connection.exec_driver_sql('UPDATE discovered_agent SET discovered_at=? WHERE id=?',
                                       (stamp, 'time-observation-%03d' % number))


def stored_rows(module, typed=False):
    with module.db.engine.connect() as connection:
        return connection.exec_driver_sql(
            'SELECT id,CAST(discovered_at AS TEXT) FROM discovered_agent '
            + ("WHERE agent_type='assistant' " if typed else '')
            + 'ORDER BY discovered_at DESC,id').all()


@pytest.mark.parametrize('limit,typed', [(1, False), (2, False), (3, True), (100, False)])
def test_mixed_timestamp_formats_follow_original_sqlite_sort_without_rewriting(api, limit, typed):
    module, client = api
    seed(module, STAMPS * 3)
    baseline = stored_rows(module)
    wanted = stored_rows(module, typed)
    found, cursors, cursor = [], set(), None
    for _ in range(len(wanted) + 1):
        query = {'limit': limit, **({'agent_type': 'assistant'} if typed else {})}
        if cursor is not None:
            query['cursor'] = cursor
        response = client.get('/api/agents', query_string=query, headers=headers(module))
        assert response.status_code == 200, response.json
        found.extend(row['id'] for row in response.json['agents'])
        assert len(found) == len(set(found)), 'Stored timestamp normalization repeated an observation'
        cursor = response.json['next_cursor']
        if cursor is None:
            assert response.json['coverage']['search_complete'] is True
            break
        assert cursor not in cursors
        cursors.add(cursor)
    else:
        pytest.fail('A finite mixed-format inventory failed to exhaust')
    assert found == [row[0] for row in wanted]
    assert stored_rows(module) == baseline


@pytest.mark.parametrize('stamp', [
    '', 'not-a-date', '2026-13-01 00:00:00', '2026-01-32 00:00:00',
    '2026-01-01 25:00:00', '2026-01-01T00:00:00Ztrailing',
    '999999999999999999999999', '2026-01-01 00:00:00.' + '1' * 50,
    b'2026-01-01 00:00:00',
    '2026-01-01.123', '2026-01-01,123',
], ids=['empty', 'text', 'month', 'day', 'hour', 'trailing', 'numeric-affinity', 'overlong', 'blob',
        'malformed-dot-time', 'malformed-comma-time'])
def test_invalid_or_unbounded_stored_timestamp_is_explicitly_unavailable(api, stamp):
    module, client = api
    seed(module, [stamp])
    response = client.get('/api/agents', query_string={'limit': 1}, headers=headers(module))
    assert response.status_code == 503, response.json
    assert response.json['code'] == 'inventory_projection_unavailable'
    assert not response.json.get('agents')
