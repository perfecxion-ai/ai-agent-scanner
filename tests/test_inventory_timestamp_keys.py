"""Cursor keys preserve valid historical SQLite timestamp representations."""

import pytest

from tests.test_api_auth import api as api, headers


@pytest.mark.parametrize('stored_stamp', [
    '2026-01-01 00:00:00.000000',
    '2026-01-01 00:00:00',
    '2026-01-01T00:00:00',
    '2026-01-01 00:00:00.123',
    '2026-01-01 00:00:00+00:00',
], ids=['native', 'whole-seconds', 'iso-separator', 'short-fraction', 'utc-offset'])
def test_cursor_traversal_preserves_raw_timestamp_sort_keys(api, stored_stamp):
    module, client = api
    module.db.session.add(module.ScanSession(
        id='timestamp-fixture', organization_id='tenant-a', scan_name='Timestamp fixture',
        scan_type='discovery_only', status='completed', target_scope={}, scan_config={}))
    for index in range(4):
        module.db.session.add(module.DiscoveredAgentModel(
            id=f'timestamp-{index}', scan_id='timestamp-fixture', agent_name='Timestamp fixture',
            agent_type='assistant', discovery_method='fixture'))
    module.db.session.commit()
    with module.db.engine.begin() as connection:
        connection.exec_driver_sql('UPDATE discovered_agent SET discovered_at=?', (stored_stamp,))
        expected = connection.exec_driver_sql(
            'SELECT id FROM discovered_agent ORDER BY discovered_at DESC,id').scalars().all()
    seen, cursors, cursor = [], set(), None
    for _ in range(5):
        query = {'limit': '1'}
        if cursor:
            query['cursor'] = cursor
        response = client.get('/api/agents', query_string=query, headers=headers(module))
        assert response.status_code == 200, response.json
        page = response.json
        seen.extend(item['id'] for item in page['agents'])
        assert len(seen) == len(set(seen)), 'A timestamp conversion repeated an observation'
        cursor = page['next_cursor']
        if cursor is None:
            assert page['coverage']['search_complete'] is True
            break
        assert cursor not in cursors, 'Continuation cursor did not progress'
        cursors.add(cursor)
    else:
        pytest.fail('Timestamp traversal never completed')
    assert seen == expected
