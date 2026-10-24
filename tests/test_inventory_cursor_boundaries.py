"""Every permitted UTF-8 key must fit a usable bounded continuation."""

from tests.test_api_auth import api as api, headers


def test_maximum_unicode_scope_and_raw_timestamp_cursor_round_trip(api):
    module, client = api
    symbol = '\U0001f4a9'
    organization, kind = symbol * 64, symbol * 100
    identifiers = [symbol * 63 + ending for ending in ('\U0001f4a0', '\U0001f4a1')]
    module.db.session.add(module.ScanSession(
        id='unicode-scope', organization_id=organization, scan_name='Unicode scope fixture',
        scan_type='discovery_only', status='completed', target_scope={}, scan_config={}))
    for identifier in identifiers:
        module.db.session.add(module.DiscoveredAgentModel(
            id=identifier, scan_id='unicode-scope', agent_name='Unicode scope fixture',
            agent_type=kind, discovery_method='fixture'))
    module.db.session.commit()
    with module.db.engine.begin() as connection:
        connection.exec_driver_sql('UPDATE discovered_agent SET discovered_at=?',
                                   ('2026-01-01 00:00:00.' + '1' * 44,))
    query = {'limit': '1', 'agent_type': kind, 'risk_level': 'unknown'}
    auth = headers(module, organization)
    first = client.get('/api/agents', query_string=query, headers=auth)
    assert first.status_code == 200, first.json
    assert first.json['next_cursor']
    assert len(first.json['next_cursor']) <= 4096
    query['cursor'] = first.json['next_cursor']
    second = client.get('/api/agents', query_string=query, headers=auth)
    assert second.status_code == 200, second.json
    assert [item['id'] for item in first.json['agents'] + second.json['agents']] == identifiers
    assert second.json['next_cursor'] is None
    assert second.json['coverage']['search_complete'] is True
