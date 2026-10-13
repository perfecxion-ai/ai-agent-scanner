"""Bounded scan history must not expose another organization's inventory."""

import pytest

from tests.test_api_auth import api as api, headers


def test_history_requires_authentication(api):
    _, client = api
    assert client.get('/api/scans').status_code == 401


def test_history_is_owned_paginated_and_omits_configuration(api):
    module, client = api
    for scan_id, tenant in [('one', 'tenant-a'), ('two', 'tenant-a'), ('private', 'tenant-b')]:
        module.db.session.add(module.ScanSession(
            id=scan_id, organization_id=tenant, scan_name=scan_id, scan_type='discovery_only',
            target_scope={'domains': ['sensitive.example.test']},
            scan_config={'sensitive': 'do-not-list'}))
    module.db.session.commit()
    response = client.get('/api/scans?limit=1&offset=0', headers=headers(module))
    assert response.status_code == 200
    assert response.json['total'] == 2
    assert len(response.json['scans']) == 1
    second = client.get('/api/scans?limit=1&offset=1', headers=headers(module)).json
    assert {response.json['scans'][0]['scan_id'], second['scans'][0]['scan_id']} == {'one', 'two'}
    assert 'sensitive' not in response.text
    assert 'private' not in response.text
    assert client.get('/api/scans?offset=2', headers=headers(module)).json['scans'] == []


@pytest.mark.parametrize('query', ['limit=0', 'limit=101', 'limit=abc', 'limit=2.5',
                                   'offset=-1', 'offset=100001', 'offset=NaN'])
def test_history_rejects_invalid_pagination(api, query):
    module, client = api
    assert client.get('/api/scans?' + query, headers=headers(module)).status_code == 400
