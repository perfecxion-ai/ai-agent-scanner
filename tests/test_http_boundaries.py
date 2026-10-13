"""Response policy applies equally to authenticated data and errors."""

from unittest.mock import patch

import pytest

from tests.test_api_auth import api as api, headers


@pytest.mark.parametrize('path', ['/api/agents', '/api/scans/missing/status', '/api/unknown'])
def test_api_responses_are_not_cacheable(api, path):
    module, client = api
    for auth in ({}, headers(module)):
        response = client.get(path, headers=auth)
        assert response.headers['Cache-Control'] == 'no-store'
        assert response.headers['X-Content-Type-Options'] == 'nosniff'
        assert response.headers['Referrer-Policy'] == 'no-referrer'


def test_auth_and_oversize_errors_are_not_cacheable(api):
    _, client = api
    for body, status in (({'api_key': 'incorrect'}, 401), ({'api_key': 'x' * 70000}, 413)):
        response = client.post('/api/auth/token', json=body)
        assert response.status_code == status
        assert response.headers['Cache-Control'] == 'no-store'


def test_handled_server_error_has_response_policy(api):
    module, client = api
    with patch.object(module.ScanSession, 'query', create=True) as query:
        query.filter_by.side_effect = RuntimeError('fixture failure')
        response = client.get('/api/scans/missing/status', headers=headers(module))
    assert response.status_code == 500
    assert response.headers['Cache-Control'] == 'no-store'
    assert response.headers['Referrer-Policy'] == 'no-referrer'


def test_html_uses_local_resource_policy_without_localhost_hsts(api):
    _, client = api
    response = client.get('/')
    assert response.status_code == 200
    policy = response.headers['Content-Security-Policy']
    for directive in ("default-src 'self'", "script-src 'self'", "style-src 'self'",
                      "connect-src 'self'", "object-src 'none'", "base-uri 'none'",
                      "frame-ancestors 'none'", "form-action 'self'"):
        assert directive in policy
    assert 'unsafe-inline' not in policy
    assert 'Strict-Transport-Security' not in response.headers
    assert response.headers['X-Content-Type-Options'] == 'nosniff'
    assert response.headers['Referrer-Policy'] == 'no-referrer'
