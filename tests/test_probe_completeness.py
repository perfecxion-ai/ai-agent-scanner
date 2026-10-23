"""Required model calls and issued cookie values need distinct treatment."""

import json
from unittest.mock import AsyncMock, patch

import pytest
from aiohttp import web

from src.core.transport import ScanBudget, scan_transport
from src.security.access_control_tests import AccessControlTester
from src.security.security_engine import SecurityTestEngine


@pytest.fixture
async def target(monkeypatch):
    monkeypatch.setenv('FIXTURE_ISSUED_KEY', 'issued-test-key')
    async def handler(request):
        status = int(request.match_info['status'])
        if request.headers.get('Authorization') == 'Bearer issued-test-key':
            return web.Response(text='private-fixture-marker')
        response = web.Response(status=status, text='Synthetic response')
        if request.query.get('cookie') == 'unsafe':
            # Attribute-like text in the value must not count as actual flags.
            response.headers.add('Set-Cookie', 'session=SecureHttpOnlySameSite-secret; Path=/')
        elif request.query.get('cookie') == 'safe':
            response.headers.add('Set-Cookie', 'session=issued-secret; Secure; HttpOnly; SameSite=Lax')
        return response

    app = web.Application()
    app.router.add_route('*', '/chat/{status}', handler)
    app.router.add_route('*', '/chat/{status}/v1/chat/completions', handler)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, '127.0.0.1', 0)
    await site.start()
    port = site._server.sockets[0].getsockname()[1]
    try:
        yield f'http://127.0.0.1:{port}/chat'
    finally:
        await runner.cleanup()


@pytest.mark.asyncio
@pytest.mark.parametrize('status', [401, 404, 429])
async def test_rejected_model_calls_cannot_report_completed_low_risk(target, status):
    engine = SecurityTestEngine()
    engine.prompt_tester.injection_payloads = {'instruction_bypass': ['Say hello']}
    agent = {'id': 'test', 'name': 'Test', 'endpoint': f'{target}/{status}',
             'provider': 'openai-compatible', 'model': 'fixture-model'}
    budget = ScanBudget(allowed_networks=('127.0.0.1/32',), allow_loopback=True)
    with scan_transport(budget), patch('asyncio.sleep', AsyncMock()), patch.object(engine.access_tester, 'test_agent', AsyncMock(return_value=[])):
        result = await engine._test_single_agent(agent)
    assert result['status'] == 'partial'
    assert result['overall_risk_score'] is None
    assert result['vulnerabilities'] == []
    assert budget.failures > 1  # Both prompt and privacy rejected interactions counted.


@pytest.mark.asyncio
async def test_denied_authentication_control_is_not_failed_model_coverage(target):
    agent = {'endpoint': f'{target}/401', 'authentication_required': True,
             'protected_response_marker': 'private-fixture-marker', 'api_key_env': 'FIXTURE_ISSUED_KEY'}
    budget = ScanBudget(allowed_networks=('127.0.0.1/32',), allow_loopback=True)
    with scan_transport(budget):
        assert await AccessControlTester()._has_access_controls(
            agent, agent['endpoint'], agent['protected_response_marker'], [])
    assert budget.failures == 0


@pytest.mark.asyncio
async def test_cookie_value_not_exported_and_does_not_fake_flags(target):
    budget = ScanBudget(allowed_networks=('127.0.0.1/32',), allow_loopback=True)
    with scan_transport(budget):
        findings = await AccessControlTester()._test_session_management({'endpoint': f'{target}/200?cookie=unsafe'})
    assert len(findings) == 1
    assert findings[0]['cookie_name'] == 'session'
    assert len(findings[0]['issues']) == 3
    assert 'SecureHttpOnlySameSite-secret' not in json.dumps(findings)
    assert 'cookie' not in findings[0]
    assert findings[0]['evidence_status'] == 'heuristic'


@pytest.mark.asyncio
async def test_secure_cookie_has_no_attribute_finding(target):
    with scan_transport(ScanBudget(allowed_networks=('127.0.0.1/32',), allow_loopback=True)):
        findings = await AccessControlTester()._test_session_management({'endpoint': f'{target}/200?cookie=safe'})
    assert findings == []
