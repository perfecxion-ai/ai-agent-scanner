"""Transport tests run against a synthetic loopback server."""

from unittest.mock import AsyncMock

import aiohttp
from aiohttp import web
import pytest

from src.core.transport import PolicyResolver, SafeSession, ScanBudget, TransportPolicyError, scan_transport


@pytest.fixture
async def target_server():
    visited = []
    async def handler(request):
        visited.append(request.path)
        if request.path == '/redirect':
            raise web.HTTPFound('/secret')
        if request.path == '/large':
            return web.Response(body=b'x' * 2048)
        return web.json_response({'response': 'fixture'})

    app = web.Application()
    app.router.add_get('/{path:.*}', handler)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, '127.0.0.1', 0)
    await site.start()
    port = site._server.sockets[0].getsockname()[1]
    try:
        yield f'http://127.0.0.1:{port}', visited
    finally:
        await runner.cleanup()


@pytest.mark.asyncio
async def test_redirect_cannot_escape_target(target_server):
    url, visited = target_server
    with scan_transport(ScanBudget(allowed_networks=('127.0.0.1/32',))):
        async with SafeSession(timeout=aiohttp.ClientTimeout(total=2)) as session:
            async with session.get(url + '/redirect', allow_redirects=True) as response:
                assert response.status == 302
    assert visited == ['/redirect']


@pytest.mark.asyncio
async def test_shared_budget_counts_across_sessions(target_server):
    url, visited = target_server
    budget = ScanBudget(allowed_networks=('127.0.0.1/32',), max_requests=1)
    with scan_transport(budget):
        async with SafeSession() as session:
            async with session.get(url) as response:
                assert await response.json() == {'response': 'fixture'}
        async with SafeSession() as session:
            with pytest.raises(TransportPolicyError, match='budget'):
                async with session.get(url):
                    pass
    assert len(visited) == 1
    assert budget.rejections == 1


@pytest.mark.asyncio
async def test_response_limit_marks_rejection(target_server):
    url, _ = target_server
    budget = ScanBudget(max_response_bytes=1024)
    with scan_transport(budget):
        async with SafeSession() as session:
            with pytest.raises(TransportPolicyError, match='body limit'):
                async with session.get(url + '/large') as response:
                    await response.text()
    assert budget.rejections == 1


@pytest.mark.asyncio
async def test_literal_ip_rejected_before_connection(target_server):
    url, visited = target_server
    with scan_transport(ScanBudget(allowed_networks=('192.0.2.0/24',))):
        async with SafeSession() as session:
            with pytest.raises(TransportPolicyError, match='allowlist'):
                async with session.get(url):
                    pass
    assert visited == []


@pytest.mark.asyncio
async def test_dns_answer_validated_at_connection_time():
    resolver = AsyncMock()
    resolver.resolve.return_value = [{'host': '192.0.2.10'}, {'host': '169.254.169.254'}]
    policy = PolicyResolver(ScanBudget(allowed_networks=('192.0.2.0/24',)), resolver)
    with pytest.raises(TransportPolicyError, match='Address class'):
        await policy.resolve('fixture.invalid', 443)
    resolver.resolve.return_value = [{'host': '192.0.2.10'}]
    assert await policy.resolve('fixture.invalid', 443) == [{'host': '192.0.2.10'}]


@pytest.mark.parametrize('url', ['file:///etc/passwd', 'http://user:password@host', 'ftp://host'])
def test_non_http_and_embedded_credentials_rejected(url):
    with pytest.raises(TransportPolicyError):
        ScanBudget().reserve(url)
