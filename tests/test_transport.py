"""Transport tests run against a synthetic loopback server."""

import asyncio
from unittest.mock import AsyncMock, patch

import aiohttp
from aiohttp import web
import pytest

from src.core.transport import PolicyResolver, SafeSession, ScanBudget, TransportPolicyError, scan_transport


@pytest.fixture
async def target_server():
    visited = []
    release = asyncio.Event()
    async def handler(request):
        visited.append(request.path)
        if request.path == '/redirect':
            raise web.HTTPFound('/secret')
        if request.path == '/large':
            return web.Response(body=b'x' * 2048)
        if request.path == '/slow':
            await release.wait()
        if request.path == '/slow-body':
            response = web.StreamResponse()
            await response.prepare(request)
            await release.wait()
            try:
                await response.write(b'fixture')
            except ConnectionResetError:
                pass
            return response
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
        release.set()
        await runner.cleanup()


@pytest.mark.asyncio
async def test_redirect_cannot_escape_target(target_server):
    url, visited = target_server
    with scan_transport(ScanBudget(allowed_networks=('127.0.0.1/32',), allow_loopback=True)):
        async with SafeSession(timeout=aiohttp.ClientTimeout(total=2)) as session:
            async with session.get(url + '/redirect', allow_redirects=True) as response:
                assert response.status == 302
    assert visited == ['/redirect']


@pytest.mark.asyncio
async def test_shared_budget_counts_across_sessions(target_server):
    url, visited = target_server
    budget = ScanBudget(allowed_networks=('127.0.0.1/32',), allow_loopback=True, max_requests=1)
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
@pytest.mark.parametrize('path', ['/slow', '/slow-body'])
async def test_request_and_body_timeouts_record_one_failure(target_server, path):
    url, _ = target_server
    budget = ScanBudget(allowed_networks=('127.0.0.1/32',), allow_loopback=True)
    with scan_transport(budget):
        async with SafeSession(timeout=aiohttp.ClientTimeout(total=0.02)) as session:
            with pytest.raises(asyncio.TimeoutError):
                async with session.get(url + path) as response:
                    await response.read()
    assert budget.requests == budget.failures == 1
    assert budget.rejections == 0


@pytest.mark.asyncio
async def test_literal_ip_rejected_before_connection(target_server):
    url, visited = target_server
    with scan_transport(ScanBudget(allowed_networks=('192.0.2.0/24',))):
        async with SafeSession() as session:
            with pytest.raises(TransportPolicyError):
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


@pytest.mark.asyncio
async def test_tcp_discovery_checks_scope_before_opening_socket():
    from src.discovery.network_scanner import NetworkScanner
    budget = ScanBudget(allowed_networks=('192.0.2.0/24',))
    with scan_transport(budget), patch('asyncio.open_connection', AsyncMock()) as connect:
        assert not await NetworkScanner()._is_port_open('169.254.169.254', 80)
        assert not await NetworkScanner()._is_port_open('198.51.100.1', 80)
        connect.assert_not_called()
    assert budget.rejections == 2


@pytest.mark.asyncio
async def test_tcp_discovery_consumes_shared_budget():
    from src.discovery.network_scanner import NetworkScanner
    budget = ScanBudget(allowed_networks=('192.0.2.0/24',), max_requests=1)
    with scan_transport(budget), patch('asyncio.open_connection', AsyncMock(side_effect=OSError)) as connect:
        assert not await NetworkScanner()._is_port_open('192.0.2.1', 80)
        assert not await NetworkScanner()._is_port_open('192.0.2.1', 443)
        assert connect.call_count == 1
    assert budget.rejections == 1


@pytest.mark.parametrize('address', ['127.0.0.1', '100.100.100.200', '168.63.129.16',
                                     '0.0.0.1', '240.0.0.1', 'fd00:ec2::254'])
def test_broad_allowlist_cannot_authorize_metadata_or_implicit_loopback(address):
    with pytest.raises(TransportPolicyError):
        ScanBudget(allowed_networks=('0.0.0.0/0', '::/0')).check_address(address)
