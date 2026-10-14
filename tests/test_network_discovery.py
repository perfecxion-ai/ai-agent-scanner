"""Protocol discovery against local HTTP fixtures and bounded DNS doubles."""

import asyncio
import json
import socket
from unittest.mock import AsyncMock

import aiohttp
from aiohttp import web
import dns.asyncresolver
import dns.exception
import dns.resolver
import pytest
import pytest_asyncio

from src.core.pipeline import run_pipeline
from src.core.transport import ScanBudget, scan_transport
from src.discovery.discovery_engine import DiscoveryEngine, DiscoveryScope
from src.discovery.network_scanner import MAX_DNS_ADDRESSES, MAX_TCP_CONNECTIONS, NetworkScanner


OLLAMA = {'models': [{'name': 'fixture:latest', 'modified_at': '2026-01-01T00:00:00Z'}]}
MODELS = {'object': 'list', 'data': [{'id': 'fixture-model', 'object': 'model',
                                    'created': 1, 'owned_by': 'fixture'}]}
TGI = {'model_id': 'fixture/model', 'max_input_length': 4096}


class Response:
    def __init__(self, body, status=200, headers=None):
        self.body = body if isinstance(body, bytes) else json.dumps(body).encode()
        self.status, self.headers, self.content = status, headers or {}, self
        self.chunks = 0

    async def iter_chunked(self, size):
        for start in range(0, len(self.body), size):
            self.chunks += 1
            yield self.body[start:start + size]


@pytest_asyncio.fixture
async def service():
    responses, calls = {}, []

    async def handle(request):
        calls.append((request.method, request.path, request.host))
        value = responses.get(request.path, web.Response(status=404))
        if callable(value):
            return await value(request)
        return web.Response(body=value.body, status=value.status, headers=value.headers)

    application = web.Application()
    application.router.add_route('*', '/{tail:.*}', handle)
    runner = web.AppRunner(application)
    await runner.setup()
    site = web.TCPSite(runner, '127.0.0.1', 0)
    await site.start()
    port = site._server.sockets[0].getsockname()[1]
    try:
        yield responses, calls, port
    finally:
        await runner.cleanup()


def budget(**options):
    return ScanBudget(allowed_networks=('127.0.0.1/32',), allow_loopback=True, **options)


@pytest.fixture
def loopback_http_dns(monkeypatch):
    calls = []

    async def resolve(self, host, port=0, family=socket.AF_INET):
        assert host == 'localhost'
        calls.append((host, port))
        return [{'hostname': host, 'host': '127.0.0.1', 'port': port,
                 'family': socket.AF_INET, 'proto': socket.IPPROTO_TCP, 'flags': 0}]

    # Replace only native DNS, not PolicyResolver or its allowlist checks.
    # Runner localhost may resolve ::1 even when the fixture binds IPv4 only.
    monkeypatch.setattr(aiohttp.resolver.DefaultResolver, 'resolve', resolve)
    return calls


@pytest.mark.asyncio
@pytest.mark.parametrize('provider,document', [('ollama', OLLAMA), ('openai', MODELS), ('vllm', MODELS), ('tgi', TGI)])
async def test_positive_protocol_shapes(provider, document):
    assert await NetworkScanner()._is_ai_service(Response(document), DiscoveryEngine().ai_signatures[provider])


@pytest.mark.asyncio
@pytest.mark.parametrize('provider,document', [
    ('ollama', {'models': []}), ('ollama', {'models': [{'name': '', 'modified_at': None}]}),
    ('ollama', {'models': 'model'}), ('ollama', {'models': [False]}),
    ('openai', {'choices': [], 'model': None, 'usage': None}),
    ('openai', {'object': 'list', 'data': []}),
    ('openai', {'object': 'list', 'data': [{'id': '', 'object': 'model'}]}),
    ('openai', {'object': 'list', 'data': [False]}),
    ('openai', {'choices': [False], 'model': 'fixture', 'usage': {}}),
    ('anthropic', {'content': 'weather', 'model': None}),
    ('cohere', {'generations': False, 'text': 0}),
    ('huggingface', {'generated_text': False, 'score': 'not-a-number'}),
    ('triton', {'models': None, 'ready': False}),
    ('tgi', {'model_id': None, 'max_input_length': 'not-a-number'}),
    ('tgi', {'model_id': 'fixture', 'max_input_length': True}),
    ('tgi', {'model_id': 'fixture', 'max_input_length': 0}),
    ('openai', {**MODELS, 'error': 'bad request'}),
    ('ollama', b'<html>models name modified_at</html>'),
])
async def test_generic_malformed_or_empty_document_does_not_identify(provider, document):
    assert not await NetworkScanner()._is_ai_service(Response(document), DiscoveryEngine().ai_signatures[provider])


@pytest.mark.asyncio
@pytest.mark.parametrize('status', [200, 401, 403])
async def test_provider_headers_do_not_identify_generic_login(status):
    response = Response({'login': 'required'}, status, {'openai-version': '', 'openai-organization': 'fixture'})
    assert not await NetworkScanner()._is_ai_service(response, DiscoveryEngine().ai_signatures['openai'])


@pytest.mark.asyncio
@pytest.mark.parametrize('document', [{'models': []}, {'object': 'list', 'data': []}, {'login': 'required'}])
async def test_valid_empty_or_unrelated_inventory_is_clean_negative(document):
    with scan_transport(budget()) as limits:
        assert not await NetworkScanner()._is_ai_service(Response(document), DiscoveryEngine().ai_signatures['openai'])
    assert limits.failures == 0


@pytest.mark.asyncio
@pytest.mark.parametrize('provider,document', [('ollama', {'models': None}),
                                    ('ollama', {'models': [{'name': 'model', 'modified_at': 'not-date'}]}),
                                    ('openai', {'object': 'list', 'data': [None]}),
                                    ('tgi', {'model_id': 'model', 'max_input_length': None})])
async def test_invalid_claimed_inventory_marks_incomplete(provider, document):
    with scan_transport(budget()) as limits:
        assert not await NetworkScanner()._is_ai_service(Response(document), DiscoveryEngine().ai_signatures[provider])
    assert limits.failures == 1


@pytest.mark.asyncio
async def test_inventory_body_cap_marks_incomplete_and_stops_reading():
    response = Response(b' ' * 100_000 + json.dumps(OLLAMA).encode())
    with scan_transport(budget()) as limits:
        assert not await NetworkScanner()._is_ai_service(response, DiscoveryEngine().ai_signatures['ollama'])
        assert limits.failures == 1 and response.chunks == 3


@pytest.mark.asyncio
async def test_real_read_only_inventory_and_stable_nonvendor_identity(service):
    responses, calls, port = service
    responses['/v1/models'] = web.json_response(MODELS)
    responses['/api/tags'] = web.json_response(OLLAMA)
    responses['/info'] = web.json_response(TGI)
    scanner = NetworkScanner()
    scanner.common_ai_ports = [port]
    engine = DiscoveryEngine()
    engine.network_scanner = scanner
    scope = DiscoveryScope(network_ranges=['127.0.0.1/32'])
    with scan_transport(budget()):
        first = await run_pipeline(engine, None, None, scope, 'discovery_only')
    with scan_transport(budget()):
        second = await run_pipeline(engine, None, None, scope, 'discovery_only')
    assert first['status'] == second['status'] == 'completed'
    assert {asset['provider'] for asset in first['agents']} == {'openai-compatible', 'ollama', 'tgi'}
    assert {asset['id'] for asset in first['agents']} == {asset['id'] for asset in second['agents']}
    assert len({asset['id'] for asset in first['agents']}) == 3
    assert all(method == 'GET' for method, _, _ in calls)
    assert [path for _, path, _ in calls].count('/v1/models') == 2


@pytest.mark.asyncio
@pytest.mark.parametrize('response', [web.Response(status=404), web.Response(status=405),
                                    web.Response(status=401), web.Response(status=302),
                                    web.Response(text='<html>login</html>')])
async def test_missing_optional_routes_and_generic_service_are_clean_negatives(service, response):
    responses, _, port = service
    responses['/v1/models'] = response
    with scan_transport(budget()) as limits:
        assets = await NetworkScanner()._identify_ai_service('127.0.0.1', port, DiscoveryEngine().ai_signatures)
    assert not assets and limits.failures == limits.rejections == 0


@pytest.mark.asyncio
@pytest.mark.parametrize('bad', [web.Response(body=b'{"models":['), web.Response(status=503),
                               web.Response(body=b' ' * 10001 + b'{}')])
async def test_unusable_source_keeps_successful_assets_and_marks_partial(service, bad):
    responses, _, port = service
    responses['/v1/models'] = web.json_response(MODELS)
    responses['/api/tags'] = bad
    engine = DiscoveryEngine()
    engine.network_scanner.common_ai_ports = [port]
    with scan_transport(budget()) as limits:
        report = await run_pipeline(engine, None, None, DiscoveryScope(network_ranges=['127.0.0.1/32']), 'discovery_only')
    assert len(report['agents']) == 1 and report['agents'][0]['provider'] == 'openai-compatible'
    assert report['status'] == 'partial' and limits.failures == 1


@pytest.mark.asyncio
@pytest.mark.parametrize('status', [408, 429, 500])
async def test_http_rate_limits_and_server_timeouts_are_incomplete(service, status):
    responses, _, port = service
    responses['/v1/models'] = web.Response(status=status)
    with scan_transport(budget()) as limits:
        assert not await NetworkScanner()._identify_ai_service('127.0.0.1', port, DiscoveryEngine().ai_signatures)
    assert limits.failures == 1


@pytest.mark.asyncio
async def test_transport_truncation_and_cap_count_once(service):
    responses, _, port = service

    async def truncated(request):
        response = web.StreamResponse(headers={'Content-Length': '1000'})
        await response.prepare(request)
        await response.write(b'{"models":[')
        request.transport.close()
        return response

    responses['/api/tags'] = truncated
    with scan_transport(budget()) as limits:
        assert not await NetworkScanner()._identify_ai_service('127.0.0.1', port, DiscoveryEngine().ai_signatures)
        assert limits.failures == 1
    responses['/api/tags'] = web.json_response(OLLAMA)
    with scan_transport(budget(max_response_bytes=8)) as limits:
        assert not await NetworkScanner()._identify_ai_service('127.0.0.1', port, DiscoveryEngine().ai_signatures)
        assert limits.rejections == 1 and limits.failures == 0


@pytest.mark.asyncio
async def test_real_domain_retains_host_and_does_not_expand(service, monkeypatch, loopback_http_dns):
    responses, calls, port = service
    responses['/v1/models'] = web.json_response(MODELS)
    scanner = NetworkScanner()
    scanner.common_ai_ports = [port]
    resolver = AsyncMock(return_value=['127.0.0.1'])
    monkeypatch.setattr(scanner, '_resolve_domain', resolver)
    with scan_transport(budget()):
        assets = await scanner.scan_domain('localhost', DiscoveryEngine().ai_signatures)
    assert assets[0]['endpoint'] == f'http://localhost:{port}/v1/models'
    assert 'internet_facing' not in assets[0]['metadata']
    assert all(host == f'localhost:{port}' for _, _, host in calls)
    resolver.assert_awaited_once_with('localhost')
    assert loopback_http_dns == [('localhost', port)]


@pytest.mark.asyncio
async def test_multi_address_domain_probes_each_http_authority_once(service, monkeypatch, loopback_http_dns):
    responses, calls, port = service
    responses['/v1/models'] = web.json_response(MODELS)
    scanner = NetworkScanner()
    scanner.common_ai_ports = [port]
    resolve = AsyncMock(return_value=['127.0.0.1', '127.0.0.2'])
    monkeypatch.setattr(scanner, '_resolve_domain', resolve)
    monkeypatch.setattr(scanner, '_is_port_open', AsyncMock(return_value=True))
    with scan_transport(budget()):
        assets = await scanner.scan_domain('LOCALHOST.', DiscoveryEngine().ai_signatures)
    assert len(assets) == 1 and len(calls) == 3
    assert assets[0]['endpoint'] == f'http://localhost:{port}/v1/models'
    resolve.assert_awaited_once_with('localhost')
    assert loopback_http_dns == [('localhost', port)]


@pytest.mark.asyncio
async def test_underlying_http_dns_still_rejects_unapproved_ipv6(service, monkeypatch):
    _, calls, port = service

    async def resolve(self, host, port=0, family=socket.AF_INET):
        return [{'hostname': host, 'host': '::1', 'port': port,
                 'family': socket.AF_INET6, 'proto': socket.IPPROTO_TCP, 'flags': 0}]

    monkeypatch.setattr(aiohttp.resolver.DefaultResolver, 'resolve', resolve)
    with scan_transport(budget()) as limits:
        assets = await NetworkScanner()._identify_ai_service('localhost', port, DiscoveryEngine().ai_signatures)
    assert not assets and not calls and limits.rejections == 1


@pytest.mark.asyncio
async def test_dns_bounded_a_and_aaaa_and_scope_checks(monkeypatch):
    resolve = AsyncMock(side_effect=[['192.0.2.1', '192.0.2.1'], ['2001:db8::1']])
    monkeypatch.setattr(dns.asyncresolver.Resolver, 'resolve', resolve)
    with scan_transport(ScanBudget(allowed_networks=('192.0.2.0/24', '2001:db8::/32'))) as limits:
        assert await NetworkScanner()._resolve_domain('fixture.invalid') == ['192.0.2.1', '2001:db8::1']
    assert [call.args[1] for call in resolve.await_args_list] == ['A', 'AAAA']
    assert all(call.kwargs['lifetime'] == 10 for call in resolve.await_args_list)
    assert limits.requests == 2 and limits.failures == 0


@pytest.mark.asyncio
async def test_mixed_dns_answers_fail_closed(monkeypatch):
    resolve = AsyncMock(return_value=['192.0.2.1', '169.254.169.254'])
    monkeypatch.setattr(dns.asyncresolver.Resolver, 'resolve', resolve)
    with scan_transport(ScanBudget(allowed_networks=('192.0.2.0/24',))) as limits:
        assert not await NetworkScanner()._resolve_domain('fixture.invalid')
    assert limits.rejections == 1


@pytest.mark.asyncio
async def test_dns_cap_does_not_scan_partial_answer_set(monkeypatch):
    resolve = AsyncMock(return_value=[f'192.0.2.{index}' for index in range(1, MAX_DNS_ADDRESSES + 2)])
    monkeypatch.setattr(dns.asyncresolver.Resolver, 'resolve', resolve)
    with scan_transport(ScanBudget()) as limits:
        assert not await NetworkScanner()._resolve_domain('fixture.invalid')
    assert limits.failures == 1 and resolve.await_count == 1


@pytest.mark.asyncio
@pytest.mark.parametrize('error', [dns.resolver.NXDOMAIN(), dns.exception.Timeout(), dns.resolver.NoAnswer()])
async def test_dns_failure_or_empty_answers_not_clean(error, monkeypatch):
    monkeypatch.setattr(dns.asyncresolver.Resolver, 'resolve', AsyncMock(side_effect=error))
    with scan_transport(ScanBudget()) as limits:
        assert not await NetworkScanner()._resolve_domain('fixture.invalid')
    assert limits.failures == 1


@pytest.mark.asyncio
async def test_dns_timeout_and_cancellation_propagate_promptly(monkeypatch):
    stopped = asyncio.Event()

    async def delayed(*args, **kwargs):
        try:
            await asyncio.Event().wait()
        finally:
            stopped.set()

    monkeypatch.setattr(dns.asyncresolver.Resolver, 'resolve', delayed)
    scanner = NetworkScanner()
    scanner.timeout = 0.01
    with scan_transport(ScanBudget()) as limits:
        assert not await scanner._resolve_domain('fixture.invalid')
    assert stopped.is_set() and limits.failures == 1
    stopped.clear()
    scanner.timeout = 10
    task = asyncio.create_task(scanner._resolve_domain('fixture.invalid'))
    await asyncio.sleep(0)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await asyncio.wait_for(task, 0.1)
    assert stopped.is_set()


@pytest.mark.asyncio
async def test_tcp_refused_is_clean_but_timeout_and_unexpected_io_are_incomplete(monkeypatch):
    scanner = NetworkScanner()
    with scan_transport(ScanBudget()) as limits:
        monkeypatch.setattr(asyncio, 'open_connection', AsyncMock(side_effect=ConnectionRefusedError()))
        assert not await scanner._is_port_open('192.0.2.1', 80)
        assert limits.failures == 0
        monkeypatch.setattr(asyncio, 'open_connection', AsyncMock(side_effect=TimeoutError()))
        assert not await scanner._is_port_open('192.0.2.1', 80)
        monkeypatch.setattr(asyncio, 'open_connection', AsyncMock(side_effect=OSError('synthetic secret')))
        assert not await scanner._is_port_open('192.0.2.1', 80)
        assert limits.failures == 2


@pytest.mark.asyncio
async def test_tcp_writer_closed_after_success_and_cancellation(monkeypatch):
    writer = AsyncMock()
    from unittest.mock import Mock
    writer.close = Mock()
    monkeypatch.setattr(asyncio, 'open_connection', AsyncMock(return_value=(None, writer)))
    with scan_transport(ScanBudget()):
        assert await NetworkScanner()._is_port_open('192.0.2.1', 80)
    writer.close.assert_called_once()
    entered = asyncio.Event()

    async def closing():
        entered.set()
        await asyncio.Event().wait()

    writer.wait_closed.side_effect = closing
    with scan_transport(ScanBudget()):
        task = asyncio.create_task(NetworkScanner()._is_port_open('192.0.2.1', 80))
        await entered.wait()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
    assert writer.close.call_count == 2


@pytest.mark.asyncio
async def test_unexpected_tcp_failure_preserves_other_port(monkeypatch):
    scanner = NetworkScanner()
    scanner.common_ai_ports = [80, 8080]
    good = scanner._asset('192.0.2.1', 8080, 'http', 'http://192.0.2.1:8080/v1/models', 'openai-compatible', 200)
    writer = AsyncMock()
    from unittest.mock import Mock
    writer.close = Mock()
    monkeypatch.setattr(asyncio, 'open_connection', AsyncMock(side_effect=[RuntimeError('synthetic secret'), (None, writer)]))
    monkeypatch.setattr(scanner, '_identify_ai_service', AsyncMock(return_value=[good]))
    with scan_transport(ScanBudget()) as limits:
        assert await scanner.scan_range('192.0.2.1/32', {}) == [good]
    assert limits.failures == 1


def test_identity_does_not_collide_across_protocols_or_routes():
    scanner = NetworkScanner()
    assets = [scanner._asset('host', 443, scheme, f'{scheme}://host:443{path}', 'ollama', 200)
              for scheme in ('http', 'https') for path in ('/api/tags', '/prefix/api/tags')]
    assert len({asset['id'] for asset in assets}) == 4


@pytest.mark.parametrize('host,expected', [('127.0.0.1', False), ('10.0.0.1', False), ('8.8.8.8', True),
                                         ('localhost', None), ('internal.fixture.invalid', None)])
def test_exposure_uses_literal_addresses_and_never_assumes_dns_is_public(host, expected):
    asset = NetworkScanner()._asset(host, 80, 'http', f'http://{host}/v1/models', 'openai-compatible', 200)
    if expected is None:
        assert 'internet_facing' not in asset['metadata']
    else:
        assert asset['metadata']['internet_facing'] is expected


@pytest.mark.asyncio
async def test_source_host_exception_does_not_discard_successes(monkeypatch):
    scanner = NetworkScanner()
    monkeypatch.setattr(scanner, '_scan_host', AsyncMock(side_effect=[[{'id': 'good'}], ValueError('synthetic secret')]))
    with scan_transport(ScanBudget()) as limits:
        assert await scanner.scan_range('192.0.2.0/31', {}) == [{'id': 'good'}]
    assert limits.failures == 1


@pytest.mark.asyncio
async def test_invalid_domain_or_discovery_path_never_becomes_request(service, monkeypatch):
    resolve = AsyncMock()
    monkeypatch.setattr(dns.asyncresolver.Resolver, 'resolve', resolve)
    with scan_transport(ScanBudget()) as limits:
        assert not await NetworkScanner()._resolve_domain('user:secret@fixture.invalid')
    resolve.assert_not_called()
    assert limits.failures == 1
    _, calls, port = service
    signature = {'ollama': {'response_patterns': ['modified_at'], 'paths': ['//attacker.invalid', '/api/tags?key=secret']}}
    with scan_transport(budget()) as limits:
        assert not await NetworkScanner()._identify_ai_service('127.0.0.1', port, signature)
    assert not calls and limits.failures == 2


@pytest.mark.asyncio
async def test_request_budget_stops_without_losing_previous_asset(service):
    responses, calls, port = service
    responses['/v1/models'] = web.json_response(MODELS)
    with scan_transport(budget(max_requests=1)) as limits:
        assets = await NetworkScanner()._identify_ai_service('127.0.0.1', port, DiscoveryEngine().ai_signatures)
    assert len(assets) == len(calls) == 1 and limits.rejections == 1


@pytest.mark.asyncio
async def test_connection_time_dns_rebinding_rejected(service, monkeypatch):
    _, calls, port = service
    from src.core.transport import PolicyResolver

    async def forbidden(self, host, port=0, family=0):
        self.budget.check_address('169.254.169.254')

    monkeypatch.setattr(PolicyResolver, 'resolve', forbidden)
    with scan_transport(budget()) as limits:
        assert not await NetworkScanner()._identify_ai_service('fixture.invalid', port, DiscoveryEngine().ai_signatures)
    assert not calls and limits.rejections == 1


@pytest.mark.asyncio
async def test_http_timeout_marks_incomplete(service):
    responses, _, port = service
    release = asyncio.Event()

    async def slow(request):
        await release.wait()
        return web.json_response(OLLAMA)

    responses['/api/tags'] = slow
    scanner = NetworkScanner()
    scanner.timeout = 0.01
    try:
        with scan_transport(budget()) as limits:
            assert not await scanner._identify_ai_service('127.0.0.1', port, DiscoveryEngine().ai_signatures)
    finally:
        release.set()
    assert limits.failures == 1


@pytest.mark.asyncio
async def test_non_json_io_failure_propagates_without_secret_logging():
    response = Response(b'')

    async def failed_stream(size):
        raise aiohttp.ClientPayloadError('synthetic secret')
        yield b''

    response.iter_chunked = failed_stream
    # Real streamed I/O is recorded by SafeSession, not by the JSON classifier.
    with pytest.raises(aiohttp.ClientPayloadError):
        await NetworkScanner()._is_ai_service(response, DiscoveryEngine().ai_signatures['ollama'])


@pytest.mark.asyncio
@pytest.mark.parametrize('body', [b'{"models":[],"models":[{"name":"x","modified_at":"x"}]}',
                               b'{"models":[{"name":"x","modified_at":"x"}],"extra":NaN}',
                               b'{"x":' + b'[' * 2000 + b'0' + b']' * 2000 + b'}'])
async def test_nonstandard_duplicate_or_deep_json_is_incomplete(body):
    with scan_transport(budget()) as limits:
        assert not await NetworkScanner()._is_ai_service(Response(body), DiscoveryEngine().ai_signatures['ollama'])
    assert limits.failures == 1


@pytest.mark.asyncio
async def test_chat_response_on_inventory_route_cannot_identify():
    document = {'model': 'fixture', 'choices': [{'message': {'role': 'assistant', 'content': 'hi'}}],
                'usage': {'prompt_tokens': 1, 'completion_tokens': 1, 'total_tokens': 2}}
    assert not await NetworkScanner()._is_ai_service(Response(document), DiscoveryEngine().ai_signatures['openai'])


@pytest.mark.asyncio
async def test_network_tcp_concurrency_is_bounded_and_cancelled_workers_stop(monkeypatch):
    scanner = NetworkScanner()
    active, peak = 0, 0

    async def probe(host, port):
        nonlocal active, peak
        active += 1
        peak = max(peak, active)
        try:
            await asyncio.sleep(0.001)
            return False
        finally:
            active -= 1

    monkeypatch.setattr(scanner, '_is_port_open', probe)
    assert not await scanner.scan_range('192.0.2.0/26', {})
    assert peak == MAX_TCP_CONNECTIONS and active == 0
    task = asyncio.create_task(scanner.scan_range('192.0.2.0/26', {}))
    await asyncio.sleep(0.0001)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert active == 0


def test_scanner_reuse_across_event_loops_does_not_reuse_bound_semaphore(monkeypatch):
    scanner = NetworkScanner()

    async def probe(host, port):
        await asyncio.sleep(0)
        return False

    monkeypatch.setattr(scanner, '_is_port_open', probe)
    for _ in range(2):
        assert not asyncio.run(scanner.scan_range('192.0.2.0/26', {}))


@pytest.mark.asyncio
async def test_unrelated_extension_fields_cannot_invalidate_expected_inventory():
    with scan_transport(budget()) as limits:
        assert await NetworkScanner()._is_ai_service(Response({**MODELS, 'models': 'unrelated metadata'}),
                                                    DiscoveryEngine().ai_signatures['openai'])
    assert limits.failures == 0


@pytest.mark.asyncio
@pytest.mark.parametrize('timestamp', ['2026-01-01', '2026-01-01T00:00:00', '2026-02-31T00:00:00Z'])
async def test_ollama_requires_valid_timezone_modification_timestamp(timestamp):
    document = {'models': [{'name': 'fixture', 'modified_at': timestamp}]}
    with scan_transport(budget()) as limits:
        assert not await NetworkScanner()._is_ai_service(Response(document), DiscoveryEngine().ai_signatures['ollama'])
    assert limits.failures == 1
