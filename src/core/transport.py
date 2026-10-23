"""Bounded HTTP transport and connection-time target enforcement."""

import asyncio
import ipaddress
import json
import logging
import math
import socket
from contextlib import asynccontextmanager, contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field

import aiohttp
from aiohttp.abc import AbstractResolver
from yarl import URL

from src.core.request_evidence import bind_response, cancel_request, capture_body, close_request, reserved_request
from src.core.request_provenance import RequestCapture
from src.core.tenant_evidence import (
    TenantEvidenceError, guard_tenant_request, observe_tenant_request,
)


class TransportPolicyError(ValueError):
    """A request was refused by the scan transport policy."""


@dataclass
class ScanBudget:
    allowed_networks: tuple[str, ...] | None = None
    allow_loopback: bool = False
    max_requests: int = 500
    max_response_bytes: int = 1_048_576
    request_timeout_seconds: float = 30
    requests: int = 0
    failures: int = 0
    rejections: int = 0
    networks: tuple = field(init=False, repr=False)

    def __post_init__(self):
        if self.max_requests < 1 or self.max_response_bytes < 1:
            raise ValueError('Transport limits must be positive')
        if (type(self.request_timeout_seconds) not in (int, float)
                or not math.isfinite(self.request_timeout_seconds)
                or not 1 <= self.request_timeout_seconds <= 300):
            raise ValueError('Request timeout must be from 1 to 300 seconds')
        self.networks = tuple(ipaddress.ip_network(value, strict=False) for value in self.allowed_networks or ())

    def check_address(self, address):
        ip = ipaddress.ip_address(address)
        if ip.is_link_local or ip.is_multicast or ip.is_unspecified or getattr(ip, 'ipv4_mapped', None):
            raise TransportPolicyError('Address class is not permitted')
        if ip.is_loopback and not self.allow_loopback:
            raise TransportPolicyError('Loopback requires explicit opt-in')
        denied = ('0.0.0.0/8', '240.0.0.0/4', '100.100.100.200/32',
                  '168.63.129.16/32', 'fd00:ec2::254/128')
        if any(ip.version == network.version and ip in network
               for network in map(ipaddress.ip_network, denied)):
            raise TransportPolicyError('Metadata or reserved address is not permitted')
        if self.allowed_networks is None:
            return
        if not any(ip.version == network.version and ip in network for network in self.networks):
            raise TransportPolicyError('Address is outside the scan allowlist')

    def reserve(self, url):
        parsed = URL(url)
        if parsed.scheme not in ('http', 'https') or not parsed.host or parsed.user is not None:
            raise TransportPolicyError('An HTTP(S) URL without embedded credentials is required')
        try:
            address = ipaddress.ip_address(parsed.host)
        except ValueError:
            address = None
        if address is not None:
            self.check_address(address)
        if self.requests >= self.max_requests:
            raise TransportPolicyError('Scan request budget exhausted')
        self.requests += 1


_budget: ContextVar[ScanBudget | None] = ContextVar('scan_budget', default=None)


def current_budget():
    return _budget.get()


def model_request_timeout():
    """Use the operator's bounded request deadline for active model probes."""
    budget = current_budget()
    return aiohttp.ClientTimeout(total=budget.request_timeout_seconds if budget else 30)


def _bounded_timeout(value, maximum):
    if isinstance(value, aiohttp.ClientTimeout):
        total = value.total
        if type(total) not in (int, float) or not math.isfinite(total) or total <= 0:
            total = maximum
        return aiohttp.ClientTimeout(total=min(total, maximum),
                                     connect=value.connect, sock_read=value.sock_read,
                                     sock_connect=value.sock_connect, ceil_threshold=value.ceil_threshold)
    if value is None:
        return aiohttp.ClientTimeout(total=maximum)
    if type(value) in (int, float) and math.isfinite(value):
        return aiohttp.ClientTimeout(total=min(value, maximum) if value > 0 else maximum)
    raise TransportPolicyError('Invalid HTTP timeout configuration')


def record_response_failure(status_code=None):
    """Record a required model interaction rejected at the HTTP layer.

    Intentional denied controls in authentication probes do not call this helper.
    """
    budget = current_budget()
    if budget is not None:
        budget.failures += 1
    reason = ('authorization denied (HTTP 401)' if status_code == 401 else
              'authorization denied (HTTP 403)' if status_code == 403 else
              'HTTP response rejected')
    logging.getLogger(__name__).warning('Required model interaction failed: %s', reason)


@contextmanager
def scan_transport(budget):
    token = _budget.set(budget)
    try:
        yield budget
    finally:
        _budget.reset(token)


class PolicyResolver(AbstractResolver):
    def __init__(self, budget, resolver=None):
        self.budget = budget
        self.resolver = resolver or aiohttp.resolver.DefaultResolver()

    async def resolve(self, host, port=0, family=socket.AF_INET):
        addresses = await asyncio.wait_for(self.resolver.resolve(host, port, family), timeout=10)
        if not addresses or len(addresses) > 32:
            raise TransportPolicyError('DNS must return between 1 and 32 addresses')
        for address in addresses:
            self.budget.check_address(address['host'])
        return addresses

    async def close(self):
        await self.resolver.close()


class BoundedResponse:
    def __init__(self, response, budget, evidence_token=None, request_evidence=None):
        self.response = response
        self.budget = budget
        self.body = None
        self._evidence_token = evidence_token
        self.__request_evidence = request_evidence
        bind_response(evidence_token, self)

    def __getattr__(self, name):
        return getattr(self.response, name)

    @property
    def content(self):
        return self

    @property
    def _request_evidence(self):
        return self.__request_evidence

    async def iter_chunked(self, size):
        received = 0
        async for chunk in self.response.content.iter_chunked(size):
            received += len(chunk)
            if received > self.budget.max_response_bytes:
                raise TransportPolicyError('Response exceeded scan body limit')
            yield chunk

    async def read(self):
        if self.body is None:
            data = bytearray()
            async for chunk in self.iter_chunked(8192):
                data.extend(chunk)
            self.body = bytes(data)
            capture_body(self._evidence_token, self, self.body)
        return self.body

    async def text(self, encoding=None, errors='replace'):
        return (await self.read()).decode(encoding or 'utf-8', errors=errors)

    async def json(self, **kwargs):
        return json.loads(await self.text())


class SafeSession:
    """ClientSession subset used by probes, with redirects and proxies disabled."""

    def __init__(self, **kwargs):
        self.budget = current_budget() or ScanBudget()
        self.kwargs = kwargs
        self.session = None
        self.resolver = None

    async def __aenter__(self):
        self.resolver = PolicyResolver(self.budget)
        connector = aiohttp.TCPConnector(resolver=self.resolver, limit=20)
        options = dict(self.kwargs)
        options['timeout'] = _bounded_timeout(options.get('timeout'), self.budget.request_timeout_seconds)
        trace = aiohttp.TraceConfig()

        async def headers_sent(session, context, params):
            capture = context.trace_request_ctx
            if isinstance(capture, RequestCapture):
                capture.sent_headers(params.method, str(params.url), params.headers)

        async def chunk_sent(session, context, params):
            capture = context.trace_request_ctx
            if isinstance(capture, RequestCapture):
                capture.sent_chunk(params.method, str(params.url), params.chunk)

        trace.on_request_headers_sent.append(headers_sent)
        trace.on_request_chunk_sent.append(chunk_sent)
        options['trace_configs'] = [*options.get('trace_configs', []), trace]
        self.session = aiohttp.ClientSession(connector=connector, trust_env=False, **options)
        await self.session.__aenter__()
        return self

    async def __aexit__(self, *args):
        try:
            return await self.session.__aexit__(*args)
        except asyncio.CancelledError:
            cancel_request()
            raise
        finally:
            await self.resolver.close()

    @asynccontextmanager
    async def request(self, method, url, discovery=False, **kwargs):
        evidence_token = None
        capture = None
        tenant_observed = False
        try:
            try:
                guard_tenant_request(method, url, kwargs, getattr(self.session, 'headers', {}))
            except TenantEvidenceError:
                raise TransportPolicyError('Protected tenant evidence conflicts with request material') from None
            self.budget.reserve(url)
            evidence_token = reserved_request()
            if 'timeout' in kwargs:
                kwargs['timeout'] = _bounded_timeout(kwargs['timeout'], self.budget.request_timeout_seconds)
            kwargs['allow_redirects'] = False
            capture = RequestCapture()
            kwargs['trace_request_ctx'] = capture
            async with self.session.request(method, url, **kwargs) as response:
                try:
                    request_evidence = capture.seal(response)
                    observe_tenant_request(request_evidence)
                    tenant_observed = True
                    yield BoundedResponse(response, self.budget, evidence_token, request_evidence)
                except asyncio.CancelledError:
                    cancel_request(evidence_token)
                    raise
        except asyncio.CancelledError:
            cancel_request(evidence_token)
            raise
        except TransportPolicyError:
            self.budget.rejections += 1
            logging.getLogger(__name__).warning('HTTP transport policy rejected request')
            raise
        except (aiohttp.ClientError, TimeoutError, asyncio.TimeoutError) as exc:
            # A TCP banner is an expected negative when asking an unknown port
            # whether it speaks HTTP. Never ignore body truncation, TLS failures,
            # refused connections, timeouts, or errors from active security work.
            if (discovery and isinstance(exc, aiohttp.ClientResponseError)
                    and exc.status == 400 and exc.headers is None):
                logging.getLogger(__name__).debug('Discovery port did not speak HTTP')
                raise
            self.budget.failures += 1
            logging.getLogger(__name__).warning('HTTP transport failed: %s',
                                               'certificate verification' if isinstance(
                                                   exc, aiohttp.ClientConnectorCertificateError)
                                               else 'request or response I/O')
            raise
        finally:
            if (capture is not None and not tenant_observed
                    and (capture.headers is not None or capture.failed)):
                observe_tenant_request(None)
            close_request(evidence_token)

    def get(self, url, **kwargs):
        return self.request('GET', url, **kwargs)
