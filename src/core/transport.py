"""Bounded HTTP transport and connection-time target enforcement."""

import ipaddress
import json
import socket
from contextlib import asynccontextmanager, contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field

import aiohttp
from aiohttp.abc import AbstractResolver
from yarl import URL


class TransportPolicyError(ValueError):
    """A request was refused by the scan transport policy."""


@dataclass
class ScanBudget:
    allowed_networks: tuple[str, ...] | None = None
    allow_loopback: bool = False
    max_requests: int = 500
    max_response_bytes: int = 1_048_576
    requests: int = 0
    failures: int = 0
    rejections: int = 0
    networks: tuple = field(init=False, repr=False)

    def __post_init__(self):
        if self.max_requests < 1 or self.max_response_bytes < 1:
            raise ValueError('Transport limits must be positive')
        self.networks = tuple(ipaddress.ip_network(value) for value in self.allowed_networks or ())

    def check_address(self, address):
        ip = ipaddress.ip_address(address)
        if self.allowed_networks is None:
            return
        if ip.is_link_local or ip.is_multicast or ip.is_unspecified or getattr(ip, 'ipv4_mapped', None):
            raise TransportPolicyError('Address class is not permitted')
        if ip.is_loopback and not self.allow_loopback:
            raise TransportPolicyError('Loopback requires explicit opt-in')
        denied = ('0.0.0.0/8', '240.0.0.0/4', '100.100.100.200/32',
                  '168.63.129.16/32', 'fd00:ec2::254/128')
        if any(ip.version == network.version and ip in network
               for network in map(ipaddress.ip_network, denied)):
            raise TransportPolicyError('Metadata or reserved address is not permitted')
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
        addresses = await self.resolver.resolve(host, port, family)
        for address in addresses:
            self.budget.check_address(address['host'])
        return addresses

    async def close(self):
        await self.resolver.close()


class BoundedResponse:
    def __init__(self, response, budget):
        self.response = response
        self.budget = budget
        self.body = None

    def __getattr__(self, name):
        return getattr(self.response, name)

    @property
    def content(self):
        return self

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
        self.session = aiohttp.ClientSession(connector=connector, trust_env=False, **self.kwargs)
        await self.session.__aenter__()
        return self

    async def __aexit__(self, *args):
        try:
            return await self.session.__aexit__(*args)
        finally:
            await self.resolver.close()

    @asynccontextmanager
    async def request(self, method, url, **kwargs):
        try:
            self.budget.reserve(url)
            kwargs['allow_redirects'] = False
            async with self.session.request(method, url, **kwargs) as response:
                yield BoundedResponse(response, self.budget)
        except TransportPolicyError:
            self.budget.rejections += 1
            raise
        except (aiohttp.ClientError, TimeoutError):
            self.budget.failures += 1
            raise

    def get(self, url, **kwargs):
        return self.request('GET', url, **kwargs)
