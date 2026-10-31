"""Public connector ownership, failure isolation and cancellation."""

import asyncio
from contextlib import asynccontextmanager
from types import SimpleNamespace

import aiohttp
import pytest

from src.core.transport import _OwnedSSLConnector, TransportPolicyError


ORIGINAL_CLOSE = aiohttp.TCPConnector.close


class Transport:
    def __init__(self, name, events, *, ssl=True, closing=False, abort_fails=False, probe_fails=False):
        self.name, self.events = name, events
        self.ssl, self.closing = ssl, closing
        self.abort_fails, self.probe_fails = abort_fails, probe_fails

    def get_extra_info(self, name):
        assert name == 'sslcontext'
        if self.probe_fails:
            raise OSError('synthetic-private-probe')
        return object() if self.ssl else None

    def is_closing(self):
        return self.closing

    def abort(self):
        self.events.append('abort-' + self.name)
        if self.abort_fails:
            raise OSError('synthetic-private-abort')
        self.closing = True


def connection(transport, events):
    return SimpleNamespace(transport=transport,
        close=lambda: events.append('connection-close-' + transport.name))


@asynccontextmanager
async def owned(limit=2):
    connector = _OwnedSSLConnector(ownership_limit=limit, enable_cleanup_closed=False)
    try:
        yield connector
    finally:
        await ORIGINAL_CLOSE(connector)


def connect_sequence(monkeypatch, connections):
    sequence = iter(connections)

    async def connect(self, *args, **kwargs):
        return next(sequence)

    monkeypatch.setattr(aiohttp.TCPConnector, 'connect', connect)


@pytest.mark.asyncio
async def test_reused_tls_transport_retained_once_and_plain_transport_unaffected(monkeypatch):
    events = []
    tls, plain = Transport('tls', events), Transport('plain', events, ssl=False)
    first, second = connection(tls, events), connection(plain, events)
    connect_sequence(monkeypatch, [first, first, second])
    async with owned(limit=1) as connector:
        assert await connector.connect(None) is first
        assert await connector.connect(None) is first
        assert await connector.connect(None) is second
        assert events == []
        await connector.close()
    assert events == ['abort-tls']


@pytest.mark.asyncio
async def test_closing_transport_retired_without_exceeding_bound(monkeypatch):
    events = []
    first, second = Transport('first', events), Transport('second', events)
    connect_sequence(monkeypatch, [connection(first, events), connection(second, events)])
    async with owned(limit=1) as connector:
        await connector.connect(None)
        first.closing = True
        await connector.connect(None)
        assert events == ['abort-first']
        await connector.close()
    assert events == ['abort-first', 'abort-second']


@pytest.mark.asyncio
async def test_bound_refuses_and_closes_only_new_connection(monkeypatch):
    events = []
    first, second = Transport('first', events), Transport('second', events)
    connect_sequence(monkeypatch, [connection(first, events), connection(second, events)])
    async with owned(limit=1) as connector:
        await connector.connect(None)
        with pytest.raises(TransportPolicyError, match='^HTTP transport ownership failed$'):
            await connector.connect(None)
        assert events == ['abort-second', 'connection-close-second']
        await connector.close()
    assert events[-1] == 'abort-first'


@pytest.mark.asyncio
async def test_failed_public_transport_probe_closes_connection_privately(monkeypatch):
    events = []
    transport = Transport('new', events, probe_fails=True)
    connect_sequence(monkeypatch, [connection(transport, events)])
    async with owned() as connector:
        with pytest.raises(TransportPolicyError, match='^HTTP transport ownership failed$'):
            await connector.connect(None)
        assert events == ['abort-new', 'connection-close-new']
        await connector.close()


@pytest.mark.asyncio
@pytest.mark.parametrize('abort_fails', [False, True])
@pytest.mark.parametrize('base_fails', [False, True])
async def test_all_owned_transports_and_base_close_attempted_on_failures(
        monkeypatch, caplog, abort_fails, base_fails):
    events = []
    first = Transport('first', events, abort_fails=abort_fails)
    second = Transport('second', events)
    connect_sequence(monkeypatch, [connection(first, events), connection(second, events)])

    async def close(self, *args, **kwargs):
        events.append('base-close')
        if base_fails:
            raise OSError('synthetic-private-base-close')

    monkeypatch.setattr(aiohttp.TCPConnector, 'close', close)
    async with owned() as connector:
        await connector.connect(None)
        await connector.connect(None)
        if abort_fails or base_fails:
            with pytest.raises(TransportPolicyError, match='^HTTP transport cleanup failed$'):
                await connector.close()
            assert 'HTTP transport cleanup failed' in caplog.text
            assert 'synthetic-private' not in caplog.text
        else:
            await connector.close()
        assert events == ['abort-first', 'abort-second', 'base-close']


@pytest.mark.asyncio
async def test_repeated_cancellation_cannot_skip_owned_transport_abort(monkeypatch):
    events, entered = [], asyncio.Event()
    transport = Transport('tls', events)
    connect_sequence(monkeypatch, [connection(transport, events)])

    async def close(self, *args, **kwargs):
        entered.set()
        await asyncio.Event().wait()

    monkeypatch.setattr(aiohttp.TCPConnector, 'close', close)
    async with owned() as connector:
        await connector.connect(None)
        caller = asyncio.create_task(connector.close())
        await entered.wait()
        assert events == ['abort-tls']
        caller.cancel()
        caller.cancel()
        with pytest.raises(asyncio.CancelledError):
            await caller
        assert caller.done() and events == ['abort-tls']
