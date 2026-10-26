"""Owned live HTTP resources for current access-policy acceptance."""

import asyncio
import base64
from contextlib import asynccontextmanager
import json
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from aiohttp import web

from src.core.pipeline import run_pipeline
from src.core.transport import ScanBudget, scan_transport
from src.risk.risk_assessor import RiskAssessment
from src.security import access_control_tests as producer
from src.security.security_engine import SecurityTestEngine


MARKER = 'access-provenance-fixture-record-942817'
ISSUED = 'issued-access-fixture-key-571824'
REFERENCE = 'ACCESS_PROVENANCE_FIXTURE_KEY'
METHODS = {'authentication_bypass': '_test_authentication_bypass',
           'weak_credentials': '_test_weak_credentials', 'weak_api_key': '_test_api_key_security',
           'authorization_bypass': '_test_authorization_bypass'}


@asynccontextmanager
async def access_target(mode='protected', *, issued=ISSUED):
    state = SimpleNamespace(mode=mode, issued=issued, calls=[], entered=asyncio.Event(), release=asyncio.Event())

    def denied(kind):
        if kind == 'header-leak':
            return web.Response(status=403, text='Denied', headers={'X-Protected-Record': MARKER})
        escaped = ''.join('\\u%04x' % ord(character) for character in MARKER)
        if kind in {'utf16', 'utf32', 'invalid-utf8', 'nul-body'}:
            raw = ('Denied'.encode(kind) if kind in {'utf16', 'utf32'}
                   else b'Denied\xff' if kind == 'invalid-utf8' else b'Denied\x00')
            return web.Response(status=403, body=raw)
        bodies = {'leak': MARKER, 'upper-leak': MARKER.upper(), 'json-leak': '"' + escaped + '"',
                  'json-bom-leak': '\ufeff{"error":"' + escaped + '"}',
                  'json-bom-valid': '\ufeff{"error":"Denied"}',
                  'json-inner-bom': ' \ufeff{"error":"Denied"}',
                  'json-nul': '{"error":"\\u0000"}',
                  'json-malformed': '{"message":', 'json-deep': '[' * 17 + '0' + ']' * 17,
                  'json-wide': '[' + ','.join('0' for _ in range(8192)) + ']',
                  'json-duplicate': '{"message":"' + escaped + '","message":"Denied"}',
                  'json-nonfinite': '{"message":NaN}',
                  'json-boundary-depth': '[' * 16 + '0' + ']' * 16,
                  'json-boundary-nodes': '[' + ','.join('0' for _ in range(8191)) + ']'}
        return web.Response(status=403, text=bodies.get(kind, 'Denied'))

    async def handler(request):
        headers = dict(request.headers)
        state.calls.append((request.path, headers))
        authorization = next((value for key, value in headers.items()
                              if key.casefold() in {'authorization', 'x-api-key', 'x-goog-api-key'}), '')
        if state.mode == 'stall' and len(state.calls) == 3:
            state.entered.set()
            await state.release.wait()
        if 'scanner-invalid-' in authorization:
            return denied(state.mode.removeprefix('denial-') if state.mode.startswith('denial-') else '')
        if state.mode == 'reflection':
            return web.Response(text=json.dumps(headers))
        if state.mode == 'credential':
            return (web.Response(text=MARKER) if headers.get('X-Extra-Issued-Key') == state.issued
                    else web.Response(status=403))
        if authorization in {'Bearer ' + state.issued, state.issued,
                             'Basic ' + base64.b64encode(state.issued.encode()).decode()}:
            return web.Response(text='Unseeded' if state.mode == 'unseeded' else MARKER)
        if state.mode == 'vulnerable' or state.mode == 'partial' and len(state.calls) == 3:
            return web.Response(text=MARKER)
        if state.mode == 'partial':
            return web.Response(status=503, text='Unavailable')
        return denied(state.mode.removeprefix('probe-') if state.mode.startswith('probe-') else '')

    app = web.Application()
    app.router.add_route('*', '/{path:.*}', handler)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, '127.0.0.1', 0)
    await site.start()
    port = site._server.sockets[0].getsockname()[1]
    agent = dict(id='fixture', name='Fixture', type='assistant', metadata={},
                 provider='openai-compatible', model='fixture-model',
                 endpoint=f'http://127.0.0.1:{port}/resource', authentication_required=True,
                 api_key_env=REFERENCE, protected_response_marker=MARKER,
                 protected_path_markers={'/admin': MARKER}, evidence_context_id='access-fixture-v3')
    try:
        with patch.dict('os.environ', {REFERENCE: issued}), patch.object(producer, 'asyncio', SimpleNamespace(
                sleep=AsyncMock(), CancelledError=asyncio.CancelledError)):
            yield agent, state
    finally:
        state.release.set()
        await runner.cleanup()


async def current_access_report(*, rule='authentication_bypass', mode='protected', checkpoint_callback=None):
    """Generate fresh genuine v3 zero, high, or partial reports without a DB."""
    if rule not in METHODS or mode not in {'protected', 'vulnerable', 'partial'}:
        raise ValueError('Unsupported live access fixture')
    async with access_target(mode) as (agent, _):
        if mode == 'partial' and rule == 'authorization_bypass':
            agent['protected_path_markers']['/admin/'] = MARKER
        engine = SecurityTestEngine()
        engine.prompt_tester.test_agent = AsyncMock(return_value=[])
        engine.privacy_tester.test_agent = AsyncMock(return_value=[])
        engine.access_tester.test_agent = getattr(engine.access_tester, METHODS[rule])
        with scan_transport(ScanBudget(allow_loopback=True, allowed_networks=('127.0.0.1/32',), max_requests=100)):
            return await run_pipeline(None, engine, RiskAssessment(), None, 'security_only',
                                      agents=[agent], checkpoint_callback=checkpoint_callback)
