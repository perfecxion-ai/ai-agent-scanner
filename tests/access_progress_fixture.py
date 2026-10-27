"""Owned real HTTP resources for protected-access observation retention."""

import asyncio
import base64
from contextlib import asynccontextmanager
import json
import secrets
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from aiohttp import web

from src.core.access_probe_policy import PROTECTED_ACCESS_PATHS
from src.security import access_control_tests as producer


REFERENCE = 'ACCESS_PROGRESS_FIXTURE_ISSUED_KEY'
METHODS = {
    'authentication_bypass': '_test_authentication_bypass',
    'weak_credentials': '_test_weak_credentials',
    'weak_api_key': '_test_api_key_security',
    'authorization_bypass': '_test_authorization_bypass',
}


@asynccontextmanager
async def access_progress_target(mode='vulnerable', *, issued=None):
    state = SimpleNamespace(mode=mode, marker=secrets.token_hex(24), issued=issued or secrets.token_hex(24),
                            generated=secrets.token_hex(24), calls=[], responses=[],
                            entered=asyncio.Event(), release=asyncio.Event(), pacing=AsyncMock())

    async def handler(request):
        headers = dict(request.headers)
        credential = next((value for key, value in headers.items()
                           if key.casefold() in {'authorization', 'x-api-key', 'x-goog-api-key', 'api-key', 'apikey'}), '')
        ordinal = len(state.calls) + 1
        state.calls.append({'ordinal': ordinal, 'path': request.path, 'headers': headers})
        if mode == 'leak-stall' and ordinal == 4:
            state.entered.set()
            await state.release.wait()
        authorized = credential in (state.issued, 'Bearer ' + state.issued,
                                    'Basic ' + base64.b64encode(state.issued.encode()).decode())
        invalid = 'scanner-invalid-' in credential
        status, text = 403, 'Denied'
        response_headers = {}
        if authorized:
            status = 503 if mode == 'authorized-error' else 200
            text = 'No seeded record' if mode == 'unseeded' else state.marker
        elif invalid:
            status = 200 if mode == 'denied-success' else 403
            text = state.marker if mode == 'denied-leak' else 'Denied'
        elif mode == 'reflection':
            status, text = 200, json.dumps(headers)
        elif mode == 'hidden-credential':
            status, text = (200, state.marker) if headers.get('X-Extra-Issued-Key') == state.issued else (403, 'Denied')
        elif mode == 'probe-error' or mode == 'leak-error' and ordinal > 3:
            status, text = 503, state.marker
        elif mode == 'probe-denial-leak':
            status, text = 403, state.marker
        elif mode == 'probe-header-leak':
            response_headers['X-Protected-Record'] = state.marker
        elif mode in {'vulnerable', 'leak-stall', 'leak-error'}:
            status, text = 200, state.marker
        if status == 200 and text == state.marker:
            text += '\n' + state.generated
            response_headers['X-Private-Reference'] = REFERENCE
        state.responses.append((ordinal, status))
        return web.Response(status=status, text=text, headers=response_headers)

    application = web.Application()
    application.router.add_route('*', '/{path:.*}', handler)
    runner = web.AppRunner(application)
    await runner.setup()
    site = web.TCPSite(runner, '127.0.0.1', 0)
    await site.start()
    port = site._server.sockets[0].getsockname()[1]
    agent = {'id': 'owned-access-progress', 'name': 'Owned access progress fixture', 'type': 'assistant',
             'provider': 'openai-compatible', 'model': 'fixture-model', 'metadata': {},
             'endpoint': f'http://127.0.0.1:{port}/resource', 'authentication_required': True,
             'api_key_env': REFERENCE, 'protected_response_marker': state.marker,
             'protected_path_markers': {path: state.marker for path in PROTECTED_ACCESS_PATHS},
             'evidence_context_id': 'owned-access-progress-v1'}
    try:
        with patch.dict('os.environ', {REFERENCE: state.issued}), patch.object(
                producer, 'asyncio', SimpleNamespace(sleep=state.pacing, CancelledError=asyncio.CancelledError)):
            yield agent, state
    finally:
        state.release.set()
        await runner.cleanup()
