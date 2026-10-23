"""Owned loopback target for genuine prompt analysis and unfinished-check tests."""

import asyncio
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from socketserver import TCPServer
import threading

from src.security.security_engine import SecurityTestEngine


CANARY = 'synthetic-progress-canary-53c127f8'


class NumericServer(ThreadingHTTPServer):
    def server_bind(self):
        TCPServer.server_bind(self)
        self.server_name, self.server_port = self.socket.getsockname()[:2]


@contextmanager
def disclosure_target():
    calls = []

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            size = int(self.headers.get('Content-Length', '0'))
            if self.path != '/api/chat' or not 0 < size <= 8192:
                self.send_error(400)
                return
            body = json.loads(self.rfile.read(size))
            calls.append(body)
            payload = json.dumps({'message': {'content': CANARY}}).encode()
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, *args):
            pass

    server = NumericServer(('127.0.0.1', 0), Handler)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    try:
        yield {
            'id': 'prompt-progress-asset', 'name': 'Prompt progress fixture',
            'type': 'assistant', 'provider': 'ollama', 'model': 'fixture-model',
            'endpoint': 'http://127.0.0.1:' + str(server.server_port),
            'discovery_method': 'fixture', 'metadata': {},
            'system_prompt_canary': CANARY, 'evidence_context_id': 'prompt-progress-fixture-v1',
        }, calls
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=5)
        if worker.is_alive():
            raise RuntimeError('Owned prompt fixture did not stop')


def unfinished_prompt_engine(after_response=None, *, prompt_suite=None):
    engine = SecurityTestEngine(prompt_suite=prompt_suite)
    original = engine.prompt_tester._test_single_payload

    async def first_response_then_stall(*args, **kwargs):
        # The real adapter, transport, analyzer, receipt publisher and cleanup run.
        # Stall before returning this first finding to its still-running category.
        finding = await original(*args, **kwargs)
        if finding is None or finding.get('evidence_status') != 'confirmed':
            raise AssertionError('Fixture did not produce a real protected disclosure')
        if after_response is not None:
            after_response()
        await asyncio.Event().wait()

    engine.prompt_tester._test_single_payload = first_response_then_stall
    return engine
