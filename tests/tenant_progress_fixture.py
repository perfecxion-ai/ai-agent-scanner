"""Owned HTTPS controls for genuine tenant observations and interruption tests."""

import asyncio
import base64
from contextlib import ExitStack, asynccontextmanager, contextmanager
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import ipaddress
import json
from pathlib import Path
from socketserver import TCPServer
import ssl
import tempfile
import threading
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch
from urllib.parse import quote

import aiohttp
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from src.core.contracts import TenantObservation
from src.core.tenant_probe_policy import TENANT_CONTROL_PROMPT, tenant_target
from src.core.transport import SafeSession
from src.security import data_privacy_tests
from src.security.security_engine import SecurityTestEngine


OWNER_KEY = 'synthetic-progress-owner-key-f8c13750'
TESTED_KEY = 'synthetic-progress-tested-key-b9e24651'
OWNER_MARKER = 'synthetic-owner-record-c8e24651'
TESTED_MARKER = 'synthetic-tested-record-d9f35762'
REFERENCES = {'TENANT_PROGRESS_OWNER_KEY': OWNER_KEY, 'TENANT_PROGRESS_TESTED_KEY': TESTED_KEY,
              'TENANT_PROGRESS_OWNER_CANARY': OWNER_MARKER, 'TENANT_PROGRESS_TESTED_CANARY': TESTED_MARKER}
LABELS = ('progress-owner-tenant', 'progress-owner-principal',
          'progress-tested-tenant', 'progress-tested-principal')


def privacy_values(state):
    """Include actual generated invalid keys and known encoded representations."""
    values = set(state.raw_privacy_values)
    values.update(call['key'] for call in state.calls if call['key'])
    variants = set(values)
    for value in values:
        variants.update((quote(value, safe=''), json.dumps(value)[1:-1],
                         base64.b64encode(value.encode()).decode(),
                         base64.urlsafe_b64encode(value.encode()).decode().rstrip('=')))
    return tuple(sorted(variants))


class NumericServer(ThreadingHTTPServer):
    daemon_threads = False

    def server_bind(self):
        TCPServer.server_bind(self)
        self.server_name, self.server_port = self.socket.getsockname()[:2]


def _certificate(directory):
    # This deterministic test key is public fixture material, never a deployment key.
    key = ec.derive_private_key(137, ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'synthetic-tenant-progress-fixture')])
    certificate = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
                   .public_key(key.public_key()).serial_number(137)
                   .not_valid_before(datetime(2020, 1, 1, tzinfo=timezone.utc))
                   .not_valid_after(datetime(2040, 1, 1, tzinfo=timezone.utc))
                   .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
                   .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address('127.0.0.1'))]),
                                  critical=False)
                   .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
                   .sign(key, hashes.SHA256()))
    key_path, ca_file = directory / 'fixture-key.pem', directory / 'fixture-ca.pem'
    key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                          serialization.NoEncryption()))
    key_path.chmod(0o600)
    ca_file.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    ca_file.chmod(0o600)
    server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_context.load_cert_chain(ca_file, key_path)
    return server_context, ca_file


@contextmanager
def trusted_tenant_tls(ca_file):
    """Trust only the fixture CA while retaining certificate and host verification."""
    context = ssl.create_default_context(cafile=str(ca_file))
    assert context.check_hostname and context.verify_mode == ssl.CERT_REQUIRED
    original = aiohttp.TCPConnector
    def connector(*args, **kwargs):
        kwargs['ssl'] = context
        return original(*args, **kwargs)
    with patch.object(aiohttp, 'TCPConnector', connector):
        yield


def _agent(endpoint):
    item = {'id': 'tenant-progress-asset', 'name': 'Tenant progress fixture', 'type': 'assistant',
            'provider': 'ollama', 'model': 'fixture-model', 'endpoint': endpoint,
            'api_key_env': 'TENANT_PROGRESS_TESTED_KEY', 'evidence_context_id': 'tenant-progress-fixture-v1',
            'discovery_method': 'fixture', 'metadata': {}}
    item['tenant_evidence'] = {
        'schema_version': '1.0', 'tested_principal_authorized_for_owner': False,
        'binding': tenant_target(endpoint, item['provider'], item['model'], item['evidence_context_id']),
        'owner': {'tenant_ref': LABELS[0], 'principal_ref': LABELS[1],
                  'api_key_env': 'TENANT_PROGRESS_OWNER_KEY', 'canary_env': 'TENANT_PROGRESS_OWNER_CANARY'},
        'tested': {'tenant_ref': LABELS[2], 'principal_ref': LABELS[3],
                   'api_key_env': 'TENANT_PROGRESS_TESTED_KEY', 'canary_env': 'TENANT_PROGRESS_TESTED_CANARY'}}
    return item


@contextmanager
def tenant_progress_target(mode='subject'):
    """Run one private HTTPS fixture with controls, a leak, and a bounded next stage."""
    if mode not in {'subject', 'attack', 'subject_cleanup', 'attack_cleanup', 'later_failure', 'later_taint'}:
        raise ValueError('Unknown owned tenant fixture mode')
    state = SimpleNamespace(mode=mode, calls=[], stall=threading.Event(), ready=threading.Event(),
                            release=threading.Event(), cleanup_failures=0, response_open=None,
                            raw_privacy_values=tuple(REFERENCES.values()) + tuple(REFERENCES) + LABELS)
    state.privacy_values = privacy_values(state)
    state.private_values = state.privacy_values
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_POST(self):
            size = int(self.headers.get('Content-Length', '0'))
            if self.path != '/api/chat' or not 0 < size <= 8192:
                self.send_error(400)
                return
            body = json.loads(self.rfile.read(size))
            prompt = body['messages'][0]['content']
            key = self.headers.get('Authorization', '').removeprefix('Bearer ')
            ordinal = len(state.calls) + 1
            state.calls.append({'ordinal': ordinal, 'key': key, 'prompt': prompt,
                                'reflection': self.headers.get('X-Synthetic-Reflection')})
            if ordinal == (4 if mode == 'subject' else 5 if mode == 'attack' else None):
                state.stall.set()
                state.release.wait(10)
            status = 200
            if key == OWNER_KEY and prompt == TENANT_CONTROL_PROMPT:
                text = OWNER_MARKER
            elif key == TESTED_KEY and prompt == TENANT_CONTROL_PROMPT:
                text = TESTED_MARKER + (' ' + OWNER_MARKER if mode.startswith('subject') else '')
            elif key != TESTED_KEY:
                status, text = 403, 'Denied'
            elif mode == 'later_failure' and ordinal > 4:
                status, text = 503, 'Unavailable'
            else:
                text = OWNER_MARKER if ordinal == 4 else 'No foreign record disclosed'
            raw = json.dumps({'message': {'content': text}}).encode()
            try:
                self.send_response(status)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Content-Length', str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)
            except (BrokenPipeError, ConnectionResetError, ssl.SSLError):
                pass

    with tempfile.TemporaryDirectory(prefix='tenant-progress-tls-') as raw_directory, ExitStack() as stack:
        server_context, state.ca_file = _certificate(Path(raw_directory))
        server = NumericServer(('127.0.0.1', 0), Handler)
        server.socket = server_context.wrap_socket(server.socket, server_side=True)
        worker = threading.Thread(target=server.serve_forever, kwargs={'poll_interval': 0.02}, daemon=True)
        worker.start()
        state.ready.set()
        endpoint = 'https://127.0.0.1:' + str(server.server_port) + '/api/chat'
        state.endpoint = endpoint
        stack.enter_context(trusted_tenant_tls(state.ca_file))
        stack.enter_context(patch.dict('os.environ', REFERENCES))
        stack.enter_context(patch.object(data_privacy_tests, 'asyncio', SimpleNamespace(
            sleep=AsyncMock(), CancelledError=asyncio.CancelledError)))
        if mode.endswith('_cleanup'):
            failure_at = 3 if mode == 'subject_cleanup' else 4
            class CleanupSession(SafeSession):
                @asynccontextmanager
                async def request(self, *args, **kwargs):
                    ordinal = None
                    try:
                        async with super().request(*args, **kwargs) as response:
                            ordinal = len(state.calls)
                            state.response_open = ordinal
                            yield response
                    finally:
                        state.response_open = None
                        if ordinal == failure_at:
                            state.cleanup_failures += 1
                            raise OSError('Synthetic tenant response cleanup failure')
            stack.enter_context(patch.object(data_privacy_tests, 'SafeSession', CleanupSession))
        if mode == 'later_taint':
            original_headers = aiohttp.ClientRequest.update_auto_headers
            request_count = 0
            def automatic_header(request, skip):
                nonlocal request_count
                original_headers(request, skip)
                request_count += 1
                if request_count == 5:
                    request.headers['X-Synthetic-Reflection'] = OWNER_MARKER
            stack.enter_context(patch.object(aiohttp.ClientRequest, 'update_auto_headers', automatic_header))
        try:
            yield _agent(endpoint), state
        finally:
            state.release.set()
            server.shutdown()
            server.server_close()
            worker.join(timeout=5)
            if worker.is_alive():
                raise RuntimeError('Owned tenant TLS fixture did not stop')


def unfinished_tenant_engine(after_response=None):
    """Run the real tenant producer and engine, isolating unrelated tester families."""
    engine = SecurityTestEngine()
    engine.prompt_tester.test_agent = AsyncMock(return_value=[])
    engine.access_tester.test_agent = AsyncMock(return_value=[])
    engine.privacy_tester.test_agent = engine.privacy_tester._test_tenant_isolation
    if after_response is not None:
        original = engine.privacy_tester._send_tenant_prompt
        acknowledged = False
        async def observed(*args, **kwargs):
            nonlocal acknowledged
            result = await original(*args, **kwargs)
            if not acknowledged and isinstance(result, TenantObservation) and result.findings:
                acknowledged = True
                after_response()
            return result
        engine.privacy_tester._send_tenant_prompt = observed
    return engine
