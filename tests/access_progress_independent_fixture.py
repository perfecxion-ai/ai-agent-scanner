"""Owned trusted TLS resources for independent access receipt boundaries."""

import asyncio
import base64
from contextlib import ExitStack, contextmanager
from http.server import BaseHTTPRequestHandler
import json
import os
from pathlib import Path
import ssl
import tempfile
import threading
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch
from urllib.parse import quote

from src.security.security_engine import SecurityTestEngine
from tests.tenant_progress_fixture import NumericServer, _certificate, trusted_tenant_tls


MARKER = 'independent-progress-access-record-c91f537b8420e6ad'
ISSUED = 'independent-progress-access-issued-key-a24e6197d50b83fc'
REFERENCE = 'INDEPENDENT_ACCESS_PROGRESS_ISSUED_KEY'
PROFILE_OVERRIDE = '/tmp/aiscan-operator-registry-must-not-exist.json'
WORKER_SIGNING_KEY = 'owned-access-worker-signing-' * 4
WORKER_OPERATOR_KEY = 'owned-access-worker-operator-key'
METHODS = {
    'authentication_bypass': '_test_authentication_bypass',
    'weak_credentials': '_test_weak_credentials',
    'weak_api_key': '_test_api_key_security',
    'authorization_bypass': '_test_authorization_bypass',
}


def selected_access_engine(rule):
    """Keep the actual family wrapper and engine, isolating unrelated checks."""
    engine = SecurityTestEngine()
    engine.prompt_tester.test_agent = AsyncMock(return_value=[])
    engine.privacy_tester.test_agent = AsyncMock(return_value=[])
    for method in (*METHODS.values(), '_test_unauthenticated_inference',
                   '_test_rate_limiting', '_test_session_management'):
        if method != METHODS[rule]:
            setattr(engine.access_tester, method, AsyncMock(return_value=[]))
    return engine


def privacy_values(state, *, extra=()):
    values = {MARKER, ISSUED, REFERENCE, *extra}
    values.update(call['credential'] for call in state.calls
                  if call['credential'].startswith('scanner-invalid-'))
    variants = set()
    for value in values:
        raw = value.encode()
        variants.update((value, quote(value, safe=''), json.dumps(value)[1:-1],
                         base64.b64encode(raw).decode(), base64.urlsafe_b64encode(raw).decode(),
                         base64.urlsafe_b64encode(raw).decode().rstrip('='),
                         ''.join('%%%02X' % byte for byte in raw)))
    return variants


@contextmanager
def access_progress_target(rule, mode='deadline', *, tls=True):
    """Leak one actual record, then optionally hold the next request open."""
    state = SimpleNamespace(calls=[], blocked=threading.Event(), release=threading.Event(), errors=[])

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_GET(self):
            ordinal = len(state.calls) + 1
            credential = next((value.removeprefix('Bearer ') for name, value in self.headers.items()
                               if name.casefold() in {'authorization', 'x-api-key', 'x-goog-api-key'}), '')
            body = self.rfile.read(int(self.headers.get('Content-Length', '0')))
            state.calls.append({'ordinal': ordinal, 'method': self.command, 'path': self.path,
                                'headers': dict(self.headers), 'body': body.decode(), 'credential': credential,
                                'tls': self.connection.version() if tls else None})
            if (mode in {'deadline', 'cancel', 'kill'} and ordinal == 4
                    or mode == 'denied_stall' and ordinal == 2):
                state.blocked.set()
                if not state.release.wait(30):
                    state.errors.append('Owned access fixture exceeded its hold bound')
            status, text = 403, 'Denied'
            if mode == 'later_503' and ordinal > 3:
                status, text = 503, 'Unavailable'
            elif credential == ISSUED:
                status, text = 200, MARKER
            elif mode == 'denied_leak' and ordinal == 2:
                text = MARKER
            elif mode not in {'protected', 'denied_stall', 'denied_leak'} and ordinal == 3:
                status, text = 200, MARKER + ' ' + ' '.join(sorted(privacy_values(state)))
            raw = text.encode()
            try:
                self.send_response(status)
                self.send_header('Content-Type', 'text/plain; charset=utf-8')
                self.send_header('Content-Length', str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)
            except (BrokenPipeError, ConnectionResetError, ssl.SSLError):
                pass

    with tempfile.TemporaryDirectory(prefix='owned-access-progress-') as raw, ExitStack() as stack:
        directory = Path(raw).resolve(strict=True)
        directory.chmod(0o700)
        server = NumericServer(('127.0.0.1', 0), Handler)
        if tls:
            context, ca_file = _certificate(directory)
            server.socket = context.wrap_socket(server.socket, server_side=True)
            stack.enter_context(trusted_tenant_tls(ca_file))
        thread = threading.Thread(target=server.serve_forever, kwargs={'poll_interval': 0.01}, daemon=True)
        thread.start()
        state.directory = directory
        endpoint = ('https' if tls else 'http') + '://127.0.0.1:' + str(server.server_port) + '/resource'
        agent = {'id': 'independent-access-progress', 'name': 'Independent access progress fixture',
                 'type': 'assistant', 'provider': 'ollama', 'model': 'independent-access-model',
                 'endpoint': endpoint, 'api_key_env': REFERENCE, 'authentication_required': True,
                 'protected_response_marker': MARKER, 'discovery_method': 'owned-fixture', 'metadata': {},
                 'evidence_context_id': 'independent-access-progress-v1'}
        if rule == 'authorization_bypass':
            agent['protected_path_markers'] = {'/admin': MARKER}
            if mode in {'later_503', 'deadline', 'cancel', 'kill'}:
                agent['protected_path_markers']['/admin/'] = MARKER
        stack.enter_context(patch.dict(os.environ, {REFERENCE: ISSUED,
                                                   'SCAN_EVIDENCE_PROFILES_FILE': PROFILE_OVERRIDE}))
        stack.enter_context(patch('src.security.access_control_tests.asyncio', SimpleNamespace(
            sleep=AsyncMock(), CancelledError=asyncio.CancelledError)))
        try:
            yield agent, state
        finally:
            state.release.set()
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)
            if thread.is_alive():
                raise RuntimeError('Owned access progress fixture did not stop')


def access_checkpoint_worker(database, agent, acknowledgement, log_path, rule):
    """Run an actual owned dispatcher until the parent kills its blocked worker."""
    from datetime import datetime, timezone
    from sqlalchemy import MetaData, create_engine
    from src.core.jobs import JobDispatcher, JobStore, current_claim_owner
    from src.core.pipeline import run_pipeline
    from src.core.transport import ScanBudget, scan_transport
    from src.risk.risk_assessor import RiskAssessment

    os.umask(0o077)
    os.environ.clear()
    os.environ.update({REFERENCE: ISSUED, 'DATABASE_URL': 'sqlite:///:memory:',
                       'SECRET_KEY': WORKER_SIGNING_KEY,
                       'OPERATOR_API_KEY': WORKER_OPERATOR_KEY, 'OPERATOR_ORGANIZATION_ID': 'tenant-a'})
    descriptor = os.open(log_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    os.dup2(descriptor, 1)
    os.dup2(descriptor, 2)
    os.close(descriptor)
    import app as server
    _snapshot_rows = server._snapshot_rows
    assert not server._evidence_profiles._profiles

    engine = create_engine('sqlite:///' + database)
    metadata = MetaData()
    metadata.reflect(bind=engine)
    store = JobStore(engine, metadata.tables['scan_job'], metadata.tables['scan_session'],
                     metadata.tables['scan_result'], metadata.tables['audit_event'])

    def run(scan_id, cancelled):
        acknowledged = False
        observed_at = datetime.now(timezone.utc)

        async def persist(report):
            nonlocal acknowledged
            report['scan_id'] = scan_id
            accepted = store.save_checkpoint(
                scan_id, report, metadata.tables['discovered_agent'],
                _snapshot_rows(scan_id, report, observed_at), owner=current_claim_owner(scan_id))
            if not accepted:
                raise RuntimeError('Owned access checkpoint rejected')
            if report['agents'][0].get('check_evidence') and not acknowledged:
                assert report['summary']['checks_unfinished'] == 1
                assert not any(check['rule_id'] == rule for check in report['agents'][0]['checks'])
                acknowledged = True
                asset = report['agents'][0]
                acknowledgement.send(('committed', report['checkpoint']['sequence'],
                                      asset['check_evidence'][0]['id'], asset['vulnerabilities'][0]['id']))

        with patch('src.security.access_control_tests.asyncio', SimpleNamespace(
                sleep=AsyncMock(), CancelledError=asyncio.CancelledError)), scan_transport(ScanBudget(
                    allowed_networks=('127.0.0.1/32',), allow_loopback=True, max_requests=80,
                    max_response_bytes=16384, request_timeout_seconds=20)):
            asyncio.run(run_pipeline(None, selected_access_engine(rule), RiskAssessment(), None,
                                     'security_only', agents=[agent], checkpoint_callback=persist))

    dispatcher = JobDispatcher(store, run, workers=1, poll_seconds=0.01)
    dispatcher.start()
    asyncio.run(asyncio.Event().wait())
