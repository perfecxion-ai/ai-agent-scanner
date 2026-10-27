"""Owned HTTPS resources and actual CLI children for crash-recovery proofs."""

import base64
from contextlib import ExitStack, contextmanager
from copy import deepcopy
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler
import json
import os
from pathlib import Path
import signal
import ssl
import subprocess
import sys
import threading
import time
from urllib.parse import quote

from src.core.tenant_probe_policy import TENANT_CONTROL_PROMPT, tenant_target
from tests.tenant_progress_fixture import NumericServer, _certificate


ROOT = Path(__file__).resolve().parents[1]
PROFILE_OVERRIDE = '/tmp/aiscan-operator-registry-must-not-exist.json'
SCENARIOS = ('prompt', 'tenant', 'access-high', 'access-critical')
MARKER = 'owned-cli-crash-record-b75e192fc0384da6'
TESTED_MARKER = 'owned-cli-crash-tested-record-c46f280ad1395eb7'
ISSUED = 'owned-cli-crash-issued-key-d39e457bc0286fa1'
TESTED = 'owned-cli-crash-tested-key-e48f536ad1297cb0'
REFERENCE = 'CLI_CRASH_ISSUED_KEY'
TESTED_REFERENCE = 'CLI_CRASH_TESTED_KEY'
OWNER_CANARY_REFERENCE = 'CLI_CRASH_OWNER_CANARY'
TESTED_CANARY_REFERENCE = 'CLI_CRASH_TESTED_CANARY'
LABELS = ('owned-crash-owner-tenant', 'owned-crash-owner-principal',
          'owned-crash-tested-tenant', 'owned-crash-tested-principal')
ENVIRONMENT = {REFERENCE: ISSUED, TESTED_REFERENCE: TESTED,
               OWNER_CANARY_REFERENCE: MARKER, TESTED_CANARY_REFERENCE: TESTED_MARKER}


@dataclass
class CrashCase:
    scenario: str
    directory: Path
    state: object
    config: Path
    checkpoint_dir: Path
    log: Path
    process: subprocess.Popen
    envelope: dict = field(default_factory=dict)
    original_bytes: bytes = b''
    calls_after_kill: int = 0


def _private_write(path, text):
    descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(descriptor, 'w', encoding='utf-8') as stream:
        stream.write(text)


def _environment():
    # No inherited provider keys, proxy configuration, profile paths or database URL.
    return {'PATH': os.defpath, 'PYTHONIOENCODING': 'utf-8', 'PYTHONUNBUFFERED': '1',
            'SCAN_EVIDENCE_PROFILES_FILE': PROFILE_OVERRIDE}


@contextmanager
def _target(directory, scenario):
    from types import SimpleNamespace

    state = SimpleNamespace(calls=[], blocked=threading.Event(), release=threading.Event(),
                            failures=[], get_count=0, post_count=0)

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def _send(self, status, content, *, model=False):
            raw = (json.dumps({'message': {'content': content}}).encode() if model else content.encode())
            try:
                self.send_response(status)
                self.send_header('Content-Type', 'application/json' if model else 'text/plain; charset=utf-8')
                self.send_header('Content-Length', str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)
            except (BrokenPipeError, ConnectionResetError, ssl.SSLError):
                pass

        def _record(self, body):
            state.calls.append({'method': self.command, 'path': self.path, 'body': body,
                                'credential': self.headers.get('Authorization', '').removeprefix('Bearer '),
                                'tls': self.connection.version()})

        def _hold(self):
            state.blocked.set()
            if not state.release.wait(90):
                state.failures.append('Owned CLI fixture hold expired')

        def do_POST(self):
            size = int(self.headers.get('Content-Length', '0'))
            if self.path not in {'/api/chat', '/resource/api/chat'} or not 0 < size <= 16384:
                self.send_error(400)
                return
            body = json.loads(self.rfile.read(size))
            self._record(body)
            state.post_count += 1
            prompt = body['messages'][0]['content']
            credential = state.calls[-1]['credential']
            if scenario == 'prompt':
                if state.post_count == 2:
                    self._hold()
                self._send(200, MARKER, model=True)
            elif scenario == 'tenant' and prompt == TENANT_CONTROL_PROMPT:
                if credential == ISSUED:
                    self._send(200, MARKER, model=True)
                elif credential == TESTED:
                    self._send(200, TESTED_MARKER + ' ' + MARKER, model=True)
                else:
                    self._send(403, 'Denied', model=True)
                    state.controls_complete = True
            elif scenario == 'tenant' and getattr(state, 'controls_complete', False):
                self._hold()
                self._send(200, 'No foreign record returned', model=True)
            elif not credential:
                self._send(403, 'Denied', model=True)
            else:
                self._send(200, 'No protected information returned', model=True)

        def do_GET(self):
            self._record('')
            state.get_count += 1
            if scenario not in {'access-high', 'access-critical'}:
                self._send(403, 'Denied')
                return
            leak_at = 3 if scenario == 'access-high' else 23
            if state.get_count == leak_at + 1:
                self._hold()
            if state.calls[-1]['credential'] == ISSUED or state.get_count == leak_at:
                self._send(200, MARKER)
            else:
                self._send(403, 'Denied')

    context, ca_file = _certificate(directory)
    server = NumericServer(('127.0.0.1', 0), Handler)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, kwargs={'poll_interval': 0.01}, daemon=True)
    thread.start()
    endpoint = ('https://127.0.0.1:' + str(server.server_port)
                + ('/resource' if scenario.startswith('access-') else '/api/chat'))
    agent = {'id': 'owned-cli-crash-' + scenario, 'name': 'Owned CLI crash fixture',
             'type': 'assistant', 'provider': 'ollama', 'model': 'owned-crash-model',
             'endpoint': endpoint, 'evidence_context_id': 'owned-cli-crash-v1', 'metadata': {}}
    if scenario == 'prompt':
        agent['system_prompt_canary'] = MARKER
    elif scenario.startswith('access-'):
        agent.update(api_key_env=REFERENCE, authentication_required=True, protected_response_marker=MARKER)
    else:
        agent['api_key_env'] = TESTED_REFERENCE
        agent['tenant_evidence'] = {
            'schema_version': '1.0', 'tested_principal_authorized_for_owner': False,
            'binding': tenant_target(endpoint, 'ollama', agent['model'], agent['evidence_context_id']),
            'owner': {'tenant_ref': LABELS[0], 'principal_ref': LABELS[1],
                      'api_key_env': REFERENCE, 'canary_env': OWNER_CANARY_REFERENCE},
            'tested': {'tenant_ref': LABELS[2], 'principal_ref': LABELS[3],
                       'api_key_env': TESTED_REFERENCE, 'canary_env': TESTED_CANARY_REFERENCE}}
    try:
        yield agent, state, ca_file
    finally:
        state.release.set()
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
        if thread.is_alive():
            raise RuntimeError('Owned CLI HTTPS fixture did not stop')


def _stop(process):
    if process.poll() is None:
        os.killpg(process.pid, signal.SIGKILL)
    process.wait(timeout=5)


@contextmanager
def killed_cli_cases(directory):
    """Run unmodified CLI processes concurrently, then kill after durable evidence."""
    cases = {}
    with ExitStack() as stack:
        for scenario in SCENARIOS:
            owned = directory / scenario
            owned.mkdir(mode=0o700)
            agent, state, ca_file = stack.enter_context(_target(owned, scenario))
            config, log, checkpoint_dir = owned / 'input.json', owned / 'scan.log', owned / 'checkpoints'
            _private_write(config, json.dumps({'agents': [agent]}))
            environment = {**_environment(), **ENVIRONMENT, 'SSL_CERT_FILE': str(ca_file)}
            with log.open('xb') as stream:
                log.chmod(0o600)
                process = subprocess.Popen(
                    [sys.executable, '-W', 'error', '-m', 'scanner_cli', 'scan', '--config', str(config),
                     '--checkpoint-dir', str(checkpoint_dir), '--output', str(owned / 'unused-report.json'),
                     '--allow-loopback', '--timeout-seconds', '75', '--request-timeout-seconds', '65',
                     '--max-requests', '300', '--max-response-bytes', '16384'],
                    cwd=ROOT, env=environment, stdout=stream, stderr=subprocess.STDOUT,
                    start_new_session=True, umask=0o077)
            stack.callback(_stop, process)
            cases[scenario] = CrashCase(scenario, owned, state, config, checkpoint_dir, log, process)
        deadline = time.monotonic() + 65
        pending = set(cases)
        while pending and time.monotonic() < deadline:
            for scenario in tuple(pending):
                case = cases[scenario]
                if case.process.poll() is not None:
                    raise AssertionError('Owned CLI exited before its durable receipt: ' + scenario)
                try:
                    raw = (case.checkpoint_dir / 'latest.json').read_bytes()
                    envelope = json.loads(raw)
                    receipts = envelope['report']['agents'][0].get('check_evidence', [])
                except (OSError, ValueError, KeyError, IndexError):
                    continue
                if receipts and case.state.blocked.is_set():
                    case.envelope, case.original_bytes = deepcopy(envelope), raw
                    os.kill(case.process.pid, signal.SIGKILL)
                    case.process.wait(timeout=5)
                    if case.process.returncode != -signal.SIGKILL:
                        raise AssertionError('Owned CLI did not terminate by SIGKILL')
                    case.calls_after_kill = len(case.state.calls)
                    pending.remove(scenario)
            time.sleep(0.02)
        if pending:
            raise AssertionError('Owned CLI did not acknowledge and stall: ' + ','.join(sorted(pending)))
        yield cases


OFFLINE_RECOVERY = r'''
import os
import runpy
import sys

forbidden = {os.path.abspath(sys.argv[1]), os.path.abspath(sys.argv[2])}
private_names = {'CLI_CRASH_ISSUED_KEY', 'CLI_CRASH_TESTED_KEY', 'CLI_CRASH_OWNER_CANARY',
                 'CLI_CRASH_TESTED_CANARY', 'SCAN_EVIDENCE_PROFILES_FILE', 'DATABASE_URL',
                 'OPERATOR_API_KEY', 'SECRET_KEY'}

def audit(event, args):
    if event in {'socket.connect', 'socket.connect_ex', 'socket.getaddrinfo', 'socket.gethostbyname',
                 'sqlite3.connect', 'subprocess.Popen'}:
        raise AssertionError('Offline recovery attempted a forbidden action')
    if event == 'open' and isinstance(args[0], (str, bytes, os.PathLike)):
        if os.path.abspath(os.fsdecode(args[0])) in forbidden:
            raise AssertionError('Offline recovery attempted private configuration access')

sys.addaudithook(audit)
original_getitem = os._Environ.__getitem__
def guarded_getitem(environment, key):
    if key in private_names:
        raise AssertionError('Offline recovery attempted private environment resolution')
    return original_getitem(environment, key)
os._Environ.__getitem__ = guarded_getitem
if sys.argv[3:4] == ['--guard-probe']:
    import socket
    import sqlite3
    import subprocess
    actions = {
        'network': lambda: socket.create_connection(('127.0.0.1', 9), timeout=1),
        'dns': lambda: socket.getaddrinfo('localhost', 9),
        'database': lambda: sqlite3.connect(':memory:'),
        'config': lambda: open(sys.argv[1]),
        'registry': lambda: open(sys.argv[2]),
        'environment': lambda: os.environ.get('CLI_CRASH_ISSUED_KEY'),
        'process': lambda: subprocess.run([sys.executable, '-c', 'pass'], check=True),
    }
    try:
        actions[sys.argv[4]]()
    except AssertionError:
        raise SystemExit(0)
    raise SystemExit(9)
sys.argv = ['scanner_cli', *sys.argv[3:]]
runpy.run_module('scanner_cli', run_name='__main__')
'''


def recover_offline(case, fmt):
    output, log = case.directory / ('recovered.' + fmt), case.directory / ('recover-' + fmt + '.log')
    registry = case.directory / 'forbidden-registry.json'
    if not registry.exists():
        _private_write(registry, json.dumps({'protected': MARKER}))
    environment = _environment()
    environment['SCAN_EVIDENCE_PROFILES_FILE'] = str(registry)
    with log.open('xb') as stream:
        log.chmod(0o600)
        completed = subprocess.run(
            [sys.executable, '-W', 'error', '-c', OFFLINE_RECOVERY, str(case.config), str(registry), 'recover',
             '--checkpoint-dir', str(case.checkpoint_dir), '--format', fmt, '--output', str(output)],
            cwd=ROOT, env=environment, stdout=stream, stderr=subprocess.STDOUT, timeout=12,
            start_new_session=True, umask=0o077, check=False)
    return completed, output, log


def private_values(case):
    values = {MARKER, TESTED_MARKER, ISSUED, TESTED, *ENVIRONMENT, *LABELS}
    values.update(call['credential'] for call in case.state.calls
                  if call['credential'].startswith('scanner-invalid-'))
    variants = set()
    for value in values:
        raw = value.encode()
        variants.update((value, quote(value, safe=''), json.dumps(value)[1:-1],
                         base64.b64encode(raw).decode(), base64.urlsafe_b64encode(raw).decode(),
                         base64.urlsafe_b64encode(raw).decode().rstrip('=')))
    return variants
