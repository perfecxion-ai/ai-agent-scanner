#!/usr/bin/env python3
"""Exercise the guided CLI on owned HTTP/HTTPS fixtures without model services.

Only a shared timeout is accepted. Profiles, credentials, TLS trust, listeners,
reports and checkpoint files belong to this invocation and are removed afterward.
The receipt describes finite synthetic workflow checks, not detection sensitivity.
"""

import argparse
import base64
from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import ipaddress
import json
import math
import os
from pathlib import Path
import secrets
import signal
from socketserver import TCPServer
import ssl
import stat
import subprocess
import sys
import tempfile
import threading
import time
from urllib.parse import quote


ROOT = Path(__file__).resolve().parents[1]
FORMAT_VERSION = 'http-assessment-acceptance-v1'
OBJECTIVE = 'protected-prompt-disclosure-v1'
CANARY_REFERENCE = 'AIS_HTTP_ACCEPTANCE_CANARY'
KEY_REFERENCE = 'AIS_HTTP_ACCEPTANCE_BEARER'
MAX_CAPTURE_BYTES = 1024 * 1024
DRIVER_SHA256 = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
REQUIRED_ASSERTIONS = (
    'private_environment_profiles_and_owned_http_https_fixtures',
    'actual_wizard_and_zero_network_plan_without_operator_inputs',
    'exact_http_post_and_thirty_five_supported_disclosure_observations',
    'trusted_https_bearer_defended_sample_remains_inconclusive',
    'https_partial_confirmation_and_negative_output_controls',
    'known_request_canary_collision_refused_before_network',
    'fresh_sessions_without_cookie_history_or_unrelated_requests',
    'sigkill_after_acknowledged_receipt_preserves_bound_partial_evidence',
    'offline_json_sarif_recovery_without_profile_secrets_or_replay',
    'known_value_privacy_and_private_output_permissions',
    'all_child_processes_reaped_and_owned_fixtures_removed',
)

# The wrapper changes no scanner functions. Audit hooks make accidental I/O fail
# during the actual CLI entry point, including actual socket construction.
OFFLINE_ENTRY = r'''
import os, runpy, sys
mode, profile, forbidden_output = sys.argv[1:4]
protected = {'AIS_HTTP_ACCEPTANCE_CANARY', 'AIS_HTTP_ACCEPTANCE_BEARER',
             'OPENAI_API_KEY', 'ANTHROPIC_API_KEY', 'GEMINI_API_KEY',
             'SCAN_EVIDENCE_PROFILES_FILE', 'DATABASE_URL', 'OPERATOR_API_KEY'}
forbidden_paths = {os.path.abspath(forbidden_output)}
if mode == 'recover':
    forbidden_paths.add(os.path.abspath(profile))
def audit(event, args):
    if event in {'socket.__new__', 'socket.connect', 'socket.getaddrinfo',
                 'socket.gethostbyname', 'sqlite3.connect', 'subprocess.Popen'}:
        raise RuntimeError('Owned offline guard refused I/O')
    if event == 'open' and isinstance(args[0], (str, bytes, os.PathLike)):
        if os.path.abspath(os.fsdecode(args[0])) in forbidden_paths:
            raise RuntimeError('Owned offline guard refused configuration access')
    if event == 'import' and args[0] == 'app':
        raise RuntimeError('Owned offline guard refused server import')
sys.addaudithook(audit)
original = os._Environ.__getitem__
def guarded(environment, key):
    if key in protected and (mode not in {'init', 'plan'} or key not in {
            'AIS_HTTP_ACCEPTANCE_CANARY', 'AIS_HTTP_ACCEPTANCE_BEARER'}):
        raise RuntimeError('Owned offline guard refused unrelated environment access')
    return original(environment, key)
os._Environ.__getitem__ = guarded
sys.argv = ['scanner_cli', *sys.argv[4:]]
runpy.run_module('scanner_cli', run_name='__main__')
'''


class GateFailure(RuntimeError):
    """Only fixed public codes escape the fixture."""


def require(condition, code):
    if not condition:
        raise GateFailure(code)


def private_write(path, content):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, 'wb') as stream:
        stream.write(content if isinstance(content, bytes) else content.encode())


def variants(values):
    found = set()
    for value in values:
        raw = value.encode()
        found.update((value, quote(value, safe=''), json.dumps(value)[1:-1], raw.hex(),
                      base64.b64encode(raw).decode(), base64.urlsafe_b64encode(raw).decode(),
                      base64.urlsafe_b64encode(raw).decode().rstrip('=')))
    return found


def privacy_check(content, values):
    require(not any(value in content for value in variants(values)), 'known_private_value_in_output')


def certificate(directory):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'owned-http-assessment-fixture')])
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime(2020, 1, 1, tzinfo=timezone.utc))
            .not_valid_after(datetime(2040, 1, 1, tzinfo=timezone.utc))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address('127.0.0.1'))]),
                           critical=False)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .sign(key, hashes.SHA256()))
    key_file, ca_file = directory / 'fixture-key.pem', directory / 'fixture-ca.pem'
    private_write(key_file, key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                            serialization.NoEncryption()))
    private_write(ca_file, cert.public_bytes(serialization.Encoding.PEM))
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(ca_file, key_file)
    return context, ca_file


class NumericServer(ThreadingHTTPServer):
    daemon_threads = True
    block_on_close = False

    def __init__(self, *args, **kwargs):
        self.handler_threads, self.connections = [], []
        super().__init__(*args, **kwargs)

    def server_bind(self):
        TCPServer.server_bind(self)
        self.server_name, self.server_port = self.socket.getsockname()[:2]

    def get_request(self):
        connection, address = super().get_request()
        connection.settimeout(2)
        self.connections.append(connection)
        return connection, address

    def process_request(self, request, address):
        worker = threading.Thread(target=self.process_request_thread, args=(request, address), daemon=True)
        self.handler_threads.append(worker)
        worker.start()


def stop_server(server, worker):
    failures = []
    if worker is not None and worker.ident is not None:
        stopper = threading.Thread(target=server.shutdown, daemon=True)
        stopper.start()
        stopper.join(timeout=5)
        if stopper.is_alive():
            failures.append('owned_fixture_shutdown_stalled')
    server.server_close()
    for connection in server.connections:
        try:
            connection.shutdown(2)
        except OSError:
            pass
        connection.close()
    for handler in server.handler_threads:
        if handler.ident is not None:
            handler.join(timeout=3)
            if handler.is_alive():
                failures.append('owned_fixture_handler_survived')
    if worker is not None and worker.ident is not None:
        worker.join(timeout=5)
        if worker.is_alive():
            failures.append('owned_fixture_thread_survived')
    require(not failures, failures[0] if failures else 'owned_fixture_cleanup_failed')


@contextmanager
def targets(directory, marker, cookie):
    calls, failures = {}, []
    blocked, release = threading.Event(), threading.Event()

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_GET(self):
            failures.append('unexpected_get')
            self.send_error(405)

        def do_POST(self):
            size = self.headers.get('Content-Length', '')
            if not size.isascii() or not size.isdigit() or not 0 < int(size) <= 65536:
                failures.append('invalid_request_size')
                self.send_error(400)
                return
            try:
                body = json.loads(self.rfile.read(int(size)))
            except (ValueError, UnicodeError):
                failures.append('invalid_request_json')
                self.send_error(400)
                return
            pieces = self.path.split('/')
            if len(pieces) != 4 or pieces[1] != 'custom' or pieces[3] != 'infer':
                failures.append('rewritten_request_path')
                self.send_error(404)
                return
            mode = pieces[2]
            record = {'method': self.command, 'path': self.path, 'body': body,
                      'authorization': self.headers.get('Authorization'), 'cookie': self.headers.get('Cookie'),
                      'user_agent': self.headers.get('User-Agent'), 'accept': self.headers.get('Accept'),
                      'tls': self.connection.version() if isinstance(self.connection, ssl.SSLSocket) else None}
            current = calls.setdefault(mode, [])
            current.append(record)
            if mode == 'crash' and len(current) == 2:
                blocked.set()
                if not release.wait(90):
                    failures.append('fixture_stall_expired')
            status = 403 if mode == 'denied' else 200
            text = marker if mode in {'leak', 'https-leak', 'crash'} else 'No protected information returned'
            response = {'answer': {'text': text}}
            if mode == 'off-pointer':
                response['metadata'] = {'canary': marker}
                response['response'] = marker
            raw = (b'{"answer":{"text":"No disclosure","text":' + json.dumps(marker).encode() + b'}}'
                   if mode == 'duplicate' else json.dumps(response).encode())
            try:
                self.send_response(status)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Content-Length', str(len(raw)))
                self.send_header('Set-Cookie', 'owned_session=' + cookie + '; HttpOnly; Path=/')
                self.end_headers()
                self.wfile.write(raw)
            except (BrokenPipeError, ConnectionResetError, ssl.SSLError):
                pass

    context, ca_file = certificate(directory)
    servers, workers = [], []
    try:
        for secure in (False, True):
            server = NumericServer(('127.0.0.1', 0), Handler)
            servers.append(server)
            workers.append(None)
            if secure:
                server.socket = context.wrap_socket(server.socket, server_side=True, do_handshake_on_connect=False)
            worker = threading.Thread(target=server.serve_forever, kwargs={'poll_interval': 0.02}, daemon=True)
            workers[-1] = worker
            worker.start()
        yield {'http': 'http://127.0.0.1:' + str(servers[0].server_port),
               'https': 'https://127.0.0.1:' + str(servers[1].server_port),
               'ca_file': ca_file, 'calls': calls, 'failures': failures, 'blocked': blocked, 'release': release}
    finally:
        release.set()
        cleanup_failures = []
        for server, worker in zip(servers, workers):
            try:
                stop_server(server, worker)
            except Exception:
                cleanup_failures.append('owned_fixture_cleanup_failed')
        require(not cleanup_failures, 'owned_fixture_cleanup_failed')


class Commands:
    def __init__(self, directory, deadline, environment):
        self.directory, self.deadline, self.environment = directory, deadline, environment
        self.processes, self.exits, self.outputs = [], {}, []
        self.drains = {}

    def remaining(self):
        value = self.deadline - time.monotonic()
        require(value > 0, 'overall_timeout')
        return value

    def check_capture(self, process):
        state = self.drains[process.pid]
        require(not state['oversized'], 'child_output_limit')
        require(not state['failed'], 'child_output_capture_failed')

    def wait(self, process):
        end = time.monotonic() + min(self.remaining(), 95)
        while process.poll() is None:
            self.check_capture(process)
            require(time.monotonic() < end, 'child_deadline')
            time.sleep(0.02)
        self.check_capture(process)

    @contextmanager
    def child(self, label, args, *, offline=None, input_text=None, environment=None):
        output = self.directory / (label + '.log')
        optimize = ['-' + 'O' * sys.flags.optimize] if sys.flags.optimize else []
        prefix = ([sys.executable, *optimize, '-Werror', '-c', OFFLINE_ENTRY, offline[0], str(offline[1]),
                   str(self.directory / 'forbidden-registry.json')] if offline else
                  [sys.executable, *optimize, '-Werror', '-m', 'scanner_cli'])
        with output.open('xb') as stream:
            output.chmod(0o600)
            process = subprocess.Popen(prefix + list(args), cwd=ROOT,
                                       env=environment or self.environment, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                       stdin=subprocess.PIPE if input_text is not None else subprocess.DEVNULL,
                                       start_new_session=True, umask=0o077)
            self.processes.append(process)
            state = {'oversized': False, 'failed': False}
            self.drains[process.pid] = state
            def drain():
                total = 0
                try:
                    while chunk := process.stdout.read(65536):
                        allowance = max(0, MAX_CAPTURE_BYTES - total)
                        if allowance:
                            stream.write(chunk[:allowance])
                        total += len(chunk)
                        state['oversized'] |= total > MAX_CAPTURE_BYTES
                except (OSError, ValueError):
                    state['failed'] = True
            reader = threading.Thread(target=drain, daemon=True)
            reader.start()
            try:
                if input_text is not None:
                    process.stdin.write(input_text.encode())
                    process.stdin.close()
                yield process, output
            finally:
                if process.stdin is not None and not process.stdin.closed:
                    process.stdin.close()
                if process.poll() is None:
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                process.wait(timeout=5)
                self.exits[label] = process.returncode
                survived = False
                try:
                    os.killpg(process.pid, 0)
                except ProcessLookupError:
                    pass
                else:
                    survived = True
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                reader.join(timeout=5)
                process.stdout.close()
                require(not reader.is_alive(), 'child_output_reader_survived')
                stream.flush()
                require(not survived, 'child_process_group_survived')
                require(output.stat().st_size <= MAX_CAPTURE_BYTES, 'child_output_limit')
                self.outputs.append(output.read_text())
                self.check_capture(process)

    def call(self, label, args, *, expected=None, **kwargs):
        with self.child(label, args, **kwargs) as (process, output):
            self.wait(process)
        if expected is not None:
            require(process.returncode == expected, 'unexpected_' + label + '_exit')
        return process.returncode, output.read_text()


def descriptor(endpoint, *, authenticated=False):
    return {'adapter_id': 'http-json', 'adapter_version': '1.0', 'endpoint': endpoint,
            'method': 'POST', 'request_prompt_field': 'question', 'response_text_pointer': '/answer/text',
            'auth_scheme': 'bearer' if authenticated else 'none',
            'principal_label': 'owned-authorized-principal-v1' if authenticated else 'anonymous',
            'context_label': 'owned-http-acceptance-v1', 'session_mode': 'fresh-per-prompt-v1'}


def profile(directory, name, endpoint, *, authenticated=False):
    path = directory / (name + '.target.json')
    value = {'schema_version': '1.0', 'name': 'Owned HTTP application',
             'http_target': descriptor(endpoint, authenticated=authenticated),
             'allowed_networks': ['127.0.0.1/32'], 'credential_env': KEY_REFERENCE if authenticated else None,
             'canary_env': CANARY_REFERENCE, 'canary_seeded': True}
    private_write(path, json.dumps(value))
    return path


def assessment_args(selected, output, *, maximum=35, checkpoint=None):
    args = ['assess', '--profile', str(selected), '--output', str(output), '--allow-loopback',
            '--max-requests', str(maximum), '--timeout-seconds', '90', '--request-timeout-seconds', '60',
            '--max-response-bytes', '65536']
    if checkpoint is not None:
        args.extend(['--checkpoint-dir', str(checkpoint)])
    return args


def report_checks(document, *, score, completed, count=None):
    require(document.get('assessment_objective') == OBJECTIVE, 'missing_report_objective')
    require(len(document.get('agents', [])) == 1, 'unexpected_report_asset_count')
    agent = document['agents'][0]
    require(agent.get('provider') == 'http-json' and agent.get('model') is None,
            'invented_model_or_provider')
    require(agent.get('assessment_objective') == OBJECTIVE and agent.get('assessment_contract_version') == '1.0',
            'missing_asset_objective')
    require(agent.get('risk_score') == score and document['summary']['overall_risk_score'] == score,
            'unexpected_canonical_score')
    require(agent.get('risk_level') == ('high' if score == 70 else 'unknown'), 'unexpected_risk_level')
    require(document.get('status') == ('completed' if completed else 'partial'), 'unexpected_scan_status')
    require(agent.get('check_evidence_schema_version') == document.get('check_evidence_schema_version') == '3.0',
            'unexpected_ledger_version')
    expected = {'prompt_injection.' + category for category in (
        'instruction_bypass', 'system_prompt_extraction', 'role_manipulation', 'dan_jailbreak',
        'context_manipulation', 'payload_injection', 'injection_via_encoding')}
    checks, receipts = agent.get('checks', []), agent.get('check_evidence', [])
    require({check['rule_id'] for check in checks} | {r['rule_id'] for r in receipts} == expected,
            'objective_rule_coverage_mismatch')
    require(len({check['rule_id'] for check in checks}) == len(checks), 'duplicate_objective_check')
    require(not any(check.get('outcome') == 'passed' for check in checks), 'prompt_nondisclosure_passed')
    if completed:
        require(len(checks) == 7 and all(check['status'] == 'completed'
                and check['requests_attempted'] == check['responses_evaluated'] == 5
                and check['outcome'] == ('confirmed' if score == 70 else 'inconclusive') for check in checks),
                'incomplete_full_prompt_sample')
        if score == 70:
            for rule in expected:
                group = [receipt for receipt in receipts if receipt['rule_id'] == rule]
                require([receipt['sample_index'] for receipt in group] == list(range(5))
                        and [receipt['sequence'] for receipt in group] == list(range(1, 6))
                        and all(receipt['requests_attempted'] == receipt['responses_evaluated'] == number
                                for number, receipt in enumerate(group, 1)), 'invalid_full_sample_accounting')
    binding = agent.get('http_target_binding')
    require(isinstance(binding, str) and len(binding) == 64 and agent['id'] == binding,
            'missing_public_target_binding')
    require(agent.get('evidence_context_id') == 'http-json-v1:' + binding, 'missing_bound_context')
    security = document.get('security_results', [])
    require(len(security) == 1 and all(security[0].get(key) == agent.get(key) for key in (
        'http_target', 'http_target_binding', 'evidence_context_id', 'assessment_objective',
        'assessment_contract_version', 'provider', 'model', 'check_evidence')), 'public_views_disagree')
    require(all(receipt.get('source_version') == '3.0' and receipt.get('http_target_binding') == binding
                for receipt in receipts), 'unbound_or_legacy_http_receipt')
    require(len(receipts) == len(agent.get('vulnerabilities', [])), 'finding_receipt_link_count')
    if count is not None:
        require(len(receipts) == count, 'unexpected_confirmed_receipt_count')
    try:
        from src.core.contracts import validate_check_evidence, validate_scan_result
        from src.core.risk_projection import project_report_risk
        validate_scan_result(document)
        validate_check_evidence(agent)
        summary, projected = project_report_risk(document)
        require(summary['overall_risk_score'] == projected[agent['id']]['risk_score'] == score,
                'unsupported_canonical_evidence')
    except (ValueError, TypeError, KeyError):
        raise GateFailure('invalid_report_evidence') from None
    return agent


def execute(directory, deadline, output, private_values):
    sys.path.insert(0, str(ROOT))
    from src.core.build_identity import current_identity, saved_identity
    from src.core.prompt_catalog import candidate_payloads

    expected_identity = current_identity(component='cli')
    require(saved_identity(expected_identity) == expected_identity
            and expected_identity['source']['status'] == 'available', 'source_identity_unavailable')
    marker, key, cookie = (secrets.token_hex(24) for _ in range(3))
    private_values.update({marker, key, cookie, CANARY_REFERENCE, KEY_REFERENCE})
    environment = {'PATH': os.defpath, 'HOME': str(directory), 'TMPDIR': str(directory),
                   'XDG_CONFIG_HOME': str(directory), 'XDG_CACHE_HOME': str(directory),
                   'PYTHONIOENCODING': 'utf-8', 'PYTHONUNBUFFERED': '1',
                   'SCAN_EVIDENCE_PROFILES_FILE': str(directory / 'absent-registry.json'),
                   CANARY_REFERENCE: marker, KEY_REFERENCE: key}
    commands = Commands(directory, deadline, environment)
    output['command_exits'] = commands.exits
    reports = []
    with targets(directory, marker, cookie) as fixture:
        environment['SSL_CERT_FILE'] = str(fixture['ca_file'])
        output['assertions'].append(REQUIRED_ASSERTIONS[0])
        selected = directory / 'wizard.target.json'
        endpoint = fixture['http'] + '/custom/leak/infer'
        wizard = '\n'.join([endpoint, '', '', '/answer/text', '', CANARY_REFERENCE,
                             'owned-http-acceptance-v1', 'y']) + '\n'
        commands.call('wizard', ['target', 'init', 'owned-target', '--output', str(selected)],
                      offline=('init', selected), input_text=wizard, expected=0)
        _, plan_text = commands.call('plan', ['assess', '--profile', str(selected), '--plan', '--allow-loopback'],
                                     offline=('plan', selected), expected=0)
        plan = json.loads(plan_text)
        require(not fixture['calls'], 'offline_setup_contacted_target')
        require(isinstance(plan, dict), 'invalid_plan_shape')
        output['assertions'].append(REQUIRED_ASSERTIONS[1])
        positive_file = directory / 'positive.json'
        commands.call('http-leak', assessment_args(selected, positive_file), expected=0)
        positive = json.loads(positive_file.read_text())
        report_checks(positive, score=70, completed=True, count=35)
        require(positive.get('producer_identity') == expected_identity, 'executed_source_identity_mismatch')
        reports.append(positive_file)
        require(len(fixture['calls'].get('leak', [])) == 35, 'positive_prompt_attempt_count')
        output['assertions'].append(REQUIRED_ASSERTIONS[2])
        defended = profile(directory, 'defended', fixture['https'] + '/custom/defended/infer', authenticated=True)
        defended_file = directory / 'defended.json'
        commands.call('https-defended', assessment_args(defended, defended_file), expected=0)
        report_checks(json.loads(defended_file.read_text()), score=None, completed=True, count=0)
        reports.append(defended_file)
        require(len(fixture['calls'].get('defended', [])) == 35, 'defended_prompt_attempt_count')
        output['assertions'].append(REQUIRED_ASSERTIONS[3])
        for mode, score in [('https-leak', 70), ('absent', None), ('denied', None),
                            ('off-pointer', None), ('duplicate', None)]:
            selected_case = profile(directory, mode, fixture['https'] + '/custom/' + mode + '/infer',
                                    authenticated=True)
            report_file = directory / (mode + '.json')
            code, _ = commands.call(mode, assessment_args(selected_case, report_file, maximum=1))
            require(code != 0, 'incomplete_sample_exit_zero')
            report_checks(json.loads(report_file.read_text()), score=score, completed=False,
                          count=1 if score == 70 else 0)
            require(len(fixture['calls'].get(mode, [])) == 1, 'single_sample_attempt_count')
            reports.append(report_file)
        output['assertions'].append(REQUIRED_ASSERTIONS[4])
        collision = profile(directory, 'collision', fixture['https'] + '/custom/collision/infer', authenticated=True)
        collision_env = dict(environment, **{KEY_REFERENCE: marker})
        code, _ = commands.call('collision', assessment_args(collision, directory / 'collision.json', maximum=1),
                                environment=collision_env)
        require(code != 0 and not fixture['calls'].get('collision') and not (directory / 'collision.json').exists(),
                'request_collision_not_refused')
        output['assertions'].append(REQUIRED_ASSERTIONS[5])
        crash = profile(directory, 'crash', fixture['http'] + '/custom/crash/infer')
        checkpoint = directory / 'checkpoints'
        original = None
        with commands.child('crash', assessment_args(crash, directory / 'unused.json', checkpoint=checkpoint)) as (
                process, _):
            while commands.remaining() > 0 and process.poll() is None:
                commands.check_capture(process)
                latest = checkpoint / 'latest.json'
                if fixture['blocked'].is_set() and latest.is_file():
                    original = latest.read_bytes()
                    envelope = json.loads(original)
                    if envelope.get('report', {}).get('agents', [{}])[0].get('check_evidence'):
                        break
                time.sleep(0.02)
            require(original is not None and fixture['blocked'].is_set(), 'missing_acknowledged_stalled_receipt')
            report_checks(envelope['report'], score=70, completed=False, count=1)
            require(envelope['report']['checkpoint']['version'] == '4.0', 'unexpected_checkpoint_version')
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                raise GateFailure('cli_exited_before_sigkill') from None
            require(process.wait(timeout=5) == -signal.SIGKILL, 'kill_did_not_stop_cli')
        output['assertions'].append(REQUIRED_ASSERTIONS[7])
        call_count = sum(map(len, fixture['calls'].values()))
        for fmt in ('json', 'sarif'):
            recovered = directory / ('recovered.' + fmt)
            commands.call('recover-' + fmt, ['recover', '--checkpoint-dir', str(checkpoint), '--output',
                                            str(recovered), '--format', fmt], offline=('recover', crash), expected=1)
            value = json.loads(recovered.read_text())
            if fmt == 'json':
                agent = report_checks(value, score=70, completed=False, count=1)
                require(agent['check_evidence'] == envelope['report']['agents'][0]['check_evidence'],
                        'recovery_changed_acknowledged_receipt')
            else:
                require(value['runs'][0]['invocations'][0]['executionSuccessful'] is False
                        and len(value['runs'][0]['results']) == 1, 'invalid_incomplete_sarif')
            require((checkpoint / 'latest.json').read_bytes() == original, 'recovery_changed_checkpoint')
            reports.append(recovered)
        require(sum(map(len, fixture['calls'].values())) == call_count, 'offline_recovery_replayed_target')
        output['assertions'].append(REQUIRED_ASSERTIONS[8])
        require(not fixture['failures'], 'fixture_recorded_unexpected_request')
        for mode, calls in fixture['calls'].items():
            for call in calls:
                require(call['method'] == 'POST' and call['path'] == '/custom/' + mode + '/infer'
                        and isinstance(call['body'], dict) and set(call['body']) == {'question'}
                        and isinstance(call['body']['question'], str) and not call['cookie'],
                        'unexpected_route_body_or_session_state')
                require(call['authorization'] == (None if mode in {'leak', 'crash'} else 'Bearer ' + key),
                        'unexpected_credential_or_default_key')
                if mode not in {'leak', 'crash'}:
                    require(call['tls'] in {'TLSv1.2', 'TLSv1.3'}, 'missing_verified_https_transport')
        prompts = [payload for payloads in candidate_payloads().values() for payload in payloads]
        require(len(prompts) == 35 and all([call['body']['question'] for call in fixture['calls'][mode]] == prompts
                for mode in ('leak', 'defended')), 'wire_prompt_sequence_mismatch')
        output['assertions'].insert(6, REQUIRED_ASSERTIONS[6])
        output['request_counts'] = {name: len(calls) for name, calls in sorted(fixture['calls'].items())}
        for path in reports:
            require(stat.S_IMODE(path.stat().st_mode) == 0o600 and path.stat().st_nlink == 1,
                    'public_output_permissions_changed')
        for path in checkpoint.iterdir():
            require(stat.S_IMODE(path.stat().st_mode) == 0o600, 'checkpoint_permissions_changed')
        require(stat.S_IMODE(checkpoint.stat().st_mode) == 0o700, 'checkpoint_directory_permissions_changed')
        public = '\n'.join([*commands.outputs, *(path.read_text() for path in reports),
                            *(path.read_text() for path in checkpoint.iterdir())])
        privacy_check(public, {marker, key, cookie, CANARY_REFERENCE, KEY_REFERENCE,
                               *(str(path) for path in directory.glob('*.target.json'))})
        output['privacy'] = {'required_values_checked': 5, 'profile_paths_checked': len(list(
            directory.glob('*.target.json'))), 'scope': 'known_values_and_encoded_forms_only'}
        output['assertions'].append(REQUIRED_ASSERTIONS[9])
        output['runtime'] = {'python': sys.version.split()[0],
                             'optimization': sys.flags.optimize, 'cli_child_optimization': sys.flags.optimize,
                             'driver_sha256': DRIVER_SHA256,
                             'producer_identity': positive.get('producer_identity')}
        require(hashlib.sha256(Path(__file__).read_bytes()).hexdigest() == DRIVER_SHA256, 'driver_source_changed')


def timeout_value(raw):
    value = float(raw)
    if not math.isfinite(value) or not 15 <= value <= 600:
        raise argparse.ArgumentTypeError('Expected finite timeout from 15 to 600 seconds')
    return value


class SafeParser(argparse.ArgumentParser):
    def error(self, message):
        raise GateFailure('invalid_arguments')


def main(argv=None):
    parser = SafeParser(prog='acceptance-http-assessment.py', description=__doc__)
    parser.add_argument('--timeout-seconds', type=timeout_value, default=240)
    output = {'format_version': FORMAT_VERSION, 'accepted': False,
              'fixture_scope': 'owned_synthetic_http_https_cli_workflow', 'assertions': []}
    started = time.monotonic()
    previous, timer = {}, None
    temporary = directory = None
    failures = []
    private_values = set()
    try:
        args = parser.parse_args(argv)
        require(os.name == 'posix', 'posix_required')
        require('app' not in sys.modules, 'cached_server_not_allowed')
        require(signal.getitimer(signal.ITIMER_REAL) == (0.0, 0.0), 'preexisting_timer_not_allowed')
        temporary = tempfile.TemporaryDirectory(prefix='ai-scanner-http-acceptance-')
        directory = Path(temporary.name).resolve(strict=True)
        directory.chmod(0o700)
        def interrupt(number, frame):
            raise GateFailure('overall_timeout' if number == signal.SIGALRM else 'driver_interrupted')
        for number in (signal.SIGALRM, signal.SIGTERM, signal.SIGINT):
            previous[number] = signal.signal(number, interrupt)
        timer = signal.setitimer(signal.ITIMER_REAL, args.timeout_seconds)
        execute(directory, started + args.timeout_seconds, output, private_values)
    except (Exception, KeyboardInterrupt) as error:
        failures.append(str(error) if isinstance(error, GateFailure) else 'unexpected_driver_failure')
    finally:
        if timer is not None:
            signal.setitimer(signal.ITIMER_REAL, 0)
        for number, handler in previous.items():
            signal.signal(number, handler)
        if temporary is not None:
            try:
                private_values.update(str(path) for path in directory.glob('*.target.json'))
                surfaces = [path for path in directory.rglob('*') if path.is_file() and (
                    path.suffix == '.log' or path.suffix == '.json' and not path.name.endswith('.target.json')
                    or path.parent.name == 'checkpoints')]
                for path in surfaces:
                    require(path.stat().st_size <= MAX_CAPTURE_BYTES, 'public_capture_size_limit')
                    privacy_check(path.read_text(), private_values)
            except Exception:
                failures.append('known_private_value_or_unreadable_public_capture')
            try:
                temporary.cleanup()
                require(not directory.exists(), 'fixture_cleanup_failed')
                if not failures:
                    output['assertions'].append(REQUIRED_ASSERTIONS[10])
            except Exception:
                failures.append('fixture_cleanup_failed')
    if not failures and output['assertions'] != list(REQUIRED_ASSERTIONS):
        failures.append('missing_required_assertions')
    output['accepted'] = not failures
    output['elapsed_seconds'] = round(time.monotonic() - started, 3)
    if failures:
        output['failure_codes'] = list(dict.fromkeys(failures))
    rendered = json.dumps(output, sort_keys=True)
    try:
        privacy_check(rendered, private_values)
    except GateFailure:
        output = {'format_version': FORMAT_VERSION, 'accepted': False, 'assertions': [],
                  'failure_codes': ['known_private_value_in_receipt']}
        rendered = json.dumps(output, sort_keys=True)
    print(rendered)
    return 0 if output['accepted'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
