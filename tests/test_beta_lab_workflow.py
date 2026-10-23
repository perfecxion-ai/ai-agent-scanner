"""Real local mixed-network discovery through durable API security assessment."""

from contextlib import ExitStack, contextmanager
from copy import deepcopy
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import importlib
import ipaddress
import json
import socket
import socketserver
import sys
import threading
import time
from types import SimpleNamespace

import pytest
from sqlalchemy import create_engine


MODEL = 'explicitly-selected-fixture-model'
PRIVATE_OUTPUT = 'synthetic-private-record-4f03c1 123-45-6789 4111111111111111'


class NumericHTTPServer(ThreadingHTTPServer):
    def server_bind(self):
        # Fixture addresses are numeric loopback literals, so no reverse DNS is needed.
        socketserver.TCPServer.server_bind(self)
        self.server_name, self.server_port = self.server_address[:2]


@contextmanager
def running_server(server):
    worker = threading.Thread(target=server.serve_forever, kwargs={'poll_interval': 0.02}, daemon=True)
    worker.start()
    try:
        yield server.server_address[1]
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=2)
        assert not worker.is_alive()


@pytest.fixture
def real_lab(monkeypatch, tmp_path):
    calls = []
    banner_connections = []

    class AIService(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def respond(self, status, document, content_type='application/json'):
            content = (json.dumps(document) if isinstance(document, dict) else document).encode()
            self.send_response(status)
            self.send_header('Content-Type', content_type)
            self.send_header('Content-Length', str(len(content)))
            self.send_header('Connection', 'close')
            self.end_headers()
            self.wfile.write(content)

        def do_GET(self):
            calls.append(('GET', self.path, None))
            if self.path == '/v1/models':
                self.respond(200, {'object': 'list', 'data': [
                    {'id': 'advertised-model-not-selected', 'object': 'model', 'created': 1,
                     'owned_by': 'synthetic-fixture'}]})
            elif self.path == '/api/tags':
                self.respond(200, {'error': 'Optional native protocol is unsupported'})
            elif self.path == '/info':
                self.respond(200, '<html>Ordinary non-AI landing page</html>', 'text/html')
            else:
                self.respond(401, {'error': 'Credentials required for this route'})

        def do_POST(self):
            body = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
            calls.append(('POST', self.path, body))
            if self.path != '/v1/chat/completions':
                self.respond(404, {'error': 'Unknown route'})
                return
            if body.get('model') != MODEL:
                self.respond(400, {'error': 'Explicitly select the fixture model'})
                return
            self.respond(200, {'choices': [{'message': {
                'content': 'I cannot disclose protected instructions. ' + PRIVATE_OUTPUT}}]})

    class UnavailableService(AIService):
        def do_GET(self):
            calls.append(('503', self.path, None))
            self.respond(503, {'error': 'Synthetic service is temporarily unavailable'})

    class Banner(socketserver.BaseRequestHandler):
        def handle(self):
            banner_connections.append(self.client_address)
            try:
                self.request.sendall(b'Ordinary non-HTTP fixture banner\r\n')
            except OSError:
                pass

    class BannerServer(socketserver.ThreadingTCPServer):
        daemon_threads = True

    operator_key = 'synthetic-local-beta-operator-key'
    monkeypatch.delenv('SCAN_EVIDENCE_PROFILES_FILE', raising=False)
    monkeypatch.setenv('SECRET_KEY', 'synthetic-local-beta-signing-key-' * 2)
    monkeypatch.setenv('OPERATOR_API_KEY', operator_key)
    monkeypatch.setenv('DATABASE_URL', 'sqlite:///:memory:')
    module = sys.modules.get('app') or importlib.import_module('app')
    assert module._job_dispatcher is None, 'Never replace an existing dispatcher'
    monkeypatch.setattr(module, '_evidence_profiles', module.load_evidence_profiles(None))
    monkeypatch.setattr(module, '_job_dispatcher', None)
    for key, value in {
        'TESTING': True, 'SECRET_KEY': 'synthetic-local-beta-signing-key-' * 2,
        'OPERATOR_API_KEY': operator_key, 'OPERATOR_ORGANIZATION_ID': 'local-beta-operator',
        'SCAN_ALLOWED_NETWORKS': ('127.0.0.1/32',), 'SCAN_ALLOW_LOOPBACK': True,
        'SCAN_ALLOWED_PATH_ROOTS': (), 'MAX_CONCURRENT_SCANS': 1,
        'SCAN_TIMEOUT_SECONDS': 15, 'SCAN_REQUEST_TIMEOUT_SECONDS': 2,
        'SCAN_MAX_REQUESTS': 150,
    }.items():
        monkeypatch.setitem(module.app.config, key, value)

    # Keep actual transport/event-loop sleeps. Only security pacing is shortened.
    async def no_pacing(seconds):
        return None

    for name in ('prompt_injection_tests', 'access_control_tests', 'data_privacy_tests'):
        tester_module = importlib.import_module('src.security.' + name)
        monkeypatch.setattr(tester_module, 'asyncio', SimpleNamespace(sleep=no_pacing))
    monkeypatch.setattr(module.security_engine.prompt_tester, 'injection_payloads', {
        category: module.security_engine.prompt_tester.injection_payloads[category][:5]
        for category in ('system_prompt_extraction', 'instruction_bypass')
    })
    monkeypatch.setattr(module.security_engine.access_tester, 'rate_limit_requests', 1)
    monkeypatch.setattr(module.security_engine.privacy_tester, 'pii_extraction_prompts', ['Provide sample data'])
    monkeypatch.setattr(module.security_engine.privacy_tester, 'compliance_test_prompts', ['Describe privacy'])

    with ExitStack() as stack:
        ai_port = stack.enter_context(running_server(NumericHTTPServer(('127.0.0.1', 0), AIService)))
        banner_port = stack.enter_context(running_server(BannerServer(('127.0.0.1', 0), Banner)))
        unavailable_port = stack.enter_context(running_server(
            NumericHTTPServer(('127.0.0.1', 0), UnavailableService)))
        scanner = module.discovery_engine.network_scanner
        monkeypatch.setattr(scanner, 'common_ai_ports', [ai_port, banner_port])
        monkeypatch.setattr(scanner, 'timeout', 2)

        # A policy regression must not let this test contact non-loopback systems.
        original_socket = socket.socket

        class LoopbackSocket(original_socket):
            def connect(self, address):
                if self.family in (socket.AF_INET, socket.AF_INET6):
                    assert ipaddress.ip_address(address[0]).is_loopback
                return super().connect(address)

            def connect_ex(self, address):
                if self.family in (socket.AF_INET, socket.AF_INET6):
                    assert ipaddress.ip_address(address[0]).is_loopback
                return super().connect_ex(address)

        monkeypatch.setattr(socket, 'socket', LoopbackSocket)
        database = tmp_path.resolve() / 'beta-lab.sqlite'
        with module.app.app_context():
            previous = module.db.engine
            # Inspect only. Do not connect to, dispose, or reuse a foreign engine.
            assert previous.dialect.name == 'sqlite' and previous.url.database == ':memory:'
            assert not previous.url.query and not database.exists()
            module.db.session.remove()
            engine = create_engine('sqlite:///' + str(database))
            assert engine.url.database == str(database) and not engine.url.query
            module.db.engines[None] = engine
            dispatcher = None
            try:
                dispatcher = module.start_job_dispatcher()
                assert dispatcher.ready and database.is_file()
                yield module, module.app.test_client(), operator_key, calls, banner_connections, unavailable_port
            finally:
                try:
                    if dispatcher:
                        dispatcher.stop(timeout=3)
                        assert not dispatcher._thread.is_alive()
                        assert all(future.done() for future, _ in dispatcher._active.values())
                        assert dispatcher._ownership.handle is None
                finally:
                    module.db.session.remove()
                    module.db.engines[None] = previous
                    engine.dispose()


def test_real_mixed_discovery_partial_source_model_selection_and_private_reports(real_lab):
    module, client, operator_key, calls, banner_connections, unavailable_port = real_lab
    login = client.post('/api/auth/token', json={'api_key': operator_key})
    assert login.status_code == 200
    headers = {'Authorization': 'Bearer ' + login.json['token']}

    def request(method, path, expected=200, body=None):
        module.db.session.remove()
        response = client.open(path, method=method, headers=headers, json=body)
        assert response.status_code == expected, response.json
        return response.json

    def run(definition):
        identifier = request('POST', '/api/scans', 202, definition)['scan_id']
        deadline = time.monotonic() + 12
        while time.monotonic() < deadline:
            status = request('GET', f'/api/scans/{identifier}/status')
            if status['status'] in module.TERMINAL_STATES:
                assert status['status'] not in {'failed', 'interrupted', 'cancelled'}, status
                return identifier, request('GET', f'/api/scans/{identifier}/report?format=json')
            time.sleep(0.02)
        pytest.fail('Actual local API scan did not finish within its bounded deadline')

    discovery = {'scan_name': 'Synthetic mixed local services', 'scan_type': 'discovery_only',
                 'target_scope': {'network_ranges': ['127.0.0.1/32']}, 'scan_config': {}}
    _, complete = run(discovery)
    assert complete['status'] == 'completed' and complete['transport_incomplete'] is False
    assert len(complete['agents']) == 1 and banner_connections
    assert any(method == 'GET' and path == '/api/tags' for method, path, _ in calls)
    assert any(method == 'GET' and path == '/info' for method, path, _ in calls)
    assert not any(method == 'POST' for method, _, _ in calls)

    # A real503 remains a genuine coverage failure, while saved AI assets survive.
    module.discovery_engine.network_scanner.common_ai_ports.append(unavailable_port)
    source_id, source = run(discovery)
    assert source['status'] == 'partial' and source['transport_incomplete'] is True
    assert len(source['agents']) == 1 and source['agents'][0].get('model') is None
    assert source['agents'][0]['provider'] == 'openai-compatible'
    original_source = deepcopy(source)
    source_results = request('GET', f'/api/scans/{source_id}/results')['results']
    saved = source_results['agents']
    assert len(saved) == 1 and saved[0]['id'] != saved[0]['asset_id']
    assert saved[0]['asset_id'] == source['agents'][0]['id']
    assert source_results['summary']['overall_risk_score'] is None
    assert saved[0]['risk_score'] is None and saved[0]['risk_level'] == 'unknown'

    scan_id, assessed = run({
        'scan_name': 'Actual model requests from partial discovery', 'scan_type': 'security_only',
        'target_scope': {}, 'scan_config': {'source_scan_id': source_id,
                                         'model_overrides': {saved[0]['id']: MODEL}},
    })
    posts = [(path, body) for method, path, body in calls if method == 'POST']
    assert posts and all(path == '/v1/chat/completions' and body['model'] == MODEL for path, body in posts)
    assert assessed['summary']['checks_completed'] > 0
    assert assessed['summary']['checks_failed'] == 0
    assert assessed['summary']['agents_tested'] == 1
    assert assessed['source_inventory']['scan_id'] == source_id
    assert assessed['source_inventory']['status'] == 'partial'
    assert assessed['source_inventory']['coverage_complete'] is False
    assert assessed['source_inventory']['warning']
    agent = assessed['agents'][0]
    assert agent['id'] == source['agents'][0]['id']
    assert agent['model'] == MODEL and agent['risk_score'] is None and agent['risk_level'] == 'unknown'
    assert not agent['vulnerabilities']
    assert any(item['vulnerability_type'] == 'unauthenticated_inference' for item in agent['observations'])
    assert not any(check['outcome'] in {'passed', 'confirmed'} for check in agent['checks'])
    assert any(check['rule_id'].startswith('prompt_injection.') and check['outcome'] == 'inconclusive'
               and check['responses_evaluated'] > 0 for check in agent['checks'])
    assert assessed['summary']['overall_risk_score'] is None
    assert assessed['risk_assessment_status'] == 'not_assessed'
    assert request('GET', f'/api/scans/{source_id}/report?format=json') == original_source
    public_results = request('GET', f'/api/scans/{scan_id}/results')['results']
    persisted = public_results['pipeline']
    assert persisted == assessed
    assert public_results['summary']['overall_risk_score'] is None
    assert public_results['summary']['risk_assessment_status'] == 'not_assessed'
    public_agent = public_results['agents'][0]
    assert public_agent['risk_score'] is None and public_agent['risk_level'] == 'unknown'
    listed = request('GET', '/api/agents')['agents']
    listed_agent = next(item for item in listed if item['id'] == public_agent['id'])
    assert listed_agent['risk_score'] is None and listed_agent['risk_level'] == 'unknown'
    assert listed_agent['risk_coverage_status'] == 'not_assessed'
    sarif = request('GET', f'/api/scans/{scan_id}/report?format=sarif')
    assert sarif['runs'][0]['properties']['source_inventory'] == assessed['source_inventory']
    assert sarif['runs'][0]['invocations'][0]['executionSuccessful'] is False
    assert sarif['runs'][0]['results'] == []
    audit = request('GET', f'/api/scans/{scan_id}/audit')['events']
    assert [event['event'] for event in audit] == ['admitted', 'claimed', 'terminal']
    serialized = json.dumps([complete, source, assessed, persisted, public_results, listed, sarif, audit])
    for secret in (operator_key, login.json['token'], 'synthetic-private-record-4f03c1',
                   '123-45-6789', '4111111111111111'):
        assert secret not in serialized
