"""Owned trusted HTTPS verifies protected GET checks through real CLI exports."""

import asyncio
import base64
from contextlib import contextmanager
from copy import deepcopy
from http.server import BaseHTTPRequestHandler
import json
import ssl
import threading
from types import SimpleNamespace
from unittest.mock import AsyncMock
from urllib.parse import quote

import click
import pytest

import scanner_cli
from src.core.build_identity import saved_identity
from src.core.contracts import risk_assessment_eligible, validate_checkpoint_report
from src.core.risk_projection import project_report_risk
from src.security.security_engine import SecurityTestEngine
from tests.tenant_progress_fixture import NumericServer, _certificate, trusted_tenant_tls


_MARKER = 'synthetic-https-access-record-9f17e36c2b804a5d'
_ISSUED = 'synthetic-https-access-issued-key-b19e357d8c2046fa'
_REFERENCE = 'SYNTHETIC_HTTPS_ACCESS_ISSUED_KEY'
_GROUPS = (
    ('_test_authentication_bypass', 'authentication_bypass', 20, 70, 'high'),
    ('_test_weak_credentials', 'weak_credentials', 7, 90, 'critical'),
    ('_test_api_key_security', 'weak_api_key', 32, 70, 'high'),
    ('_test_authorization_bypass', 'authorization_bypass', 3, 70, 'high'),
)


@contextmanager
def _https_access_target(directory, mode, authorization):
    """Serve real controls, one disclosed record, and optional later failures."""
    directory.mkdir(mode=0o700)
    context, ca_file = _certificate(directory)
    calls = []

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_GET(self):
            ordinal = len(calls) + 1
            credential = self.headers.get('Authorization', '').removeprefix('Bearer ')
            calls.append({'ordinal': ordinal, 'method': self.command, 'path': self.path,
                          'credential': credential, 'tls': self.connection.version()})
            status, text = 403, 'Denied'
            if mode == 'partial' and ordinal > 3:
                status, text = 503, 'Unavailable'
            elif credential == _ISSUED or (mode != 'protected' and ordinal == 3):
                status, text = 200, _MARKER
            raw = text.encode()
            try:
                self.send_response(status)
                self.send_header('Content-Type', 'text/plain; charset=utf-8')
                self.send_header('Content-Length', str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)
            except (BrokenPipeError, ConnectionResetError, ssl.SSLError):
                pass

    server = NumericServer(('127.0.0.1', 0), Handler)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    worker = threading.Thread(target=server.serve_forever, kwargs={'poll_interval': 0.02}, daemon=True)
    worker.start()
    endpoint = 'https://127.0.0.1:' + str(server.server_port) + '/resource'
    agent = {'id': 'access-https-asset', 'name': 'Owned HTTPS access fixture', 'type': 'assistant',
             'provider': 'ollama', 'model': 'owned-access-model', 'endpoint': endpoint,
             'api_key_env': _REFERENCE, 'authentication_required': True,
             'protected_response_marker': _MARKER, 'evidence_context_id': 'owned-access-https-v1',
             'discovery_method': 'owned-fixture', 'metadata': {}}
    if authorization:
        agent['protected_path_markers'] = {'/admin': _MARKER}
        if mode == 'partial':
            # A second configured resource supplies a genuine failure after the
            # first path's complete three-request confirmation.
            agent['protected_path_markers']['/admin/'] = _MARKER
    try:
        with trusted_tenant_tls(ca_file):
            yield agent, calls
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=5)
        if worker.is_alive():
            raise RuntimeError('Owned HTTPS access fixture did not stop')


def _private_variants(values):
    variants = set()
    for value in values:
        if not value:
            continue
        raw = value.encode()
        variants.update((value, quote(value, safe=''), json.dumps(value)[1:-1],
                         base64.b64encode(raw).decode(), base64.urlsafe_b64encode(raw).decode(),
                         base64.urlsafe_b64encode(raw).decode().rstrip('=')))
    return variants


@pytest.mark.asyncio
@pytest.mark.parametrize('fmt', ['json', 'sarif'])
@pytest.mark.parametrize('mode', ['protected', 'vulnerable', 'partial'])
@pytest.mark.parametrize('method,rule,count,score,level', _GROUPS, ids=[item[1] for item in _GROUPS])
async def test_trusted_https_access_cli_workflow(
        tmp_path, monkeypatch, capsys, caplog, fmt, mode, method, rule, count, score, level):
    monkeypatch.setenv(_REFERENCE, _ISSUED)
    monkeypatch.setattr('src.security.access_control_tests.asyncio', SimpleNamespace(
        sleep=AsyncMock(), CancelledError=asyncio.CancelledError))
    security = SecurityTestEngine()
    security.prompt_tester.test_agent = AsyncMock(return_value=[])
    security.privacy_tester.test_agent = AsyncMock(return_value=[])
    security.access_tester.test_agent = getattr(security.access_tester, method)
    monkeypatch.setattr(scanner_cli, 'SecurityTestEngine', lambda: security)

    checkpoints, finished = [], []
    original_pipeline = scanner_cli.run_pipeline

    async def observed_pipeline(*args, **kwargs):
        retain = kwargs['checkpoint_callback']
        async def observed_checkpoint(report):
            validate_checkpoint_report(report)
            checkpoints.append(deepcopy(report))
            await retain(report)
        kwargs['checkpoint_callback'] = observed_checkpoint
        result = await original_pipeline(*args, **kwargs)
        finished.append(deepcopy(result))
        return result

    monkeypatch.setattr(scanner_cli, 'run_pipeline', observed_pipeline)
    output = tmp_path / ('access-workflow.' + fmt)
    with _https_access_target(tmp_path / 'tls-fixture', mode, rule == 'authorization_bypass') as (agent, calls):
        operation = scanner_cli._execute(
            None, [agent], str(output), fmt, 'security_only', False,
            max_requests=80, max_response_bytes=4096, timeout_seconds=15,
            request_timeout_seconds=2, allow_loopback=True)
        if mode == 'partial':
            with pytest.raises(click.ClickException, match='No security checks completed') as failure:
                await operation
            assert failure.value.exit_code == 1
        else:
            assert await operation is None

    assert len(finished) == 1 and checkpoints
    result, asset = finished[0], finished[0]['agents'][0]
    expected_score = 0 if mode == 'protected' else score
    expected_level = 'minimal' if mode == 'protected' else level
    expected_count = count
    if rule == 'weak_api_key' and mode != 'protected':
        # The first accepted key skips its remaining five header variations.
        expected_count -= 5
    if rule == 'authorization_bypass' and mode == 'partial':
        expected_count = 4
    assert len(calls) == expected_count
    assert all(call['method'] == 'GET' and call['tls'] in {'TLSv1.2', 'TLSv1.3'} for call in calls)
    assert calls[0]['credential'] == _ISSUED and calls[1]['credential'].startswith('scanner-invalid-')
    assert result['status'] == ('partial' if mode == 'partial' else 'completed')
    assert result['summary']['overall_risk_score'] == asset['risk_score'] == expected_score
    assert type(asset['risk_score']) in (int, float)
    assert type(result['summary']['overall_risk_score']) in (int, float)
    assert asset['risk_level'] == expected_level
    assert asset['risk_coverage_status'] == ('partial' if mode == 'partial' else 'sampled')
    assert risk_assessment_eligible(result['security_results'][0])
    summary, projected = project_report_risk(result)
    assert summary['overall_risk_score'] == projected[asset['id']]['risk_score'] == expected_score
    checks = [check for check in asset['checks'] if check['rule_id'] == rule]
    assert len(checks) == 1
    check = checks[0]
    assert check['outcome'] == ('passed' if mode == 'protected' else 'confirmed')
    assert check['requests_attempted'] == expected_count
    assert check['responses_evaluated'] == (3 if mode == 'partial' else expected_count)
    assert check['status'] == ('failed' if mode == 'partial' else 'completed')
    assert len(asset['vulnerabilities']) == (0 if mode == 'protected' else 1)
    if asset['vulnerabilities']:
        finding = asset['vulnerabilities'][0]
        assert finding['vulnerability_type'] == rule and finding['evidence_status'] == 'confirmed'
        assert finding['protected_control_version'] == 3
    assert result['check_evidence_schema_version'] == asset['check_evidence_schema_version'] == '3.0'
    assert all(checkpoint['checkpoint']['version'] == '4.0' for checkpoint in checkpoints)
    assert len(asset['check_evidence']) == len(asset['vulnerabilities'])
    if asset['check_evidence']:
        receipt = asset['check_evidence'][0]
        assert receipt['source'] == 'controlled_access_response' and receipt['source_version'] == '1.0'
        assert receipt['request_ordinal'] == receipt['requests_attempted'] == receipt['responses_evaluated'] == 3
        assert receipt['control_proof'] == {'request_ordinals': [1, 2], 'status_codes': [200, 403]}
        assert receipt['finding_id'] == asset['vulnerabilities'][0]['id']
        assert receipt['access_target']['endpoint'] == agent['endpoint']
        if rule == 'authorization_bypass':
            assert receipt['protected_path_index'] == 0
    identity = result['producer_identity']
    assert saved_identity(identity) == identity and identity['component'] == 'cli'
    assert all(checkpoint['producer_identity'] == identity for checkpoint in checkpoints)

    encoded = output.read_text()
    document = json.loads(encoded)
    assert output.stat().st_mode & 0o777 == 0o600
    assert (tmp_path / 'tls-fixture').stat().st_mode & 0o777 == 0o700
    assert all(path.stat().st_mode & 0o777 == 0o600 for path in (tmp_path / 'tls-fixture').iterdir())
    if fmt == 'json':
        assert document == result
    else:
        run = document['runs'][0]
        assert run['properties']['producer_identity'] == identity
        assert run['properties']['summary']['overall_risk_score'] == expected_score
        assert run['properties']['scan_status'] == result['status']
        assert run['invocations'][0]['executionSuccessful'] is (mode != 'partial')
        assert len(run['results']) == len(asset['vulnerabilities'])
        assert {item['properties']['vulnerability_id'] for item in run['results']} == {
            finding['id'] for finding in asset['vulnerabilities']}
        assert run['properties']['check_evidence'][0]['check_evidence'] == asset['check_evidence']

    captured = capsys.readouterr()
    private = {_MARKER, _ISSUED, _REFERENCE}
    private.update(call['credential'] for call in calls if call['credential'].startswith('scanner-invalid-'))
    combined = encoded + json.dumps(checkpoints) + captured.out + captured.err + caplog.text
    assert all(value not in combined for value in _private_variants(private))
    assert _MARKER not in json.dumps(calls) and all('response_excerpt' not in item or
        item['response_excerpt'] == '[RESPONSE_TEXT_OMITTED]' for item in asset['vulnerabilities'])
