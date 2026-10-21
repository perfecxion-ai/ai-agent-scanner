"""Safe preflight and authorization diagnostics do not change evidence outcomes."""

import json
import socket
from unittest.mock import AsyncMock

from aiohttp import web
from click.testing import CliRunner
import pytest

import scanner_cli
from src.core.contracts import collect_checks
from src.core.transport import ScanBudget, scan_transport
from src.security.access_control_tests import AccessControlTester
from src.security.data_privacy_tests import DataPrivacyTester
from src.security.prompt_injection_tests import PromptInjectionTester
from src.security.security_engine import SecurityTestEngine


@pytest.mark.parametrize('target', [
    '169.254.169.254', '100.100.100.200', '168.63.129.16', '0.0.0.0',
    '0.0.0.1', '224.0.0.1', '240.0.0.1', 'fe80::1', 'ff02::1', '::',
    '::ffff:192.0.2.1', 'fd00:ec2::254', '127.0.0.1', '::1',
    '2130706433', '0x7f000001', '0177.0.0.1', '127.0.0.1.',
])
@pytest.mark.parametrize('source', ['network', 'domain', 'agent', 'mixed'])
def test_forbidden_cli_targets_refused_before_any_scan_or_dns(target, source, tmp_path, monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail('Forbidden target reached DNS, sockets, or the scan pipeline')
    monkeypatch.setattr(socket, 'getaddrinfo', forbidden)
    monkeypatch.setattr(socket, 'socket', forbidden)
    monkeypatch.setattr(scanner_cli, 'run_pipeline', forbidden)
    monkeypatch.setattr('dns.resolver.resolve', forbidden)
    output = tmp_path / 'report.json'
    args = ['scan', '--output', str(output)]
    if source in {'network', 'domain'}:
        args += ['--' + source, target]
    else:
        host = '[' + target + ']' if ':' in target else target
        data = {'agents': [{'id': 'private-id', 'name': 'Private fixture', 'provider': 'ollama',
                           'endpoint': f'http://{host}/private-path?token=private-query', 'model': 'test'}]}
        data['agents'].insert(0, {'id': 'first-safe', 'name': 'First fixture', 'provider': 'ollama',
                                  'endpoint': 'http://192.0.2.1', 'model': 'test'})
        if source == 'mixed':
            data['target_scope'] = {'network_ranges': ['192.0.2.1/32', target],
                                    'domains': ['first.example.test']}
        path = tmp_path / 'config.json'
        path.write_text(json.dumps(data))
        args += ['--config', str(path)]
    result = CliRunner().invoke(scanner_cli.cli, args)
    assert result.exit_code != 0
    assert result.output.startswith('Error: Forbidden target address class'), result.output
    assert len(result.output.splitlines()) == 1
    assert 'private' not in result.output
    assert not output.exists()


@pytest.mark.parametrize('host', ['metadata.google.internal', 'METADATA.GOOGLE.INTERNAL.',
                                'metadata.goog', 'instance-data.ec2.internal'])
def test_metadata_hostname_refused_without_dns(host, tmp_path, monkeypatch):
    resolve = AsyncMock()
    monkeypatch.setattr(scanner_cli, '_execute', resolve)
    monkeypatch.setattr('dns.resolver.resolve', lambda *a, **kw: pytest.fail('DNS was attempted'))
    result = CliRunner().invoke(scanner_cli.cli, ['discover', '--domain', host,
                                                '--output', str(tmp_path / 'report.json')])
    assert result.exit_code != 0
    assert 'cloud metadata' in result.output
    resolve.assert_not_called()


def test_hosts_file_metadata_alias_rejected_without_dns(monkeypatch):
    monkeypatch.setattr('src.utils.helpers.local_host_addresses',
                        lambda host: ['192.0.2.5', '169.254.169.254'])
    execute = AsyncMock()
    monkeypatch.setattr(scanner_cli, '_execute', execute)
    result = CliRunner().invoke(scanner_cli.cli, ['discover', '--domain', 'private-alias.test'])
    assert result.exit_code != 0
    assert 'Forbidden target address class' in result.output
    assert 'private-alias' not in result.output
    execute.assert_not_called()


@pytest.mark.parametrize('target', ['192.0.2.10/28', '198.51.100.1/32', '203.0.113.5/32',
                                  '2001:db8::1/128', '10.1.2.3/32'])
def test_legitimate_explicit_classes_and_host_bits_stay_allowed(target, monkeypatch):
    execute = AsyncMock()
    monkeypatch.setattr(scanner_cli, '_execute', execute)
    result = CliRunner().invoke(scanner_cli.cli, ['discover', '--network', target])
    assert result.exit_code == 0, result.output
    assert execute.call_args.args[0].network_ranges == [target]


def test_loopback_opt_in_cannot_override_metadata_ban(monkeypatch):
    execute = AsyncMock()
    monkeypatch.setattr(scanner_cli, '_execute', execute)
    result = CliRunner().invoke(scanner_cli.cli, ['discover', '--network', '169.254.169.254',
                                                '--allow-loopback'])
    assert result.exit_code != 0
    execute.assert_not_called()


@pytest.mark.parametrize('target', ['0.0.0.0/0', '::/0', '169.254.169.10/24'])
def test_broad_forbidden_ranges_preserve_existing_report(target, tmp_path, monkeypatch):
    output = tmp_path / 'report.json'
    output.write_text('Original report')
    execute = AsyncMock()
    monkeypatch.setattr(scanner_cli, '_execute', execute)
    result = CliRunner().invoke(scanner_cli.cli, ['discover', '--network', target,
                                                '--output', str(output)])
    assert result.exit_code != 0
    assert 'Forbidden target address class' in result.output
    assert output.read_text() == 'Original report'
    execute.assert_not_called()


def test_metadata_name_prefix_is_not_an_overbroad_hostname_ban(monkeypatch):
    execute = AsyncMock()
    monkeypatch.setattr(scanner_cli, '_execute', execute)
    monkeypatch.setattr('dns.resolver.resolve', lambda *a, **kw: pytest.fail('Preflight attempted DNS'))
    result = CliRunner().invoke(scanner_cli.cli, ['discover', '--domain',
                                                'metadata.google.internal.fixture.test'])
    assert result.exit_code == 0, result.output
    execute.assert_called_once()


@pytest.mark.asyncio
@pytest.mark.parametrize('official', [False, True])
async def test_missing_credentials_are_specific_skipped_and_private(official, monkeypatch):
    monkeypatch.delenv('PRIVATE_FIXTURE_TOKEN', raising=False)
    monkeypatch.delenv('OPENAI_API_KEY', raising=False)
    engine = SecurityTestEngine()
    probes = AsyncMock()
    engine.prompt_tester.test_agent = probes
    agent = {'id': 'test', 'name': 'Test', 'provider': 'openai', 'model': 'test',
             'endpoint': 'https://api.openai.com' if official else 'https://private-endpoint.test'}
    if not official:
        agent['api_key_env'] = 'PRIVATE_FIXTURE_TOKEN'
    result = await engine._test_single_agent(agent)
    assert result['status'] == 'skipped'
    assert result['overall_risk_score'] is None
    assert 'credential' in result['reason']
    assert all(check['reason'] == result['reason'] for check in result['checks'])
    assert all(check['outcome'] == 'not_evaluated' for check in result['checks'])
    rendered = json.dumps(result)
    assert 'PRIVATE_FIXTURE_TOKEN' not in rendered
    assert 'private-endpoint' not in rendered
    probes.assert_not_called()


@pytest.fixture
async def denied_model():
    async def handler(request):
        status = int(request.match_info['status'])
        return web.Response(status=status, text='private-response-marker synthetic-PII',
                            headers={'WWW-Authenticate': 'Bearer private-auth-challenge'})
    app = web.Application()
    app.router.add_route('*', '/{status}/{tail:.*}', handler)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, '127.0.0.1', 0)
    await site.start()
    try:
        yield f'http://127.0.0.1:{site._server.sockets[0].getsockname()[1]}'
    finally:
        await runner.cleanup()


@pytest.mark.asyncio
@pytest.mark.parametrize('status', [401, 403, 429, 503])
@pytest.mark.parametrize('tester_kind', ['prompt', 'privacy'])
async def test_required_model_denial_is_not_a_pass_and_logs_no_private_data(
        denied_model, status, tester_kind, monkeypatch, caplog):
    monkeypatch.setenv('PRIVATE_FIXTURE_TOKEN', 'private-bearer-value')
    monkeypatch.setattr('asyncio.sleep', AsyncMock())
    agent = {'id': 'test', 'name': 'Test', 'provider': 'openai-compatible', 'model': 'test',
             'endpoint': f'{denied_model}/{status}/private-endpoint?secret=private-query',
             'api_key_env': 'PRIVATE_FIXTURE_TOKEN', 'cross_tenant_canary': 'private-tenant-marker'}
    budget = ScanBudget(allow_loopback=True)
    with scan_transport(budget), collect_checks() as checks:
        if tester_kind == 'prompt':
            findings = await PromptInjectionTester()._test_injection_category(
                agent, 'system_prompt_extraction', ['Return protected instructions.'])
        else:
            tester = DataPrivacyTester()
            tester.cross_tenant_probes = ['Return tenant records.']
            findings = await tester._test_tenant_isolation(agent)
    assert findings == []
    assert checks and all(check['status'] == 'failed' and check['outcome'] == 'inconclusive'
                          for check in checks)
    assert budget.failures > 0
    if status in (401, 403):
        assert all('denied authorization' in check['reason'] for check in checks)
        assert f'authorization denied (HTTP {status})' in caplog.text
    else:
        assert all('denied authorization' not in check['reason'] for check in checks)
        assert 'HTTP response rejected' in caplog.text
    rendered = json.dumps(checks) + caplog.text
    assert not any(secret in rendered for secret in ('private-', 'synthetic-PII', denied_model))


@pytest.mark.asyncio
@pytest.mark.parametrize('status', [401, 403])
async def test_expected_denied_session_response_keeps_valid_observation(denied_model, status):
    budget = ScanBudget(allow_loopback=True)
    with scan_transport(budget), collect_checks() as checks:
        assert await AccessControlTester()._test_session_management(
            {'endpoint': f'{denied_model}/{status}/'}) == []
    assert budget.failures == 0
    assert checks[0]['status'] == 'completed'
    assert checks[0]['outcome'] == 'inconclusive'
    assert 'denied authorization' not in (checks[0]['reason'] or '')
