import json
from unittest.mock import AsyncMock

import pytest

from click.testing import CliRunner

import scanner_cli


@pytest.mark.parametrize('network', ['127.0.0.1/32', '::1/128'])
def test_local_cli_accepts_explicit_loopback_but_helper_defaults_closed(network, tmp_path, monkeypatch):
    from src.utils.helpers import validate_scan_scope
    discovery = AsyncMock(return_value=[])
    monkeypatch.setattr(scanner_cli.DiscoveryEngine, 'discover_agents', discovery)
    result = CliRunner().invoke(scanner_cli.cli, ['discover', '--network', network, '--allow-loopback',
                               '--output', str(tmp_path / 'inventory.json')])
    assert result.exit_code == 0, result.output
    assert discovery.call_args.args[0].network_ranges == [network]
    assert not validate_scan_scope({'network_ranges': [network]})[0]


def test_empty_scan_writes_json_and_sarif(tmp_path, monkeypatch):
    discovery = AsyncMock(return_value=[])
    monkeypatch.setattr(scanner_cli.DiscoveryEngine, 'discover_agents', discovery)
    for fmt in ('json', 'sarif'):
        output = tmp_path / fmt
        result = CliRunner().invoke(scanner_cli.cli, ['scan', '--domain', 'example.test',
                                  '--format', fmt, '--output', str(output)])
        assert result.exit_code == 0, result.output
        document = json.loads(output.read_text())
        if fmt == 'json':
            assert document['agents'] == []
            assert document['schema_version'] == '1.0'
        else:
            assert document['runs'][0]['results'] == []


def test_invalid_config_rejected_without_discovery(tmp_path, monkeypatch):
    discovery = AsyncMock()
    monkeypatch.setattr(scanner_cli.DiscoveryEngine, 'discover_agents', discovery)
    config = tmp_path / 'config.json'
    config.write_text('{"target_scope":{"network_ranges":"192.0.2.1"}}')
    result = CliRunner().invoke(scanner_cli.cli, ['scan', '--config', str(config)])
    assert result.exit_code != 0
    discovery.assert_not_called()


def test_discovered_model_override_reaches_security_and_does_not_guess_others(tmp_path, monkeypatch):
    from tests.test_pipeline import asset, engines
    first, second = asset(), asset(asset_id='other-asset')
    discovery, security, risk = engines([first, second])
    # Return an appropriately bound result for each input, without real requests.
    template = security.test_agents.return_value[0]
    async def assess(values):
        return [{**template, 'agent_id': values[0]['id']}]
    security.test_agents.side_effect = assess
    monkeypatch.setattr(scanner_cli, 'DiscoveryEngine', lambda: discovery)
    monkeypatch.setattr(scanner_cli, 'SecurityTestEngine', lambda: security)
    monkeypatch.setattr(scanner_cli, 'RiskAssessment', lambda: risk)
    result = CliRunner().invoke(scanner_cli.cli, ['scan', '--network', '192.0.2.1/32',
        '--model-override', 'stable-asset=fixture-model', '--output', str(tmp_path / 'report.json')])
    assert result.exit_code == 0, result.output
    calls = [call.args[0][0] for call in security.test_agents.call_args_list]
    assert calls[0]['model'] == 'fixture-model'
    assert 'model' not in calls[1]
    assert 'model' not in first


@pytest.mark.parametrize('arguments', [
    ['--model-override', 'missing-model'],
    ['--model-override', 'asset=model', '--model-override', 'asset=other'],
    ['--model-override', 'asset='],
    ['--model-override', 'asset=model', '--skip-security'],
    ['--max-requests', '0'], ['--max-requests', '10001'],
    ['--max-response-bytes', '0'], ['--timeout-seconds', '3601'],
])
def test_invalid_selection_and_limits_fail_before_discovery(arguments, monkeypatch):
    discovery = AsyncMock()
    monkeypatch.setattr(scanner_cli.DiscoveryEngine, 'discover_agents', discovery)
    result = CliRunner().invoke(scanner_cli.cli, ['scan', '--domain', 'example.test', *arguments])
    assert result.exit_code != 0
    discovery.assert_not_called()


@pytest.mark.parametrize('agents', [['unknown'], ['duplicate', 'duplicate']])
def test_unknown_or_ambiguous_model_binding_never_probes(agents, monkeypatch):
    from tests.test_pipeline import asset, engines
    discovery, security, risk = engines([asset(asset_id=value) for value in agents])
    monkeypatch.setattr(scanner_cli, 'DiscoveryEngine', lambda: discovery)
    monkeypatch.setattr(scanner_cli, 'SecurityTestEngine', lambda: security)
    monkeypatch.setattr(scanner_cli, 'RiskAssessment', lambda: risk)
    result = CliRunner().invoke(scanner_cli.cli, ['scan', '--network', '192.0.2.1/32',
        '--model-override', 'stable-asset=fixture-model'])
    assert result.exit_code != 0
    security.test_agents.assert_not_called()


def test_scan_budget_flags_reach_shared_context(tmp_path, monkeypatch):
    from src.core.transport import current_budget
    async def discover(scope):
        budget = current_budget()
        assert budget.max_requests == 37
        assert budget.max_response_bytes == 4096
        assert budget.allow_loopback is True
        return []
    # A staticmethod prevents binding this fixture function as an engine method.
    monkeypatch.setattr(scanner_cli.DiscoveryEngine, 'discover_agents', staticmethod(discover))
    result = CliRunner().invoke(scanner_cli.cli, ['discover', '--network', '127.0.0.1/32',
        '--allow-loopback', '--max-requests', '37', '--max-response-bytes', '4096',
        '--timeout-seconds', '2', '--output', str(tmp_path / 'report.json')])
    assert result.exit_code == 0, result.output


def test_all_skipped_security_retains_private_report_and_exits_nonzero(tmp_path, monkeypatch):
    from tests.test_pipeline import asset, engines
    discovery, security, risk = engines([asset()], status='skipped')
    monkeypatch.setattr(scanner_cli, 'DiscoveryEngine', lambda: discovery)
    monkeypatch.setattr(scanner_cli, 'SecurityTestEngine', lambda: security)
    monkeypatch.setattr(scanner_cli, 'RiskAssessment', lambda: risk)
    output = tmp_path / 'report.json'
    result = CliRunner().invoke(scanner_cli.cli, ['scan', '--network', '192.0.2.1/32', '--output', str(output)])
    assert result.exit_code != 0
    assert 'No security checks completed' in result.output
    assert json.loads(output.read_text())['summary']['checks_completed'] == 0
    assert output.stat().st_mode & 0o777 == 0o600


def test_legacy_cli_forwards_target_flags_and_budget(monkeypatch):
    import cli as legacy
    forwarded = []
    monkeypatch.setattr(legacy, 'cli', lambda **kwargs: forwarded.append(kwargs))
    monkeypatch.setattr(legacy.sys, 'argv', ['cli.py', '--network', '192.0.2.1/32', '--max-requests', '12'])
    legacy.main()
    assert forwarded[0]['args'] == ['discover', '--network', '192.0.2.1/32', '--max-requests', '12']


def test_cli_requires_loopback_opt_in_before_discovery(monkeypatch):
    discovery = AsyncMock()
    monkeypatch.setattr(scanner_cli.DiscoveryEngine, 'discover_agents', discovery)
    result = CliRunner().invoke(scanner_cli.cli, ['discover', '--network', '127.0.0.1/32'])
    assert result.exit_code != 0
    discovery.assert_not_called()
