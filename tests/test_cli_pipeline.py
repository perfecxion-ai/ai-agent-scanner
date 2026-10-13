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
    result = CliRunner().invoke(scanner_cli.cli, ['discover', '--network', network,
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
