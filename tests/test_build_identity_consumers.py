"""Producer provenance stays distinct from current formatting and private values."""

import asyncio
from copy import deepcopy
import json
from types import SimpleNamespace
from unittest.mock import AsyncMock

import click
from click.testing import CliRunner
import pytest
from sqlalchemy import event

import scanner_cli
from src._version import __version__
from src.core import pipeline
from src.core.build_identity import current_identity
from src.evaluation import replay
from src.evaluation import benchmark_validation, prompt_benchmark
from src.mcp import assessment
from src.mcp import live, policy as mcp_policy
from src.reporting.report_generator import ReportGenerator
from src.reporting.sarif_output import generate_sarif
from tests.test_api_auth import api as api, headers
from tests.test_pipeline import asset, engines
from tests import test_benchmark_validation as benchmark_fixtures
from tests import test_mcp_live as mcp_fixtures
from tests import test_mcp_policy as protected_mcp
from tests.test_prompt_benchmark import config as benchmark_config


benchmark_report = benchmark_fixtures.report
mcp_server = mcp_fixtures.server
EXPECTED = benchmark_fixtures.EXPECTED


def test_cli_version_and_public_build_info_use_the_running_package(monkeypatch):
    calls = []
    identity = current_identity(component='cli')
    def capture(component):
        calls.append(component)
        return deepcopy(identity)
    monkeypatch.setattr(scanner_cli, 'current_identity', capture)
    runner = CliRunner()
    assert __version__ in runner.invoke(scanner_cli.cli, ['--version']).output
    response = runner.invoke(scanner_cli.cli, ['build-info', '--json'])
    assert response.exit_code == 0 and json.loads(response.output) == identity
    assert calls == ['cli']


def test_authenticated_build_route_performs_no_sql(api):
    module, client = api
    def reject_sql(*_args):
        raise AssertionError('Build diagnostics must not read the database')
    event.listen(module.db.engine, 'before_cursor_execute', reject_sql)
    try:
        assert client.get('/api/build').status_code == 401
        response = client.get('/api/build', headers=headers(module))
        assert response.status_code == 200 and response.json['success'] is True
        assert response.headers['Cache-Control'] == 'no-store'
        identity = response.json['build']
        assert identity['package_version'] == __version__ and identity['component'] == 'server'
        assert identity['server_app']['status'] == 'available'
    finally:
        event.remove(module.db.engine, 'before_cursor_execute', reject_sql)


@pytest.mark.asyncio
async def test_pipeline_captures_before_discovery_once_and_copies_every_checkpoint(monkeypatch):
    stamp = current_identity(component='cli')
    calls, saved = [], []
    def capture(component):
        calls.append(component)
        return deepcopy(stamp)
    async def discover(_scope):
        assert calls == ['cli']
        return [asset()]
    async def checkpoint(report):
        saved.append(deepcopy(report))
        report['producer_identity']['source']['sha256'] = 'f' * 64
    monkeypatch.setattr(pipeline, 'current_identity', capture)
    report = await pipeline.run_pipeline(SimpleNamespace(discover_agents=discover), None, None, None,
                                         'discovery_only', checkpoint_callback=checkpoint,
                                         producer_component='cli')
    assert calls == ['cli'] and saved
    assert all(value['producer_identity'] == stamp for value in saved + [report])
    assert 'exporter_identity' not in report


@pytest.mark.asyncio
@pytest.mark.parametrize('interruption', ['deadline', 'cancel'])
async def test_cli_interruption_retains_the_original_producer(interruption, tmp_path, monkeypatch):
    entered = asyncio.Event()
    async def stall(_agents):
        entered.set()
        await asyncio.Future()
    discovery = SimpleNamespace(discover_agents=AsyncMock(return_value=[asset()]))
    security = SimpleNamespace(test_agents=stall)
    monkeypatch.setattr(scanner_cli, 'DiscoveryEngine', lambda: discovery)
    monkeypatch.setattr(scanner_cli, 'SecurityTestEngine', lambda: security)
    monkeypatch.setattr(scanner_cli, 'RiskAssessment', lambda: None)
    output = tmp_path / 'partial.json'
    task = asyncio.create_task(scanner_cli._execute(None, None, output, 'json', 'full', False,
                              timeout_seconds=0.03 if interruption == 'deadline' else 30))
    if interruption == 'cancel':
        await entered.wait()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
    else:
        with pytest.raises(click.ClickException, match='deadline'):
            await task
    report = json.loads(output.read_text())
    assert report['status'] == ('cancelled' if interruption == 'cancel' else 'failed')
    assert report['producer_identity'] == current_identity(component='cli')


@pytest.mark.parametrize('stamp', ['absent', None, {'source': {'sha256': '[redacted]'}}])
def test_historical_sarif_unknown_producer_and_explicit_withholding_are_distinct(stamp):
    original = {'agents': [], 'status': 'completed', 'summary': {}}
    if stamp != 'absent':
        original['producer_identity'] = stamp
    before = deepcopy(original)
    document = pipeline.to_sarif(original)
    run = document['runs'][0]
    assert run['properties']['producer_identity'] is None
    assert run['properties']['exporter_identity'] == (current_identity() if stamp == 'absent' else None)
    assert 'version' not in run['tool']['driver']
    assert original == before


def test_saved_older_producer_is_preserved_beside_current_exporter():
    producer = current_identity()
    producer['package_version'] = '0.9.0'
    producer['source']['sha256'] = 'a' * 64
    report = generate_sarif([], {'producer_identity': producer})
    run = report['runs'][0]
    assert run['properties']['producer_identity'] == producer
    assert run['tool']['driver']['version'] == '0.9.0'
    assert run['properties']['exporter_identity'] == current_identity()


@pytest.mark.parametrize('withheld', [False, True])
def test_comprehensive_formatter_does_not_claim_current_producer(withheld):
    metadata = {'producer_identity': None} if withheld else {}
    report = ReportGenerator().generate_comprehensive_report(scan_metadata=metadata)
    assert report['producer_identity'] is None
    assert report['exporter_identity'] == (None if withheld else current_identity())
    assert report['report_metadata']['scanner_version'] is None
    assert report['report_metadata']['exporter_version'] == (None if withheld else __version__)


@pytest.mark.parametrize('case', ['current', 'older', 'historical', 'withheld'])
def test_comprehensive_text_distinguishes_producer_and_exporter_versions(case):
    metadata = {}
    producer_version = None
    if case in {'current', 'older'}:
        identity = current_identity()
        producer_version = __version__ if case == 'current' else '0.9.0'
        identity['package_version'] = producer_version
        metadata['producer_identity'] = identity
    elif case == 'withheld':
        metadata['producer_identity'] = None
    generator = ReportGenerator()
    report = generator.generate_comprehensive_report(scan_metadata=metadata)
    text = generator.generate_executive_summary(report)
    expected_producer = f'AI Agent Scanner v{producer_version}' if producer_version else 'Unknown version'
    expected_exporter = 'Unknown version' if case == 'withheld' else f'AI Agent Scanner v{__version__}'
    assert f'  Producer:   {expected_producer}' in text
    assert f'  Exporter:   {expected_exporter}' in text
    assert 'vNone' not in text
    if case == 'withheld':
        assert __version__ not in text


def test_formatter_identity_cannot_expose_a_protected_value_omitted_from_the_view():
    marker = current_identity()['source']['sha256']
    report = ReportGenerator().generate_comprehensive_report(agents=[{'system_prompt_canary': marker}])
    assert report['producer_identity'] is None and report['exporter_identity'] is None
    assert marker not in json.dumps(report)


@pytest.mark.asyncio
async def test_protected_source_digest_is_not_reintroduced_by_export(monkeypatch):
    producer = current_identity()
    marker = producer['source']['sha256']
    assert marker is not None
    target = asset()
    target['system_prompt_canary'] = marker
    discovery, security, risk = engines([target])
    monkeypatch.setattr(pipeline, 'current_identity', lambda component: deepcopy(producer))
    result = await pipeline.run_pipeline(discovery, security, risk, None)
    assert result['producer_identity'] is None
    exported = pipeline.to_sarif(result)
    assert exported['runs'][0]['properties']['exporter_identity'] is None
    assert marker not in json.dumps([result, exported])


def test_passive_mcp_identity_does_not_expose_an_embedded_credential(monkeypatch):
    producer = current_identity()
    marker = producer['source']['sha256']
    monkeypatch.setattr(assessment, 'current_identity', lambda: deepcopy(producer))
    report = assessment.assess({'mcpServers': {'fixture': {'command': 'python', 'env': {'API_KEY': marker}}}})
    assert report['producer_identity'] is None and report['ruleset_version'] == '1.0.0'
    sarif = assessment.to_sarif(report)
    assert sarif['runs'][0]['properties']['exporter_identity'] is None
    assert marker not in json.dumps([report, sarif])


def test_replay_current_producer_does_not_echo_the_policy_canary(monkeypatch):
    producer = current_identity()
    marker = producer['source']['sha256']
    calls = []
    def capture():
        calls.append(True)
        return deepcopy(producer)
    monkeypatch.setattr(replay, 'current_identity', capture)
    report = replay.evaluate_suite({'schema_version': '1.0', 'suite_id': 'identity', 'cases': [{
        'id': 'fixture', 'check_id': 'REPLAY001', 'expected_violation': True,
        'retrieved_documents': [{'content': marker}],
        'observed': {'outputs': [marker], 'tool_calls': []},
        'policy': {'forbidden_output_markers': [marker]}}]})
    assert calls == [True] and report['producer_identity'] is None
    assert report['ruleset_version'] == '1.1.0'
    assert report['metrics']['true_positive'] == 1
    assert marker not in json.dumps(report)


@pytest.mark.parametrize('family', ['inventory', 'policy'])
def test_live_mcp_captures_one_producer_before_http(mcp_server, monkeypatch, family):
    producer = current_identity()
    calls = []
    module = live if family == 'inventory' else mcp_policy
    def capture():
        assert not mcp_server[2]
        calls.append(True)
        return deepcopy(producer)
    monkeypatch.setattr(module, 'current_identity', capture)
    if family == 'inventory':
        report = asyncio.run(live.inventory(mcp_server[0], ('127.0.0.1/32',), allow_loopback=True))
    else:
        monkeypatch.setenv('MCP_FIXTURE_TOOL', protected_mcp.MARKER)
        monkeypatch.setenv('MCP_FIXTURE_BEARER', protected_mcp.CREDENTIAL)
        protected_mcp.configure(mcp_server)
        report = protected_mcp.collect(mcp_server)
    assert calls == [True] and report['producer_identity'] == producer
    assert report['protocol_version'] == live.PROTOCOL_VERSION
    assert all(request['params']['_meta']['io.modelcontextprotocol/clientInfo'] ==
               {'name': 'ai-agent-scanner', 'version': __version__} for request, _ in mcp_server[2])


@pytest.mark.parametrize('collision', [False, True])
def test_benchmark_identity_is_captured_before_probes_and_guarded(monkeypatch, collision):
    producer = current_identity()
    config = benchmark_config()
    marker = producer['source']['sha256'] if collision else 'synthetic-build-benchmark-17382649'
    monkeypatch.setenv(config.canary_env, marker)
    calls = []
    def capture():
        calls.append(True)
        return deepcopy(producer)
    monkeypatch.setattr(prompt_benchmark, 'current_identity', capture)
    _, _, _, public, _ = prompt_benchmark._prepare(config)
    assert calls == [True]
    assert public['producer_identity'] == (None if collision else producer)
    if collision:
        assert marker not in json.dumps(public)


@pytest.mark.asyncio
@pytest.mark.parametrize('kind', ['absent', 'valid', 'null', 'malformed'])
async def test_benchmark_validator_optional_producer_keeps_historical_compatibility(benchmark_report, kind):
    document = deepcopy(benchmark_report)
    if kind == 'absent':
        document.pop('producer_identity')
    elif kind == 'null':
        document['producer_identity'] = None
    elif kind == 'valid':
        document['producer_identity']['package_version'] = '0.9.0'
    else:
        document['producer_identity'] = {'source': {'sha256': '[redacted]'}}
    before = deepcopy(document)
    if kind == 'malformed':
        with pytest.raises(benchmark_validation.ReportValidationError):
            benchmark_validation.validate_report(document, EXPECTED)
    else:
        assert benchmark_validation.validate_report(document, EXPECTED)['status'] == document['status']
    assert document == before


@pytest.mark.asyncio
@pytest.mark.parametrize('mode', ['full', 'discovery_only'])
@pytest.mark.parametrize('marker', ['producer_identity', 'exporter_identity'])
async def test_outer_identity_field_collision_stops_before_security(mode, marker):
    target = asset()
    target['system_prompt_canary'] = marker
    discovery, security, risk = engines([target])
    with pytest.raises(ValueError, match='Protected data conflicts with scanner identity fields') as error:
        await pipeline.run_pipeline(discovery, security, risk, None, mode)
    assert marker not in str(error.value)
    security.test_agents.assert_not_called()


@pytest.mark.parametrize('family', ['formatter', 'mcp', 'replay', 'benchmark'])
def test_known_outer_field_collisions_are_refused_without_echoing_the_marker(family, monkeypatch):
    marker = 'exporter_identity'
    with pytest.raises(ValueError) as error:
        if family == 'formatter':
            ReportGenerator().generate_comprehensive_report(agents=[{'system_prompt_canary': marker}])
        elif family == 'mcp':
            assessment.assess({'mcpServers': {'fixture': {'command': 'python', 'env': {'API_KEY': marker}}}})
        elif family == 'replay':
            replay.evaluate_suite({'schema_version': '1.0', 'suite_id': 'identity', 'cases': [{
                'id': 'fixture', 'check_id': 'REPLAY001', 'expected_violation': True,
                'retrieved_documents': [{'content': marker}],
                'observed': {'outputs': [marker], 'tool_calls': []},
                'policy': {'forbidden_output_markers': [marker]}}]})
        else:
            config = benchmark_config()
            monkeypatch.setenv(config.canary_env, marker)
            prompt_benchmark._prepare(config)
    assert marker not in str(error.value)


@pytest.mark.parametrize('family', ['pipeline', 'mcp'])
@pytest.mark.parametrize('old_producer', [False, True])
@pytest.mark.parametrize('field', ['source', 'version'])
def test_sarif_adapter_keeps_private_basis_from_omitted_report_fields(family, old_producer, field):
    current = current_identity()
    marker = current['source']['sha256'] if field == 'source' else current['package_version']
    if family == 'pipeline':
        report = {'status': 'completed', 'summary': {}, 'agents': [{
            'id': 'historical', 'checks': [], 'vulnerabilities': [], 'metadata': {'api_key': marker}}]}
        convert = pipeline.to_sarif
    else:
        report = {'mode': 'passive', 'findings': [], 'observations': [], 'limitations': [],
                  'metadata': {'api_key': marker}}
        convert = assessment.to_sarif
    if old_producer:
        producer = deepcopy(current)
        producer['package_version'] = '0.7.2'
        producer['source']['sha256'] = 'a' * 64
        report['producer_identity'] = producer
    original = deepcopy(report)
    result = convert(report)
    properties = result['runs'][0]['properties']
    assert properties['producer_identity'] == report.get('producer_identity')
    assert properties['exporter_identity'] is None
    assert marker not in json.dumps(result)
    assert report == original
