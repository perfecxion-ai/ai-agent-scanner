"""Discovery regressions use local data and fake responses, never external hosts."""

from copy import deepcopy
from unittest.mock import AsyncMock

import pytest

from src.discovery.discovery_engine import DiscoveryEngine, DiscoveryScope
from src.discovery.network_scanner import NetworkScanner
from src.core.pipeline import run_pipeline
from src.reporting.workflows import inventory


def observation(asset_id, endpoint=None, **metadata):
    return {
        'id': asset_id, 'name': asset_id, 'endpoint': endpoint,
        'provider': 'openai', 'metadata': metadata,
        'discovery_method': 'code_scan', 'confidence': 0.8,
    }


def test_endpointless_assets_remain_distinct():
    engine = DiscoveryEngine()
    agents = [observation('repo-a'), observation('repo-b')]
    assert len(engine._deduplicate_agents(agents)) == 2


def test_endpoint_identity_preserves_scheme_path_and_query():
    engine = DiscoveryEngine()
    urls = ['http://host/api', 'https://host/api', 'https://host/API',
            'https://host/api?deployment=a', 'https://host/api?deployment=b']
    assert len({engine._normalize_endpoint(url) for url in urls}) == len(urls)
    assert engine._normalize_endpoint('http://HOST:80/api') == engine._normalize_endpoint(urls[0])


def test_deduplication_preserves_provenance_without_mutating_input():
    engine = DiscoveryEngine()
    agents = [observation('a', 'https://host/api', source='code'),
              observation('b', 'https://host:443/api', source='traffic')]
    original = deepcopy(agents)
    merged = engine._deduplicate_agents(agents)
    assert len(merged) == 1
    assert len(merged[0]['metadata']['observations']) == 2
    assert agents == original


@pytest.mark.asyncio
async def test_shared_cloud_endpoint_does_not_collapse_distinct_subscription_resources():
    endpoint = 'https://eastus.api.cognitive.microsoft.com'
    resource_a = '/subscriptions/111/resourceGroups/lab/providers/Microsoft.CognitiveServices/accounts/shared-name'
    resource_b = '/subscriptions/222/resourceGroups/lab/providers/Microsoft.CognitiveServices/accounts/shared-name'
    first = observation('azure-a', endpoint, cloud='azure', resource_id=resource_a)
    second = observation('azure-b', endpoint, cloud='azure', resource_id=resource_b)
    duplicate = {**deepcopy(first), 'id': 'azure-a-repeat', 'confidence': 0.95}
    network = observation('network-observation', endpoint)
    for agent in (first, second, duplicate, network):
        agent.update(name='Shared AI', provider='azure-cognitive')
    original = deepcopy([first, second, duplicate, network])
    engine = DiscoveryEngine()
    engine.cloud_scanner.scan_azure = AsyncMock(return_value=[first, second, duplicate])
    engine.network_scanner.scan_domain = AsyncMock(return_value=[network])
    scope = DiscoveryScope(
        include_network=True, domains=['cloud-fixture.invalid'],
        include_cloud=True, cloud_accounts={'azure': {'subscription_id': 'fixture'}})
    report = await run_pipeline(engine, None, None, scope, 'discovery_only')
    assert [first, second, duplicate, network] == original
    assert len(report['agents']) == 3
    resources = [agent for agent in report['agents'] if agent['metadata'].get('resource_id')]
    assert {agent['metadata']['resource_id'] for agent in resources} == {resource_a, resource_b}
    assert {agent['endpoint'] for agent in report['agents']} == {endpoint}
    merged = engine._deduplicate_agents([first, duplicate])
    assert len(merged) == 1
    assert len(merged[0]['metadata']['observations']) == 2
    assert merged[0]['confidence'] == 0.95
    assets, _ = inventory(report)
    assert len(assets) == 3
    assert sum(asset['identity_basis'] == 'cloud_resource' for asset in assets.values()) == 2
    assert sum(asset['identity_basis'] == 'endpoint' for asset in assets.values()) == 1
    assert not any(asset['ambiguous'] for asset in assets.values())


@pytest.mark.asyncio
async def test_code_discovery_handles_missing_endpoint(tmp_path):
    (tmp_path / 'agent.py').write_text('import openai\nimport anthropic\n')
    agents = await DiscoveryEngine().discover_agents(DiscoveryScope(
        include_network=False, include_repositories=True, repositories=[str(tmp_path)],
    ))
    assert {agent.provider for agent in agents} == {'openai', 'anthropic'}
    assert all(agent.endpoint is None for agent in agents)


@pytest.mark.asyncio
async def test_unknown_cloud_provider_fails_explicitly():
    with pytest.raises(ValueError, match='Unsupported cloud provider'):
        await DiscoveryEngine().discover_agents(DiscoveryScope(
            include_network=False, include_cloud=True, cloud_accounts={'typo': {}},
        ))


@pytest.mark.asyncio
@pytest.mark.parametrize('network', ['0.0.0.0/0', '::/0', '10.0.0.0/16'])
async def test_oversized_ranges_rejected_before_host_allocation(network):
    scanner = NetworkScanner()
    scanner._scan_host = AsyncMock()
    with pytest.raises(ValueError, match='1024'):
        await scanner.scan_range(network, {})
    scanner._scan_host.assert_not_called()


class Response:
    def __init__(self, body=b'', status=200, headers=None):
        self.body, self.status, self.headers = body, status, headers or {}
        self.content = self

    async def iter_chunked(self, size):
        for offset in range(0, len(self.body), size):
            yield self.body[offset:offset + size]


@pytest.mark.asyncio
async def test_generic_bearer_and_html_are_not_ai_services():
    scanner = NetworkScanner()
    signature = DiscoveryEngine().ai_signatures['openai']
    assert not await scanner._is_ai_service(Response(status=401, headers={
        'www-authenticate': 'Bearer',
    }), signature)
    assert not await scanner._is_ai_service(Response(b'<html>model choices usage</html>'), signature)
    assert not await scanner._is_ai_service(Response(b'{"message":"model choices usage"}'), signature)


@pytest.mark.asyncio
async def test_chunked_ollama_response_identifies_service():
    response = Response(b'{"models":[{"name":"fixture","modified_at":"2026-01-01T00:00:00Z"}]}')
    assert await NetworkScanner()._is_ai_service(response, DiscoveryEngine().ai_signatures['ollama'])


@pytest.mark.asyncio
async def test_service_body_cap_and_redirects():
    scanner = NetworkScanner()
    signature = DiscoveryEngine().ai_signatures['ollama']
    assert not await scanner._is_ai_service(Response(b' ' * 10001 + b'{"models":[]}'), signature)
    assert not await scanner._is_ai_service(Response(b'{"models":[]}', status=302), signature)
