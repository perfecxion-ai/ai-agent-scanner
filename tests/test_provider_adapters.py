import json
from unittest.mock import AsyncMock

import pytest

from src.utils.request_builder import construct_agent_request, extract_response_text
from src.security.security_engine import SecurityTestEngine
from src.core.pipeline import run_pipeline


@pytest.mark.parametrize('provider,endpoint,expected', [
    ('ollama', 'http://localhost:11434/proxy/api/tags', 'http://localhost:11434/proxy/api/chat'),
    ('ollama', 'http://localhost:11434/api/generate', 'http://localhost:11434/api/chat'),
    ('vllm', 'https://fixture.test/prefix/v1/models', 'https://fixture.test/prefix/v1/chat/completions'),
    ('openai', 'https://fixture.test/prefix/v1/chat/completions?api-version=1',
     'https://fixture.test/prefix/v1/chat/completions?api-version=1'),
    ('anthropic', 'https://fixture.test/proxy/v1/complete', 'https://fixture.test/proxy/v1/messages'),
    ('gemini', 'https://fixture.test/proxy/v1beta/models',
     'https://fixture.test/proxy/v1beta/models/fixture-model:generateContent'),
])
def test_adapter_preserves_prefix(provider, endpoint, expected):
    request = construct_agent_request({'provider': provider, 'endpoint': endpoint, 'model': 'fixture-model'}, 'hello')
    assert request['method'] == 'POST'
    assert request['url'] == expected
    assert 'hello' not in request['url']
    assert 'test-key' not in json.dumps(request)
    if provider == 'ollama':
        assert request['json']['stream'] is False
        assert request['json']['messages'][0]['content'] == 'hello'


def test_official_auth_requires_actual_key_and_does_not_leak_to_discovered_hosts(monkeypatch):
    monkeypatch.delenv('ANTHROPIC_API_KEY', raising=False)
    agent = {'provider': 'anthropic', 'endpoint': 'https://api.anthropic.com', 'model': 'fixture-model'}
    assert construct_agent_request(agent, 'hello') is None
    monkeypatch.setenv('ANTHROPIC_API_KEY', 'fixture-private-key')
    request = construct_agent_request(agent, 'hello')
    assert request['headers']['x-api-key'] == 'fixture-private-key'
    assert request['headers']['anthropic-version'] == '2023-06-01'
    agent['endpoint'] = 'https://untrusted.test'
    assert 'x-api-key' not in construct_agent_request(agent, 'hello')['headers']


def test_explicit_env_credential_and_gemini_body(monkeypatch):
    monkeypatch.setenv('LAB_TOKEN', 'fixture-private-key')
    agent = {'provider': 'gemini', 'endpoint': 'https://fixture.test/v1beta/models/fixture-model:generateContent',
             'api_key_env': 'LAB_TOKEN'}
    request = construct_agent_request(agent, 'hello')
    assert request['headers']['x-goog-api-key'] == 'fixture-private-key'
    assert request['json']['contents'][0]['parts'][0]['text'] == 'hello'
    assert extract_response_text('{"message":{"role":"assistant","content":"hello"}}') == 'hello'


@pytest.mark.asyncio
async def test_unsupported_and_missing_models_skip_without_probes():
    engine = SecurityTestEngine()
    engine.prompt_tester.test_agent = AsyncMock()
    for provider in ('unknown', 'ollama'):
        result = await engine._test_single_agent({'id': 'fixture', 'name': 'fixture',
                     'provider': provider, 'endpoint': 'https://fixture.test'})
        assert result['status'] == 'skipped'
        assert result['overall_risk_score'] is None
    engine.prompt_tester.test_agent.assert_not_called()


@pytest.mark.asyncio
async def test_env_credential_not_persisted_even_if_echoed(monkeypatch):
    monkeypatch.setenv('LAB_TOKEN', 'fixture-private-key')
    agent = {'id': 'fixture', 'name': 'fixture', 'provider': 'vllm', 'model': 'fixture-model',
             'endpoint': 'https://fixture.test/v1/models', 'api_key_env': 'LAB_TOKEN'}
    discovery = AsyncMock()
    security = AsyncMock()
    security.test_agents.return_value = [{'agent_id': 'fixture', 'status': 'partial',
        'vulnerabilities': [{'vulnerability_type': 'fixture', 'description': 'fixture-private-key'}]}]
    result = await run_pipeline(discovery, security, AsyncMock(), None, 'security_only', agents=[agent])
    assert 'fixture-private-key' not in json.dumps(result)
    assert 'api_key_env' not in json.dumps(result)
    assert result['agents'][0]['model'] == 'fixture-model'


@pytest.mark.parametrize('suffix,version', [('/v1', 'v1'), ('/v1/', 'v1'),
    ('/v1/models', 'v1'), ('/v1beta', 'v1beta'), ('/v1beta/models', 'v1beta')])
def test_gemini_base_preserves_api_version_and_proxy_prefix(suffix, version):
    agent = {'provider': 'gemini', 'endpoint': 'https://fixture.test/proxy' + suffix,
             'model': 'fixture-model'}
    request = construct_agent_request(agent, 'hello')
    assert request['url'] == f'https://fixture.test/proxy/{version}/models/fixture-model:generateContent'


@pytest.mark.parametrize('model', ['different-model', 7])
def test_gemini_conflicting_explicit_model_rejected(model):
    agent = {'provider': 'gemini', 'endpoint': 'https://fixture.test/v1/models/fixture-model:generateContent',
             'model': model}
    assert construct_agent_request(agent, 'hello') is None


def test_gemini_matching_prefixed_model_and_incomplete_route():
    agent = {'provider': 'gemini', 'endpoint': 'https://fixture.test/v1/models/fixture-model:generateContent',
             'model': 'models/fixture-model'}
    assert construct_agent_request(agent, 'hello')['url'] == agent['endpoint']
    agent['endpoint'] = 'https://fixture.test/v1/:generateContent'
    assert construct_agent_request(agent, 'hello') is None


@pytest.mark.asyncio
async def test_gemini_model_conflict_skips_without_probes_or_score():
    engine = SecurityTestEngine()
    engine.prompt_tester.test_agent = AsyncMock()
    result = await engine._test_single_agent({'id': 'test', 'name': 'Test', 'provider': 'gemini',
        'endpoint': 'https://fixture.test/v1/models/actual-model:generateContent', 'model': 'different-model'})
    assert result['status'] == 'skipped'
    assert result['overall_risk_score'] is None
    engine.prompt_tester.test_agent.assert_not_called()
