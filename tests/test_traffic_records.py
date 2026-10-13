import json

import pytest

from src.core.transport import ScanBudget, scan_transport
from src.discovery.traffic_analyzer import TrafficAnalyzer


@pytest.mark.parametrize('url', [
    'https://api.openai.com.evil.example/v1/chat/completions',
    'https://evil.example/api.openai.com/v1/chat/completions',
    'https://evil.example/?url=https://api.openai.com/v1/chat/completions',
    'https://api.openai.com@evil.example/v1/chat/completions',
    'https://proxy.example/v1/chat/completions',
    'https://api.openai.com:bad/v1/chat/completions',
])
def test_spoofed_authority_and_shared_paths_do_not_identify_provider(url):
    assert TrafficAnalyzer()._match_url_to_provider(url) is None


@pytest.mark.parametrize('url,provider', [
    ('https://API.OPENAI.COM/v1/responses', 'openai'),
    ('https://lab.openai.azure.com/openai/deployments/test', 'azure_openai'),
    ('https://us-central1-aiplatform.googleapis.com/v1/projects/p', 'google_ai'),
    ('http://[::1]:11434/api/chat', 'ollama'),
    ('https://api.mistral.ai/v1/chat/completions', 'mistral'),
])
def test_provider_matches_explicit_authority(url, provider):
    assert TrafficAnalyzer()._match_url_to_provider(url) == provider


@pytest.mark.asyncio
@pytest.mark.parametrize('suffix', ['.har', '.json', '.jsonl', '.log'])
async def test_one_request_count_and_safe_stable_identity(tmp_path, suffix):
    path = tmp_path / ('requests' + suffix)
    url = 'https://user:synthetic-password@api.openai.com/v1/chat/completions?api_key=synthetic-key#secret'
    record = {'request': {'url': url, 'method': 'POST'}}
    if suffix == '.har':
        content = json.dumps({'log': {'entries': [record, record]}})
    elif suffix == '.json':
        content = json.dumps([record, record])
    elif suffix == '.jsonl':
        content = '\n'.join([json.dumps(record)] * 2)
    else:
        content = '\n'.join([f'"POST {url} HTTP/1.1" 200'] * 2)
    path.write_text(content)
    scanner = TrafficAnalyzer()
    result = await scanner.analyze_traffic(str(path))
    assert len(result) == 1
    assert result[0]['metadata']['total_api_calls'] == 2
    assert result[0]['metadata']['methods'] == ['POST']
    assert result[0]['endpoint'] == 'https://api.openai.com/v1/chat/completions'
    assert 'synthetic-' not in json.dumps(result)
    assert 'internet_facing' not in result[0]['metadata']
    assert await scanner.analyze_traffic(str(path)) == result


@pytest.mark.asyncio
async def test_endpoint_identity_separates_resources_and_ignores_mentions(tmp_path):
    path = tmp_path / 'requests.log'
    path.write_text('api.openai.com mentioned by a user\n'
                    '"POST https://api.openai.com/v1/responses HTTP/1.1" 200\n'
                    '"POST https://api.openai.com/v1/embeddings HTTP/1.1" 200\n')
    result = await TrafficAnalyzer().analyze_traffic(str(path))
    assert len(result) == 2
    assert len({item['id'] for item in result}) == 2
    assert sum(item['metadata']['total_api_calls'] for item in result) == 2


@pytest.mark.asyncio
async def test_bad_file_retains_valid_file_and_marks_scan_incomplete(tmp_path):
    (tmp_path / 'a.json').write_text('{bad')
    (tmp_path / 'b.har').write_text(json.dumps({'log': {'entries': [
        {'request': {'url': 'https://api.anthropic.com/v1/messages'}}]}}))
    budget = ScanBudget()
    with scan_transport(budget):
        result = await TrafficAnalyzer().analyze_traffic(str(tmp_path))
    assert budget.failures == 1
    assert result[0]['provider'] == 'anthropic'


@pytest.mark.asyncio
async def test_bounded_read_does_not_turn_oversized_file_into_empty_success(tmp_path, monkeypatch):
    monkeypatch.setattr('src.discovery.traffic_analyzer.MAX_FILE_BYTES', 10)
    (tmp_path / 'requests.har').write_text('x' * 11)
    budget = ScanBudget()
    with scan_transport(budget):
        assert await TrafficAnalyzer().analyze_traffic(str(tmp_path)) == []
    assert budget.failures == 1


@pytest.mark.asyncio
async def test_missing_source_is_explicit_without_scan_context(tmp_path):
    with pytest.raises(ValueError, match='incomplete'):
        await TrafficAnalyzer().analyze_traffic(str(tmp_path / 'absent'))
