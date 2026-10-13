"""
Shared request construction logic for AI agent API interaction.

Used by security testing modules to construct appropriate HTTP requests
based on the agent's provider type.
"""

from typing import Dict, Any, Optional
import json
from urllib.parse import urlsplit, urlunsplit, parse_qsl, urlencode


def _provider_url(endpoint: str, suffix: str) -> str:
    """Preserve deployment prefixes and already complete provider routes."""
    parts = urlsplit(endpoint)
    path = parts.path.rstrip('/')
    if not path.endswith(suffix) and not path.endswith(suffix.split('/', 1)[-1]):
        path += '/' + (suffix.split('/', 1)[-1] if path.endswith('/v1') else suffix)
    return urlunsplit(parts._replace(path=path))


def extract_response_text(response_text: str) -> str:
    """Extract generated text, excluding provider metadata and error envelopes."""
    try:
        body = json.loads(response_text)
    except (ValueError, TypeError):
        return response_text
    if not isinstance(body, dict) or 'error' in body:
        return ''
    try:
        if 'choices' in body:
            content = body['choices'][0]['message']['content']
            return content if isinstance(content, str) else ''
        if isinstance(body.get('content'), list):
            return '\n'.join(block['text'] for block in body['content'] if block.get('type') == 'text')
        if 'candidates' in body:
            return '\n'.join(part['text'] for part in body['candidates'][0]['content']['parts'] if 'text' in part)
        for key in ('response', 'message', 'text', 'output'):
            if isinstance(body.get(key), str):
                return body[key]
    except (KeyError, IndexError, TypeError, AttributeError):
        pass
    return ''


def construct_agent_request(agent: Dict[str, Any], payload: str) -> Optional[Dict[str, Any]]:
    """
    Construct an appropriate HTTP request for the given agent type.

    Args:
        agent: Agent dict with 'endpoint' and 'provider' keys.
        payload: The prompt/payload string to send.

    Returns:
        Request dict with method, url, headers, and json/data, or None if
        no endpoint is available.
    """
    endpoint = agent.get('endpoint')
    provider = agent.get('provider', '').lower()

    if not endpoint:
        return None

    # OpenAI-style APIs
    if 'openai' in provider or 'gpt' in endpoint.lower():
        return {
            'method': 'POST',
            'url': _provider_url(endpoint, 'v1/chat/completions'),
            'headers': {
                'Content-Type': 'application/json',
                'Authorization': 'Bearer test-key'
            },
            'json': {
                'model': agent.get('model', 'gpt-3.5-turbo'),
                'messages': [{'role': 'user', 'content': payload}],
                'max_tokens': 100
            }
        }

    # Anthropic Claude-style APIs
    elif 'anthropic' in provider or 'claude' in endpoint.lower():
        return {
            'method': 'POST',
            'url': _provider_url(endpoint, 'v1/messages'),
            'headers': {
                'Content-Type': 'application/json',
                'x-api-key': 'test-key',
                'anthropic-version': '2023-06-01'
            },
            'json': {
                'model': agent.get('model', 'claude-3-sonnet-20240229'),
                'max_tokens': 100,
                'messages': [{'role': 'user', 'content': payload}]
            }
        }

    # Google/Gemini-style APIs
    elif 'google' in provider or 'gemini' in endpoint.lower():
        return {
            'method': 'POST',
            'url': endpoint if ':generateContent' in endpoint else _provider_url(endpoint, 'v1/models/gemini-pro:generateContent'),
            'headers': {
                'Content-Type': 'application/json',
                'x-goog-api-key': 'test-key'
            },
            'json': {
                'contents': [{'parts': [{'text': payload}]}]
            }
        }

    # Generic chat endpoint
    elif any(path in endpoint.lower() for path in ['/chat', '/api/chat', '/generate']):
        return {
            'method': 'POST',
            'url': endpoint,
            'headers': {'Content-Type': 'application/json'},
            'json': {
                'message': payload,
                'max_tokens': 100
            }
        }

    # Generic GET endpoint with query parameter (URL-encoded to prevent
    # payload corruption and access log leakage of raw attack strings)
    else:
        parts = urlsplit(endpoint)
        query = parse_qsl(parts.query, keep_blank_values=True)
        query = [(key, value) for key, value in query if key not in ('query', 'limit')]
        query.extend([('query', payload), ('limit', '100')])
        return {
            'method': 'GET',
            'url': urlunsplit(parts._replace(query=urlencode(query)))
        }
