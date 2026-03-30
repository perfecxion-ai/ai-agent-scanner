"""
Shared request construction logic for AI agent API interaction.

Used by security testing modules to construct appropriate HTTP requests
based on the agent's provider type.
"""

from typing import Dict, Any, Optional
from urllib.parse import urljoin, urlencode


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
            'url': urljoin(endpoint, '/v1/chat/completions'),
            'headers': {
                'Content-Type': 'application/json',
                'Authorization': 'Bearer test-key'
            },
            'json': {
                'model': 'gpt-3.5-turbo',
                'messages': [{'role': 'user', 'content': payload}],
                'max_tokens': 100
            }
        }

    # Anthropic Claude-style APIs
    elif 'anthropic' in provider or 'claude' in endpoint.lower():
        return {
            'method': 'POST',
            'url': urljoin(endpoint, '/v1/messages'),
            'headers': {
                'Content-Type': 'application/json',
                'x-api-key': 'test-key',
                'anthropic-version': '2023-06-01'
            },
            'json': {
                'model': 'claude-3-sonnet-20240229',
                'max_tokens': 100,
                'messages': [{'role': 'user', 'content': payload}]
            }
        }

    # Google/Gemini-style APIs
    elif 'google' in provider or 'gemini' in endpoint.lower():
        return {
            'method': 'POST',
            'url': urljoin(endpoint, '/v1/models/gemini-pro:generateContent'),
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
        return {
            'method': 'GET',
            'url': f"{endpoint}?{urlencode({'query': payload, 'limit': 100})}"
        }
