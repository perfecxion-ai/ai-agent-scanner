"""Provider-specific request adapters with explicit models and transient credentials."""

import json
import os
import re
from urllib.parse import urlsplit, urlunsplit, quote, unquote
from yarl import URL
from src.core.redaction import contains_literal
from src.core.request_provenance import known_request_excludes_canary
from src.core.tenant_evidence import get_tenant_evidence


SUPPORTED_PROVIDERS = {'openai', 'openai-compatible', 'vllm', 'ollama', 'anthropic', 'google', 'gemini'}
_CLOUD = {
    'api.openai.com': 'OPENAI_API_KEY',
    'api.anthropic.com': 'ANTHROPIC_API_KEY',
    'generativelanguage.googleapis.com': 'GEMINI_API_KEY',
}
_DEFAULT_KEY = object()


def resolve_api_key(agent):
    """Resolve explicit environment references; automatic keys stay on official HTTPS hosts."""
    context = get_tenant_evidence(agent)
    if context is not None:
        return context.tested_api_key
    if 'tenant_evidence' in agent:
        return None
    endpoint = urlsplit(agent.get('endpoint') or '')
    reference = agent.get('api_key_env')
    if reference:
        if not isinstance(reference, str) or not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*', reference):
            return None
        return os.environ.get(reference) or None
    if endpoint.scheme == 'https' and endpoint.port in (None, 443):
        variable = _CLOUD.get(endpoint.hostname)
        return os.environ.get(variable) or None if variable else None
    return None


def missing_credential_reason(agent):
    """Describe missing declared credentials without exposing references or URLs."""
    if not resolve_api_key(agent):
        if agent.get('api_key_env'):
            return 'Required credential environment reference is unset or empty'
        if urlsplit(agent.get('endpoint') or '').hostname in _CLOUD:
            return 'Required provider credential is unavailable; configure the provider API key'
    return None


def _route(endpoint, suffix, known):
    parts = urlsplit(endpoint)
    path = parts.path.rstrip('/')
    for ending in sorted(known, key=len, reverse=True):
        if path.endswith('/' + ending):
            path = path[:-len(ending)].rstrip('/')
            break
    else:
        version = suffix.split('/', 1)[0]
        if path.endswith('/' + version):
            path = path[:-(len(version) + 1)]
    return urlunsplit(parts._replace(path=path + '/' + suffix))


def extract_response_text(response_text):
    """Extract generated text without interpreting response metadata as model output."""
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
        if isinstance(body.get('message'), dict):
            content = body['message'].get('content')
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


def construct_agent_request(agent, payload, *, api_key=_DEFAULT_KEY):
    """Return a supported POST request or None when execution lacks required configuration."""
    context = get_tenant_evidence(agent)
    if 'tenant_evidence' in agent and context is None:
        return None
    markers = [agent.get('system_prompt_canary')]
    if context is not None:
        markers.extend((context.owner_canary, context.tested_canary))
    markers = [marker for marker in markers if isinstance(marker, str) and marker]
    if isinstance(payload, str) and any(marker.casefold() in payload.casefold() for marker in markers):
        return None
    endpoint = agent.get('endpoint')
    provider = str(agent.get('provider', '')).lower()
    if not endpoint or provider not in SUPPORTED_PROVIDERS:
        return None
    parts = urlsplit(endpoint)
    if parts.scheme not in {'http', 'https'} or not parts.hostname or parts.username or parts.password or parts.fragment:
        return None
    model = agent.get('model')
    if provider in {'google', 'gemini'} and parts.path.endswith(':generateContent'):
        match = re.search(r'/models/([^/]+):generateContent$', parts.path)
        if not match:
            return None
        endpoint_model = unquote(match.group(1))
        if model is not None and (not isinstance(model, str) or model.removeprefix('models/') != endpoint_model):
            return None
        model = endpoint_model
    if not isinstance(model, str) or not model.strip():
        return None
    key = resolve_api_key(agent) if api_key is _DEFAULT_KEY else api_key
    if key is not None and not isinstance(key, str):
        return None
    if agent.get('api_key_env') and not key:
        return None
    if parts.hostname in _CLOUD and (parts.scheme != 'https' or not key):
        return None
    headers = {'Content-Type': 'application/json'}
    if provider in {'openai', 'openai-compatible', 'vllm'}:
        url = _route(endpoint, 'v1/chat/completions',
                     ('v1/chat/completions', 'v1/completions', 'v1/models'))
        body = {'model': model, 'messages': [{'role': 'user', 'content': payload}], 'max_tokens': 100}
        if key:
            headers['Authorization'] = 'Bearer ' + key
    elif provider == 'ollama':
        url = _route(endpoint, 'api/chat', ('api/tags', 'api/chat', 'api/generate'))
        body = {'model': model, 'messages': [{'role': 'user', 'content': payload}],
                'stream': False, 'options': {'num_predict': 100}}
        if key:
            headers['Authorization'] = 'Bearer ' + key
    elif provider == 'anthropic':
        url = _route(endpoint, 'v1/messages', ('v1/messages', 'v1/complete'))
        body = {'model': model, 'messages': [{'role': 'user', 'content': payload}], 'max_tokens': 100}
        headers['anthropic-version'] = '2023-06-01'
        if key:
            headers['x-api-key'] = key
    else:
        if parts.path.endswith(':generateContent'):
            url = endpoint
        else:
            version_match = re.search(r'/(v1|v1beta)(?:/models)?$', parts.path.rstrip('/'))
            version = version_match.group(1) if version_match else 'v1beta'
            url = _route(endpoint, version + '/models/' + quote(model.removeprefix('models/'), safe='') + ':generateContent',
                         ('v1beta/models', 'v1/models'))
        body = {'contents': [{'role': 'user', 'parts': [{'text': payload}]}],
                'generationConfig': {'maxOutputTokens': 100}}
        if key:
            headers['x-goog-api-key'] = key
    result = {'method': 'POST', 'url': url, 'headers': headers, 'json': body}
    for protected in markers:
        if (not known_request_excludes_canary(result, protected)
                or contains_literal(result, protected) or protected in str(URL(url))
                or protected in json.dumps(result)):
            return None
    return result
