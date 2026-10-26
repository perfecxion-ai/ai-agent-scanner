"""Pinned private access controls and bounded outbound request validation."""

import base64
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field
import json
import re
from types import MappingProxyType
from urllib.parse import quote, urljoin

from yarl import URL

from src.core.access_probe_policy import PROTECTED_ACCESS_PATHS
from src.core.request_provenance import (
    MAX_HEADER_COUNT, MAX_REQUEST_HEADERS, RequestEvidence, known_request_excludes_canary,
    request_excludes_canary,
)


_STATE = ContextVar('private_access_evidence', default=None)
_ENV = re.compile(r'[A-Za-z_][A-Za-z0-9_]{0,127}\Z')
_BOUND_FIELDS = ('id', 'endpoint', 'provider', 'model', 'evidence_context_id', 'api_key_env',
                 'authentication_required', 'protected_response_marker', 'protected_path_markers')
_AUTH_HEADERS = frozenset({'authorization', 'proxy-authorization', 'x-api-key', 'api-key',
                           'apikey', 'x-goog-api-key'})
_AUTOMATIC_HEADERS = frozenset({'host', 'content-length', 'connection'})


class AccessEvidenceError(ValueError):
    def __init__(self):
        super().__init__('Protected access evidence is unavailable or conflicts with request material')


@dataclass(frozen=True, repr=False)
class AccessEvidence:
    identity: str = field(repr=False)
    issued_key: str | None = field(repr=False)
    markers: tuple = field(repr=False)
    reference: str | None = field(repr=False)
    resources: tuple = field(repr=False)


def _identity(agent):
    if not isinstance(agent, dict):
        raise AccessEvidenceError()
    try:
        return json.dumps({key: agent[key] for key in _BOUND_FIELDS if key in agent},
                          sort_keys=True, allow_nan=False, separators=(',', ':'))
    except (TypeError, ValueError, OverflowError, RecursionError):
        raise AccessEvidenceError() from None


def _markers(agent):
    if not isinstance(agent, dict):
        raise AccessEvidenceError()
    values = [agent.get('protected_response_marker')]
    paths = agent.get('protected_path_markers')
    if isinstance(paths, dict):
        values.extend(paths.get(path) for path in PROTECTED_ACCESS_PATHS)
    return tuple(dict.fromkeys(value for value in values if isinstance(value, str) and value))


def _variants(value):
    raw = value.encode('utf-8')
    encoded = (base64.b64encode(raw).decode(), base64.urlsafe_b64encode(raw).decode())
    return tuple(dict.fromkeys((value, quote(value, safe=''), *encoded,
                               *(item.rstrip('=') for item in encoded))))


def get_access_evidence(agent):
    """Reuse an exact prepared declaration without reading its environment again."""
    state = _STATE.get()
    if state is None:
        return None
    identity = _identity(agent)
    context = state[0].get(agent.get('id'))
    if context is None:
        if _markers(agent):
            raise AccessEvidenceError()
        return None
    if identity != context.identity:
        raise AccessEvidenceError()
    return context


def access_evidence_usable(agent):
    context = get_access_evidence(agent)
    state = _STATE.get()
    return context is not None and context.issued_key is not None and agent.get('id') not in state[2]


def access_secrets():
    state = _STATE.get()
    return state[1] if state is not None else ()


@contextmanager
def access_evidence_context(agents):
    """Pin private values once; nested checks cannot silently rebind the scan."""
    agents = list(agents)
    active = _STATE.get()
    if active is not None:
        for agent in agents:
            get_access_evidence(agent)
        yield access_secrets()
        return
    prepared, private = {}, set()
    from src.utils.request_builder import resolve_api_key
    for agent in agents:
        markers = _markers(agent)
        if not markers:
            continue
        if (any(len(value) > 4096 for value in markers)
                or not isinstance(agent.get('id'), str) or not 1 <= len(agent['id']) <= 256
                or agent['id'] in prepared):
            raise AccessEvidenceError()
        reference = agent.get('api_key_env')
        key = resolve_api_key(agent) if isinstance(reference, str) and _ENV.fullmatch(reference) else None
        if key is not None and (not isinstance(key, str) or len(key) > 4096 or '\r' in key or '\n' in key):
            raise AccessEvidenceError()
        endpoint = agent.get('endpoint')
        try:
            resources = [str(URL(endpoint))] if isinstance(endpoint, str) else []
            paths = agent.get('protected_path_markers')
            if isinstance(paths, dict) and isinstance(endpoint, str):
                resources.extend(str(URL(urljoin(endpoint.rstrip('/'), path)))
                                 for path in PROTECTED_ACCESS_PATHS if path in paths)
        except (TypeError, ValueError):
            raise AccessEvidenceError() from None
        context = AccessEvidence(_identity(agent), key, markers, reference if isinstance(reference, str) else None,
                                 tuple(dict.fromkeys(resources)))
        prepared[agent['id']] = context
        private.update(variant for value in (*markers, key, context.reference) if value for variant in _variants(value))
    token = _STATE.set((MappingProxyType(prepared), tuple(sorted(private)), set()))
    try:
        yield access_secrets()
    finally:
        _STATE.reset(token)


def guard_access_request(method, url, kwargs, session_headers):
    """Refuse known protected-marker transmission before reserving a request."""
    state = _STATE.get()
    if state is None or not state[0]:
        return
    try:
        headers = dict(session_headers or {})
        headers.update(kwargs.get('headers') or {})
        request = {'method': method, 'url': str(url), 'headers': headers}
        request.update({key: value for key, value in kwargs.items() if key not in {
            'headers', 'timeout', 'allow_redirects', 'ssl', 'trace_request_ctx', 'raise_for_status'}})
        if any(not known_request_excludes_canary(request, variant)
               for context in state[0].values() for marker in context.markers for variant in _variants(marker)):
            raise AccessEvidenceError()
    except (TypeError, ValueError, KeyError, AttributeError, UnicodeError, RecursionError):
        raise AccessEvidenceError() from None


def observe_access_request(request_evidence):
    """An earlier transmitted marker or incomplete capture taints its controls."""
    state = _STATE.get()
    if state is None:
        return
    for identifier, context in state[0].items():
        if any(not request_excludes_canary(request_evidence, variant)
               for marker in context.markers for variant in _variants(marker)):
            state[2].add(identifier)


def _fail(agent):
    state = _STATE.get()
    if state is not None:
        state[2].add(agent.get('id') if isinstance(agent, dict) else None)
    return False


def verify_access_response(response, *, agent, endpoint, headers):
    """Authorize scalar evaluation only from an exact live captured GET request."""
    from src.core.transport import BoundedResponse
    try:
        if (not isinstance(response, BoundedResponse) or response._request_active is not True
                or not isinstance(response.body, bytes) or not access_evidence_usable(agent)):
            return _fail(agent)
        context = get_access_evidence(agent)
        actual = response._request_evidence
        if (str(URL(endpoint)) not in context.resources
                or not isinstance(actual, RequestEvidence) or actual.method != 'GET'
                or actual.url != str(URL(endpoint)) or actual.body != b''
                or not isinstance(actual.headers, tuple) or not 1 <= len(actual.headers) <= MAX_HEADER_COUNT
                or any(not isinstance(pair, tuple) or len(pair) != 2
                       or any(not isinstance(value, str) for value in pair) for pair in actual.headers)
                or sum(len(key.encode()) + len(value.encode()) for key, value in actual.headers) > MAX_REQUEST_HEADERS):
            return _fail(agent)
        expected = {key.casefold(): value for key, value in headers.items()}
        if (len(expected) != len(headers) or not all(isinstance(value, str) for value in expected.values())
                or any(key.casefold() not in expected.keys() | _AUTOMATIC_HEADERS for key, _ in actual.headers)):
            return _fail(agent)
        for key, value in expected.items():
            if [item for name, item in actual.headers if name.casefold() == key] != [value]:
                return _fail(agent)
        if ([value for key, value in actual.headers if key.casefold() == 'host'] != [URL(actual.url).raw_authority]
                or any(key.casefold() in {'cookie', 'proxy-authorization'} for key, _ in actual.headers)):
            return _fail(agent)
        lengths = [value for key, value in actual.headers if key.casefold() == 'content-length']
        connections = [value for key, value in actual.headers if key.casefold() == 'connection']
        if (lengths not in ([], ['0']) or len(connections) > 1
                or any(value.casefold() not in {'close', 'keep-alive'} for value in connections)):
            return _fail(agent)
        if any(not request_excludes_canary(actual, variant)
               for marker in context.markers for variant in _variants(marker)):
            return _fail(agent)
        # Remove only the exact selected credential-bearing header values.
        # Intentional weak candidates remain valid even when issued to the tester.
        scrubbed = RequestEvidence(actual.method, actual.url, tuple(
            (key, '' if key.casefold() in _AUTH_HEADERS and key.casefold() in expected else value)
            for key, value in actual.headers), actual.body)
        if any(not request_excludes_canary(scrubbed, variant) for variant in _variants(context.issued_key)):
            return _fail(agent)
        return True
    except (TypeError, ValueError, KeyError, AttributeError, UnicodeError, OverflowError, RecursionError):
        return _fail(agent)
