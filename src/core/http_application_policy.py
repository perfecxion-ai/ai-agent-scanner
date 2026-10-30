"""Pure public contract for one explicitly configured HTTP JSON application."""

from functools import lru_cache
import hashlib
import ipaddress
import json
import math
import re
from urllib.parse import urlsplit, urlunsplit

from yarl import URL

from src.core.prompt_catalog import candidate_payloads
from src.core.request_provenance import MAX_REQUEST_BODY, RequestEvidence


HTTP_OBJECTIVE = 'protected-prompt-disclosure-v1'
HTTP_CONTRACT_VERSION = '1.0'
HTTP_PUBLIC_FIELDS = ('http_target', 'http_target_binding', 'assessment_objective',
                      'assessment_contract_version')
HTTP_PROMPT_RULES = tuple('prompt_injection.' + category for category in candidate_payloads())
HTTP_SOURCE_VERSION = '3.0'
HTTP_RECEIPT_FIELD = 'http_target_binding'
HTTP_ERROR = 'HTTP application configuration or evidence is invalid'
HTTP_FAILURE_REASONS = {
    'target_authentication_denied': 'The application denied the configured authentication.',
    'target_route_not_found': 'The configured POST route was not found.',
    'target_response_failed': 'The application returned an unsuccessful HTTP status.',
    'target_scope_refused': 'Transport policy refused the application target.',
    'target_tls_untrusted': 'TLS certificate verification failed.',
    'target_unreachable': 'The application connection failed.',
    'target_request_timeout': 'The application request deadline expired.',
    'response_invalid_json': 'The response was not supported bounded JSON.',
    'response_error_envelope': 'The application returned a JSON error envelope.',
    'response_selector_missing': 'The configured response pointer did not exist.',
    'response_selector_type': 'The configured response pointer did not select a string.',
    'response_selector_empty': 'The configured response text was empty.',
    'response_too_large': 'The response exceeded the configured byte limit.',
    'request_provenance_invalid': 'The complete outbound request did not match the configured protected test.',
}
MAX_RESPONSE_BYTES = 16 * 1024 * 1024
_FIELDS = frozenset({'adapter_id', 'adapter_version', 'endpoint', 'method', 'request_prompt_field',
                     'response_text_pointer', 'auth_scheme', 'principal_label', 'context_label', 'session_mode'})
HTTP_PUBLIC_DESCRIPTORS = (
    *HTTP_PUBLIC_FIELDS, *sorted(_FIELDS), HTTP_OBJECTIVE, 'http-json-prompt-source-v3',
    'fresh-per-prompt-v1', 'explicit-http-profile', 'prepared_http_application', 'http-json-target-v1',
    *HTTP_FAILURE_REASONS, *HTTP_FAILURE_REASONS.values(),
)
_HEX64 = re.compile(r'[0-9a-f]{64}\Z')
_INDEX = re.compile(r'0|[1-9][0-9]*\Z')


def _invalid():
    return ValueError(HTTP_ERROR)


def _text(value, maximum, *, blank=False):
    if (type(value) is not str or len(value) > maximum or not blank and not value
            or value != value.strip() or any(ord(char) < 32 or ord(char) == 127 for char in value)
            or '[redact' in value.casefold()):
        raise _invalid()
    return value


def canonical_http_endpoint(value):
    _text(value, 4096)
    if not value.isascii() or any(mark in value for mark in ('?', '#', '\\', '%')):
        raise _invalid()
    try:
        parts = urlsplit(value)
        if (parts.scheme not in {'http', 'https'} or not parts.hostname
                or parts.username is not None or parts.password is not None
                or parts.port is not None and not 1 <= parts.port <= 65535
                or any(piece in {'.', '..'} for piece in parts.path.split('/'))
                or URL(value).raw_path != (parts.path or '/')):
            raise _invalid()
        host = parts.hostname.lower()
        try:
            host = str(ipaddress.ip_address(host))
        except ValueError:
            if not re.fullmatch(r'[a-z0-9.-]+', host) or host.endswith('.'):
                raise _invalid() from None
        if ':' in host:
            host = '[' + host + ']'
        return urlunsplit((parts.scheme, host + ':' + str(parts.port or (
            443 if parts.scheme == 'https' else 80)), parts.path or '/', '', ''))
    except (TypeError, ValueError, UnicodeError):
        raise _invalid() from None


def pointer_parts(pointer):
    _text(pointer, 256)
    if len(pointer.encode('utf-8')) > 256 or not pointer.startswith('/'):
        raise _invalid()
    parts = pointer[1:].split('/')
    if len(parts) > 8 or any(re.search(r'~(?![01])', part) for part in parts):
        raise _invalid()
    return tuple(part.replace('~1', '/').replace('~0', '~') for part in parts)


def validate_http_target(descriptor):
    if type(descriptor) is not dict or set(descriptor) != _FIELDS:
        raise _invalid()
    if any(descriptor.get(key) != value for key, value in (
            ('adapter_id', 'http-json'), ('adapter_version', '1.0'),
            ('method', 'POST'), ('session_mode', 'fresh-per-prompt-v1'))):
        raise _invalid()
    result = dict(descriptor)
    result['endpoint'] = canonical_http_endpoint(descriptor['endpoint'])
    field = _text(descriptor['request_prompt_field'], 128)
    if len(field.encode('utf-8')) > 512:
        raise _invalid()
    pointer_parts(descriptor['response_text_pointer'])
    for name in ('principal_label', 'context_label'):
        _text(descriptor[name], 128)
    if type(descriptor['auth_scheme']) is not str or descriptor['auth_scheme'] not in {'none', 'bearer'}:
        raise _invalid()
    if descriptor['auth_scheme'] == 'none' and descriptor['principal_label'] != 'anonymous':
        raise _invalid()
    if descriptor['auth_scheme'] == 'bearer' and urlsplit(result['endpoint']).scheme != 'https':
        try:
            if not ipaddress.ip_address(urlsplit(result['endpoint']).hostname).is_loopback:
                raise _invalid()
        except ValueError:
            raise _invalid() from None
    return result


def http_target_binding(descriptor):
    public = validate_http_target(descriptor)
    encoded = json.dumps(['http-json-target-v1', public], sort_keys=True, ensure_ascii=True,
                         separators=(',', ':'), allow_nan=False).encode('ascii')
    return hashlib.sha256(encoded).hexdigest()


def public_http_agent(descriptor, name='HTTP JSON application'):
    public = validate_http_target(descriptor)
    binding = http_target_binding(public)
    return {'id': binding, 'name': _text(name, 255), 'type': 'application', 'provider': 'http-json',
            'model': None, 'endpoint': public['endpoint'], 'discovery_method': 'explicit-http-profile',
            'metadata': {}, 'http_target': public, 'http_target_binding': binding,
            'evidence_context_id': 'http-json-v1:' + binding,
            'assessment_objective': HTTP_OBJECTIVE, 'assessment_contract_version': HTTP_CONTRACT_VERSION}


def is_http_agent(agent):
    if not isinstance(agent, dict):
        return False
    provider = agent.get('provider')
    return (isinstance(provider, str) and provider.strip().casefold() == 'http-json'
            or any(name in agent for name in HTTP_PUBLIC_FIELDS))


def validate_http_agent(agent):
    if (type(agent) is not dict or agent.get('provider') != 'http-json'
            or 'model' not in agent or agent['model'] is not None
            or agent.get('assessment_objective') != HTTP_OBJECTIVE
            or agent.get('assessment_contract_version') != HTTP_CONTRACT_VERSION):
        raise _invalid()
    public = validate_http_target(agent.get('http_target'))
    binding = http_target_binding(public)
    if (agent.get('http_target') != public or agent.get('http_target_binding') != binding
            or agent.get('agent_id', agent.get('id')) != binding
            or agent.get('endpoint') != public['endpoint']
            or agent.get('evidence_context_id') != 'http-json-v1:' + binding):
        raise _invalid()
    return public


def http_public_fields(agent):
    if not is_http_agent(agent):
        return {}
    validate_http_agent(agent)
    return {name: agent[name] for name in HTTP_PUBLIC_FIELDS}


def http_views_match(agent, security):
    if not is_http_agent(agent) and not is_http_agent(security):
        return True
    try:
        return (validate_http_agent(agent) == validate_http_agent(security)
                and http_report_coverage_matches(agent) and http_report_coverage_matches(security) and all(
            agent.get(name) == security.get(name) for name in (
                *HTTP_PUBLIC_FIELDS, 'provider', 'model', 'endpoint', 'evidence_context_id')))
    except (TypeError, ValueError, KeyError):
        return False


def http_report_coverage_matches(asset):
    """Persisted views account for all selected rules, including unfinished ones."""
    try:
        rows = [*asset.get('checks', []), *asset.get('check_evidence', [])]
        return {row['rule_id'] for row in rows} == set(HTTP_PROMPT_RULES)
    except (TypeError, KeyError):
        return False


def objective_rules(value=None):
    if value is None:
        return None
    if value != HTTP_OBJECTIVE:
        raise _invalid()
    return HTTP_PROMPT_RULES


def _public_strings(value):
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for key, item in value.items():
            yield from _public_strings(key)
            yield from _public_strings(item)
    elif isinstance(value, (tuple, list)):
        for item in value:
            yield from _public_strings(item)


def validate_http_public_privacy(public, protected_values):
    reserved = [HTTP_ERROR, HTTP_OBJECTIVE, HTTP_CONTRACT_VERSION, HTTP_SOURCE_VERSION, HTTP_PUBLIC_DESCRIPTORS,
                *_FIELDS, *HTTP_PUBLIC_FIELDS, *HTTP_PROMPT_RULES, 'http-json-v1:',
                'protected_system_canary_match', '[GENERATED_TEXT_OMITTED]',
                'assessment_objective', 'check_evidence_schema_version', 'check_evidence',
                'source_version', 'http_target_binding', 'requests_attempted', 'responses_evaluated',
                HTTP_FAILURE_REASONS]
    material = list(_public_strings([public, reserved, candidate_payloads()]))
    for value in protected_values:
        if isinstance(value, str) and value and any(value.casefold() in item.casefold() for item in material):
            raise _invalid()


def _pairs(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise _invalid()
        value[key] = item
    return value


def _constant(_):
    raise _invalid()


def _finite_float(raw):
    value = float(raw)
    if not math.isfinite(value):
        raise _invalid()
    return value


def _bounded_int(raw):
    if len(raw) > 256:
        raise _invalid()
    return int(raw)


def strict_http_json(raw):
    if isinstance(raw, str):
        if len(raw) > MAX_RESPONSE_BYTES:
            raise _invalid()
        raw = raw.encode('utf-8')
    if type(raw) is not bytes or len(raw) > MAX_RESPONSE_BYTES:
        raise _invalid()
    text = raw.decode('utf-8')
    depth, nodes, quoted, escaped, scalar = 0, 0, False, False, False
    # Bound container depth and lexical values before allocating JSON objects.
    # json.loads still supplies the authoritative grammar/type validation.
    for char in text:
        if quoted:
            if escaped:
                escaped = False
            elif char == '\\':
                escaped = True
            elif char == '"':
                quoted = False
            continue
        if char == '"':
            quoted, scalar = True, False
            nodes += 1
        elif char in '[{':
            depth += 1
            nodes += 1
            scalar = False
        elif char in ']}':
            depth -= 1
            scalar = False
        elif char in ',:' or char.isspace():
            scalar = False
        elif not scalar:
            nodes += 1
            scalar = True
        if depth < 0 or depth > 16 or nodes > 8192:
            raise _invalid()
    if quoted or depth:
        raise _invalid()
    return json.loads(text, object_pairs_hook=_pairs, parse_constant=_constant,
                      parse_float=_finite_float, parse_int=_bounded_int)


def extract_http_json_generated(raw, descriptor):
    try:
        public = validate_http_target(descriptor)
        value = strict_http_json(raw)
        if isinstance(value, dict) and 'error' in value and value['error'] is not None:
            return ''
        for part in pointer_parts(public['response_text_pointer']):
            if isinstance(value, dict):
                value = value[part]
            elif isinstance(value, list) and _INDEX.fullmatch(part) and len(part) <= 8:
                value = value[int(part)]
            else:
                return ''
        return value if isinstance(value, str) and value.strip() else ''
    except (ValueError, TypeError, KeyError, IndexError, UnicodeError, OverflowError, RecursionError):
        return ''


def http_response_failure(raw, descriptor, status):
    if status in {401, 403}:
        return 'target_authentication_denied'
    if status == 404:
        return 'target_route_not_found'
    if not 200 <= status < 300:
        return 'target_response_failed'
    try:
        public = validate_http_target(descriptor)
        value = strict_http_json(raw)
        if isinstance(value, dict) and 'error' in value and value['error'] is not None:
            return 'response_error_envelope'
        for part in pointer_parts(public['response_text_pointer']):
            if isinstance(value, dict):
                if part not in value:
                    return 'response_selector_missing'
                value = value[part]
            elif isinstance(value, list) and _INDEX.fullmatch(part) and len(part) <= 8:
                if int(part) >= len(value):
                    return 'response_selector_missing'
                value = value[int(part)]
            else:
                return 'response_selector_missing'
        if not isinstance(value, str):
            return 'response_selector_type'
        return 'response_selector_empty' if not value.strip() else None
    except (ValueError, TypeError, KeyError, IndexError, UnicodeError, OverflowError, RecursionError):
        return 'response_invalid_json'


def http_prompt_probe_version(definition, agent):
    validate_http_agent(agent)
    identity = [definition, 'http-json', None,
                {'contract': 'http-json-prompt-source-v3', 'http_target_binding': agent['http_target_binding']}]
    return '1:' + hashlib.sha256(json.dumps(identity, sort_keys=True).encode()).hexdigest()


@lru_cache(maxsize=128)
def _http_probes(binding):
    values = {}
    for category, payloads in candidate_payloads().items():
        definition = {'semantics': 'nondisclosure-inconclusive-v2', 'payloads': payloads}
        identity = [definition, 'http-json', None,
                    {'contract': 'http-json-prompt-source-v3', 'http_target_binding': binding}]
        version = '1:' + hashlib.sha256(json.dumps(identity, sort_keys=True).encode()).hexdigest()
        values[('prompt_injection.' + category, version)] = tuple(payloads)
    return values


def http_prompt_payloads(rule, probe, version, agent):
    try:
        validate_http_agent(agent)
        if rule not in HTTP_PROMPT_RULES or probe != rule + '.sample' or not _HEX64.fullmatch(version[2:]):
            return None
        return _http_probes(agent['http_target_binding']).get((rule, version))
    except (TypeError, ValueError, KeyError):
        return None


def http_json_request_matches_capture(evidence, agent, payload, credential):
    try:
        public = validate_http_agent(agent)
        if (not isinstance(evidence, RequestEvidence) or evidence.method != 'POST'
                or not isinstance(evidence.body, bytes) or len(evidence.body) > MAX_REQUEST_BODY
                or evidence.url != str(URL(public['endpoint']))
                or strict_http_json(evidence.body) != {public['request_prompt_field']: payload}):
            return False
        headers = {}
        allowed = {'host', 'content-type', 'content-length', 'accept', 'accept-encoding', 'user-agent', 'authorization'}
        for name, value in evidence.headers:
            name = name.casefold()
            if name in headers or name not in allowed:
                return False
            headers[name] = value
        if headers.get('content-type') != 'application/json' or headers.get('host') != URL(evidence.url).raw_authority:
            return False
        authorization = headers.get('authorization')
        return (authorization is None and credential is None if public['auth_scheme'] == 'none'
                else isinstance(credential, str) and authorization == 'Bearer ' + credential)
    except (ValueError, TypeError, KeyError, AttributeError, UnicodeError, OverflowError, RecursionError):
        return False
