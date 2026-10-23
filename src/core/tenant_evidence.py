"""Private, immutable tenant controls resolved once per local scan."""

from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field
import json
import os
import re
import secrets
from types import MappingProxyType

from src.core.tenant_probe_policy import PUBLIC_TENANT_FIELDS, TENANT_PROVIDERS, tenant_target
from src.core.request_provenance import known_request_excludes_canary, request_excludes_canary


_ENV = re.compile(r'[A-Za-z_][A-Za-z0-9_]{0,127}\Z')
_LABEL = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z')
_MARKER = re.compile(r'[A-Za-z0-9_.~-]{16,128}\Z')
_FIELDS = {'schema_version', 'binding', 'tested_principal_authorized_for_owner', 'owner', 'tested'}
_ACTOR_FIELDS = {'tenant_ref', 'principal_ref', 'api_key_env', 'canary_env'}
_STATE = ContextVar('private_tenant_evidence', default=None)


class TenantEvidenceError(ValueError):
    """Never disclose private input values through validation errors."""

    def __init__(self):
        super().__init__('Tenant evidence is invalid, unavailable, or conflicts with public request material')


@dataclass(frozen=True, repr=False)
class TenantEvidence:
    target: object
    owner_api_key: str = field(repr=False)
    tested_api_key: str = field(repr=False)
    invalid_api_key: str = field(repr=False)
    owner_canary: str = field(repr=False)
    tested_canary: str = field(repr=False)


def reject_private_tenant_inputs(agents):
    """Server rejection is structural and never reads credential environments."""
    def forbidden(value):
        if isinstance(value, dict):
            return any(key in {'tenant_evidence', 'cross_tenant_canary'} or forbidden(item)
                       for key, item in value.items())
        if isinstance(value, (list, tuple)):
            return any(forbidden(item) for item in value)
        return False
    if forbidden(agents):
        raise TenantEvidenceError()
    return agents


def validate_tenant_input(agent, *, resolve=False, server=False):
    """Validate the local declaration without reading any environment value."""
    if server:
        reject_private_tenant_inputs(agent)
        return None
    if resolve is not False or not isinstance(agent, dict):
        raise TenantEvidenceError()
    if 'tenant_evidence' not in agent:
        return None
    try:
        envelope = agent['tenant_evidence']
        if (not isinstance(envelope, dict) or set(envelope) != _FIELDS
                or envelope['schema_version'] != '1.0'
                or envelope['tested_principal_authorized_for_owner'] is not False
                or 'cross_tenant_canary' in agent):
            raise TenantEvidenceError()
        target = tenant_target(*(agent.get(key) for key in
                                ('endpoint', 'provider', 'model', 'evidence_context_id')))
        binding = envelope['binding']
        if (not isinstance(binding, dict) or set(binding) != set(target)
                or tenant_target(**binding) != target
                or agent.get('provider') not in TENANT_PROVIDERS
                or not isinstance(agent.get('id'), str) or not 0 < len(agent['id']) <= 256):
            raise TenantEvidenceError()
        for actor in ('owner', 'tested'):
            value = envelope[actor]
            if not isinstance(value, dict) or set(value) != _ACTOR_FIELDS:
                raise TenantEvidenceError()
            if any(not isinstance(value[key], str) or not _LABEL.fullmatch(value[key])
                   for key in ('tenant_ref', 'principal_ref')):
                raise TenantEvidenceError()
            if any(not isinstance(value[key], str) or not _ENV.fullmatch(value[key])
                   or value[key] == 'SCAN_EVIDENCE_PROFILES_FILE'
                   for key in ('api_key_env', 'canary_env')):
                raise TenantEvidenceError()
        owner, tested = envelope['owner'], envelope['tested']
        if (any(owner[key].casefold() == tested[key].casefold()
                for key in ('tenant_ref', 'principal_ref'))
                or len({actor[key].casefold() for actor in (owner, tested)
                        for key in ('api_key_env', 'canary_env')}) != 4
                or agent.get('api_key_env') != tested['api_key_env']):
            raise TenantEvidenceError()
        return target
    except (ValueError, TypeError, KeyError, AttributeError, OverflowError):
        raise TenantEvidenceError() from None


def _identity(agent):
    target = validate_tenant_input(agent)
    if target is None:
        return None
    return (agent['id'], json.dumps([target, agent['tenant_evidence']], sort_keys=True,
                                   separators=(',', ':'), allow_nan=False))


def get_tenant_evidence(agent):
    """Return only the current scan's exact prepared asset; never resolve values."""
    state = _STATE.get()
    if state is None:
        return None
    identities, _, _ = state
    identifier = agent.get('id') if isinstance(agent, dict) else None
    if identifier not in identities:
        return None
    identity, context = identities[identifier]
    if _identity(agent) != identity:
        raise TenantEvidenceError()
    return context


def tenant_secrets():
    """Return all pinned keys, markers and environment names for scan redaction."""
    state = _STATE.get()
    return state[1] if state is not None else ()


def guard_tenant_request(method, url, kwargs, session_headers):
    """Reject known marker transmission before any active scan request starts."""
    state = _STATE.get()
    if state is None or not state[0]:
        return
    try:
        headers = dict(session_headers or {})
        headers.update(kwargs.get('headers') or {})
        request = {'method': method, 'url': str(url), 'headers': headers}
        request.update({key: value for key, value in kwargs.items()
                        if key not in {'headers', 'timeout', 'allow_redirects', 'ssl',
                                       'trace_request_ctx', 'raise_for_status'}})
        if any(not known_request_excludes_canary(request, marker)
               for _, context in state[0].values()
               for marker in (context.owner_canary, context.tested_canary)):
            raise TenantEvidenceError()
    except (TypeError, ValueError, KeyError, AttributeError, RecursionError):
        raise TenantEvidenceError() from None


def observe_tenant_request(request_evidence):
    """Record private contamination, including incomplete transmitted requests."""
    state = _STATE.get()
    if state is None:
        return
    for identifier, (_, context) in state[0].items():
        if any(not request_excludes_canary(request_evidence, marker)
               for marker in (context.owner_canary, context.tested_canary)):
            state[2].add(identifier)


def tenant_evidence_tainted(agent):
    state = _STATE.get()
    return state is not None and agent.get('id') in state[2]


def tenant_evidence_usable(agent):
    return get_tenant_evidence(agent) is not None and not tenant_evidence_tainted(agent)


def _overlap(first, second):
    first, second = first.casefold(), second.casefold()
    return first in second or second in first


def _public(value):
    from src.core.redaction import sensitive_key
    if isinstance(value, dict):
        return {key: _public(item) for key, item in value.items() if not sensitive_key(key)}
    if isinstance(value, list):
        return [_public(item) for item in value]
    return value


@contextmanager
def tenant_evidence_context(agents):
    """Pin the complete local input set before checkpoints, reusing nested scopes."""
    agents = list(agents)
    identities = [_identity(agent) for agent in agents]
    active = _STATE.get()
    if active is not None:
        for agent, identity in zip(agents, identities):
            if identity is not None and get_tenant_evidence(agent) is None:
                raise TenantEvidenceError()
            if identity is None and agent.get('id') in active[0]:
                raise TenantEvidenceError()
        yield active[1]
        return
    configured = [(agent, identity) for agent, identity in zip(agents, identities) if identity is not None]
    if len({agent['id'] for agent, _ in configured}) != len(configured):
        raise TenantEvidenceError()
    prepared, private = {}, set()
    public = json.dumps(_public(agents), sort_keys=True, allow_nan=False).casefold()
    for agent, identity in configured:
        envelope = agent['tenant_evidence']
        references = [envelope[actor][key] for actor in ('owner', 'tested')
                      for key in ('api_key_env', 'canary_env')]
        values = [os.environ.get(reference) for reference in references]
        if any(not isinstance(value, str) or not value or len(value) > 4096
               or any(ord(char) < 33 or ord(char) > 126 for char in value) for value in values):
            raise TenantEvidenceError()
        owner_key, owner_marker, tested_key, tested_marker = values
        if (not _MARKER.fullmatch(owner_marker) or not _MARKER.fullmatch(tested_marker)
                or owner_key.casefold() == tested_key.casefold()
                or _overlap(owner_marker, tested_marker)
                or any(_overlap(marker, key) for marker in (owner_marker, tested_marker)
                       for key in (owner_key, tested_key))):
            raise TenantEvidenceError()
        invalid_key = secrets.token_urlsafe(32)
        if (invalid_key in values or any(_overlap(marker, invalid_key)
                                       for marker in (owner_marker, tested_marker))):
            raise TenantEvidenceError()
        material = (*values, *references, invalid_key)
        if any(value.casefold() in public
               or any(value.casefold() in field.casefold() for field in PUBLIC_TENANT_FIELDS)
               for value in material):
            raise TenantEvidenceError()
        context = TenantEvidence(MappingProxyType(validate_tenant_input(agent)), owner_key,
                                 tested_key, invalid_key, owner_marker, tested_marker)
        prepared[agent['id']] = (identity, context)
        private.update(material)
    token = _STATE.set((MappingProxyType(prepared), tuple(sorted(private)), set()))
    try:
        yield tenant_secrets()
    finally:
        _STATE.reset(token)


tenant_context = get_tenant_evidence
prepare_tenant_evidence = tenant_evidence_context
