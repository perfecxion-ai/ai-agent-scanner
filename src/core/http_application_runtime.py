"""Explicit memory-only prepared HTTP targets, without environment or file reads."""

from contextlib import contextmanager
from contextvars import ContextVar
from copy import deepcopy
from dataclasses import dataclass, field
import re

from src.core.http_application_policy import (
    HTTP_ERROR, validate_http_agent, validate_http_public_privacy,
)


_prepared = ContextVar('prepared_http_application', default=None)
_MARKER = re.compile(r'[A-Za-z0-9_.~-]{16,128}\Z')


@dataclass(frozen=True, repr=False)
class PreparedHTTPJSONTarget:
    _agent: dict = field(repr=False)
    credential: str | None = field(repr=False)
    canary: str = field(repr=False)
    private_values: tuple = field(default=(), repr=False)

    @property
    def agent(self):
        return dict(deepcopy(self._agent), system_prompt_canary=self.canary)


def prepare_http_target(agent, *, credential=None, canary, private_values=()):
    descriptor = validate_http_agent(agent)
    allowed = {'id', 'name', 'type', 'provider', 'model', 'endpoint', 'discovery_method',
               'metadata', 'http_target', 'http_target_binding', 'evidence_context_id',
               'assessment_objective', 'assessment_contract_version'}
    if set(agent) - allowed or agent.get('metadata', {}) != {}:
        raise ValueError(HTTP_ERROR)
    if (not isinstance(canary, str) or not _MARKER.fullmatch(canary)
            or not isinstance(private_values, (tuple, list))
            or any(not isinstance(value, str) for value in private_values)):
        raise ValueError(HTTP_ERROR)
    if descriptor['auth_scheme'] == 'none':
        if credential is not None:
            raise ValueError(HTTP_ERROR)
    elif (not isinstance(credential, str) or not 16 <= len(credential) <= 4096
          or not all(33 <= ord(char) <= 126 for char in credential)):
        raise ValueError(HTTP_ERROR)
    protected = [canary, credential, *private_values]
    validate_http_public_privacy(agent, protected)
    if credential and canary.casefold() in credential.casefold():
        raise ValueError(HTTP_ERROR)
    return PreparedHTTPJSONTarget(deepcopy(agent), credential, canary, tuple(private_values))


@contextmanager
def http_application_context(prepared):
    if not isinstance(prepared, PreparedHTTPJSONTarget):
        raise ValueError(HTTP_ERROR)
    token = _prepared.set(prepared)
    try:
        yield prepared
    finally:
        _prepared.reset(token)


def get_http_target(agent):
    prepared = _prepared.get()
    if prepared is None:
        return None
    try:
        validate_http_agent(agent)
        expected = prepared.agent
        if (any(agent.get(name) != expected.get(name) for name in (
                'id', 'provider', 'model', 'endpoint', 'evidence_context_id', 'http_target',
                'http_target_binding', 'assessment_objective', 'assessment_contract_version'))
                or agent.get('system_prompt_canary') != prepared.canary):
            return None
        return prepared
    except (TypeError, ValueError, KeyError):
        return None


def http_application_secrets():
    prepared = _prepared.get()
    return ({value for value in (prepared.canary, prepared.credential, *prepared.private_values) if value}
            if prepared is not None else set())
