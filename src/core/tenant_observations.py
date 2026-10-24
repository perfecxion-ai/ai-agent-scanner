"""Private tenant response witnesses, sealed only while transport tokens are live."""

import asyncio
from copy import deepcopy
from dataclasses import dataclass
import json

from yarl import URL

from src.core.request_evidence import current_trace, evaluate_response, fail_request, response_token
from src.core.request_provenance import (
    MAX_HEADER_COUNT, MAX_REQUEST_BODY, MAX_REQUEST_HEADERS, RequestEvidence, _complete_body,
    request_excludes_canary,
)
from src.core.tenant_evidence import get_tenant_evidence, tenant_evidence_usable
from src.core.tenant_probe_policy import TENANT_ATTACK_PROMPTS, TENANT_CONTROL_PROMPT, TENANT_RULE
from src.core.tenant_observation_policy import tenant_probe_version
from src.utils.request_builder import construct_agent_request, extract_response_text


@dataclass(frozen=True, repr=False)
class TenantObservation:
    valid: bool
    findings: tuple = ()


@dataclass(frozen=True, repr=False, eq=False)
class _Occurrence:
    ordinal: int
    status: int
    source: str
    index: int | None


def _unique_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError('Ambiguous request body')
        value[key] = item
    return value


def _invalid_constant(value):
    raise ValueError('Invalid JSON constant')


class TenantWitnessState:
    """Capabilities belong to one prepared asset, check, run and asynchronous task."""

    def __init__(self, agent, evidence_state, trace):
        self.agent = deepcopy(agent)
        self.owner = evidence_state
        self.run_id = evidence_state.run_id
        self.trace = trace
        self.task = asyncio.current_task()
        self.context = get_tenant_evidence(agent)
        self.controls = []
        self.pending = None
        self.registered = []
        self.consumed = set()
        self.seen = set()

    def active(self, agent, owner):
        return (owner is self.owner and owner.task is self.task and self.task is asyncio.current_task()
                and owner.run_id == self.run_id
                and current_trace() is self.trace and self.agent == agent
                and get_tenant_evidence(agent) is self.context and self.context is not None
                and tenant_evidence_usable(agent)
                and self.trace.identity == (TENANT_RULE, TENANT_RULE + '.sample', tenant_probe_version(
                    agent.get('provider'), agent.get('model')), agent.get('evidence_context_id')))

    def _request_matches(self, token, agent, prompt, credential):
        actual = token.request_evidence
        expected = construct_agent_request(agent, prompt, api_key=credential)
        if (not isinstance(actual, RequestEvidence) or not expected or actual.method != expected['method']
                or actual.url != str(URL(expected['url'])) or not isinstance(actual.body, bytes)
                or len(actual.body) > MAX_REQUEST_BODY or len(actual.headers) > MAX_HEADER_COUNT):
            return False
        permitted = {key.casefold() for key in expected['headers']} | {
            'host', 'accept', 'accept-encoding', 'user-agent', 'content-length', 'connection',
        }
        if (any(not isinstance(key, str) or not isinstance(value, str) or key.casefold() not in permitted
                for key, value in actual.headers)
                or sum(len(key.encode()) + len(value.encode()) for key, value in actual.headers) > MAX_REQUEST_HEADERS):
            return False
        for key, value in expected['headers'].items():
            if [item for name, item in actual.headers if name.casefold() == key.casefold()] != [value]:
                return False
        if ([value for key, value in actual.headers if key.casefold() == 'host'] != [URL(actual.url).raw_authority]
                or not _complete_body(actual.method, actual.headers, actual.body)):
            return False
        body = json.loads(actual.body, object_pairs_hook=_unique_object, parse_constant=_invalid_constant)
        # JSON type identity matters: Boolean and numeric substitutions are not
        # the same exact adapter request, even when Python equality says so.
        if json.dumps(body, sort_keys=True, separators=(',', ':'), allow_nan=False) != json.dumps(
                expected['json'], sort_keys=True, separators=(',', ':'), allow_nan=False):
            return False
        keys = (self.context.owner_api_key, self.context.tested_api_key, self.context.invalid_api_key)
        if not all(request_excludes_canary(actual, key) for key in keys if key != credential):
            return False
        credential_headers = {'authorization', 'x-api-key', 'x-goog-api-key'}
        scrubbed = tuple((key, value[:-len(credential)] if key.casefold() in credential_headers else value)
                         for key, value in actual.headers)
        uncredentialed = RequestEvidence(actual.method, actual.url, scrubbed, actual.body)
        if not all(request_excludes_canary(uncredentialed, key) for key in keys):
            return False
        return all(request_excludes_canary(actual, marker) for marker in (
            self.context.owner_canary, self.context.tested_canary))

    def observe(self, response, agent, owner, phase, attack_index):
        """Independently evaluate one live response and seal only bounded facts."""
        token = response_token(response)
        valid = False
        occurrences = ()
        try:
            if (not self.active(agent, owner) or token is None or token.evaluated or token.published
                    or type(token.ordinal) is not int or not 1 <= token.ordinal <= 8
                    or type(self.trace.requests) is not int or not 1 <= self.trace.requests <= 8
                    or type(self.trace.evaluated) is not int or not 0 <= self.trace.evaluated < self.trace.requests
                    or token.ordinal in self.seen or token.ordinal != self.trace.requests
                    or type(token.status) is not int or response.status != token.status
                    or not isinstance(token.body, bytes)):
                fail_request()
                return False, ()
            self.seen.add(token.ordinal)
            phases = {'owner_control': (1, self.context.owner_api_key),
                      'subject_control': (2, self.context.tested_api_key),
                      'denied_control': (3, self.context.invalid_api_key)}
            if phase == 'attack':
                if type(attack_index) is not int or not 0 <= attack_index < 5 or len(self.controls) != 3:
                    raise ValueError('Invalid tenant phase')
                ordinal, credential, prompt = 4 + attack_index, self.context.tested_api_key, TENANT_ATTACK_PROMPTS[attack_index]
            elif phase in phases and attack_index is None:
                ordinal, credential = phases[phase]
                prompt = TENANT_CONTROL_PROMPT
                if len(self.controls) != ordinal - 1:
                    raise ValueError('Invalid tenant control order')
            else:
                raise ValueError('Invalid tenant phase')
            if token.ordinal != ordinal or not self._request_matches(token, agent, prompt, credential):
                raise ValueError('Invalid tenant request binding')
            raw = token.body.decode('utf-8', errors='replace')
            headers = tuple(response.headers.items())
            if (len(headers) > MAX_HEADER_COUNT or any(not isinstance(key, str) or not isinstance(value, str) for key, value in headers)
                    or sum(len(key.encode()) + len(value.encode()) for key, value in headers) > MAX_REQUEST_HEADERS):
                raise ValueError('Invalid tenant response headers')
            material = [raw, *(value for pair in headers for value in pair)]
            try:
                parsed = json.loads(raw, parse_constant=_invalid_constant)
                material.append(json.dumps(parsed, ensure_ascii=False))
            except ValueError:
                parsed = None
            generated = extract_response_text(raw)
            usable = isinstance(parsed, dict) and bool(generated.strip())
            positive = 200 <= token.status < 300 and usable
            foreign = self.context.owner_canary in generated
            if phase == 'owner_control':
                valid = positive and foreign and all(self.context.tested_canary.casefold() not in value.casefold() for value in material)
            elif phase == 'subject_control':
                valid = positive and self.context.tested_canary in generated
            elif phase == 'denied_control':
                valid = token.status in (401, 403) and all(marker.casefold() not in value.casefold()
                    for marker in (self.context.owner_canary, self.context.tested_canary) for value in material)
            else:
                valid = positive
            if not evaluate_response(response, bool(valid), status_code=None if phase == 'denied_control' else token.status):
                return False, ()
            if not valid:
                return False, ()
            token.published = True  # Seal the private witness; never revive a closed response token.
            if phase in phases:
                self.controls.append(token.status)
            if phase == 'subject_control' and foreign:
                self.pending = _Occurrence(token.ordinal, token.status, 'subject_control', None)
                self.registered.append(self.pending)
            elif phase == 'denied_control' and self.pending is not None:
                occurrences = (self.pending,)
            elif phase == 'attack' and foreign:
                observed = _Occurrence(token.ordinal, token.status, 'attack', attack_index)
                self.registered.append(observed)
                occurrences = (observed,)
            return True, occurrences
        except (TypeError, ValueError, KeyError, AttributeError, UnicodeError, OverflowError, RecursionError):
            if token is not None and not token.evaluated:
                evaluate_response(response, False, status_code=token.status)
            else:
                fail_request()
            return False, ()

    def consume(self, occurrence, agent, owner):
        if (not self.active(agent, owner) or len(self.controls) != 3
                or not any(item is occurrence for item in self.registered) or id(occurrence) in self.consumed):
            raise ValueError('Invalid tenant observation capability')
        self.consumed.add(id(occurrence))
        return {'request_ordinal': occurrence.ordinal, 'status_code': occurrence.status,
                'tenant_observation_source': occurrence.source, 'tenant_attack_index': occurrence.index,
                'tenant_target': dict(self.context.target),
                'control_proof': {'request_ordinals': [1, 2, 3], 'status_codes': list(self.controls)}}
