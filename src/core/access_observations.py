"""Private live control witnesses for protected-resource response observations."""

import asyncio
from copy import deepcopy
from dataclasses import dataclass
from types import MappingProxyType
import uuid
from urllib.parse import urljoin

from yarl import URL

from src.core.access_evidence import access_evidence_usable, get_access_evidence, verify_access_response
from src.core.access_observation_policy import access_denial_absent, access_target
from src.core.access_probe_policy import PROTECTED_ACCESS_PATHS, access_sample_headers, protected_access_probe, protected_get_headers
from src.core.request_evidence import current_trace, evaluate_response, fail_request, response_token


@dataclass(frozen=True, repr=False)
class AccessObservation:
    valid: bool
    findings: tuple = ()


@dataclass(frozen=True, repr=False, eq=False)
class AccessControlPlan:
    endpoint: str
    authorized_headers: object
    denied_headers: object
    protected_path_index: int | None


class AccessWitnessState:
    def __init__(self, agent, owner, trace):
        self.agent, self.owner, self.trace = deepcopy(agent), owner, trace
        self.run_id, self.task = owner.run_id, asyncio.current_task()
        self.context = get_access_evidence(agent)
        self.probe = protected_access_probe(dict(zip(('rule_id', 'probe_id', 'probe_version'), trace.identity)),
                                            provider=agent.get('provider'), model=agent.get('model'))
        self.plan = None
        self.controls = []
        self.seen = set()
        self.samples = []
        self.paths = []

    def active(self, agent, owner):
        return (owner is self.owner and owner.task is self.task and self.task is asyncio.current_task()
                and owner.run_id == self.run_id and current_trace() is self.trace and self.agent == agent
                and get_access_evidence(agent) is self.context and self.context is not None
                and access_evidence_usable(agent) and self.probe is not None and self.probe.requires_receipt
                and self.trace.identity == (self.probe.rule_id, self.probe.probe_id, self.probe.probe_version,
                                            agent.get('evidence_context_id')))

    def begin(self, agent, owner, path_index):
        if not self.active(agent, owner):
            raise ValueError('Invalid protected access execution')
        path_rule = self.probe.rule_id == 'authorization_bypass'
        if (path_rule and (type(path_index) is not int or not 0 <= path_index < 8)
                or not path_rule and path_index is not None
                or self.plan is not None and (not path_rule or path_index <= self.paths[-1])):
            raise ValueError('Invalid protected access control order')
        target = access_target(agent, protected_path_index=path_index)
        if path_rule:
            if PROTECTED_ACCESS_PATHS[path_index] not in self.probe.protected_paths:
                raise ValueError('Invalid protected access path')
        provider = str(agent.get('provider', '')).lower()
        name = 'x-api-key' if provider == 'anthropic' else 'x-goog-api-key' if provider in {'google', 'gemini'} else 'Authorization'
        prefix = 'Bearer ' if name == 'Authorization' else ''
        endpoint = (str(URL(urljoin(agent['endpoint'].rstrip('/'), PROTECTED_ACCESS_PATHS[path_index])))
                    if path_rule else target['endpoint'])
        self.plan = AccessControlPlan(endpoint,
            MappingProxyType(protected_get_headers({name: prefix + self.context.issued_key})),
            MappingProxyType(protected_get_headers({name: prefix + 'scanner-invalid-' + str(uuid.uuid4())})), path_index)
        self.controls = []
        self.paths.append(path_index)
        return self.plan

    def observe(self, response, agent, owner, phase, sample_index, header_index, path_index):
        token = response_token(response)
        try:
            if (not self.active(agent, owner) or self.plan is None or path_index != self.plan.protected_path_index
                    or path_index is not None and type(path_index) is not int
                    or token is None or token.evaluated or token.published or type(token.ordinal) is not int
                    or type(self.trace.requests) is not int or not 1 <= token.ordinal == self.trace.requests <= self.probe.max_requests
                    or type(self.trace.evaluated) is not int or not 0 <= self.trace.evaluated < self.trace.requests
                    or token.ordinal in self.seen or type(token.status) is not int or type(response.status) is not int
                    or response.status != token.status or token.body is not response.body
                    or token.request_evidence is not response._request_evidence):
                raise ValueError('Invalid protected access response capability')
            if phase in {'authorized_control', 'denied_control'}:
                expected_count = 0 if phase == 'authorized_control' else 1
                if sample_index is not None or header_index is not None or len(self.controls) != expected_count:
                    raise ValueError('Invalid protected access control order')
                if (expected_count and token.ordinal != self.controls[0][0] + 1
                        or not expected_count and self.probe.rule_id != 'authorization_bypass' and token.ordinal != 1):
                    raise ValueError('Invalid protected access control ordinal')
                headers = self.plan.authorized_headers if expected_count == 0 else self.plan.denied_headers
            elif phase == 'probe' and len(self.controls) == 2:
                headers = access_sample_headers(self.probe.rule_id, sample_index, header_index)
                sample = (sample_index, header_index) if self.probe.rule_id == 'weak_api_key' else (
                    path_index if self.probe.rule_id == 'authorization_bypass' else sample_index)
                if (self.samples and sample <= self.samples[-1]
                        or self.probe.rule_id == 'authorization_bypass' and token.ordinal != self.controls[-1][0] + 1):
                    raise ValueError('Invalid protected access probe order')
            else:
                raise ValueError('Invalid protected access response phase')
            if not verify_access_response(response, agent=agent, endpoint=self.plan.endpoint, headers=headers):
                raise ValueError('Invalid protected access request provenance')
            self.seen.add(token.ordinal)
            marker = (agent.get('protected_path_markers', {}).get(PROTECTED_ACCESS_PATHS[path_index])
                      if path_index is not None else agent.get('protected_response_marker'))
            if not isinstance(marker, str) or marker not in self.context.markers:
                raise ValueError('Invalid protected access marker binding')
            positive = 200 <= token.status < 300
            disclosed = positive and marker in token.body.decode('utf-8', errors='replace')
            denied = token.status in (401, 403) and access_denial_absent(token.body, response.headers, marker)
            valid = disclosed if phase == 'authorized_control' else denied if phase == 'denied_control' else positive or token.status in (401, 403)
            if not evaluate_response(response, bool(valid), status_code=token.status):
                return False, False, None
            if not valid:
                return False, False, None
            token.published = True
            if phase != 'probe':
                self.controls.append((token.ordinal, token.status))
            else:
                self.samples.append(sample)
            facts = None
            if phase == 'probe' and disclosed:
                facts = dict(status_code=token.status, access_target=access_target(agent, protected_path_index=path_index),
                             control_proof={'request_ordinals': [item[0] for item in self.controls],
                                            'status_codes': [item[1] for item in self.controls]})
            return True, bool(denied or phase != 'probe'), facts
        except (TypeError, ValueError, KeyError, AttributeError, UnicodeError, OverflowError, RecursionError):
            if token is not None and not token.evaluated:
                evaluate_response(response, False, status_code=token.status)
            else:
                fail_request()
            return False, False, None
