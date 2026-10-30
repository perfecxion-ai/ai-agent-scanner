"""Additive scan contracts and context-local evidence accounting."""

import asyncio
from copy import deepcopy
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from functools import wraps
import hashlib
import json
import uuid
from typing import Literal, TypedDict

from src.core.transport import current_budget
from src.utils.request_builder import extract_response_text, extract_agent_response_text
from src.core.http_application_policy import (
    HTTP_FAILURE_REASONS, http_json_request_matches_capture, http_prompt_payloads,
    http_prompt_probe_version, http_views_match, is_http_agent,
)
from src.core.http_application_runtime import get_http_target
from src.core.access_probe_policy import (
    PROTECTED_ACCESS_RULES, protected_access_pass, protected_access_confirmation,
    ACCESS_CONTROL_STATUS, ACCESS_EVIDENCE_SOURCE, AUTHENTICATION_SAMPLES,
    PROTECTED_ACCESS_PATHS, PROTECTED_CONTROL_VERSION, modern_access_definition,
)
from src.core.access_observation_policy import MAX_ACCESS_CHECK_EVIDENCE, access_claim, access_target
from src.core.access_observations import AccessObservation, AccessWitnessState
from src.core.tenant_probe_policy import (
    TENANT_CONTROL_STATUS, TENANT_CONTROL_VERSION, TENANT_FINDING_DESCRIPTION, TENANT_FINDING_TITLE,
    TENANT_REMEDIATION, TENANT_RULE, tenant_claim, tenant_confirmation, tenant_target,
)
from src.core.prompt_evidence_policy import (
    EVIDENCE_SOURCE, has_evidence_contract, prompt_claim, prompt_probe_payloads,
)
from src.core.observation_evidence_policy import (
    CHECK_EVIDENCE_SCHEMA_VERSION, MAX_CHECK_EVIDENCE, MAX_PROMPT_CHECK_EVIDENCE,
    SUPPORTED_CHECK_EVIDENCE_SCHEMA_VERSIONS as SUPPORTED_CHECK_EVIDENCE_SCHEMA_VERSIONS,
    checkpoint_evidence_version, is_supported_evidence_version, is_mixed_evidence_version,
    validate_observation_evidence,
)
from src.core.tenant_observation_policy import TENANT_EVIDENCE_SOURCE, MAX_TENANT_CHECK_EVIDENCE
from src.core.tenant_observations import TenantObservation, TenantWitnessState
from src.core.request_evidence import (
    RequestTrace, current_trace, evaluate_response, fail_request, response_token, trace_requests,
)
from src.core.request_provenance import request_excludes_canary


CHECK_SCHEMA_VERSION = "1.0"
CHECK_INTERRUPTED_REASON = "Check interrupted before completion"
MAX_CHECKPOINTS = 4096
MAX_CHECKPOINT_BYTES = 8 * 1024 * 1024
MAX_CHECKPOINT_TOTAL_BYTES = 128 * 1024 * 1024
PLANNED_RULES = tuple("prompt_injection." + category for category in (
    "system_prompt_extraction", "instruction_bypass", "role_manipulation", "dan_jailbreak",
    "context_manipulation", "injection_via_encoding", "payload_injection")) + (
    "authentication_bypass", "weak_credentials", "weak_api_key", "authorization_bypass",
    "no_rate_limiting", "insecure_session_management", "pii_disclosure",
    "tenant_isolation_violation", "data_retention", "privacy_transparency_issue",
    "information_disclosure_in_errors", "unauthenticated_inference")
CheckStatus = Literal["completed", "skipped", "failed"]
EvidenceOutcome = Literal["passed", "confirmed", "heuristic", "inconclusive", "not_evaluated"]


class Evidence(TypedDict, total=False):
    evidence_status: Literal["confirmed", "heuristic", "inconclusive"]
    control_status: str
    evidence_context_id: str | None


class Finding(Evidence, total=False):
    rule_id: str
    probe_id: str
    probe_version: str
    vulnerability_type: str
    severity: str
    description: str


class AssetSnapshot(TypedDict, total=False):
    id: str
    name: str
    endpoint: str
    endpoint_redacted: bool
    security_status: str
    vulnerabilities: list[Finding]
    checks: list[dict]


class ScanResult(TypedDict):
    schema_version: str
    check_schema_version: str
    generated_at: str
    scan_type: str
    status: str
    agents: list[AssetSnapshot]
    security_results: list[dict]
    risk_assessments: list[dict]
    summary: dict


@dataclass(frozen=True)
class CheckRecord:
    rule_id: str
    probe_id: str
    probe_version: str
    status: CheckStatus
    outcome: EvidenceOutcome
    requests_attempted: int = 0
    responses_evaluated: int = 0
    reason: str | None = None
    evidence_context_id: str | None = None

    def __post_init__(self):
        if not all(isinstance(value, str) and value for value in (self.rule_id, self.probe_id, self.probe_version)):
            raise ValueError("Check identifiers must be nonempty strings")
        if self.status not in {"completed", "skipped", "failed"}:
            raise ValueError("Invalid check execution status")
        if self.outcome not in {"passed", "confirmed", "heuristic", "inconclusive", "not_evaluated"}:
            raise ValueError("Invalid check evidence outcome")
        if any(type(value) is not int or value < 0 for value in (self.requests_attempted, self.responses_evaluated)):
            raise ValueError("Check counters cannot be negative")
        if self.reason is not None and not isinstance(self.reason, str):
            raise ValueError("Check reason must be text")
        if self.evidence_context_id is not None and not (
                isinstance(self.evidence_context_id, str) and self.evidence_context_id.strip()
                and len(self.evidence_context_id) <= 128):
            raise ValueError("Evidence context must be a nonempty string of at most 128 characters")
        if self.responses_evaluated > self.requests_attempted:
            raise ValueError("Evaluated responses cannot exceed attempted interactions")
        if self.status == "completed" and self.responses_evaluated < 1:
            raise ValueError("Completed checks require evaluated responses")
        if self.outcome == "confirmed" and self.responses_evaluated < 1:
            raise ValueError("Confirmed evidence requires evaluated responses")
        if self.outcome == "passed" and (self.status != "completed" or self.responses_evaluated < 1):
            raise ValueError("Passed checks require completed evaluated responses")
        if self.status == "skipped" and self.outcome != "not_evaluated":
            raise ValueError("Skipped checks cannot establish evidence")
        if self.status != "skipped" and self.outcome == "not_evaluated":
            raise ValueError("Executed checks require an evidence outcome")
        if self.status == "skipped" and self.responses_evaluated:
            raise ValueError("Skipped checks cannot have evaluated responses")

    def to_dict(self):
        return asdict(self)


@dataclass
class _Execution:
    evaluated: int = 0
    failed_interactions: int = 0
    failed: bool = False
    decisive: bool = True
    authorization_denied: bool = False
    trace: RequestTrace | None = None
    findings: list = field(default_factory=list)
    tenant_state: object = None
    access_state: object = None
    http_diagnostic: str | None = None


_records = ContextVar("security_check_records", default=None)
_execution = ContextVar("security_check_execution", default=None)
_observer = ContextVar("finalized_check_observer", default=None)
_evidence = ContextVar('evidence_state', default=None)
_evidence_observer = ContextVar('evidence_sink', default=None)


@dataclass
class _EvidenceState:
    agent: dict
    observer: object
    task: object
    schema_version: str = CHECK_EVIDENCE_SCHEMA_VERSION
    run_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    receipts: list = field(default_factory=list)
    findings: list = field(default_factory=list)
    sink_failed: bool = False
    cancelled: bool = False


@contextmanager
def observe_evidence(observer):
    """Install an asynchronous receipt sink without changing detector behavior."""
    token = _evidence_observer.set(observer)
    try:
        yield
    finally:
        _evidence_observer.reset(token)


@contextmanager
def collect_evidence(agent, observer=None, *, schema_version=CHECK_EVIDENCE_SCHEMA_VERSION):
    """Collect observations under a schema chosen before execution begins."""
    if not is_supported_evidence_version(schema_version):
        raise CheckpointError()
    state = _EvidenceState(deepcopy(agent), observer if observer is not None else _evidence_observer.get(),
                           asyncio.current_task(), schema_version=schema_version)
    token = _evidence.set(state)
    try:
        yield state
    finally:
        _evidence.reset(token)


def record_prompt_response(response, valid, *, status_code=None):
    if current_trace() is None:
        record_interaction(valid, status_code=status_code)
    else:
        evaluate_response(response, valid, status_code=status_code)


def ensure_evidence_active():
    """A cleanup error cannot erase a failed or cancelled receipt delivery."""
    state = _evidence.get()
    trace = current_trace()
    if trace is not None and trace.cancelled:
        raise asyncio.CancelledError()
    if state is not None:
        if state.cancelled:
            raise asyncio.CancelledError()
        if state.sink_failed:
            raise CheckpointError()


def record_prompt_failure(*, legacy=True):
    ensure_evidence_active()
    if current_trace() is None:
        if legacy:
            record_interaction(False)
    else:
        fail_request()


def record_http_diagnostic(code):
    execution = _execution.get()
    if execution is not None and code in HTTP_FAILURE_REASONS and execution.http_diagnostic is None:
        execution.http_diagnostic = code


async def publish_prompt_evidence(response, finding, *, agent, category, payload):
    state = _evidence.get()
    ensure_evidence_active()
    try:
        return await _publish_prompt_evidence(response, finding, agent=agent, category=category, payload=payload)
    except asyncio.CancelledError:
        if state is not None:
            state.cancelled = True
        raise
    except Exception:
        if state is not None:
            state.sink_failed = True
        raise CheckpointError() from None


async def _publish_prompt_evidence(response, finding, *, agent, category, payload):
    """Mint only from a live, evaluated transport response and actual canary match."""
    state, execution, trace = _evidence.get(), _execution.get(), current_trace()
    if state is None or trace is None or execution is None or not isinstance(finding, dict):
        return
    token = response_token(response, evaluated=True)
    if (token is None or token.published or state.task is not asyncio.current_task()
            or execution.trace is not trace or trace.sample is None
            or trace.sample[1:] != (category, payload)
            or finding.get('evidence_status') != 'confirmed'):
        return
    identity = trace.identity
    custom_http = is_http_agent(agent)
    payloads = (http_prompt_payloads(*identity[:3], agent) if custom_http else
                prompt_probe_payloads(*identity[:3], provider=agent.get('provider'), model=agent.get('model')))
    index = trace.sample[0]
    if (payloads is None or type(index) is not int or not 0 <= index < len(payloads)
            or payload != payloads[index] or agent != state.agent):
        return
    canary = agent.get('system_prompt_canary')
    text = token.body if custom_http else token.body.decode('utf-8', errors='replace')
    if (not usable_model_response(text, agent=agent) or not isinstance(canary, str) or len(canary) < 16
            or canary in payload or canary not in extract_agent_response_text(agent, text)
            or not request_excludes_canary(token.request_evidence, canary)
            or type(token.status) is not int or not 200 <= token.status < 300
            or finding.get('status_code') != token.status):
        return
    if custom_http:
        prepared = get_http_target(agent)
        if prepared is None or not http_json_request_matches_capture(
                token.request_evidence, agent, payload, prepared.credential):
            return
    if (len(state.receipts) >= MAX_CHECK_EVIDENCE or sum(
            receipt['source'] == EVIDENCE_SOURCE for receipt in state.receipts) >= MAX_PROMPT_CHECK_EVIDENCE):
        raise CheckpointError()
    finding.update(rule_id=identity[0], probe_id=identity[1], probe_version=identity[2],
                   evidence_context_id=identity[3], check_evidence_id=str(uuid.uuid4()))
    receipt = {
        'id': finding['check_evidence_id'], 'run_id': state.run_id, 'agent_id': agent.get('id'),
        'rule_id': identity[0], 'probe_id': identity[1], 'probe_version': identity[2],
        'evidence_context_id': identity[3], 'finding_id': finding.get('id'),
        'sample_index': index, 'sequence': len(execution.findings) + 1,
        'request_ordinal': token.ordinal, 'requests_attempted': trace.requests,
        'responses_evaluated': trace.evaluated, 'source': EVIDENCE_SOURCE, 'source_version': '2.0',
    }
    if custom_http:
        receipt['source_version'] = '3.0'
        receipt['http_target_binding'] = finding['http_target_binding'] = agent['http_target_binding']
    candidate = dict(state.agent, provider=state.agent.get('provider'), model=state.agent.get('model'),
                     check_evidence_schema_version=state.schema_version,
                     check_evidence_run_id=state.run_id, check_evidence=[*state.receipts, receipt],
                     vulnerabilities=[*state.findings, finding], checks=[])
    try:
        validate_check_evidence(candidate)
    except (TypeError, ValueError):
        raise CheckpointError() from None
    token.published = True
    state.receipts.append(deepcopy(receipt))
    state.findings.append(deepcopy(finding))
    execution.findings.append(deepcopy(finding))
    if state.observer is not None:
        execution_token, evidence_token = _execution.set(None), _evidence.set(None)
        try:
            with trace_requests(None):
                await state.observer(deepcopy(receipt), deepcopy(finding))
        except asyncio.CancelledError:
            raise
        except Exception:
            raise CheckpointError() from None
        finally:
            _evidence.reset(evidence_token)
            _execution.reset(execution_token)


async def observe_tenant_response(response, *, agent, phase, attack_index=None):
    """Publish only registered tenant facts from this active normal execution."""
    state = _evidence.get()
    if state is None:
        return None
    ensure_evidence_active()
    execution, trace = _execution.get(), current_trace()
    if (not is_mixed_evidence_version(state.schema_version) or execution is None or trace is None
            or state.task is not asyncio.current_task() or execution.trace is not trace
            or type(trace.identity) is not tuple or len(trace.identity) != 4
            or trace.identity[0] != TENANT_RULE or state.agent != agent):
        if execution is not None:
            execution.failed = True
        if trace is not None:
            trace.failed = True
        return TenantObservation(False, ())
    try:
        if execution.tenant_state is None:
            execution.tenant_state = TenantWitnessState(agent, state, trace)
        valid, occurrences = execution.tenant_state.observe(response, agent, state, phase, attack_index)
        findings = []
        for occurrence in occurrences:
            ensure_evidence_active()
            facts = execution.tenant_state.consume(occurrence, agent, state)
            if (len(state.receipts) >= MAX_CHECK_EVIDENCE or sum(
                    receipt['source'] == TENANT_EVIDENCE_SOURCE for receipt in state.receipts) >= MAX_TENANT_CHECK_EVIDENCE):
                raise CheckpointError()
            identity = trace.identity
            finding_id, receipt_id = str(uuid.uuid4()), str(uuid.uuid4())
            finding = {
                'id': finding_id, 'agent_id': agent['id'], 'vulnerability_type': TENANT_RULE,
                'severity': 'critical', 'evidence_status': 'confirmed', 'title': TENANT_FINDING_TITLE,
                'description': TENANT_FINDING_DESCRIPTION, 'response_excerpt': '[GENERATED_TEXT_OMITTED]',
                'timestamp': datetime.now(timezone.utc).isoformat(), 'remediation': TENANT_REMEDIATION,
                'status_code': facts['status_code'], 'tenant_control_version': TENANT_CONTROL_VERSION,
                'control_status': TENANT_CONTROL_STATUS, 'tenant_target': facts['tenant_target'],
                'tenant_observation_source': facts['tenant_observation_source'],
                'rule_id': identity[0], 'probe_id': identity[1], 'probe_version': identity[2],
                'evidence_context_id': identity[3], 'check_evidence_id': receipt_id,
            }
            receipt = {
                'id': receipt_id, 'run_id': state.run_id, 'agent_id': agent['id'],
                'rule_id': identity[0], 'probe_id': identity[1], 'probe_version': identity[2],
                'evidence_context_id': identity[3], 'finding_id': finding_id,
                'sequence': len(execution.findings) + 1, 'request_ordinal': facts['request_ordinal'],
                'requests_attempted': trace.requests, 'responses_evaluated': trace.evaluated,
                'source': TENANT_EVIDENCE_SOURCE, 'source_version': '1.0',
                'tenant_target': facts['tenant_target'], 'tenant_observation_source': facts['tenant_observation_source'],
                'control_proof': facts['control_proof'],
            }
            if facts['tenant_attack_index'] is not None:
                finding['tenant_attack_index'] = receipt['tenant_attack_index'] = facts['tenant_attack_index']
            candidate = dict(state.agent, check_evidence_schema_version=state.schema_version,
                             check_evidence_run_id=state.run_id, check_evidence=[*state.receipts, receipt],
                             vulnerabilities=[*state.findings, finding], checks=[])
            validate_check_evidence(candidate)
            state.receipts.append(deepcopy(receipt))
            state.findings.append(deepcopy(finding))
            execution.findings.append(deepcopy(finding))
            findings.append(deepcopy(finding))
            if state.observer is not None:
                execution_token, evidence_token = _execution.set(None), _evidence.set(None)
                try:
                    with trace_requests(None):
                        await state.observer(deepcopy(receipt), deepcopy(finding))
                finally:
                    _evidence.reset(evidence_token)
                    _execution.reset(execution_token)
        return TenantObservation(valid, tuple(findings))
    except asyncio.CancelledError:
        state.cancelled = True
        raise
    except Exception:
        state.sink_failed = True
        raise CheckpointError() from None


def begin_access_controls(agent, *, protected_path_index=None):
    state = _evidence.get()
    if state is None or type(state.schema_version) is str and state.schema_version in {'1.0', '2.0'}:
        return None
    ensure_evidence_active()
    execution, trace = _execution.get(), current_trace()
    try:
        if (state.schema_version != '3.0' or execution is None or trace is None
                or state.task is not asyncio.current_task() or execution.trace is not trace
                or state.agent != agent):
            raise ValueError('Invalid protected access execution')
        if execution.access_state is None:
            execution.access_state = AccessWitnessState(agent, state, trace)
        return execution.access_state.begin(agent, state, protected_path_index)
    except (TypeError, ValueError, KeyError, AttributeError, UnicodeError, OverflowError, RecursionError):
        raise CheckpointError() from None


async def observe_access_response(response, *, agent, phase, sample_index=None, header_index=None,
                                  protected_path_index=None):
    state = _evidence.get()
    if state is None or type(state.schema_version) is str and state.schema_version in {'1.0', '2.0'}:
        return None
    ensure_evidence_active()
    execution, trace = _execution.get(), current_trace()
    if (state.schema_version != '3.0' or execution is None or trace is None
            or state.task is not asyncio.current_task() or execution.trace is not trace
            or execution.access_state is None or state.agent != agent):
        if execution is not None:
            execution.failed = True
        fail_request()
        return AccessObservation(False, ())
    try:
        valid, decisive, facts = execution.access_state.observe(response, agent, state, phase, sample_index,
                                                                header_index, protected_path_index)
        execution.decisive &= decisive
        if facts is None:
            return AccessObservation(valid, ())
        identity = trace.identity
        rule = identity[0]
        if len(state.receipts) >= MAX_CHECK_EVIDENCE or sum(
                item['source'] == ACCESS_EVIDENCE_SOURCE for item in state.receipts) >= MAX_ACCESS_CHECK_EVIDENCE:
            raise CheckpointError()
        finding_id, receipt_id = str(uuid.uuid4()), str(uuid.uuid4())
        finding = dict(id=finding_id, agent_id=agent['id'], vulnerability_type=rule,
                       severity='critical' if rule == 'weak_credentials' else 'high', evidence_status='confirmed',
                       control_status=ACCESS_CONTROL_STATUS, protected_control_version=PROTECTED_CONTROL_VERSION,
                       title='Protected Resource Access Confirmed',
                       description='A configured protected record was returned after successful authorized and denied controls.',
                       timestamp=datetime.now(timezone.utc).isoformat(), response_excerpt='[RESPONSE_TEXT_OMITTED]',
                       remediation='Enforce the configured authentication and authorization boundary.',
                       rule_id=identity[0], probe_id=identity[1], probe_version=identity[2],
                       evidence_context_id=identity[3], check_evidence_id=receipt_id,
                       access_target=facts['access_target'], status_code=facts['status_code'])
        receipt = dict(id=receipt_id, run_id=state.run_id, agent_id=agent['id'], rule_id=identity[0],
                       probe_id=identity[1], probe_version=identity[2], evidence_context_id=identity[3],
                       finding_id=finding_id, sequence=len(execution.findings) + 1,
                       request_ordinal=trace.requests, requests_attempted=trace.requests,
                       responses_evaluated=trace.evaluated, source=ACCESS_EVIDENCE_SOURCE, source_version='1.0',
                       access_target=facts['access_target'], control_proof=facts['control_proof'])
        if protected_path_index is not None:
            finding['protected_path_index'] = receipt['protected_path_index'] = protected_path_index
            finding['path'] = PROTECTED_ACCESS_PATHS[protected_path_index]
        else:
            finding['sample_index'] = receipt['sample_index'] = sample_index
            if rule == 'weak_api_key':
                finding['header_index'] = receipt['header_index'] = header_index
            elif rule == 'authentication_bypass':
                finding['method'] = AUTHENTICATION_SAMPLES[sample_index][0]
        candidate = dict(state.agent, check_evidence_schema_version=state.schema_version,
                         check_evidence_run_id=state.run_id, check_evidence=[*state.receipts, receipt],
                         vulnerabilities=[*state.findings, finding], checks=[])
        validate_check_evidence(candidate)
        state.receipts.append(deepcopy(receipt))
        state.findings.append(deepcopy(finding))
        execution.findings.append(deepcopy(finding))
        if state.observer is not None:
            execution_token, evidence_token = _execution.set(None), _evidence.set(None)
            try:
                with trace_requests(None):
                    await state.observer(deepcopy(receipt), deepcopy(finding))
            finally:
                _evidence.reset(evidence_token)
                _execution.reset(execution_token)
        return AccessObservation(valid, (deepcopy(finding),))
    except asyncio.CancelledError:
        state.cancelled = True
        raise
    except Exception:
        state.sink_failed = True
        raise CheckpointError() from None


class CheckpointError(RuntimeError):
    """Checkpoint failure stops further probes without exposing private details."""

    def __init__(self):
        super().__init__("Scan checkpoint could not be preserved")


@contextmanager
def observe_checks(observer):
    """Observe independent finalized check/finding pairs in this scan context."""
    token = _observer.set(observer)
    try:
        yield
    finally:
        _observer.reset(token)


@contextmanager
def collect_checks():
    records = []
    token = _records.set(records)
    try:
        yield records
    finally:
        _records.reset(token)


def record_interaction(valid: bool, decisive: bool = False, *, status_code=None):
    """Record response analysis, excluding empty or rejected required responses."""
    execution = _execution.get()
    if execution is not None:
        execution.evaluated += int(valid)
        execution.failed_interactions += int(not valid)
        execution.failed |= not valid
        execution.decisive &= decisive
        execution.authorization_denied |= not valid and status_code in (401, 403)


def has_canary(agent, field):
    value = agent.get(field)
    return isinstance(value, str) and len(value) >= 16


def usable_model_response(text, *, agent=None):
    """Supported adapters return JSON with nonempty generated text."""
    if is_http_agent(agent):
        return bool(extract_agent_response_text(agent, text).strip())
    try:
        body = json.loads(text)
    except (ValueError, TypeError):
        return False
    return isinstance(body, dict) and bool(extract_response_text(text).strip())


def checked(rule, spec, prerequisite=None, oracle=None, coverage=None, absence_reason=None):
    """Track a probe group without storing prompts, credentials, or response bodies."""
    def decorate(method):
        @wraps(method)
        async def wrapped(self, agent, *args, **kwargs):
            rule_id = rule(self, *args, **kwargs) if callable(rule) else rule
            definition = spec(self, *args, **kwargs) if callable(spec) else spec
            evidence_state = _evidence.get()
            modern_access = (evidence_state is not None and evidence_state.schema_version == '3.0'
                             and rule_id in PROTECTED_ACCESS_RULES)
            if modern_access:
                definition = modern_access_definition(definition)
            # Bind the selected protocol/model and public probe definition.
            # Protected canaries and actual credentials are excluded.
            identity = [definition, agent.get("provider"), agent.get("model")]
            if coverage:
                identity.append(coverage(self, agent, *args, **kwargs))
            version = (http_prompt_probe_version(definition, agent) if is_http_agent(agent) else
                       "1:" + hashlib.sha256(json.dumps(identity, sort_keys=True).encode()).hexdigest())
            probe_id = rule_id + ".sample"
            reason = prerequisite(agent) if prerequisite else None
            execution = _Execution()
            if evidence_state is not None and (rule_id.startswith('prompt_injection.') or rule_id == TENANT_RULE or modern_access):
                if evidence_state.task is not asyncio.current_task():
                    raise CheckpointError()
                execution.trace = RequestTrace(asyncio.current_task(), (
                    rule_id, probe_id, version, agent.get('evidence_context_id')))
            budget = current_budget()
            before = (budget.requests, budget.failures + budget.rejections) if budget else (0, 0)
            findings = []
            interrupted = False
            token = _execution.set(execution)
            tracing = trace_requests(execution.trace)
            tracing.__enter__()
            try:
                if not reason:
                    findings = await method(self, agent, *args, **kwargs)
            except asyncio.CancelledError:
                execution.failed = True
                interrupted = True
                raise
            except Exception:
                execution.failed = True
                raise
            finally:
                tracing.__exit__(None, None, None)
                _execution.reset(token)
                attempts = max(0, budget.requests - before[0]) if budget else execution.evaluated
                attempts = max(attempts, execution.evaluated + execution.failed_interactions)
                if execution.trace is None:
                    execution.failed |= bool(budget and budget.failures + budget.rejections > before[1])
                if execution.trace is not None:
                    attempts, execution.evaluated = execution.trace.requests, execution.trace.evaluated
                    execution.failed |= execution.trace.failed
                    execution.authorization_denied |= execution.trace.authorization_denied
                    existing = {finding.get('id'): finding for finding in findings}
                    for observed in execution.findings:
                        if observed['id'] not in existing:
                            findings.append(deepcopy(observed))
                        elif existing[observed['id']] != observed:
                            raise CheckpointError()
                evidence = {finding.get("evidence_status") for finding in findings}
                if reason:
                    status, outcome = "skipped", "not_evaluated"
                elif execution.failed:
                    status = "failed"
                    outcome = "confirmed" if "confirmed" in evidence and execution.evaluated else "inconclusive"
                    reason = (CHECK_INTERRUPTED_REASON if interrupted else
                              execution.http_diagnostic + ': ' + HTTP_FAILURE_REASONS[execution.http_diagnostic]
                              if execution.http_diagnostic else
                              "Required model interaction denied authorization (HTTP 401/403); verify credentials and access policy"
                              if execution.authorization_denied else
                              "Some required interactions failed or returned unusable responses")
                elif not execution.evaluated:
                    status, outcome = "skipped", "not_evaluated"
                    reason = "No response was evaluated"
                else:
                    status = "completed"
                    outcome = ("confirmed" if "confirmed" in evidence else "heuristic" if evidence else
                               "passed" if oracle and oracle(agent) and execution.decisive else "inconclusive")
                    if outcome == "inconclusive" and absence_reason:
                        reason = absence_reason
                record = CheckRecord(rule_id, probe_id, version, status, outcome,
                                     attempts, execution.evaluated, reason,
                                     agent.get("evidence_context_id"))
                if _records.get() is not None:
                    _records.get().append(record.to_dict())
                for finding in findings:
                    finding.update(rule_id=rule_id, probe_id=probe_id, probe_version=version,
                                   evidence_context_id=record.evidence_context_id)
            observer = _observer.get()
            if observer is not None:
                try:
                    await observer(deepcopy(record.to_dict()), deepcopy(findings))
                except asyncio.CancelledError:
                    raise
                except Exception:
                    raise CheckpointError() from None
            return findings
        return wrapped
    return decorate


def validate_checks(checks):
    """Validate new records; legacy reports without checks remain readable."""
    if not isinstance(checks, list):
        raise ValueError("Checks must be an array")
    seen = set()
    for check in checks:
        if not isinstance(check, dict):
            raise ValueError("Check must be an object")
        record = CheckRecord(**check)
        identity = (record.rule_id, record.probe_id, record.probe_version)
        if identity in seen:
            raise ValueError("Duplicate check identity")
        seen.add(identity)


def missing_checks(records, reason, *, rules=None):
    recorded = {record["rule_id"] for record in records}
    return [CheckRecord(rule, rule + ".sample", "1:unexecuted", "skipped",
                        "not_evaluated", reason=reason).to_dict()
            for rule in (PLANNED_RULES if rules is None else rules) if rule not in recorded]


def _access_context(asset):
    if not isinstance(asset, dict) or not all(key in asset for key in ('provider', 'model')):
        return None
    return {'provider': asset['provider'], 'model': asset['model']}


def _protected_access_claim(value):
    return isinstance(value, dict) and any(
        isinstance(value.get(key), str) and value[key] in PROTECTED_ACCESS_RULES
        for key in ('rule_id', 'vulnerability_type'))


def _supported_confirmation(check, finding, asset):
    if prompt_claim(check) or prompt_claim(finding):
        return False
    if tenant_claim(check) or tenant_claim(finding):
        if is_mixed_evidence_version(asset.get('check_evidence_schema_version')):
            return False
        context = _access_context(asset)
        return context is not None and tenant_confirmation(
            check, finding, endpoint=asset.get('endpoint'),
            evidence_context_id=asset.get('evidence_context_id'), **context)
    if _protected_access_claim(check) or _protected_access_claim(finding):
        context = _access_context(asset)
        return context is not None and protected_access_confirmation(check, finding, **context)
    return True


def _unsupported_access_confirmation(result):
    """Unverifiable positive claims cannot be reinterpreted as an assessed zero."""
    checks = result.get('checks', [])
    findings = result.get('vulnerabilities', [])
    if not isinstance(findings, list) or any(not isinstance(finding, dict) for finding in findings):
        return True
    if result.get('check_evidence_schema_version') == '3.0':
        observed = [finding for finding in evidence_findings(result) if access_claim(finding)]
        identifiers = {finding.get('id') for finding in observed}
        keys = ('rule_id', 'probe_id', 'probe_version', 'evidence_context_id')
        return (any(access_claim(value) and value.get('evidence_status') == 'confirmed' and value.get('id') not in identifiers for value in findings)
                or any(access_claim(check) and check.get('outcome') == 'confirmed' and not any(
                    tuple(check.get(key) for key in keys) == tuple(value.get(key) for key in keys)
                    for value in observed) for check in checks))
    for finding in findings:
        if _protected_access_claim(finding) and finding.get('evidence_status') == 'confirmed':
            if not any(_supported_confirmation(check, finding, result) for check in checks):
                return True
    for check in checks:
        if _protected_access_claim(check) and check.get('outcome') == 'confirmed':
            if not any(_supported_confirmation(check, finding, result) for finding in findings):
                return True
    return False


def _unsupported_tenant_confirmation(result):
    """Old or unbound tenant positives cannot expose a companion assessed zero."""
    checks, findings = result.get('checks', []), result.get('vulnerabilities', [])
    if is_mixed_evidence_version(result.get('check_evidence_schema_version')):
        observed = evidence_findings(result)
        identifiers = {finding.get('id') for finding in observed}
        keys = ('rule_id', 'probe_id', 'probe_version', 'evidence_context_id')
        return (any(tenant_claim(finding) and finding.get('evidence_status') == 'confirmed'
                    and finding.get('id') not in identifiers for finding in findings)
                or any(tenant_claim(check) and check.get('outcome') == 'confirmed' and not any(
                    tuple(finding.get(key) for key in keys) == tuple(check.get(key) for key in keys)
                    for finding in observed) for check in checks))
    for finding in findings:
        if tenant_claim(finding) and finding.get('evidence_status') == 'confirmed':
            if not any(_supported_confirmation(check, finding, result) for check in checks):
                return True
    for check in checks:
        if tenant_claim(check) and check.get('outcome') == 'confirmed':
            if not any(_supported_confirmation(check, finding, result) for finding in findings):
                return True
    return False


def validate_check_evidence(asset, *, strict=True):
    """Validate the new ledger; strict=False preserves redacted public metadata."""
    return validate_observation_evidence(asset, strict=strict)


def evidence_findings(asset):
    """Select original occurrences backed by valid immutable response receipts."""
    try:
        validate_check_evidence(asset)
    except (TypeError, ValueError, KeyError):
        return []
    identifiers = {receipt['finding_id'] for receipt in asset.get('check_evidence', [])}
    return [finding for finding in asset.get('vulnerabilities', [])
            if isinstance(finding.get('id'), str) and finding['id'] in identifiers]


def _unsupported_prompt_confirmation(result):
    """An unsupported prompt positive cannot become zero after filtering."""
    observed = {finding['id'] for finding in evidence_findings(result)}
    for finding in result.get('vulnerabilities', []):
        if (prompt_claim(finding) and finding.get('evidence_status') == 'confirmed'
                and (not isinstance(finding.get('id'), str) or finding['id'] not in observed)):
            return True
    keys = ('rule_id', 'probe_id', 'probe_version', 'evidence_context_id')
    supported = {tuple(receipt[key] for key in keys) for receipt in result.get('check_evidence', [])}
    return any(prompt_claim(check) and check.get('outcome') == 'confirmed'
               and tuple(check.get(key) for key in keys) not in supported
               for check in result.get('checks', []))


def unfinished_evidence_checks(asset):
    """Return supported observed identities without any actual terminal check."""
    try:
        validate_check_evidence(asset)
    except (TypeError, ValueError, KeyError):
        return set()
    keys = ('rule_id', 'probe_id', 'probe_version', 'evidence_context_id')
    terminal = {tuple(check.get(key) for key in keys) for check in asset.get('checks', [])}
    return {tuple(receipt[key] for key in keys) for receipt in asset.get('check_evidence', [])} - terminal


def proves_absence(check, finding, *, asset=None, previous_asset=None):
    """Resolve only supported controlled probes with matching prior evidence."""
    rule = finding.get("rule_id", finding.get("vulnerability_type", ""))
    if not isinstance(rule, str):
        return False
    if rule not in PROTECTED_ACCESS_RULES:
        return False
    try:
        record = CheckRecord(**check)
    except (TypeError, ValueError):
        return False
    context = record.evidence_context_id
    safe_context = (isinstance(context, str) and context.strip()
                    and "[" not in context and "]" not in context)
    if _protected_access_claim(check) or _protected_access_claim(finding):
        current_context, previous_context = _access_context(asset), _access_context(previous_asset)
        if (current_context is None or previous_context != current_context
                or not protected_access_pass(check, evidence_schema_version=asset.get('check_evidence_schema_version'), **current_context)):
            return False
        previous_checks = previous_asset.get('checks', [])
        try:
            validate_checks(previous_checks)
        except (TypeError, ValueError):
            return False
        observed = evidence_findings(previous_asset)
        if (not any(protected_access_confirmation(previous, finding, **previous_context) for previous in previous_checks)
                and not any(value == finding for value in observed)):
            return False
    return (safe_context and context == finding.get("evidence_context_id")
            and record.status == "completed" and record.outcome == "passed"
            and record.rule_id == finding.get("rule_id", finding.get("vulnerability_type"))
            and record.probe_id == finding.get("probe_id")
            and record.probe_version == finding.get("probe_version"))


def risk_assessment_eligible(result):
    """Confirmed evidence survives incomplete coverage; absence needs completion."""
    if result.get("status") not in {"completed", "partial", "failed"} or result.get("check_schema_version") != CHECK_SCHEMA_VERSION:
        return False
    try:
        validate_checks(result.get("checks", []))
        validate_check_evidence(result)
    except (TypeError, ValueError):
        return False
    if (_unsupported_access_confirmation(result) or _unsupported_prompt_confirmation(result)
            or _unsupported_tenant_confirmation(result)):
        return False
    confirmed = confirmed_findings(result)
    if confirmed:
        return True
    return result.get("status") == "completed" and any(
        check.get("status") == "completed" and check.get("outcome") == "passed"
        and _protected_access_claim(check)
        and _access_context(result) is not None and protected_access_pass(
            check, evidence_schema_version=result.get('check_evidence_schema_version'), **_access_context(result))
        for check in result.get("checks", []))


def preserves_observation_eligibility(previous, current):
    """A mixed-ledger extension cannot invalidate acknowledged supported evidence.

    Public asset rows and security results expose execution status differently.
    This guard does not require a score: evidence is committed before scoring.
    Existing identity, typed-prefix and schema checks remain separate guards.
    """
    if not isinstance(previous, dict) or not isinstance(current, dict):
        return False
    if not is_mixed_evidence_version(previous.get('check_evidence_schema_version')):
        return True
    if current.get('check_evidence_schema_version') != previous.get('check_evidence_schema_version'):
        return False
    def execution(value):
        return dict(value, status=value.get('security_status', value.get('status')),
                    check_schema_version=CHECK_SCHEMA_VERSION)
    try:
        return not risk_assessment_eligible(execution(previous)) or risk_assessment_eligible(execution(current))
    except (TypeError, ValueError, KeyError, AttributeError, OverflowError, RecursionError):
        return False


def confirmed_findings(result):
    """Select findings with matching versioned confirmed check evidence."""
    if not isinstance(result, dict):
        return []
    try:
        validate_check_evidence(result)
    except (TypeError, ValueError, KeyError):
        return []
    observed = {finding.get('id') for finding in evidence_findings(result)}
    checks = {(check.get("rule_id"), check.get("probe_id"), check.get("probe_version")): check
              for check in result.get("checks", []) if check.get("outcome") == "confirmed"}
    return [finding for finding in result.get("vulnerabilities", [])
            if finding.get("evidence_status") == "confirmed"
            and (isinstance(finding.get('id'), str) and finding['id'] in observed or (
                not prompt_claim(finding)
                and (identity := (finding.get("rule_id"), finding.get("probe_id"), finding.get("probe_version"))) in checks
                and _supported_confirmation(checks[identity], finding, result)))]


def tenant_evidence_views_match(agent, security):
    """Only tenant positives require matching canonical public target bindings."""
    try:
        values = [*agent.get('vulnerabilities', []), *agent.get('checks', []),
                  *security.get('vulnerabilities', []), *security.get('checks', [])]
        positive = any(tenant_claim(value) and (
            value.get('evidence_status') == 'confirmed' or value.get('outcome') == 'confirmed') for value in values)
        if not positive:
            return True
        def target(value):
            return tenant_target(*(value.get(key) for key in (
                'endpoint', 'provider', 'model', 'evidence_context_id')))
        return target(agent) == target(security)
    except (TypeError, ValueError, KeyError, AttributeError, OverflowError, RecursionError):
        return False


def access_evidence_views_match(agent, security):
    """Modern access verdicts bind both public views to the same resource context."""
    if agent.get('check_evidence_schema_version') != '3.0':
        return True
    try:
        values = [*agent.get('vulnerabilities', []), *agent.get('checks', []),
                  *security.get('vulnerabilities', []), *security.get('checks', [])]
        assessed = any(access_claim(value) and (value.get('evidence_status') == 'confirmed'
                                                or value.get('outcome') in {'confirmed', 'passed'}) for value in values)
        return not assessed or access_target(agent, strict=False) == access_target(security, strict=False)
    except (TypeError, ValueError, KeyError, AttributeError, UnicodeError, OverflowError, RecursionError):
        return False


def _validate_evidence_views(result):
    """New writes preserve one canonical evidence ledger across both public views."""
    agents, security_results = result['agents'], result.get('security_results', [])
    if not isinstance(security_results, list):
        raise ValueError('Security results must be an array')
    snapshots = {}
    for agent in agents:
        identity = agent.get('id')
        if not isinstance(identity, str) or not identity or identity in snapshots:
            raise ValueError('Observation asset identity is ambiguous')
        if agent.get('check_evidence_schema_version') != result.get('check_evidence_schema_version'):
            raise ValueError('Observation asset requires matching schema')
        snapshots[identity] = agent
    seen = set()
    shared = ('check_evidence_schema_version', 'check_evidence_run_id', 'provider', 'model')
    for security in security_results:
        if not isinstance(security, dict):
            raise ValueError('Invalid observation security result')
        identity = security.get('agent_id')
        if not isinstance(identity, str) or identity not in snapshots or identity in seen:
            raise ValueError('Observation security identity is ambiguous')
        seen.add(identity)
        agent = snapshots[identity]
        if any((key in agent) != (key in security) or agent.get(key) != security.get(key) for key in shared):
            raise ValueError('Observation evidence views disagree')
        if any(agent.get(key, []) != security.get(key, []) for key in (
                'check_evidence', 'checks', 'vulnerabilities', 'observations')):
            raise ValueError('Observation evidence views disagree')
        if not tenant_evidence_views_match(agent, security):
            raise ValueError('Observation tenant target bindings disagree')
        if not http_views_match(agent, security):
            raise ValueError('Observation HTTP application target bindings disagree')
        if not access_evidence_views_match(agent, security):
            raise ValueError('Observation access target bindings disagree')
        if agent.get('security_status') != security.get('status'):
            raise ValueError('Observation execution views disagree')
    for identity, agent in snapshots.items():
        if identity not in seen and (agent.get('check_evidence') or 'check_evidence_run_id' in agent
                                     or agent.get('vulnerabilities') or agent.get('observations')
                                     or any(check.get('probe_version') != '1:unexecuted'
                                            for check in agent.get('checks', []))):
            raise ValueError('Observation evidence requires a matching security result')


def validate_scan_result(result, *, validate_evidence=True):
    if not isinstance(result, dict) or result.get("schema_version") != "1.0":
        raise ValueError("Expected a version 1.0 scan report")
    if not isinstance(result.get("agents"), list):
        raise ValueError("Report agents must be an array")
    modern = "check_schema_version" in result
    if modern and result["check_schema_version"] != CHECK_SCHEMA_VERSION:
        raise ValueError("Unsupported check schema version")
    evidence_version = result.get('check_evidence_schema_version')
    if validate_evidence and 'check_evidence_schema_version' in result and not is_supported_evidence_version(evidence_version):
        raise ValueError('Unsupported observation schema version')
    for agent in result["agents"]:
        if not isinstance(agent, dict) or not isinstance(agent.get("vulnerabilities", []), list):
            raise ValueError("Invalid agent findings")
        if not all(isinstance(finding, dict) for finding in agent.get("vulnerabilities", [])):
            raise ValueError("Each finding must be an object")
        if modern:
            if not isinstance(agent.get("id"), str) or not agent["id"]:
                raise ValueError("Asset snapshot requires a nonempty ID")
            validate_checks(agent.get("checks", []))
            for finding in agent.get("vulnerabilities", []):
                identifiers = ("rule_id", "probe_id", "probe_version")
                if any(key in finding for key in identifiers) and not all(
                        isinstance(finding.get(key), str) and finding[key] for key in identifiers):
                    raise ValueError("Finding requires rule, probe, and probe version together")
                if "evidence_status" in finding and finding["evidence_status"] not in {
                        "confirmed", "heuristic", "inconclusive"}:
                    raise ValueError("Invalid finding evidence status")
        if validate_evidence and (is_http_agent(agent) or has_evidence_contract(agent)):
            if evidence_version != agent.get('check_evidence_schema_version'):
                raise ValueError('Conflicting observation schema versions')
            validate_check_evidence(agent, strict=False)
    for security in result.get('security_results', []):
        if validate_evidence and (is_http_agent(security) or has_evidence_contract(security)):
            if evidence_version != security.get('check_evidence_schema_version'):
                raise ValueError('Conflicting observation schema versions')
            validate_check_evidence(security, strict=False)
    if validate_evidence and is_supported_evidence_version(evidence_version):
        _validate_evidence_views(result)
    return result


def validate_checkpoint_report(report, *, final=False):
    """Validate a bounded canonical checkpoint without changing its contents."""
    try:
        validate_scan_result(report)
        identifiers = [agent.get("id") for agent in report["agents"]]
        if len(set(identifiers)) != len(identifiers):
            raise ValueError("Checkpoint asset identity is ambiguous")
        if report.get("check_schema_version") != CHECK_SCHEMA_VERSION:
            raise ValueError("Checkpoint requires current evidence contracts")
        if report.get("status") not in ({"completed", "partial"} if final else {"partial"}):
            raise ValueError("Invalid checkpoint execution status")
        checkpoint = report.get("checkpoint")
        if (not isinstance(checkpoint, dict) or set(checkpoint) != {"version", "sequence", "coverage"}
                or type(checkpoint["sequence"]) is not int
                or not 1 <= checkpoint["sequence"] <= MAX_CHECKPOINTS):
            raise ValueError("Invalid checkpoint metadata")
        version = checkpoint['version']
        if version == '1.0':
            if (checkpoint['coverage'] != 'finalized_checks_only'
                    or has_evidence_contract(report)
                    or any(has_evidence_contract(value) for value in (
                        *report['agents'], *report.get('security_results', [])))):
                raise ValueError('Legacy checkpoint cannot carry observations')
        elif checkpoint_evidence_version(version) is not None:
            if (checkpoint['coverage'] != 'confirmed_observations_and_finalized_checks'
                    or report.get('check_evidence_schema_version') != checkpoint_evidence_version(version)):
                raise ValueError('Observation checkpoint requires current evidence schema')
        else:
            raise ValueError('Unsupported checkpoint version')
        if not all(isinstance(report.get(key), list) for key in ("security_results", "risk_assessments")):
            raise ValueError("Invalid checkpoint result arrays")
        if not isinstance(report.get("summary"), dict):
            raise ValueError("Invalid checkpoint summary")
        encoded = json.dumps(report, ensure_ascii=True, allow_nan=False, separators=(",", ":")).encode("utf-8")
        if len(encoded) > MAX_CHECKPOINT_BYTES:
            raise ValueError("Checkpoint size limit exceeded")
    except (TypeError, ValueError, OverflowError, RecursionError):
        raise CheckpointError() from None
    return report
