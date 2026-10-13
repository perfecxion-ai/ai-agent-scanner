"""Additive scan contracts and context-local evidence accounting."""

from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import asdict, dataclass
from functools import wraps
import hashlib
import json
from typing import Literal, TypedDict

from src.core.transport import current_budget
from src.utils.request_builder import extract_response_text


CHECK_SCHEMA_VERSION = "1.0"
PLANNED_RULES = tuple("prompt_injection." + category for category in (
    "system_prompt_extraction", "instruction_bypass", "role_manipulation", "dan_jailbreak",
    "context_manipulation", "injection_via_encoding", "payload_injection")) + (
    "authentication_bypass", "weak_credentials", "weak_api_key", "authorization_bypass",
    "no_rate_limiting", "insecure_session_management", "pii_disclosure",
    "tenant_isolation_violation", "data_retention", "privacy_transparency_issue",
    "information_disclosure_in_errors")
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


_records = ContextVar("security_check_records", default=None)
_execution = ContextVar("security_check_execution", default=None)


@contextmanager
def collect_checks():
    records = []
    token = _records.set(records)
    try:
        yield records
    finally:
        _records.reset(token)


def record_interaction(valid: bool, decisive: bool = False):
    """Record response analysis, excluding empty or rejected required responses."""
    execution = _execution.get()
    if execution is not None:
        execution.evaluated += int(valid)
        execution.failed_interactions += int(not valid)
        execution.failed |= not valid
        execution.decisive &= decisive


def has_canary(agent, field):
    value = agent.get(field)
    return isinstance(value, str) and len(value) >= 16


def usable_model_response(text):
    """Supported adapters return JSON with nonempty generated text."""
    try:
        body = json.loads(text)
    except (ValueError, TypeError):
        return False
    return isinstance(body, dict) and bool(extract_response_text(text).strip())


def checked(rule, spec, prerequisite=None, oracle=None):
    """Track a probe group without storing prompts, credentials, or response bodies."""
    def decorate(method):
        @wraps(method)
        async def wrapped(self, agent, *args, **kwargs):
            rule_id = rule(self, *args, **kwargs) if callable(rule) else rule
            definition = spec(self, *args, **kwargs) if callable(spec) else spec
            # Bind the selected protocol/model and public probe definition.
            # Protected canaries and actual credentials are excluded.
            identity = [definition, agent.get("provider"), agent.get("model")]
            version = "1:" + hashlib.sha256(json.dumps(identity, sort_keys=True).encode()).hexdigest()
            probe_id = rule_id + ".sample"
            reason = prerequisite(agent) if prerequisite else None
            execution = _Execution()
            budget = current_budget()
            before = (budget.requests, budget.failures + budget.rejections) if budget else (0, 0)
            findings = []
            token = _execution.set(execution)
            try:
                if not reason:
                    findings = await method(self, agent, *args, **kwargs)
            except Exception:
                execution.failed = True
                raise
            finally:
                _execution.reset(token)
                attempts = max(0, budget.requests - before[0]) if budget else execution.evaluated
                attempts = max(attempts, execution.evaluated + execution.failed_interactions)
                execution.failed |= bool(budget and budget.failures + budget.rejections > before[1])
                evidence = {finding.get("evidence_status") for finding in findings}
                if reason:
                    status, outcome = "skipped", "not_evaluated"
                elif execution.failed:
                    status = "failed"
                    outcome = "confirmed" if "confirmed" in evidence else "inconclusive"
                    reason = "Some required interactions failed or returned unusable responses"
                elif not execution.evaluated:
                    status, outcome = "skipped", "not_evaluated"
                    reason = "No response was evaluated"
                else:
                    status = "completed"
                    outcome = ("confirmed" if "confirmed" in evidence else "heuristic" if evidence else
                               "passed" if oracle and oracle(agent) and execution.decisive else "inconclusive")
                record = CheckRecord(rule_id, probe_id, version, status, outcome,
                                     attempts, execution.evaluated, reason,
                                     agent.get("evidence_context_id"))
                if _records.get() is not None:
                    _records.get().append(record.to_dict())
                for finding in findings:
                    finding.update(rule_id=rule_id, probe_id=probe_id, probe_version=version,
                                   evidence_context_id=record.evidence_context_id)
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


def missing_checks(records, reason):
    recorded = {record["rule_id"] for record in records}
    return [CheckRecord(rule, rule + ".sample", "1:unexecuted", "skipped",
                        "not_evaluated", reason=reason).to_dict()
            for rule in PLANNED_RULES if rule not in recorded]


def proves_absence(check, finding):
    try:
        record = CheckRecord(**check)
    except (TypeError, ValueError):
        return False
    context = record.evidence_context_id
    safe_context = (isinstance(context, str) and context.strip()
                    and "[" not in context and "]" not in context)
    return (safe_context and context == finding.get("evidence_context_id")
            and record.status == "completed" and record.outcome == "passed"
            and record.rule_id == finding.get("rule_id", finding.get("vulnerability_type"))
            and record.probe_id == finding.get("probe_id")
            and record.probe_version == finding.get("probe_version"))


def validate_scan_result(result):
    if not isinstance(result, dict) or result.get("schema_version") != "1.0":
        raise ValueError("Expected a version 1.0 scan report")
    if not isinstance(result.get("agents"), list):
        raise ValueError("Report agents must be an array")
    modern = "check_schema_version" in result
    if modern and result["check_schema_version"] != CHECK_SCHEMA_VERSION:
        raise ValueError("Unsupported check schema version")
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
    return result
