"""Versioned scan results shared by API, CLI, and report exporters."""

from dataclasses import asdict, is_dataclass
import asyncio
from collections import Counter
from contextlib import nullcontext
from datetime import datetime, timezone
from copy import deepcopy
import json
from urllib.parse import urlsplit, urlunsplit
from src.core.transport import current_budget, scan_transport, ScanBudget
from src.core.redaction import collect_secrets, redact_secrets
from src.core.risk_projection import project_agent_risk
from src.core.access_probe_policy import PUBLIC_ACCESS_FIELDS
from src.core.prompt_evidence_policy import PUBLIC_EVIDENCE_FIELDS, has_evidence_contract
from src.reporting.sarif_output import generate_sarif
from src.utils.request_builder import resolve_api_key
from src.core.contracts import (
    CHECK_SCHEMA_VERSION, CHECK_EVIDENCE_SCHEMA_VERSION, CheckpointError, MAX_CHECKPOINTS, MAX_CHECKPOINT_BYTES,
    MAX_CHECKPOINT_TOTAL_BYTES, confirmed_findings, missing_checks, observe_checks,
    validate_checks, validate_scan_result, validate_checkpoint_report, risk_assessment_eligible,
    observe_evidence, validate_check_evidence, unfinished_evidence_checks,
)
from src.security.prompt_suites import PROTECTED_DISCLOSURE_SUITE, validate_prompt_suite_agents
from src.security.security_engine import SecurityTestEngine


SCHEMA_VERSION = "1.0"


def _validate_access_field_privacy(secrets):
    if any(secret and any(secret.casefold() in field.casefold() for field in PUBLIC_ACCESS_FIELDS)
           for secret in secrets):
        raise ValueError('Protected evidence conflicts with public access fields')
    if any(secret and any(secret.casefold() in field.casefold() for field in PUBLIC_EVIDENCE_FIELDS)
           for secret in secrets):
        raise ValueError('Protected evidence conflicts with public evidence fields')


def public_metadata(metadata):
    allowed = {"internet_facing", "public_api", "processes_pii", "financial_data_access", "healthcare_data"}
    clean = {key: value for key, value in metadata.items() if key in allowed and isinstance(value, bool)}
    if metadata.get("environment") in {"production", "development", "staging", "test"}:
        clean["environment"] = metadata["environment"]
    resource = metadata.get("resource_id")
    if isinstance(resource, str) and resource.strip() and len(resource) <= 2048:
        clean["resource_id"] = resource
    if metadata.get("cloud") in {"aws", "azure", "gcp"}:
        clean["cloud"] = metadata["cloud"]
    return clean


async def run_pipeline(discovery, security, risk, scope, scan_type="full", agents=None,
                       agent_validator=None, checkpoint_callback=None):
    """Run requested phases, preserving unsuccessful security outcomes."""
    if current_budget() is None:
        with scan_transport(ScanBudget()):
            return await run_pipeline(discovery, security, risk, scope, scan_type,
                                      agents, agent_validator, checkpoint_callback)
    if scan_type not in {"full", "discovery_only", "security_only"}:
        raise ValueError("Unsupported scan type")
    if scan_type == "security_only":
        if agents is None:
            raise ValueError("Security-only scans require source agents")
    else:
        agents = await discovery.discover_agents(scope)
    observations = [asdict(agent) if is_dataclass(agent) else deepcopy(agent) for agent in agents]
    prompt_suite = (PROTECTED_DISCLOSURE_SUITE
                    if getattr(security, "prompt_suite", None) == PROTECTED_DISCLOSURE_SUITE else None)
    secrets = collect_secrets(observations)
    secrets.update(key for agent in observations if (key := resolve_api_key(agent)))
    security_results = []
    if scan_type != "discovery_only":
        if agent_validator:
            observations = agent_validator(observations)
        # Validators may attach protected evidence or resolve model configuration.
        secrets.update(collect_secrets(observations))
        secrets.update(key for agent in observations if (key := resolve_api_key(agent)))
        if prompt_suite is not None:
            validate_prompt_suite_agents(observations)
    checkpoint = None
    evidence_enabled = scan_type != 'discovery_only' and isinstance(security, SecurityTestEngine)
    adapter_evidence_mode = None
    if scan_type != "discovery_only" and isinstance(security, SecurityTestEngine):
        # Ordinary and checkpointed reports use the same privacy/evidence basis.
        secrets.update(security.checkpoint_secrets(observations))
    if scan_type != "discovery_only":
        _validate_access_field_privacy(secrets)
    if checkpoint_callback is not None:
        checkpoint = _CheckpointState(observations, risk, scan_type, prompt_suite, secrets,
                                      checkpoint_callback, evidence_enabled=evidence_enabled)
        await checkpoint.publish()
    if scan_type != "discovery_only":
        for index, agent in enumerate(observations):
            if not agent.get("endpoint"):
                result = {"agent_id": agent["id"], "agent_name": agent["name"],
                          "status": "skipped", "reason": "No accessible endpoint", "vulnerabilities": []}
            else:
                try:
                    if checkpoint:
                        await checkpoint.start(index)
                    async def observed(check, findings):
                        await checkpoint.accept(index, check, findings)
                    async def evidence_observed(receipt, finding):
                        await checkpoint.accept_evidence(index, receipt, finding)
                    with (observe_checks(observed) if checkpoint else nullcontext(),
                          observe_evidence(evidence_observed) if checkpoint else nullcontext()):
                        results = await security.test_agents([agent])
                    result = results[0] if results else {}
                    if result.get("status") not in {"completed", "partial", "failed", "skipped"}:
                        raise ValueError("Missing security result status")
                except CheckpointError:
                    raise
                except Exception:
                    result = {"agent_id": agent["id"], "agent_name": agent["name"],
                              "status": "failed", "error": "Security testing failed", "vulnerabilities": []}
            # Do not persist arbitrary transport exceptions that may contain credentials.
            if result.get("error"):
                result["error"] = "Security testing failed"
            # Probe versions bind original public context, not tester-supplied labels.
            result['provider'], result['model'] = agent.get('provider'), agent.get('model')
            supplied_evidence = has_evidence_contract(result)
            if supplied_evidence:
                validate_check_evidence(result, strict=not isinstance(security, SecurityTestEngine))
            if not isinstance(security, SecurityTestEngine):
                if adapter_evidence_mode is not None and adapter_evidence_mode != supplied_evidence:
                    raise ValueError('Mixed evidence contracts are not supported by this adapter')
                adapter_evidence_mode = supplied_evidence
            if supplied_evidence:
                evidence_enabled = True
                if checkpoint:
                    checkpoint.evidence_enabled = True
            if evidence_enabled:
                result.setdefault('check_evidence_schema_version', CHECK_EVIDENCE_SCHEMA_VERSION)
                result.setdefault('check_evidence', [])
            if "checks" in result:
                try:
                    validate_checks(result["checks"])
                    if any(check["status"] == "failed" for check in result["checks"]) and result["status"] == "completed":
                        result["status"] = "partial"
                except (TypeError, ValueError):
                    result.update(status="failed", error="Invalid security check result", vulnerabilities=[], checks=[])
            else:
                result["checks"] = missing_checks([], "No check-level evidence supplied")
            if result.get("status") == "completed" and not any(
                    check["responses_evaluated"] for check in result["checks"]):
                result.update(status="partial", reason="No security checks evaluated a response")
            if not risk_assessment_eligible(result):
                result["overall_risk_score"] = None
                if "risk_level" in result:
                    result["risk_level"] = "unknown"
            result["metadata"] = public_metadata(agent.get("metadata", {}))
            secrets.update(collect_secrets(result))
            security_results.append(result)
            if checkpoint:
                await checkpoint.finish(index, result)
    if checkpoint:
        return checkpoint.final_report()
    risks, risk_status = await _assess_results(risk, security_results)
    return _project_report(observations, security_results, risks, risk_status, scan_type, prompt_suite, secrets,
                           evidence_enabled=evidence_enabled)


async def _assess_results(risk, security_results):
    completed = [result for result in security_results if result["status"] == "completed"]
    eligible = [result for result in security_results if risk_assessment_eligible(result)]
    risk_status = "not_assessed" if completed and not eligible else "not_run"
    risks = []
    if eligible:
        try:
            risks = await risk.assess_risks(eligible)
            risk_status = "partial" if any(item["status"] != "completed" for item in eligible) else "completed"
        except Exception:
            risk_status = "failed"
    return risks, risk_status


def _project_report(observations, security_results, risks, risk_status, scan_type, prompt_suite, secrets,
                    *, incomplete=False, evidence_enabled=False):
    """One canonical projection for ordinary reports and durable evidence snapshots."""
    if scan_type != "discovery_only":
        _validate_access_field_privacy(secrets)
    security_results, risks = deepcopy(security_results), deepcopy(risks)
    # A public verdict needs independently verifiable public evidence. Redaction
    # can erase the original context used to bind a protected-access probe.
    public_tests = {result['agent_id']: redact_secrets(result, secrets) for result in security_results}

    def supported_assessment(assessment):
        evidence = public_tests.get(assessment['agent_id'], {})
        if not risk_assessment_eligible(evidence):
            return False
        candidate = {**evidence, 'security_status': evidence['status'], **redact_secrets({
            'risk_score': assessment.get('overall_risk_score'),
            'risk_level': assessment.get('risk_level'),
            'risk_coverage_status': assessment.get('coverage_status'),
            'risk_scoring_policy': assessment.get('scoring_policy'),
        }, secrets)}
        return project_agent_risk(candidate, assessed=True)['risk_score'] is not None

    original_risk_count = len(risks)
    risks = [assessment for assessment in risks if supported_assessment(assessment)]
    if len(risks) != original_risk_count:
        risk_status = ('partial' if any(item.get('coverage_status') == 'partial' for item in risks)
                       else 'completed') if risks else 'not_assessed'
    completed = [result for result in security_results if result["status"] == "completed"]
    if incomplete and risks:
        risk_status = "partial"
    tests_by_id = {result["agent_id"]: result for result in security_results}
    risks_by_id = {result["agent_id"]: result for result in risks}
    # The risk phase is authoritative; do not retain conflicting engine estimates.
    for result in security_results:
        assessment = risks_by_id.get(result["agent_id"], {})
        result["overall_risk_score"] = assessment.get("overall_risk_score")
        result["risk_level"] = assessment.get("risk_level", "unknown")
        result["risk_coverage_status"] = assessment.get("coverage_status", "not_assessed")
        result["risk_scoring_policy"] = assessment.get("scoring_policy")
    public_agents = []
    for original in observations:
        agent = {key: original[key] for key in ("id", "name", "type", "provider", "model", "endpoint", "discovery_method", "confidence") if key in original}
        agent['provider'], agent['model'] = original.get('provider'), original.get('model')
        agent["metadata"] = public_metadata(original.get("metadata", {}))
        if agent.get("endpoint"):
            endpoint = urlsplit(agent["endpoint"])
            agent["endpoint_redacted"] = bool(
                original.get("endpoint_redacted") is True or
                original.get("metadata", {}).get("endpoint_redacted") is True or
                endpoint.query or endpoint.username or endpoint.password
            )
            agent["endpoint"] = urlunsplit((endpoint.scheme, endpoint.netloc.rsplit('@', 1)[-1], endpoint.path, '', ''))
        test = tests_by_id.get(agent["id"], {})
        assessment = risks_by_id.get(agent["id"], {})
        agent["security_status"] = test.get("status", "not_tested")
        agent["vulnerabilities"] = test.get("vulnerabilities", [])
        agent["observations"] = test.get("observations", [])
        agent["checks"] = test.get("checks", missing_checks([], "Security testing was not requested"))
        if evidence_enabled:
            agent['check_evidence_schema_version'] = test.get(
                'check_evidence_schema_version', CHECK_EVIDENCE_SCHEMA_VERSION)
            agent['check_evidence'] = test.get('check_evidence', [])
            if 'check_evidence_run_id' in test:
                agent['check_evidence_run_id'] = test['check_evidence_run_id']
        if prompt_suite is not None and scan_type != "discovery_only":
            agent["prompt_suite"] = prompt_suite
        agent["risk_score"] = assessment.get("overall_risk_score")
        agent["risk_level"] = assessment.get("risk_level", "unknown")
        agent["risk_coverage_status"] = assessment.get("coverage_status", "not_assessed")
        agent["risk_scoring_policy"] = assessment.get("scoring_policy")
        public_agents.append(agent)
    observations = public_agents
    findings = [finding for agent in observations for finding in agent["vulnerabilities"]]
    failed = sum(result["status"] == "failed" for result in security_results)
    partial = sum(result["status"] == "partial" for result in security_results)
    skipped = sum(result["status"] == "skipped" for result in security_results)
    budget = current_budget()
    transport_incomplete = bool(budget and (budget.failures or budget.rejections))
    report = redact_secrets({
        "schema_version": SCHEMA_VERSION,
        "check_schema_version": CHECK_SCHEMA_VERSION,
        **({'check_evidence_schema_version': CHECK_EVIDENCE_SCHEMA_VERSION} if evidence_enabled else {}),
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "scan_type": scan_type,
        **({"prompt_suite": prompt_suite} if prompt_suite is not None and scan_type != "discovery_only" else {}),
        "status": "partial" if incomplete or failed or partial or skipped or transport_incomplete or risk_status == "failed" else "completed",
        "transport_incomplete": transport_incomplete,
        "risk_assessment_status": risk_status,
        "agents": observations,
        "security_results": security_results,
        "risk_assessments": risks,
        "summary": {
            "agents_discovered": len(observations), "vulnerabilities_found": len(findings),
            "critical_risks": sum(finding.get("severity") == "critical" for finding in findings),
            "overall_risk_score": max((item["overall_risk_score"] for item in risks), default=None),
            "agents_tested": len(completed), "agents_failed": failed, "agents_skipped": skipped,
            "agents_partial": partial,
            "agents_not_tested": len(observations) - len(security_results),
            "agents_risk_assessed": len(risks),
            "agents_risk_not_assessed": len(observations) - len(risks),
            "checks_completed": sum(check["status"] == "completed" for agent in observations for check in agent["checks"]),
            "checks_skipped": sum(check["status"] == "skipped" for agent in observations for check in agent["checks"]),
            "checks_failed": sum(check["status"] == "failed" for agent in observations for check in agent["checks"]),
            **({'checks_unfinished': sum(len(unfinished_evidence_checks(agent)) for agent in observations)}
               if evidence_enabled else {}),
        },
    }, secrets)
    return validate_scan_result(report)


class _CheckpointState:
    """Scan-local evidence ledger; only acknowledged independent copies escape."""

    def __init__(self, observations, risk, scan_type, prompt_suite, secrets, callback, *, evidence_enabled=False):
        self.observations = deepcopy(observations)
        identifiers = [agent.get("id") for agent in observations]
        if any(not isinstance(value, str) or not value for value in identifiers) or len(set(identifiers)) != len(identifiers):
            raise CheckpointError()
        self.risk, self.scan_type, self.prompt_suite = risk, scan_type, prompt_suite
        self.secrets, self.callback = secrets, callback
        self.evidence_enabled = evidence_enabled
        self.results, self.assessed = {}, {}
        self.sequence = self.total_bytes = 0
        self.last = None

    async def start(self, index):
        agent = self.observations[index]
        self.results[index] = {
            "agent_id": agent["id"], "agent_name": agent["name"], "type": agent.get("type", "unknown"),
            "provider": agent.get("provider"), "model": agent.get("model"),
            "metadata": public_metadata(agent.get("metadata", {})),
            "check_schema_version": CHECK_SCHEMA_VERSION, "status": "partial",
            "vulnerabilities": [], "observations": [], "checks": [],
            **({'check_evidence_schema_version': CHECK_EVIDENCE_SCHEMA_VERSION, 'check_evidence': []}
               if self.evidence_enabled else {}),
        }
        await self.publish()

    @staticmethod
    def _merge_checks(existing, incoming):
        result = [deepcopy(check) for check in existing if check["probe_version"] != "1:unexecuted"]
        identities = {(check["rule_id"], check["probe_id"], check["probe_version"]): check for check in result}
        for check in incoming:
            if check["probe_version"] == "1:unexecuted":
                continue
            key = (check["rule_id"], check["probe_id"], check["probe_version"])
            if key in identities:
                if identities[key] != check:
                    raise CheckpointError()
            else:
                copied = deepcopy(check)
                result.append(copied)
                identities[key] = copied
        validate_checks(result)
        return result

    @staticmethod
    def _merge_findings(existing, incoming):
        def identity(finding):
            return json.dumps(finding, sort_keys=True, allow_nan=False, separators=(",", ":"))
        result = deepcopy(existing)
        prior = Counter(identity(finding) for finding in existing)
        observed = Counter()
        for finding in incoming:
            key = identity(finding)
            observed[key] += 1
            if observed[key] > prior[key]:
                result.append(deepcopy(finding))
        return result

    async def accept(self, index, check, findings):
        validate_checks([check])
        identity = (check["rule_id"], check["probe_id"], check["probe_version"], check["evidence_context_id"])
        if not isinstance(findings, list) or any(
                not isinstance(finding, dict)
                or tuple(finding.get(key) for key in ("rule_id", "probe_id", "probe_version", "evidence_context_id")) != identity
                or finding.get("evidence_status") not in {"confirmed", "heuristic", "inconclusive"}
                for finding in findings):
            raise CheckpointError()
        if any(finding["evidence_status"] == "confirmed" for finding in findings) != (check["outcome"] == "confirmed"):
            raise CheckpointError()
        result = deepcopy(self.results[index])
        unchanged = check in result["checks"]
        result["checks"] = self._merge_checks(result["checks"], [check])
        for key in ("vulnerabilities", "observations"):
            incoming = [finding for finding in findings
                        if (finding["evidence_status"] == "confirmed") == (key == "vulnerabilities")]
            merged = self._merge_findings(result[key], incoming)
            unchanged &= merged == result[key]
            result[key] = merged
        if self.evidence_enabled:
            validate_check_evidence(result, strict=False)
        self.results[index] = result
        self.secrets.update(collect_secrets(findings))
        if not unchanged and (check["status"] != "skipped" or findings):
            await self.refresh()

    @staticmethod
    def _merge_receipts(existing, incoming):
        merged = deepcopy(existing)
        by_id = {item['id']: item for item in existing}
        if len(by_id) != len(existing):
            raise CheckpointError()
        for receipt in incoming:
            previous = by_id.get(receipt['id'])
            if previous is not None and previous != receipt:
                raise CheckpointError()
            if previous is None:
                copied = deepcopy(receipt)
                merged.append(copied)
                by_id[copied['id']] = copied
        return merged

    async def accept_evidence(self, index, receipt, finding):
        if not self.evidence_enabled:
            raise CheckpointError()
        previous = self.results[index]
        result = deepcopy(previous)
        if (result.get('check_evidence_run_id') not in (None, receipt.get('run_id'))
                or receipt.get('agent_id') != self.observations[index]['id']):
            raise CheckpointError()
        result['check_evidence_run_id'] = receipt['run_id']
        result['check_evidence'] = self._merge_receipts(result['check_evidence'], [receipt])
        result['vulnerabilities'] = self._merge_findings(result['vulnerabilities'], [finding])
        validate_check_evidence(result)
        if result == previous:
            return
        self.results[index] = result
        self.secrets.update(collect_secrets([receipt, finding]))
        await self.refresh()

    async def finish(self, index, result):
        previous = self.results.get(index, {})
        merged = deepcopy(result)
        merged["checks"] = self._merge_checks(previous.get("checks", []), result.get("checks", []))
        for key in ("vulnerabilities", "observations"):
            merged[key] = self._merge_findings(previous.get(key, []), result.get(key, []))
        if self.evidence_enabled:
            merged.setdefault('check_schema_version', CHECK_SCHEMA_VERSION)
            merged['check_evidence_schema_version'] = result.get(
                'check_evidence_schema_version', CHECK_EVIDENCE_SCHEMA_VERSION)
            old_run, new_run = previous.get('check_evidence_run_id'), result.get('check_evidence_run_id')
            if old_run is not None and new_run is not None and old_run != new_run:
                raise CheckpointError()
            if old_run is not None or new_run is not None:
                merged['check_evidence_run_id'] = old_run or new_run
            merged['check_evidence'] = self._merge_receipts(
                previous.get('check_evidence', []), result.get('check_evidence', []))
            validate_check_evidence(merged, strict=False)
        self.results[index] = merged
        self.secrets.update(collect_secrets(merged))
        await self.refresh()

    @staticmethod
    def _basis(result):
        # The shared assessor scores confirmed findings and asset context, not
        # the growing request ledger or unrelated heuristic observations.
        return deepcopy({
            "agent_id": result.get("agent_id"), "agent_name": result.get("agent_name"),
            "agent_type": result.get("agent_type"), "type": result.get("type"),
            "provider": result.get("provider"), "model": result.get("model"),
            "metadata": result.get("metadata", {}),
            "vulnerabilities": confirmed_findings(result),
        })

    def _current_risks(self):
        risks = []
        for index, result in self.results.items():
            cached = self.assessed.get(index)
            if risk_assessment_eligible(result) and cached and cached[0] == self._basis(result) and cached[1] is not None:
                assessment = deepcopy(cached[1])
                assessment["coverage_status"] = "sampled" if result["status"] == "completed" else "partial"
                risks.append(assessment)
        return risks

    async def refresh(self):
        # Evidence is durable before an asynchronous scorer can stall or fail.
        await self.publish()
        eligible = {index: result for index, result in self.results.items() if risk_assessment_eligible(result)}
        changed = any(index not in self.assessed or self.assessed[index][0] != self._basis(result)
                      for index, result in eligible.items())
        if not changed:
            return
        try:
            assessments = await self.risk.assess_risks(deepcopy(list(eligible.values())))
            if not isinstance(assessments, list) or not all(isinstance(item, dict) for item in assessments):
                raise CheckpointError()
            by_id = {item["agent_id"]: item for item in assessments}
            if len(by_id) != len(assessments) or set(by_id) - {item["agent_id"] for item in eligible.values()}:
                raise CheckpointError()
            for index, result in eligible.items():
                self.assessed[index] = (self._basis(result), deepcopy(by_id.get(result["agent_id"])))
            await self.publish()
        except asyncio.CancelledError:
            raise
        except Exception:
            raise CheckpointError() from None

    def _report(self, *, incomplete):
        results = deepcopy(list(self.results.values()))
        for result in results:
            unfinished = {identity[0] for identity in unfinished_evidence_checks(result)}
            result["checks"].extend(check for check in missing_checks(
                result["checks"], "No finalized check evidence at checkpoint") if check['rule_id'] not in unfinished)
        risks = self._current_risks()
        if risks:
            risk_status = "partial" if any(item["coverage_status"] == "partial" for item in risks) else "completed"
        else:
            risk_status = "not_assessed" if any(item["status"] == "completed" for item in results) else "not_run"
        return _project_report(self.observations, results, risks, risk_status, self.scan_type,
                               self.prompt_suite, self.secrets, incomplete=incomplete,
                               evidence_enabled=self.evidence_enabled)

    def _preserves_previous(self, report):
        if self.last is None:
            return
        if len(self.last['agents']) != len(report['agents']):
            raise CheckpointError()
        for previous, current in zip(self.last["agents"], report["agents"]):
            fields = ("id", "name", "type", "provider", "model", "endpoint", "endpoint_redacted", "metadata")
            if any(previous.get(key) != current.get(key) for key in fields):
                raise CheckpointError()
            if any(check not in current["checks"] for check in previous["checks"]
                   if check["probe_version"] != "1:unexecuted"):
                raise CheckpointError()
            for key in ("vulnerabilities", "observations"):
                before = Counter(json.dumps(finding, sort_keys=True, allow_nan=False) for finding in previous[key])
                after = Counter(json.dumps(finding, sort_keys=True, allow_nan=False) for finding in current[key])
                if before - after:
                    raise CheckpointError()
            if previous.get('check_evidence_run_id') is not None and (
                    previous['check_evidence_run_id'] != current.get('check_evidence_run_id')):
                raise CheckpointError()
            if 'check_evidence_schema_version' in previous and (
                    previous['check_evidence_schema_version'] != current.get('check_evidence_schema_version')):
                raise CheckpointError()
            old_receipts = previous.get('check_evidence', [])
            if current.get('check_evidence', [])[:len(old_receipts)] != old_receipts:
                raise CheckpointError()

    async def publish(self):
        try:
            if self.sequence >= MAX_CHECKPOINTS:
                raise CheckpointError()
            report = self._report(incomplete=True)
            report["checkpoint"] = {
                "version": "2.0" if self.evidence_enabled else "1.0", "sequence": self.sequence + 1,
                "coverage": "confirmed_observations_and_finalized_checks" if self.evidence_enabled
                else "finalized_checks_only"}
            validate_checkpoint_report(report)
            encoded = json.dumps(report, ensure_ascii=True, allow_nan=False, separators=(",", ":")).encode("utf-8")
            if len(encoded) > MAX_CHECKPOINT_BYTES or self.total_bytes + len(encoded) > MAX_CHECKPOINT_TOTAL_BYTES:
                raise CheckpointError()
            self._preserves_previous(report)
            await self.callback(deepcopy(report))
            self.sequence += 1
            self.total_bytes += len(encoded)
            self.last = deepcopy(report)
        except asyncio.CancelledError:
            raise
        except Exception:
            raise CheckpointError() from None

    def final_report(self):
        try:
            report = self._report(incomplete=False)
            report["checkpoint"] = deepcopy(self.last["checkpoint"])
            validate_checkpoint_report(report, final=True)
            self._preserves_previous(report)
            return report
        except Exception:
            raise CheckpointError() from None


def to_sarif(result):
    """Use the shared SARIF exporter and attach execution completeness."""
    findings = []
    for agent in result.get("agents", []):
        for finding in agent.get("vulnerabilities", []):
            findings.append({**finding, "agent_id": agent["id"]})
    report = generate_sarif(findings, {"started_at": result.get("generated_at")})
    summary = result.get("summary", {})
    complete = result.get("status") == "completed" and not any(
        summary.get(key, 0) for key in ("agents_failed", "agents_partial", "agents_skipped", "agents_not_tested")
    )
    if result.get("source_inventory", {}).get("coverage_complete") is False:
        complete = False
    report["runs"][0]["invocations"][0]["executionSuccessful"] = complete
    report["runs"][0]["properties"] = {
        "scan_status": result.get("status"), "summary": summary,
        "check_schema_version": result.get("check_schema_version"),
        "checks": [{"agent_id": agent["id"], **check}
                   for agent in result.get("agents", []) for check in agent.get("checks", [])],
    }
    if "source_inventory" in result:
        report["runs"][0]["properties"]["source_inventory"] = deepcopy(result["source_inventory"])
    if "checkpoint" in result:
        report["runs"][0]["properties"]["checkpoint"] = deepcopy(result["checkpoint"])
    if 'check_evidence_schema_version' in result:
        report['runs'][0]['properties']['check_evidence_schema_version'] = result['check_evidence_schema_version']
        report['runs'][0]['properties']['check_evidence'] = [
            {'agent_id': agent['id'],
             **({'check_evidence_run_id': agent['check_evidence_run_id']}
                if 'check_evidence_run_id' in agent else {}),
             'check_evidence': deepcopy(agent.get('check_evidence', []))}
            for agent in result.get('agents', [])]
    if result.get("prompt_suite") == PROTECTED_DISCLOSURE_SUITE:
        report["runs"][0]["properties"]["prompt_suite"] = PROTECTED_DISCLOSURE_SUITE
    return report
