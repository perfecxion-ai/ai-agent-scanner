"""Versioned scan results shared by API, CLI, and report exporters."""

from dataclasses import asdict, is_dataclass
from datetime import datetime, timezone
from copy import deepcopy
from urllib.parse import urlsplit, urlunsplit
from src.core.transport import current_budget, scan_transport, ScanBudget
from src.core.redaction import collect_secrets, redact_secrets
from src.reporting.sarif_output import generate_sarif
from src.utils.request_builder import resolve_api_key
from src.core.contracts import CHECK_SCHEMA_VERSION, missing_checks, validate_checks, validate_scan_result, risk_assessment_eligible


SCHEMA_VERSION = "1.0"


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
                       agent_validator=None):
    """Run requested phases, preserving unsuccessful security outcomes."""
    if current_budget() is None:
        with scan_transport(ScanBudget()):
            return await run_pipeline(discovery, security, risk, scope, scan_type,
                                      agents, agent_validator)
    if scan_type not in {"full", "discovery_only", "security_only"}:
        raise ValueError("Unsupported scan type")
    if scan_type == "security_only":
        if agents is None:
            raise ValueError("Security-only scans require source agents")
    else:
        agents = await discovery.discover_agents(scope)
    observations = [asdict(agent) if is_dataclass(agent) else deepcopy(agent) for agent in agents]
    secrets = collect_secrets(observations)
    secrets.update(key for agent in observations if (key := resolve_api_key(agent)))
    security_results = []
    if scan_type != "discovery_only":
        if agent_validator:
            observations = agent_validator(observations)
        for agent in observations:
            if not agent.get("endpoint"):
                result = {"agent_id": agent["id"], "agent_name": agent["name"],
                          "status": "skipped", "reason": "No accessible endpoint", "vulnerabilities": []}
            else:
                try:
                    results = await security.test_agents([agent])
                    result = results[0] if results else {}
                    if result.get("status") not in {"completed", "partial", "failed", "skipped"}:
                        raise ValueError("Missing security result status")
                except Exception:
                    result = {"agent_id": agent["id"], "agent_name": agent["name"],
                              "status": "failed", "error": "Security testing failed", "vulnerabilities": []}
            # Do not persist arbitrary transport exceptions that may contain credentials.
            if result.get("error"):
                result["error"] = "Security testing failed"
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
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "scan_type": scan_type,
        "status": "partial" if failed or partial or skipped or transport_incomplete or risk_status == "failed" else "completed",
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
        },
    }, secrets)
    return validate_scan_result(report)


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
    return report
