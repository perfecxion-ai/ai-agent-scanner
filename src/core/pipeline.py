"""Versioned scan results shared by API, CLI, and report exporters."""

from dataclasses import asdict, is_dataclass
from datetime import datetime, timezone
from copy import deepcopy
from urllib.parse import urlsplit, urlunsplit
from src.core.transport import current_budget
from src.reporting.sarif_output import generate_sarif


SCHEMA_VERSION = "1.0"


def public_metadata(metadata):
    allowed = {"internet_facing", "public_api", "processes_pii", "financial_data_access", "healthcare_data"}
    clean = {key: value for key, value in metadata.items() if key in allowed and isinstance(value, bool)}
    if metadata.get("environment") in {"production", "development", "staging", "test"}:
        clean["environment"] = metadata["environment"]
    return clean


def redact_secrets(value, secrets):
    if isinstance(value, dict):
        return {key: redact_secrets(item, secrets) for key, item in value.items()}
    if isinstance(value, list):
        return [redact_secrets(item, secrets) for item in value]
    if isinstance(value, str):
        for secret in secrets:
            value = value.replace(secret, "[redacted]")
    return value


def collect_secrets(value):
    secrets = set()
    if isinstance(value, dict):
        for key, item in value.items():
            if any(word in key.lower() for word in ("secret", "token", "password", "canary", "marker", "api_key", "authorization")):
                if isinstance(item, str) and item:
                    secrets.add(item)
                elif isinstance(item, dict):
                    secrets.update(str(entry) for entry in item.values() if isinstance(entry, str) and entry)
            secrets.update(collect_secrets(item))
    elif isinstance(value, list):
        for item in value:
            secrets.update(collect_secrets(item))
    return secrets


async def run_pipeline(discovery, security, risk, scope, scan_type="full", agents=None,
                       agent_validator=None):
    """Run requested phases, preserving unsuccessful security outcomes."""
    if scan_type not in {"full", "discovery_only", "security_only"}:
        raise ValueError("Unsupported scan type")
    if scan_type == "security_only":
        if agents is None:
            raise ValueError("Security-only scans require source agents")
    else:
        agents = await discovery.discover_agents(scope)
    observations = [asdict(agent) if is_dataclass(agent) else deepcopy(agent) for agent in agents]
    secrets = collect_secrets(observations)
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
            result["metadata"] = public_metadata(agent.get("metadata", {}))
            security_results.append(result)
    completed = [result for result in security_results if result["status"] == "completed"]
    risk_status = "not_run"
    risks = []
    if completed:
        try:
            risks = await risk.assess_risks(completed)
            risk_status = "completed"
        except Exception:
            risk_status = "failed"
    tests_by_id = {result["agent_id"]: result for result in security_results}
    risks_by_id = {result["agent_id"]: result for result in risks}
    public_agents = []
    for original in observations:
        agent = {key: original[key] for key in ("id", "name", "type", "provider", "endpoint", "discovery_method", "confidence") if key in original}
        agent["metadata"] = public_metadata(original.get("metadata", {}))
        if agent.get("endpoint"):
            endpoint = urlsplit(agent["endpoint"])
            agent["endpoint_redacted"] = bool(endpoint.query or endpoint.username or endpoint.password)
            agent["endpoint"] = urlunsplit((endpoint.scheme, endpoint.netloc.rsplit('@', 1)[-1], endpoint.path, '', ''))
        test = tests_by_id.get(agent["id"], {})
        assessment = risks_by_id.get(agent["id"], {})
        agent["security_status"] = test.get("status", "not_tested")
        agent["vulnerabilities"] = test.get("vulnerabilities", [])
        agent["risk_score"] = assessment.get("overall_risk_score")
        agent["risk_level"] = assessment.get("risk_level", "unknown")
        public_agents.append(agent)
    observations = public_agents
    findings = [finding for agent in observations for finding in agent["vulnerabilities"]]
    failed = sum(result["status"] == "failed" for result in security_results)
    partial = sum(result["status"] == "partial" for result in security_results)
    skipped = sum(result["status"] == "skipped" for result in security_results)
    budget = current_budget()
    transport_incomplete = bool(budget and (budget.failures or budget.rejections))
    return redact_secrets({
        "schema_version": SCHEMA_VERSION,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "scan_type": scan_type,
        "status": "partial" if failed or partial or transport_incomplete or risk_status == "failed" else "completed",
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
        },
    }, secrets)


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
    report["runs"][0]["invocations"][0]["executionSuccessful"] = complete
    report["runs"][0]["properties"] = {"scan_status": result.get("status"), "summary": summary}
    return report
