"""Versioned scan results shared by API, CLI, and report exporters."""

from dataclasses import asdict, is_dataclass
from datetime import datetime, timezone
from copy import deepcopy
from urllib.parse import urlsplit, urlunsplit


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
    return redact_secrets({
        "schema_version": SCHEMA_VERSION,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "scan_type": scan_type,
        "status": "partial" if failed or partial or risk_status == "failed" else "completed",
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
    """Export findings and execution completeness without claiming clean skipped assets."""
    findings = []
    rules = {}
    for agent in result.get("agents", []):
        for finding in agent.get("vulnerabilities", []):
            rule_id = str(finding.get("vulnerability_type") or finding.get("type") or "unknown")
            rules.setdefault(rule_id, {"id": rule_id, "shortDescription": {"text": rule_id}})
            findings.append({
                "ruleId": rule_id,
                "level": {"critical": "error", "high": "error", "medium": "warning"}.get(
                    finding.get("severity"), "note"),
                "message": {"text": str(finding.get("description") or finding.get("title") or rule_id)},
                "properties": {"asset_id": agent["id"], "finding": finding},
            })
    summary = result.get("summary", {})
    complete = result.get("status") == "completed" and not any(
        summary.get(key, 0) for key in ("agents_failed", "agents_partial", "agents_skipped", "agents_not_tested")
    )
    return {"version": "2.1.0", "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "runs": [{"tool": {"driver": {"name": "AI Agent Scanner", "rules": list(rules.values())}},
                      "results": findings, "invocations": [{"executionSuccessful": complete}],
                      "properties": {"scan_status": result.get("status"), "summary": summary}}]}
