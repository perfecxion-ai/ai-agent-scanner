"""Versioned scan results shared by API, CLI, and report exporters."""

from dataclasses import asdict, is_dataclass
from datetime import datetime, timezone
from copy import deepcopy


SCHEMA_VERSION = "1.0"


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
                    if result.get("status") not in {"completed", "failed", "skipped"}:
                        raise ValueError("Missing security result status")
                except Exception:
                    result = {"agent_id": agent["id"], "agent_name": agent["name"],
                              "status": "failed", "error": "Security testing failed", "vulnerabilities": []}
            # Do not persist arbitrary transport exceptions that may contain credentials.
            if result.get("error"):
                result["error"] = "Security testing failed"
            result["metadata"] = deepcopy(agent.get("metadata", {}))
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
    for agent in observations:
        test = tests_by_id.get(agent["id"], {})
        assessment = risks_by_id.get(agent["id"], {})
        agent["security_status"] = test.get("status", "not_tested")
        agent["vulnerabilities"] = test.get("vulnerabilities", [])
        agent["risk_score"] = assessment.get("overall_risk_score")
        agent["risk_level"] = assessment.get("risk_level", "unknown")
    findings = [finding for agent in observations for finding in agent["vulnerabilities"]]
    failed = sum(result["status"] == "failed" for result in security_results)
    skipped = sum(result["status"] == "skipped" for result in security_results)
    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "scan_type": scan_type,
        "status": "partial" if failed or risk_status == "failed" else "completed",
        "risk_assessment_status": risk_status,
        "agents": observations,
        "security_results": security_results,
        "risk_assessments": risks,
        "summary": {
            "agents_discovered": len(observations), "vulnerabilities_found": len(findings),
            "critical_risks": sum(finding.get("severity") == "critical" for finding in findings),
            "overall_risk_score": max((item["overall_risk_score"] for item in risks), default=None),
            "agents_tested": len(completed), "agents_failed": failed, "agents_skipped": skipped,
            "agents_not_tested": len(observations) - len(security_results),
        },
    }


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
        summary.get(key, 0) for key in ("agents_failed", "agents_skipped", "agents_not_tested")
    )
    return {"version": "2.1.0", "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "runs": [{"tool": {"driver": {"name": "AI Agent Scanner", "rules": list(rules.values())}},
                      "results": findings, "invocations": [{"executionSuccessful": complete}],
                      "properties": {"scan_status": result.get("status"), "summary": summary}}]}
