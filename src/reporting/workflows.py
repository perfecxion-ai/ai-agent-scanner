"""Offline inventory comparison and explicit, expiring finding suppression."""

import hashlib
import json
from copy import deepcopy
from datetime import datetime, timezone
from urllib.parse import urlsplit, urlunsplit
from src.core.http_application_policy import is_http_agent, validate_http_agent
from src.core.contracts import proves_absence, validate_scan_result


def _digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _validate(report):
    validate_scan_result(report)


def asset_identity(agent):
    """Prefer cloud resource identity, then endpoint, source, or labeled fallback."""
    endpoint = agent.get("endpoint")
    metadata = agent.get("metadata", {})
    resource = metadata.get("resource_id")
    if is_http_agent(agent):
        validate_http_agent(agent)
        basis = ['http_application_contract', agent['http_target_binding']]
        quality = 'http_application_contract'
    elif isinstance(resource, str) and resource.strip() and len(resource) <= 2048 and metadata.get("cloud") in {"aws", "azure", "gcp"}:
        basis = ["cloud_resource", metadata["cloud"], agent.get("provider"), resource]
        quality = "cloud_resource"
    elif endpoint:
        parsed = urlsplit(endpoint)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ValueError("Invalid report endpoint")
        host = parsed.hostname.lower()
        if ':' in host:
            host = f'[{host}]'
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        canonical = urlunsplit((parsed.scheme, f"{host}:{port}", parsed.path or '/', parsed.query, ''))
        basis = ["endpoint", canonical]
        quality = "redacted_endpoint" if agent.get("endpoint_redacted") else "endpoint"
    else:
        source = metadata.get("source_path") or metadata.get("file_path") or metadata.get("repository")
        basis = ["source" if source else "fallback", source, agent.get("provider"),
                 agent.get("name"), agent.get("type"), agent.get("discovery_method")]
        quality = "source" if source else "provider_name_fallback"
    return {"asset_key": _digest(basis), "identity_basis": quality,
            "name": agent.get("name"), "endpoint": endpoint, "provider": agent.get("provider"),
            "model": agent.get("model")}


def inventory(report):
    _validate(report)
    assets = {}
    findings = {}
    for agent in report["agents"]:
        identity = asset_identity(agent)
        key = identity["asset_key"]
        if key in assets:
            assets[key]["ambiguous"] = True
        else:
            assets[key] = {**identity, "security_status": agent.get("security_status", "unknown"),
                           "checks": deepcopy(agent.get("checks", [])),
                           "ambiguous": False}
        for finding in agent.get("vulnerabilities", []):
            rule = finding.get("rule_id") or finding.get("vulnerability_type") or finding.get("type")
            if not isinstance(rule, str) or not rule:
                raise ValueError("Finding requires a stable rule or vulnerability type")
            semantic = [rule, finding.get("category"), finding.get("test_name"), finding.get("path")]
            finding_key = _digest([key, semantic])
            if finding_key in findings:
                findings[finding_key]["occurrences"].append(deepcopy(finding))
            else:
                findings[finding_key] = {"finding_key": finding_key, "asset_key": key, "rule_id": rule,
                                         "finding": deepcopy(finding), "occurrences": [deepcopy(finding)]}
    return assets, findings


def _complete(report):
    return report.get("status") == "completed" and report.get("scan_type") != "discovery_only" and not any(
        report.get("summary", {}).get(key, 0) for key in (
            "agents_failed", "agents_partial", "agents_skipped", "agents_not_tested")
    )


def compare_reports(before, after):
    old_assets, old_findings = inventory(before)
    new_assets, new_findings = inventory(after)
    # Keep original context presence; inventory labels may synthesize absent values.
    old_contexts = {asset_identity(agent)['asset_key']: agent for agent in before['agents']}
    new_contexts = {asset_identity(agent)['asset_key']: agent for agent in after['agents']}
    absent = old_findings.keys() - new_findings.keys()
    resolved, unverified = [], []
    for key in sorted(absent):
        item = old_findings[key]
        asset = new_assets.get(item["asset_key"])
        verified = (_complete(after) and asset and asset["security_status"] == "completed"
                    and not asset["ambiguous"] and not old_assets[item["asset_key"]]["ambiguous"]
                    and asset["identity_basis"] == "endpoint"
                    and old_assets[item["asset_key"]]["identity_basis"] == "endpoint"
                    and asset["provider"] == old_assets[item["asset_key"]]["provider"]
                    and asset["model"] == old_assets[item["asset_key"]]["model"]
                    and all(occurrence.get("probe_id") and occurrence.get("probe_version") and any(
                        isinstance(check, dict) and proves_absence(
                            check, occurrence, asset=new_contexts[item['asset_key']],
                            previous_asset=old_contexts[item['asset_key']])
                        for check in asset.get("checks", []))
                        for occurrence in item["occurrences"]))
        (resolved if verified else unverified).append(item)
    return {"workflow": "diff", "schema_version": "1.0",
            "before_scan_id": before.get("scan_id"), "after_scan_id": after.get("scan_id"),
            "baseline_complete": _complete(before), "current_complete": _complete(after),
            "inventory_added": [new_assets[key] for key in sorted(new_assets.keys() - old_assets.keys())],
            "inventory_not_observed": [old_assets[key] for key in sorted(old_assets.keys() - new_assets.keys())],
            "newly_observed": [new_findings[key] for key in sorted(new_findings.keys() - old_findings.keys())],
            "persistent": [new_findings[key] for key in sorted(new_findings.keys() & old_findings.keys())],
            "resolved": resolved, "resolution_unverified": unverified}


def apply_policy(report, policy, now=None):
    """Derive triage output; keep source findings immutable and expired rules inactive."""
    assets, findings = inventory(report)
    if not isinstance(policy, dict) or set(policy) != {"suppressions"} or not isinstance(policy["suppressions"], list):
        raise ValueError("Policy must contain a suppressions array")
    now = now or datetime.now(timezone.utc)
    if now.tzinfo is None:
        raise ValueError("Policy evaluation time requires a timezone")
    rules, expired = {}, []
    for entry in policy["suppressions"]:
        required = {"asset_key", "rule_id", "rationale", "expires_at"}
        if not isinstance(entry, dict) or set(entry) != required:
            raise ValueError("Suppression requires asset_key, rule_id, rationale, and expires_at")
        if not all(isinstance(entry[key], str) and entry[key].strip() for key in required):
            raise ValueError("Suppression fields must be nonempty strings")
        if len(entry["asset_key"]) != 64 or any(c not in '0123456789abcdef' for c in entry["asset_key"]):
            raise ValueError("asset_key must identify a specific asset; wildcards are not supported")
        try:
            expiry = datetime.fromisoformat(entry["expires_at"].replace('Z', '+00:00'))
        except ValueError as exc:
            raise ValueError("Invalid suppression expiry") from exc
        if expiry.tzinfo is None:
            raise ValueError("Suppression expiry requires a timezone")
        if expiry <= now:
            expired.append(deepcopy(entry))
            continue
        key = (entry["asset_key"], entry["rule_id"])
        if key in rules:
            raise ValueError("Duplicate active suppression for the same asset and rule")
        rules[key] = entry
    active, suppressed = [], []
    for item in findings.values():
        rule = rules.get((item["asset_key"], item["rule_id"]))
        if rule and not assets[item["asset_key"]]["ambiguous"]:
            suppressed.append({**item, "suppression": deepcopy(rule)})
        else:
            active.append(item)
    return {"workflow": "triage", "schema_version": "1.0", "source_scan_id": report.get("scan_id"),
            "evaluated_at": now.isoformat(), "source_status": report.get("status"),
            "inventory": list(assets.values()), "active_findings": active, "suppressed_findings": suppressed,
            "expired_suppressions": expired,
            "summary": {"active_findings": len(active), "suppressed_findings": len(suppressed),
                        "expired_suppressions": len(expired)}}
