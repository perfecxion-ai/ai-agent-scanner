"""Presentation grouping cannot rewrite raw evidence, scoring, or finding lifecycle."""

from copy import deepcopy
import json
from pathlib import Path
import shutil
import subprocess
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest

from src.core.contracts import collect_checks, record_interaction
from src.core.pipeline import run_pipeline, to_sarif
from src.reporting.workflows import apply_policy, compare_reports, inventory
from src.risk.risk_assessor import RiskAssessment
from src.security.prompt_injection_tests import PromptInjectionTester


@pytest.fixture
async def sampled_report():
    tester = PromptInjectionTester()
    agent = {"id": "synthetic-asset", "name": "Synthetic fixture", "type": "assistant",
             "provider": "openai-compatible", "model": "fixture-model", "discovery_method": "fixture",
             "endpoint": "https://fixture.invalid/api", "system_prompt_canary": "synthetic-protected-marker-8c4b21",
             "evidence_context_id": "synthetic-policy-v1"}

    async def disclose(target, category, payload):
        record_interaction(True)
        response = json.dumps({"choices": [{"message": {"content": target["system_prompt_canary"]}}]})
        return tester._analyze_response(target, category, payload, response, 200)

    findings = []
    with collect_checks() as checks, patch.object(tester, "_test_single_payload", side_effect=disclose), patch(
            "asyncio.sleep", AsyncMock()):
        for category, count in zip(tester.injection_payloads, [3, 3, 3, 3, 2, 2, 2]):
            findings.extend(await tester._test_injection_category(
                agent, category, [f"Synthetic payload {index}" for index in range(count)]))
    result = {"agent_id": agent["id"], "agent_name": agent["name"], "status": "completed",
              "check_schema_version": "1.0", "checks": checks, "vulnerabilities": findings}
    report = await run_pipeline(SimpleNamespace(discover_agents=AsyncMock(return_value=[agent])),
                                SimpleNamespace(test_agents=AsyncMock(return_value=[result])), RiskAssessment(), None)
    # Exercise the actual stored/exported JSON contract rather than Python tuples.
    return json.loads(json.dumps(report))


def presentation(report):
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node is required for the actual dashboard presentation helper")
    program = '''
const fs = require('node:fs');
const {groupFindingOccurrences} = require('./static/js/dashboard.js');
const source = JSON.parse(fs.readFileSync(0, 'utf8'));
const groups = groupFindingOccurrences(source).map(group => ({sampled: group.sampled, occurrences: group.occurrences}));
process.stdout.write(JSON.stringify({source, groups}));
'''
    result = subprocess.run([node, "-e", program], input=json.dumps(report), capture_output=True,
                            text=True, timeout=5, check=True, cwd=Path(__file__).resolve().parents[1])
    return json.loads(result.stdout)


@pytest.mark.asyncio
async def test_actual_prompt_evidence_forms_seven_groups_without_losing_samples(sampled_report):
    report = sampled_report
    original = deepcopy(report)
    displayed = presentation(report)
    assert [len(group["occurrences"]) for group in displayed["groups"]] == [3, 3, 3, 3, 2, 2, 2]
    originals = report["agents"][0]["vulnerabilities"]
    assert [item for group in displayed["groups"] for item in group["occurrences"]] == originals
    assert len({finding["id"] for finding in originals}) == 18
    assert sum(check["responses_evaluated"] for check in report["agents"][0]["checks"]) == 18
    assert report["summary"]["checks_completed"] == 7
    assert displayed["source"] == report == original


@pytest.mark.asyncio
async def test_raw_json_sarif_counts_and_risk_are_unchanged(sampled_report):
    report = sampled_report
    original = json.dumps(report, sort_keys=True)
    sarif = to_sarif(report)
    displayed = presentation(report)
    assert displayed["source"] == report
    assert json.dumps(report, sort_keys=True) == original
    assert to_sarif(displayed["source"]) == sarif
    assert len(sarif["runs"][0]["results"]) == 18
    assert len(sarif["runs"][0]["tool"]["driver"]["rules"]) == 7
    assert report["summary"]["vulnerabilities_found"] == report["risk_assessments"][0]["total_vulnerabilities"] == 18
    assert displayed["source"]["summary"]["overall_risk_score"] == 70
    assert displayed["source"]["agents"][0]["risk_level"] == "high"


@pytest.mark.asyncio
async def test_diff_and_suppression_keys_and_original_occurrences_remain_unchanged(sampled_report):
    report = sampled_report
    assets, findings = inventory(report)
    first = next(iter(findings.values()))
    policy = {"suppressions": [{"asset_key": next(iter(assets)), "rule_id": first["rule_id"],
                               "rationale": "Synthetic fixture", "expires_at": "2099-01-01T00:00:00Z"}]}
    comparison = compare_reports(report, report)
    triage = apply_policy(report, policy)
    displayed = presentation(report)["source"]
    assert inventory(displayed) == (assets, findings)
    assert compare_reports(report, displayed) == comparison
    assert apply_policy(displayed, policy)["suppressed_findings"] == triage["suppressed_findings"]
    assert len(triage["suppressed_findings"]) == 1
    assert len(triage["suppressed_findings"][0]["occurrences"]) == 3
    assert len(comparison["persistent"]) == 7 and not comparison["resolved"]


@pytest.mark.asyncio
async def test_nondisclosure_cannot_resolve_after_presentation_grouping(sampled_report):
    before = sampled_report
    after = deepcopy(before)
    after["agents"][0]["vulnerabilities"] = []
    for check in after["agents"][0]["checks"]:
        check["outcome"] = "inconclusive"
    comparison = compare_reports(before, after)
    assert not comparison["resolved"] and len(comparison["resolution_unverified"]) == 7
    assert sum(len(item["occurrences"]) for item in comparison["resolution_unverified"]) == 18
    assert compare_reports(presentation(before)["source"], presentation(after)["source"]) == comparison


@pytest.mark.asyncio
async def test_unknown_and_historical_risk_are_not_recomputed(sampled_report):
    report = deepcopy(sampled_report)
    report["summary"]["overall_risk_score"] = None
    report["agents"][0]["risk_score"] = None
    report["agents"][0]["risk_level"] = "unknown"
    assert presentation(report)["source"] == report
    del report["check_schema_version"]
    report["summary"]["overall_risk_score"] = 6.58
    displayed = presentation(report)
    assert len(displayed["groups"]) == 18
    assert all(len(group["occurrences"]) == 1 for group in displayed["groups"])
    assert displayed["source"] == report
