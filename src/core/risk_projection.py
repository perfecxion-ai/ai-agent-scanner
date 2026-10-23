"""Conservative public risk projections of persisted, versioned pipeline evidence."""

from collections import Counter
from math import isfinite

from src.core.contracts import (
    CHECK_SCHEMA_VERSION, CHECK_EVIDENCE_SCHEMA_VERSION, confirmed_findings,
    risk_assessment_eligible, validate_scan_result,
)
from src.risk.risk_assessor import SEVERITY_SCORES, risk_level_for_score


def _score(value):
    return type(value) in {int, float} and 0 <= value <= 100 and isfinite(value)


_UNSPECIFIED = object()


def project_agent_risk(agent=None, *, assessed=False, evidence_schema_version=_UNSPECIFIED):
    """Unknown is distinct from an assessed zero; database defaults are not evidence."""
    agent = agent if isinstance(agent, dict) else {}
    security_status = agent.get('security_status')
    if not isinstance(security_status, str) or security_status not in {
            'completed', 'partial', 'failed', 'skipped', 'not_tested'}:
        security_status = 'unknown'
    result = {'risk_score': None, 'risk_level': 'unknown',
              'risk_coverage_status': 'not_assessed', 'risk_scoring_policy': None,
              'risk_assessment_status': 'not_assessed',
              'security_status': security_status}
    findings = agent.get('vulnerabilities', [])
    has_evidence = any(key in agent for key in (
        'check_evidence_schema_version', 'check_evidence_run_id', 'check_evidence')) or (
            isinstance(findings, list) and any(isinstance(finding, dict) and 'check_evidence_id' in finding
                                              for finding in findings))
    if evidence_schema_version == CHECK_EVIDENCE_SCHEMA_VERSION and (
            agent.get('check_evidence_schema_version') != evidence_schema_version):
        return result
    if has_evidence and evidence_schema_version is not _UNSPECIFIED and (
            evidence_schema_version != CHECK_EVIDENCE_SCHEMA_VERSION
            or agent.get('check_evidence_schema_version') != evidence_schema_version):
        return result
    if not assessed or agent.get('risk_scoring_policy') != 'severity-floor-v2':
        return result
    if not _score(agent.get('risk_score')) or agent.get('risk_level') != risk_level_for_score(agent['risk_score']):
        return result
    coverage = agent.get('risk_coverage_status')
    if not isinstance(coverage, str) or coverage not in {'sampled', 'partial'}:
        return result
    if security_status not in {'completed', 'partial', 'failed'}:
        return result
    if coverage != ('sampled' if security_status == 'completed' else 'partial'):
        return result
    evidence = {**agent, 'status': security_status, 'check_schema_version': CHECK_SCHEMA_VERSION}
    if not risk_assessment_eligible(evidence):
        return result
    floor = max((SEVERITY_SCORES.get(finding.get('severity'), 1)
                 if isinstance(finding.get('severity'), str) else 1
                 for finding in confirmed_findings(evidence)), default=0)
    if agent['risk_score'] < floor:
        return result
    result.update(risk_score=agent['risk_score'], risk_level=agent['risk_level'],
                  risk_coverage_status=agent['risk_coverage_status'],
                  risk_assessment_status='partial' if agent['risk_coverage_status'] == 'partial' else 'completed',
                  risk_scoring_policy=agent['risk_scoring_policy'])
    return result


def project_report_risk(report):
    """Leave historical exports untouched, but never promote their scores to current risk."""
    summary = {'overall_risk_score': None, 'risk_assessment_status': 'not_assessed'}
    if not isinstance(report, dict) or report.get('check_schema_version') != CHECK_SCHEMA_VERSION:
        return summary, {}
    try:
        # Receipt provenance is checked per asset below. One unsupported public
        # ledger must not erase an independent asset's valid assessment.
        validate_scan_result(report, validate_evidence=False)
    except (TypeError, ValueError):
        return summary, {}
    status = report.get('risk_assessment_status')
    status = status if isinstance(status, str) else None
    assessed = status in {'completed', 'partial'}
    if status in {'not_run', 'not_assessed', 'failed'}:
        summary['risk_assessment_status'] = status
    counts = Counter(agent['id'] for agent in report['agents'])
    agents = {agent['id']: project_agent_risk(
        agent, assessed=assessed, evidence_schema_version=report.get('check_evidence_schema_version'))
              for agent in report['agents'] if counts[agent['id']] == 1}
    scores = [agent['risk_score'] for agent in agents.values() if agent['risk_score'] is not None]
    declared = report.get('summary')
    declared_score = declared.get('overall_risk_score') if isinstance(declared, dict) else None
    if scores and _score(declared_score) and declared_score == max(scores):
        summary.update(overall_risk_score=declared_score, risk_assessment_status=status)
    return summary, agents
