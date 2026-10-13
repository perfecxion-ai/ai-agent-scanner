"""Reports must not equate untested controls with compliance."""

from copy import deepcopy

import pytest

from src.compliance.compliance_engine import ComplianceEngine
from src.reporting.report_generator import ReportGenerator


@pytest.mark.asyncio
async def test_empty_findings_do_not_certify_compliance():
    report = await ComplianceEngine().assess_compliance([])
    assert all(framework['status'] == 'not_assessed' for framework in report['frameworks'].values())
    assert 'compliance_score' not in report['summary']
    assert report['limitations']


@pytest.mark.asyncio
async def test_findings_request_control_review_not_legal_conclusion():
    report = await ComplianceEngine().assess_compliance([], [
        {'vulnerability_type': 'authentication_bypass', 'severity': 'high'},
    ])
    assert report['summary']['controls_with_findings'] > 0
    assert report['frameworks']['soc2']['status'] == 'requires_review'
    assert 'controls_violated' not in report['frameworks']['soc2']


def test_unassessed_risk_stays_unknown_in_summary():
    generator = ReportGenerator()
    report = generator.generate_comprehensive_report(agents=[{'name': 'Unknown target'}])
    assert report['executive_summary']['highest_risk_score'] is None
    assert report['executive_summary']['overall_risk_level'] == 'unknown'
    summary = generator.generate_executive_summary(report)
    assert 'Not assessed' in summary


def test_reporting_does_not_mutate_risk_assessments():
    risks = [{'agent_name': 'Fixture', 'overall_risk_score': 10,
              'remediation_priorities': [{'title': 'Fix authentication', 'severity': 'high'}]}]
    original = deepcopy(risks)
    ReportGenerator().generate_comprehensive_report(risk_assessments=risks)
    assert risks == original
