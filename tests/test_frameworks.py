"""Tests for OWASP LLM Top 10 and MITRE ATLAS framework mappings."""

import pytest
from datetime import datetime, timezone

from src.frameworks.owasp_llm_top10 import (
    OWASP_LLM_TOP_10,
    map_vulnerability_to_owasp,
    generate_owasp_coverage_report,
    get_coverage_summary,
)
from src.frameworks.mitre_atlas import (
    ATLAS_TECHNIQUES,
    map_vulnerability_to_atlas,
    generate_atlas_coverage_report,
)


class TestOWASPMapping:
    """Test OWASP LLM Top 10 mapping."""

    def test_all_10_categories_defined(self):
        assert len(OWASP_LLM_TOP_10) == 10
        for i in range(1, 11):
            assert f"LLM{i:02d}" in OWASP_LLM_TOP_10

    def test_categories_have_required_fields(self):
        for cat_id, cat in OWASP_LLM_TOP_10.items():
            assert cat.id == cat_id
            assert len(cat.name) > 0
            assert cat.risk_level in ('critical', 'high', 'medium', 'low')
            assert cat.test_coverage in ('full', 'partial', 'planned', 'none')
            assert len(cat.vulnerability_types) > 0
            assert len(cat.mitigations) > 0

    def test_prompt_injection_maps_to_llm01(self):
        vuln = {'vulnerability_type': 'prompt_injection'}
        mapped = map_vulnerability_to_owasp(vuln)
        assert 'LLM01' in mapped

    def test_pii_disclosure_maps_to_llm02(self):
        vuln = {'vulnerability_type': 'pii_disclosure'}
        mapped = map_vulnerability_to_owasp(vuln)
        assert 'LLM02' in mapped

    def test_system_prompt_maps_to_llm01_and_llm07(self):
        vuln = {'vulnerability_type': 'system_prompt_extraction'}
        mapped = map_vulnerability_to_owasp(vuln)
        assert 'LLM01' in mapped
        assert 'LLM07' in mapped

    def test_no_rate_limiting_maps_to_llm10(self):
        vuln = {'vulnerability_type': 'no_rate_limiting'}
        mapped = map_vulnerability_to_owasp(vuln)
        assert 'LLM10' in mapped

    def test_unknown_vuln_maps_to_nothing(self):
        vuln = {'vulnerability_type': 'completely_unknown_type'}
        mapped = map_vulnerability_to_owasp(vuln)
        assert mapped == []

    def test_coverage_report_structure(self):
        vulns = [
            {'vulnerability_type': 'prompt_injection', 'category': 'instruction_bypass'},
            {'vulnerability_type': 'pii_disclosure'},
        ]
        report = generate_owasp_coverage_report(vulns)

        assert report['framework'] == 'OWASP LLM Top 10 (2025)'
        assert len(report['categories']) == 10
        assert report['summary']['total_categories'] == 10
        assert report['summary']['categories_with_findings'] >= 1

    def test_coverage_report_empty_vulns(self):
        report = generate_owasp_coverage_report([])
        assert report['summary']['categories_with_findings'] == 0

    def test_get_coverage_summary(self):
        summary = get_coverage_summary()
        assert len(summary) == 10
        for cat_id, info in summary.items():
            assert 'name' in info
            assert 'coverage' in info
            assert 'risk_level' in info


class TestMITREATLASMapping:
    """Test MITRE ATLAS mapping."""

    def test_techniques_defined(self):
        assert len(ATLAS_TECHNIQUES) >= 5

    def test_techniques_have_required_fields(self):
        for tech_id, tech in ATLAS_TECHNIQUES.items():
            assert tech.id == tech_id
            assert len(tech.name) > 0
            assert len(tech.tactic) > 0
            assert tech.test_coverage in ('full', 'partial', 'planned', 'none')
            assert len(tech.vulnerability_types) > 0

    def test_prompt_injection_maps_to_atlas(self):
        vuln = {'vulnerability_type': 'prompt_injection'}
        mapped = map_vulnerability_to_atlas(vuln)
        assert len(mapped) > 0
        assert 'AML.T0051' in mapped

    def test_weak_credentials_maps_to_atlas(self):
        vuln = {'vulnerability_type': 'weak_credentials'}
        mapped = map_vulnerability_to_atlas(vuln)
        assert 'AML.T0040' in mapped

    def test_atlas_coverage_report(self):
        vulns = [{'vulnerability_type': 'prompt_injection'}]
        report = generate_atlas_coverage_report(vulns)

        assert report['framework'] == 'MITRE ATLAS'
        assert report['summary']['techniques_with_findings'] >= 1


class TestSARIFOutput:
    """Test SARIF output generation."""

    def test_sarif_structure(self):
        from src.reporting.sarif_output import generate_sarif

        vulns = [
            {
                'id': 'v1',
                'vulnerability_type': 'prompt_injection',
                'category': 'instruction_bypass',
                'severity': 'high',
                'description': 'Test vulnerability',
                'confidence': 0.9,
                'agent_id': 'agent-1',
                'remediation': 'Fix it',
            }
        ]

        sarif = generate_sarif(vulns)

        assert sarif['version'] == '2.1.0'
        assert len(sarif['runs']) == 1
        assert len(sarif['runs'][0]['results']) == 1
        assert sarif['runs'][0]['results'][0]['level'] == 'error'  # high -> error

    def test_sarif_severity_mapping(self):
        from src.reporting.sarif_output import _severity_to_sarif_level

        assert _severity_to_sarif_level('critical') == 'error'
        assert _severity_to_sarif_level('high') == 'error'
        assert _severity_to_sarif_level('medium') == 'warning'
        assert _severity_to_sarif_level('low') == 'note'
        assert _severity_to_sarif_level('info') == 'note'

    def test_sarif_empty_vulns(self):
        from src.reporting.sarif_output import generate_sarif

        sarif = generate_sarif([])
        assert len(sarif['runs'][0]['results']) == 0
