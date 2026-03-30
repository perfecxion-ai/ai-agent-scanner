"""
Compliance Assessment Engine

Maps discovered AI agents and their vulnerabilities to regulatory
frameworks and standards: GDPR, SOC 2, HIPAA, PCI DSS, NIST AI RMF,
and the EU AI Act.
"""

import logging
from typing import List, Dict, Any
from datetime import datetime, timezone


# Compliance framework definitions with article/control mappings
FRAMEWORKS = {
    'gdpr': {
        'name': 'GDPR (General Data Protection Regulation)',
        'controls': {
            'art_5': {
                'ref': 'Article 5 — Principles',
                'description': 'Lawfulness, fairness, transparency, purpose limitation, data minimisation',
                'triggered_by': ['pii_disclosure', 'inappropriate_data_retention', 'privacy_transparency_issue'],
            },
            'art_25': {
                'ref': 'Article 25 — Data Protection by Design',
                'description': 'Technical and organizational measures for data protection',
                'triggered_by': ['pii_disclosure', 'tenant_isolation_violation', 'information_disclosure_in_errors'],
            },
            'art_32': {
                'ref': 'Article 32 — Security of Processing',
                'description': 'Appropriate security measures for personal data',
                'triggered_by': ['authentication_bypass', 'weak_credentials', 'no_rate_limiting',
                                 'insecure_session_management', 'weak_api_key'],
            },
            'art_35': {
                'ref': 'Article 35 — Data Protection Impact Assessment',
                'description': 'DPIA required for high-risk processing including AI profiling',
                'triggered_by': ['pii_disclosure', 'tenant_isolation_violation'],
            },
        },
    },
    'soc2': {
        'name': 'SOC 2 Type II',
        'controls': {
            'cc6_1': {
                'ref': 'CC6.1 — Logical and Physical Access',
                'description': 'Logical access security over information assets',
                'triggered_by': ['authentication_bypass', 'weak_credentials', 'authorization_bypass',
                                 'weak_api_key', 'insecure_session_management'],
            },
            'cc6_3': {
                'ref': 'CC6.3 — Role-Based Access',
                'description': 'Access based on authorization and business need',
                'triggered_by': ['authorization_bypass', 'tenant_isolation_violation'],
            },
            'cc7_2': {
                'ref': 'CC7.2 — System Monitoring',
                'description': 'Monitoring for anomalies and security events',
                'triggered_by': ['no_rate_limiting'],
            },
            'cc8_1': {
                'ref': 'CC8.1 — Change Management',
                'description': 'Changes to infrastructure and software are controlled',
                'triggered_by': ['prompt_injection'],
            },
        },
    },
    'hipaa': {
        'name': 'HIPAA Security Rule',
        'controls': {
            'access_control': {
                'ref': '§164.312(a) — Access Control',
                'description': 'Technical safeguards for ePHI access',
                'triggered_by': ['authentication_bypass', 'weak_credentials', 'authorization_bypass'],
            },
            'audit_controls': {
                'ref': '§164.312(b) — Audit Controls',
                'description': 'Record and examine activity in systems with ePHI',
                'triggered_by': ['no_rate_limiting', 'information_disclosure_in_errors'],
            },
            'integrity': {
                'ref': '§164.312(c) — Integrity',
                'description': 'Protect ePHI from improper alteration or destruction',
                'triggered_by': ['prompt_injection', 'tenant_isolation_violation'],
            },
            'transmission': {
                'ref': '§164.312(e) — Transmission Security',
                'description': 'Guard against unauthorized access during transmission',
                'triggered_by': ['insecure_session_management', 'weak_api_key'],
            },
        },
    },
    'pci_dss': {
        'name': 'PCI DSS v4.0',
        'controls': {
            'req_2': {
                'ref': 'Requirement 2 — Secure Configurations',
                'description': 'Apply secure configurations to all system components',
                'triggered_by': ['weak_credentials', 'weak_api_key'],
            },
            'req_6': {
                'ref': 'Requirement 6 — Secure Software',
                'description': 'Develop and maintain secure systems and software',
                'triggered_by': ['prompt_injection', 'information_disclosure_in_errors'],
            },
            'req_7': {
                'ref': 'Requirement 7 — Restrict Access',
                'description': 'Restrict access by business need to know',
                'triggered_by': ['authentication_bypass', 'authorization_bypass'],
            },
            'req_8': {
                'ref': 'Requirement 8 — Identify Users',
                'description': 'Identify and authenticate access to system components',
                'triggered_by': ['authentication_bypass', 'weak_credentials', 'insecure_session_management'],
            },
        },
    },
    'nist_ai_rmf': {
        'name': 'NIST AI Risk Management Framework',
        'controls': {
            'govern_1': {
                'ref': 'GOVERN 1 — AI Risk Management Policies',
                'description': 'Policies for AI risk management are established',
                'triggered_by': ['prompt_injection', 'pii_disclosure'],
            },
            'map_3': {
                'ref': 'MAP 3 — AI Risks and Benefits',
                'description': 'AI risks and benefits are mapped for each use case',
                'triggered_by': ['prompt_injection', 'pii_disclosure', 'tenant_isolation_violation'],
            },
            'measure_2': {
                'ref': 'MEASURE 2 — AI Systems are Evaluated',
                'description': 'Systems are evaluated for trustworthy AI characteristics',
                'triggered_by': ['prompt_injection', 'authentication_bypass', 'pii_disclosure'],
            },
            'manage_2': {
                'ref': 'MANAGE 2 — AI Risks are Prioritized',
                'description': 'Strategies to maximize benefits and minimize risks',
                'triggered_by': ['no_rate_limiting', 'weak_credentials'],
            },
        },
    },
    'eu_ai_act': {
        'name': 'EU AI Act',
        'controls': {
            'art_9': {
                'ref': 'Article 9 — Risk Management System',
                'description': 'Continuous risk management for high-risk AI systems',
                'triggered_by': ['prompt_injection', 'pii_disclosure', 'authentication_bypass',
                                 'tenant_isolation_violation'],
            },
            'art_10': {
                'ref': 'Article 10 — Data Governance',
                'description': 'Training, validation, and testing data shall meet quality criteria',
                'triggered_by': ['pii_disclosure', 'inappropriate_data_retention'],
            },
            'art_13': {
                'ref': 'Article 13 — Transparency',
                'description': 'High-risk AI systems designed for transparency and interpretability',
                'triggered_by': ['privacy_transparency_issue'],
            },
            'art_15': {
                'ref': 'Article 15 — Accuracy, Robustness, Cybersecurity',
                'description': 'Appropriate level of accuracy, robustness, and cybersecurity',
                'triggered_by': ['prompt_injection', 'authentication_bypass', 'weak_credentials',
                                 'no_rate_limiting', 'weak_api_key'],
            },
        },
    },
}


class ComplianceEngine:
    """Compliance assessment for AI agents."""

    def __init__(self):
        self.logger = logging.getLogger(__name__)

    async def assess_compliance(self, agents: List[Dict[str, Any]],
                                vulnerabilities: List[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Assess compliance status for discovered agents and their vulnerabilities.

        Args:
            agents: List of discovered agent dicts.
            vulnerabilities: List of vulnerability dicts from security testing.

        Returns:
            Compliance assessment report.
        """
        vulns = vulnerabilities or []

        # Collect all vulnerability types present
        vuln_types = set()
        for v in vulns:
            vuln_types.add(v.get('vulnerability_type', ''))
            vuln_types.add(v.get('category', ''))

        # Assess each framework
        framework_results = {}
        total_violations = 0
        frameworks_impacted = 0

        for fw_key, framework in FRAMEWORKS.items():
            controls_triggered = []

            for ctrl_key, control in framework['controls'].items():
                matching_vulns = [
                    t for t in control['triggered_by'] if t in vuln_types
                ]
                if matching_vulns:
                    # Find the actual vulnerabilities
                    related = [
                        v for v in vulns
                        if v.get('vulnerability_type') in matching_vulns
                        or v.get('category') in matching_vulns
                    ]
                    controls_triggered.append({
                        'control': ctrl_key,
                        'reference': control['ref'],
                        'description': control['description'],
                        'triggered_by_types': matching_vulns,
                        'related_vulnerability_count': len(related),
                        'max_severity': max(
                            (v.get('severity', 'low') for v in related),
                            key=lambda s: {'critical': 4, 'high': 3, 'medium': 2, 'low': 1, 'info': 0}.get(s, 0),
                            default='low'
                        ),
                    })

            status = 'non_compliant' if controls_triggered else 'compliant'
            if controls_triggered:
                frameworks_impacted += 1
                total_violations += len(controls_triggered)

            framework_results[fw_key] = {
                'name': framework['name'],
                'status': status,
                'controls_violated': len(controls_triggered),
                'total_controls_assessed': len(framework['controls']),
                'details': controls_triggered,
            }

        return {
            'assessment_timestamp': datetime.now(timezone.utc).isoformat(),
            'agents_assessed': len(agents),
            'vulnerabilities_assessed': len(vulns),
            'summary': {
                'frameworks_assessed': len(FRAMEWORKS),
                'frameworks_impacted': frameworks_impacted,
                'total_control_violations': total_violations,
                'compliance_score': round(
                    (1 - frameworks_impacted / len(FRAMEWORKS)) * 100, 1
                ) if FRAMEWORKS else 100.0,
            },
            'frameworks': framework_results,
        }
