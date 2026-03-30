"""
Report Generator

Generates structured security reports from scan results in multiple
formats: JSON (machine-readable), executive summary (text), and
HTML (human-readable dashboard).
"""

import json
import logging
from typing import Dict, Any, List
from datetime import datetime, timezone
from pathlib import Path


class ReportGenerator:
    """Generate security and compliance reports."""

    def __init__(self):
        self.logger = logging.getLogger(__name__)

    def generate_comprehensive_report(
        self,
        agents: List[Dict[str, Any]] = None,
        security_results: List[Dict[str, Any]] = None,
        risk_assessments: List[Dict[str, Any]] = None,
        compliance_report: Dict[str, Any] = None,
        scan_metadata: Dict[str, Any] = None,
    ) -> Dict[str, Any]:
        """
        Generate a comprehensive security report combining all scan phases.

        Returns a structured dict that can be serialized to JSON or rendered
        to other formats.
        """
        agents = agents or []
        security_results = security_results or []
        risk_assessments = risk_assessments or []

        # Collect all vulnerabilities
        all_vulns = []
        for result in security_results:
            all_vulns.extend(result.get('vulnerabilities', []))

        # Severity breakdown
        severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        for v in all_vulns:
            sev = v.get('severity', 'low')
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        # Type breakdown
        type_counts: Dict[str, int] = {}
        for v in all_vulns:
            vtype = v.get('vulnerability_type', 'unknown')
            type_counts[vtype] = type_counts.get(vtype, 0) + 1

        # Discovery method breakdown
        discovery_methods: Dict[str, int] = {}
        for a in agents:
            method = a.get('discovery_method', 'unknown')
            discovery_methods[method] = discovery_methods.get(method, 0) + 1

        # Provider breakdown
        providers: Dict[str, int] = {}
        for a in agents:
            provider = a.get('provider', 'unknown')
            providers[provider] = providers.get(provider, 0) + 1

        # Highest risk agent
        highest_risk = None
        if risk_assessments:
            highest_risk = max(risk_assessments, key=lambda r: r.get('overall_risk_score', 0))

        report = {
            'report_metadata': {
                'generated_at': datetime.now(timezone.utc).isoformat(),
                'scanner_version': '1.1.0',
                'report_format': 'comprehensive',
            },
            'scan_metadata': scan_metadata or {},
            'executive_summary': {
                'total_agents_discovered': len(agents),
                'total_vulnerabilities': len(all_vulns),
                'critical_findings': severity_counts['critical'],
                'high_findings': severity_counts['high'],
                'highest_risk_score': highest_risk.get('overall_risk_score', 0) if highest_risk else 0,
                'highest_risk_agent': highest_risk.get('agent_name', 'N/A') if highest_risk else 'N/A',
                'overall_risk_level': highest_risk.get('risk_level', 'minimal') if highest_risk else 'minimal',
                'requires_immediate_action': severity_counts['critical'] > 0,
            },
            'discovery_summary': {
                'agents': len(agents),
                'by_discovery_method': discovery_methods,
                'by_provider': providers,
                'agents_list': [
                    {
                        'name': a.get('name'),
                        'provider': a.get('provider'),
                        'endpoint': a.get('endpoint'),
                        'discovery_method': a.get('discovery_method'),
                        'confidence': a.get('confidence'),
                    }
                    for a in agents
                ],
            },
            'vulnerability_summary': {
                'total': len(all_vulns),
                'by_severity': severity_counts,
                'by_type': type_counts,
            },
            'risk_assessments': risk_assessments,
            'compliance': compliance_report,
            'vulnerabilities': all_vulns,
            'remediation_priorities': self._build_remediation_priorities(all_vulns, risk_assessments),
        }

        return report

    def _build_remediation_priorities(
        self,
        vulnerabilities: List[Dict],
        risk_assessments: List[Dict],
    ) -> List[Dict]:
        """Build a unified remediation priority list across all agents."""
        all_priorities = []
        for assessment in risk_assessments:
            for priority in assessment.get('remediation_priorities', []):
                priority['agent_name'] = assessment.get('agent_name')
                all_priorities.append(priority)

        # Sort by severity then priority number
        severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
        all_priorities.sort(
            key=lambda p: (severity_order.get(p.get('severity', 'low'), 4), p.get('priority', 99))
        )

        return all_priorities[:20]  # Top 20 across all agents

    def generate_executive_summary(self, report: Dict[str, Any]) -> str:
        """Generate a plain-text executive summary from a comprehensive report."""
        es = report.get('executive_summary', {})
        comp = report.get('compliance', {})

        lines = [
            "=" * 60,
            "  AI AGENT SECURITY ASSESSMENT — EXECUTIVE SUMMARY",
            "=" * 60,
            "",
            f"  Date:       {report.get('report_metadata', {}).get('generated_at', 'N/A')}",
            f"  Scanner:    AI Agent Scanner v{report.get('report_metadata', {}).get('scanner_version', '?')}",
            "",
            "  FINDINGS",
            "  " + "-" * 55,
            f"  Agents Discovered:       {es.get('total_agents_discovered', 0)}",
            f"  Total Vulnerabilities:   {es.get('total_vulnerabilities', 0)}",
            f"    Critical:              {es.get('critical_findings', 0)}",
            f"    High:                  {es.get('high_findings', 0)}",
            f"  Highest Risk Score:      {es.get('highest_risk_score', 0):.1f}/100",
            f"  Highest Risk Agent:      {es.get('highest_risk_agent', 'N/A')}",
            f"  Overall Risk Level:      {es.get('overall_risk_level', 'N/A').upper()}",
            "",
        ]

        if es.get('requires_immediate_action'):
            lines.append("  *** IMMEDIATE ACTION REQUIRED — CRITICAL FINDINGS ***")
            lines.append("")

        # Compliance summary
        if comp and comp.get('summary'):
            cs = comp['summary']
            lines.extend([
                "  COMPLIANCE",
                "  " + "-" * 55,
                f"  Frameworks Assessed:     {cs.get('frameworks_assessed', 0)}",
                f"  Frameworks Impacted:     {cs.get('frameworks_impacted', 0)}",
                f"  Control Violations:      {cs.get('total_control_violations', 0)}",
                f"  Compliance Score:        {cs.get('compliance_score', 0):.0f}%",
                "",
            ])

        # Top remediation priorities
        priorities = report.get('remediation_priorities', [])
        if priorities:
            lines.extend([
                "  TOP REMEDIATION PRIORITIES",
                "  " + "-" * 55,
            ])
            for i, p in enumerate(priorities[:5], 1):
                lines.append(
                    f"  {i}. [{p.get('severity', '?').upper()}] {p.get('title', 'Unknown')}"
                )
                if p.get('agent_name'):
                    lines.append(f"     Agent: {p['agent_name']}")
            lines.append("")

        lines.extend(["=" * 60, ""])
        return "\n".join(lines)

    def save_report(self, report: Dict[str, Any], output_path: str, fmt: str = 'json') -> str:
        """
        Save report to file.

        Args:
            report: Report dict from generate_comprehensive_report.
            output_path: File path to write.
            fmt: 'json' or 'txt'.

        Returns:
            The output path written.
        """
        path = Path(output_path)

        if fmt == 'txt':
            content = self.generate_executive_summary(report)
            path.write_text(content)
        else:
            with open(path, 'w') as f:
                json.dump(report, f, indent=2, default=str)

        self.logger.info(f"Report saved to {path}")
        return str(path)
