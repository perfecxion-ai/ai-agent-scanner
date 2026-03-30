#!/usr/bin/env python3
"""
AI Agent Scanner — Professional CLI

Discover, assess, and secure AI agents across your infrastructure.

Usage:
    python scanner_cli.py discover --network 192.168.1.0/24
    python scanner_cli.py scan --network 192.168.1.0/24 --output report.json
    python scanner_cli.py scan --domain api.company.com --format sarif
    python scanner_cli.py coverage
"""

import asyncio
import json
import sys
from pathlib import Path
from datetime import datetime, timezone

import click

from src.discovery.discovery_engine import DiscoveryEngine, DiscoveryScope
from src.security.security_engine import SecurityTestEngine
from src.risk.risk_assessor import RiskAssessment
from src.frameworks.owasp_llm_top10 import get_coverage_summary, generate_owasp_coverage_report
from src.frameworks.mitre_atlas import generate_atlas_coverage_report
from src.reporting.sarif_output import write_sarif, generate_sarif


VERSION = "1.1.0"

BANNER = r"""
    _    ___      _                    _     ____
   / \  |_ _|   / \   __ _  ___ _ __ | |_  / ___|  ___ __ _ _ __  _ __   ___ _ __
  / _ \  | |   / _ \ / _` |/ _ \ '_ \| __| \___ \ / __/ _` | '_ \| '_ \ / _ \ '__|
 / ___ \ | |  / ___ \ (_| |  __/ | | | |_   ___) | (_| (_| | | | | | | |  __/ |
/_/   \_\___| /_/   \_\__, |\___|_| |_|\__| |____/ \___\__,_|_| |_|_| |_|\___|_|
                       |___/
"""


@click.group()
@click.version_option(version=VERSION, prog_name="ai-agent-scanner")
def cli():
    """AI Agent Scanner — Discover, assess, and secure AI agents."""
    pass


@cli.command()
@click.option('--network', '-n', help='Network range (CIDR, e.g. 192.168.1.0/24)')
@click.option('--domain', '-d', help='Domain to scan')
@click.option('--output', '-o', help='Output file path')
@click.option('--verbose', '-v', is_flag=True, help='Verbose output')
def discover(network, domain, output, verbose):
    """Discover AI agents in your infrastructure (discovery only, no security testing)."""
    if not network and not domain:
        click.echo("Error: specify --network or --domain", err=True)
        sys.exit(1)

    click.echo(BANNER)
    click.echo(f"  v{VERSION} | Defensive AI Security Assessment")
    click.echo("=" * 60)

    asyncio.run(_run_discovery(network, domain, output, verbose))


@cli.command()
@click.option('--network', '-n', help='Network range (CIDR)')
@click.option('--domain', '-d', help='Domain to scan')
@click.option('--output', '-o', default='scan_results.json', help='Output file (default: scan_results.json)')
@click.option('--format', '-f', 'fmt', type=click.Choice(['json', 'sarif']), default='json', help='Output format')
@click.option('--verbose', '-v', is_flag=True, help='Verbose output')
@click.option('--skip-security', is_flag=True, help='Skip security testing (discovery only)')
def scan(network, domain, output, fmt, verbose, skip_security):
    """Full scan: discover agents, test security, assess risk, and generate report."""
    if not network and not domain:
        click.echo("Error: specify --network or --domain", err=True)
        sys.exit(1)

    click.echo(BANNER)
    click.echo(f"  v{VERSION} | Full Security Assessment")
    click.echo("=" * 60)

    asyncio.run(_run_full_scan(network, domain, output, fmt, verbose, skip_security))


@cli.command()
def coverage():
    """Show OWASP LLM Top 10 and MITRE ATLAS test coverage."""
    click.echo(BANNER)
    click.echo(f"  v{VERSION} | Framework Coverage Report")
    click.echo("=" * 60)

    click.echo("\n  OWASP LLM Top 10 (2025) Coverage")
    click.echo("  " + "-" * 55)

    summary = get_coverage_summary()
    for cat_id, info in summary.items():
        status_icon = {
            'full': click.style('[FULL]    ', fg='green'),
            'partial': click.style('[PARTIAL] ', fg='yellow'),
            'planned': click.style('[PLANNED] ', fg='red'),
            'none': click.style('[NONE]    ', fg='red'),
        }.get(info['coverage'], '[?]')

        risk_color = {'critical': 'red', 'high': 'yellow', 'medium': 'cyan'}.get(info['risk_level'], 'white')

        click.echo(
            f"  {status_icon} {cat_id}: {info['name']}"
            f" ({click.style(info['risk_level'].upper(), fg=risk_color)})"
        )

    tested = sum(1 for i in summary.values() if i['coverage'] in ('full', 'partial'))
    total = len(summary)
    click.echo(f"\n  Coverage: {tested}/{total} categories tested")
    click.echo(f"  Full: {sum(1 for i in summary.values() if i['coverage'] == 'full')}")
    click.echo(f"  Partial: {sum(1 for i in summary.values() if i['coverage'] == 'partial')}")
    click.echo(f"  Planned: {sum(1 for i in summary.values() if i['coverage'] == 'planned')}")


async def _run_discovery(network, domain, output, verbose):
    """Run discovery-only scan."""
    engine = DiscoveryEngine()
    scope = DiscoveryScope(
        include_network=True,
        network_ranges=[network] if network else None,
        domains=[domain] if domain else None,
    )

    if network:
        click.echo(f"\n  Target network: {network}")
    if domain:
        click.echo(f"  Target domain:  {domain}")

    click.echo("\n  Phase 1: Discovering AI agents...")

    agents = await engine.discover_agents(scope)
    click.echo(f"  Found {len(agents)} AI agent(s)\n")

    for i, agent in enumerate(agents, 1):
        click.echo(f"  {i}. {agent.name}")
        click.echo(f"     Provider:   {agent.provider or 'Unknown'}")
        click.echo(f"     Endpoint:   {agent.endpoint or 'N/A'}")
        click.echo(f"     Type:       {agent.type}")
        click.echo(f"     Confidence: {agent.confidence:.0%}")
        if verbose:
            click.echo(f"     Metadata:   {json.dumps(agent.metadata, indent=2)}")
        click.echo()

    if output:
        results = [
            {
                'id': a.id, 'name': a.name, 'type': a.type,
                'provider': a.provider, 'endpoint': a.endpoint,
                'discovery_method': a.discovery_method,
                'confidence': a.confidence, 'metadata': a.metadata,
            }
            for a in agents
        ]
        with open(output, 'w') as f:
            json.dump(results, f, indent=2)
        click.echo(f"  Results saved to {output}")


async def _run_full_scan(network, domain, output, fmt, verbose, skip_security):
    """Run full discovery + security + risk assessment scan."""
    discovery = DiscoveryEngine()
    security = SecurityTestEngine()
    risk_assessor = RiskAssessment()

    scope = DiscoveryScope(
        include_network=True,
        network_ranges=[network] if network else None,
        domains=[domain] if domain else None,
    )

    scan_start = datetime.now(timezone.utc)

    # Phase 1: Discovery
    if network:
        click.echo(f"\n  Target network: {network}")
    if domain:
        click.echo(f"  Target domain:  {domain}")

    click.echo("\n  Phase 1: Discovering AI agents...")
    agents = await discovery.discover_agents(scope)
    click.echo(f"  Found {len(agents)} AI agent(s)")

    if not agents:
        click.echo("\n  No agents found. Scan complete.")
        return

    # Convert to dicts for security engine
    agent_dicts = [
        {
            'id': a.id, 'name': a.name, 'type': a.type,
            'provider': a.provider, 'endpoint': a.endpoint,
            'metadata': a.metadata,
        }
        for a in agents
    ]

    all_vulnerabilities = []

    if not skip_security:
        # Phase 2: Security Testing
        click.echo("\n  Phase 2: Security testing...")
        security_results = await security.test_agents(agent_dicts)

        for result in security_results:
            vulns = result.get('vulnerabilities', [])
            all_vulnerabilities.extend(vulns)
            status = result.get('status', 'unknown')
            click.echo(
                f"    {result.get('agent_name', '?')}: "
                f"{len(vulns)} vulnerabilities ({status})"
            )

        # Phase 3: Risk Assessment
        click.echo("\n  Phase 3: Risk assessment...")
        risk_assessments = await risk_assessor.assess_risks(security_results)

        for assessment in risk_assessments:
            level = assessment.get('risk_level', 'unknown')
            score = assessment.get('overall_risk_score', 0)
            level_color = {
                'critical': 'red', 'high': 'yellow',
                'medium': 'cyan', 'low': 'green', 'minimal': 'green',
            }.get(level, 'white')

            click.echo(
                f"    {assessment.get('agent_name', '?')}: "
                f"Score {score:.1f}/100 "
                f"({click.style(level.upper(), fg=level_color)})"
            )
    else:
        security_results = []
        risk_assessments = []

    # Generate output
    scan_metadata = {
        'started_at': scan_start.isoformat(),
        'completed_at': datetime.now(timezone.utc).isoformat(),
        'targets': {'network': network, 'domain': domain},
        'version': VERSION,
    }

    if fmt == 'sarif':
        write_sarif(all_vulnerabilities, output, scan_metadata)
        click.echo(f"\n  SARIF report saved to {output}")
    else:
        report = {
            'scan_metadata': scan_metadata,
            'agents_discovered': len(agents),
            'total_vulnerabilities': len(all_vulnerabilities),
            'agents': agent_dicts,
            'security_results': security_results,
            'risk_assessments': risk_assessments,
            'frameworks': {
                'owasp_llm_top10': generate_owasp_coverage_report(all_vulnerabilities),
                'mitre_atlas': generate_atlas_coverage_report(all_vulnerabilities),
            },
        }
        with open(output, 'w') as f:
            json.dump(report, f, indent=2, default=str)
        click.echo(f"\n  JSON report saved to {output}")

    # Summary
    click.echo("\n" + "=" * 60)
    click.echo("  SCAN SUMMARY")
    click.echo("=" * 60)
    click.echo(f"  Agents discovered:     {len(agents)}")
    click.echo(f"  Vulnerabilities found: {len(all_vulnerabilities)}")

    if risk_assessments:
        max_risk = max(a.get('overall_risk_score', 0) for a in risk_assessments)
        click.echo(f"  Highest risk score:    {max_risk:.1f}/100")

    click.echo(f"  Output:                {output}")
    click.echo()


if __name__ == '__main__':
    cli()
