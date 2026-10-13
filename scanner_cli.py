#!/usr/bin/env python3
"""AI Agent Scanner CLI."""

import asyncio
import json
from pathlib import Path
from urllib.parse import urlsplit

import click

from src.discovery.discovery_engine import DiscoveryEngine, DiscoveryScope
from src.security.security_engine import SecurityTestEngine
from src.risk.risk_assessor import RiskAssessment
from src.frameworks.owasp_llm_top10 import get_coverage_summary
from src.core.pipeline import run_pipeline, to_sarif
from src.utils.helpers import validate_scan_scope

VERSION = "1.1.0"
BANNER = "AI Agent Scanner"


@click.group()
@click.version_option(version=VERSION, prog_name="ai-agent-scanner")
def cli():
    """Discover and assess AI agents."""


def target_options(function):
    options = [
        click.option('--network', '-n', multiple=True, help='Network CIDR (repeatable)'),
        click.option('--domain', '-d', multiple=True, help='Domain (repeatable)'),
        click.option('--repository', multiple=True, type=click.Path(exists=True), help='Local repository'),
        click.option('--traffic', multiple=True, type=click.Path(exists=True), help='Traffic capture or log'),
        click.option('--config', type=click.Path(exists=True, dir_okay=False), help='Local JSON scan configuration'),
    ]
    for option in reversed(options):
        function = option(function)
    return function


def load_targets(network, domain, repository=(), traffic=(), config=None):
    data = {}
    if config:
        try:
            data = json.loads(Path(config).read_text())
        except (OSError, ValueError) as exc:
            raise click.ClickException("Unable to read JSON scan configuration") from exc
        if not isinstance(data, dict) or set(data) - {'target_scope', 'agents'}:
            raise click.ClickException("Configuration supports target_scope and agents only")
    raw = data.get('target_scope', {})
    if not isinstance(raw, dict) or set(raw) - set(DiscoveryScope.__dataclass_fields__):
        raise click.ClickException("Invalid target_scope fields")
    scope = dict(raw)
    for key, values in [('network_ranges', network), ('domains', domain),
                        ('repositories', repository), ('traffic_sources', traffic)]:
        if values:
            scope[key] = list(values)
    for key in ('network_ranges', 'domains', 'repositories', 'traffic_sources'):
        if key in scope and (not isinstance(scope[key], list) or
                             not all(isinstance(value, str) and value for value in scope[key])):
            raise click.ClickException(f"{key} must be an array of strings")
    for flag in ('include_network', 'include_repositories', 'include_cloud', 'include_traffic'):
        if flag in scope and not isinstance(scope[flag], bool):
            raise click.ClickException(f"{flag} must be boolean")
    scope.setdefault('include_network', bool(scope.get('network_ranges') or scope.get('domains')))
    scope.setdefault('include_repositories', bool(scope.get('repositories')))
    scope.setdefault('include_traffic', bool(scope.get('traffic_sources')))
    scope.setdefault('include_cloud', bool(scope.get('cloud_accounts')))
    if scope.get('cloud_accounts') is not None and not isinstance(scope['cloud_accounts'], dict):
        raise click.ClickException("cloud_accounts must be an object")
    agents = data.get('agents')
    if agents is not None:
        if not isinstance(agents, list) or not agents:
            raise click.ClickException("agents must be a nonempty array")
        seen = set()
        for agent in agents:
            if not isinstance(agent, dict) or not all(isinstance(agent.get(key), str) and agent[key]
                                                      for key in ('id', 'name', 'endpoint', 'provider')):
                raise click.ClickException("Each agent requires id, name, endpoint, and provider")
            allowed = {'id', 'name', 'endpoint', 'provider', 'type', 'discovery_method', 'metadata',
                       'system_prompt_canary', 'cross_tenant_canary', 'authentication_required',
                       'protected_response_marker', 'protected_path_markers'}
            if set(agent) - allowed:
                raise click.ClickException("Unsupported agent configuration fields")
            endpoint = urlsplit(agent['endpoint'])
            if endpoint.scheme not in {'http', 'https'} or not endpoint.hostname or endpoint.username or endpoint.password:
                raise click.ClickException("Agent endpoint must be HTTP(S) without embedded credentials")
            for field in ('system_prompt_canary', 'cross_tenant_canary', 'protected_response_marker'):
                if field in agent and (not isinstance(agent[field], str) or len(agent[field]) < 16):
                    raise click.ClickException(f"{field} must be a string of at least 16 characters")
            if 'authentication_required' in agent and not isinstance(agent['authentication_required'], bool):
                raise click.ClickException("authentication_required must be boolean")
            if not isinstance(agent.get('metadata', {}), dict):
                raise click.ClickException("metadata must be an object")
            markers = agent.get('protected_path_markers', {})
            if not isinstance(markers, dict) or not all(isinstance(path, str) and path.startswith('/') and
                    isinstance(marker, str) and len(marker) >= 16 for path, marker in markers.items()):
                raise click.ClickException("protected_path_markers requires paths mapped to markers of at least 16 characters")
            if agent['id'] in seen:
                raise click.ClickException("Agent IDs must be unique")
            seen.add(agent['id'])
            agent.setdefault('type', 'assistant')
            agent.setdefault('discovery_method', 'explicit')
            agent.setdefault('metadata', {})
    else:
        valid, error = validate_scan_scope(scope)
        if not valid:
            raise click.ClickException(error)
    return DiscoveryScope(**scope), agents


@cli.command()
@target_options
@click.option('--output', '-o', help='JSON output file')
@click.option('--verbose', '-v', is_flag=True, help='Show completion details')
def discover(network, domain, repository, traffic, config, output, verbose):
    """Discover agents across network, repositories, cloud, and traffic sources."""
    scope, agents = load_targets(network, domain, repository, traffic, config)
    if agents is not None:
        raise click.ClickException("Explicit agents are supported by scan only")
    asyncio.run(_execute(scope, None, output, 'json', 'discovery_only', verbose))


@cli.command()
@target_options
@click.option('--output', '-o', default='scan_results.json', help='Output file')
@click.option('--format', '-f', 'fmt', type=click.Choice(['json', 'sarif']), default='json')
@click.option('--verbose', '-v', is_flag=True, help='Show completion details')
@click.option('--skip-security', is_flag=True, help='Discovery only')
def scan(network, domain, repository, traffic, config, output, fmt, verbose, skip_security):
    """Run shared discovery, security, risk, and report pipeline."""
    scope, agents = load_targets(network, domain, repository, traffic, config)
    if agents is not None and skip_security:
        raise click.ClickException("Explicit agents cannot be combined with --skip-security")
    mode = 'security_only' if agents is not None else ('discovery_only' if skip_security else 'full')
    asyncio.run(_execute(scope, agents, output, fmt, mode, verbose))


async def _execute(scope, agents, output, fmt, mode, verbose):
    try:
        result = await run_pipeline(DiscoveryEngine(), SecurityTestEngine(), RiskAssessment(),
                                    scope, mode, agents=agents)
    except Exception as exc:
        raise click.ClickException("Scan execution failed") from exc
    report = to_sarif(result) if fmt == 'sarif' else result
    serialized = json.dumps(report, indent=2)
    if output:
        try:
            Path(output).write_text(serialized + '\n')
        except OSError as exc:
            raise click.ClickException("Unable to write report") from exc
        click.echo(f"Report saved to {output}")
    else:
        click.echo(serialized)
    if verbose:
        click.echo(f"Scan status: {result['status']}", err=True)
    if result['status'] != 'completed':
        raise click.ClickException("Scan completed with failed phases; inspect report")


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



if __name__ == '__main__':
    cli()
