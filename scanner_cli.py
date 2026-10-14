#!/usr/bin/env python3
"""AI Agent Scanner CLI."""

import asyncio
import json
import re
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
                       'protected_response_marker', 'protected_path_markers', 'model', 'api_key_env',
                       'evidence_context_id'}
            if set(agent) - allowed:
                raise click.ClickException("Unsupported agent configuration fields")
            for field in ('model', 'api_key_env'):
                if field in agent and (not isinstance(agent[field], str) or not agent[field].strip()):
                    raise click.ClickException(f"{field} must be a nonempty string")
            if 'api_key_env' in agent and not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*', agent['api_key_env']):
                raise click.ClickException("api_key_env must be an environment variable name")
            context = agent.get('evidence_context_id')
            if 'evidence_context_id' in agent and not (
                    isinstance(context, str) and context.strip() and len(context) <= 128
                    and '[' not in context and ']' not in context):
                raise click.ClickException("evidence_context_id must be nonempty public text of at most 128 characters without brackets")
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
        valid, error = validate_scan_scope(scope, allow_loopback=True)
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
    """Show declared OWASP mapping scope, not exhaustive or executed coverage."""
    click.echo(BANNER)
    click.echo(f"  v{VERSION} | Framework Mapping Scope")
    click.echo("=" * 60)

    click.echo("\n  OWASP LLM Top 10 (2025) Mapping Scope")
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
    click.echo(f"\n  Declared checks: {tested}/{total} categories have partial mappings")
    click.echo("  Static declarations do not show completed testing or exhaustive attack coverage.")
    click.echo("  Offline replay fixtures do not establish live target coverage.")
    click.echo(f"  Partial: {sum(1 for i in summary.values() if i['coverage'] == 'partial')}")
    click.echo(f"  Planned: {sum(1 for i in summary.values() if i['coverage'] == 'planned')}")



@cli.command('mcp')
@click.option('--config', type=click.Path(exists=True, dir_okay=False), help='Local MCP client configuration JSON')
@click.option('--tools', 'tools_path', type=click.Path(exists=True, dir_okay=False), help='Saved tools/list inventory JSON')
@click.option('--format', '-f', 'fmt', type=click.Choice(['json', 'sarif']), default='json')
@click.option('--output', '-o', type=click.Path(dir_okay=False), help='Report destination; default stdout')
def mcp_command(config, tools_path, fmt, output):
    """Passively assess MCP configuration and saved tool schemas without execution."""
    from src.mcp import assess, load_json, to_sarif

    if not config and not tools_path:
        raise click.UsageError('Provide --config or --tools')
    try:
        report = assess(load_json(config) if config else None,
                        load_json(tools_path) if tools_path else None)
        document = to_sarif(report) if fmt == 'sarif' else report
        rendered = json.dumps(document, indent=2)
        if output:
            # Refuse to overwrite either input, including symlink aliases.
            from pathlib import Path
            destination = Path(output)
            if any(destination.resolve() == Path(path).resolve() or
                   destination.exists() and destination.samefile(path)
                   for path in (config, tools_path) if path):
                raise ValueError('Output must differ from input files')
            with open(output, 'w', encoding='utf-8') as stream:
                stream.write(rendered + '\n')
        else:
            click.echo(rendered)
    except (OSError, ValueError) as exc:
        raise click.ClickException(str(exc)) from exc


@cli.command('mcp-live')
@click.option('--endpoint', required=True, help='Already-running MCP 2026-07-28 HTTP(S) endpoint')
@click.option('--allow-network', multiple=True, required=True, help='Explicit allowed network CIDR (repeatable)')
@click.option('--allow-loopback', is_flag=True, help='Permit explicitly allowlisted loopback targets')
@click.option('--api-key-env', help='Environment variable holding a bearer token; never exported')
@click.option('--format', '-f', 'fmt', type=click.Choice(['json', 'sarif']), default='json')
@click.option('--output', '-o', type=click.Path(dir_okay=False), help='Report destination; default stdout')
def mcp_live_command(endpoint, allow_network, allow_loopback, api_key_env, fmt, output):
    """Collect read-only live MCP inventory; never start servers or invoke tools."""
    from src.mcp.live import inventory
    from src.mcp import to_sarif

    try:
        report = asyncio.run(inventory(endpoint, allow_network, allow_loopback, api_key_env))
        rendered = json.dumps(to_sarif(report) if fmt == 'sarif' else report, indent=2)
        if output:
            Path(output).write_text(rendered + '\n', encoding='utf-8')
        else:
            click.echo(rendered)
    except (OSError, ValueError) as exc:
        raise click.ClickException('Unable to collect or write MCP inventory; check target scope and credential configuration') from exc
    if report['status'] != 'completed':
        raise click.ClickException('MCP inventory is incomplete; inspect report')


@cli.command('evaluate')
@click.option('--suite', type=click.Path(exists=True, dir_okay=False), help='Local labeled replay suite JSON; default synthetic smoke fixtures')
@click.option('--output', '-o', type=click.Path(dir_okay=False), help='Metrics JSON destination; default stdout')
def evaluate_command(suite, output):
    """Evaluate offline transcripts against explicit lab policies and labels."""
    from pathlib import Path
    from src.evaluation import evaluate_suite
    from src.evaluation.fixtures import synthetic_suite
    from src.mcp import load_json

    try:
        report = evaluate_suite(load_json(suite) if suite else synthetic_suite())
        report['fixture_source'] = 'user_supplied' if suite else 'builtin_synthetic'
        rendered = json.dumps(report, indent=2)
        if output:
            destination = Path(output)
            if suite and (destination.resolve() == Path(suite).resolve() or
                          destination.exists() and destination.samefile(suite)):
                raise ValueError('Output must differ from suite input')
            with destination.open('w', encoding='utf-8') as stream:
                stream.write(rendered + '\n')
        else:
            click.echo(rendered)
    except (OSError, ValueError) as exc:
        raise click.ClickException(str(exc)) from exc
def _read_report_file(path):
    try:
        return json.loads(Path(path).read_text())
    except (OSError, ValueError) as exc:
        raise click.ClickException("Unable to read report or policy JSON") from exc


def _write_derived_report(document, output, sources):
    destination = Path(output)
    for source in sources:
        path = Path(source)
        if destination.resolve() == path.resolve() or (destination.exists() and destination.samefile(path)):
            raise click.ClickException("Output must be a different file from the inputs")
    try:
        destination.write_text(json.dumps(document, indent=2) + '\n')
    except OSError as exc:
        raise click.ClickException("Unable to write derived report") from exc


@cli.command('diff')
@click.option('--before', required=True, type=click.Path(exists=True, dir_okay=False))
@click.option('--after', required=True, type=click.Path(exists=True, dir_okay=False))
@click.option('--output', '-o', required=True, type=click.Path(dir_okay=False))
def diff_reports(before, after, output):
    """Compare inventory and findings from two saved JSON scan reports."""
    from src.reporting.workflows import compare_reports
    try:
        report = compare_reports(_read_report_file(before), _read_report_file(after))
    except (ValueError, TypeError, AttributeError) as exc:
        raise click.ClickException(f"Invalid scan report: {exc}") from exc
    _write_derived_report(report, output, (before, after))


@cli.command('triage')
@click.option('--report', required=True, type=click.Path(exists=True, dir_okay=False))
@click.option('--policy', required=True, type=click.Path(exists=True, dir_okay=False))
@click.option('--output', '-o', required=True, type=click.Path(dir_okay=False))
def triage_report(report, policy, output):
    """Apply explicit expiring suppressions without changing source evidence."""
    from src.reporting.workflows import apply_policy
    try:
        derived = apply_policy(_read_report_file(report), _read_report_file(policy))
    except (ValueError, TypeError, AttributeError) as exc:
        raise click.ClickException(f"Invalid report or policy: {exc}") from exc
    _write_derived_report(derived, output, (report, policy))


if __name__ == '__main__':
    cli()
