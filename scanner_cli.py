#!/usr/bin/env python3
"""AI Agent Scanner CLI."""

import asyncio
import json
import re
from copy import deepcopy
from pathlib import Path
from urllib.parse import urlsplit

import click

from src._version import __version__
from src.core.build_identity import current_identity
from src.discovery.discovery_engine import DiscoveryEngine, DiscoveryScope
from src.security.security_engine import SecurityTestEngine
from src.security.prompt_suites import (
    PROTECTED_DISCLOSURE_SUITE, PromptSuiteError,
    validate_prompt_suite, validate_prompt_suite_agents,
)
from src.risk.risk_assessor import RiskAssessment
from src.frameworks.owasp_llm_top10 import get_coverage_summary
from src.core.pipeline import run_pipeline, to_sarif
from src.core.tenant_evidence import TenantEvidenceError, validate_tenant_input
from src.core.contracts import validate_checkpoint_report
from src.core.model_selection import apply_model_overrides, validate_model_overrides
from src.core.transport import ScanBudget, scan_transport
from src.core.files import write_private_text
from src.utils.helpers import validate_cli_target_classes, validate_scan_scope

VERSION = __version__
BANNER = "AI Agent Scanner"
_CLI_INTERRUPTION_REASONS = (
    'Scan cancelled; retained partial report',
    'Scan execution failed; retained partial report',
    'Scan deadline exhausted; retained partial report',
)


@click.group()
@click.version_option(version=VERSION, prog_name="ai-agent-scanner")
def cli():
    """Discover and assess AI agents."""


@cli.command('build-info')
@click.option('--json', 'as_json', is_flag=True, help='Print structured public build identity')
def build_info(as_json):
    """Show the running CLI build and bundled catalog identity."""
    identity = current_identity(component='cli')
    click.echo(json.dumps(identity, indent=2, allow_nan=False) if as_json
               else f'AI Agent Scanner {identity["package_version"]}\n' + json.dumps(identity, indent=2))


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


def budget_options(function):
    for option in reversed([
        click.option('--max-requests', type=click.IntRange(1, 10000), default=500, show_default=True,
                     help='Shared DNS/TCP/HTTP attempt budget'),
        click.option('--max-response-bytes', type=click.IntRange(1, 16777216), default=1048576,
                     show_default=True, help='Maximum bytes per HTTP response'),
        click.option('--timeout-seconds', type=click.IntRange(1, 3600), default=300,
                     show_default=True, help='Overall scan deadline'),
        click.option('--request-timeout-seconds', type=click.FloatRange(1, 300), default=30,
                     show_default=True, help='Maximum duration of each HTTP request'),
        click.option('--allow-loopback', is_flag=True, help='Explicitly permit local loopback targets'),
    ]):
        function = option(function)
    return function


def load_targets(network, domain, repository=(), traffic=(), config=None, allow_loopback=False):
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
                       'evidence_context_id', 'tenant_evidence'}
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
            try:
                validate_tenant_input(agent)
            except TenantEvidenceError as exc:
                raise click.ClickException(str(exc)) from None
            seen.add(agent['id'])
            agent.setdefault('type', 'assistant')
            agent.setdefault('discovery_method', 'explicit')
            agent.setdefault('metadata', {})
    valid, error = validate_cli_target_classes(scope, agents, allow_loopback=allow_loopback)
    if not valid:
        raise click.ClickException(error)
    if agents is None:
        valid, error = validate_scan_scope(scope, allow_loopback=allow_loopback)
        if not valid:
            raise click.ClickException(error)
    return DiscoveryScope(**scope), agents


@cli.command()
@target_options
@budget_options
@click.option('--output', '-o', help='JSON output file')
@click.option('--checkpoint-dir', type=click.Path(file_okay=False),
              help='Create a new private directory for crash-recoverable public checkpoints')
@click.option('--verbose', '-v', is_flag=True, help='Show completion details')
def discover(network, domain, repository, traffic, config, output, verbose,
             max_requests, max_response_bytes, timeout_seconds, allow_loopback, request_timeout_seconds,
             checkpoint_dir):
    """Discover agents across network, repositories, cloud, and traffic sources."""
    scope, agents = load_targets(network, domain, repository, traffic, config, allow_loopback)
    if agents is not None:
        raise click.ClickException("Explicit agents are supported by scan only")
    asyncio.run(_execute(scope, None, output, 'json', 'discovery_only', verbose,
                         max_requests, max_response_bytes, timeout_seconds, allow_loopback,
                         request_timeout_seconds=request_timeout_seconds, checkpoint_dir=checkpoint_dir))


@cli.command()
@target_options
@budget_options
@click.option('--model-override', multiple=True, metavar='ASSET_ID=MODEL',
              help='Bind an exact discovered stable asset ID to a model (repeatable)')
@click.option('--output', '-o', default='scan_results.json', help='Output file')
@click.option('--checkpoint-dir', type=click.Path(file_okay=False),
              help='Create a new private directory for crash-recoverable public checkpoints')
@click.option('--format', '-f', 'fmt', type=click.Choice(['json', 'sarif']), default='json')
@click.option('--verbose', '-v', is_flag=True, help='Show completion details')
@click.option('--skip-security', is_flag=True, help='Discovery only')
@click.option('--prompt-suite', metavar=PROTECTED_DISCLOSURE_SUITE,
              help='Experimental protected-disclosure suite; requires explicit agents with canaries and public contexts')
def scan(network, domain, repository, traffic, config, output, fmt, verbose, skip_security,
         model_override, max_requests, max_response_bytes, timeout_seconds, allow_loopback,
         request_timeout_seconds, prompt_suite, checkpoint_dir):
    """Run shared discovery, security, risk, and report pipeline."""
    if prompt_suite is not None:
        try:
            validate_prompt_suite(prompt_suite)
        except PromptSuiteError as exc:
            raise click.UsageError(str(exc)) from None
        if skip_security:
            raise click.UsageError('--prompt-suite requires security testing')
    scope, agents = load_targets(network, domain, repository, traffic, config, allow_loopback)
    if prompt_suite is not None and agents is None:
        raise click.UsageError('--prompt-suite requires explicit agents with protected canaries and public evidence contexts')
    if agents is not None and skip_security:
        raise click.ClickException("Explicit agents cannot be combined with --skip-security")
    selections = {}
    for selection in model_override:
        asset_id, separator, model = selection.partition('=')
        if not separator or asset_id in selections:
            raise click.UsageError('Model overrides require unique ASSET_ID=MODEL entries')
        selections[asset_id] = model
    try:
        selections = validate_model_overrides(selections)
    except ValueError as exc:
        raise click.UsageError(str(exc)) from exc
    if selections and skip_security:
        raise click.UsageError('--model-override requires security testing')
    if prompt_suite is not None:
        try:
            validate_prompt_suite_agents(apply_model_overrides(agents, selections) if selections else agents)
        except PromptSuiteError as exc:
            raise click.UsageError(str(exc)) from None
    mode = 'security_only' if agents is not None else ('discovery_only' if skip_security else 'full')
    asyncio.run(_execute(scope, agents, output, fmt, mode, verbose,
                         max_requests, max_response_bytes, timeout_seconds, allow_loopback, selections,
                         request_timeout_seconds, prompt_suite=prompt_suite, checkpoint_dir=checkpoint_dir))


def _checkpoint_output_conflicts(checkpoint_dir, output):
    checkpoint = Path(checkpoint_dir).expanduser().resolve()
    destination = Path(output).resolve()
    if destination.is_relative_to(checkpoint):
        return True
    try:
        identity = checkpoint.stat()
    except FileNotFoundError:
        return False
    # Filesystem aliases can retain different path spellings after resolution.
    for ancestor in (destination, *destination.parents):
        try:
            candidate = ancestor.stat()
        except FileNotFoundError:
            continue
        if (candidate.st_dev, candidate.st_ino) == (identity.st_dev, identity.st_ino):
            return True
    return False


async def _execute(scope, agents, output, fmt, mode, verbose, max_requests=500,
                   max_response_bytes=1048576, timeout_seconds=300, allow_loopback=False,
                   selections=None, request_timeout_seconds=30, prompt_suite=None, checkpoint_dir=None):
    if not checkpoint_dir:
        return await _execute_with_store(scope, agents, output, fmt, mode, verbose, max_requests,
                                         max_response_bytes, timeout_seconds, allow_loopback, selections,
                                         request_timeout_seconds, prompt_suite, None)
    from src.core.cli_checkpoints import CheckpointStore, CLICheckpointError

    try:
        if output and _checkpoint_output_conflicts(checkpoint_dir, output):
            raise CLICheckpointError()
        with CheckpointStore.create(checkpoint_dir) as store:
            if output and _checkpoint_output_conflicts(store.path, output):
                raise CLICheckpointError()
            await _execute_with_store(scope, agents, output, fmt, mode, verbose, max_requests,
                                      max_response_bytes, timeout_seconds, allow_loopback, selections,
                                      request_timeout_seconds, prompt_suite, store)
    except (CLICheckpointError, OSError, ValueError, RuntimeError):
        raise click.ClickException('Unable to preserve CLI checkpoint; use a new private checkpoint directory') from None


async def _execute_with_store(scope, agents, output, fmt, mode, verbose, max_requests,
                              max_response_bytes, timeout_seconds, allow_loopback, selections,
                              request_timeout_seconds, prompt_suite, store):
    latest_checkpoint = None
    interruption = None
    cancelled = False

    async def retain_checkpoint(report):
        nonlocal latest_checkpoint
        candidate = deepcopy(validate_checkpoint_report(report))
        if store is not None:
            store.publish(candidate)
        latest_checkpoint = candidate

    try:
        with scan_transport(ScanBudget(max_requests=max_requests, max_response_bytes=max_response_bytes,
                                       allow_loopback=allow_loopback,
                                       request_timeout_seconds=request_timeout_seconds)):
            security = SecurityTestEngine(prompt_suite=prompt_suite) if prompt_suite is not None else SecurityTestEngine()
            result = await asyncio.wait_for(
                run_pipeline(DiscoveryEngine(), security, RiskAssessment(),
                             scope, mode, agents=agents,
                             agent_validator=(lambda values: apply_model_overrides(values, selections))
                             if selections else None,
                             checkpoint_callback=retain_checkpoint, producer_component='cli',
                             checkpoint_public_fields=(*store.public_fields, *_CLI_INTERRUPTION_REASONS)
                             if store is not None else ()),
                timeout=timeout_seconds)
    except asyncio.CancelledError:
        if latest_checkpoint is None:
            raise
        cancelled = True
        interruption = _CLI_INTERRUPTION_REASONS[0]
    except ValueError as exc:
        if latest_checkpoint is None:
            if str(exc).startswith(('model_overrides', 'Source assets', 'Source asset')):
                raise click.ClickException(str(exc)) from exc
            raise click.ClickException('Scan execution failed') from exc
        interruption = _CLI_INTERRUPTION_REASONS[1]
    except (TimeoutError, asyncio.TimeoutError) as exc:
        if latest_checkpoint is None:
            raise click.ClickException('Scan deadline exhausted; no report checkpoint was produced') from exc
        interruption = _CLI_INTERRUPTION_REASONS[2]
    except Exception as exc:
        if latest_checkpoint is None:
            raise click.ClickException("Scan execution failed") from exc
        interruption = _CLI_INTERRUPTION_REASONS[1]
    if interruption is not None:
        result = latest_checkpoint
        result['status'] = 'cancelled' if cancelled else 'failed'
        result['error'] = interruption
    if store is not None:
        try:
            store.finish(result)
        except Exception:
            if cancelled:
                click.echo('Unable to preserve final CLI checkpoint after cancellation', err=True)
                raise asyncio.CancelledError from None
            raise
    try:
        report = to_sarif(result) if fmt == 'sarif' else result
        serialized = json.dumps(report, indent=2, allow_nan=False)
        if output:
            write_private_text(output, serialized + '\n')
            click.echo(f"Report saved to {output}")
        else:
            click.echo(serialized)
    except (OSError, ValueError, TypeError) as exc:
        if cancelled:
            click.echo('Unable to write partial report after cancellation', err=True)
            raise asyncio.CancelledError from None
        raise click.ClickException("Unable to write report") from exc
    if verbose:
        click.echo(f"Scan status: {result['status']}", err=True)
    if cancelled:
        raise asyncio.CancelledError
    if interruption is not None:
        raise click.ClickException(interruption)
    if mode != 'discovery_only' and result.get('agents') and not result.get('summary', {}).get('checks_completed'):
        raise click.ClickException('No security checks completed; configure an explicit model or inspect skipped prerequisites')
    if result['status'] != 'completed':
        raise click.ClickException("Scan completed with failed phases; inspect report")


@cli.command('recover')
@click.option('--checkpoint-dir', required=True, type=click.Path(file_okay=False),
              help='Private checkpoint directory from an earlier CLI execution')
@click.option('--output', '-o', required=True, type=click.Path(dir_okay=False),
              help='New report destination outside the checkpoint directory')
@click.option('--format', '-f', 'fmt', type=click.Choice(['json', 'sarif']), default='json')
def recover_command(checkpoint_dir, output, fmt):
    """Export saved evidence offline without resuming or repeating a scan."""
    from src.core.cli_checkpoints import recover_checkpoint, CLICheckpointError

    try:
        if _checkpoint_output_conflicts(checkpoint_dir, output):
            raise CLICheckpointError()
        with recover_checkpoint(checkpoint_dir) as result:
            document = to_sarif(result) if fmt == 'sarif' else result
            write_private_text(output, json.dumps(document, indent=2, allow_nan=False) + '\n')
    except (CLICheckpointError, OSError, ValueError, TypeError, RecursionError, RuntimeError):
        raise click.ClickException('Unable to recover CLI checkpoint; verify the private directory and output') from None
    click.echo(f'Report saved to {output}')
    if result['status'] != 'completed':
        raise click.ClickException('Saved evidence exported; original scan did not complete')


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
            write_private_text(output, rendered + '\n')
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
    from src.mcp.diagnostics import public_failure_reason
    from src.mcp import to_sarif

    try:
        report = asyncio.run(inventory(endpoint, allow_network, allow_loopback, api_key_env))
        rendered = json.dumps(to_sarif(report) if fmt == 'sarif' else report, indent=2)
        if output:
            write_private_text(output, rendered + '\n')
        else:
            click.echo(rendered)
    except (OSError, ValueError) as exc:
        raise click.ClickException('Unable to collect or write MCP inventory; check target scope and credential configuration') from exc
    if report['status'] != 'completed':
        reason = public_failure_reason(report)
        detail = f': {reason}' if reason else ''
        raise click.ClickException(f'MCP inventory is incomplete{detail}; inspect report')


@cli.command('mcp-check')
@click.option('--endpoint', required=True, help='Exact already-running protected MCP endpoint')
@click.option('--allow-network', multiple=True, required=True, help='Explicit allowed network CIDR (repeatable)')
@click.option('--allow-loopback', is_flag=True, help='Permit explicitly allowlisted loopback targets')
@click.option('--api-key-env', required=True, help='Environment variable holding the authorized bearer token')
@click.option('--policy', required=True, type=click.Path(exists=True, dir_okay=False), help='Local trusted protected-inventory policy JSON')
@click.option('--format', '-f', 'fmt', type=click.Choice(['json', 'sarif']), default='json')
@click.option('--output', '-o', type=click.Path(dir_okay=False), help='Report destination; default stdout')
def mcp_check_command(endpoint, allow_network, allow_loopback, api_key_env, policy, fmt, output):
    """Check declared protected inventory controls without invoking tools."""
    from src.mcp.policy import check, load_policy
    from src.mcp.diagnostics import public_failure_reason
    from src.mcp import to_sarif

    try:
        if output:
            destination, source = Path(output), Path(policy)
            if (destination.resolve() == source.resolve()
                    or destination.exists() and destination.samefile(source)):
                raise ValueError('Output must differ from policy input')
        report = asyncio.run(check(endpoint, allow_network, load_policy(policy), allow_loopback, api_key_env))
        rendered = json.dumps(to_sarif(report) if fmt == 'sarif' else report, indent=2)
        if output:
            write_private_text(output, rendered + '\n')
        else:
            click.echo(rendered)
    except (OSError, ValueError) as exc:
        raise click.ClickException('Unable to check MCP policy; verify local policy, scope, credentials, and output') from exc
    if report['status'] != 'completed':
        reason = public_failure_reason(report)
        detail = f': {reason}' if reason else ''
        raise click.ClickException(f'MCP policy check is incomplete{detail}; inspect report')


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
            write_private_text(destination, rendered + '\n')
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
        write_private_text(destination, json.dumps(document, indent=2) + '\n')
    except (OSError, ValueError) as exc:
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
