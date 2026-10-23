"""Orderly CLI interruption retains public finalized-check evidence."""

import asyncio
from copy import deepcopy
import json
from types import SimpleNamespace
from unittest.mock import AsyncMock

import click
import pytest

import scanner_cli
from src.core.contracts import checked, record_interaction
from src.core.pipeline import run_pipeline
from src.security.security_engine import SecurityTestEngine
from tests.test_pipeline import asset, engines


async def public_checkpoint():
    discovery, security, risk = engines([asset()])
    report = await run_pipeline(discovery, security, risk, None)
    report['status'] = 'partial'
    report['checkpoint'] = {
        'version': '1.0', 'sequence': 1, 'coverage': 'finalized_checks_only',
    }
    return report


async def execute(output, fmt='json', timeout=1):
    await scanner_cli._execute(None, None, output, fmt, 'full', False,
                               timeout_seconds=timeout)


@pytest.mark.asyncio
@pytest.mark.parametrize('failure', [RuntimeError, ValueError, TimeoutError])
@pytest.mark.parametrize('fmt', ['json', 'sarif'])
async def test_later_failure_retains_checkpoint_privately(tmp_path, monkeypatch, failure, fmt):
    checkpoint = await public_checkpoint()
    original = deepcopy(checkpoint)

    async def interrupted(*args, checkpoint_callback, **kwargs):
        await checkpoint_callback(checkpoint)
        # The consumer owns its copy even if the producer changes its object.
        checkpoint['agents'][0]['vulnerabilities'].clear()
        raise failure('private-upstream-error-value')

    monkeypatch.setattr(scanner_cli, 'run_pipeline', interrupted)
    output = tmp_path / ('report.' + fmt)
    with pytest.raises(click.ClickException, match='retained partial report'):
        await execute(str(output), fmt)
    document = json.loads(output.read_text())
    assert output.stat().st_mode & 0o777 == 0o600
    assert 'private-upstream-error-value' not in output.read_text()
    if fmt == 'json':
        assert document['status'] == 'failed'
        assert document['agents'] == original['agents']
        assert document['summary'] == original['summary']
        assert document['checkpoint'] == original['checkpoint']
    else:
        run = document['runs'][0]
        assert not run['invocations'][0]['executionSuccessful']
        assert run['properties']['scan_status'] == 'failed'
        assert len(run['results']) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize('failure', [RuntimeError, ValueError, TimeoutError, asyncio.CancelledError])
async def test_failure_before_checkpoint_preserves_existing_output(tmp_path, monkeypatch, failure):
    async def interrupted(*args, **kwargs):
        raise failure('private-upstream-error-value')

    monkeypatch.setattr(scanner_cli, 'run_pipeline', interrupted)
    output = tmp_path / 'existing-report.json'
    output.write_text('previous report')
    expected = asyncio.CancelledError if failure is asyncio.CancelledError else click.ClickException
    with pytest.raises(expected):
        await execute(str(output))
    assert output.read_text() == 'previous report'


@pytest.mark.asyncio
async def test_orderly_cancellation_exports_and_stays_cancelled(tmp_path, monkeypatch):
    checkpoint = await public_checkpoint()
    reached = asyncio.Event()

    async def interrupted(*args, checkpoint_callback, **kwargs):
        await checkpoint_callback(checkpoint)
        reached.set()
        await asyncio.Event().wait()

    monkeypatch.setattr(scanner_cli, 'run_pipeline', interrupted)
    output = tmp_path / 'cancelled.json'
    task = asyncio.create_task(execute(str(output)))
    await asyncio.wait_for(reached.wait(), 1)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert task.cancelled()
    report = json.loads(output.read_text())
    assert report['status'] == 'cancelled'
    assert report['agents'] == checkpoint['agents']
    assert checkpoint['status'] == 'partial'
    assert output.stat().st_mode & 0o777 == 0o600


@pytest.mark.asyncio
async def test_timeout_does_not_follow_output_symlink(tmp_path, monkeypatch):
    checkpoint = await public_checkpoint()

    async def interrupted(*args, checkpoint_callback, **kwargs):
        await checkpoint_callback(checkpoint)
        raise TimeoutError

    monkeypatch.setattr(scanner_cli, 'run_pipeline', interrupted)
    target = tmp_path / 'private-original'
    target.write_text('preserve')
    output = tmp_path / 'report.json'
    output.symlink_to(target)
    with pytest.raises(click.ClickException, match='Unable to write report'):
        await execute(str(output))
    assert target.read_text() == 'preserve'


@pytest.mark.asyncio
async def test_timeout_can_export_checkpoint_to_stdout(monkeypatch, capsys):
    checkpoint = await public_checkpoint()

    async def interrupted(*args, checkpoint_callback, **kwargs):
        await checkpoint_callback(checkpoint)
        raise TimeoutError

    monkeypatch.setattr(scanner_cli, 'run_pipeline', interrupted)
    with pytest.raises(click.ClickException, match='deadline exhausted'):
        await execute(None)
    report = json.loads(capsys.readouterr().out)
    assert report['status'] == 'failed'
    assert report['summary']['vulnerabilities_found'] == 1


@pytest.mark.asyncio
@pytest.mark.parametrize('failure', ['write', 'serialize'])
async def test_export_error_does_not_override_cancellation(tmp_path, monkeypatch, capsys, failure):
    checkpoint = await public_checkpoint()
    reached = asyncio.Event()

    async def interrupted(*args, checkpoint_callback, **kwargs):
        await checkpoint_callback(checkpoint)
        reached.set()
        await asyncio.Event().wait()

    def fail_export(*args, **kwargs):
        raise OSError('private-export-failure-value')

    monkeypatch.setattr(scanner_cli, 'run_pipeline', interrupted)
    if failure == 'write':
        monkeypatch.setattr(scanner_cli, 'write_private_text', fail_export)
    else:
        monkeypatch.setattr(scanner_cli, 'to_sarif', fail_export)
    output = tmp_path / 'existing-report.json'
    output.write_text('previous report')
    task = asyncio.create_task(execute(str(output), fmt='sarif'))
    await asyncio.wait_for(reached.wait(), 1)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert task.cancelled()
    assert output.read_text() == 'previous report'
    error = capsys.readouterr().err
    assert 'Unable to write partial report after cancellation' in error
    assert 'private-export-failure-value' not in error


@pytest.mark.asyncio
@pytest.mark.parametrize('invalid', ['envelope', 'nonfinite', 'size'])
async def test_invalid_callback_preserves_previous_valid_checkpoint(tmp_path, monkeypatch, invalid):
    from src.core import contracts

    checkpoint = await public_checkpoint()
    corrupt = deepcopy(checkpoint)
    if invalid == 'envelope':
        corrupt['checkpoint']['sequence'] = True
    elif invalid == 'nonfinite':
        corrupt['summary']['overall_risk_score'] = float('nan')
    else:
        monkeypatch.setattr(contracts, 'MAX_CHECKPOINT_BYTES', len(json.dumps(checkpoint)) + 1024)
        corrupt['unbounded'] = 'x' * (len(json.dumps(checkpoint)) + 2048)

    async def interrupted(*args, checkpoint_callback, **kwargs):
        await checkpoint_callback(checkpoint)
        await checkpoint_callback(corrupt)
        pytest.fail('Invalid checkpoint must stop execution')

    monkeypatch.setattr(scanner_cli, 'run_pipeline', interrupted)
    output = tmp_path / 'report.json'
    with pytest.raises(click.ClickException, match='retained partial report'):
        await execute(str(output))
    report = json.loads(output.read_text())
    assert report['status'] == 'failed'
    assert report['summary'] == checkpoint['summary']
    assert report['checkpoint'] == checkpoint['checkpoint']


class FinalizedThenStalled:
    @checked('fixture.finalized_disclosure', ['fixture-probe'],
             oracle=lambda agent: True)
    async def complete(self, agent):
        record_interaction(True, decisive=True)
        return [{
            'vulnerability_type': 'fixture_disclosure',
            'severity': 'high',
            'description': 'Protected fixture disclosure confirmed',
            'evidence_status': 'confirmed',
        }]

    async def test_agent(self, agent):
        await self.complete(agent)
        await asyncio.Event().wait()


@pytest.mark.asyncio
@pytest.mark.parametrize('fmt', ['json', 'sarif'])
async def test_real_pipeline_deadline_keeps_finalized_check(tmp_path, monkeypatch, fmt):
    agent = asset()
    agent.update(provider='ollama', model='fixture-model',
                 system_prompt_canary='synthetic-private-canary-value',
                 evidence_context_id='public-fixture-context')
    discovery = SimpleNamespace(discover_agents=AsyncMock(return_value=[agent]))
    security = SecurityTestEngine()
    security.prompt_tester = FinalizedThenStalled()
    monkeypatch.setattr(scanner_cli, 'DiscoveryEngine', lambda: discovery)
    monkeypatch.setattr(scanner_cli, 'SecurityTestEngine', lambda: security)
    output = tmp_path / ('deadline.' + fmt)
    with pytest.raises(click.ClickException, match='deadline exhausted'):
        await execute(str(output), fmt, timeout=0.1)
    document = json.loads(output.read_text())
    assert agent['system_prompt_canary'] not in output.read_text()
    assert output.stat().st_mode & 0o777 == 0o600
    if fmt == 'json':
        assert document['status'] == 'failed'
        assert document['summary']['overall_risk_score'] == 70
        assert document['summary']['vulnerabilities_found'] == 1
        assert document['agents'][0]['security_status'] == 'partial'
        assert document['agents'][0]['risk_coverage_status'] == 'partial'
        check = next(item for item in document['agents'][0]['checks']
                     if item['rule_id'] == 'fixture.finalized_disclosure')
        assert check['status'] == 'completed'
        assert check['outcome'] == 'confirmed'
    else:
        run = document['runs'][0]
        assert not run['invocations'][0]['executionSuccessful']
        assert run['properties']['scan_status'] == 'failed'
        assert len(run['results']) == 1
