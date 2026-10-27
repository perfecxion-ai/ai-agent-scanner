"""CLI opt-in checkpoint persistence and offline export integration."""

import asyncio
from copy import deepcopy
import json
from unittest.mock import AsyncMock

import click
from click.testing import CliRunner
import pytest

import scanner_cli
from src.core.cli_checkpoints import CheckpointStore, recover_checkpoint, CLICheckpointError
from src.core.pipeline import run_pipeline
from tests.test_cli_checkpoints import public_checkpoint
from tests.test_pipeline import asset, engines


@pytest.fixture
async def reports():
    partial = await public_checkpoint()
    final = deepcopy(partial)
    final['status'] = 'completed'
    return partial, final


def install_pipeline(monkeypatch, reports, failure=None):
    partial, final = reports

    async def pipeline(*args, checkpoint_callback, **kwargs):
        await checkpoint_callback(partial)
        if failure is not None:
            raise failure('synthetic-private-exception-value')
        return deepcopy(final)

    monkeypatch.setattr(scanner_cli, 'run_pipeline', pipeline)


async def execute(output, checkpoint_dir=None):
    await scanner_cli._execute(None, None, str(output), 'json', 'full', False,
                               checkpoint_dir=str(checkpoint_dir) if checkpoint_dir else None)


@pytest.mark.asyncio
async def test_default_execution_does_not_create_checkpoint_store(tmp_path, monkeypatch, reports):
    install_pipeline(monkeypatch, reports)
    monkeypatch.setattr(CheckpointStore, 'create', lambda *args: pytest.fail('Checkpoint option was not used'))
    await execute(tmp_path / 'report.json')
    assert {path.name for path in tmp_path.iterdir()} == {'report.json'}


@pytest.mark.asyncio
async def test_completed_scan_and_offline_recovery_agree(tmp_path, monkeypatch, reports):
    install_pipeline(monkeypatch, reports)
    store = tmp_path / 'checkpoints'
    output = tmp_path / 'report.json'
    await execute(output, store)
    original = (store / 'latest.json').read_bytes()
    assert store.stat().st_mode & 0o777 == 0o700
    assert all(path.stat().st_mode & 0o777 == 0o600 for path in store.iterdir())
    saved = json.loads(output.read_text())
    with recover_checkpoint(store) as recovered:
        assert recovered == saved == reports[1]
    monkeypatch.setattr(scanner_cli, 'run_pipeline', lambda *args, **kwargs: pytest.fail('Recovery ran a scan'))
    recovered_path = tmp_path / 'recovered.json'
    result = CliRunner().invoke(scanner_cli.cli, ['recover', '--checkpoint-dir', str(store),
                                                 '--output', str(recovered_path)])
    assert result.exit_code == 0, result.output
    assert json.loads(recovered_path.read_text()) == saved
    assert recovered_path.stat().st_mode & 0o777 == 0o600
    assert (store / 'latest.json').read_bytes() == original


@pytest.mark.asyncio
@pytest.mark.parametrize('failure', [RuntimeError, ValueError, TimeoutError, asyncio.CancelledError])
@pytest.mark.parametrize('fmt', ['json', 'sarif'])
async def test_terminal_interruption_recovery_preserves_truth(tmp_path, monkeypatch, reports, failure, fmt):
    install_pipeline(monkeypatch, reports, failure)
    store = tmp_path / 'checkpoints'
    expected_error = asyncio.CancelledError if failure is asyncio.CancelledError else click.ClickException
    with pytest.raises(expected_error):
        await execute(tmp_path / 'report.json', store)
    destination = tmp_path / ('recovered.' + fmt)
    result = CliRunner().invoke(scanner_cli.cli, ['recover', '--checkpoint-dir', str(store),
                                                 '--format', fmt, '--output', str(destination)])
    assert result.exit_code == 1
    assert destination.exists(), result.output
    report = json.loads(destination.read_text())
    status = 'cancelled' if failure is asyncio.CancelledError else 'failed'
    if fmt == 'json':
        assert report['status'] == status
        assert report['agents'] == reports[0]['agents']
        assert report['checkpoint'] == reports[0]['checkpoint']
    else:
        assert report['runs'][0]['properties']['scan_status'] == status
        assert report['runs'][0]['invocations'][0]['executionSuccessful'] is False
    assert 'synthetic-private-exception-value' not in destination.read_text() + result.output


@pytest.mark.asyncio
async def test_output_failure_leaves_terminal_checkpoint_recoverable(tmp_path, monkeypatch, reports):
    install_pipeline(monkeypatch, reports)
    store = tmp_path / 'checkpoints'
    output = tmp_path / 'missing-parent' / 'report.json'
    with pytest.raises(click.ClickException, match='Unable to write report'):
        await execute(output, store)
    with recover_checkpoint(store) as recovered:
        assert recovered == reports[1]


@pytest.mark.asyncio
async def test_failure_before_first_acknowledgement_cannot_recover(tmp_path, monkeypatch):
    async def pipeline(*args, **kwargs):
        raise RuntimeError('synthetic-private-exception-value')

    monkeypatch.setattr(scanner_cli, 'run_pipeline', pipeline)
    store = tmp_path / 'checkpoints'
    with pytest.raises(click.ClickException, match='Scan execution failed'):
        await execute(tmp_path / 'report.json', store)
    assert not (store / 'latest.json').exists()
    with pytest.raises(CLICheckpointError):
        with recover_checkpoint(store):
            pytest.fail('Missing checkpoint was accepted')


@pytest.mark.asyncio
async def test_cancelled_scan_stays_cancelled_if_final_persistence_fails(tmp_path, monkeypatch, reports):
    install_pipeline(monkeypatch, reports, asyncio.CancelledError)
    monkeypatch.setattr(CheckpointStore, 'finish', lambda *args: (_ for _ in ()).throw(CLICheckpointError()))
    store = tmp_path / 'checkpoints'
    with pytest.raises(asyncio.CancelledError):
        await execute(tmp_path / 'report.json', store)
    with recover_checkpoint(store) as recovered:
        assert recovered['status'] == 'partial'
        assert recovered['agents'] == reports[0]['agents']


@pytest.mark.asyncio
@pytest.mark.parametrize('destination', ['latest.json', '.lock', 'nested/report.json'])
async def test_scan_output_inside_checkpoint_directory_is_rejected_before_execution(
        tmp_path, monkeypatch, destination):
    monkeypatch.setattr(scanner_cli, 'run_pipeline', lambda *args, **kwargs: pytest.fail('Invalid output ran a scan'))
    store = tmp_path / 'checkpoints'
    with pytest.raises(click.ClickException, match='Unable to preserve CLI checkpoint'):
        await execute(store / destination, store)
    assert not store.exists()


@pytest.mark.asyncio
@pytest.mark.parametrize('destination', ['latest.json', '.lock', 'nested/report.json'])
async def test_recovery_output_cannot_modify_checkpoint_directory(tmp_path, reports, destination):
    store = tmp_path / 'checkpoints'
    with CheckpointStore.create(store) as writer:
        writer.publish(reports[0])
    original = (store / 'latest.json').read_bytes()
    result = CliRunner().invoke(scanner_cli.cli, ['recover', '--checkpoint-dir', str(store),
                                                 '--output', str(store / destination)])
    assert result.exit_code == 1
    assert (store / 'latest.json').read_bytes() == original
    assert {path.name for path in store.iterdir()} == {'.lock', 'latest.json'}


@pytest.mark.asyncio
async def test_live_writer_refuses_recovery_and_second_scan(tmp_path, reports, monkeypatch):
    store = tmp_path / 'checkpoints'
    with CheckpointStore.create(store) as writer:
        writer.publish(reports[0])
        result = CliRunner().invoke(scanner_cli.cli, ['recover', '--checkpoint-dir', str(store),
                                                     '--output', str(tmp_path / 'recovered.json')])
        assert result.exit_code == 1
        assert not (tmp_path / 'recovered.json').exists()
        monkeypatch.setattr(scanner_cli, 'run_pipeline', lambda *args, **kwargs: pytest.fail('Existing store ran a scan'))
        with pytest.raises(click.ClickException, match='Unable to preserve CLI checkpoint'):
            await execute(tmp_path / 'report.json', store)


@pytest.mark.parametrize('command', ['scan', 'discover'])
def test_checkpoint_option_reaches_shared_executor(tmp_path, monkeypatch, command):
    monkeypatch.setattr(scanner_cli, 'load_targets', lambda *args: (None, None))
    execute_mock = AsyncMock()
    monkeypatch.setattr(scanner_cli, '_execute', execute_mock)
    destination = str(tmp_path / 'new-checkpoint')
    result = CliRunner().invoke(scanner_cli.cli, [command, '--checkpoint-dir', destination])
    assert result.exit_code == 0, result.output
    assert execute_mock.await_args.kwargs['checkpoint_dir'] == destination


def test_recovery_output_symlink_loop_has_static_error(tmp_path):
    destination = tmp_path / 'synthetic-private-output'
    destination.symlink_to(destination.name)
    result = CliRunner().invoke(scanner_cli.cli, ['recover', '--checkpoint-dir', str(tmp_path / 'missing'),
                                                 '--output', str(destination)])
    assert result.exit_code == 1
    assert isinstance(result.exception, SystemExit)
    assert 'Unable to recover CLI checkpoint' in result.output
    assert destination.name not in result.output


@pytest.mark.asyncio
@pytest.mark.parametrize('source', ['canary', 'credential'])
async def test_new_public_descriptors_are_checked_against_pinned_private_values(tmp_path, monkeypatch, source):
    protected = 'ai-agent-scanner-cli-checkpoint'
    target = asset()
    if source == 'canary':
        target['system_prompt_canary'] = protected
    else:
        target['api_key_env'] = 'CLI_CHECKPOINT_FIXTURE_KEY'
        monkeypatch.setenv('CLI_CHECKPOINT_FIXTURE_KEY', protected)
    discovery, security, risk = engines([target])
    published = []

    async def retain(report):
        published.append(report)

    with pytest.raises(ValueError, match='Protected evidence conflicts with checkpoint fields'):
        await run_pipeline(discovery, security, risk, None, 'security_only', agents=[target],
                           checkpoint_callback=retain, checkpoint_public_fields=(protected,))
    assert published == []
    security.test_agents.assert_not_called()
    # The new descriptors are reserved only for an opted-in store.
    report = await run_pipeline(discovery, security, risk, None, 'security_only', agents=[target])
    assert protected not in json.dumps(report)


@pytest.mark.asyncio
@pytest.mark.parametrize('protected', ['ai-agent-scanner-cli-checkpoint', *scanner_cli._CLI_INTERRUPTION_REASONS])
async def test_cli_reserves_actual_file_and_terminal_labels_before_first_write(
        tmp_path, monkeypatch, capsys, protected):
    target = dict(asset(), system_prompt_canary=protected)
    enter = AsyncMock(side_effect=AssertionError('Protected public label reached HTTP'))
    monkeypatch.setattr('src.core.transport.SafeSession.__aenter__', enter)
    directory = tmp_path / 'checkpoints'
    with pytest.raises(click.ClickException, match='Scan execution failed'):
        await scanner_cli._execute(None, [target], str(tmp_path / 'report.json'), 'json',
                                   'security_only', False, checkpoint_dir=str(directory))
    assert not (directory / 'latest.json').exists()
    assert protected not in capsys.readouterr().out
    enter.assert_not_called()
