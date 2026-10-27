"""Private CLI snapshot contracts, using owned disposable filesystem paths."""

import asyncio
from copy import deepcopy
import json
import os
import signal
import stat
import subprocess
import sys
import uuid

import pytest
import pytest_asyncio

from src.core import cli_checkpoints as store_module
from src.core.cli_checkpoints import CheckpointStore, CLICheckpointError, recover_checkpoint
from tests.test_cli_checkpoints import public_checkpoint


@pytest_asyncio.fixture
async def report():
    return await public_checkpoint()


def read(path):
    return json.loads((path / 'latest.json').read_text())


def rewrite(path, envelope):
    (path / 'latest.json').write_text(json.dumps(envelope))


def following(report):
    value = deepcopy(report)
    value['checkpoint']['sequence'] += 1
    return value


def test_acknowledged_snapshot_is_private_and_recovers_read_only(tmp_path, report):
    path = tmp_path / 'run'
    original = deepcopy(report)
    with CheckpointStore.create(path) as store:
        store.publish(report)
        with pytest.raises(CLICheckpointError):
            with recover_checkpoint(path):
                pytest.fail('Live writer must exclude recovery')
        report['agents'].clear()
    assert read(path)['report'] == original
    assert stat.S_IMODE(path.stat().st_mode) == 0o700
    for entry in path.iterdir():
        assert stat.S_IMODE(entry.stat().st_mode) == 0o600
        assert entry.stat().st_nlink == 1
    before = {entry.name: (entry.read_bytes(), entry.stat().st_mtime_ns) for entry in path.iterdir()}
    with recover_checkpoint(path) as recovered:
        assert recovered == {**original, 'error': store_module.RECOVERY_REASON, 'status': 'partial'}
        recovered['agents'].clear()
        with pytest.raises(CLICheckpointError):
            with recover_checkpoint(path):
                pytest.fail('Reader must hold the exclusive lock through export')
    assert before == {entry.name: (entry.read_bytes(), entry.stat().st_mtime_ns) for entry in path.iterdir()}


@pytest.mark.parametrize('status', ['completed', 'partial', 'failed', 'cancelled'])
def test_terminal_truth_and_producer_are_preserved(tmp_path, report, status):
    path = tmp_path / 'run'
    with CheckpointStore.create(path) as store:
        store.publish(report)
        final = {**report, 'status': status}
        store.finish(final)
        with pytest.raises(CLICheckpointError):
            store.publish(following(report))
    with recover_checkpoint(path) as recovered:
        assert recovered == final
        assert recovered.get('producer_identity') == report.get('producer_identity')
        assert 'exporter_identity' not in recovered


def test_fsync_and_replace_finish_before_ack(tmp_path, report, monkeypatch):
    events = []
    fsync, replace = os.fsync, os.replace

    def sync(fd):
        events.append('directory-sync' if stat.S_ISDIR(os.fstat(fd).st_mode) else 'file-sync')
        return fsync(fd)

    def move(*args, **kwargs):
        events.append('replace')
        return replace(*args, **kwargs)

    with CheckpointStore.create(tmp_path / 'run') as store:
        monkeypatch.setattr(os, 'fsync', sync)
        monkeypatch.setattr(os, 'replace', move)
        store.publish(report)
        events.append('ack')
    assert events == ['file-sync', 'replace', 'directory-sync', 'ack']


@pytest.mark.parametrize('failure', ['write', 'file-sync', 'replace', 'directory-sync'])
def test_persistence_fault_is_fatal_and_keeps_valid_snapshot(tmp_path, report, monkeypatch, failure):
    path = tmp_path / 'run'
    with CheckpointStore.create(path) as store:
        store.publish(report)
        original = (path / 'latest.json').read_bytes()
        fsync = os.fsync

        def broken(*args, **kwargs):
            raise OSError('private-filesystem-error-do-not-echo')

        def sync(fd):
            directory = stat.S_ISDIR(os.fstat(fd).st_mode)
            if directory == (failure == 'directory-sync'):
                broken()
            return fsync(fd)

        with monkeypatch.context() as changed:
            if failure in {'write', 'replace'}:
                changed.setattr(os, failure, broken)
            else:
                changed.setattr(os, 'fsync', sync)
            with pytest.raises(CLICheckpointError, match='^CLI checkpoint is unavailable, unsafe, or invalid$'):
                store.publish(following(report))
        with pytest.raises(CLICheckpointError):
            store.finish({**report, 'status': 'completed'})
    if failure != 'directory-sync':
        assert (path / 'latest.json').read_bytes() == original
    else:
        assert read(path)['report']['checkpoint']['sequence'] == 2
    assert not list(path.glob('*.tmp'))
    with recover_checkpoint(path) as recovered:
        assert recovered['summary'] == report['summary']
        assert recovered['status'] == 'partial'


@pytest.mark.parametrize('mutation', ['identity', 'version', 'sequence', 'asset-id', 'finding', 'check'])
def test_typed_execution_prefix_cannot_change(tmp_path, report, mutation):
    path = tmp_path / 'run'
    with CheckpointStore.create(path) as store:
        store.publish(report)
        previous = (path / 'latest.json').read_bytes()
        changed = following(report)
        if mutation == 'identity':
            changed['producer_identity'] = None
        elif mutation == 'version':
            changed['checkpoint']['version'] = '2.0'
        elif mutation == 'sequence':
            changed['checkpoint']['sequence'] = True
        elif mutation == 'asset-id':
            changed['agents'][0]['id'] = 'different-asset'
        elif mutation == 'finding':
            changed['agents'][0]['vulnerabilities'][0]['description'] = 'Changed evidence'
        else:
            changed['agents'][0]['checks'][0]['responses_evaluated'] += 1
        with pytest.raises(CLICheckpointError):
            store.publish(changed)
        assert (path / 'latest.json').read_bytes() == previous


@pytest.mark.parametrize('mutation', ['raw-key', 'credential-url', 'score', 'producer', 'cycle', 'depth', 'expanded-dag'])
def test_untrusted_writer_input_fails_before_new_artifact(tmp_path, report, monkeypatch, mutation):
    changed = deepcopy(report)
    if mutation == 'raw-key':
        changed['agents'][0]['metadata']['api_key'] = 'private-fixture-secret'
    elif mutation == 'credential-url':
        changed['agents'][0]['endpoint'] = 'https://user:private-fixture-secret@example.test/'
    elif mutation == 'score':
        changed['agents'][0]['risk_score'] = 0
    elif mutation == 'producer':
        changed['producer_identity']['source']['sha256'] = '[redacted]'
    elif mutation == 'cycle':
        changed['loop'] = changed
    elif mutation == 'depth':
        nested = 0
        for _ in range(64):
            nested = [nested]
        changed['extra'] = nested
    else:
        monkeypatch.setattr(store_module, 'MAX_CHECKPOINT_BYTES', 4096)
        nested = ['x']
        for _ in range(16):
            nested = [nested, nested]
        changed['extra'] = nested
    path = tmp_path / 'run'
    with CheckpointStore.create(path) as store:
        with pytest.raises(CLICheckpointError):
            store.publish(changed)
    assert not (path / 'latest.json').exists()


@pytest.mark.parametrize('leaf', ['latest.json', '.lock'])
@pytest.mark.parametrize('kind', ['symlink', 'hardlink', 'directory', 'fifo', 'mode', 'owner'])
def test_unsafe_leaf_is_refused_without_touching_external_file(tmp_path, report, leaf, kind, monkeypatch):
    path = tmp_path / 'run'
    with CheckpointStore.create(path) as store:
        store.publish(report)
    external = tmp_path / 'external'
    external.write_text('private-external-value')
    external.chmod(0o600)
    destination = path / leaf
    destination.unlink()
    if kind == 'symlink':
        destination.symlink_to(external)
    elif kind == 'hardlink':
        os.link(external, destination)
    elif kind == 'directory':
        destination.mkdir(mode=0o600)
    elif kind == 'fifo':
        os.mkfifo(destination, 0o600)
    else:
        destination.write_text('untrusted')
        destination.chmod(0o644 if kind == 'mode' else 0o600)
        if kind == 'owner':
            monkeypatch.setattr(store_module.os, 'getuid', lambda: destination.stat().st_uid + 1)
    # A subprocess deadline proves FIFO type rejection occurs before blocking open.
    if kind == 'fifo':
        code = ('from src.core.cli_checkpoints import recover_checkpoint, CLICheckpointError\n'
                'import sys\ntry:\n with recover_checkpoint(sys.argv[1]): pass\n'
                'except CLICheckpointError: sys.exit(0)\nsys.exit(1)')
        result = subprocess.run([sys.executable, '-c', code, str(path)], capture_output=True, timeout=5)
        assert result.returncode == 0 and result.stderr == b''
    else:
        with pytest.raises(CLICheckpointError):
            with recover_checkpoint(path):
                pytest.fail('Unsafe leaf accepted')
    assert external.read_text() == 'private-external-value'


@pytest.mark.parametrize('kind', ['unknown', 'two-stages', 'unsafe-stage', 'oversized-stage'])
def test_unknown_or_unsafe_residue_is_refused(tmp_path, report, kind):
    path = tmp_path / 'run'
    with CheckpointStore.create(path) as store:
        store.publish(report)
    stage = path / ('.checkpoint-' + uuid.uuid4().hex + '.tmp')
    stage.write_bytes(b'uncommitted-candidate')
    stage.chmod(0o600)
    if kind == 'unknown':
        stage.rename(path / 'unrecognized')
    elif kind == 'two-stages':
        other = path / ('.checkpoint-' + uuid.uuid4().hex + '.tmp')
        other.write_bytes(b'other')
        other.chmod(0o600)
    elif kind == 'unsafe-stage':
        stage.chmod(0o644)
    else:
        with stage.open('wb') as stream:
            stream.truncate(store_module.MAX_FILE_BYTES + 1)
    with pytest.raises(CLICheckpointError):
        with recover_checkpoint(path):
            pytest.fail('Unsafe layout accepted')


def test_interrupted_staging_file_never_hides_previous_ack(tmp_path, report):
    path = tmp_path / 'run'
    with CheckpointStore.create(path) as store:
        store.publish(report)
    stage = path / ('.checkpoint-' + uuid.uuid4().hex + '.tmp')
    stage.write_bytes(b'not-json-or-committed')
    stage.chmod(0o600)
    before = stage.read_bytes()
    with recover_checkpoint(path) as recovered:
        assert recovered['agents'] == report['agents']
    assert stage.read_bytes() == before


@pytest.mark.parametrize('mutation', ['duplicate', 'nonfinite', 'deep', 'utf16', 'oversized', 'wrapper', 'uuid', 'status'])
def test_bounded_strict_json_and_terminal_honesty(tmp_path, report, mutation):
    path = tmp_path / 'run'
    with CheckpointStore.create(path) as store:
        store.publish(report)
    envelope = read(path)
    if mutation == 'duplicate':
        raw = b'{"format":0,"format":1}'
    elif mutation == 'nonfinite':
        raw = b'{"extra":NaN}'
    elif mutation == 'deep':
        raw = b'[' * 66 + b'0' + b']' * 66
    elif mutation == 'utf16':
        raw = json.dumps(envelope).encode('utf-16')
    elif mutation == 'oversized':
        raw = b' ' * (store_module.MAX_FILE_BYTES + 1)
    else:
        if mutation == 'wrapper':
            envelope['version'] = 'unrecognized'
        elif mutation == 'uuid':
            envelope['execution_id'] = True
        else:
            envelope['state'] = 'terminal'
            envelope['report']['status'] = 'completed'
            envelope['report']['agents'][0]['security_status'] = 'partial'
            envelope['report']['security_results'][0]['status'] = 'partial'
        raw = json.dumps(envelope).encode()
    (path / 'latest.json').write_bytes(raw)
    with pytest.raises(CLICheckpointError):
        with recover_checkpoint(path):
            pytest.fail('Invalid archive accepted')


def test_fresh_directory_does_not_overwrite_and_allows_symlink_ancestors(tmp_path, report):
    ancestor = tmp_path / 'canonical'
    ancestor.mkdir(mode=0o700)
    alias = tmp_path / 'alias'
    alias.symlink_to(ancestor, target_is_directory=True)
    path = alias / 'run'
    with CheckpointStore.create(path) as store:
        store.publish(report)
    original = (path / 'latest.json').read_bytes()
    with pytest.raises(CLICheckpointError):
        with CheckpointStore.create(path):
            pytest.fail('Existing run was overwritten')
    assert (path / 'latest.json').read_bytes() == original
    linked_run = tmp_path / 'linked-run'
    linked_run.symlink_to(path, target_is_directory=True)
    with pytest.raises(CLICheckpointError):
        with recover_checkpoint(linked_run):
            pytest.fail('Final-directory symlink accepted')


def test_cancellation_survives_cleanup_failure(tmp_path, report, monkeypatch):
    original = store_module.CheckpointStore.close

    def broken(store):
        original(store)
        raise CLICheckpointError()

    with pytest.raises(asyncio.CancelledError):
        with CheckpointStore.create(tmp_path / 'run') as store:
            store.publish(report)
            monkeypatch.setattr(store_module.CheckpointStore, 'close', broken)
            raise asyncio.CancelledError


def test_kernel_releases_writer_lock_after_process_kill(tmp_path, report):
    path = tmp_path / 'run'
    input_file = tmp_path / 'input.json'
    input_file.write_text(json.dumps(report))
    code = ('import json,sys,time\nfrom src.core.cli_checkpoints import CheckpointStore\n'
            'with CheckpointStore.create(sys.argv[1]) as store:\n'
            ' store.publish(json.load(open(sys.argv[2])))\n print("ACK",flush=True)\n time.sleep(60)\n')
    child = subprocess.Popen([sys.executable, '-c', code, str(path), str(input_file)], stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE, text=True)
    try:
        import select
        ready, _, _ = select.select([child.stdout], [], [], 5)
        assert ready and child.stdout.readline().strip() == 'ACK'
        with pytest.raises(CLICheckpointError):
            with recover_checkpoint(path):
                pytest.fail('Writer lock not held')
        child.send_signal(signal.SIGKILL)
        child.wait(timeout=5)
        with recover_checkpoint(path) as saved:
            assert saved['agents'] == report['agents']
    finally:
        if child.poll() is None:
            child.kill()
        _, error = child.communicate(timeout=5)
        assert error == ''


@pytest.mark.asyncio
@pytest.mark.parametrize('rule', ['authentication_bypass', 'authorization_bypass'])
@pytest.mark.parametrize('mode,score', [('protected', 0), ('vulnerable', 70), ('partial', 70)])
async def test_current_receipts_roundtrip_every_ack_and_terminal(tmp_path, rule, mode, score):
    from tests.access_provenance_fixture import current_access_report

    path, saved = tmp_path / 'run', []
    with CheckpointStore.create(path) as store:
        async def publish(report):
            store.publish(report)
            saved.append(deepcopy(report))
        report = await current_access_report(rule=rule, mode=mode, checkpoint_callback=publish)
        assert report['checkpoint']['version'] == '4.0'
        assert report['summary']['overall_risk_score'] == score
        assert report['check_evidence_schema_version'] == '3.0'
        store.finish(report)
    with recover_checkpoint(path) as recovered:
        assert recovered == report
    assert saved[0]['checkpoint']['sequence'] == 1
    assert saved[-1]['checkpoint']['sequence'] == report['checkpoint']['sequence']
    if mode != 'protected':
        assert report['agents'][0]['check_evidence']
        assert any(item['summary']['overall_risk_score'] == score for item in saved)


@pytest.mark.parametrize('name', ['zero', 'high', 'partial', 'mixed'])
def test_frozen_ledger_two_access_v3_is_not_restamped(tmp_path, name):
    from tests.legacy_access_v3_fixtures import legacy_access_v3_report

    report = legacy_access_v3_report(name)
    final_status = report['status']
    report['status'] = 'partial'
    report['checkpoint']['sequence'] = 1
    original = deepcopy(report)
    path = tmp_path / 'run'
    with CheckpointStore.create(path) as store:
        store.publish(report)
        report['status'] = final_status
        store.finish(report)
    with recover_checkpoint(path) as recovered:
        assert recovered == {**original, 'status': final_status}
        assert recovered['checkpoint']['version'] == '3.0'
        assert recovered['check_evidence_schema_version'] == '2.0'


def test_frozen_prompt_ledger_one_recovers_unfinished_evidence(tmp_path):
    from tests.legacy_observation_fixtures import legacy_report

    report = legacy_report('prompt-unfinished-checkpoint')
    report['checkpoint']['sequence'] = 1
    path = tmp_path / 'run'
    with CheckpointStore.create(path) as store:
        store.publish(report)
    with recover_checkpoint(path) as recovered:
        assert recovered == {**report, 'status': 'partial', 'error': store_module.RECOVERY_REASON}
        assert recovered['checkpoint']['version'] == '2.0'
        assert recovered['check_evidence_schema_version'] == '1.0'
        assert recovered['summary']['overall_risk_score'] == 70


@pytest.mark.parametrize('field,value', [('overall_risk_score', False), ('risk_level', 'critical'),
                                        ('coverage_status', 'partial'), ('scoring_policy', 'forged-policy')])
@pytest.mark.asyncio
async def test_assessment_view_cannot_contradict_a_genuine_zero(tmp_path, field, value):
    from tests.access_provenance_fixture import current_access_report

    async def sink(value):
        pass

    report = await current_access_report(mode='protected', checkpoint_callback=sink)
    report['status'] = 'partial'
    report['checkpoint']['sequence'] = 1
    report['risk_assessments'][0][field] = value
    with CheckpointStore.create(tmp_path / 'run') as store:
        with pytest.raises(CLICheckpointError):
            store.publish(report)


def test_write_cancellation_survives_temporary_cleanup_failure(tmp_path, report, monkeypatch):
    def cancelled(*args, **kwargs):
        raise asyncio.CancelledError

    def failed(*args, **kwargs):
        raise OSError('private-cleanup-failure')

    with CheckpointStore.create(tmp_path / 'run') as store:
        with monkeypatch.context() as changed:
            changed.setattr(os, 'write', cancelled)
            changed.setattr(os, 'unlink', failed)
            with pytest.raises(asyncio.CancelledError):
                store.publish(report)
        with pytest.raises(CLICheckpointError):
            store.finish({**report, 'status': 'completed'})


@pytest.mark.asyncio
async def test_real_prompt_receipt_tuples_are_normalized_before_every_ack(tmp_path):
    from src.core.pipeline import run_pipeline
    from src.core.risk_projection import project_report_risk
    from src.core.transport import ScanBudget, scan_transport
    from src.risk.risk_assessor import RiskAssessment
    from tests.prompt_progress_fixture import CANARY, disclosure_target, unfinished_prompt_engine

    ready, saved, tuple_paths = asyncio.Event(), [], []
    path = tmp_path / 'run'
    engine = unfinished_prompt_engine(ready.set)
    with disclosure_target() as (agent, calls), CheckpointStore.create(path) as store:
        async def publish(report):
            for view in (*report['agents'], *report['security_results']):
                for finding in view.get('vulnerabilities', []):
                    tuple_paths.extend(item for item in finding.get('detected_patterns', []) if isinstance(item, tuple))
            store.publish(report)
            # Validate every on-disk intermediate representation, including the
            # first unscored receipt, without releasing the writer's lock.
            _, on_disk = store._read()
            assert on_disk == json.loads(json.dumps(report))
            saved.append(on_disk)

        with scan_transport(ScanBudget(allow_loopback=True, allowed_networks=('127.0.0.1/32',), max_requests=5)):
            task = asyncio.create_task(run_pipeline(None, engine, RiskAssessment(), None, 'security_only',
                                                    agents=[agent], checkpoint_callback=publish))
            try:
                await asyncio.wait_for(ready.wait(), 5)
            finally:
                task.cancel()
                with pytest.raises(asyncio.CancelledError):
                    await task
        assert len(calls) == 1
        assert tuple_paths
        assert len(saved) >= 3
        assert saved[-1]['summary']['overall_risk_score'] == 70
        assert saved[-1]['summary']['checks_unfinished'] == 1
    with recover_checkpoint(path) as recovered:
        assert recovered == {**saved[-1], 'error': store_module.RECOVERY_REASON, 'status': 'partial'}
        assert project_report_risk(recovered)[0]['overall_risk_score'] == 70
        assert CANARY not in json.dumps(recovered)


@pytest.mark.parametrize('kind', ['cycle', 'private-field', 'credential-url', 'expanded-dag', 'depth'])
def test_tuple_normalization_preserves_bounds_and_privacy(tmp_path, report, monkeypatch, kind):
    if kind == 'cycle':
        values = []
        report['extra'] = (values,)
        values.append(report['extra'])
    elif kind == 'private-field':
        report['extra'] = ({'api_key': 'tuple-contained-private-key'},)
    elif kind == 'credential-url':
        report['extra'] = ('https://user:tuple-private-key@example.test/',)
    elif kind == 'expanded-dag':
        monkeypatch.setattr(store_module, 'MAX_CHECKPOINT_BYTES', 4096)
        values = ('x',)
        for _ in range(16):
            values = (values, values)
        report['extra'] = values
    else:
        values = 0
        for _ in range(64):
            values = (values,)
        report['extra'] = values
    with CheckpointStore.create(tmp_path / 'run') as store:
        with pytest.raises(CLICheckpointError):
            store.publish(report)
