"""SIGKILL recovery of acknowledged evidence through production CLI entry points."""

from copy import deepcopy
import json
import os
import signal
import stat
import subprocess
import sys

import pytest

from src.core.build_identity import saved_identity
from src.core.contracts import validate_checkpoint_report
from src.core.risk_projection import project_report_risk
from tests.cli_checkpoint_process_fixture import (
    OFFLINE_RECOVERY, ROOT, SCENARIOS, killed_cli_cases, private_values, recover_offline,
)


pytestmark = pytest.mark.skipif(os.name != 'posix', reason='CLI file checkpoints require POSIX')


@pytest.mark.parametrize('action', ['network', 'dns', 'database', 'config', 'registry', 'environment', 'process'])
def test_offline_recovery_guards_reject_owned_probe_actions(tmp_path, action):
    config, registry = tmp_path / 'config.json', tmp_path / 'registry.json'
    config.write_text('{}')
    registry.write_text('{}')
    completed = subprocess.run(
        [sys.executable, '-W', 'error', '-c', OFFLINE_RECOVERY, str(config), str(registry), '--guard-probe', action],
        cwd=ROOT, env={'PATH': os.defpath, 'PYTHONIOENCODING': 'utf-8'},
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5, check=False)
    assert completed.returncode == 0, completed.stderr.decode()


@pytest.fixture(scope='module')
def killed_cases(tmp_path_factory):
    directory = tmp_path_factory.mktemp('owned-cli-checkpoint-process').resolve(strict=True)
    directory.chmod(0o700)
    with killed_cli_cases(directory) as cases:
        yield cases


@pytest.mark.parametrize('scenario', SCENARIOS)
def test_sigkill_cli_recovers_exact_public_receipts_offline(killed_cases, scenario):
    case = killed_cases[scenario]
    expected_score = 90 if scenario in {'tenant', 'access-critical'} else 70
    envelope = case.envelope
    assert set(envelope) == {'format', 'version', 'execution_id', 'state', 'report'}
    assert envelope['format'] == 'ai-agent-scanner-cli-checkpoint' and envelope['version'] == '1.0'
    assert envelope['state'] == 'checkpoint'
    assert case.process.returncode == -signal.SIGKILL
    with pytest.raises(ProcessLookupError):
        os.killpg(case.process.pid, 0)
    original = envelope['report']
    validate_checkpoint_report(original)
    assert original['checkpoint']['version'] == '4.0'
    assert original['check_evidence_schema_version'] == '3.0'
    assert original['summary']['overall_risk_score'] == expected_score
    asset = original['agents'][0]
    receipts, findings = asset['check_evidence'], asset['vulnerabilities']
    assert len(receipts) == len(findings) == 1
    receipt, finding = receipts[0], findings[0]
    assert receipt['id'] == finding['check_evidence_id']
    assert receipt['finding_id'] == finding['id']
    assert receipt['agent_id'] == finding['agent_id'] == asset['id']
    assert receipt['run_id'] == asset['check_evidence_run_id']
    assert receipt['sequence'] == 1
    assert not any(check['rule_id'] == receipt['rule_id'] for check in asset['checks'])
    assert original['summary']['checks_unfinished'] == 1
    expected_source = ('controlled_tenant_response' if scenario == 'tenant' else
                       'protected_system_canary_match' if scenario == 'prompt' else 'controlled_access_response')
    assert receipt['source'] == expected_source
    assert receipt['source_version'] == ('2.0' if scenario == 'prompt' else '1.0')
    if scenario == 'tenant':
        assert receipt['request_ordinal'] == 2
        assert receipt['requests_attempted'] == receipt['responses_evaluated'] == 3
        assert receipt['control_proof'] == {'request_ordinals': [1, 2, 3], 'status_codes': [200, 200, 403]}
    elif scenario.startswith('access-'):
        assert receipt['request_ordinal'] == receipt['requests_attempted'] == receipt['responses_evaluated'] == 3
        assert receipt['control_proof'] == {'request_ordinals': [1, 2], 'status_codes': [200, 403]}
        assert receipt['rule_id'] == ('weak_credentials' if scenario == 'access-critical' else 'authentication_bypass')
    else:
        assert receipt['request_ordinal'] == receipt['requests_attempted'] == receipt['responses_evaluated'] == 1
    identity = original['producer_identity']
    assert saved_identity(identity) == identity and identity['component'] == 'cli'
    for path in case.checkpoint_dir.iterdir():
        info = path.lstat()
        assert stat.S_ISREG(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o600 and info.st_nlink == 1
        assert info.st_uid == os.getuid()
    assert {path.name for path in case.checkpoint_dir.iterdir()} == {'.lock', 'latest.json'}
    assert stat.S_IMODE(case.checkpoint_dir.stat().st_mode) == 0o700
    assert case.checkpoint_dir.stat().st_uid == os.getuid()
    assert all(call['tls'] in {'TLSv1.2', 'TLSv1.3'} for call in case.state.calls)
    assert not case.state.failures
    assert case.state.blocked.is_set()
    assert 'ResourceWarning' not in case.log.read_text()
    public = case.original_bytes.decode() + case.log.read_text()
    recovered_json = None
    for fmt in ('json', 'sarif'):
        before = {path.name: path.read_bytes() for path in case.checkpoint_dir.iterdir()}
        completed, output, log = recover_offline(case, fmt)
        assert completed.returncode == 1, log.read_text()
        assert 'original scan did not complete' in log.read_text()
        assert 'ResourceWarning' not in log.read_text()
        assert {path.name: path.read_bytes() for path in case.checkpoint_dir.iterdir()} == before
        assert (case.checkpoint_dir / 'latest.json').read_bytes() == case.original_bytes
        assert len(case.state.calls) == case.calls_after_kill
        assert stat.S_IMODE(output.stat().st_mode) == 0o600
        document = json.loads(output.read_text())
        public += output.read_text() + log.read_text()
        if fmt == 'json':
            recovered_json = document
            assert document['status'] == 'partial'
            assert document['error']
            expected = deepcopy(original)
            expected['status'] = document['status']
            expected['error'] = document['error']
            assert document == expected
            assert project_report_risk(document)[0]['overall_risk_score'] == expected_score
            assert document['agents'][0]['risk_coverage_status'] == 'partial'
        else:
            run = document['runs'][0]
            assert run['invocations'][0]['executionSuccessful'] is False
            assert run['properties']['summary'] == recovered_json['summary']
            assert run['properties']['producer_identity'] == identity
            assert run['properties']['check_evidence_schema_version'] == '3.0'
            assert run['properties']['check_evidence'][0]['check_evidence'] == receipts
            assert {item['properties']['vulnerability_id'] for item in run['results']} == {finding['id']}
    assert all(value not in public for value in private_values(case))
    assert not (case.directory / 'unused-report.json').exists()
