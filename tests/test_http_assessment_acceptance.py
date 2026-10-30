"""Public HTTP assessment gate owns its processes, I/O guards and failure exits."""

import importlib.util
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import time

import pytest


SCRIPT = Path(__file__).resolve().parents[1] / 'scripts/acceptance-http-assessment.py'
SPEC = importlib.util.spec_from_file_location('http_assessment_gate', SCRIPT)
gate = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(gate)


@pytest.mark.parametrize('optimized', [False, True])
def test_public_http_gate_runs_actual_cli_and_reaps_all_owned_resources(optimized, tmp_path):
    operator = tmp_path / 'operator-database'
    profile = tmp_path / 'operator-registry'
    operator.write_bytes(b'Owned sentinel must remain unchanged')
    profile.write_bytes(b'Owned profile sentinel must never be opened')
    original = (operator.read_bytes(), profile.read_bytes())
    environment = dict(os.environ, DATABASE_URL='sqlite:///' + str(operator),
                       SCAN_EVIDENCE_PROFILES_FILE=str(profile),
                       OPERATOR_API_KEY='inherited-owned-operator-key-not-for-http',
                       OPENAI_API_KEY='inherited-owned-cloud-key-not-for-http',
                       HTTP_PROXY='http://invalid.invalid:9', HTTPS_PROXY='http://invalid.invalid:9')
    result = subprocess.run([sys.executable, *(['-O'] if optimized else []), '-Werror', str(SCRIPT),
                             '--timeout-seconds', '240'], env=environment, capture_output=True,
                            text=True, timeout=260, check=False)
    assert result.returncode == 0, result.stdout
    assert result.stderr == ''
    receipt = json.loads(result.stdout)
    assert receipt['accepted'] is True and receipt['assertions'] == list(gate.REQUIRED_ASSERTIONS)
    assert receipt['format_version'] == 'http-assessment-acceptance-v1'
    assert receipt['request_counts'] == {'leak': 35, 'defended': 35, 'crash': 2, 'https-leak': 1,
                                         'absent': 1, 'denied': 1, 'off-pointer': 1, 'duplicate': 1}
    assert receipt['command_exits'] == {'wizard': 0, 'plan': 0, 'http-leak': 0, 'https-defended': 0,
        'https-leak': 1, 'absent': 1, 'denied': 1, 'off-pointer': 1, 'duplicate': 1, 'collision': 1,
        'crash': -signal.SIGKILL, 'recover-json': 1, 'recover-sarif': 1}
    assert receipt['privacy']['required_values_checked'] == 5
    assert receipt['runtime']['producer_identity']['source']['status'] == 'available'
    assert receipt['runtime']['optimization'] == receipt['runtime']['cli_child_optimization'] == int(optimized)
    assert (operator.read_bytes(), profile.read_bytes()) == original
    for value in (str(operator), str(profile), environment['OPERATOR_API_KEY'], environment['OPENAI_API_KEY']):
        assert value not in result.stdout + result.stderr


@pytest.mark.parametrize('arguments', [['--profile', '/private/owned-profile'],
    ['--database', '/private/owned-database'], ['--timeout-seconds', '0'],
    ['--timeout-seconds', 'nan'], ['--timeout-seconds', '601']])
def test_public_gate_invalid_arguments_are_static_and_nonzero(arguments):
    result = subprocess.run([sys.executable, str(SCRIPT), *arguments], capture_output=True, text=True,
                            timeout=5, check=False)
    assert result.returncode == 1 and result.stderr == ''
    assert json.loads(result.stdout)['failure_codes'] == ['invalid_arguments']
    assert '/private/' not in result.stdout


@pytest.mark.parametrize('action', ['socket', 'dns', 'database', 'process', 'server', 'registry',
                                  'default-key', 'profile', 'canary-reference'])
def test_offline_entry_guards_reject_actual_forbidden_operations(tmp_path, action):
    profile, registry = tmp_path / 'profile', tmp_path / 'registry'
    profile.write_text('{}')
    registry.write_text('{}')
    expression = {
        'socket': "__import__('socket').socket()",
        'dns': "__import__('socket').getaddrinfo('localhost', 9)",
        'database': "__import__('sqlite3').connect(':memory:')",
        'process': "__import__('subprocess').run([sys.executable, '-c', 'pass'])",
        'server': "__import__('app')",
        'registry': 'open(sys.argv[3])',
        'default-key': "os.environ.get('OPENAI_API_KEY')",
        'profile': 'open(sys.argv[2])',
        'canary-reference': "os.environ.get('AIS_HTTP_ACCEPTANCE_CANARY')",
    }[action]
    entry = gate.OFFLINE_ENTRY.split("sys.argv = ['scanner_cli'", 1)[0] + (
        '\ntry:\n    ' + expression + '\nexcept RuntimeError:\n    raise SystemExit(0)\nraise SystemExit(9)\n')
    completed = subprocess.run([sys.executable, '-Werror', '-c', entry, 'recover', str(profile), str(registry)],
        cwd=SCRIPT.parents[1], env={'PATH': os.defpath}, capture_output=True, text=True, timeout=5, check=False)
    assert completed.returncode == 0, completed.stderr


def test_plan_never_constructs_http_sessions_or_resolves_dns(tmp_path, monkeypatch):
    import aiohttp
    from click.testing import CliRunner
    import scanner_cli
    from src.core.transport import SafeSession
    tmp_path.chmod(0o700)
    monkeypatch.setenv(gate.CANARY_REFERENCE, 'owned-offline-plan-canary-a13c49768')
    selected = gate.profile(tmp_path, 'offline', 'http://127.0.0.1:8123/custom/infer')
    def forbidden(*args, **kwargs):
        pytest.fail('Offline plan constructed a session or attempted DNS/socket I/O')
    monkeypatch.setattr(aiohttp, 'ClientSession', forbidden)
    monkeypatch.setattr(SafeSession, '__init__', forbidden)
    monkeypatch.setattr(socket, 'socket', forbidden)
    monkeypatch.setattr(socket, 'getaddrinfo', forbidden)
    result = CliRunner().invoke(scanner_cli.cli, ['assess', '--profile', str(selected), '--plan', '--allow-loopback'])
    assert result.exit_code == 0, result.output
    preview = json.loads(result.output)
    assert preview['configuration_status'] == 'ready'
    assert preview['network_readiness_status'] == 'not_checked'


def test_child_output_limit_is_enforced_during_execution_and_child_is_reaped(tmp_path, monkeypatch):
    tmp_path.chmod(0o700)
    monkeypatch.setattr(gate, 'MAX_CAPTURE_BYTES', 256)
    monkeypatch.setattr(gate, 'OFFLINE_ENTRY', "import os,time; os.write(1,b'x'*65536); time.sleep(30)")
    commands = gate.Commands(tmp_path, time.monotonic() + 10, {'PATH': os.defpath})
    with pytest.raises(gate.GateFailure, match='^child_output_limit$'):
        commands.call('flood', [], offline=('plan', tmp_path / 'unused'))
    assert (tmp_path / 'flood.log').stat().st_size == 256
    assert commands.exits['flood'] == -signal.SIGKILL
    assert all(process.poll() is not None for process in commands.processes)
    with pytest.raises(ProcessLookupError):
        os.killpg(commands.processes[0].pid, 0)


@pytest.mark.parametrize('mode', ['-O', '-OO'])
def test_actual_child_inherits_the_parent_optimization_mode(tmp_path, mode):
    program = r'''
import importlib.util, os, pathlib, sys, time
spec=importlib.util.spec_from_file_location('owned_gate',sys.argv[1])
gate=importlib.util.module_from_spec(spec);spec.loader.exec_module(gate)
gate.OFFLINE_ENTRY='import sys; print(sys.flags.optimize)'
commands=gate.Commands(pathlib.Path(sys.argv[2]),time.monotonic()+10,{'PATH':os.defpath})
code,text=commands.call('mode',[],offline=('plan','unused'),expected=0)
assert int(text.strip()) == sys.flags.optimize
print(text.strip())
'''
    completed = subprocess.run([sys.executable, mode, '-Werror', '-c', program, str(SCRIPT), str(tmp_path)],
                               env={'PATH': os.defpath}, capture_output=True, text=True, timeout=15, check=False)
    assert completed.returncode == 0, completed.stderr
    assert completed.stdout.strip() == ('1' if mode == '-O' else '2')


def test_preexisting_process_timer_is_not_discarded_or_modified(monkeypatch, capsys):
    monkeypatch.delitem(sys.modules, 'app', raising=False)
    previous = signal.setitimer(signal.ITIMER_REAL, 30)
    try:
        assert gate.main(['--timeout-seconds', '15']) == 1
        receipt = json.loads(capsys.readouterr().out)
        assert receipt['failure_codes'] == ['preexisting_timer_not_allowed']
        assert signal.getitimer(signal.ITIMER_REAL)[0] > 0
    finally:
        signal.setitimer(signal.ITIMER_REAL, *previous)


@pytest.mark.parametrize('fault', ['assertion', 'privacy', 'cleanup'])
def test_failed_driver_preserves_nonzero_state_and_removes_owned_root(monkeypatch, capsys, fault):
    monkeypatch.delitem(sys.modules, 'app', raising=False)
    owned, marker = [], 'owned-injected-private-value-a13c4976'
    def exercise(directory, deadline, output, private_values):
        owned.append(directory)
        private_values.add(marker)
        if fault == 'privacy':
            gate.private_write(directory / 'public.log', marker)
            output['runtime'] = {'invalid_public_value': marker}
        elif fault == 'assertion':
            raise gate.GateFailure('owned_assertion_failed')
        else:
            gate.private_write(directory / 'cleanup-proof.log', 'owned')
    monkeypatch.setattr(gate, 'execute', exercise)
    if fault == 'cleanup':
        original = gate.tempfile.TemporaryDirectory.cleanup
        def failed(temporary):
            original(temporary)
            raise OSError('Owned injected cleanup failure')
        monkeypatch.setattr(gate.tempfile.TemporaryDirectory, 'cleanup', failed)
    assert gate.main(['--timeout-seconds', '15']) == 1
    captured = capsys.readouterr()
    assert marker not in captured.out + captured.err
    assert json.loads(captured.out)['accepted'] is False
    assert owned and not owned[0].exists()


def test_incomplete_tls_handshake_and_body_cannot_hold_fixture_cleanup(tmp_path):
    tmp_path.chmod(0o700)
    clients = []
    try:
        with gate.targets(tmp_path, 'owned-marker-918273645', 'owned-cookie') as fixture:
            for endpoint in (fixture['http'], fixture['https']):
                port = int(endpoint.rsplit(':', 1)[1])
                client = socket.create_connection(('127.0.0.1', port), timeout=2)
                clients.append(client)
                if endpoint.startswith('http:'):
                    client.sendall(b'POST /custom/absent/infer HTTP/1.1\r\nHost: 127.0.0.1\r\n'
                                   b'Content-Length: 1000\r\n\r\npartial')
            # Exit while both connections remain open and incomplete.
    finally:
        for client in clients:
            client.close()


def test_full_sample_oracle_rejects_wrong_attempts_or_missing_confirmations():
    # An otherwise shaped synthetic document cannot satisfy the accounting oracle.
    document = {'assessment_objective': gate.OBJECTIVE, 'agents': [{'provider': 'http-json', 'model': None,
        'assessment_objective': gate.OBJECTIVE, 'assessment_contract_version': '1.0', 'risk_score': 70,
        'risk_level': 'high', 'check_evidence_schema_version': '3.0', 'checks': [], 'check_evidence': []}],
        'summary': {'overall_risk_score': 70}, 'status': 'completed', 'check_evidence_schema_version': '3.0'}
    with pytest.raises(gate.GateFailure, match='^objective_rule_coverage_mismatch$'):
        gate.report_checks(document, score=70, completed=True, count=35)
