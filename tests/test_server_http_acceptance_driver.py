"""Failure boundaries for the owned real-process HTTP acceptance gate."""

import importlib.util
from contextlib import contextmanager
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
from types import SimpleNamespace

import pytest


SCRIPT = Path(__file__).resolve().parents[1] / 'scripts' / 'acceptance-server-http.py'


@pytest.fixture
def driver():
    spec = importlib.util.spec_from_file_location('owned_server_http_acceptance', SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def child(tmp_path, label):
    ready = tmp_path / (label + '.ready')
    process = subprocess.Popen([sys.executable, '-c',
        'import signal,sys,time; signal.signal(signal.SIGTERM, signal.SIG_IGN); '
        'open(sys.argv[1], "x").close(); time.sleep(20)', str(ready)],
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        env={'PATH': os.defpath, 'HOME': str(tmp_path),
             'SCAN_EVIDENCE_PROFILES_FILE': str(tmp_path / 'absent-operator-registry.json')})
    end = time.monotonic() + 3
    while not ready.exists() and time.monotonic() < end:
        assert process.poll() is None
        time.sleep(0.01)
    assert ready.is_file()
    return process


def server(driver, tmp_path, process, label):
    result = driver.Server(tmp_path, {}, tmp_path / 'unused.sock', label,
                           time.monotonic() + 10, set(), lambda *_: None)
    result.process = process
    return result


def test_forced_cleanup_is_reaped_and_repeat_stop_retains_failure(driver, tmp_path):
    process = child(tmp_path, 'forced')
    owned = server(driver, tmp_path, process, 'forced')
    try:
        with pytest.raises(driver.GateFailure):
            owned.stop(deadline=time.monotonic() + 0.25)
        assert owned.forced and process.returncode == -signal.SIGKILL
        assert process.poll() == -signal.SIGKILL
        first = list(owned.stop_failures)
        started = time.monotonic()
        with pytest.raises(driver.GateFailure):
            owned.stop(deadline=time.monotonic() + 30)
        assert time.monotonic() - started < 0.1
        assert owned.stop_failures == first
    finally:
        if process.poll() is None:
            process.kill()
        process.wait(timeout=3)
        process.stdout.close()


def test_multiple_processes_share_one_cleanup_deadline(driver, tmp_path):
    processes = [child(tmp_path, name) for name in ('first', 'second')]
    resources = driver.Resources(time.monotonic() + 30)
    resources.cleanup_deadline = time.monotonic() + 0.4
    resources.servers = [server(driver, tmp_path, process, str(index))
                         for index, process in enumerate(processes)]
    try:
        original = resources.cleanup_deadline
        started = time.monotonic()
        resources.cleanup()
        assert time.monotonic() - started < 0.8
        assert resources.cleanup_deadline == original
        assert resources.failures
        assert all(process.poll() == -signal.SIGKILL for process in processes)
        resources.cleanup()
        assert resources.cleanup_deadline == original
    finally:
        for process in processes:
            if process.poll() is None:
                process.kill()
            process.wait(timeout=3)
            process.stdout.close()


def test_failed_server_cleanup_does_not_skip_owned_listener(driver):
    class FailedServer:
        stopped = False
        stop_failures = ['synthetic_stop_failure']
        process = None

        def stop(self, *, deadline):
            raise OSError('synthetic private diagnostic')

    listener = socket.socket()
    resources = driver.Resources(time.monotonic() + 30)
    resources.cleanup_deadline = time.monotonic() + 0.2
    resources.servers.append(FailedServer())
    resources.listeners.append(listener)
    resources.cleanup()
    assert listener.fileno() == -1
    assert resources.failures == ['synthetic_stop_failure']


def test_descendant_probe_failure_still_reaps_owned_master(driver, tmp_path, monkeypatch):
    import psutil
    process = child(tmp_path, 'probe-failure')
    owned = server(driver, tmp_path, process, 'probe-failure')

    class Denied:
        def children(self, recursive):
            raise psutil.AccessDenied(process.pid)

    monkeypatch.setattr(psutil, 'Process', lambda _pid: Denied())
    try:
        with pytest.raises(driver.GateFailure):
            owned.stop(deadline=time.monotonic() + 0.25)
        assert process.poll() == -signal.SIGKILL
        assert 'owned_server_descendant_probe_failed' in owned.stop_failures
        assert owned.cleanup_record['master_exit'] == -signal.SIGKILL
    finally:
        if process.poll() is None:
            process.kill()
        process.wait(timeout=3)
        process.stdout.close()


def test_no_new_child_probe_or_signal_after_identity_probe_exhausts_deadline(driver, tmp_path, monkeypatch):
    import psutil
    clock, actions = [100.0], []

    class Process:
        pid = 880001
        returncode = None
        stdout = None

        def poll(self):
            return self.returncode

        def terminate(self):
            actions.append('terminate-master')

        def wait(self, timeout):
            self.returncode = 0
            return 0

    class Observed:
        pid = 880002

        def create_time(self):
            return 1.0

    class Master:
        def children(self, recursive):
            return [Observed()]

    class Fresh:
        def create_time(self):
            actions.append('creation-time')
            clock[0] = 200.0
            return 1.0

        def status(self):
            actions.append('status-after-deadline')
            return 'running'

        def kill(self):
            actions.append('kill-after-deadline')

    monkeypatch.setattr(driver, 'time', SimpleNamespace(monotonic=lambda: clock[0], sleep=lambda _: None))
    monkeypatch.setattr(psutil, 'Process', lambda pid: Master() if pid == Process.pid else Fresh())
    owned = server(driver, tmp_path, Process(), 'deadline')
    with pytest.raises(driver.GateFailure):
        owned.stop(deadline=150.0)
    assert actions == ['terminate-master', 'creation-time']
    assert 'owned_server_cleanup_deadline' in owned.stop_failures
    assert 'owned_server_descendant_unreaped' in owned.stop_failures


def test_early_setup_failure_is_nonzero_private_and_cleans_listener(tmp_path):
    source = r'''
import importlib.util,json,pathlib,socket,sys
spec = importlib.util.spec_from_file_location('owned_gate', sys.argv[1])
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
owned = {}
def fail(directory, deadline, output, private_values, resources):
    owned['directory'] = directory
    owned['listener'] = socket.socket()
    resources.listeners.append(owned['listener'])
    raise RuntimeError('synthetic-private-do-not-publish')
module.execute = fail
code = module.main(['--timeout-seconds', '30'])
assert code == 1
assert owned['listener'].fileno() == -1
assert not owned['directory'].exists()
raise SystemExit(code)
'''
    result = subprocess.run([sys.executable, '-Werror', '-c', source, str(SCRIPT)],
        capture_output=True, timeout=8, check=False,
        env={'PATH': os.defpath, 'HOME': str(tmp_path),
             'SCAN_EVIDENCE_PROFILES_FILE': str(tmp_path / 'absent-operator-registry.json')})
    assert result.returncode == 1 and result.stderr == b''
    document = json.loads(result.stdout)
    assert document['accepted'] is False
    assert document['failure_codes'] == ['unexpected_driver_failure']
    assert document['failure_class'] == 'RuntimeError'
    assert b'synthetic-private-do-not-publish' not in result.stdout


@pytest.mark.parametrize('precondition', ['timer', 'cached_app'])
def test_refusal_preserves_preexisting_timer_and_signal_handlers(tmp_path, precondition):
    source = r'''
import importlib.util,signal,sys,types
spec = importlib.util.spec_from_file_location('owned_gate', sys.argv[1])
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
def original(number, frame):
    pass
signal.signal(signal.SIGTERM, original)
signal.signal(signal.SIGINT, original)
if sys.argv[2] == 'timer':
    signal.setitimer(signal.ITIMER_REAL, 60)
else:
    sys.modules['app'] = types.SimpleNamespace()
code = module.main(['--timeout-seconds', '30'])
assert code == 1
assert signal.getsignal(signal.SIGTERM) is original
assert signal.getsignal(signal.SIGINT) is original
if sys.argv[2] == 'timer':
    assert signal.getitimer(signal.ITIMER_REAL)[0] > 59
    signal.setitimer(signal.ITIMER_REAL, 0)
raise SystemExit(code)
'''
    result = subprocess.run([sys.executable, '-Werror', '-c', source, str(SCRIPT), precondition],
        capture_output=True, timeout=8, check=False,
        env={'PATH': os.defpath, 'HOME': str(tmp_path),
             'SCAN_EVIDENCE_PROFILES_FILE': str(tmp_path / 'absent-operator-registry.json')})
    assert result.returncode == 1 and result.stderr == b''
    assert json.loads(result.stdout)['accepted'] is False


def test_cleanup_only_failure_cannot_claim_successful_process_reaping(tmp_path):
    source = r'''
import importlib.util,sys
spec = importlib.util.spec_from_file_location('owned_gate', sys.argv[1])
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
def incomplete(directory, deadline, output, private_values, resources):
    output['assertions'].extend(module.REQUIRED_ASSERTIONS[:-1])
    resources.failures.append('synthetic_cleanup_only')
module.execute = incomplete
raise SystemExit(module.main(['--timeout-seconds', '30']))
'''
    result = subprocess.run([sys.executable, '-Werror', '-c', source, str(SCRIPT)],
        capture_output=True, timeout=8, check=False,
        env={'PATH': os.defpath, 'HOME': str(tmp_path),
             'SCAN_EVIDENCE_PROFILES_FILE': str(tmp_path / 'absent-operator-registry.json')})
    assert result.returncode == 1 and result.stderr == b''
    document = json.loads(result.stdout)
    assert document['accepted'] is False
    assert document['failure_codes'] == ['owned_server_cleanup_failed']
    assert 'all_owned_processes_reaped_and_fixtures_removed' not in document['assertions']


def test_failed_unix_connection_closes_its_owned_socket(driver, tmp_path):
    connection = driver.UnixHTTPConnection('owned-server-http.invalid', socket_path=tmp_path / 'absent.sock', timeout=0.1)
    with pytest.raises(OSError):
        connection.connect()
    assert connection.sock is None


def test_unix_http_success_uses_no_dns_and_closes_client_server_sockets(driver, monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError('DNS must not be used for the owned Unix HTTP listener')

    monkeypatch.setattr(socket, 'getaddrinfo', forbidden)
    with tempfile.TemporaryDirectory(prefix='ais-uds-', dir='/tmp') as raw:
        path = Path(raw) / 's'
        accepted = []
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
            listener.bind(str(path))
            listener.listen(1)
            listener.settimeout(1)

            def response():
                with listener.accept()[0] as connection:
                    connection.settimeout(1)
                    request = b''
                    while b'\r\n\r\n' not in request and len(request) <= 4096:
                        request += connection.recv(4096)
                    accepted.append(request)
                    body = b'{"success": true}'
                    connection.sendall(b'HTTP/1.0 200 OK\r\nContent-Type: application/json\r\nContent-Length: '
                                       + str(len(body)).encode() + b'\r\n\r\n' + body)

            worker = threading.Thread(target=response, daemon=True)
            worker.start()
            server = driver.Server(Path(raw), {}, path, 'unit', time.monotonic() + 3, set(), lambda *_: None)
            try:
                status, value = server.request('/probe', tenant=None)
                assert status == 200 and value == {'success': True}
            finally:
                worker.join(timeout=1)
            assert not worker.is_alive()
            assert accepted and accepted[0].startswith(b'GET /probe HTTP/1.1')


def test_python_warning_receipt_excludes_messages_and_private_paths(driver):
    private = 'synthetic-private-value-231ebc'
    raw = ('Traceback (most recent call last):\n'
           '  File "/private/operator/' + private + '/arbiter.py", line 205, in run\n'
           'ResourceWarning: unclosed <socket.socket ' + private + '>\n').encode()
    observed = driver.python_warnings(raw, 'initial')
    assert observed == [{'phase': 'initial', 'kind': 'ResourceWarning',
                         'location': {'module': 'arbiter.py', 'line': 205}, 'categories': ['socket.socket']}]
    assert private not in json.dumps(observed) and '/private/' not in json.dumps(observed)


@contextmanager
def tiny_worker(driver, mode):
    with tempfile.TemporaryDirectory(prefix='ais-worker-', dir='/tmp') as raw:
        directory = Path(raw)
        application = directory / 'fixture_wsgi.py'
        application.write_text('def application(environ, start_response):\n'
            '    body = b\'{"status":"ready"}\'\n'
            '    start_response("200 OK", [("Content-Type","application/json"), '
            '("Content-Length",str(len(body)))])\n'
            '    return [body]\n')
        config = directory / 'owned_config.py'
        config.write_text('import os,time\numask=0o077\n'
            'def worker_exit(server, worker):\n'
            '    if os.getpid() != worker.pid: return\n'
            '    for listener in worker.sockets: getattr(listener,"sock",listener).close()\n'
            + ('    raise RuntimeError("Owned synthetic worker cleanup failure")\n' if mode == 'exception' else '')
            + ('    time.sleep(30)\n' if mode == 'hang-before-ack' else '')
            + '    worker.log.info("Scan worker cleanup ok pid=%s",os.getpid())\n'
            + ('    time.sleep(30)\n' if mode == 'hang-after-ack' else ''))
        application.chmod(0o600)
        config.chmod(0o600)
        environment = {'PATH': os.defpath, 'HOME': str(directory), 'TMPDIR': str(directory),
            'PYTHONUTF8': '1', 'PYTHONNOUSERSITE': '1',
            'SCAN_EVIDENCE_PROFILES_FILE': str(directory / 'absent-operator-registry.json')}
        owned = driver.Server(directory, environment, directory / 'api.sock', mode,
                              time.monotonic() + 20, set(), lambda *_: None)
        owned.graceful_timeout_seconds = 1
        owned.stream = owned.log_path.open('xb')
        owned.process = subprocess.Popen([sys.executable, '-Werror', '-m', 'gunicorn',
            '--config', str(config), '--workers', '1', '--bind', 'unix:' + str(owned.socket_path),
            '--timeout', '10', '--graceful-timeout', '1', '--worker-tmp-dir', str(directory),
            'fixture_wsgi:application'], cwd=directory, env=environment,
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            start_new_session=True, umask=0o077)

        def drain():
            total = 0
            try:
                while chunk := os.read(owned.process.stdout.fileno(), 65536):
                    if total + len(chunk) > driver.MAX_CAPTURE_BYTES:
                        owned.capture_overflow.set()
                        break
                    owned.stream.write(chunk)
                    total += len(chunk)
            except (OSError, ValueError):
                owned.capture_failure.set()

        owned.reader = threading.Thread(target=drain, daemon=True)
        owned.reader.start()
        try:
            owned.ready()
            owned.observe_worker()
            yield owned
        finally:
            if not owned.stopped:
                try:
                    owned.stop(deadline=time.monotonic() + 4)
                except driver.GateFailure:
                    pass
            if owned.process.poll() is None:
                owned.process.kill()
            owned.process.wait(timeout=3)
            owned.reader.join(timeout=2)
            owned.process.stdout.close()
            owned.stream.close()


def test_actual_worker_hook_exception_fails_when_master_exits_zero(driver):
    with tiny_worker(driver, 'exception') as owned:
        with pytest.raises(driver.GateFailure):
            owned.stop(deadline=time.monotonic() + 4)
        assert owned.process.returncode == 0
        assert 'critical_worker_lifecycle_error' in owned.stop_failures
        assert 'worker_cleanup_ack_missing_duplicate_or_unexpected' in owned.stop_failures
        assert owned.cleanup_record['worker_lifecycle']['cleanup_ack_count'] == 0


@pytest.mark.parametrize('mode', ['hang-before-ack', 'hang-after-ack'])
def test_actual_master_graceful_timeout_cannot_pass_even_when_master_exits_zero(driver, mode):
    with tiny_worker(driver, mode) as owned:
        with pytest.raises(driver.GateFailure):
            owned.stop(deadline=time.monotonic() + 4)
        assert owned.process.returncode == 0
        assert 'worker_graceful_shutdown_boundary_unverified' in owned.stop_failures
        if mode == 'hang-before-ack':
            assert 'worker_cleanup_ack_missing_duplicate_or_unexpected' in owned.stop_failures


def test_actual_one_fresh_owned_worker_sigkill_is_the_only_allowed_exception(driver):
    with tiny_worker(driver, 'normal') as owned:
        crash = owned.crash_worker()
        assert crash['fresh_identity_verified'] and crash['old_identity_gone'] and crash['replacement_observed']
        with pytest.raises(driver.GateFailure, match='duplicate_intentional_worker_crash'):
            owned.crash_worker()
        assert owned.stop(deadline=time.monotonic() + 4) == 0
        lifecycle = owned.cleanup_record['worker_lifecycle']
        assert lifecycle['observed_worker_count'] == 2
        assert lifecycle['cleanup_ack_count'] == lifecycle['intentional_crash_count'] == 1
        assert lifecycle['failure_codes'] == []


def test_caller_pause_after_sigterm_cannot_hide_master_graceful_kill(driver):
    with tiny_worker(driver, 'hang-after-ack') as owned:
        original = owned.process.terminate

        def delayed():
            original()
            time.sleep(1.25)

        owned.process.terminate = delayed
        with pytest.raises(driver.GateFailure):
            owned.stop(deadline=time.monotonic() + 4)
        assert owned.process.returncode == 0
        assert owned.master_shutdown_seconds >= 1.25
        assert 'worker_graceful_shutdown_boundary_unverified' in owned.stop_failures


def test_repeated_sigkill_log_cannot_reuse_the_intentional_crash_exception(driver):
    raw = b'\n'.join([
        b'[owned] [101] [INFO] Booting worker with pid: 101',
        b'[owned] [100] [ERROR] Worker (pid:101) was sent SIGKILL! Perhaps out of memory?',
        b'[owned] [100] [ERROR] Worker (pid:101) was sent SIGKILL! Perhaps out of memory?',
        b'[owned] [102] [INFO] Booting worker with pid: 102',
        b'[owned] [102] [INFO] Scan worker cleanup ok pid=102',
        b'[owned] [100] [INFO] Shutting down: Master'])
    intentional = {'pid': 101, 'create_time': 1.0, 'signal_sent': 'SIGKILL', 'fresh_identity_verified': True}
    verdict = driver.worker_lifecycle(raw, 100, {101: 1.0, 102: 2.0}, intentional)
    assert 'worker_signal_does_not_match_one_intentional_crash' in verdict['failure_codes']
