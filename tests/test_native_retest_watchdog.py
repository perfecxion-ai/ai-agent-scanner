"""Exercise the guide's exact watchdog with owned processes and bounded faults."""

import ast
from contextlib import contextmanager
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import signal
import shutil
import site
import stat
import subprocess
import sys
import threading
import time
import textwrap
from types import SimpleNamespace

import psutil
import pytest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / 'scripts/native_retest_watchdog.py'
SPEC = importlib.util.spec_from_file_location('native_retest_watchdog', SCRIPT)
watchdog = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(watchdog)


def guide_run(tmp_path, library=psutil):
    """Load only functions from our checked-in guide, never a supplied archive."""
    guide = (ROOT / 'docs/http-assessment-retest.md').read_text()
    program = guide.split("<<'PY'\n", 1)[1].split('\nPY\n', 1)[0]
    tree = ast.parse(program)
    functions = ast.Module(body=[node for node in tree.body if isinstance(node, ast.FunctionDef)
                                and node.name in ('run', 'write', 'record')], type_ignores=[])
    namespace = dict(os=os, Path=Path, json=json, signal=signal, subprocess=subprocess,
                     threading=threading, time=time, checkout=ROOT, captures=tmp_path,
                     environment={'PATH': os.defpath,
                         'SCAN_EVIDENCE_PROFILES_FILE': '/tmp/aiscan-operator-registry-must-not-exist.json'},
                     deadline=time.monotonic() + 10, interrupted=threading.Event(),
                     process_library=library, OwnedChildren=watchdog.OwnedChildren,
                     failures=[], exits={})
    exec(compile(functions, str(ROOT / 'docs/http-assessment-retest.md'), 'exec'), namespace)
    return namespace


@contextmanager
def owned_child(program):
    process = subprocess.Popen([sys.executable, '-c', program], stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        env={'PATH': os.defpath,
             'SCAN_EVIDENCE_PROFILES_FILE': '/tmp/aiscan-operator-registry-must-not-exist.json'})
    try:
        yield process
    finally:
        if process.poll() is None:
            process.kill()
        process.wait(timeout=5)


def watch_real_child(process):
    # The real child is directly owned by this test so wait can genuinely reap
    # it. Restrict enumeration to that child, excluding any pytest plugin work.
    snapshot = psutil.Process(process.pid)
    parent_pid = os.getpid()
    def lookup(pid):
        if pid == parent_pid:
            return SimpleNamespace(children=lambda **_: [snapshot])
        return psutil.Process(pid)
    library = SimpleNamespace(Process=lookup, NoSuchProcess=psutil.NoSuchProcess,
        ZombieProcess=psutil.ZombieProcess, TimeoutExpired=psutil.TimeoutExpired,
        STATUS_ZOMBIE=psutil.STATUS_ZOMBIE)
    owner = watchdog.OwnedChildren(library)
    owner.observe(SimpleNamespace(pid=parent_pid, poll=lambda: None))
    return owner


def test_real_delayed_natural_exit_is_reaped_without_kill():
    with owned_child('import time; time.sleep(0.25)') as process:
        owner = watch_real_child(process)
        result = owner.cleanup()
        assert result['failure_codes'] == []
        assert result['processes'][0]['state'] == 'gone'
        assert result['processes'][0]['forced_kill'] is False
        assert 0.1 < result['cleanup_elapsed_seconds'] < 1
        with pytest.raises(ChildProcessError):
            os.waitpid(process.pid, os.WNOHANG)


def test_real_stubborn_child_requires_kill_and_stays_failed():
    with owned_child('import time; time.sleep(30)') as process:
        owner = watch_real_child(process)
        result = owner.cleanup()
        assert result['failure_codes'] == ['surviving_owned_child']
        assert result['processes'][0]['forced_kill'] is True
        assert result['processes'][0]['state'] == 'gone'
        assert 0.9 <= result['natural_elapsed_seconds'] < 1.3
        assert result['cleanup_elapsed_seconds'] < 5
        with pytest.raises(ChildProcessError):
            os.waitpid(process.pid, os.WNOHANG)


def test_real_zombie_is_genuinely_reaped_without_kill():
    if os.name != 'posix':
        pytest.skip('Native retest requires POSIX')
    with owned_child('pass') as process:
        owner = watch_real_child(process)
        stop = time.monotonic() + 3
        while psutil.Process(process.pid).status() != psutil.STATUS_ZOMBIE:
            assert time.monotonic() < stop
            time.sleep(0.01)
        result = owner.cleanup()
        assert result['failure_codes'] == []
        assert result['processes'][0]['state'] == 'gone'
        assert any(event['state'] == 'zombie' for event in result['processes'][0]['events'])
        with pytest.raises(ChildProcessError):
            os.waitpid(process.pid, os.WNOHANG)


class Clock:
    def __init__(self):
        self.now = 0

    def __call__(self):
        return self.now

    def sleep(self, seconds):
        self.now += seconds


def fake_owner(*, fault=None, state='running', reused=False, count=1):
    clock, killed = Clock(), []
    class Process:
        def __init__(self, pid, snapshot=False):
            self.pid, self.snapshot = pid, snapshot
        def children(self, **kwargs):
            if fault == 'children':
                raise psutil.AccessDenied(self.pid, msg='/private/path secret argv env')
            return [Process(pid, True) for pid in range(101, 101 + count)]
        def create_time(self):
            if fault == 'create_time':
                raise psutil.AccessDenied(self.pid, msg='/private/path secret argv env')
            if reused and not self.snapshot:
                return 2
            return 1
        def status(self):
            if fault == 'status':
                raise psutil.AccessDenied(self.pid, msg='/private/path secret argv env')
            return state
        def wait(self, timeout):
            assert timeout == 0
            if fault == 'wait':
                raise OSError('/private/path secret argv env')
            raise psutil.TimeoutExpired(timeout)
        def kill(self):
            killed.append(self.pid)
            if fault == 'kill':
                raise psutil.AccessDenied(self.pid, msg='/private/path secret argv env')
    library = SimpleNamespace(Process=Process, NoSuchProcess=psutil.NoSuchProcess,
        ZombieProcess=psutil.ZombieProcess, TimeoutExpired=psutil.TimeoutExpired,
        STATUS_ZOMBIE=psutil.STATUS_ZOMBIE)
    owner = watchdog.OwnedChildren(library, clock=clock, sleep=clock.sleep)
    owner.observe(SimpleNamespace(pid=100, poll=lambda: None))
    return owner, clock, killed, Process


def test_enumeration_to_current_pid_reuse_never_signals_replacement():
    owner, clock, killed, _ = fake_owner(reused=True)
    result = owner.cleanup()
    assert result['failure_codes'] == ['owned_child_pid_reused']
    assert killed == []
    assert result['processes'][0]['create_time'] == 1
    assert result['processes'][0]['state'] == 'pid_reused'
    assert clock.now == 0


def test_pid_reuse_after_natural_window_never_signals_replacement():
    owner, clock, killed, process = fake_owner()
    original = process.create_time
    def changed_identity(self):
        if clock.now >= 1 and not self.snapshot:
            return 2
        return original(self)
    process.create_time = changed_identity
    result = owner.cleanup()
    assert result['failure_codes'] == ['owned_child_pid_reused']
    assert killed == []
    assert result['processes'][0]['state'] == 'pid_reused'
    assert result['natural_elapsed_seconds'] == 1
    assert result['cleanup_elapsed_seconds'] == 1


@pytest.mark.parametrize('fault', ['children', 'create_time', 'status', 'wait', 'kill'])
def test_unknown_probes_and_cleanup_errors_fail_closed_and_keep_diagnostics_private(fault):
    owner, _, killed, _ = fake_owner(fault=fault)
    result = owner.cleanup()
    assert result['failure_codes']
    encoded = json.dumps(result)
    for private in ('/private/path', 'secret', 'argv', 'env'):
        assert private not in encoded
    if fault in ('children', 'create_time', 'status'):
        assert killed == []
        assert 'owned_child_probe_failed' in result['failure_codes']
    else:
        assert 'owned_child_cleanup_failed' in result['failure_codes']
    assert result['cleanup_elapsed_seconds'] <= 5.000001


def test_unreaped_zombie_uses_one_total_budget_and_is_never_killed():
    owner, clock, killed, _ = fake_owner(state='zombie')
    result = owner.cleanup()
    assert result['failure_codes'] == ['unreaped_owned_child']
    assert killed == []
    assert clock.now == 5
    assert result['natural_elapsed_seconds'] == 1


def test_shared_deadline_is_checked_between_process_probes():
    owner, clock, killed, process = fake_owner(count=5)
    original = process.status
    def slow_status(self):
        clock.now += 0.4
        return original(self)
    process.status = slow_status
    began = clock.now
    result = owner.cleanup()
    assert result['cleanup_elapsed_seconds'] <= 5.4
    assert clock.now - began <= 5.4
    assert 'unreaped_owned_child' in result['failure_codes']
    assert len(killed) <= 5


def test_no_signal_or_wait_starts_after_probe_consumes_total_budget():
    owner, clock, killed, process = fake_owner()
    original = process.status
    waits = []
    def slow_status(self):
        clock.now += 5
        return original(self)
    def wait(self, timeout):
        waits.append(clock.now)
        raise AssertionError('A wait started after the shared deadline')
    process.status, process.wait = slow_status, wait
    result = owner.cleanup()
    assert killed == waits == []
    assert result['failure_codes'] == ['unreaped_owned_child']


def test_tracking_and_diagnostic_limits_are_explicit_failures(monkeypatch):
    monkeypatch.setattr(watchdog, 'MAX_PROCESSES', 2)
    monkeypatch.setattr(watchdog, 'MAX_EVENTS', 2)
    monkeypatch.setattr(watchdog, 'MAX_PROBE_ERRORS', 2)
    owner, _, _, _ = fake_owner(count=4, reused=True)
    result = owner.cleanup()
    assert len(result['processes']) == 2
    assert sum(len(entry['events']) for entry in result['processes']) <= 2
    assert 'owned_child_tracking_limit' in result['failure_codes']
    assert 'owned_child_diagnostic_limit' in result['failure_codes']
    assert len(json.dumps(result).encode()) < watchdog.MAX_DIAGNOSTIC_BYTES


def test_diagnostic_byte_overflow_returns_only_a_static_failure(monkeypatch):
    owner, _, _, _ = fake_owner(reused=True)
    monkeypatch.setattr(watchdog, 'MAX_DIAGNOSTIC_BYTES', 256)
    result = owner.cleanup()
    assert result['diagnostic_overflow'] is True
    assert 'owned_child_diagnostic_limit' in result['failure_codes']
    assert len(json.dumps(result).encode()) <= 256


def test_exact_guide_run_keeps_nonzero_exit_and_safe_cleanup_receipt(tmp_path):
    state = guide_run(tmp_path)
    assert state['run']('nonzero', [sys.executable, '-c', 'raise SystemExit(7)']) == 7
    assert state['failures'] == ['nonzero_nonzero_exit']
    assert (tmp_path / 'nonzero.exit').read_text() == '7\n'
    cleanup = json.loads((tmp_path / 'nonzero.process-cleanup.json').read_text())
    assert cleanup['failure_codes'] == []
    assert cleanup['tracking_available'] is True


def test_exact_guide_run_preserves_timeout_failure(tmp_path):
    state = guide_run(tmp_path)
    assert state['run']('timeout', [sys.executable, '-c', 'import time; time.sleep(30)'], seconds=0.1) != 0
    assert 'timeout_outer_timeout_or_output_limit' in state['failures']
    assert 'timeout_nonzero_exit' in state['failures']
    assert (tmp_path / 'timeout.process-cleanup.json').exists()


def test_exact_guide_run_preserves_output_limit_failure(tmp_path):
    state = guide_run(tmp_path)
    program = "import sys,time; sys.stdout.write('x' * (9 * 1024 * 1024)); sys.stdout.flush(); time.sleep(30)"
    assert state['run']('overflow', [sys.executable, '-c', program]) != 0
    assert 'overflow_outer_timeout_or_output_limit' in state['failures']
    assert 'overflow_output_limit' in state['failures']
    assert (tmp_path / 'overflow.log').stat().st_size == 8 * 1024 * 1024


def test_exact_guide_run_keeps_original_main_error_after_cleanup(tmp_path, monkeypatch):
    state = guide_run(tmp_path)
    def failed_probe(*args):
        raise RuntimeError('owned injected main error')
    monkeypatch.setattr(watchdog.OwnedChildren, 'observe', failed_probe)
    with pytest.raises(RuntimeError, match='owned injected main error'):
        state['run']('error', [sys.executable, '-c', 'import time; time.sleep(30)'])
    assert 'error_outer_timeout_or_output_limit' in state['failures']
    assert state['exits']['error'] != 0
    assert (tmp_path / 'error.process-cleanup.json').exists()


def test_guide_executes_the_tested_helper_and_keeps_work_deadlines():
    text = (ROOT / 'docs/http-assessment-retest.md').read_text()
    assert "runpy.run_path(str(checkout / 'scripts' / 'native_retest_watchdog.py'))['OwnedChildren']" in text
    assert 'deadline = time.monotonic() + 1800' in text
    assert 'stop = min(deadline, time.monotonic() + seconds)' in text
    assert 'descendants.observe(process)' in text
    assert 'cleanup = descendants.cleanup()' in text
    assert 'surviving_owned_child' not in text.split("<<'PY'\n", 1)[1].split('\nPY\n', 1)[0]


@pytest.mark.parametrize('fault', [None, 'dependencies', 'source-status', 'helper-pin',
    'baseline-symlink', 'baseline-oversize', 'baseline-fifo'])
def test_focused_mode_keeps_exact_capture_contract_and_omits_full_workflow(tmp_path, fault):
    """Execute only our guide's orchestration using synthetic command captures."""
    state = guide_run(tmp_path)
    source_identity = {'source': {'sha256': '70299904cb69dafdec45cfe906ff826e095b1df5dab711a54453f3ed28339e48'}}
    baseline = tmp_path / 'baseline'
    baseline.mkdir()
    dependencies = [{'name': 'pytest', 'version': '9.1.1'}]
    for name, value in [('runtime.json', {}), ('dependencies.json', dependencies), ('source-build.json', source_identity)]:
        (baseline / name).write_text(json.dumps(value))
    (baseline / 'revision.log').write_text('5a9ab356d2f68d1ff4a988dd9d17a26788a9141d\n')
    if fault in ('baseline-symlink', 'baseline-oversize', 'baseline-fifo'):
        original = baseline / 'runtime.json'
        original.unlink()
        if fault == 'baseline-symlink':
            target = tmp_path / 'private-sentinel'
            target.write_text('private sentinel must not be read')
            original.symlink_to(target)
        elif fault == 'baseline-oversize':
            original.write_text('x' * 4097)
        else:
            os.mkfifo(original)
    work = tmp_path / 'work'
    work.mkdir()
    revision = '1' * 40
    def fake_run(label, command, *, structured=False, **kwargs):
        assert label in {'source-venv', 'source-install', 'revision', 'runtime',
                         'dependencies', 'source-build', 'focused-tests', 'source-status'}
        if label == 'focused-tests':
            assert 'tests/test_native_retest_watchdog.py' in command
            assert sum(item.startswith('tests/') for item in command) == 27
        values = {'revision': revision + '\n', 'runtime': '{}', 'dependencies':
                  '[{"name":"changed","version":"1"}]' if fault == 'dependencies' else json.dumps(dependencies),
                  'source-build': json.dumps(source_identity),
                  'focused-tests': '843 passed, 2 deselected in 1.49s\n'}
        if not (label == 'source-status' and fault == 'source-status'):
            (tmp_path / (label + ('.json' if structured else '.log'))).write_text(values.get(label, ''))
        (tmp_path / (label + '.stderr')).write_text('')
        (tmp_path / (label + '.exit')).write_text('0\n')
        (tmp_path / (label + '.process-cleanup.json')).write_text('{"failure_codes":[]}')
        state['exits'][label] = 0
        return 0
    state.update(ast=ast, hashlib=hashlib, re=__import__('re'), shutil=shutil,
                 site=site, stat=stat, sys=sys, textwrap=textwrap, work=work,
                 work_identity=(work.stat().st_dev, work.stat().st_ino),
                 mode='focused-cleanup', baseline=baseline, revision=revision, run=fake_run,
                 loaded_helper_sha=hashlib.sha256(SCRIPT.read_bytes()).hexdigest(),
                 expected_helper='0' * 64 if fault == 'helper-pin' else hashlib.sha256(SCRIPT.read_bytes()).hexdigest())
    text = (ROOT / 'docs/http-assessment-retest.md').read_text()
    program = text.split("<<'PY'\n", 1)[1].split('\nPY\n', 1)[0]
    tree = ast.parse(program)
    orchestration = next(node for node in tree.body if isinstance(node, ast.Try))
    exec(compile(ast.Module(body=[orchestration], type_ignores=[]), '<owned-guide-orchestration>', 'exec'), state)
    result = json.loads((tmp_path / 'wrapper-result.json').read_text())
    assert result['mode'] == 'focused-cleanup'
    accepted = fault in (None, 'dependencies')
    assert result['accepted'] is accepted
    assert (tmp_path / 'driver.exit').read_text() == ('0\n' if accepted else '1\n')
    assert not work.exists()
    if fault not in ('source-status', 'baseline-symlink', 'baseline-oversize', 'baseline-fifo'):
        contract = json.loads((tmp_path / 'capture-contract.json').read_text())
        assert contract['mode'] == 'focused-cleanup'
        assert contract['required_before_finalization']
        assert all((tmp_path / name).is_file() for name in contract['required_before_finalization'])
        assert all((tmp_path / name).is_file() for name in contract['required_after_finalization'])
        comparison = json.loads((tmp_path / 'baseline-comparison.json').read_text())
        assert comparison['dependencies']['identical'] is (fault != 'dependencies')
        assert comparison['qualifications'] == (['dependency_inventory_changed'] if fault == 'dependencies' else [])
