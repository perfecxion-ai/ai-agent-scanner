"""Forked worker cleanup closes child descriptors without touching the master."""

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

import pytest


ROOT = Path(__file__).resolve().parents[1]
pytestmark = pytest.mark.skipif(os.name != 'posix', reason='Gunicorn worker lifecycle requires POSIX')


PROGRAM = r'''
import builtins,json,os,runpy,signal,socket,sys
from types import SimpleNamespace
config = runpy.run_path(sys.argv[1])
kind,stop_failure,close_failure,master = sys.argv[3:]
events,acknowledgements = [],[]
class ObservedSocket(socket.socket):
    def close(self):
        events.append('close')
        super().close()
        if close_failure == 'yes' and len(events) == 2:
            raise OSError('owned-private-listener-failure')
class Wrapper:
    def __init__(self,raw,path):
        self.sock,self.path,self.called = raw,path,False
    def close(self):
        self.called = True
        if self.path is not None:
            os.unlink(self.path)
        self.sock.close()
listeners = []
for number in range(2):
    raw = ObservedSocket(socket.AF_UNIX if kind == 'unix' else socket.AF_INET)
    raw.settimeout(2)
    path = os.path.join(sys.argv[2],str(number)+'.sock') if kind == 'unix' else None
    raw.bind(path if path is not None else ('127.0.0.1',0))
    raw.listen(2)
    listeners.append(Wrapper(raw,path))
def usable():
    for listener in listeners:
        address = listener.path if listener.path is not None else listener.sock.getsockname()
        if listener.path is not None:
            assert os.path.exists(listener.path)
        with socket.socket(listener.sock.family) as client:
            client.settimeout(2)
            client.connect(address)
            connection,_ = listener.sock.accept()
            connection.close()
def stop():
    events.append('stop')
    if stop_failure == 'yes':
        raise RuntimeError('owned-private-dispatcher-failure')
def invoke(pid):
    def info(message,*args):
        events.append('ack')
        acknowledgements.append(message % args)
    worker = SimpleNamespace(pid=pid,sockets=listeners,log=SimpleNamespace(info=info))
    error = None
    try:
        config['worker_exit'](None,worker)
    except RuntimeError as caught:
        error = str(caught)
    return {'closed':[listener.sock.fileno()==-1 for listener in listeners],
            'wrapper_called':any(listener.called for listener in listeners),
            'events':events,'error':error,'acknowledgements':acknowledgements}
child = None
try:
    if master == 'yes':
        original = builtins.__import__
        def guarded(name,*args,**kwargs):
            if name == 'app':
                raise AssertionError('Master hook must not import app')
            return original(name,*args,**kwargs)
        builtins.__import__ = guarded
        result = invoke(os.getpid()+1)
        assert result == {'closed':[False,False],'wrapper_called':False,'events':[],'error':None,'acknowledgements':[]}
    else:
        read_end,write_end = os.pipe()
        child = os.fork()
        if child == 0:
            os.close(read_end)
            sys.modules['app'] = SimpleNamespace(stop_job_dispatcher=stop)
            result = invoke(os.getpid())
            os.write(write_end,json.dumps(result).encode())
            os.close(write_end)
            os._exit(0)
        os.close(write_end)
        with os.fdopen(read_end,'rb') as stream:
            result = json.loads(stream.read(4096))
        _,status = os.waitpid(child,0)
        child_pid = child
        child = None
        assert os.waitstatus_to_exitcode(status) == 0
        assert result['closed'] == [True,True] and result['wrapper_called'] is False
        failures = (['dispatcher'] if stop_failure == 'yes' else []) + (['listener'] if close_failure == 'yes' else [])
        assert result['events'] == ['stop','close','close'] + ([] if failures else ['ack'])
        assert result['acknowledgements'] == ([] if failures else ['Scan worker cleanup ok pid='+str(child_pid)])
        assert result['error'] == ('Server worker cleanup failed: '+', '.join(failures) if failures else None)
    usable()
    print(json.dumps(result))
finally:
    if child is not None:
        try:
            os.kill(child,signal.SIGKILL)
        except ProcessLookupError:
            pass
        os.waitpid(child,0)
    for listener in listeners:
        socket.socket.close(listener.sock)
        if listener.path is not None and os.path.exists(listener.path):
            os.unlink(listener.path)
'''


@pytest.fixture
def listener_directory():
    with tempfile.TemporaryDirectory(prefix='ais-worker-', dir='/tmp') as directory:
        yield Path(directory).resolve(strict=True)


@pytest.mark.parametrize('kind', ['tcp', 'unix'])
@pytest.mark.parametrize('stop_failure,close_failure', [('no', 'no'), ('yes', 'no'), ('no', 'yes'), ('yes', 'yes')])
def test_child_closes_every_raw_listener_and_preserves_parent(kind, stop_failure, close_failure, listener_directory):
    result = subprocess.run([sys.executable, '-Werror', '-c', PROGRAM, str(ROOT / 'gunicorn.conf.py'),
        str(listener_directory), kind, stop_failure, close_failure, 'no'], capture_output=True, text=True,
        timeout=10, check=False, env={'PATH': os.defpath,
            'SCAN_EVIDENCE_PROFILES_FILE': '/tmp/aiscan-operator-registry-must-not-exist.json'})
    assert result.returncode == 0, result.stderr
    assert result.stderr == ''
    assert json.loads(result.stdout)['closed'] == [True, True]
    assert 'owned-private' not in result.stdout


@pytest.mark.parametrize('kind', ['tcp', 'unix'])
def test_master_hook_never_imports_app_or_closes_parent_listener(kind, listener_directory):
    result = subprocess.run([sys.executable, '-Werror', '-c', PROGRAM, str(ROOT / 'gunicorn.conf.py'),
        str(listener_directory), kind, 'no', 'no', 'yes'], capture_output=True, text=True,
        timeout=10, check=False, env={'PATH': os.defpath,
            'SCAN_EVIDENCE_PROFILES_FILE': '/tmp/aiscan-operator-registry-must-not-exist.json'})
    assert result.returncode == 0, result.stderr
    assert result.stderr == ''
    assert json.loads(result.stdout)['closed'] == [False, False]
