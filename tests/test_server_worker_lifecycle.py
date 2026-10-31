"""Forked worker cleanup closes child descriptors without touching the master."""

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
from unittest.mock import Mock

import pytest

from src.core.jobs import JobDispatcher
from src.core.schedules import ScheduleService
from tests.test_api_auth import api as api
from tests.test_jobs import complete, enqueue, store as store


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
    return True
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


def test_incomplete_worker_stop_retains_lock_until_actual_work_finishes(api, store, monkeypatch):
    module, _ = api
    started, release = threading.Event(), threading.Event()
    def run(scan_id, cancelled):
        started.set()
        assert release.wait(5)
        complete(store, scan_id)
    enqueue(store, 'owned-blocked-worker')
    dispatcher = JobDispatcher(store, run, workers=1, poll_seconds=0.01)
    replacement = JobDispatcher(store, Mock(), workers=1, poll_seconds=0.01)
    stop = dispatcher.stop
    try:
        dispatcher.start()
        assert started.wait(2)
        monkeypatch.setattr(dispatcher, 'stop', lambda: stop(timeout=0.01))
        monkeypatch.setattr(module, '_job_dispatcher', dispatcher)
        with pytest.raises(RuntimeError, match='^Server dispatcher shutdown incomplete$'):
            module.stop_job_dispatcher()
        assert dispatcher._ownership.handle is not None
        assert any(not future.done() for future, _ in dispatcher._active.values())
        with pytest.raises(RuntimeError):
            replacement.start()
        release.set()
        assert stop(timeout=2) is True
        assert dispatcher._ownership.handle is None
        assert all(future.done() for future, _ in dispatcher._active.values())
        assert dispatcher._thread.is_alive() is False
        replacement.start()
        assert replacement.stop(timeout=2) is True
    finally:
        release.set()
        stop(timeout=2)
        replacement.stop(timeout=2)


def test_dispatcher_stop_before_start_is_a_completed_noop(store):
    dispatcher = JobDispatcher(store, Mock(), workers=1)
    assert dispatcher.stop(timeout=0.01) is True
    assert dispatcher._thread is None and dispatcher._ownership.handle is None


def test_pending_schedule_preflight_retains_dispatcher_ownership_until_finished(store):
    started, release = threading.Event(), threading.Event()
    admitted = []
    candidates = iter([{'id': 'owned-preflight'}, None])
    def preflight(candidate):
        started.set()
        assert release.wait(5)
        return {'ready': True}
    service = ScheduleService(lambda: next(candidates, None), preflight,
        lambda *args: admitted.append(True), lambda: None)
    dispatcher = JobDispatcher(store, Mock(), workers=1, poll_seconds=0.01, service=service)
    replacement = JobDispatcher(store, Mock(), workers=1, poll_seconds=0.01)
    try:
        dispatcher.start()
        assert started.wait(2)
        assert dispatcher.stop(timeout=0.01) is False
        assert service.future.done() is False
        assert dispatcher._ownership.handle is not None
        with pytest.raises(RuntimeError):
            replacement.start()
        release.set()
        assert dispatcher.stop(timeout=2) is True
        assert service.future.done() is True and dispatcher._ownership.handle is None
        assert admitted == []
        replacement.start()
        assert replacement.stop(timeout=2) is True
    finally:
        release.set()
        dispatcher.stop(timeout=2)
        replacement.stop(timeout=2)


def test_schedule_dispatcher_stop_before_start_is_a_completed_noop(store):
    service = ScheduleService(Mock(), Mock(), Mock(), Mock())
    dispatcher = JobDispatcher(store, Mock(), workers=1, service=service)
    assert dispatcher.stop(timeout=0.01) is True
    assert service.future is None and dispatcher._ownership.handle is None


@pytest.mark.parametrize('result', [False, None, 1, 'yes'])
def test_app_shutdown_requires_explicit_completed_dispatcher_result(api, monkeypatch, result):
    module, _ = api
    stopper = Mock(return_value=result)
    monkeypatch.setattr(module, '_job_dispatcher', type('OwnedDispatcher', (), {'stop': staticmethod(stopper)})())
    with pytest.raises(RuntimeError, match='^Server dispatcher shutdown incomplete$'):
        module.stop_job_dispatcher()
    stopper.assert_called_once_with()


def test_app_shutdown_accepts_completed_or_absent_dispatcher(api, monkeypatch):
    module, _ = api
    monkeypatch.setattr(module, '_job_dispatcher', None)
    assert module.stop_job_dispatcher() is True
    monkeypatch.setattr(module, '_job_dispatcher', type('OwnedDispatcher', (), {'stop': lambda self: True})())
    assert module.stop_job_dispatcher() is True


TLS_CANCEL_PROGRAM = r'''
import gc,json,os,runpy,secrets,ssl,sys,threading,time
from http.server import BaseHTTPRequestHandler
from pathlib import Path
root,directory = Path(sys.argv[1]),Path(sys.argv[2])
sys.path.insert(0,str(root))
helper = runpy.run_path(str(root/'scripts/acceptance-http-assessment.py'))
context,ca = helper['certificate'](directory)
marker,bearer,operator,signing = [secrets.token_hex(24) for _ in range(4)]
stalled,release = threading.Event(),threading.Event()
requests = []
class Handler(BaseHTTPRequestHandler):
    def log_message(self,*args):
        pass
    def do_POST(self):
        assert self.path == '/cancel'
        assert self.headers.get('Authorization') == 'Bearer '+bearer
        assert self.headers.get('Cookie') is None
        body = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
        assert set(body) == {'question'}
        requests.append(body)
        if len(requests) == 2:
            stalled.set()
            assert release.wait(10)
        raw = json.dumps({'answer':marker}).encode()
        try:
            self.send_response(200)
            self.send_header('Content-Type','application/json')
            self.send_header('Content-Length',str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)
        except (BrokenPipeError,ConnectionResetError,ssl.SSLError):
            pass
server = helper['NumericServer'](('127.0.0.1',0),Handler)
server.socket = context.wrap_socket(server.socket,server_side=True,do_handshake_on_connect=False)
thread = threading.Thread(target=server.serve_forever,kwargs={'poll_interval':0.02},daemon=True)
thread.start()
module = None
try:
    descriptor = {'adapter_id':'http-json','adapter_version':'1.0','method':'POST',
        'endpoint':'https://127.0.0.1:'+str(server.server_port)+'/cancel',
        'request_prompt_field':'question','response_text_pointer':'/answer','auth_scheme':'bearer',
        'principal_label':'owned-tls-principal','context_label':'owned-tls-cancel-v1',
        'session_mode':'fresh-per-prompt-v1'}
    registry = {'schema_version':'2.0','profiles':{},'http_targets':{'cancel':{
        'organization_id':'owned-tls','schema_version':'1.0','name':'Owned TLS cancellation',
        'http_target':descriptor,'allowed_networks':['127.0.0.1/32'],
        'credential_env':'SCAN_EVIDENCE_TLS_CANCEL_KEY','canary_env':'SCAN_EVIDENCE_TLS_CANCEL_MARKER',
        'canary_seeded':True}}}
    path = directory/'registry.json'
    helper['private_write'](path,json.dumps(registry))
    os.environ.update({'SECRET_KEY':signing,'OPERATOR_API_KEY':operator,'OPERATOR_ORGANIZATION_ID':'owned-tls',
        'DATABASE_URL':'sqlite:///'+str(directory/'jobs.sqlite'),'SCAN_EVIDENCE_PROFILES_FILE':str(path),
        'SCAN_EVIDENCE_TLS_CANCEL_KEY':bearer,'SCAN_EVIDENCE_TLS_CANCEL_MARKER':marker,
        'SSL_CERT_FILE':str(ca),'SCAN_ALLOWED_NETWORKS':'127.0.0.1/32','SCAN_ALLOW_LOOPBACK':'true',
        'SCAN_TIMEOUT_SECONDS':'10','SCAN_REQUEST_TIMEOUT_SECONDS':'5','MAX_CONCURRENT_SCANS':'1'})
    import app as module
    dispatcher = module.start_job_dispatcher()
    client = module.app.test_client()
    token = client.post('/api/auth/token',json={'api_key':operator}).json['token']
    headers = {'Authorization':'Bearer '+token}
    plan = client.get('/api/http-targets/cancel/plan',headers=headers).json['target']
    response = client.post('/api/scans',headers=headers,json={'scan_type':'security_only',
        'scan_config':{'http_target_profile':'cancel','http_target_revision':plan['revision'],'max_requests':2}})
    assert response.status_code == 202
    scan_id = response.json['scan_id']
    assert stalled.wait(5)
    initial = client.get('/api/scans/'+scan_id+'/report?format=json',headers=headers).json
    assert initial['summary']['overall_risk_score'] == 70
    acknowledged = initial['agents'][0]['check_evidence']
    assert len(acknowledged) == 1 and len(requests) == 2
    assert client.post('/api/scans/'+scan_id+'/cancel',headers=headers).status_code == 202
    stop = time.monotonic()+5
    while time.monotonic() < stop:
        result = client.get('/api/scans/'+scan_id+'/report?format=json',headers=headers).json
        if result['status'] == 'cancelled':
            break
        time.sleep(0.02)
    assert result['status'] == 'cancelled' and result['summary']['overall_risk_score'] == 70
    assert result['agents'][0]['check_evidence'] == acknowledged
    assert module.stop_job_dispatcher() is True
    for _ in range(3):
        gc.collect()
    assert not release.is_set()
    assert len(requests) == 2
    print(json.dumps({'status':result['status'],'score':result['summary']['overall_risk_score'],
        'receipts':len(acknowledged),'posts':len(requests),'stopped':True}))
finally:
    release.set()
    try:
        if module is not None:
            module.stop_job_dispatcher()
    finally:
        helper['stop_server'](server,thread)
gc.collect()
'''


def test_actual_verified_https_cancel_closes_worker_transports_without_warnings(listener_directory):
    result = subprocess.run([sys.executable, '-Werror', '-c', TLS_CANCEL_PROGRAM, str(ROOT), str(listener_directory)],
        capture_output=True, text=True, timeout=30, check=False,
        env={'PATH': os.defpath, 'HOME': str(listener_directory), 'TMPDIR': str(listener_directory),
             'PYTHONNOUSERSITE': '1', 'PYTHONUTF8': '1',
             'SCAN_EVIDENCE_PROFILES_FILE': '/tmp/aiscan-operator-registry-must-not-exist.json'})
    assert result.returncode == 0, result.stderr
    assert not any(value in result.stderr for value in ('ResourceWarning', 'RuntimeWarning', 'Traceback', 'Exception ignored'))
    assert all(line.startswith('INFO:src.') for line in result.stderr.splitlines()), result.stderr
    assert json.loads(result.stdout) == {'status': 'cancelled', 'score': 70, 'receipts': 1, 'posts': 2, 'stopped': True}
