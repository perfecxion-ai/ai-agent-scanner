#!/usr/bin/env python3
"""Exercise reference-only HTTP assessment through an owned real server.

Run from a source checkout with the server extra installed. All listeners,
credentials, registry, TLS trust, SQLite data and logs are disposable synthetic
inputs owned by this invocation. Only a finite work timeout is accepted.
"""

import argparse
from contextlib import closing, contextmanager
from copy import deepcopy
import hashlib
from http.server import BaseHTTPRequestHandler
from http.client import HTTPConnection
import importlib.util
import json
import math
import os
from pathlib import Path
import re
import runpy
import secrets
import signal
import socket
import sqlite3
import ssl
import stat
import subprocess
import sys
import tempfile
import threading
import time
from urllib.error import HTTPError, URLError
from urllib.request import HTTPHandler, HTTPRedirectHandler, ProxyHandler, Request, build_opener


ROOT = Path(__file__).resolve().parents[1]
FORMAT_VERSION = 'server-http-acceptance-v1'
MAX_CAPTURE_BYTES = 1024 * 1024
MAX_PUBLIC_BYTES = 16 * 1024 * 1024
DRIVER_SHA256 = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
HELPER = ROOT / 'scripts' / 'acceptance-http-assessment.py'
CLEANUP_INTERRUPTS = set()
REFERENCES = {
    'marker_a': 'SCAN_EVIDENCE_SERVER_HTTP_MARKER_A',
    'marker_b': 'SCAN_EVIDENCE_SERVER_HTTP_MARKER_B',
    'marker_c': 'SCAN_EVIDENCE_SERVER_HTTP_MARKER_C',
    'bearer': 'SCAN_EVIDENCE_SERVER_HTTP_BEARER',
}
REQUIRED_ASSERTIONS = (
    'private_environment_owned_http_https_and_real_gunicorn_dispatcher',
    'authenticated_tenant_scoped_preview_without_target_posts_or_admission_writes',
    'raw_mixed_unknown_forged_and_template_schedule_inputs_refused',
    'concurrent_http_https_disclosures_keep_independent_canaries',
    'defended_https_is_null_inconclusive_with_seven_sampled_checks',
    'off_pointer_and_untrusted_tls_remain_partial_unknown',
    'api_inventory_json_and_sarif_match_saved_canonical_evidence',
    'verified_https_bearer_exact_post_and_fresh_sessions',
    'cancellation_and_deadline_keep_acknowledged_disclosure',
    'worker_sigkill_restart_keeps_acknowledged_evidence_without_replay',
    'queued_removed_reference_refused_before_post',
    'queued_current_server_policy_refused_before_post',
    'clean_master_restarts_preserve_completed_reports',
    'known_private_values_and_reference_paths_absent_from_public_surfaces',
    'all_owned_processes_reaped_and_fixtures_removed',
)


class GateFailure(RuntimeError):
    """Only static failure codes are included in the receipt."""


def require(condition, code):
    if not condition:
        raise GateFailure(code)


def private_write(path, value):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, 'wb') as stream:
        stream.write(value.encode() if isinstance(value, str) else value)


def remaining(deadline):
    seconds = deadline - time.monotonic()
    require(seconds > 0, 'work_deadline')
    return seconds


def python_warnings(raw, phase):
    """Retain bounded static warning metadata without messages or paths."""
    observations = []
    lines = raw.decode('utf-8', errors='replace').splitlines()
    categories = ('_SSLProtocolTransport', '_SelectorSocketTransport', 'socket.socket',
                  'sqlite3.Connection', 'unclosed event loop', 'unclosed file',
                  'unclosed transport', 'was never awaited')
    for index, line in enumerate(lines):
        kind = next((value for value in ('ResourceWarning', 'RuntimeWarning') if value in line), None)
        if kind is None:
            continue
        location = re.findall(r'[/\\]([A-Za-z_][A-Za-z0-9_]*\.py)(?:["\']?, line |:)([0-9]+)',
                              '\n'.join(lines[max(0, index - 5):index + 1]))
        observations.append({'phase': phase, 'kind': kind,
            'location': {'module': location[-1][0], 'line': int(location[-1][1])} if location else None,
            'categories': [category for category in categories if category in line]})
        require(len(observations) <= 16, 'python_warning_observation_limit')
    return observations


def worker_lifecycle(raw, master_pid, observed, intentional=None):
    """Validate bounded owned worker events, not the master's exit alone."""
    require(len(raw) <= MAX_CAPTURE_BYTES, 'server_log_output_limit')
    records, failures = [], []
    prefix = re.compile(r'^\[[^\r\n]{1,80}\]\s+\[([0-9]+)\]\s+\[(DEBUG|INFO|WARNING|ERROR|CRITICAL)\]\s+(.*)$')
    boots, acknowledgements, killed = [], [], []
    shutdowns = 0
    critical = ('Exception during worker exit', 'Exception in worker process', 'WORKER TIMEOUT',
                'Worker failed to boot', 'App failed to load', 'Error handling request')
    for line in raw.decode('utf-8', errors='replace').splitlines():
        match = prefix.fullmatch(line)
        if match is None:
            continue
        logger_pid, _level, message = int(match[1]), match[2], match[3]
        if any(value in message for value in critical):
            failures.append('critical_worker_lifecycle_error')
        boot = re.fullmatch(r'Booting worker with pid: ([0-9]+)', message)
        ack = re.fullmatch(r'Scan worker cleanup ok pid=([0-9]+)', message)
        sent = re.fullmatch(r'Worker \(pid:\s*([0-9]+)\) was sent (SIG[A-Z0-9]+|signal [0-9]+)!.*', message)
        exited = re.fullmatch(r'Worker \(pid:\s*([0-9]+)\) exited with code ([0-9]+)\.?', message)
        if boot:
            pid = int(boot[1])
            boots.append(pid)
            if logger_pid != pid:
                failures.append('worker_boot_identity_mismatch')
            records.append({'event': 'boot', 'pid': pid})
        if ack:
            pid = int(ack[1])
            acknowledgements.append(pid)
            if logger_pid != pid:
                failures.append('worker_cleanup_ack_identity_mismatch')
            records.append({'event': 'cleanup_ack', 'pid': pid})
        if sent:
            pid, selected_signal = int(sent[1]), sent[2]
            if logger_pid != master_pid:
                failures.append('worker_signal_logger_mismatch')
            killed.append((pid, selected_signal))
            records.append({'event': 'signal', 'pid': pid, 'signal': selected_signal})
        if exited:
            pid, code = int(exited[1]), int(exited[2])
            if logger_pid != master_pid or code != 0:
                failures.append('worker_exit_nonzero_or_unowned')
            records.append({'event': 'exit_code', 'pid': pid, 'code': code})
        if message == 'Shutting down: Master':
            shutdowns += 1
            if logger_pid != master_pid:
                failures.append('master_shutdown_identity_mismatch')
        require(len(records) <= 32, 'worker_lifecycle_event_limit')
    expected = set(observed)
    if not 1 <= len(expected) <= 4 or len(boots) != len(set(boots)) or set(boots) != expected:
        failures.append('worker_boot_observation_mismatch')
    crash_pid = None
    if intentional is not None:
        crash_pid = intentional.get('pid')
        if (intentional.get('fresh_identity_verified') is not True
                or observed.get(crash_pid) != intentional.get('create_time')
                or intentional.get('signal_sent') != 'SIGKILL'):
            failures.append('intentional_worker_crash_unverified')
        if killed != [(crash_pid, 'SIGKILL')]:
            failures.append('worker_signal_does_not_match_one_intentional_crash')
    elif killed:
        failures.append('unexpected_worker_signal')
    required_ack = expected - ({crash_pid} if crash_pid is not None else set())
    if (len(acknowledgements) != len(set(acknowledgements))
            or set(acknowledgements) != required_ack):
        failures.append('worker_cleanup_ack_missing_duplicate_or_unexpected')
    if len(expected) != 1 + (intentional is not None):
        failures.append('unexpected_worker_replacement')
    if shutdowns != 1:
        failures.append('master_shutdown_record_missing_or_duplicate')
    return {'observed_worker_count': len(expected), 'cleanup_ack_count': len(acknowledgements),
            'intentional_crash_count': int(intentional is not None), 'events': records,
            'failure_codes': list(dict.fromkeys(failures))}


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        raise GateFailure('unexpected_api_redirect')


class UnixHTTPConnection(HTTPConnection):
    def __init__(self, host, *, socket_path, **kwargs):
        super().__init__(host, **kwargs)
        self.socket_path = socket_path

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            self.sock.settimeout(self.timeout)
            self.sock.connect(str(self.socket_path))
        except BaseException:
            self.sock.close()
            self.sock = None
            raise


class UnixHTTPHandler(HTTPHandler):
    def __init__(self, socket_path):
        super().__init__()
        self.socket_path = socket_path

    def http_open(self, request):
        def connection(host, **kwargs):
            return UnixHTTPConnection(host, socket_path=self.socket_path, **kwargs)
        return self.do_open(connection, request)


class Resources:
    """Register ownership before setup and share one final cleanup deadline."""

    def __init__(self, outer_deadline):
        self.outer_deadline, self.cleanup_deadline = outer_deadline, None
        self.servers, self.listeners, self.target_servers, self.target_workers, self.releases = [], [], [], [], []
        self.failures = []
        self.servers_cleaned = self.targets_cleaned = self.listeners_closed = False

    def begin_cleanup(self):
        if self.cleanup_deadline is None:
            self.cleanup_deadline = min(self.outer_deadline, time.monotonic() + 20)
            signal.setitimer(signal.ITIMER_REAL, 0)
            for number in (signal.SIGTERM, signal.SIGINT):
                signal.signal(number, lambda signum, frame: CLEANUP_INTERRUPTS.add(signum))
        return self.cleanup_deadline

    def cleanup_servers(self):
        deadline = self.begin_cleanup()
        if self.servers_cleaned:
            return
        self.servers_cleaned = True
        for release in self.releases:
            release.set()
        pending = [server for server in self.servers if not server.stopped]
        for index, server in enumerate(self.servers):
            try:
                count = max(1, sum(not value.stopped for value in self.servers[index:]))
                available = max(0, deadline - time.monotonic())
                allowance = (available - min(6, available / 3)) / count
                server.stop(deadline=min(deadline, time.monotonic() + allowance))
            except (Exception, KeyboardInterrupt):
                self.failures.extend(server.stop_failures or ['owned_server_cleanup_failed'])
        if len(pending) > 3:
            self.failures.append('unexpected_owned_server_count')
        for server in self.servers:
            if server.process is not None and time.monotonic() < deadline:
                code = server.process.poll()
                if code is not None:
                    server.exit_code = code

    def cleanup_targets(self):
        deadline = self.begin_cleanup()
        if self.targets_cleaned:
            return
        self.targets_cleaned = True
        for release in self.releases:
            release.set()
        stopping = []
        for index, server in enumerate(self.target_servers):
            worker = self.target_workers[index] if index < len(self.target_workers) else None
            if worker is not None and worker.ident is not None and worker.is_alive():
                stopper = threading.Thread(target=server.shutdown, daemon=True)
                stopping.append(stopper)
                stopper.start()
            for connection in server.connections:
                try:
                    connection.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                try:
                    connection.close()
                except OSError:
                    self.failures.append('owned_target_socket_close_failed')
            try:
                server.server_close()
            except OSError:
                self.failures.append('owned_target_listener_close_failed')
        threads = [*stopping, *self.target_workers,
                   *(thread for server in self.target_servers for thread in server.handler_threads)]
        for thread in threads:
            if thread.ident is not None:
                thread.join(timeout=max(0, deadline - time.monotonic()))
                if thread.is_alive():
                    self.failures.append('owned_target_thread_survived')

    def close_listeners(self):
        self.begin_cleanup()
        if self.listeners_closed:
            return
        self.listeners_closed = True
        for listener in self.listeners:
            try:
                listener.close()
            except OSError:
                self.failures.append('owned_api_listener_close_failed')

    def cleanup(self):
        for operation in (self.cleanup_servers, self.cleanup_targets, self.close_listeners):
            try:
                operation()
            except (Exception, KeyboardInterrupt):
                self.failures.append('owned_resource_cleanup_failed')


class Server:
    def __init__(self, directory, environment, socket_path, phase, deadline, private_values, privacy_check):
        self.directory, self.environment, self.socket_path = directory, environment, Path(socket_path)
        self.hooks_sha256 = hashlib.sha256((ROOT / 'gunicorn.conf.py').read_bytes()).hexdigest()
        self.phase, self.deadline, self.private_values = phase, deadline, private_values
        self.privacy_check = privacy_check
        self.base = 'http://owned-server-http.invalid'
        self.opener = build_opener(ProxyHandler({}), UnixHTTPHandler(self.socket_path), NoRedirect())
        self.process = self.reader = self.stream = None
        self.log_path = directory / (phase + '.log')
        self.capture_failure = threading.Event()
        self.capture_overflow = threading.Event()
        self.tokens, self.public_responses, self.public_bytes = {}, [], 0
        self.stopped, self.exit_code, self.forced, self.survived = False, None, False, False
        self.stop_failures = []
        self.children = {}
        self.child_states = {}
        self.cleanup_record = {}
        self.worker_identities = {}
        self.intentional_crash = None
        self.graceful_timeout_seconds = 5
        self.master_shutdown_seconds = None

    def observe_worker(self):
        import psutil
        children = psutil.Process(self.process.pid).children(recursive=False)
        require(len(children) == 1, 'unexpected_gunicorn_worker_count')
        child = children[0]
        identity = child.pid, child.create_time()
        require(child.ppid() == self.process.pid, 'owned_worker_parent_changed')
        if identity[0] in self.worker_identities:
            require(self.worker_identities[identity[0]] == identity[1], 'owned_worker_identity_reused')
        self.worker_identities[identity[0]] = identity[1]
        require(len(self.worker_identities) <= 4, 'owned_worker_observation_limit')
        return identity

    def check(self):
        remaining(self.deadline)
        require(not self.capture_failure.is_set(), 'server_log_capture_failed')
        require(not self.capture_overflow.is_set(), 'server_log_output_limit')

    def start(self):
        require(hashlib.sha256((ROOT / 'gunicorn.conf.py').read_bytes()).hexdigest() == self.hooks_sha256,
                'server_hooks_changed_before_start')
        require(self.socket_path.is_absolute() and self.socket_path.parent == self.directory
                and len(os.fsencode(self.socket_path)) <= 90
                and stat.S_IMODE(self.directory.stat().st_mode) == 0o700
                and self.directory.stat().st_uid == os.geteuid()
                and not self.socket_path.exists() and not self.socket_path.is_symlink(),
                'unsafe_owned_api_socket_path')
        self.stream = self.log_path.open('xb')
        os.fchmod(self.stream.fileno(), 0o600)
        optimize = ['-' + 'O' * sys.flags.optimize] if sys.flags.optimize else []
        # Gunicorn documents unix:PATH for an owned filesystem HTTP listener.
        # https://gunicorn.org/reference/settings/#bind
        command = [sys.executable, *optimize, '-Werror', '-m', 'gunicorn', '--config', str(ROOT / 'gunicorn.conf.py'),
                   '--workers', '1', '--bind', 'unix:' + str(self.socket_path),
                   '--timeout', '30', '--graceful-timeout', str(self.graceful_timeout_seconds),
                   '--worker-tmp-dir', str(self.directory), 'app:app']
        pending, handlers = [], {}
        try:
            for number in (signal.SIGALRM, signal.SIGTERM, signal.SIGINT):
                handlers[number] = signal.signal(number, lambda signum, frame: pending.append(signum))
            self.process = subprocess.Popen(command, cwd=ROOT, env=self.environment,
                                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                            stdin=subprocess.DEVNULL, start_new_session=True,
                                            umask=0o077)
        finally:
            for number, handler in handlers.items():
                signal.signal(number, handler)

        def drain():
            total = 0
            try:
                while chunk := os.read(self.process.stdout.fileno(), 65536):
                    allowance = max(0, MAX_CAPTURE_BYTES - total)
                    if allowance:
                        self.stream.write(chunk[:allowance])
                    total += len(chunk)
                    if total > MAX_CAPTURE_BYTES:
                        self.capture_overflow.set()
            except (OSError, ValueError):
                self.capture_failure.set()

        self.reader = threading.Thread(target=drain, daemon=True)
        self.reader.start()
        require(not pending, 'driver_interrupted_during_server_start')
        self.ready()
        self.observe_worker()
        metadata = self.socket_path.lstat()
        require(stat.S_ISSOCK(metadata.st_mode) and metadata.st_uid == os.geteuid()
                and not stat.S_IMODE(metadata.st_mode) & 0o077, 'unsafe_owned_api_socket_permissions')

    def ready(self):
        end = min(self.deadline, time.monotonic() + 20)
        while time.monotonic() < end:
            self.check()
            require(self.process.poll() is None, 'server_exited_during_startup')
            try:
                status, value = self.request('/health/ready', tenant=None, timeout=0.25)
                if status == 200 and value.get('status') == 'ready':
                    return
            except (URLError, TimeoutError, OSError):
                pass
            time.sleep(0.04)
        raise GateFailure('server_startup_deadline')

    def request(self, path, *, payload=None, method=None, tenant='server-http-a', timeout=3):
        self.check()
        headers = {'Authorization': 'Bearer ' + self.tokens[tenant]} if tenant in self.tokens else {}
        data = json.dumps(payload).encode() if payload is not None else None
        if data is not None:
            headers['Content-Type'] = 'application/json'
        req = Request(self.base + path, data=data, headers=headers, method=method)
        try:
            response = self.opener.open(req, timeout=min(timeout, remaining(self.deadline)))
        except HTTPError as error:
            response = error
        with response:
            raw = response.read(MAX_CAPTURE_BYTES + 1)
            require(len(raw) <= MAX_CAPTURE_BYTES, 'api_response_byte_limit')
            value = json.loads(raw)
            header_bytes = str(response.headers).encode()
            if path == '/api/auth/token' and response.status == 200:
                require(set(value) == {'success', 'token'} and value['success'] is True
                        and isinstance(value['token'], str), 'unexpected_auth_response')
                self.private_values.add(value['token'])
                public = json.dumps({'success': True}).encode()
            else:
                public = raw + json.dumps(value, ensure_ascii=False).encode()
            try:
                self.privacy_check((public + header_bytes).decode('utf-8'), self.private_values)
            except Exception:
                raise GateFailure('known_private_value_in_api_response') from None
            self.public_bytes += len(public) + len(header_bytes)
            require(self.public_bytes <= MAX_PUBLIC_BYTES, 'api_public_capture_budget')
            self.public_responses.append(public)
            return response.status, value

    def authenticate(self, values):
        status, value = self.request('/api/auth/token', tenant=None, payload={'api_key': values['operator']})
        require(status == 200, 'operator_authentication_failed')
        self.tokens['server-http-a'] = value['token']
        from src.utils.auth import create_jwt_token
        self.tokens['server-http-b'] = create_jwt_token(
            {'user_id': 'owned-server-http-fixture', 'organization_id': 'server-http-b'}, values['signing'])
        self.private_values.add(self.tokens['server-http-b'])

    def plan(self, identifier):
        status, value = self.request('/api/http-targets/' + identifier + '/plan')
        require(status == 200 and value.get('success') is True, 'target_plan_unavailable')
        return value['target']

    def submit(self, identifier, revision, **limits):
        value = {'scan_name': 'Owned server HTTP fixture', 'scan_type': 'security_only',
                 'target_scope': {}, 'scan_config': {'http_target_profile': identifier,
                     'http_target_revision': revision, **limits}}
        status, response = self.request('/api/scans', payload=value)
        require(status == 202 and isinstance(response.get('scan_id'), str), 'scan_not_queued')
        return response['scan_id']

    def wait_status(self, identifier, states):
        end = min(self.deadline, time.monotonic() + 100)
        while time.monotonic() < end:
            status, value = self.request('/api/scans/' + identifier + '/status')
            require(status == 200, 'scan_status_unavailable')
            if value['status'] in states:
                return value['status']
            if value['status'] in {'failed', 'cancelled', 'interrupted', 'completed', 'partial'}:
                raise GateFailure('unexpected_terminal_scan_' + value['status'])
            time.sleep(0.08)
        raise GateFailure('scan_terminal_deadline')

    def result(self, identifier):
        status, value = self.request('/api/scans/' + identifier + '/results')
        require(status == 200 and value.get('success') is True, 'scan_result_unavailable')
        return value['results']

    def crash_worker(self):
        import psutil
        require(self.intentional_crash is None, 'duplicate_intentional_worker_crash')
        identity = self.observe_worker()
        fresh = psutil.Process(identity[0])
        require(fresh.create_time() == identity[1] and fresh.ppid() == self.process.pid,
                'owned_worker_identity_changed')
        fresh.kill()
        self.intentional_crash = {'pid': identity[0], 'create_time': identity[1],
                                 'signal_sent': 'SIGKILL', 'fresh_identity_verified': True}
        end = min(self.deadline, time.monotonic() + 20)
        while time.monotonic() < end:
            self.check()
            replacements = psutil.Process(self.process.pid).children(recursive=False)
            old_gone = not any((p.pid, p.create_time()) == identity for p in replacements)
            if old_gone and len(replacements) == 1:
                self.ready()
                self.observe_worker()
                return {**self.intentional_crash, 'old_identity_gone': True, 'replacement_observed': True}
            time.sleep(0.04)
        raise GateFailure('worker_replacement_deadline')

    def stop(self, *, deadline=None):
        import psutil
        if self.stopped:
            require(not self.stop_failures, self.stop_failures[0] if self.stop_failures else 'owned_server_cleanup_failed')
            return self.exit_code
        deadline = min(self.deadline, time.monotonic() + 12) if deadline is None else deadline
        started = time.monotonic()

        def allowance(maximum):
            return min(maximum, max(0, deadline - time.monotonic()))

        def permitted():
            if time.monotonic() < deadline:
                return True
            if 'owned_server_cleanup_deadline' not in self.stop_failures:
                self.stop_failures.append('owned_server_cleanup_deadline')
            return False

        def children():
            if permitted() and self.process is not None and self.process.poll() is None:
                try:
                    found = psutil.Process(self.process.pid).children(recursive=True)
                except psutil.NoSuchProcess:
                    found = []
                except psutil.Error:
                    self.stop_failures.append('owned_server_descendant_probe_failed')
                    found = []
                if len(found) > 4:
                    self.stop_failures.append('unexpected_server_descendant_count')
                for child in found[:4]:
                    if not permitted():
                        break
                    try:
                        self.children[(child.pid, child.create_time())] = child
                    except psutil.NoSuchProcess:
                        pass
                    except psutil.Error:
                        self.stop_failures.append('owned_server_descendant_probe_failed')

        try:
            if self.process is not None:
                children()
                if not permitted():
                    raise GateFailure('owned_server_cleanup_deadline')
                shutdown_started = time.monotonic()
                if self.process.poll() is None and permitted():
                    self.process.terminate()
                try:
                    if not permitted():
                        raise GateFailure('owned_server_cleanup_deadline')
                    self.exit_code = self.process.wait(timeout=max(0, allowance(8) - 1))
                except subprocess.TimeoutExpired:
                    self.forced = True
                    children()
                    for identity in self.children:
                        if not permitted():
                            break
                        try:
                            child = psutil.Process(identity[0])
                            if permitted() and child.create_time() == identity[1] and permitted():
                                child.kill()
                        except psutil.NoSuchProcess:
                            pass
                    if permitted():
                        self.process.kill()
                    if permitted():
                        self.exit_code = self.process.wait(timeout=allowance(3))
                self.master_shutdown_seconds = time.monotonic() - shutdown_started
                alive = set(self.children)
                while alive:
                    for identity in list(alive):
                        if not permitted():
                            break
                        try:
                            child = psutil.Process(identity[0])
                            if not permitted():
                                break
                            if child.create_time() != identity[1]:
                                self.stop_failures.append('owned_server_identity_reused')
                                self.child_states[identity] = 'pid_reused'
                                alive.remove(identity)
                            elif permitted():
                                state = child.status()
                                self.child_states[identity] = state
                                if state != psutil.STATUS_ZOMBIE and permitted():
                                    self.survived = True
                                    child.kill()
                        except psutil.NoSuchProcess:
                            self.child_states[identity] = 'gone'
                            alive.remove(identity)
                    if not alive or allowance(1) <= 0:
                        break
                    time.sleep(allowance(0.02))
                if alive:
                    self.stop_failures.append('owned_server_descendant_unreaped')
                if self.reader is not None and permitted():
                    self.reader.join(timeout=allowance(3))
                if self.process.stdout is not None:
                    self.process.stdout.close()
        except (Exception, KeyboardInterrupt):
            self.stop_failures.append('owned_server_cleanup_failed')
        finally:
            if self.process is not None and self.exit_code is None and permitted():
                try:
                    if self.process.poll() is None and permitted():
                        self.forced = True
                        self.process.kill()
                    if permitted():
                        self.exit_code = self.process.wait(timeout=allowance(3))
                except (Exception, KeyboardInterrupt):
                    self.stop_failures.append('owned_master_reap_failed')
            self.stopped = True
            if self.stream is not None:
                self.stream.close()
        if self.forced:
            self.stop_failures.append('server_required_forced_cleanup')
        if self.survived:
            self.stop_failures.append('owned_server_descendant_survived')
        if self.reader is not None and self.reader.is_alive():
            self.stop_failures.append('server_log_reader_survived')
        if self.capture_failure.is_set() or self.capture_overflow.is_set():
            self.stop_failures.append('server_log_failed')
        lifecycle = None
        if self.process is not None and self.log_path.is_file() and not self.capture_overflow.is_set():
            try:
                lifecycle = worker_lifecycle(self.log_path.read_bytes(), self.process.pid,
                                              self.worker_identities, self.intentional_crash)
                self.stop_failures.extend(lifecycle['failure_codes'])
            except Exception:
                self.stop_failures.append('worker_lifecycle_log_unavailable_or_invalid')
        elif self.process is not None:
            self.stop_failures.append('worker_lifecycle_log_unavailable_or_invalid')
        if self.exit_code is not None and self.exit_code != 0:
            self.stop_failures.append('owned_master_exit_nonzero')
        if (self.master_shutdown_seconds is not None
                and self.master_shutdown_seconds >= self.graceful_timeout_seconds):
            self.stop_failures.append('worker_graceful_shutdown_boundary_unverified')
        self.cleanup_record = {'elapsed_seconds': round(time.monotonic() - started, 6),
            'master_exit': self.exit_code, 'forced_cleanup': self.forced,
            'master_shutdown_seconds': self.master_shutdown_seconds, 'worker_lifecycle': lifecycle,
            'failure_codes': list(dict.fromkeys(self.stop_failures)),
            'children': [{'pid': identity[0], 'create_time': identity[1],
                          'state': self.child_states.get(identity, 'unknown')} for identity in self.children]}
        require(not self.stop_failures, self.stop_failures[0] if self.stop_failures else 'owned_server_cleanup_failed')
        return self.exit_code


@contextmanager
def targets(directory, values, helper, resources):
    calls, failures, events, releases = {}, [], {}, {}
    authenticated = {'tls-leak', 'defended', 'unusable', 'cancel', 'deadline', 'crash',
                     'hold-a', 'hold-b', 'hold-c', 'untrusted'}
    stalled = {'cancel', 'deadline', 'crash', 'hold-a', 'hold-b', 'hold-c'}
    for mode in stalled:
        events[mode], releases[mode] = threading.Event(), threading.Event()
        resources.releases.append(releases[mode])

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_GET(self):
            failures.append('unexpected_target_get')
            self.send_error(405)

        def do_POST(self):
            size = self.headers.get('Content-Length', '')
            if not size.isascii() or not size.isdigit() or not 0 < int(size) <= 65536:
                failures.append('invalid_target_request_size')
                self.send_error(400)
                return
            try:
                body = json.loads(self.rfile.read(int(size)))
            except (ValueError, UnicodeError):
                failures.append('invalid_target_json')
                self.send_error(400)
                return
            pieces = self.path.split('/')
            if len(pieces) != 4 or pieces[1] != 'custom' or pieces[3] != 'infer':
                failures.append('rewritten_target_path')
                self.send_error(404)
                return
            mode = pieces[2]
            record = {'body': body, 'authorization': self.headers.get('Authorization'),
                      'cookie': self.headers.get('Cookie'), 'path': self.path,
                      'tls': self.connection.version() if isinstance(self.connection, ssl.SSLSocket) else None}
            current = calls.setdefault(mode, [])
            current.append(record)
            if mode in authenticated and record['authorization'] != 'Bearer ' + values['bearer']:
                failures.append('incorrect_target_bearer')
                self.send_error(403)
                return
            if mode in stalled and len(current) == 2:
                events[mode].set()
                if not releases[mode].wait(90):
                    failures.append('fixture_stall_expired')
            marker = values['marker_b'] if mode in authenticated else values['marker_a']
            text = 'Protected information is unavailable' if mode == 'defended' else marker + '\n' + values['pii']
            response = {'metadata': {'text': marker}} if mode == 'unusable' else {'answer': {'text': text}}
            raw = json.dumps(response).encode()
            try:
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Content-Length', str(len(raw)))
                self.send_header('Set-Cookie', 'owned_session=' + values['cookie'] + '; HttpOnly; Path=/')
                self.end_headers()
                self.wfile.write(raw)
            except (BrokenPipeError, ConnectionResetError, ssl.SSLError):
                pass

    servers, workers = [], []
    trusted_context, ca_file = helper['certificate'](directory)
    untrusted = directory / 'untrusted-cert'
    untrusted.mkdir(mode=0o700)
    untrusted_context, _ = helper['certificate'](untrusted)
    try:
        for context in (None, trusted_context, untrusted_context):
            server = helper['NumericServer'](('127.0.0.1', 0), Handler)
            servers.append(server)
            resources.target_servers.append(server)
            if context is not None:
                server.socket = context.wrap_socket(server.socket, server_side=True, do_handshake_on_connect=False)
            worker = threading.Thread(target=server.serve_forever, kwargs={'poll_interval': 0.02}, daemon=True)
            workers.append(worker)
            resources.target_workers.append(worker)
            worker.start()
        yield {'http': 'http://127.0.0.1:' + str(servers[0].server_port),
               'https': 'https://127.0.0.1:' + str(servers[1].server_port),
               'untrusted': 'https://127.0.0.1:' + str(servers[2].server_port),
               'ca_file': ca_file, 'calls': calls, 'failures': failures,
               'events': events, 'releases': releases, 'authenticated': authenticated}
    finally:
        resources.cleanup_targets()


def registry(fixture):
    entries = {}
    names = ['http-leak', 'tls-leak', 'defended', 'unusable', 'untrusted', 'cancel', 'deadline',
             'crash', 'hold-a', 'hold-b', 'hold-c', 'missing', 'policy', 'foreign']
    for mode in names:
        authenticated = mode in fixture['authenticated']
        base = fixture['untrusted'] if mode == 'untrusted' else fixture['https'] if authenticated else fixture['http']
        descriptor = {'adapter_id': 'http-json', 'adapter_version': '1.0',
                      'endpoint': base + '/custom/' + mode + '/infer', 'method': 'POST',
                      'request_prompt_field': 'question', 'response_text_pointer': '/answer/text',
                      'auth_scheme': 'bearer' if authenticated else 'none',
                      'principal_label': 'owned-authorized-principal-v1' if authenticated else 'anonymous',
                      'context_label': 'owned-server-http-v1', 'session_mode': 'fresh-per-prompt-v1'}
        entries[mode] = {'organization_id': 'server-http-b' if mode == 'foreign' else 'server-http-a',
                         'schema_version': '1.0', 'name': 'Owned server HTTP ' + mode,
                         'http_target': descriptor, 'allowed_networks': ['127.0.0.1/32'],
                         'credential_env': REFERENCES['bearer'] if authenticated else None,
                         'canary_env': REFERENCES['marker_c'] if mode == 'foreign' else
                             REFERENCES['marker_b'] if authenticated else REFERENCES['marker_a'],
                         'canary_seeded': True}
    return {'schema_version': '2.0', 'profiles': {}, 'http_targets': entries}


def table_rows(database):
    with closing(sqlite3.connect('file:' + str(database) + '?mode=ro', uri=True, timeout=1)) as connection:
        return {name: connection.execute('SELECT count(*) FROM "' + name + '"').fetchone()[0]
                for name in ('scan_session', 'scan_job', 'scan_result', 'discovered_agent',
                             'scan_template', 'scan_schedule', 'audit_event')}


def wait_blocked(server, fixture, mode, identifier):
    end = min(server.deadline, time.monotonic() + 12)
    while time.monotonic() < end:
        server.check()
        if fixture['events'][mode].is_set():
            report = server.result(identifier)['pipeline']
            if report and report['agents'][0].get('check_evidence'):
                require(report['summary']['overall_risk_score'] == 70, 'acknowledged_disclosure_not_high')
                return deepcopy(report['agents'][0]['check_evidence'])
        time.sleep(0.04)
    raise GateFailure('missing_acknowledged_blocked_receipt')


def compare_views(server, identifier, helper, *, score, completed, count, terminal_status=None):
    from src.core.pipeline import to_sarif
    from src.core.risk_projection import project_report_risk
    value = server.result(identifier)
    report = value['pipeline']
    expected_status = terminal_status or ('completed' if completed else 'partial')
    require(report.get('status') == expected_status, 'unexpected_saved_server_report_state')
    # The shared CLI helper labels every incomplete export partial. Server
    # cancellation/failure/recovery truthfully retain their terminal state.
    # Adapt only its input copy; every API/export comparison uses the original.
    evidence_view = deepcopy(report)
    if not completed and terminal_status in {'cancelled', 'failed', 'interrupted'}:
        evidence_view['status'] = 'partial'
    try:
        agent = helper['report_checks'](evidence_view, score=score, completed=completed, count=count)
    except helper['GateFailure'] as error:
        raise GateFailure(str(error)) from None
    summary, agents = project_report_risk(report)
    require(all(value['summary'].get(key) == expected for key, expected in summary.items()),
            'outer_summary_projection_mismatch')
    require(len(value['agents']) == 1 and all(value['agents'][0].get(key) == expected
            for key, expected in agents[agent['id']].items()), 'api_agent_projection_mismatch')
    status, inventory = server.request('/api/agents?limit=100')
    require(status == 200 and inventory['coverage']['search_complete'] is True, 'inventory_unavailable_or_incomplete')
    selected = [item for item in inventory['agents'] if item['id'] == value['agents'][0]['id']]
    require(len(selected) == 1 and all(selected[0].get(key) == expected
            for key, expected in agents[agent['id']].items()), 'inventory_projection_mismatch')
    status, export = server.request('/api/scans/' + identifier + '/report?format=json')
    require(status == 200 and export == report, 'json_export_changed_saved_report')
    status, export = server.request('/api/scans/' + identifier + '/report?format=sarif')
    require(status == 200 and export == to_sarif(report), 'sarif_export_changed_saved_evidence')
    return report


def execute(directory, deadline, output, private_values, resources):
    sys.path.insert(0, str(ROOT))
    helper = runpy.run_path(str(HELPER))
    from src.core.build_identity import _digest, current_identity
    from src.core.prompt_catalog import candidate_payloads
    expected_identity = current_identity(component='server')
    require(expected_identity['source']['status'] == 'available', 'source_identity_unavailable')
    expected_identity['server_app'] = {'status': 'available', 'sha256': _digest(
        [('app.py', (ROOT / 'app.py').read_bytes())], 'server-app-python-v1')}
    values = {name: secrets.token_hex(24) for name in ('operator', 'signing', 'marker_a', 'marker_b',
                                                     'marker_c', 'bearer', 'cookie')}
    values['pii'] = '078-05-1120 4111 1111 1111 1111'
    private_values.update([*values.values(), *REFERENCES.values()])
    private_values.update({'078-05-1120', '4111 1111 1111 1111', '4111111111111111'})
    database, registry_file = directory / 'fixture.sqlite', directory / 'target-registry.json'
    private_values.add(str(registry_file))
    private_values.add(str(database))
    output['runtime'] = {'python': sys.version.split()[0], 'optimization': sys.flags.optimize,
                         'driver_sha256': DRIVER_SHA256,
                         'fixture_helper_sha256': hashlib.sha256(HELPER.read_bytes()).hexdigest(),
                         'app_sha256': hashlib.sha256((ROOT / 'app.py').read_bytes()).hexdigest(),
                         'server_child_requested_optimization': sys.flags.optimize,
                         'producer_identity': expected_identity,
                         'gunicorn_hooks_sha256': hashlib.sha256((ROOT / 'gunicorn.conf.py').read_bytes()).hexdigest()}
    api_socket = directory / 'api.sock'
    servers, completed_reports, all_public = [], {}, []
    with targets(directory, values, helper, resources) as fixture:
        private_values.update({str(fixture['ca_file']), str(directory / 'fixture-key.pem')})
        document = registry(fixture)
        private_write(registry_file, json.dumps(document))
        environment = {'PATH': os.defpath, 'HOME': str(directory), 'TMPDIR': str(directory),
                       'XDG_CONFIG_HOME': str(directory), 'XDG_CACHE_HOME': str(directory),
                       'PYTHONUTF8': '1', 'PYTHONNOUSERSITE': '1', 'PYTHONUNBUFFERED': '1',
                       'SECRET_KEY': values['signing'], 'OPERATOR_API_KEY': values['operator'],
                       'OPERATOR_ORGANIZATION_ID': 'server-http-a',
                       'DATABASE_URL': 'sqlite:///' + str(database),
                       'SCAN_EVIDENCE_PROFILES_FILE': str(registry_file),
                       'SCAN_ALLOWED_NETWORKS': '127.0.0.1/32', 'SCAN_ALLOW_LOOPBACK': 'true',
                       'MAX_CONCURRENT_SCANS': '2', 'SCAN_TIMEOUT_SECONDS': '180',
                       'SCAN_MAX_REQUESTS': '35', 'SCAN_MAX_RESPONSE_BYTES': '65536',
                       'SCAN_REQUEST_TIMEOUT_SECONDS': '10', 'SSL_CERT_FILE': str(fixture['ca_file']),
                       **{reference: values[key] for key, reference in REFERENCES.items()}}

        def launch(phase, **changed):
            server = Server(directory, {**environment, **changed}, api_socket, phase, deadline,
                            private_values, helper['privacy_check'])
            servers.append(server)
            resources.servers.append(server)
            require(server.hooks_sha256 == output['runtime']['gunicorn_hooks_sha256'],
                    'server_hooks_changed_between_starts')
            server.start()
            server.authenticate(values)
            return server

        def stop(server):
            code = server.stop()
            output['server_exits'].append({'phase': server.phase, 'master_exit': code})
            require(code == 0, 'server_master_exit_nonzero')
            all_public.extend(server.public_responses)

        try:
            server = launch('initial')
            status, build = server.request('/api/build')
            require(status == 200 and build['build'] == expected_identity, 'executed_server_identity_mismatch')
            output['assertions'].append(REQUIRED_ASSERTIONS[0])
            before = table_rows(database)
            require(server.request('/api/http-targets', tenant=None)[0] == 401, 'anonymous_target_listing')
            status, listed = server.request('/api/http-targets')
            require(status == 200 and {p['id'] for p in listed['targets']} == set(document['http_targets']) - {'foreign'},
                    'tenant_target_list_mismatch')
            require(server.request('/api/http-targets/foreign/plan')[0] == 404, 'foreign_target_plan_visible')
            status, foreign = server.request('/api/http-targets', tenant='server-http-b')
            require(status == 200 and [p['id'] for p in foreign['targets']] == ['foreign'], 'foreign_target_list_mismatch')
            plans = {p['id']: server.plan(p['id']) for p in listed['targets']}
            for plan in plans.values():
                require(plan['configuration_status'] == 'ready' and plan['network_readiness_status'] == 'not_checked'
                        and plan['selected_rule_count'] == 7 and plan['maximum_prompt_http_attempts'] == 35
                        and plan['shared_attempt_budget'] == 35 and plan['max_response_bytes'] == 65536
                        and plan['overall_timeout_seconds'] == 180 and plan['request_timeout_seconds'] == 10,
                        'unexpected_offline_plan_contract')
            require(table_rows(database) == before and not fixture['calls'], 'preview_admitted_work_or_posted_target')
            output['assertions'].append(REQUIRED_ASSERTIONS[1])
            base = {'scan_name': 'Owned refusal fixture', 'scan_type': 'security_only', 'target_scope': {},
                    'scan_config': {'http_target_profile': 'http-leak',
                                    'http_target_revision': plans['http-leak']['revision']}}
            invalid = []
            for field, value in (('source_scan_id', 'unknown'), ('evidence_profiles', {}), ('model_overrides', {}),
                                 ('prompt_suite', 'unsupported'), ('credential', values['bearer']),
                                 ('canary_env', REFERENCES['marker_a']), ('profile_path', str(registry_file))):
                selected = deepcopy(base)
                selected['scan_config'][field] = value
                invalid.append(selected)
            for profile, revision in [('unknown', '0' * 64), ('foreign', '0' * 64), ('http-leak', '0' * 64)]:
                invalid.append({**base, 'scan_config': {'http_target_profile': profile, 'http_target_revision': revision}})
            invalid.append({**base, 'scan_type': 'full'})
            invalid.append({**base, 'target_scope': {'network_ranges': ['127.0.0.1/32']}})
            for selected in invalid:
                require(server.request('/api/scans', payload=selected)[0] == 400, 'invalid_http_definition_admitted')
            require(server.request('/api/templates', payload=base)[0] == 400, 'http_template_admitted')
            require(server.request('/api/schedules', payload=base)[0] == 400, 'inline_http_schedule_admitted')
            require(table_rows(database) == before and not fixture['calls'], 'refused_input_admitted_work')
            output['assertions'].append(REQUIRED_ASSERTIONS[2])
            ids = {name: server.submit(name, plans[name]['revision']) for name in ('http-leak', 'tls-leak')}
            for name, identifier in ids.items():
                require(server.wait_status(identifier, {'completed'}) == 'completed', 'full_leak_not_completed')
                report = compare_views(server, identifier, helper, score=70, completed=True, count=35)
                require(report['producer_identity'] == expected_identity, 'report_producer_mismatch')
                completed_reports[identifier] = report
                require(len(fixture['calls'].get(name, [])) == 35, 'full_leak_post_count')
            output['assertions'].append(REQUIRED_ASSERTIONS[3])
            defended = server.submit('defended', plans['defended']['revision'])
            server.wait_status(defended, {'completed'})
            completed_reports[defended] = compare_views(server, defended, helper, score=None, completed=True, count=0)
            output['assertions'].append(REQUIRED_ASSERTIONS[4])
            for mode in ('unusable', 'untrusted'):
                identifier = server.submit(mode, plans[mode]['revision'], max_requests=1)
                server.wait_status(identifier, {'partial'})
                compare_views(server, identifier, helper, score=None, completed=False, count=0)
            require(len(fixture['calls'].get('unusable', [])) == 1 and not fixture['calls'].get('untrusted'),
                    'unusable_or_untrusted_request_count')
            output['assertions'].extend(REQUIRED_ASSERTIONS[5:7])
            for mode in ('cancel', 'deadline'):
                identifier = server.submit(mode, plans[mode]['revision'],
                    **({'timeout_seconds': 4} if mode == 'deadline' else {}))
                acknowledged = wait_blocked(server, fixture, mode, identifier)
                if mode == 'cancel':
                    require(server.request('/api/scans/' + identifier + '/cancel', payload={})[0] == 202,
                            'scan_cancellation_refused')
                server.wait_status(identifier, {'cancelled'} if mode == 'cancel' else {'failed'})
                report = compare_views(server, identifier, helper, score=70, completed=False, count=1,
                                       terminal_status='cancelled' if mode == 'cancel' else 'failed')
                require(report['agents'][0]['check_evidence'] == acknowledged, 'terminalization_changed_acknowledged_receipt')
                fixture['releases'][mode].set()
            output['assertions'].append(REQUIRED_ASSERTIONS[8])
            crash = server.submit('crash', plans['crash']['revision'])
            acknowledged = wait_blocked(server, fixture, 'crash', crash)
            count_before = sum(map(len, fixture['calls'].values()))
            output['worker_crash'] = server.crash_worker()
            server.wait_status(crash, {'interrupted'})
            report = compare_views(server, crash, helper, score=70, completed=False, count=1,
                                   terminal_status='interrupted')
            require(report['agents'][0]['check_evidence'] == acknowledged
                    and sum(map(len, fixture['calls'].values())) == count_before, 'crash_replayed_or_changed_receipt')
            fixture['releases']['crash'].set()
            output['assertions'].append(REQUIRED_ASSERTIONS[9])
            for name in ('hold-a', 'hold-b'):
                identifier = server.submit(name, plans[name]['revision'])
                wait_blocked(server, fixture, name, identifier)
            removed = server.submit('missing', plans['missing']['revision'])
            held = server.submit('hold-c', plans['hold-c']['revision'])
            policy = server.submit('policy', plans['policy']['revision'])
            require(server.wait_status(removed, {'queued'}) == 'queued'
                    and server.wait_status(policy, {'queued'}) == 'queued', 'queued_revalidation_fixture_not_queued')
            stop(server)
            fixture['releases']['hold-a'].set()
            fixture['releases']['hold-b'].set()
            document['http_targets'].pop('missing')
            registry_file.unlink()
            private_write(registry_file, json.dumps(document))
            server = launch('registry-restart', MAX_CONCURRENT_SCANS='1')
            server.wait_status(removed, {'failed'})
            require(not fixture['calls'].get('missing'), 'removed_reference_posted_target')
            output['assertions'].append(REQUIRED_ASSERTIONS[10])
            wait_blocked(server, fixture, 'hold-c', held)
            require(server.wait_status(policy, {'queued'}) == 'queued', 'policy_fixture_not_queued')
            stop(server)
            fixture['releases']['hold-c'].set()
            server = launch('policy-restart', MAX_CONCURRENT_SCANS='1', SCAN_ALLOWED_NETWORKS='192.0.2.0/24')
            server.wait_status(policy, {'failed'})
            require(not fixture['calls'].get('policy'), 'tightened_policy_posted_target')
            output['assertions'].append(REQUIRED_ASSERTIONS[11])
            for identifier, original in completed_reports.items():
                require(server.result(identifier)['pipeline'] == original, 'restart_changed_completed_report')
            output['assertions'].append(REQUIRED_ASSERTIONS[12])
            prompts = [payload for payloads in candidate_payloads().values() for payload in payloads]
            for mode, calls in fixture['calls'].items():
                for call in calls:
                    require(call['path'] == '/custom/' + mode + '/infer'
                            and set(call['body']) == {'question'} and isinstance(call['body']['question'], str)
                            and call['cookie'] is None, 'target_mapping_or_session_state_changed')
                    require(call['authorization'] == ('Bearer ' + values['bearer']
                            if mode in fixture['authenticated'] else None), 'target_credential_changed')
                    if mode in fixture['authenticated']:
                        require(call['tls'] in {'TLSv1.2', 'TLSv1.3'}, 'authenticated_target_not_tls')
            require(len(prompts) == 35 and all([call['body']['question'] for call in fixture['calls'][mode]] == prompts
                    for mode in ('http-leak', 'tls-leak', 'defended')), 'wire_prompt_sequence_changed')
            require(not fixture['failures'], 'owned_target_fixture_error')
            output['assertions'].insert(7, REQUIRED_ASSERTIONS[7])
            output['request_counts'] = {mode: len(calls) for mode, calls in sorted(fixture['calls'].items())}
            stop(server)
        finally:
            resources.cleanup_servers()
            for server in servers:
                if not any(item['phase'] == server.phase for item in output['server_exits']):
                    output['server_exits'].append({'phase': server.phase, 'master_exit': server.exit_code})
            resources.close_listeners()
        for path in [*directory.glob('*.log'), *directory.glob('fixture.sqlite*')]:
            require(stat.S_IMODE(path.stat().st_mode) == 0o600 and path.stat().st_nlink == 1,
                    'private_output_permissions_changed')
            raw = path.read_bytes()
            require(len(raw) <= 8 * 1024 * 1024, 'private_surface_byte_limit')
            if path.suffix == '.log':
                warnings = python_warnings(raw, path.stem)
                if warnings:
                    output.setdefault('python_warning_observations', []).extend(warnings)
                    raise GateFailure('python_resource_or_runtime_warning_in_server_log')
            helper['privacy_check'](raw.decode('utf-8', errors='ignore'), private_values)
        helper['privacy_check'](b'\n'.join(all_public).decode(), private_values)
        require(hashlib.sha256((ROOT / 'gunicorn.conf.py').read_bytes()).hexdigest()
                == output['runtime']['gunicorn_hooks_sha256'], 'server_hooks_changed_during_execution')
        output['runtime']['gunicorn_hooks_unchanged'] = True
        output['privacy'] = {'known_values_checked': len(private_values),
                             'scope': 'owned_public_api_exports_logs_sqlite_and_known_encoded_forms_only'}
        output['assertions'].append(REQUIRED_ASSERTIONS[13])


def timeout_value(raw):
    number = float(raw)
    if not math.isfinite(number) or not 30 <= number <= 240:
        raise argparse.ArgumentTypeError('Expected finite work timeout from 30 to 240 seconds')
    return number


class SafeParser(argparse.ArgumentParser):
    def error(self, message):
        raise GateFailure('invalid_arguments')


def main(argv=None):
    CLEANUP_INTERRUPTS.clear()
    parser = SafeParser(prog='acceptance-server-http.py', description=__doc__)
    parser.add_argument('--timeout-seconds', type=timeout_value, default=240)
    output = {'format_version': FORMAT_VERSION, 'accepted': False,
              'scope': 'owned_synthetic_single_process_gunicorn_http_reference_workflow',
              'api_transport': 'owned_private_unix_http',
              'assertions': [], 'server_exits': [],
              'limitations': ['Synthetic fixtures do not measure real-model sensitivity or enterprise readiness.',
                  'Preview checks observe target POSTs and admission table rows, not arbitrary DNS or all SQL activity.',
                  'The API uses an owned Unix HTTP socket; TCP, public and reverse-proxy deployment are separate gates.',
                  'Master exit codes are actual waits; worker crash evidence records an owned SIGKILL and replacement.']}
    private_values, failures, previous = set(), [], {}
    temporary = directory = mask = resources = None
    started = time.monotonic()
    try:
        args = parser.parse_args(argv)
        require(os.name == 'posix', 'posix_required')
        require(importlib.util.find_spec('gunicorn') is not None, 'server_extra_required')
        require('app' not in sys.modules, 'cached_server_not_allowed')
        require(signal.getitimer(signal.ITIMER_REAL) == (0.0, 0.0), 'preexisting_timer_not_allowed')
        mask = os.umask(0o077)
        temporary = tempfile.TemporaryDirectory(prefix='ai-scanner-server-http-', dir='/tmp')
        directory = Path(temporary.name).resolve(strict=True)
        directory.chmod(0o700)
        def interrupted(number, frame):
            raise GateFailure('work_deadline' if number == signal.SIGALRM else 'driver_interrupted')
        for number in (signal.SIGALRM, signal.SIGTERM, signal.SIGINT):
            previous[number] = signal.signal(number, interrupted)
        signal.setitimer(signal.ITIMER_REAL, args.timeout_seconds)
        resources = Resources(started + args.timeout_seconds + 25)
        execute(directory, started + args.timeout_seconds, output, private_values, resources)
    except (Exception, KeyboardInterrupt) as error:
        failures.append(str(error) if isinstance(error, GateFailure) else 'unexpected_driver_failure')
        if not isinstance(error, GateFailure):
            output['failure_class'] = type(error).__name__
    finally:
        if resources is not None:
            try:
                resources.cleanup()
            except (Exception, KeyboardInterrupt):
                resources.failures.append('owned_resource_cleanup_failed')
            if resources.failures:
                output['cleanup_failure_codes'] = list(dict.fromkeys(resources.failures))
            for server in resources.servers:
                existing = next((item for item in output['server_exits'] if item['phase'] == server.phase), None)
                if existing is None:
                    existing = {'phase': server.phase}
                    output['server_exits'].append(existing)
                existing.update(master_exit=server.exit_code, cleanup=server.cleanup_record)
        if previous:
            signal.setitimer(signal.ITIMER_REAL, 0)
        for number, handler in previous.items():
            signal.signal(number, handler)
        if temporary is not None:
            try:
                temporary.cleanup()
                require(not directory.exists(), 'owned_directory_survived')
                if not failures and not output.get('cleanup_failure_codes') and not CLEANUP_INTERRUPTS:
                    output['assertions'].append(REQUIRED_ASSERTIONS[14])
            except Exception:
                failures.append('owned_directory_cleanup_failed')
        if mask is not None:
            os.umask(mask)
    if (not failures and not output.get('cleanup_failure_codes') and not CLEANUP_INTERRUPTS
            and output['assertions'] != list(REQUIRED_ASSERTIONS)):
        failures.append('missing_required_assertions')
    if output.get('cleanup_failure_codes'):
        failures.append('owned_server_cleanup_failed')
    if CLEANUP_INTERRUPTS:
        failures.append('driver_interrupted_during_cleanup')
    if hashlib.sha256(Path(__file__).read_bytes()).hexdigest() != DRIVER_SHA256:
        failures.append('driver_source_changed')
    output['accepted'] = not failures
    output['elapsed_seconds'] = round(time.monotonic() - started, 3)
    if failures:
        output['failure_codes'] = list(dict.fromkeys(failures))
    rendered = json.dumps(output, sort_keys=True)
    try:
        runpy.run_path(str(HELPER))['privacy_check'](rendered, private_values)
    except Exception:
        output = {'format_version': FORMAT_VERSION, 'accepted': False, 'assertions': [],
                  'failure_codes': ['private_value_in_receipt_or_privacy_check_failed']}
        rendered = json.dumps(output, sort_keys=True)
    print(rendered)
    return 0 if output['accepted'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
