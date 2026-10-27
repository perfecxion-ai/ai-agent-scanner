"""Opt-in private CLI snapshots, with offline export and no probe resumption."""

from collections import Counter
from contextlib import contextmanager
from copy import deepcopy
import json
import os
from pathlib import Path
import re
import stat
import sys
import uuid

try:
    import fcntl
except ImportError:  # The optional store requires the supported POSIX filesystem.
    fcntl = None

from src.core.build_identity import saved_identity
from src.core.contracts import (
    MAX_CHECKPOINT_BYTES, MAX_CHECKPOINTS, MAX_CHECKPOINT_TOTAL_BYTES,
    preserves_observation_eligibility, unfinished_evidence_checks, validate_checkpoint_report,
)
from src.core.redaction import collect_secrets, redact_secrets
from src.core.risk_projection import project_report_risk


FORMAT = 'ai-agent-scanner-cli-checkpoint'
VERSION = '1.0'
LATEST = 'latest.json'
LOCK = '.lock'
MAX_FILE_BYTES = MAX_CHECKPOINT_BYTES + 1024
RECOVERY_REASON = 'CLI execution ended without a recorded terminal result'
PUBLIC_FIELDS = ('format', 'version', 'execution_id', 'state', 'report', FORMAT, VERSION,
                 'checkpoint', 'terminal', 'partial', 'error', RECOVERY_REASON)
_FIELDS = frozenset({'format', 'version', 'execution_id', 'state', 'report'})
_TEMP = re.compile(r'\.checkpoint-[0-9a-f]{32}\.tmp\Z')
_JSON_MARKS = re.compile(r'["\\\[\]{}]')
_TERMINAL = frozenset({'completed', 'partial', 'failed', 'cancelled'})
MAX_REPORT_DEPTH = 64


class CLICheckpointError(RuntimeError):
    def __init__(self):
        super().__init__('CLI checkpoint is unavailable, unsafe, or invalid')


def _encoded(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=True, allow_nan=False, separators=(',', ':')).encode('utf-8')


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise CLICheckpointError()
        result[key] = value
    return result


def _constant(value):
    raise CLICheckpointError()


def _decode(raw):
    if len(raw) > MAX_FILE_BYTES:
        raise CLICheckpointError()
    text = raw.decode('utf-8-sig')
    depth, quoted, escaped_at = 0, False, -1
    for match in _JSON_MARKS.finditer(text):
        position, mark = match.start(), match.group()
        if quoted:
            if position == escaped_at:
                escaped_at = -1
                continue
            escaped_at = position + 1 if mark == '\\' else -1
            if mark == '"':
                quoted = False
        elif mark == '"':
            quoted = True
        elif mark in '[{':
            depth += 1
            if depth > MAX_REPORT_DEPTH + 1:
                raise CLICheckpointError()
        elif mark in ']}':
            depth -= 1
            if depth < 0:
                raise CLICheckpointError()
        else:
            raise CLICheckpointError()
    if depth or quoted:
        raise CLICheckpointError()
    return json.loads(text, object_pairs_hook=_pairs, parse_constant=_constant)


def _bounded_object(value):
    """Bound expansion before copying or serializing caller-owned objects."""
    stack, active, minimum = [(iter((value,)), 0, None)], set(), 0
    while stack:
        children, depth, identity = stack[-1]
        try:
            child = next(children)
        except StopIteration:
            stack.pop()
            if identity is not None:
                active.remove(identity)
            continue
        if type(child) in (dict, list, tuple):
            if depth >= MAX_REPORT_DEPTH or id(child) in active:
                return False
            active.add(id(child))
            minimum += 2
            if type(child) is dict:
                if any(type(key) is not str for key in child):
                    return False
                values = (item for pair in child.items() for item in pair)
            else:
                values = iter(child)
            stack.append((values, depth + 1, id(child)))
        elif type(child) is str:
            minimum += len(child) + 2
        elif child is None or type(child) in (int, float, bool):
            minimum += 1
        else:
            return False
        if minimum > MAX_CHECKPOINT_BYTES:
            return False
    return True


def _report(value, *, terminal):
    if not _bounded_object(value):
        raise CLICheckpointError()
    raw = _encoded(value)
    if len(raw) > MAX_CHECKPOINT_BYTES:
        raise CLICheckpointError()
    report = json.loads(raw)
    if type(report) is not dict or report.get('status') not in (_TERMINAL if terminal else {'partial'}):
        raise CLICheckpointError()
    validation = deepcopy(report)
    if validation['status'] in {'failed', 'cancelled'}:
        validation['status'] = 'partial'
    validate_checkpoint_report(validation, final=terminal)
    if report['status'] == 'completed':
        if (report.get('transport_incomplete') or report.get('risk_assessment_status') == 'failed'
                or any(source.get('status') != 'completed' for source in report['security_results'])
                or any(unfinished_evidence_checks(asset) for asset in report['agents'])
                or any(check.get('status') == 'failed' for asset in report['agents']
                       for check in asset.get('checks', []))):
            raise CLICheckpointError()
        if report.get('scan_type') != 'discovery_only' and (
                any(asset.get('security_status') != 'completed' for asset in report['agents'])
                or Counter(source.get('agent_id') for source in report['security_results'])
                != Counter(asset['id'] for asset in report['agents'])):
            raise CLICheckpointError()
    if _encoded(report) != _encoded(redact_secrets(report, collect_secrets(report))):
        raise CLICheckpointError()
    if 'producer_identity' in report and report['producer_identity'] is not None and saved_identity(report['producer_identity']) is None:
        raise CLICheckpointError()
    summary, assets = project_report_risk(report)
    if _encoded(report.get('summary', {}).get('overall_risk_score')) != _encoded(summary['overall_risk_score']):
        raise CLICheckpointError()
    for asset in report['agents']:
        canonical = assets.get(asset['id'], {})
        for key in ('risk_score', 'risk_level', 'risk_coverage_status', 'risk_scoring_policy'):
            if key in asset and _encoded(asset[key]) != _encoded(canonical.get(key)):
                raise CLICheckpointError()
    for source in report['security_results']:
        canonical = assets.get(source.get('agent_id'), {})
        for key, projected in (('overall_risk_score', 'risk_score'), ('risk_level', 'risk_level'),
                               ('risk_coverage_status', 'risk_coverage_status'), ('risk_scoring_policy', 'risk_scoring_policy')):
            if key in source and _encoded(source[key]) != _encoded(canonical.get(projected)):
                raise CLICheckpointError()
    for assessment in report['risk_assessments']:
        canonical = assets.get(assessment.get('agent_id'), {})
        if (canonical.get('risk_score') is None
                or _encoded(assessment.get('overall_risk_score')) != _encoded(canonical['risk_score'])):
            raise CLICheckpointError()
        for key, projected in (('risk_level', 'risk_level'), ('coverage_status', 'risk_coverage_status'),
                               ('scoring_policy', 'risk_scoring_policy')):
            if key in assessment and _encoded(assessment[key]) != _encoded(canonical.get(projected)):
                raise CLICheckpointError()
    return report


def _extends(previous, current):
    for key in ('schema_version', 'check_schema_version', 'check_evidence_schema_version', 'scan_type', 'producer_identity'):
        if (key in previous) != (key in current) or _encoded(previous.get(key)) != _encoded(current.get(key)):
            return False
    if any(previous['checkpoint'][key] != current['checkpoint'][key] for key in ('version', 'coverage')):
        return False
    if len(previous['agents']) != len(current['agents']):
        return False
    for old, new in zip(previous['agents'], current['agents']):
        if not preserves_observation_eligibility(old, new):
            return False
        for key in ('id', 'name', 'type', 'provider', 'model', 'endpoint', 'endpoint_redacted', 'metadata',
                    'evidence_context_id', 'check_evidence_schema_version', 'check_evidence_run_id'):
            if key == 'check_evidence_run_id' and key not in old:
                continue
            if _encoded(old.get(key)) != _encoded(new.get(key)):
                return False
        before = old.get('check_evidence', [])
        if _encoded(before) != _encoded(new.get('check_evidence', [])[:len(before)]):
            return False
        for key in ('checks', 'vulnerabilities', 'observations'):
            original = Counter(_encoded(item) for item in old.get(key, [])
                               if key != 'checks' or item.get('probe_version') != '1:unexecuted')
            following = Counter(_encoded(item) for item in new.get(key, []))
            if original - following:
                return False
    return True


def _safe_file(info):
    if (not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600
            or info.st_uid != os.getuid() or info.st_nlink != 1):
        raise CLICheckpointError()


def _identity(info):
    return info.st_dev, info.st_ino


class CheckpointStore:
    def __init__(self, path, parent_fd, directory_fd, lock_fd, execution_id):
        self.path, self._parent_fd, self._directory_fd, self._lock_fd = path, parent_fd, directory_fd, lock_fd
        self._directory_identity = _identity(os.fstat(directory_fd))
        self._lock_identity = _identity(os.fstat(lock_fd))
        self._execution_id, self._last, self._latest_identity = execution_id, None, None
        self._failed = self._finished = False
        self._total_bytes = 0
        self.public_fields = (*PUBLIC_FIELDS, execution_id)

    @classmethod
    @contextmanager
    def create(cls, path):
        store = None
        try:
            store = _open_store(path, fresh=True)
            yield store
        except BaseException:
            if store is not None:
                try:
                    store.close()
                except CLICheckpointError:
                    pass
            raise
        else:
            store.close()

    def _directory(self):
        info = os.fstat(self._directory_fd)
        named = os.stat(self.path.name, dir_fd=self._parent_fd, follow_symlinks=False)
        if (not stat.S_ISDIR(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o700 or info.st_uid != os.getuid()
                or _identity(info) != self._directory_identity or _identity(named) != self._directory_identity):
            raise CLICheckpointError()
        lock = os.stat(LOCK, dir_fd=self._directory_fd, follow_symlinks=False)
        _safe_file(lock)
        if _identity(lock) != self._lock_identity:
            raise CLICheckpointError()
        names = []
        with os.scandir(self._directory_fd) as entries:
            for entry in entries:
                names.append(entry.name)
                if len(names) > 3 or entry.name not in {LOCK, LATEST} and not _TEMP.fullmatch(entry.name):
                    raise CLICheckpointError()
                if _TEMP.fullmatch(entry.name):
                    temporary = os.stat(entry.name, dir_fd=self._directory_fd, follow_symlinks=False)
                    _safe_file(temporary)
                    if temporary.st_size > MAX_FILE_BYTES:
                        raise CLICheckpointError()
        if sum(bool(_TEMP.fullmatch(name)) for name in names) > 1:
            raise CLICheckpointError()

    def _read(self):
        self._directory()
        named = os.stat(LATEST, dir_fd=self._directory_fd, follow_symlinks=False)
        _safe_file(named)
        fd = os.open(LATEST, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK,
                     dir_fd=self._directory_fd)
        try:
            before = os.fstat(fd)
            _safe_file(before)
            if before.st_size > MAX_FILE_BYTES or _identity(before) != _identity(named):
                raise CLICheckpointError()
            chunks, remaining = [], MAX_FILE_BYTES + 1
            while remaining:
                chunk = os.read(fd, min(65536, remaining))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            after = os.fstat(fd)
            _safe_file(after)
            if (not remaining or _identity(before) != _identity(after) or before.st_size != after.st_size
                    or before.st_mtime_ns != after.st_mtime_ns or before.st_ctime_ns != after.st_ctime_ns):
                raise CLICheckpointError()
            envelope = _decode(b''.join(chunks))
            if (type(envelope) is not dict or set(envelope) != _FIELDS or envelope['format'] != FORMAT
                    or envelope['version'] != VERSION or type(envelope['execution_id']) is not str
                    or str(uuid.UUID(envelope['execution_id'])) != envelope['execution_id']
                    or envelope['state'] not in {'checkpoint', 'terminal'}):
                raise CLICheckpointError()
            report = _report(envelope['report'], terminal=envelope['state'] == 'terminal')
            return envelope, report
        finally:
            os.close(fd)

    def _write(self, report, *, terminal):
        if self._failed or self._finished or self._directory_fd is None:
            raise CLICheckpointError()
        temporary = None
        try:
            report = _report(report, terminal=terminal)
            sequence = report['checkpoint']['sequence']
            if self._last is None:
                if terminal or sequence != 1:
                    raise CLICheckpointError()
            elif (not _extends(self._last, report)
                  or sequence != self._last['checkpoint']['sequence'] + (0 if terminal else 1)):
                raise CLICheckpointError()
            self._directory()
            try:
                latest = os.stat(LATEST, dir_fd=self._directory_fd, follow_symlinks=False)
            except FileNotFoundError:
                latest = None
            if latest is not None:
                _safe_file(latest)
            if (latest is None) != (self._latest_identity is None) or latest is not None and _identity(latest) != self._latest_identity:
                raise CLICheckpointError()
            blob = _encoded(dict(format=FORMAT, version=VERSION, execution_id=self._execution_id,
                                 state='terminal' if terminal else 'checkpoint', report=report))
            total_limit = MAX_CHECKPOINT_TOTAL_BYTES + MAX_CHECKPOINTS * 1024 + (MAX_FILE_BYTES if terminal else 0)
            if len(blob) > MAX_FILE_BYTES or self._total_bytes + len(blob) > total_limit:
                raise CLICheckpointError()
            temporary = '.checkpoint-' + uuid.uuid4().hex + '.tmp'
            fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                         0o600, dir_fd=self._directory_fd)
            try:
                os.fchmod(fd, 0o600)
                view = memoryview(blob)
                while view:
                    count = os.write(fd, view)
                    if count <= 0:
                        raise CLICheckpointError()
                    view = view[count:]
                os.fsync(fd)
            finally:
                os.close(fd)
            self._directory()
            os.replace(temporary, LATEST, src_dir_fd=self._directory_fd, dst_dir_fd=self._directory_fd)
            temporary = None
            os.fsync(self._directory_fd)
            info = os.stat(LATEST, dir_fd=self._directory_fd, follow_symlinks=False)
            _safe_file(info)
            self._latest_identity = _identity(info)
            self._last, self._finished = deepcopy(report), terminal
            self._total_bytes += len(blob)
        except (OSError, TypeError, ValueError, KeyError, AttributeError, OverflowError, RecursionError, RuntimeError):
            self._failed = True
            raise CLICheckpointError() from None
        except BaseException:
            self._failed = True
            raise
        finally:
            if temporary is not None:
                active = sys.exc_info()[0] is not None
                try:
                    os.unlink(temporary, dir_fd=self._directory_fd)
                except FileNotFoundError:
                    pass
                except OSError:
                    self._failed = True
                    if not active:
                        raise CLICheckpointError() from None

    def publish(self, report):
        self._write(report, terminal=False)

    def finish(self, report):
        self._write(report, terminal=True)

    def close(self):
        failed = False
        for name in ('_lock_fd', '_directory_fd', '_parent_fd'):
            fd = getattr(self, name)
            if fd is not None:
                setattr(self, name, None)
                try:
                    os.close(fd)
                except OSError:
                    failed = True
        if failed:
            raise CLICheckpointError()


def _open_store(path, *, fresh):
    if fcntl is None or os.name != 'posix' or not hasattr(os, 'O_NOFOLLOW'):
        raise CLICheckpointError()
    parent_fd = directory_fd = lock_fd = None
    destination, created = None, False
    try:
        requested = Path(path).expanduser()
        if requested.name in {'', '.', '..'}:
            raise CLICheckpointError()
        parent = requested.parent.resolve(strict=True)
        parent_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        info = os.fstat(parent_fd)
        if info.st_mode & (stat.S_IWGRP | stat.S_IWOTH) and not info.st_mode & stat.S_ISVTX:
            raise CLICheckpointError()
        destination = parent / requested.name
        if fresh:
            os.mkdir(requested.name, 0o700, dir_fd=parent_fd)
            created = True
        directory_fd = os.open(requested.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent_fd)
        info = os.fstat(directory_fd)
        if stat.S_IMODE(info.st_mode) != 0o700 or info.st_uid != os.getuid():
            raise CLICheckpointError()
        if not fresh:
            _safe_file(os.stat(LOCK, dir_fd=directory_fd, follow_symlinks=False))
        flags = os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK | (os.O_CREAT | os.O_EXCL if fresh else 0)
        lock_fd = os.open(LOCK, flags, 0o600, dir_fd=directory_fd)
        if fresh:
            os.fchmod(lock_fd, 0o600)
        _safe_file(os.fstat(lock_fd))
        fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        store = CheckpointStore(destination, parent_fd, directory_fd, lock_fd, str(uuid.uuid4()))
        store._directory()
        return store
    except (OSError, TypeError, ValueError, KeyError, AttributeError, RuntimeError):
        for fd in (lock_fd, directory_fd, parent_fd):
            if fd is not None:
                try:
                    os.close(fd)
                except OSError:
                    pass
        if created:
            try:
                if destination is not None:
                    destination.rmdir()
            except OSError:
                pass
        raise CLICheckpointError() from None


@contextmanager
def recover_checkpoint(path):
    store = None
    try:
        store = _open_store(path, fresh=False)
        envelope, report = store._read()
        if envelope['state'] == 'checkpoint':
            report.update(status='partial', error=RECOVERY_REASON)
        yield report
    except (OSError, TypeError, ValueError, KeyError, AttributeError, OverflowError, RecursionError, RuntimeError):
        raise CLICheckpointError() from None
    finally:
        if store is not None:
            active = sys.exc_info()[0] is not None
            try:
                store.close()
            except CLICheckpointError:
                if not active:
                    raise
