"""Owned-child cleanup for the native HTTP retest guide, without scanner imports."""

import json
import time


MAX_PROCESSES = 512
MAX_EVENTS = 1024
MAX_PROBE_ERRORS = 512
MAX_DIAGNOSTIC_BYTES = 1024 * 1024


class OwnedChildren:
    """Retain identities, then settle and clean up within one five-second budget.

    Diagnostics deliberately contain no command, environment, path or exception
    message. A new Process object checks identity before every signal. Missing
    processes are complete; replacement PIDs and failed probes remain failures.
    """

    def __init__(self, process_library, *, clock=time.monotonic, sleep=time.sleep):
        self.library = process_library
        self.clock = clock
        self.sleep = sleep
        self.started = clock()
        self.entries = {}
        self.errors = []
        self.failures = set()
        self.event_count = 0

    def _event(self, entry, phase, state, error=None):
        event = {'phase': phase, 'state': state,
                 'elapsed_seconds': round(self.clock() - self.started, 6)}
        if error is not None:
            event['error_type'] = type(error).__name__
        events = entry['events']
        # Repeated polling states add no evidence and needlessly grow captures.
        if not events or any(events[-1].get(key) != event.get(key)
                             for key in ('phase', 'state', 'error_type')):
            if self.event_count < MAX_EVENTS:
                events.append(event)
                self.event_count += 1
            else:
                self.failures.add('owned_child_diagnostic_limit')
        entry['state'] = state

    def _error(self, operation, error, pid=None):
        self.failures.add('owned_child_probe_failed')
        event = {'operation': operation, 'error_type': type(error).__name__,
                 'elapsed_seconds': round(self.clock() - self.started, 6)}
        if pid is not None:
            event['pid'] = pid
        if len(self.errors) < MAX_PROBE_ERRORS:
            self.errors.append(event)
        else:
            self.failures.add('owned_child_diagnostic_limit')

    def observe(self, parent):
        """Discover descendants while the genuine Popen parent is still active."""
        if self.library is None:
            return
        try:
            children = self.library.Process(parent.pid).children(recursive=True)
        except self.library.NoSuchProcess as error:
            if parent.poll() is None:
                self._error('children', error, parent.pid)
            return
        except Exception as error:
            self._error('children', error, parent.pid)
            return
        for child in children:
            try:
                # Keep the identity supplied by the enumeration snapshot. A
                # fresh object's identity must agree before adopting the PID.
                created = child.create_time()
            except self.library.ZombieProcess as error:
                self._error('create_time', error, child.pid)
                continue
            except self.library.NoSuchProcess:
                # A child that vanished before an identity could be read cannot
                # be signaled. Its disappearance is not a surviving process.
                continue
            except Exception as error:
                self._error('create_time', error, child.pid)
                continue
            key = (child.pid, created)
            if key not in self.entries:
                if len(self.entries) >= MAX_PROCESSES:
                    self.failures.add('owned_child_tracking_limit')
                    break
                self.entries[key] = {'pid': child.pid, 'create_time': created,
                                     'forced_kill': False, 'events': []}
            self._probe(self.entries[key], 'observe')

    def _probe(self, entry, phase, deadline=None):
        def expired():
            return deadline is not None and self.clock() >= deadline

        if expired():
            return None
        try:
            current = self.library.Process(entry['pid'])
            if expired():
                return None
            if current.create_time() != entry['create_time']:
                self.failures.add('owned_child_pid_reused')
                self._event(entry, phase, 'pid_reused')
                return None
            if expired():
                return None
            state = current.status()
        except self.library.ZombieProcess as error:
            self.failures.add('owned_child_probe_failed')
            self._event(entry, phase, 'probe_failed', error)
            return None
        except self.library.NoSuchProcess:
            self._event(entry, phase, 'gone')
            return None
        except Exception as error:
            self.failures.add('owned_child_probe_failed')
            self._event(entry, phase, 'probe_failed', error)
            return None
        self._event(entry, phase, state)
        return current

    def _settle(self, entry, phase, deadline):
        current = self._probe(entry, phase, deadline)
        if current is None:
            return entry['state'] in ('gone', 'pid_reused')
        if self.clock() >= deadline:
            return False
        try:
            current.wait(timeout=0)
        except self.library.TimeoutExpired:
            return False
        except self.library.ZombieProcess as error:
            self.failures.add('owned_child_cleanup_failed')
            self._event(entry, phase, 'wait_failed', error)
            return False
        except self.library.NoSuchProcess:
            self._event(entry, phase, 'gone')
            return True
        except Exception as error:
            self.failures.add('owned_child_cleanup_failed')
            self._event(entry, phase, 'wait_failed', error)
            return False
        # In particular, a zombie is complete only after wait reaps it or a
        # fresh identity probe proves that it disappeared.
        self._event(entry, phase, 'wait_returned')
        self._probe(entry, phase, deadline)
        return entry['state'] in ('gone', 'pid_reused')

    def cleanup(self):
        """Allow <=1s natural exit/reap, sharing the existing total 5s budget."""
        began = self.clock()
        stop = began + 5
        natural_stop = began + 1
        pending = list(self.entries.values())
        def settle_pending(entries, phase, deadline):
            remaining = []
            for entry in entries:
                if self.clock() >= deadline or not self._settle(entry, phase, deadline):
                    remaining.append(entry)
            return remaining

        while pending:
            pending = settle_pending(pending, 'natural', natural_stop)
            remaining = natural_stop - self.clock()
            if not pending or remaining <= 0:
                break
            self.sleep(min(0.02, remaining))
        natural_elapsed = self.clock() - began
        while pending and self.clock() < stop:
            for entry in pending:
                if self.clock() >= stop:
                    break
                current = self._probe(entry, 'forced', stop)
                if current is None or entry['state'] == self.library.STATUS_ZOMBIE:
                    continue
                if self.clock() >= stop:
                    break
                if not entry['forced_kill']:
                    self.failures.add('surviving_owned_child')
                    # _probe uses fresh create_time/status; psutil.kill also
                    # guards PID reuse immediately before sending its signal.
                    try:
                        current.kill()
                        entry['forced_kill'] = True
                        self._event(entry, 'forced', 'kill_sent')
                    except self.library.NoSuchProcess:
                        self._event(entry, 'forced', 'gone')
                    except Exception as error:
                        self.failures.add('owned_child_cleanup_failed')
                        self._event(entry, 'forced', 'kill_failed', error)
            pending = settle_pending(pending, 'forced', stop)
            remaining = stop - self.clock()
            if pending and remaining > 0:
                self.sleep(min(0.02, remaining))
        if pending:
            self.failures.add('unreaped_owned_child')
        result = {'format_version': 'native-owned-child-cleanup-v1',
                'tracking_available': self.library is not None,
                'natural_budget_seconds': 1, 'total_budget_seconds': 5,
                'natural_elapsed_seconds': round(natural_elapsed, 6),
                'cleanup_elapsed_seconds': round(self.clock() - began, 6),
                'limits': {'processes': MAX_PROCESSES, 'events': MAX_EVENTS,
                           'probe_errors': MAX_PROBE_ERRORS,
                           'diagnostic_bytes': MAX_DIAGNOSTIC_BYTES},
                'processes': list(self.entries.values()), 'probe_errors': self.errors,
                'failure_codes': sorted(self.failures)}
        if len(json.dumps(result, sort_keys=True).encode('utf-8')) > MAX_DIAGNOSTIC_BYTES:
            self.failures.add('owned_child_diagnostic_limit')
            return {'format_version': 'native-owned-child-cleanup-v1',
                    'diagnostic_overflow': True, 'failure_codes': sorted(self.failures)}
        return result
