"""Persistent jobs with atomic claims and bounded execution for one server process."""

import logging
import threading
import uuid
from concurrent.futures import ThreadPoolExecutor, wait
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy import select, update, insert, func


TERMINAL_STATES = frozenset({"completed", "partial", "failed", "cancelled", "interrupted"})


class DispatcherLock:
    """Hold exclusive ownership across recovery and every active worker."""

    def __init__(self, engine):
        self.engine, self.handle = engine, None

    def acquire(self):
        if self.engine.dialect.name == "sqlite":
            database = self.engine.url.database
            if not database or database == ":memory:" or self.engine.url.query.get("mode") == "memory":
                raise RuntimeError("Persistent jobs require a file-backed SQLite database")
            try:
                import fcntl
            except ImportError as exc:
                raise RuntimeError("SQLite dispatcher locking requires a POSIX server") from exc
            path = Path(database).resolve()
            handle = path.with_name(path.name + ".dispatcher.lock").open("a")
            try:
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError as exc:
                handle.close()
                raise RuntimeError("Another dispatcher owns this database") from exc
            self.handle = handle
        else:
            raise RuntimeError("Persistent jobs currently require SQLite; other database dispatchers are not implemented")

    def release(self):
        if self.handle is None:
            return
        self.handle.close()
        self.handle = None


class JobStore:
    def __init__(self, engine, jobs, scans, results, audit):
        self.engine, self.jobs, self.scans, self.results = engine, jobs, scans, results
        self.audit = audit

    def _event(self, connection, scan_id, event, previous, status):
        tenant = connection.scalar(select(self.scans.c.organization_id).where(self.scans.c.id == scan_id))
        if tenant is None:
            raise ValueError("Job has no scan session")
        connection.execute(insert(self.audit).values(
            scan_id=scan_id, organization_id=tenant, event=event,
            previous_status=previous, status=status, created_at=datetime.now(timezone.utc)))

    def queued_count(self):
        with self.engine.connect() as connection:
            return connection.scalar(select(func.count()).select_from(self.jobs).where(
                self.jobs.c.status == "queued"))

    def claim(self, owner):
        """Only the winner of the conditional update may execute a job."""
        with self.engine.begin() as connection:
            scan_id = connection.scalar(select(self.jobs.c.scan_id).where(
                self.jobs.c.status == "queued").order_by(self.jobs.c.created_at, self.jobs.c.scan_id).limit(1))
            if scan_id is None:
                return None
            claimed = connection.execute(update(self.jobs).where(
                self.jobs.c.scan_id == scan_id, self.jobs.c.status == "queued",
            ).values(status="running", owner=owner, started_at=datetime.now(timezone.utc)))
            if claimed.rowcount != 1:
                return None
            connection.execute(update(self.scans).where(self.scans.c.id == scan_id).values(
                status="running", started_at=datetime.now(timezone.utc)))
            self._event(connection, scan_id, "claimed", "queued", "running")
            return scan_id

    def _finalize(self, connection, scan_id, status, error=None, output=None):
        now = datetime.now(timezone.utc)
        scan = connection.execute(select(self.scans).where(self.scans.c.id == scan_id)).mappings().first()
        if not scan:
            raise ValueError("Job has no scan session")
        previous = connection.scalar(select(self.jobs.c.status).where(self.jobs.c.scan_id == scan_id))
        connection.execute(update(self.jobs).where(self.jobs.c.scan_id == scan_id).values(
            status=status, completed_at=now))
        connection.execute(update(self.scans).where(self.scans.c.id == scan_id).values(
            status=status, completed_at=now))
        result = connection.scalar(select(self.results.c.result).where(self.results.c.scan_id == scan_id))
        output = dict(output) if output is not None else dict(result) if result is not None else {
            "schema_version": "1.0", "scan_id": scan_id, "scan_type": scan["scan_type"],
            "agents": [], "security_results": [], "risk_assessments": [], "summary": {},
        }
        output["status"] = status
        if error:
            output["error"] = error
        if result is None:
            connection.execute(insert(self.results).values(scan_id=scan_id, result=output))
        else:
            connection.execute(update(self.results).where(self.results.c.scan_id == scan_id).values(result=output))
        self._event(connection, scan_id, "terminal", previous or scan["status"], status)

    def _locked_status(self, connection, scan_id):
        connection.execute(update(self.jobs).where(self.jobs.c.scan_id == scan_id).values(
            status=self.jobs.c.status))
        return connection.scalar(select(self.jobs.c.status).where(self.jobs.c.scan_id == scan_id))

    def save_result(self, scan_id, output, agents_table, snapshots):
        """Commit the report, snapshots, terminal queue state and event together."""
        if output["status"] not in {"completed", "partial"}:
            raise ValueError("Pipeline result must be completed or partial")
        with self.engine.begin() as connection:
            status = self._locked_status(connection, scan_id)
            if status in TERMINAL_STATES:
                return
            if status is None:
                scan_status = connection.scalar(select(self.scans.c.status).where(self.scans.c.id == scan_id))
                if scan_status in TERMINAL_STATES:
                    return
                if scan_status is None:
                    raise ValueError("Job has no scan session")
            summary = output["summary"]
            connection.execute(update(self.scans).where(self.scans.c.id == scan_id).values(
                agents_discovered=summary["agents_discovered"],
                vulnerabilities_found=summary["vulnerabilities_found"],
                critical_risks=summary["critical_risks"],
                overall_risk_score=summary["overall_risk_score"] or 0.0, progress=100.0))
            if snapshots:
                connection.execute(insert(agents_table), snapshots)
            if status == "cancel_requested":
                self._finalize(connection, scan_id, "cancelled", "Scan cancelled by operator", output)
            else:
                self._finalize(connection, scan_id, output["status"], output=output)

    def finish(self, scan_id, error=None, *, status=None):
        explicit_status = status is not None
        with self.engine.begin() as connection:
            # Lock before reading so a concurrent accepted cancellation cannot be overwritten.
            job_status = self._locked_status(connection, scan_id)
            if job_status in TERMINAL_STATES:
                return
            scan_status = connection.scalar(select(self.scans.c.status).where(self.scans.c.id == scan_id))
            if job_status is None and (scan_status is None or scan_status in TERMINAL_STATES):
                return
            status = status or scan_status
            if job_status == "cancel_requested":
                status, error = "cancelled", "Scan cancelled by operator"
            elif (error and not explicit_status) or status not in TERMINAL_STATES:
                status, error = "failed", error or "Worker exited without a terminal result"
            self._finalize(connection, scan_id, status, error)

    def cancel(self, scan_id):
        with self.engine.begin() as connection:
            status = self._locked_status(connection, scan_id)
            if status == "queued":
                self._finalize(connection, scan_id, "cancelled", "Scan cancelled before execution")
                return "cancelled"
            if status == "cancel_requested":
                return "cancel_requested"
            changed = connection.execute(update(self.jobs).where(
                self.jobs.c.scan_id == scan_id, self.jobs.c.status == "running",
            ).values(status="cancel_requested"))
            if changed.rowcount:
                self._event(connection, scan_id, "cancel_requested", "running", "cancel_requested")
            return "cancel_requested" if changed.rowcount else None

    def cancellation_requested(self, scan_id):
        with self.engine.connect() as connection:
            return connection.scalar(select(self.jobs.c.status).where(
                self.jobs.c.scan_id == scan_id)) == "cancel_requested"

    def recover(self):
        """Call only at exclusive server startup; never replay previously active probes."""
        with self.engine.begin() as connection:
            active = connection.execute(select(self.jobs.c.scan_id, self.jobs.c.status).where(
                self.jobs.c.status.in_(("running", "cancel_requested")),
            )).all()
            for scan_id, status in active:
                terminal = "cancelled" if status == "cancel_requested" else "interrupted"
                self._finalize(connection, scan_id, terminal, "Server stopped before scan completion")
            # Earlier releases had threads but no persisted queue record.
            legacy = connection.scalars(select(self.scans.c.id).where(
                self.scans.c.status.in_(("pending", "running")),
                ~self.scans.c.id.in_(select(self.jobs.c.scan_id)),
            )).all()
            for scan_id in legacy:
                self._finalize(connection, scan_id, "interrupted", "Legacy scan had no recoverable job")
            return len(active) + len(legacy)


class JobDispatcher:
    def __init__(self, store, run, workers=2, poll_seconds=0.25, initialize=None):
        if workers < 1 or poll_seconds <= 0:
            raise ValueError("Worker count and poll interval must be positive")
        self.store, self.run = store, run
        self.workers, self.poll_seconds = workers, poll_seconds
        self.owner = uuid.uuid4().hex
        self._stop = threading.Event()
        self._wake = threading.Event()
        self._thread = None
        self._executor = None
        self._active = {}
        self._lock = threading.Lock()
        self._healthy = False
        self._ownership = DispatcherLock(store.engine)
        self.logger = logging.getLogger(__name__)
        self.initialize = initialize

    @property
    def ready(self):
        return bool(self._healthy and self._thread and self._thread.is_alive() and not self._stop.is_set())

    def start(self):
        with self._lock:
            if self._thread is not None:
                raise RuntimeError("Dispatcher has already been started")
            self._ownership.acquire()
            try:
                if self.initialize:
                    self.initialize()
                self.store.recover()
                self._executor = ThreadPoolExecutor(max_workers=self.workers, thread_name_prefix="scan-job")
                self._thread = threading.Thread(target=self._loop, name="scan-dispatcher", daemon=True)
                self._healthy = True
                self._thread.start()
            except Exception:
                self._ownership.release()
                if self._executor:
                    self._executor.shutdown(wait=False)
                raise

    def wake(self):
        self._wake.set()

    def stop(self, timeout=5):
        self._stop.set()
        self._wake.set()
        if self._thread:
            self._thread.join(timeout)
        if self._executor:
            _, pending = wait([future for future, _ in self._active.values()], timeout=timeout)
            self._executor.shutdown(wait=False, cancel_futures=True)
            if not pending and (not self._thread or not self._thread.is_alive()):
                self._ownership.release()

    def _work(self, scan_id, cancelled):
        error = None
        try:
            self.run(scan_id, cancelled)
        except Exception:
            error = "Scan worker failed"
            self.logger.error("Scan worker failed for %s", scan_id)
        finally:
            self.store.finish(scan_id, error)

    def _tick(self):
        for scan_id, (future, cancelled) in list(self._active.items()):
            if future.done():
                try:
                    future.result()
                except Exception:
                    # Retry transient persistence failures before releasing worker capacity.
                    self.store.finish(scan_id)
                del self._active[scan_id]
            elif self._stop.is_set() or self.store.cancellation_requested(scan_id):
                cancelled.set()
        if self._stop.is_set():
            return
        while not self._stop.is_set() and len(self._active) < self.workers:
            scan_id = self.store.claim(self.owner)
            if scan_id is None:
                break
            cancelled = threading.Event()
            self._active[scan_id] = (self._executor.submit(self._work, scan_id, cancelled), cancelled)

    def _loop(self):
        while True:
            try:
                self._tick()
                self._healthy = True
            except Exception:
                self._healthy = False
                self.logger.error("Job dispatcher could not access or finalize its queue")
            if self._stop.is_set():
                for _, cancelled in self._active.values():
                    cancelled.set()
                break
            self._wake.wait(self.poll_seconds)
            self._wake.clear()
