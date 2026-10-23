"""Explicit dispatcher claims for direct isolated API workflow fixtures."""

from contextlib import contextmanager
import uuid

from src.core.jobs import worker_claim, TERMINAL_STATES


@contextmanager
def claimed_job(module, scan_id):
    owner = 'fixture-' + uuid.uuid4().hex
    with module.app.app_context():
        scan = module.db.session.get(module.ScanSession, scan_id)
        job = module.db.session.get(module.ScanJob, scan_id)
        if scan is not None:
            if job is None:
                job = module.ScanJob(scan_id=scan_id, status='queued')
                module.db.session.add(job)
            if job.status not in TERMINAL_STATES:
                previous = job.status
                job.owner = owner
                if previous != 'cancel_requested':
                    job.status = 'running'
                scan.status = 'running'
                module.db.session.flush()
                if previous == 'queued':
                    module._get_job_store()._event(module.db.session.connection(), scan_id,
                                                   'claimed', 'queued', 'running')
            module.db.session.commit()
    with worker_claim(scan_id, owner):
        yield


async def execute_scan(module, scan_id, *args, **kwargs):
    with claimed_job(module, scan_id):
        return await module._execute_scan(scan_id, *args, **kwargs)


def execute_job(module, scan_id, *args, **kwargs):
    with claimed_job(module, scan_id):
        return module._execute_job(scan_id, *args, **kwargs)


def run_scan_in_thread(module, scan_id, *args, **kwargs):
    with claimed_job(module, scan_id):
        return module._run_scan_in_thread(scan_id, *args, **kwargs)

