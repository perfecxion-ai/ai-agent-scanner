"""Lifecycle hooks for the single-process persistent job dispatcher."""

import os

# Gunicorn applies this setting to its own socket and worker temporary files.
umask = 0o077


def _private_worker_mask(worker):
    if worker.cfg.workers != 1:
        raise RuntimeError("Persistent job execution currently requires exactly one Gunicorn worker")
    os.umask(0o077)


def post_fork(server, worker):
    # With normal non-preloaded startup, protect directories made on app import.
    # Existing operator files, parent directories, and volumes are not changed.
    _private_worker_mask(worker)


def post_worker_init(worker):
    # Reassert the worker mask before creating SQLite and dispatcher lock files.
    _private_worker_mask(worker)
    from app import start_job_dispatcher
    start_job_dispatcher()


def worker_exit(server, worker):
    # Gunicorn can invoke this hook in the master after an ESRCH result. Only
    # the actual worker may import the app, stop its dispatcher or close its
    # inherited descriptors. The master's listener and pathname remain owned.
    if os.getpid() != getattr(worker, 'pid', None):
        return
    failures = []
    try:
        from app import stop_job_dispatcher
        if stop_job_dispatcher() is not True:
            raise RuntimeError('Server dispatcher shutdown incomplete')
    except BaseException:
        failures.append('dispatcher')
    finally:
        for listener in worker.sockets:
            try:
                # Close this process's raw descriptor. A wrapper's close may
                # unlink a Unix pathname still used by the master process.
                descriptor = getattr(listener, 'sock', listener)
                if descriptor is not None:
                    descriptor.close()
            except BaseException:
                if 'listener' not in failures:
                    failures.append('listener')
    if failures:
        raise RuntimeError('Server worker cleanup failed: ' + ', '.join(failures)) from None
    worker.log.info('Scan worker cleanup ok pid=%s', os.getpid())
