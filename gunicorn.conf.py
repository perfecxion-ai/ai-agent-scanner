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
    from app import stop_job_dispatcher
    stop_job_dispatcher()
