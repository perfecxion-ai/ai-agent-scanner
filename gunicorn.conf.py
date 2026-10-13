"""Lifecycle hooks for the single-process persistent job dispatcher."""


def post_worker_init(worker):
    if worker.cfg.workers != 1:
        raise RuntimeError("Persistent job execution currently requires exactly one Gunicorn worker")
    from app import start_job_dispatcher
    start_job_dispatcher()


def worker_exit(server, worker):
    from app import stop_job_dispatcher
    stop_job_dispatcher()
