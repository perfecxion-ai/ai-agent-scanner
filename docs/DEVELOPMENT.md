# Development and delivery

Use Python 3.10 through 3.13. Install the project and development tools together:

```sh
python -m venv .venv
. .venv/bin/activate
python -m pip install '.[dev]'
ruff check .
python -m pytest tests/
python -m build
python -m twine check dist/*
sh scripts/package-smoke.sh dist/*.whl
```

`pyproject.toml` owns dependency declarations. `requirements.txt` installs the
local project and its runtime dependencies. Add `[cloud]` for cloud discovery
SDKs or `[server]` for Gunicorn. The wheel provides the CLI; the web application,
templates, and static files are delivered from the checkout or container.

The smoke script installs a wheel into a temporary virtual environment, changes
out of the checkout, and runs version, help, and framework coverage commands.
It requires package index access to install dependencies.

## Container

```sh
docker build -t ai-agent-scanner .
docker run --rm -p 127.0.0.1:5000:5000 \
  -e SECRET_KEY="$(openssl rand -hex 32)" \
  -v scanner-data:/app/instance ai-agent-scanner
```

The container initializes missing database tables and starts Gunicorn as an
unprivileged user. Keep one worker and one server instance per database. Queued
jobs survive restarts; active jobs are marked interrupted and are not replayed.
Table creation adds the job and result tables but does not alter existing table
schemas. The default SQLite database lives in
`/app/instance`; use a volume to retain it between containers. TLS belongs at the
deployment proxy. Review authentication configuration before exposing the server.
The persistent dispatcher currently requires file-backed SQLite on a POSIX
server; PostgreSQL and distributed execution are not implemented. Start Gunicorn
with `--config gunicorn.conf.py` so its lifecycle hooks start and stop the queue.
The development server (`python app.py`) binds only to `127.0.0.1` and disables
the reloader to avoid duplicate dispatchers. See [job operations](jobs.md).

## CI and publication

CI checks all Python files with Ruff, runs tests and installed-wheel smoke checks
on all supported Python versions, audits resolved dependencies (including cloud
and server extras), runs Bandit, and builds and starts the container. Dependency
audit failures fail CI. The dependency audit needs access to the advisory service.

A published GitHub release reruns CI and publishes the distribution artifacts
produced by that successful run through the `pypi` environment. Configure its
protection rules and PyPI trusted publisher before releasing. Merging a PR does
not publish a package. Dependency ranges are currently resolved during each
build; a fully reproducible deployment lock remains future work.
