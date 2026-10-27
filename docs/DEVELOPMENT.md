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
out of the checkout, and runs version, command help, static framework mapping,
and offline evaluation checks. It also compares the installed CLI's structured
source/catalog identity against the checkout and distribution metadata.
An owned static-source fixture also exercises installed CLI checkpoint persistence
and offline recovery, preserving completed discovery and unknown risk.
It requires package index access to install dependencies.

`src/_version.py` owns the development package version. Setuptools, CLI, server
health and MCP client information share it; evidence, protocol, database and
ruleset versions retain their own meanings. See [build identity](build-identity.md)
before interpreting a saved report's producer or a current exporter's version.

Synthetic API, local-lab, and queue fixtures must not load the operator's private
evidence registry. They clear `SCAN_EVIDENCE_PROFILES_FILE` before importing the
app. Unit fixtures temporarily replace a cached registry with an empty one and
restore it afterward; the standalone queue benchmark refuses a cached nonempty
registry before database access. This is harness isolation, not a change to
normal server startup or its configured profiles. Keep using the fixtures'
private database and dispatcher guards; do not point tests at an operator app.
Offline operator fixtures use the same isolation. Backup acceptance keeps its
outer child-environment filter and also clears the registry at the inner entrypoint;
cached nonempty registries are rejected before database access there as well.

## Optional Chromium dashboard checks

The mandatory Node controller suite runs through pytest. A separate optional
browser smoke test uses real Flask authentication, SQLite, and the dispatcher,
with synthetic scanner engines and seeded scan records only. It never accepts
an external base URL or an existing database. Playwright is not a runtime
dependency. From the checkout, create an isolated environment:

```sh
browser_env=$(mktemp -d /tmp/ai-scanner-browser-env-XXXXXX)
python3 -m venv "$browser_env"
"$browser_env/bin/python" -m pip install -e '.[server]' playwright
"$browser_env/bin/python" -m playwright install chromium
"$browser_env/bin/python" scripts/dashboard-browser-smoke.py
```

Chromium may need operating-system libraries on a fresh machine. The smoke test
starts an OS-assigned loopback server and owns a fresh temporary database. It
stops the server and removes the database on success or a handled failure.
Screenshots and fixture logs remain in the newly created artifact directory
printed at startup. `--artifacts-dir /absolute/new-directory` selects a new
destination; an existing destination is rejected to avoid overwrites.
`--fail-after-start` deliberately raises an assertion after fixture startup to
exercise server cleanup and should exit nonzero.

Assertions cover linked guidance, named scroll regions, bounded check pages,
keyboard focus ownership, terminal announcements and stale/authentication guards,
control contrast, and 320/390/1440-pixel reflow. This is not a comprehensive
accessibility audit, screen-reader test, or real-provider compatibility check.

## Container

```sh
docker build -t ai-agent-scanner .
export SECRET_KEY="$(openssl rand -hex 32)"
export OPERATOR_API_KEY="$(openssl rand -hex 32)"
export OPERATOR_ORGANIZATION_ID=local-lab
export SCAN_ALLOWED_NETWORKS=127.0.0.1/32
export SCAN_ALLOW_LOOPBACK=true
docker run --rm -p 127.0.0.1:5000:5000 \
  -e SECRET_KEY -e OPERATOR_API_KEY -e OPERATOR_ORGANIZATION_ID \
  -e SCAN_ALLOWED_NETWORKS -e SCAN_ALLOW_LOOPBACK \
  -v scanner-data:/app/instance ai-agent-scanner
```

Enter the operator key at `http://127.0.0.1:5000`. These exports explicitly allow
only container loopback targets; host services are not container loopback.
Choose only authorized scope, and leave filesystem roots unset to deny file scans.
The application does not load `.env` automatically. Keep keys outside version
control and reuse them only for the same intended local deployment. An unset
operator key disables login and protected API routes.

The container initializes missing database tables and starts Gunicorn as an
unprivileged user. Keep one worker and one server instance per database. Queued
jobs survive restarts; active jobs are marked interrupted and are not replayed.
Startup accepts only the documented SQLite layouts and reaches schema 6.
Versions 1 through 3 first receive nullable risk caches; schema 4 already has them.
Schema 5 adds inventory generations, recognized triggers, and candidate indexes
while preserving existing rows, scalar caches, and archived reports. Schema 6
reconciles obsolete access-policy caches without rebuilding tables or rewriting
archives, with existing trigger invalidation for affected observations. Stop and
back up the database before upgrading; see [schema upgrades](jobs.md#schema-upgrades).
The default SQLite database lives in
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
Installed-wheel smoke checks the live MCP inventory and controlled-policy commands
and imports their implementations
without contacting an endpoint. Network and live MCP tests use local HTTP/DNS
fixtures; explicit parser-depth limits do not depend on Python recursion behavior.
The installed-wheel smoke also imports and validates the finite scheduling helper
without starting a dispatcher or enabling a schedule.

A published GitHub release reruns CI and publishes the distribution artifacts
produced by that successful run through the `pypi` environment. Configure its
protection rules and PyPI trusted publisher before releasing. Merging a PR does
not publish a package. Workflow actions use pinned commit IDs and an explicit
Ubuntu runner version. CI downloads its uploaded distributions and verifies their
contents; artifact digest mismatches fail download. Review upstream changes before
updating pins. Dependency ranges are currently resolved during each
build; a fully reproducible deployment lock remains future work.
