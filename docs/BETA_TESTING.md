# Local beta testing

Status: reopened for limited single-operator beta testing on runtime revision
`82ee7d5` after reviewed lab remediation and targeted API acceptance. This is not
production or enterprise approval, and results must not be the sole basis for
operational risk decisions. Detection sensitivity remains unvalidated. See the
[remediation gate](BETA_REMEDIATION.md) and [evidence limits](detection-evidence.md).

This is a finite acceptance gate for the documented single-operator beta, not
completion of every engineering milestone. The supported server is one process
on POSIX with local file-backed SQLite. Start with the offline fixture below;
it needs no provider account, model, external target, or provider API credential.

## Automated acceptance

Activate the checkout's Python 3.10-3.13 environment and install `.[dev,server]`.
Run from the repository root:

```sh
python -m pip install --upgrade pip setuptools
python -m pytest tests/
ruff check .
bandit -r src app.py scanner_cli.py cli.py -ll
python -m pip check
pip-audit
python -m build
python -m twine check dist/*
sh scripts/package-smoke.sh dist/*.whl
python scripts/acceptance-backup-restore.py --timeout-seconds 5
python -O scripts/acceptance-backup-restore.py --timeout-seconds 5
```

`pip-audit` includes installed environment tooling, not only project requirements.
Use a fresh environment with current pip and setuptools; record and investigate
any advisory rather than excluding tooling to obtain a green result.
The backup commands canonicalize their created temporary root, so the default
macOS `/var` alias needs no `TMPDIR` workaround. Database and child-directory
symlinks are still rejected.

The optional [Chromium check](DEVELOPMENT.md#optional-chromium-dashboard-checks)
needs Playwright and Chromium. Run it with ordinary Python and `PYTHONOPTIMIZE`
unset: its browser assertions are not valid acceptance under optimized Python.
It owns its loopback server/database and retains screenshots and logs.

The [queue workload](performance.md) checks terminal consistency, audit history,
unique claims, and concurrency bounds. Repeated finite runs are a regression
profile, not a long-duration soak or production throughput measurement.

Before calling a revision test-ready, require independent review, all required CI
jobs green on its PR and merged commit, current full-suite/package/security checks,
the browser check, both backup checks, and the recorded queue profile. Record the
tested commit with `git rev-parse HEAD`; [validation](VALIDATION.md) records results
and limitations. A later source change needs the relevant checks again.
Documentation-only updates do not change the tested runtime and do not require
another cloud run. New runtime changes require risk-proportionate revalidation.

Server request budgets use `SCAN_MAX_REQUESTS` (default 500, maximum 10000)
and `SCAN_TIMEOUT_SECONDS` (default 300, maximum 3600). Active model requests use
`SCAN_REQUEST_TIMEOUT_SECONDS` (integer 1-300, default 30); this does not extend
the whole-scan deadline or trigger retries. CLI `scan`/`discover` expose bounded
`--max-requests`, `--max-response-bytes`, `--timeout-seconds`, and
`--request-timeout-seconds`. Loopback requires `--allow-loopback`. A request budget
is a cap for the whole scan, not a retry count. Resource limits do not establish
complete security coverage.

## Start an isolated, offline workspace

Use the checkout environment with `.[server]` installed. These commands assume a
POSIX shell, OpenSSL, and an unused local port 5000. Run from the repository root:

```sh
umask 077
beta_repo=$(pwd -P)
beta_data=$(mktemp -d /tmp/ai-scanner-beta-XXXXXX)
beta_secret=$(openssl rand -hex 32)
beta_key=$(openssl rand -hex 32)
printf 'Database directory: %s\nOperator key: %s\n' "$beta_data" "$beta_key"
env -i PATH="$PATH" \
  SECRET_KEY="$beta_secret" OPERATOR_API_KEY="$beta_key" \
  OPERATOR_ORGANIZATION_ID=offline-beta FLASK_DEBUG=false \
  DATABASE_URL="sqlite:///$beta_data/scanner.sqlite" \
  SCAN_ALLOWED_NETWORKS="" SCAN_ALLOW_LOOPBACK=false \
  SCAN_ALLOWED_PATH_ROOTS="$beta_repo/examples/offline-lab" \
  SCAN_TIMEOUT_SECONDS=30 SCAN_MAX_QUEUED=4 MAX_CONCURRENT_SCANS=2 \
  gunicorn --chdir "$beta_repo" --config "$beta_repo/gunicorn.conf.py" \
  --bind 127.0.0.1:5000 --workers 1 --threads 4 app:app
```

The empty environment prevents inherited provider keys or target policy from
changing this exercise. Only the static fixture directory is allowed. The fixture
contains an SDK import for inventory; it is read as text and must not be executed.
The operator key printed in your terminal is a local secret. Do not paste it into
issues, screenshots, saved recipes, or reports. The application does not load
`.env` automatically.

The fresh database is private and separate from any existing instance. These
commands leave it in the printed directory for repeat tests. Keep this shell open
so the `beta_*` values remain available. This is a local test server, not a remote
deployment recipe; do not change its bind address to expose it.

## Operator walkthrough

1. Open `http://127.0.0.1:5000`. Confirm a wrong key is rejected, then sign in with
   the printed operator key.
2. Keep **Assessment mode** at **Discovery only**. Leave **Networks and domains**
   empty. Open **Repository and traffic inputs** and set **Repository paths** to
   the absolute checkout path followed by `/examples/offline-lab`. Leave traffic
   inputs empty. Queue the scan.
3. Expect a completed inventory with an OpenAI SDK observation, no configured
   endpoint or confirmed vulnerability, and risk **Not assessed**. An import is
   not proof of a running service or a security defect. Inspect the admitted,
   claimed, and terminal audit events and download JSON and SARIF.
4. Save this form as a new template, load it, and run its saved revision. Confirm
   a separate scan/report appears. Saving or loading alone must not start work.
5. Optionally review the saved pin, create a disabled schedule with a 60-second
   interval and one total run, and confirm creation does not scan. Explicitly
   enable it. After the interval, use **Refresh detail** and **Refresh occurrences**
   (schedule views do not poll), then open the single admitted occurrence/report.
   This scans only the local fixture. Pause/delete inactive schedules when done;
   deleting a recipe or schedule must not delete prior reports.
6. Sign out and confirm protected results clear. Sign back in to reopen history.
   Refreshing the page also clears the browser's in-memory token.
7. Stop Gunicorn with Ctrl-C and wait for it to exit fully. Repeat only the
   `env -i ... gunicorn ...` command above, keeping the same directory and keys.
   Verify saved history/templates/reports remain. Any still-enabled schedule must
   pause for restart review; previously active scans are not replayed. Do not use
   overlapping reloads or start a second process against this database.

Use a new `beta_data` and new keys for a fresh run. Stop the server when finished.
The test directory is intentionally retained; remove it only after confirming its
exact printed path and that you no longer need its reports. Rotating `SECRET_KEY`
invalidates tokens; rotating only the operator key does not revoke issued tokens.

## What this does not sign off

This gate does not certify security or production readiness. Representative
real-provider accuracy, long-duration load/soak, comprehensive accessibility and
screen-reader evaluation, deployed backup/upgrade procedures, enterprise identity,
immutable audit, PostgreSQL/distributed operation, and new external integrations
remain deferred or require separate deployment contracts and authorization.
No package publication or remote deployment is implied by a green gate.

After this gate passes, stop adding features for this beta and collect operator
feedback. Record any failure with the tested SHA, redacted reproduction, expected
behavior, and actual behavior. Never attach credentials or protected canaries.
