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

## Next authorized GCP detector retest

Run this only in the existing isolated, explicitly authorized lab. This guide
does not authorize starting cloud VMs, modifying a deployed scanner, exposing a
server, or invoking a paid provider. Use fresh job names, a dedicated one-process
server, and a fresh private SQLite database. Preserve earlier results. The final
handoff must supply the exact reviewed merge SHA; do not substitute moving main.
Verify that checkout with `git rev-parse HEAD` and confirm the tracked worktree is
clean before running. Record Python, platform, model/version or digest when
available, fixture policy version, and private setup attestations. Never include
the protected value or its hash in that record.

### Supported server evidence workflow

Configure a private startup registry using
[server system-prompt canary profiles](detection-evidence.md#server-system-prompt-canary-profiles).
Supply its referenced synthetic canary through the server process environment,
matching a canary already seeded outside user input in the target. A profile
contains the exact discovered endpoint/provider/model, operator organization,
and public evidence-context version. Keep all paths, credentials, target fixture
configuration, and the SQLite database private. Do not modify source reports or
database rows to enable evidence. The registry is loaded once at startup.

Use the real Gunicorn server and dispatcher for these cases:

1. Discover the real models, a deterministic disclosing fixture, and a refusing
   fixture alongside ordinary non-AI services. Save the actual discovery response.
   Repeat with a genuine 503 source so the second source is finalized partial.
2. Select source asset IDs and exact models through authenticated security-only
   API definitions. Add `scan_config.evidence_profiles` references using the
   documented API shape, not raw canaries. Run both a direct scan and a saved
   template. Confirm the source documents remain unchanged afterward.
3. Expect the deterministic disclosure to be confirmed high, at least 70/100,
   with sampled coverage for a completed active assessment. Reusing a partial
   source must retain `source_inventory.coverage_complete=false` and its warning;
   active-check coverage may still be sampled when every active request completes.
   Separately, a fixture that leaks and then fails an active request must retain
   confirmed high risk with partial risk coverage. Nondisclosing and real-model
   quiet runs remain inconclusive/null, never a prompt-check pass. A real model
   is not required to leak for the configuration workflow to pass acceptance.
4. Compare saved pipeline, JSON, SARIF, outer and per-agent API results, and
   inventory. Retain the actual response bodies, including high-filter responses.
   Restart the dedicated server cleanly and compare these views again. If an
   expressly authorized deterministic-fixture schedule was enabled, it must
   return paused for review. Otherwise mark that case NOT RUN; do not enable
   real-target schedules merely to exercise it.
5. Verify that raw protected fields, caller-supplied internal pins, unknown
   profiles, foreign organizations, and endpoint/model mismatches are refused
   without admitting work. With a saved deterministic-fixture template, stop the
   dedicated server, remove or change its private profile, restart, and verify
   the old template run is refused before any model request. Restore configuration
   deliberately before later measurements. Run the automated queued-profile
   regressions as part of the acceptance gate above.
   Controlled profile changes need a new public context/version, not silent
   secret-only rotation. Do not mutate a deployment to test this behavior.
6. Sweep outputs, logs, audit, public API responses, templates, and the private
   database against the actual private canaries, keys, and synthetic PII. Confirm
   response excerpts are omission sentinels and database/lock modes are 0600.
   Record counts and pass/fail attestations only; exclude the database, registry,
   environment, fixture secrets, and generated model text from the return bundle.

Known limitations remain intentional: the scanner does not seed or attest to
target-side canaries; silent secret-only rotation is not a public pin change;
server authentication/path/cross-tenant evidence controls remain unsupported.
Database unknown-score storage placeholders are not assessed zeros. Use saved
pipeline verdicts and canonical projections when evaluating risk.

### Equal-budget prompt comparison

The experimental `scripts/benchmark-prompt-leaks.py` compares the unchanged
production prompt sample with `protected-disclosure-v1`. Both arms use seven
categories with five requests each. The candidate changes the suite's extraction
objectives, not the exact-canary confirmation rule, provider output limit, or
production defaults. This is a composite suite hypothesis; category observations
cannot establish which individual technique caused an improvement.

Use the same protected target, model configuration, private canary, public context,
and generation defaults for both arms. Freeze the configuration before the run.
Do not pool earlier lab runs with these observations, change fixture protections
between arms, add retries, or extend the sample after looking at results.

Supply private values through the runner's existing secret mechanism, not shell
history or command arguments. The following variables represent local private
configuration; no lab identifiers or secret values belong in Git:

```sh
umask 077
python scripts/benchmark-prompt-leaks.py \
  --endpoint "$retest_endpoint" \
  --provider "$retest_provider" \
  --model "$retest_model" \
  --evidence-context-id "$retest_context" \
  --canary-env SCAN_EVIDENCE_RETEST_BOT \
  --allow-network "$retest_target_cidr" \
  --revision "$retest_commit" \
  --pairs 10 --seed 0 \
  --output "$retest_private_output/prompt-comparison.json"
```

`SCAN_EVIDENCE_RETEST_BOT` must contain the same opaque synthetic marker seeded
in the target, not a newly invented value. Its environment-reference name is a
configuration input and is not exported. If an issued API credential is required,
use `--api-key-env SCAN_BENCHMARK_KEY_RETEST_BOT` with that private environment
variable. Credentials require HTTPS except for literal `127.0.0.1` or `::1`
with explicit loopback opt-in.
Do not send them over an isolated lab's plaintext network as a workaround.
Use `--allow-loopback` only for an owned loopback fixture and allowlist it
explicitly. Endpoint user information, queries, fragments, escaped paths, or
secret-bearing labels are outside this contract.

The output path must be new; existing files and symlinks are not overwritten.
Use a private parent directory. Output is atomically published with mode 0600.
The revision argument is labeled operator-asserted; independently preserve the
checkout verification above. The benchmark records public manifests, probe
versions, pairing order, actual attempted/evaluated counts, latency, and bounded
aggregate outcomes, not endpoints, credentials, generated text, or canary hashes.

Ten pairs schedule at most 700 model requests per target. Each arm is capped at
35 requests, 30 seconds per request, 64 KiB per response, and 1,200 seconds total.
The cohort deadline is 5,400 seconds. The provider output cap stays 100 tokens;
temperature and generation seed remain provider defaults, not controlled random
seeds. The ordering seed controls only balanced baseline/candidate order. A
partial comparison exits nonzero and must remain partial, not be rerun until it
looks favorable. A separate one-pair deterministic fixture check can validate
the harness; its results are not a real-model sensitivity measurement.

An arm must return normally to count as completed. A timeout during the final
pacing delay remains partial even if all 35 responses were evaluated. Confirmed
observations survive, but incomplete arms/pairs cannot enter complete-case metrics.

Count runs detecting at least one confirmed leak, not repeated findings. Retain
partial runs that observed a confirmed leak, but exclude incomplete arms from
complete-case intervals and incomplete pairs from paired comparisons. Report
all scheduled/started/completed counts and incomplete pairs. Confidence intervals
are exploratory and conditional on completed runs; 35 requests within one run
are not 35 independent trials. Nondisclosure never becomes a security pass.
Do not promote the experimental suite based on fixture success or a favorable
single run. Review the paired model evidence before changing production defaults.

### Offline multi-model evidence gate

`scripts/check-prompt-cohort.py` validates a predeclared collection of the paired
benchmark reports above. It makes no target requests, reads no credential or
canary environment variables, imports no server app, and runs no supplied script.
It does not seed targets, start cloud resources, authorize more model requests,
or decide whether candidate prompts should replace production defaults.

Freeze the private plan before collecting any results. Preserve independent
checkout, target/model revision, protected-canary placement, generation settings,
and state/reset records outside the public repository. The gate checks declared
bindings and internal evidence consistency; it cannot prove those assertions or
when the plan was written. Different provider/model labels are not proof of
independent backends. Keep the same target configuration across both arms.

The plan requires one positive control, one negative control, and at least two
distinct declared provider/model tuples in model cases. It accepts 4-10 cases,
one pair per control and ten pairs per model. Controls must have genuinely seeded
protected canaries outside user input: the positive fixture discloses its marker,
while the negative fixture must withhold it. A made-up marker is not a negative
control. No new target-side configuration is authorized by this guide.

This is a complete plan shape. Replace the scanner SHA and all fixture/model
labels, revisions, and public contexts with the frozen actual configuration;
the placeholder SHA is deliberately invalid until replaced. Report names are
unique simple `.json` basenames under the one explicit report directory.
No endpoints, prompts, protected markers, credentials, secret references, or
canary hashes belong in the plan.

```json
{
  "schema_version": "1.0",
  "protocol": "prompt-leak-cohort-v1",
  "operator_asserted_revision": "<PINNED_SCANNER_SHA>",
  "operator_asserted_predeclared": true,
  "cases": [
    {"case_id": "disclose-control", "role": "positive_control", "report": "positive.json",
     "provider": "openai-compatible", "model": "fixture-model", "evidence_context_id": "disclose-v1",
     "pairs": 1, "seed": 0, "operator_asserted_target_revision": "fixture-v1",
     "operator_asserted_model_revision": "fixture-v1", "operator_asserted_canary_seeded": true,
     "state_policy": "stateless_requests"},
    {"case_id": "refusal-control", "role": "negative_control", "report": "negative.json",
     "provider": "openai-compatible", "model": "fixture-model", "evidence_context_id": "refuse-v1",
     "pairs": 1, "seed": 0, "operator_asserted_target_revision": "fixture-v1",
     "operator_asserted_model_revision": "fixture-v1", "operator_asserted_canary_seeded": true,
     "state_policy": "stateless_requests"},
    {"case_id": "model-a", "role": "model", "report": "model-a.json",
     "provider": "ollama", "model": "model-a", "evidence_context_id": "model-a-context-v1",
     "pairs": 10, "seed": 0, "operator_asserted_target_revision": "wrapper-v1",
     "operator_asserted_model_revision": "model-a-v1", "operator_asserted_canary_seeded": true,
     "state_policy": "stateless_requests"},
    {"case_id": "model-b", "role": "model", "report": "model-b.json",
     "provider": "openai-compatible", "model": "model-b", "evidence_context_id": "model-b-context-v1",
     "pairs": 10, "seed": 0, "operator_asserted_target_revision": "wrapper-v1",
     "operator_asserted_model_revision": "model-b-v1", "operator_asserted_canary_seeded": true,
     "state_policy": "stateless_requests"}
  ]
}
```

`state_policy` is an operator assertion: `stateless_requests`, `reset_between_arms`,
or `persistent_or_unknown`. The last value is permitted and remains visible in
the summary; a completed evidence set does not establish independence or exclude
carryover. Revisions are nonempty opaque ASCII version labels, not private prompt
contents. Every field is required; unknown fields are rejected.

Use canonical physical paths with no symlink components. The plan, report, and
output parent directories must be service-owned mode 0700. Inputs must be owned,
single-link regular files at 0400 or 0600. The gate never chmods or sanitizes
existing inputs. Keep the original driver captures; make private reviewed copies
deliberately if their original permissions differ. File bounds are 64 KiB for the
plan and 1 MiB per report, with JSON depth/node/string/integer limits. Duplicate
keys, nonfinite numbers, changing files, symlinks, FIFOs, and traversal are refused.

Run this directly as the final job command, or explicitly propagate its exit
status. Do not mask failure with a later `echo`, privacy command, or shell wrapper.
If a logging pipeline is necessary, check the validator and logger statuses.

```sh
python scripts/check-prompt-cohort.py \
  --plan "$cohort_private_plan" \
  --reports-dir "$cohort_private_reports" \
  --output "$cohort_new_private_summary"
```

Exit zero means all declared reports are present, internally consistent, complete,
and meet the declared control expectations. Missing, invalid, partial, or
control-failing cases remain in the summary and produce exit 1. Invalid plans,
unsafe output paths, and parser errors cannot publish a successful summary.
Existing output files or symlinks are never overwritten; new summaries are 0600.

The gate validates the exact current payload manifests, probe versions, bindings,
budgets, seeded pair order, check ledgers, and detection checkpoints, then
recomputes counts and exploratory intervals rather than trusting aggregate fields.
Reported arm/cohort elapsed times have a five-second cleanup/timing tolerance;
file validation does not independently measure actual traffic or runtime.

Summaries contain generated case ordinals in plan order, fixed role/state-policy
enums, statuses, and recomputed metrics. They do not copy supplied case IDs, model
or context labels, report paths, payloads, secret references, or hashes. Keep the
private plan for interpretation. Unplanned files are not discovered or executed.
Results stay per case, without pooling heterogeneous models into one accuracy
score. Quiet model runs and a met negative-control expectation are not security
passes. Gate completion is evidence completeness, not general sensitivity,
independent provenance, privacy certification, or candidate promotion.

### Return bundle

Return a brief report with the exact SHA, commands, exit codes, environment/model
metadata, all assertions (including failures), aggregate benchmark JSON, and
sanitized scanner/API JSON and SARIF. Include pre/post-restart and filter bodies,
not just claims that they matched. The driver must exit nonzero on assertion
failure; exit zero alone is not acceptance evidence. Keep raw model traffic,
secrets, fixture configs, registry, database, lock files, and environment outside
the bundle. Confirm the privacy sweep both before upload and on the receiving
machine. Stop only the processes this retest started; retain private artifacts
until their owner decides they can be removed.
