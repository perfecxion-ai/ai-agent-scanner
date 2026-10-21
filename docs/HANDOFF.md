# Continuation handoff

## Current hold

External lab validation found verdict accuracy, evidence privacy, mixed-network
workflow, and macOS acceptance defects in the prior beta. The earlier local-beta
finish checkpoint below is historical infrastructure acceptance, not release
approval. Follow the [remediation gate](BETA_REMEDIATION.md) before reopening the
beta. Keep the source lab report and raw artifacts local and private.

The first remediation PR adds private atomic exports, macOS temporary-root
canonicalization, and native macOS CI. Its PR and merged revision passed all
eight jobs. The verdict follow-up changes stochastic nondisclosure to inconclusive,
uses severity-floor-v2 scoring without duplicate-sample inflation, preserves
confirmed partial risk, omits generated text, and keeps exception logs static.
Historical scoring is not recalculated or displayed as a current verdict.
Local verdict acceptance is 1150 Python cases, 82 Node cases, and synthetic
Chromium. The next network/deadline slice passes 1194 combined local tests with
mixed-service and protocol-negative regressions, pre-I/O metadata blocking,
bounded hosts resolution, consistent CIDRs, and secret-safe MCP TLS errors.
The operator slice adds finalized partial-source reuse with matching snapshots,
canonical/snapshot model IDs, actual CLI model calls, bounded CLI/server budgets,
and an explicit MCP sampled-page warning. Corrupt source arrays/metadata are
rejected before admission; source changes preserve schedule conflict semantics.
See validation for combined acceptance. The beta hold remains in effect until an
explicitly authorized real-service retest and the readiness gates pass.

A related storage follow-up protects new server state in actual Gunicorn worker
hooks and container startup, without changing the importing process's umask or
chmod on existing data. The image instance directory is private; container CI
checks directory/database/lock modes and service ownership across restart.
Local acceptance is now 1242 cases with seven new storage regressions. Existing
volumes/parents and historical reports still need explicit operator review.

## Original checkpoint

Baseline: `b5efe3f`, main after PRs #1 through #14. The working tree was clean and
all seven CI jobs passed. Local validation recorded 422 pytest cases, 11 Node
controller tests, and 78% line coverage across the source, API, and CLI.
Desktop and mobile browser fixtures cover authentication, queue/cancellation,
history, source model selection, and exports. See [validation](VALIDATION.md)
for limits on those measurements.

The repository has a shared CLI/API pipeline, conservative evidence handling,
scope and transport enforcement, a durable SQLite queue, passive MCP assessment,
offline replay, report comparison, and expiring suppression policies. The broader
milestones in [the engineering plan](ENGINEERING_PLAN.md) remain partially complete.

## Completed continuation slices

PRs #15 through #22 persist the delivery rules, pin CI actions, strengthen
traffic/cloud discovery, add check contracts, version known SQLite upgrades,
persist audit events, add queue-load acceptance, and expose evidence/audit
history in the dashboard. The acceptance results below cover local fixtures,
not a production release or all milestones. The updated measured checkpoint is
in [validation](VALIDATION.md).

### 1. Make discovery failure and resource identity reliable

Cloud inventory and traffic parsing now parse URLs and structured records,
bound file and SDK pagination work, preserve stable resource identities, and
expose unavailable or failed sources without losing successful observations.
Cloud resources require resource-specific identity;
a shared provider runtime URL cannot identify several deployed models.

Acceptance: positive and negative HAR/JSON/text fixtures, spoofed-host rejection,
no credential retention, stable repeated discovery, bounded reads/pagination,
missing SDK and provider failures distinct from successful empty inventory.
SDK fixtures run without real provider accounts.

### 2. Complete the scan and check contracts

Typed scan, asset, finding, and evidence records and versioned check records
preserve existing JSON/SARIF consumers and record execution and oracle outcomes
explicitly. A missing finding can be resolved only when the same
versioned check actually passed for the same unambiguous asset.

Acceptance: skipped prerequisites, rejected requests, failures, and heuristic
signals cannot become passed checks; genuine protected-canary checks record their
outcome; CLI/API snapshots and report comparison consume the same contract;
existing version 1.0 reports remain readable.

### 3. Version SQLite upgrades and persist audit history

Transactional schema versioning supports known existing layouts and safe fresh
initialization. Exclusive dispatcher ownership precedes migration/recovery.
Admission, claim, cancellation, and terminal audit events persist in the same
transaction as each state transition. Audit history is bounded and tenant-owned.

Acceptance: fresh and known legacy upgrades preserve rows; unknown/future schemas
fail before writes; interrupted upgrades roll back; repeated calls do not duplicate
transitions; cancellation cannot leave inconsistent terminal job/session/report
states. Audit records contain only operational identifiers, states, and timestamps.
This history is not a tamper-resistant audit system.

### Additional acceptance

The local synthetic queue benchmark checks deterministic terminal counts,
unique claims, bounded workers, and matching job/session/report/audit states.
The dashboard displays per-asset check execution and outcome, unassessed risk,
cloud resource IDs, and authenticated audit pagination. Node regressions cover
stale requests, logout, bounded display, and text rendering. Chromium fixtures
cover the corresponding authenticated desktop/mobile workflows.

### Network and live protocol checkpoint

PRs #24 through #26 fix cross-version transport timeout accounting, strengthen
network discovery, and add scoped read-only live MCP inventory. Network fixtures
cover typed protocol evidence, false attribution, canonical authority, expected
negative services, incomplete responses, DNS/TCP limits, cancellation, and
deterministic JSON depth/finiteness. Unknown hostname exposure is omitted.
PR #28 adds current TGI input-limit recognition with explicit router identity;
historical router-less responses remain unsupported rather than misattributed.

The live MCP CLI supports the documented 2026-07-28 inventory subset only.
JSON/SSE, pagination, schemas, and report pointers are bounded; credentials and
escaped credential echoes are removed. It never starts commands, invokes tools,
fetches external references, or follows authentication metadata. Collection
outcomes are not security passes; runtime authorization, Origin, and execution
checks remain skipped. See [live scope](mcp-live.md) and [network scope](network-discovery.md).

### Controlled policy and saved-template checkpoint

PR #29 adds a separate `mcp-check` command for declared protected inventory
policy. An authenticated fixture baseline gates isolated credential and Origin
controls. Valid protected tool disclosure can confirm only that inventory
boundary; public enumeration, malformed responses, marker echoes, and missing
prerequisites cannot establish passes. Shared budgets, reflection guards,
secret-safe public identities, and JSON/SARIF check provenance have regressions.
Tool execution, browser exploitation, OAuth, and legacy adapters remain unsupported.
Operator canary provenance is declared, not independently attested. See
[controlled checks](mcp-policy.md).

PR #30 adds tenant-owned API templates with bounded lists, quota, optimistic
revisions, and manual runs through the shared scan admission path. Creation,
update, admission, and worker execution recheck scope and source prerequisites.
Declared domains and unresolved absolute paths survive until worker validation;
recipe edits/deletion do not change admitted snapshots. Exact SQLite version 1
upgrades add the template table transactionally, preserving existing records.
At that checkpoint, dashboard controls and scheduling were pending. See
[template contract](scan-templates.md).

### Dashboard and finite scheduling checkpoint

PR #32 adds manual dashboard template save/load/edit/run/delete, bounded paging,
dirty-editor discard, advanced-field preservation, revision/policy errors, and
logout/late-response guards. Real desktop/mobile Chromium fixtures use actual
authentication, SQLite, and template APIs with synthetic scanner functions.

PR #33 adds disabled-by-default finite API schedules pinned to template revisions.
One occurrence, scan/job/audit, and admission count commit together. Each schedule
has one outstanding scan, no catch-up burst, and no replay of admitted jobs.
Restart and template changes require operator review. Read-only preflight runs in
one off-thread slot; only the dispatcher admits scans after final guards. Soft
timeout retains occupied work, rejects late results, and fails readiness without
blocking cancellation. Schema version 3 upgrades exact version 1/2 layouts.
No schedule was enabled against a real target; see
[schedule contract and limits](scan-schedules.md).

PR #35 adds reviewed-pin dashboard creation, explicit enable/pause, bounded
schedule/occurrence pages, admitted-scan navigation, and constrained deletion.
Creation starts disabled; unsaved editor changes cannot be scheduled. Responses
must match expected IDs, pins, recurrence, and transitions before becoming
actionable. Independent real desktop/mobile browser acceptance covers policy,
quota, revision, restart, admission, deletion, session, and late-response paths.
Targeted real keyboard acceptance covers focus after explicit transitions,
deletion, logout, and 401. All browser fixture servers were stopped; artifact
scripts, screenshots, and disposable databases are preserved in
`/tmp/ai-scanner-schedule-browser-rDbOYW`. This is not comprehensive accessibility
acceptance or real-target schedule validation.

### Dependency and accessibility checkpoint

PR #37 requires certifi 2026.10.19 or newer following the published trust-bundle
advisory. The local dependency audit passed after upgrading the environment.
Existing environments and images still need their own upgrade/rebuild; no service
was deployed. See [dependency maintenance](../SECURITY.md#dependency-maintenance).

PR #38 completes the focused accessibility slice with stronger enabled-control
borders, linked scope/model guidance, named check/audit regions, focus restoration
at the final check page, and conservative terminal feedback. Unchanged polls keep
the loaded report and focus intact; report recovery updates feedback and clears
only obsolete report-owned notices. Other workflow messages remain intact.
The optional [Chromium command](DEVELOPMENT.md#optional-chromium-dashboard-checks)
owns a loopback fixture and temporary SQLite database, substitutes scanner engines,
blocks external browser requests, and tests stale selection/session clearing.
Thirteen mandatory Python tests cover its database guard, bounded startup,
environment isolation, and cleanup. The measured suite is 1039 pytest cases and
78 Node cases. Targeted browser acceptance is not comprehensive accessibility or
screen-reader acceptance. Root browser artifacts are preserved in
`/tmp/ai-scanner-browser-54ifn1sb`. The fixture was stopped and its database removed.

### Disposable backup/restore checkpoint

PR #40 adds a bounded command that owns stopped synthetic SQLite databases and
accepts no operator source/destination paths. All eight cases passed, including
exact schema 1/2/3 backup/restore, real upgrade/recovery, single queued execution,
preserved evidence/snapshots/audit/templates, restart-review schedules without
admission, and an idempotent second dispatcher restart. Negative cases cover
version-stamp rollback, future versions, competing ownership, and a restored copy
missing a report despite valid SQLite integrity. Independent restoration retains
old content/version; source and backup hashes stay unchanged.

Forty-two mandatory tests cover containment, cached-engine rejection before
connection, no-clobber copies, bounded child results/deadlines, optimized checks,
environment isolation, and cleanup. The full local suite is 1081 pytest cases,
78 Node cases, and 90% measured line coverage. Independent Python 3.12 acceptance
passed 187 focused cases. No operator database or real target was accessed.
See [usage and limits](jobs.md#disposable-backuprestore-acceptance).
Deployed backup, online procedures, old-binary compatibility, crash durability,
and M6 sign-off remain outside this acceptance slice.

### Offline replay key-disclosure checkpoint

PR #41 closes a reproduced REPLAY002 false negative: exact protected foreign
canaries in tool-argument property names were missed while values were detected.
String keys now use numeric `/keys/N` locations at supported nesting depths;
existing `/values/N` locations remain unchanged. Literal names never enter
evidence. Ruleset 1.1.0 changes evidence IDs for all checks, so IDs across that
version boundary cannot establish new/resolved findings.

Twenty-five new regressions cover nested objects/arrays, multiple occurrences,
secret-safe deterministic IDs, label independence, exact matching, and depth
limits. Encoded disclosures remain counted false negatives. Independent acceptance
passed all 48 replay cases on Python 3.10 and 3.12 with networking and execution
blocked. REPLAY001/003 detection and the six built-in smoke fixtures are unchanged.
The integrated local suite passed 1106 pytest cases and 78 Node cases at 90%
measured line coverage. This remains synthetic offline acceptance, not
representative production accuracy or live tool authorization. See
[replay scope and identity](replay-evaluations.md).

### Local-beta finish checkpoint

PR #42 adds a real offline operator workflow regression without scanner-function
substitution: authentication, current-policy template admission, repository
discovery/pipeline, SQLite dispatch, conservative skipped security, JSON/SARIF,
audit, and one explicitly enabled finite schedule occurrence. Independent Python
3.10/3.12 acceptance passed. Container CI now checks authenticated access before
and after restart; the local real-Docker run passed with no scans or deployed DB.
Container setup includes its missing operator key, and authentication docs now
correctly describe self-hosted scripts.

The integrated suite passed 1107 Python cases and 78 Node cases at 91% measured
line coverage. Normal Chromium and normal/optimized backup acceptance passed.
Five bounded queue runs passed 1600 jobs with no duplicate claims or state
mismatches; the deliberately insufficient deadline correctly failed. Disposable
processes/databases/containers were cleaned up. See [validation](VALIDATION.md)
for exact measurements, artifacts, and limits.

The [beta test guide](BETA_TESTING.md) supplies a static offline fixture and a
fresh private-database walkthrough. Its finite gate is the stopping point for
this beta after independent review and all required CI. It is not M6 completion,
security certification, representative model accuracy, or deployment authority.

## Next delivery sequence

The privacy follow-up keeps machine-local assistant instructions and lab assets
out of the public index and build inputs while retaining local copies. Package
and image contact metadata no longer exposes private account emails. Public
professional attribution and the security-reporting contact remain. Two privacy
regressions bring the local suite to 1109 cases. This is prospective cleanup;
historical Git blobs, commit metadata, and previously distributed artifacts remain.
New commits use the account's approved repository-local noreply email without
changing global identity. Do not rewrite history or erase local files implicitly.

1. Finish the reported remediation slices and require independent review plus
   every PR and post-merge CI job, including native macOS, to pass.
2. Retest the exact merged revision in an explicitly authorized real-service lab
   before reopening the beta. Starting cloud VMs, changing deployments, and
   enabling real schedules require authorization; do not infer it from this plan.
3. Treat representative accuracy/compatibility, long-duration load/soak,
   comprehensive accessibility, deployed backup/upgrade, and integrations as
   separate follow-up work. External integrations need an explicit destination
   and secret contract. Keep real-provider measurements separate from fixtures.

Broader live MCP and any legacy adapter need separate versioned designs. Do not
silently downgrade the current client or equate fixture inventory checks with
tool authorization, sandboxing, browser exploits, or complete attack coverage.

Each slice needs positive/negative fixtures, a concise independent review, all
required CI checks, and truthful operator documentation before merge. These are
implementation priorities, not additional deployment or publication authority.

## Verification and review

```bash
python -m pytest tests/
ruff check .
bandit -r src app.py scanner_cli.py cli.py -ll
python -m build
python -m twine check dist/*
sh scripts/package-smoke.sh dist/*.whl
```

Use the existing virtual environment when available. Independent reviewers should
exercise regression cases and inspect failure paths. Every implementation PR must
pass the current Python matrix, lint, dependency audit, package, and container
checks before merge. Public delivery rules are in the
[engineering plan](ENGINEERING_PLAN.md#delivery-rules); machine-local assistant
instructions are intentionally not distributed.

Do not reuse stale implementation branches without checking their contents.
Earlier agent worktrees remain on old branches; create a fresh worktree from the
latest merged main for new work. Temporary browser artifacts from the first phase
are supporting evidence, not required repository dependencies.

## Later milestones

After these slices, continue scoped live lab adapters and stronger discovery
fixtures, workflow acceptance and selected integrations, then representative
accuracy, load/soak, accessibility, and upgrade acceptance. Enterprise identity,
PostgreSQL/distributed execution, and external deployments need explicit supported
contracts and their own validation. Keep unimplemented capabilities visible in
the plan and product documentation.
