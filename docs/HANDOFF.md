# Continuation handoff

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

## Next delivery sequence

1. Complete the next focused dashboard accessibility slice: stronger enabled
   control borders, linked scope/model hints, named check/audit scroll regions,
   focus restoration when the final Show more control disappears, and concise
   completion announcements. Add reproducible keyboard regressions without
   moving focus on background polling or weakening authentication/epoch guards.
2. Expand workflow acceptance and selected integrations without bypassing shared
   admission, cancellation, or current-policy checks. Do not enable schedules or
   scan real targets automatically as part of engineering work.
   External integrations need an explicit supported destination and secret contract.
3. Expand representative accuracy and service-compatibility fixtures, then run
   load/soak, accessibility, and deployed backup/upgrade acceptance. Keep real
   provider compatibility separate from mocked SDK and synthetic protocol fixtures;
   do not require paid calls or claim complete coverage from line percentages.

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
checks before merge. Follow [AGENTS.md](../AGENTS.md) for Git identity and delivery.

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
