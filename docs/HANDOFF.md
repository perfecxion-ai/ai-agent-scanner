# Continuation handoff

## Active revised-roadmap checkpoint

The 2026-10-22 strategic review at `aae1863` and the operator's approval replace
the next delivery order with [R1 through R4](ENGINEERING_PLAN.md#active-roadmap):
trustworthy results, useful application assessment, meaningful live agent
coverage, then team readiness. Release/contributor work and public benchmark
design run alongside implementation. Historical acceptance below remains scoped;
it does not establish market leadership or enterprise readiness.

Two new trust gaps take priority. Generic authentication checks can pass against
an always-denied endpoint without proving a protected resource is reachable with
valid credentials, and report comparison can treat that result as resolution.
Separately, an outer deadline can discard confirmed results accumulated before a
later stage stalls. The review also identifies incomplete newest-100 inventory
filtering, unknown-score storage placeholders, stale release identity, difficult
operator configuration, and narrow live application/agent coverage. See
[review evidence](VALIDATION.md#strategic-review-and-revised-roadmap).

The R1.1 slice now has explicit authorized positive controls, denied
controls, versioned evidence semantics, and false-pass/resolution regressions.
Explicit cancelled-check accounting is included: a cancelled check cannot pass
merely because its controls succeeded. Local acceptance passes 2,220 cases with
warnings treated as errors, independent review, lint/security checks, build,
metadata, and installed-wheel smoke. PR #64 and merged revision `9a696d1` pass
all eight CI jobs; see
[local acceptance and limits](VALIDATION.md#protected-access-positive-control-local-acceptance).
R1.2a now retains finalized-check evidence through later failures, orderly CLI
interruption, and server-process recovery. The combined tree passes 2,307 tests
with warnings treated as errors, independent review, and installed-wheel smoke.
The process-kill fixture waits for an acknowledged SQLite checkpoint, kills the
actual dispatcher process, and verifies exact evidence/snapshot retention without
probe replay. PR #65 and merged revision `4f9de3f` pass all eight CI jobs. See
[checkpoint acceptance and limits](VALIDATION.md#finalized-check-checkpoint-local-acceptance).

R1.2 remains open: observations inside unfinished checks need a separate
versioned progress/evidence contract, and CLI process-crash recovery needs a
private checkpoint-file contract. Neither is implemented by R1.2a. Do not equate
the benchmark's observation checkpoint with genuine normal-scan finding evidence.
The historical compatibility prerequisite now centralizes supported
protected-access evidence eligibility for scoring, API/dashboard projection, and
comparison. Unsupported historical passes and confirmations cannot become current
verdicts; original reports and findings remain untouched and unresolved. Genuine
current sampled zero and confirmed findings remain supported. Local acceptance
passes 2,899 tests with warnings treated as errors, 143 dashboard cases, real
Chromium, independent review, both backup modes, and installed-wheel smoke.
PR #66 and merged revision `8135310` pass all eight CI jobs. See
[compatibility acceptance](VALIDATION.md#historical-protected-access-compatibility-follow-up).
This also protects the planned nullable-score migration. The prompt-only
within-check retention slice now passes 3,216 local coverage tests, 793 overlapping
independent cases, 143 dashboard cases, both backup modes, and installed-wheel
smoke. Immutable receipts bind a finding to an actual evaluated response without
inventing a completed check; real loopback CLI/server and dispatcher-kill cases
retain the evidence. PR #67 records independent review and cross-platform CI. See
[prompt receipt acceptance](VALIDATION.md#within-check-prompt-receipt-local-acceptance).
Tenant/access observation retention and CLI process-crash files remain separate
gates; this work does not close them.
All eight PR CI jobs passed at `9c411ad`, but a subsequent prompt request-reflection
audit held the merge. The correction now binds a private complete outbound request
to the response, rejecting case-changed request values and automatic-header echoes
as confirmation evidence. The final local gate and independent review pass;
PR #67 records required CI results for the corrected revision.
PR #67 merged as `17750e0` after all eight PR checks passed. All eight post-merge
jobs pass too, with one unchanged macOS rerun after a SQLite contention test exceeded
its wall-clock limit by 15 ms. Independent instrumentation verified the configured
lock cap and restoration; no production timeout or assertion was relaxed.
See the [reflection correction evidence](VALIDATION.md#prompt-request-reflection-correction).
The historical prompt follow-up removes finalized-check fallback from current
versioned prompt scoring. Unsupported positive checks/findings leave only their
asset's numeric assessment unknown, including beside a valid access pass. Original
reports and unresolved findings remain intact; supported independent assets remain
assessed. Local acceptance passes 3,281 coverage tests, 1,170 overlapping independent
cases, 145 dashboard cases, real Chromium, both backup modes, and installed-wheel
smoke. See [historical prompt acceptance](VALIDATION.md#historical-prompt-eligibility-follow-up).
PR #68 merged as `a8ea520` with all eight PR and post-merge jobs passing.
Nullable-score migration remains a separate prerequisite.
The next read-only review also reproduces an existing tenant false-confirmation
path: a fixture echoing a model or credential equal to the foreign-tenant canary
produces eligible confirmed findings without tenant data. Close this request
reflection/provenance gap before making tenant observations durable. See
[tenant prerequisite evidence](VALIDATION.md#tenant-evidence-prerequisite-for-the-next-increment).
The tenant-control slice now requires explicit CLI/Python principal references,
two independently seeded records, an operator-attested authorization boundary,
and three successful controls before five attack prompts. Both keys and markers
are pinned before checkpoints. Shared transport checks prevent known request
contamination, including observations from earlier probes. Public findings bind
the original endpoint/provider/model/context; unsupported historical tenant claims
remain archived with unknown current risk. The server rejects private tenant
inputs before environment resolution. See
[configuration](detection-evidence.md#controlled-tenant-assessment) and
[local validation](VALIDATION.md#controlled-tenant-evidence-local-acceptance).
Final local acceptance passes 3,515 coverage tests, 247 overlapping independent
review cases, 145 dashboard cases, both backup modes, and installed-wheel smoke.
PR #69 merged as `1072d8b` with all eight PR and post-merge CI jobs passing.
The supplied scoped HTTPS tenant retest is accepted for CLI workflow correctness:
three vulnerable runs retain 90/critical, three defended runs stay inconclusive
with null risk, and all broken-control cases stop without confirmation or a pass.
Two independent reviews validate the nine reports, ten real exits, 70 captured
expectations, and fixture POST outcomes. Its deterministic fixtures do not
establish real-model sensitivity. The private harness and narrative have limits
around held-candidate/reflection coverage, privacy capture scope, and failure
propagation; see [qualified acceptance](VALIDATION.md#supplied-tenant-workflow-acceptance).
No broad repeat is needed for those qualifications. The R1.3 nullable-score
storage slice now passes local acceptance: schema 4 stores unknown scores as SQL
NULL, preserves supported zero and partial evidence, and upgrades recognized old
layouts transactionally using independently frozen historical definitions.
Archives and non-cache fields remain unchanged, and unsupported table/index
semantics fail before writes. The final local gate passes 3,631 coverage tests,
423 overlapping independent cases, both ten-case backup modes, and installed-wheel
smoke. Offline copies of all nine supplied tenant reports keep their exact bytes
and canonical scores through upgrade and restart. See
[storage acceptance](VALIDATION.md#nullable-score-storage-local-acceptance).
Required delivery checks are recorded on the PR. After merge and CI, the next
external gate is the [native storage and server upgrade retest](storage-retest.md)
on its exact merged revision; repeating tenant probes is unnecessary.
Tenant/access within-check receipts, server tenant profiles, CLI crash files,
exhaustive inventory, and later roadmap slices remain open.

Do not ask for another broad GCP run merely for this roadmap update. Use isolated
local fixtures for the initial correctness slices. Request a scoped, pinned
operator retest only when a merged runtime change needs real-service validation,
with exact commands, required captures, budgets, and genuine process exits.
Keep experimental prompt selection opt-in and existing scope/privacy/budget
limits intact. No cloud startup, deployed service change, package publication,
or real schedule enablement is authorized by this continuation.

## Prior limited-beta checkpoint

The [remediation hold](BETA_REMEDIATION.md) is closed for limited single-operator
beta testing on runtime revision `82ee7d5e8d1a0183fe5344b41da90f60b49c5f91`.
This is not publication, deployment, production, or enterprise approval. Private
lab reports, drivers, secrets, database inputs, and captures remain outside Git.

The earlier operator retest of `1507625` supports the core verdict, mixed-network,
source-reuse, privacy-omission, MCP, and native macOS fixes. Independent review
found one remaining API defect, corrected in PR #49: storage placeholder zeros
must not become public verdicts when saved pipeline scores are null. The fix
passes 1279 local cases, independent review, and all eight PR/post-merge CI jobs.

The targeted live server retest of `82ee7d5` now closes that API blocker. Two
independent artifact reviews verified ten scans and 31 agent snapshots across
saved pipelines, results, inventory, and restart inventory. All 29 unassessed
snapshots remain null; both confirmed snapshots remain 70/high with the correct
sampled or partial coverage. The archived checks record 78 passes and no failures.
All 324 response excerpts are omission sentinels. Final database privacy/mode
checks are operator attestations because the database and secrets were excluded.

Positive cases used deterministic fixtures and canary/context input seeding while
the server was stopped; no finding or score was fabricated. That tested revision
had no supported canary-configuration input. Editing reports or the database is
not an operator setup method. Three real-model attempts remained inconclusive, not
passed; this does not establish detection sensitivity. Restart per-scan result
and high-filter bodies were not separately saved, so those assertions rely on
driver checks; archived restart inventory independently contains all 31 entries.

Inventory filters explicitly apply to a newest-100 tenant/type window. Keep the
remaining observations, representative
accuracy, and broader enterprise work visible. Documentation-only updates do not
change the tested runtime or require another cloud run. See [targeted acceptance
and qualifications](VALIDATION.md#targeted-live-api-acceptance).

The operator-diagnostics follow-up addresses O1/O2/O4/O5/O6 and passes 1408 local
tests plus independent network/MCP reviews, Ruff, and configured Bandit. Forbidden
CLI classes fail before scanning; required model denials and MCP failures have
static secret-safe diagnostics; baseline/control pagination wording is explicit.
The wildcard detector keeps a justified narrowly scoped suppression without stale
warnings. No security pass, scope boundary, retry behavior, or MCP control coverage
was broadened. PR #51 and its merged revision passed all eight CI jobs. This is not a
new cloud retest. O3 presentation is addressed in the later checkpoint below;
the larger product gaps remain.

The server evidence-reference slice adds an opt-in supported API workflow for
system-prompt canaries. A private startup-only registry binds a named profile to
the operator organization and exact endpoint/provider/model/context. API jobs,
templates, and schedules contain public references and binding pins, not secret
values. Admission and execution revalidate; injection is into fresh in-memory
source copies before secret collection. Source reports are unchanged. See
[setup and rotation limits](detection-evidence.md#server-system-prompt-canary-profiles).
Cross-tenant/authentication/path evidence inputs remain CLI/Python-only. The
database's historical unknown-score placeholders are unchanged; canonical saved
pipeline results and API projections are authoritative, not raw score columns.

Local HTTP/API/dispatcher fixtures cover supported profile input, confirmed
70/high versus inconclusive/null, source immutability, and privacy across
SQLite, logs, audit, requests, JSON, SARIF, and inventory. Isolated subprocesses
exercise actual startup configuration without network or database access.
Independent reviews closed reflected-request, mixed-inventory, escaped-marker,
and shared-canary multi-model bugs. Final combined acceptance is recorded in
[validation](VALIDATION.md#server-evidence-reference-slice). PR #52 and merged
revision `ed5684d` passed all eight CI jobs. No cloud service or real model was
exercised for this slice.

The prompt-only benchmark now supplies an opt-in, fixed-budget paired baseline
and experimental extraction-focused candidate. It uses actual adapters,
transport, analyzer, and check contracts without changing production defaults.
Each arm is capped at 35 requests; ten balanced pairs cap a target cohort at 700
requests and 90 minutes. Partial observations and planned denominators remain
explicit. Neither successful fixtures nor nondisclosure establish accuracy.
See [GCP retest scope and commands](BETA_TESTING.md#next-authorized-gcp-detector-retest)
before requesting authorized operator execution on the final pinned revision.
Do not start cloud resources, change deployed services, or invent target-side
canaries to obtain a positive result. Freeze setup and sample counts before runs.

A benchmark-only follow-up requires normal tester return before labeling an arm
completed. Timeout during the final pacing delay remains partial even with all
35 responses evaluated; analyzer confirmations survive without manufacturing
complete-case observations. Production prompts and sampling are unchanged. See
[the regression scope](VALIDATION.md#benchmark-final-pacing-timeout-follow-up).

The supplied retest of `4f03d6350058c40ad1cdba1d73b16d22a4fa1575` now supports
the normal server profile workflow without stored-report edits. Six pipelines,
40 agent projections, SARIF, and restart inventory agree. The experimental prompt
suite observes disclosure in 10/10 completed runs versus 2/10 for the legacy suite
on one operator-attested target, across ten balanced-order pairs and 700 requests.
This is target-specific evidence, not general sensitivity or enterprise acceptance.
See [reviewed evidence and qualifications](VALIDATION.md#supported-server-canary-and-paired-prompt-retest).

The server driver retains one incorrect null expectation and exits 1 despite its
wrapper's exit zero. Per-scan restart bodies, high-risk filter captures, and some
negative response bodies are missing; schedules were not run. Private-secret
sweeps and database modes remain operator attestations. Benchmark manifests
include static attack payloads but omit generated responses. Preserve these
limits rather than calling the whole lab gate green.

The next accuracy step is an independent frozen multi-model replication with
explicit controls and target provenance before adopting a candidate or increasing
sampling. Production defaults remain unchanged. Keep raw-score schema migration,
broader authorization controls, and enterprise readiness as separate reviewed work.

The offline cohort gate now makes the next evidence collection reproducible from
an explicit private plan. It checks current manifests, ordered pairs, check
provenance, counters, checkpoints, timing consistency, and recomputed metrics.
Every declared positive/negative control and model case remains visible; missing,
invalid, partial, and failed-control evidence produce nonzero exit. Inputs are
bounded private files, and atomic no-clobber summaries omit supplied labels,
paths, payloads, secret references, and hashes. There is no network or app startup.
This accepts internally consistent files and declared controls, not actual target
identity, preregistration, privacy, independence, or model safety. State policies
remain visible operator assertions. See [usage and limits](BETA_TESTING.md#offline-multi-model-evidence-gate).
Production defaults stay unchanged; the earlier one-target bundle is not a new
multi-model replication.

The supplied frozen-cohort retest of `4070eed` now passes independent offline
replay with a summary identical to the archived output. Both declared controls
meet expectations; each declared model target completes ten balanced-order pairs.
Candidate observes disclosure in 10/10 runs on each target versus baseline 5/10
and 1/10, respectively, at equal 35-request arm budgets. All 1,540 benchmark
requests are accounted for, and nondisclosure never becomes a security pass.
These are per-target measurements, not pooled accuracy or proof of independent
backends. One target's state is explicitly unknown. Preserve the failed setup,
corrected seeding, missing audit artifacts, and privacy-sweep/retention limits in
[the reviewed acceptance](VALIDATION.md#frozen-paired-cohort-retest).

This closes collection of an internally consistent declared cohort, not candidate
promotion or enterprise readiness. The next product step is a separate reviewed
decision on explicit opt-in candidate use in normal scans, with unchanged default
prompts, bounded requests, versioned provenance, conservative evidence, and
CLI/API workflow regressions. No new cloud run is needed for this documentation
checkpoint; runtime changes need their own scoped validation.

The shared-catalog foundation adds explicit Python constructor selection for
`protected-disclosure-v1`, with protected-canary/context prerequisites and static
configuration errors before candidate requests. Both the benchmark and candidate
tester use the same frozen payloads and existing probe versions. Default catalogs,
sampling, scope, scoring, and deadlines are unchanged. Independent copies and
cross-asset collision checks protect concurrent use and public evidence identity.
CLI/API selection, saved-definition pins, and operator workflow acceptance are
separately described in the integration slice below.
See [local validation](VALIDATION.md#shared-experimental-prompt-catalog).

Normal CLI and API scans now expose explicit `protected-disclosure-v1` selection.
The CLI requires an explicit agents configuration kept private by the operator;
server security-only scans require
selected startup profiles for every request-ready model. Saved raw canaries
cannot substitute for profiles. Source records stay unchanged. Jobs/templates
pin the public catalog, reject caller pins and drift, and schedules revalidate
before admission. Candidate engines are scan-local; defaults and shared budgets
remain unchanged. JSON/SARIF labels identify selection, not successful execution.
The complete template JSON editor preserves the option; the new-scan form does
not enable it. See [operator setup](detection-evidence.md#experimental-prompt-suite).

After local acceptance, independent review, and all required PR/post-merge CI,
request only the [normal-workflow GCP retest](BETA_TESTING.md#normal-scan-experimental-suite-acceptance)
on the final merged revision. Do not repeat the paired accuracy cohort merely to
validate these entry points. Preserve failed assertions and capture bodies, state
uncertainty, and complete privacy-sweep coverage. No deployment, publication,
cloud startup, or live schedule enablement is implied by this integration.

The supplied normal-workflow retest of `ae1ba9b` supports the opt-in CLI/server
paths. Three independent artifact reviews found no new product blocker. The final
CLI driver records 165 passing assertions; the server records 181. Deterministic
disclosure and both declared real targets retain 70/high; refusing and unseeded
controls stay null. All eight server JSON/SARIF export pairs match their saved
pipelines, and complete inventory/high-filter/history bodies match across restart.
The local 453-case focused gate passes again with warnings treated as errors.

This is scoped workflow acceptance, not completion of every requested capture.
Per-scan post-restart bodies, template documents, full negative responses, and
post-reuse source bodies are missing. Preserve corrected real-model category
counts, both failed CLI attempts, incomplete executed-driver provenance, and
operator-attested privacy/retention limits in the
[reviewed retest](VALIDATION.md#normal-cli-and-server-experimental-suite-retest).
Schedules remain NOT RUN; defaults and runtime code are unchanged. No new cloud
run is needed for this documentation checkpoint. Missing captures are not passes,
and this does not establish general sensitivity or enterprise readiness.

O3 now has conservative dashboard-only finding groups: 18 sample occurrences
can display as seven groups while original JSON/SARIF, score 70, all occurrence
IDs, check counts, suppression keys, and resolution behavior remain unchanged.
Grouping requires exact modern confirmed provenance and a matching check within
one asset entry; malformed/historical/ambiguous records stay separate. Details
and pagination are bounded, text is literal, and final-page keyboard focus is
preserved. The checked-in Chromium fixture exercises this at 320/390/1440 pixels.
It uses synthetic reports and private temporary SQLite, not real models. The
fixture also excludes inherited operator evidence-registry configuration.
See [presentation contract](dashboard-evidence.md#finding-groups-and-original-occurrences)
and [acceptance](VALIDATION.md#finding-presentation-grouping).

The following slice descriptions record earlier local remediation checkpoints.

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
See validation for combined acceptance. At that checkpoint the beta remained
held pending an authorized real-service retest and the readiness gates above.

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

The active [revised roadmap](ENGINEERING_PLAN.md#active-roadmap) supersedes this
older sequence. The following privacy and validation constraints still apply.

The privacy follow-up keeps machine-local assistant instructions and lab assets
out of the public index and build inputs while retaining local copies. Package
and image contact metadata no longer exposes private account emails. Public
professional attribution and the security-reporting contact remain. Two privacy
regressions bring the local suite to 1109 cases. This is prospective cleanup;
historical Git blobs, commit metadata, and previously distributed artifacts remain.
New commits use the account's approved repository-local noreply email without
changing global identity. Do not rewrite history or erase local files implicitly.

1. Preserve the reviewed remediation checkpoint and require scoped independent
   review plus PR/post-merge CI for changes. Runtime changes need relevant
   revalidation; documentation-only changes do not require another cloud run.
2. Measure fixed-budget detection sensitivity before increasing prompts/sampling.
   Preserve exact-canary confirmation, inconclusive nondisclosure, existing scan
   deadlines, source uncertainty, and response omission. Compare the same protected
   fixture/context and model configuration across baseline and candidate runs;
   synthetic contract fixtures cannot establish representative model accuracy.
   Presentation grouping must preserve occurrences, check IDs, and lifecycle rules.
   Do not use report/database modification as a product feature. Starting cloud
   VMs, changing deployments, and enabling real schedules require authorization;
   do not infer it from this plan.
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

Synthetic API/local-lab/offline-operator fixtures exclude inherited operator
registry settings and temporarily isolate cached registries. Queue and backup
acceptance runners clear that setting before app import and reject a cached
nonempty registry before database access. Backup's outer child-environment filter
remains in place. Eight bounded regressions cover forbidden private-file access,
cached rejection, and parent environment/registry restoration. Loopback HTTP
fixtures bind numeric names without reverse DNS; their fresh/cached setup is
tested with reverse lookups forbidden. A Linux symlink-ancestor regression checks
owned temporary-root canonicalization without weakening database leaf guards.
The browser fixture has equivalent isolation
in its presentation slice. These are local harness guards, not secret-manager or
runtime deployment changes. See [validation](VALIDATION.md#synthetic-evaluation-registry-isolation).

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
