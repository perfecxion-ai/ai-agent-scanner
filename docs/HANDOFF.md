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
semantics fail before writes. The final local gate passes 3,763 coverage tests,
279 overlapping independent Python 3.13 cases, both ten-case backup modes, and
installed-wheel smoke. Offline copies of all nine supplied tenant reports keep their exact bytes
and canonical scores through upgrade and restart. See
[storage acceptance](VALIDATION.md#nullable-score-storage-local-acceptance).
PR #72 merged as `3f32c6e` with all eight PR and post-merge checks passing.
The supplied native storage retest is accepted for the reconstructed fixture's
upgrade and restart workflow on Python 3.11.2/SQLite 3.40.1. Both ten-case backup
modes exit zero, and all 60 server assertions match the captured log. SQL caches
and results retain null, genuine zero, and confirmed 70/partial evidence through
restart. This is not an upgrade of the original lab database. Inventory/SARIF
checks prove availability only, and the private harness has preservation,
privacy-sweep, and failure-propagation limits. See
[qualified native acceptance](VALIDATION.md#supplied-native-storage-upgrade-acceptance).
No broad repeat is needed for those qualifications. R1.4a now passes local
acceptance: exhaustive observation traversal uses canonical risk filters,
bounded source/output work, and signed cursors invalidated by source changes.
Schema 5 installs recognized generation triggers and indexes while preserving
schema-4 data and scalar caches. The full local gate passes 3,964 tests with
warnings treated as errors and coverage; final independent review passes 99
cases on Python 3.13, including real normal/optimized Gunicorn traversal and
restart over 10,000 observations. See
[pagination acceptance](VALIDATION.md#exhaustive-observation-pagination-local-acceptance).
PR #74 merged as `c6e4600` with all eight PR and post-merge checks passing. One
unchanged macOS contention test required an isolated post-merge rerun after a
2.65-second wall-clock result exceeded its 2.5-second assertion; no assertion or
production timeout changed.
The supplied native inventory retest now passes scoped acceptance on Python
3.11.2 and SQLite 3.40.1: both inventory modes retain all 13 required assertions,
10,000 observations, matching canonical filter counts, and clean server exits.
Both eleven-case backup modes pass. Runtime hashes match the pinned source.
Raw databases and HTTP bodies were removed by the owned gate, and outer-wrapper
setup/cleanup and privacy claims have recorded limits. See
[native acceptance](VALIDATION.md#supplied-native-inventory-traversal-acceptance).
No broad repeat is needed. Distinct-asset identity and authoritative indexed risk
caches remain separate work.

R1.5a now has local development identity: canonical `1.2.0.dev0`, deterministic
packaged-source and bundled-catalog fingerprints, read-only CLI/API diagnostics,
and a producer stamp retained across actual pipeline checkpoints. Derived exports
keep historical producer identity separate from the current exporter; raw saved
JSON is unchanged. Unknown or privacy-withheld provenance stays unknown.
The local coverage gate passes 4,142 tests with warnings as errors; independent
review passes 65 cases on Python 3.13. A public import-compatibility alias receives
its focused final checks separately, and required delivery CI is recorded on the
implementation PR. See [identity contract](build-identity.md) and
[local acceptance](VALIDATION.md#development-producer-identity-local-acceptance).
PR #76 merged as `0d60e09` with all eight PR and post-merge checks passing.
This metadata slice needs no GCP retest and does not close release/SBOM work.

R1.2c now retains genuine tenant observations inside unfinished checks under
mixed ledger `2.0` and checkpoint `3.0`. Subject leaks publish only after the
third control succeeds; attack leaks publish before cleanup or the next request.
Malformed extensions cannot erase acknowledged eligibility. Older ledger/checkpoint
meanings and raw archive bytes remain intact. Actual HTTPS, orderly CLI export,
SQLite dispatcher-kill recovery and authenticated recovered-result reads pass.
The combined local coverage gate passes 4,366 cases with warnings as errors;
95 focused cases cover the final literal adapter-declaration hardening. See
[acceptance and limits](VALIDATION.md#tenant-observation-retention-local-acceptance).
PR #77 merged as `6af7fa2` with all eight PR and post-merge checks passing.
The supplied native tenant interruption retest now passes scoped acceptance:
both stalled CLI cases retain 90/critical partial evidence, a contaminated denied
control withholds the held candidate, defended nondisclosure stays null, and both
native dispatcher recovery tests pass. All 66 captured expectations agree with
the four original reports and real exits. Privacy, cleanup, original wrapper
modes and native HTTP/HTTPS claims have explicit qualifications. See
[native acceptance](VALIDATION.md#supplied-native-tenant-interruption-acceptance).
No broad repeat is needed. Private server tenant admission, protected-access observation receipts,
CLI process-crash files, distinct-asset inventory and later roadmap slices remain
open. Do not treat this fixture acceptance as enterprise readiness.

The next protected-access audit reproduces a prerequisite before durable access
observations: a transport-added marker reflected by a record-free fixture, or an
extra issued credential silently authorizing nominally anonymous probes, each
produces 18 confirmed findings and canonical 70/high over 20 actual GETs at
`6af7fa2`. Access checks inspect planned material rather than the complete actual
capture. A separate genuine leak-then-stall case also loses the first finding
inside its unfinished check. Fix provenance first with versioned semantics and
explicit historical scalar-cache reconciliation, then add access receipts as a
separate slice. See [audit evidence](VALIDATION.md#protected-access-request-provenance-prerequisite).

The access provenance correction now has local acceptance. Four existing GET
families use pinned private controls, exact live outbound captures and v3
semantics. Reflected markers, extra credentials, incomplete captures and
disclosing/malformed denials cannot confirm or pass. New confirmations require
integer control version 3. Older v2 access-only claims become current unknowns;
their original reports remain readable and unchanged.

Schema 6 reconciles obsolete scalar caches transactionally without rebuilding
schema-5 tables, changing archive bytes or suppressing existing generation
triggers. Genuine current zero/partial evidence and independent prompt/tenant
risk remain supported. The inventory gate now checks reconciliation before
restoring its owned stale fixture caches for traversal and restart.

Local coverage passes 4,694 cases, followed by 838 focused cases covering the
final static phase-log privacy fix and 24 trusted HTTPS CLI cases. See
[acceptance](VALIDATION.md#protected-access-v3-and-cache-policy-local-acceptance).
PR #79 merged as `a9b2718` after all eight PR and post-merge checks passed;
all five full suites passed 4,721 tests. The supplied native access/cache retest
now passes scoped acceptance on Python 3.11.2/SQLite 3.40.1: 337 targeted tests,
both thirteen-case backup modes and both inventory modes pass, with all 109
captured expectations reconciled. The CLI source identity and inventory runtime
hashes match the pinned checkout. See
[native acceptance and qualifications](VALIDATION.md#supplied-native-access-and-cache-policy-acceptance).
The private wrapper has narrower failure-propagation, privacy-sweep and file-mode
evidence than its narrative claims. These limits need no broad repeat and do not
establish an operator migration or model sensitivity.

The provenance prerequisite preserved frozen v3 finalized-check eligibility and
raw archives. Its separate within-check retention increment is recorded below.

R1.2d now implements protected-access observations under ledger `3.0` and
checkpoint `4.0`. All four existing GET families publish actual control-backed
findings before cleanup, pacing or another request. Private task-bound witnesses
verify exact transmitted requests and selected roles. Public base-target binding
plus numeric path indices preserves admin-resource identity through redaction.
Malformed extensions cannot erase acknowledged evidence or expose a companion zero.

Frozen ledger 1/2 readers and finalized-v3 eligibility remain supported; modern
probe hashes cannot downgrade to legacy confirmation by stripping their ledger.
Four genuine original v3 reports retain exact bytes and canonical 0/70/partial/90
results. Schema 6 and existing caches need no new reclassification. CLI forced
process-crash files and private API admission remain outside this slice.

Independent review passes 1,052 combined cases on Python 3.13.15, followed by
421 descriptor/version cases after extending the direct experimental-suite
privacy guard. Catalog bytes, suite semantics/pin and request behavior remain
unchanged. The full coverage gate passes 4,983 tests with warnings as errors;
PR #81 merged as `0797857` with all eight PR checks and all eight post-merge
checks passed. See
[local acceptance](VALIDATION.md#protected-access-observation-retention-local-acceptance).
The supplied native retention gate now passes qualified acceptance on Python
3.11.2/SQLite 3.40.1: 230 targeted tests, both thirteen-case backups and both
inventory modes pass; all 110 captured checks reconcile. Source and runtime
hashes match the pinned checkout. See
[native acceptance and qualifications](VALIDATION.md#supplied-native-protected-access-retention-acceptance).
The private driver's trap, wrapper cleanup, privacy inventory and outer file
modes support narrower claims than its narrative. These qualifications need no
broad repeat and do not establish model sensitivity or an operator migration.
The separate CLI checkpoint-file increment is recorded below. Private API
admission remains a separate gate.

R1.2e now has local acceptance for opt-in CLI process-crash files. `scan` and
`discover` can create a fresh private checkpoint directory; `recover` exports its
public evidence offline without credential resolution or probe replay. Exclusive
ownership, bounded canonical validation and atomic file replacement preserve
earlier evidence. Nonterminal recovery remains partial and exits nonzero;
recorded terminal results preserve their actual status. Existing defaults, sample
budgets, catalog bytes, server inputs, evidence versions and schema 6 are unchanged.

All 119 new cases pass, including four unmodified production CLI children over
verified owned HTTPS, acknowledged evidence followed by a real request stall,
SIGKILL and fresh offline JSON/SARIF recovery. Independent Python 3.13 review
passes 73 core cases and 46 CLI/process/guard cases. The full coverage gate passes
5,102 tests with warnings as errors; build, installed-wheel recovery, lint and
configured Bandit pass. See
[local acceptance](VALIDATION.md#cli-process-crash-checkpoint-local-acceptance)
and [file contract](cli-checkpoints.md). PR #83 merged as `1d790bf` after all
eight PR checks passed. PR #84 adds manual CI dispatch and merged as `49c1041`
after all eight PR checks; all eight checks on that main revision also pass,
covering the unchanged scanner runtime.

The supplied native file-recovery gate now passes qualified acceptance on Python
3.11.2: 119 cases in 61.24 seconds, build, Twine and installed-wheel smoke all
pass, with 23 captured checks reconciled and matching 74-file source identity.
The wrapper's setup/cleanup handling, temporal privacy sweep, sanitized logs and
returned modes support narrower claims than its report. See
[native acceptance and qualifications](VALIDATION.md#supplied-native-cli-checkpoint-acceptance).
This closes R1.2e for the currently implemented prompt, tenant and access receipt
families on the supported POSIX/local-filesystem process-recovery boundary.
Future evidence families, power loss, deployed storage, private API admission and
enterprise acceptance remain separate gates.

R1.4b1 now implements authenticated public-target groups and occurrence history.
Latest canonical risk remains separate from prior confirmations, including
genuine supported receipts saved before scoring. Quiet or unknown later runs do
not resolve earlier findings. Schema 7 adds a derived, sealed index without
rewriting schema-6 reports, observations or score caches. Idle maintenance holds
dispatcher ownership and yields to active scan workers; GET never repairs the
index. Stale or unreadable sources return unavailable. See the
[contract](asset-groups.md) and [local acceptance](VALIDATION.md#public-target-grouping-local-acceptance).

PR #86 merged as `678fd717788d91a5062f4d3a723cc30979427871` with all eight PR and
post-merge checks passing. The supplied native grouping gate at that revision failed:
both 180-second modes time out, and SQLite 3.40.1 chooses a valid covering index
that one focused assertion rejects. A separate 300-second diagnostic passes all
fourteen assertions in 191.528 seconds without replacing those failed receipts.
See [failure review and correction](VALIDATION.md#supplied-native-asset-group-gate-failure-and-portability-correction).
The correction prepares each bounded source selector once per reader with fresh
observation, scan and owner bindings. It preserves source reopening, evidence
validation, limits and the 180-second gate. Report and metadata SELECTs also
reuse only their SQL, rebinding identifiers and byte caps before every fetch.
Independent review passes 105 combined cases on SQLite 3.40.1 and 3.45.1. Owned
complete normal/optimized gates pass in 48.152/48.214 seconds on the local
compatibility runtime, with all fourteen assertions and both backup modes passing.
The first correction CI run also exposes an unclassified restart-page failure
in the optimized Python 3.12 gate. A controlled cleanup fixture proves that the
documented retryable 503 can occur while a valid cursor remains usable. The gate
now follows that narrow retry contract within its existing deadline and records
phase retry counts, while retaining all negative controls and full-view checks.
The original CI status was not captured, so its cause remains unproven; corrected
delivery required all platform checks at that checkpoint.

The corrected [scoped native retest](asset-groups-retest.md) now passes at PR #87's
merged revision `1b164df8bdd4361dc92ef17b917bc1e63291fa91`. Both unchanged
180-second modes accept all fourteen assertions, 10,000 observations and 24 groups
in 129.273/135.675 seconds, with zero pagination retries and clean initial/restart
server exits. Both fourteen-case backup modes and the expanded fourteen-file
warnings-as-errors set pass (309 passed, two deselected). All five step exits,
the driver and outer job exit are zero; the 37-record capture table reconciles.
Native Python 3.11.2/SQLite 3.40.1 captures match the exact 78-file source digest
and pinned component, policy and catalog hashes. See
[native acceptance and qualifications](VALIDATION.md#supplied-native-asset-group-acceptance).
This closes the R1.4b1 native correctness gate without replacing the failed
`678fd71` receipts or historical CI failures. The Mac comparison and same-runner
claims are producer attestations. Known-value/privacy sweeps cover supplied
evidence; sanitized logs and absent raw databases/responses do not prove arbitrary
secret absence. The private wrapper has setup, failure-propagation and cleanup
limits, and its setup note understates the actual focused file count.

R1.4b2 authoritative risk indexes, dashboard group views,
credential/principal equivalence, logical-finding consolidation, and the remaining
R2 through R4 work are separate. Group history counts occurrences, not independent
vulnerabilities. No enterprise or release approval follows from these local gates.

R1.4b2a implements indexed latest-risk filtering for group lists in
[PR #89](https://github.com/perfecxion-ai/ai-agent-scanner/pull/89). Schema 8 adds
six nullable derived facts and one partial index, preserving source records and
existing schema-7 cache fields. Readiness checks cover the complete publication
before filtering; selected rows must match a fresh canonical source projection.
Prior confirmations remain in history, and unknown remains null. Filters bind
signed cursors, including normalized equivalent values. Filtered continuation
plans use a timestamp range while preserving tied-group ordering.

Local focused/independent checks pass on SQLite 3.40.1, 3.45.1 and 3.53.1. Initial
extended gates pass on the owned Python 3.12.3/SQLite 3.40.1 compatibility runtime
in 52.205/51.440 seconds, retaining the 180-second budget and original
10,000-observation/24-group oracle plus five separate risk controls. Both backup
modes pass all fifteen cases. See
[local evidence](VALIDATION.md#indexed-group-risk-local-acceptance) and the PR for
full-suite, packaging and required delivery checks. The supplied
[native gate](asset-groups-retest.md) now passes at merged
`c12ceadcc6c830d73e1d484f17b45c06f07c329b` on Python 3.11.2/SQLite 3.40.1:
both modes accept all seventeen assertions in 150.237/150.768 seconds, both
fifteen-case backup modes pass, and the twenty-file focused set passes 447 tests
with two separately captured group gate cases deselected. All five step exits,
the driver and outer job exits are zero. All 24 risk-filter counts and digests,
the exact source, component and policy identities, and the available workstation
expected-result manifest reconcile. See
[native acceptance and qualifications](VALIDATION.md#supplied-native-indexed-group-risk-acceptance).
Observation API risk indexing/eligibility, dashboard grouping and logical findings
remain separate. Readiness remains O(N), and continuous writes can keep grouping
unavailable; no broader deployment or sensitivity claim follows.

Subsequent CI exposes SQLite index-order cost ties on filtered continuations.
The refined risk index repeats the constant head flag before risk level, avoiding
the older page index's residual scan without a planner hint. All six creation-order
and timestamp-distribution cases retain exact results and source reopening. The
refinement changes no predicates, evidence semantics or execution budgets. Its
79-file source digest is
`bf1f96fe64b5e9f3dd711e9499ab01848e6c37d1e1a35ae288bded8486261831`.
See PR #89 for final full-suite, refreshed compatibility receipts and required CI.

This closes R1.4b2a's scoped native gate. The report's Mac comparison remains
producer-attested; no Mac captures were supplied. The manifest was absent on the
runner and was compared locally during review. Private-wrapper setup, status,
sanitization and cleanup have recorded failure-propagation limits. Known-value
privacy checks do not establish arbitrary-secret absence. No repeat is needed
for this acceptance record; source-bound observation filtering is the next
separate increment.

R1.4b2b1 now makes observation risk attribution use the same safe unique alias
and saved target selectors as group staging. Different valid provider, model or
endpoint selectors leave the original observation visible with null risk.
Strict duplicate-member decoding and bounded selector validation fail incomplete
instead of borrowing another target's score. No archive, scalar-cache or schema
rewrite is included. See [contract](inventory.md) and
[local acceptance](VALIDATION.md#shared-observation-source-binding-local-acceptance).
The complete local gate passes 5,563 tests with warnings as errors and 93%
coverage. Independent review passes 42 cases on SQLite 3.40.1 and 3.53.1; both
real-server inventory modes pass all fifteen assertions over 10,000 observations.
Fresh package, metadata and installed-wheel recovery checks pass. The delivery
PR records required platform checks before merge.

The next product increment is the guided HTTP JSON application workflow
(R2.1a/R2.2a), ahead of observation-index acceleration. Operators should create a
private target profile, inspect an offline readiness plan and assess one
authorized application without hand-editing agent JSON or choosing internal IDs.
The approved scope is exact-path JSON POST, one response-text pointer, explicit
credential/canary environment references, fresh sessions and seven prompt groups
with at most 35 requests. Existing scan defaults and server admission retain
their contracts. The new adapter must bind its identity through live receipts,
both report views, scoring, checkpoints, exports and offline recovery. Setup and
active assessment ship together after real HTTP/HTTPS and installed-CLI fixture
acceptance. One scoped native retest follows that complete merged workflow; no
interim GCP run is needed for this attribution correction. R1.4 indexing,
dashboard groups, logical findings and the broader roadmap remain open.

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

That tested revision filtered a newest-100 tenant/type window. Current local
R1.4a acceptance uses [cursor traversal](inventory.md); its native operator gate
is separate. Representative accuracy and broader enterprise work remain open.
Documentation-only updates do not change the tested runtime or require another cloud run. See [targeted acceptance
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
