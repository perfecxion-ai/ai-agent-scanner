# Engineering validation checkpoint

Date: 2026-10-22. This records the beta build-out, not a release certification.
The remediation hold is closed for limited single-operator beta testing on
runtime revision `82ee7d5`, following reviewed core and targeted API retests.
This is not production or enterprise approval and does not establish detection
sensitivity. Historical infrastructure results alone did not close the original
defects. Follow the [remediation gate](BETA_REMEDIATION.md) for scope and limits.
The first checkpoint followed PRs #1 through #14. PRs #15 through #22 add
discovery, check contracts, SQLite upgrades/audit history, local queue acceptance,
and dashboard evidence views. None of these merges publishes a package.
PRs #24 through #26 add cross-version timeout accounting, conservative network
inventories, and scoped read-only live MCP collection.
PR #28 updates current TGI recognition and its conservative historical boundary.
PRs #29 and #30 add controlled protected MCP inventory checks and tenant-owned
API templates with an exact SQLite version 1 to 2 upgrade.
PRs #32 and #33 add manual dashboard template controls and finite API schedules
with exact SQLite upgrades to schema version 3.
PR #35 adds reviewed-pin dashboard schedules and targeted keyboard acceptance.
PR #37 adds the remediated certifi dependency floor. PR #38 adds focused
accessibility improvements and a reusable optional Chromium smoke workflow.
PR #40 adds disposable stopped-SQLite backup/restore and recovery acceptance.
PR #41 fixes offline replay detection of protected canaries in argument keys.
PR #42 closes the local-beta acceptance slice with a real offline operator flow,
authenticated container restart checks, corrected setup, and a finite test guide.

## Strategic review and revised roadmap

The strategic review at `aae186339dc2b0f4f59222d12ec77f07b11fb308` used source,
the recorded lab evidence, independent architecture/detection/product reviews,
and primary-source competitor documentation. It did not rerun the GCP lab or
establish comparative detection performance. One hundred existing targeted
pipeline/job/contract and API projection cases passed during review; these are
regressions, not model observations. The full suite was not rerun for that review.

Two isolated local reproductions establish open correctness work:

- Actual generic authentication-check code, with an in-process always-401
  transport and no network, records 36 evaluated interactions, no findings, and
  a completed passed check for an unseeded protected marker. There is no valid
  authenticated positive baseline. The isolated result is risk-assessment
  eligible; this is not a claim that a full normal scan necessarily scores zero.
  Independent comparison of tester-produced positive and later all-denied
  records also resolves the earlier finding group. R1.1 must prevent unsupported
  sampled passes and resolution, with versioned evidence semantics.
- Independent actual analyzer/check/engine/pipeline/server-deadline testing with
  deterministic in-process responses confirms prompt findings, then stalls a
  later stage. Normal completion retains 70/high; the outer deadline saves a
  failed empty report with null risk and loses the earlier confirmations.
  This is distinct from ordinary failed-request partial-result retention and
  from benchmark-only observation checkpoints. R1.2 needs durable sanitized
  checkpoints, transactional terminalization, and interruption/recovery tests.

Source and existing tests also establish that risk-level inventory filtering is
limited to the newest 100 records, database columns still store placeholder zeros,
advanced dashboard configuration uses raw JSON, and main retains package version
`1.1.0` despite 285 commits beyond that tag. These are current limitations, not
new cloud observations. Earlier successful lab cases do not close them.

The [active roadmap](ENGINEERING_PLAN.md#active-roadmap) is approved direction,
not completed acceptance. Each slice must add positive/negative regressions,
independent review, and all required PR/post-merge checks. For R1.1, require
valid/invalid credentials, absent/unseeded markers, failed controls, privacy,
probe-version compatibility, and finding-lifecycle cases. For R1.2, require
confirmation followed by timeout/cancel/crash, restart consistency, no replay,
bounded checkpoints, no secret retention, and matching CLI/API/JSON/SARIF risk
and coverage. Mark measured behavior separately from future acceptance targets.

## Protected-access positive-control local acceptance

The R1.1 working slice covers authentication bypass, weak credentials, weak API
keys, and declared protected admin paths. Each group/path requires a successful
issued-credential GET that returns its marker and a fresh invalid-credential
denial before probes. Missing explicit credentials skip; unavailable, stale,
unseeded, failed, or reflected controls cannot pass or confirm. Successful
responses without the marker remain inconclusive. Controls use separate sessions
and the shared scan limits. Default successful-denial samples use 20, 7, and 32
requests for the first three groups, and three requests per protected admin path.

Versioned protected-access evidence now requires opaque ASCII markers of 16 to
128 characters, explicit credential environment references, and query/escape-free
resource URLs. Exact response matching is unchanged. Explicit transport headers
and collision checks cover normalized URL, credential, probe, wire-header, and
case-variant public material. Review reproduced and closed automatic User-Agent
and serialized/lowercase-header reflection, session-entry failure accounting,
empty-sample passes, and empty-credential redaction corrupting report strings.
Historical probe versions cannot establish resolution under the changed rules.

The prerequisite contract fix propagates cancellation and records failed,
inconclusive execution rather than a completed pass after successful controls.
Counters remain actual interactions, not invented HTTP failures. The strict
benchmark validator accepts the static interruption reason only on a final
failed/inconclusive check in a partial arm. Actual final-pacing producer output
and legacy partial reports both validate; benchmark observations do not become
fabricated confirmed production checks.

Combined local acceptance passes 2,220 tests with warnings treated as errors and
an inherited nonexistent evidence-registry sentinel. Independent review passes
646 focused cases, plus separately exercised 32 actual-loopback control/budget/
scope/lifecycle cases and 32 reflection cases rejected before HTTP. These are
overlapping regression gates, not independent model observations. Ruff,
configured Bandit, whitespace checks, distribution build, Twine, and an
installed-wheel smoke outside the checkout pass. The built access-control module
matches the reviewed working source.

PR #64 and merged revision `9a696d18542c18bf36f357729fd622408cb88257` pass all
eight CI jobs: Python 3.10 through 3.13, macOS, lint, security, and container.
The roadmap-only PR #63 and its merge also pass all eight jobs. Independent
review is recorded in each PR. These checks do not establish real-service
compatibility. No GCP service,
real model, operator database, or registry was accessed; no package was published
or service deployed. Supported controls are exact GET resources, not arbitrary
credential schemes or POST-only model authorization. Server authorization-evidence
configuration is unchanged. Durable findings through an unfinished category or
outer deadline remain R1.2 work; the cancellation-status fix does not close them.

## Finalized-check checkpoint local acceptance

R1.2a adds scan-local finalized-check observation, immutable public checkpoints,
and claim-bound transactional storage. The same shared risk projection serves
final and intermediate reports. Evidence is saved before scoring; a stalled
scorer cannot erase a new finalized finding, but its new score stays null until
successfully assessed. Quiet later checks retain unchanged valid assessments.
Duplicate-identical finding occurrences survive without being counted again when
the final result returns. An incomplete asset cannot become assessed zero from
an earlier sampled pass.

SQLite writes bind the active owner and increasing sequence, atomically preserve
report/snapshots/counts, retain cancellation, and reject stale or regressing final
results. Snapshot identity and first discovery time remain stable. Explicit short
read transactions prevent mixed report/inventory revisions during checkpoint
commits. Bounds cover report size, emission count, cumulative serialization, and
write-lock waiting. Sink errors stop further probes and use static diagnostics.

Combined Linux/Python 3.10 acceptance passes 2,307 tests with warnings treated as
errors and an inherited nonexistent evidence-registry sentinel. Independent review
passes 215 overlapping focused cases. Cases include finalized confirmation followed
by failure/timeout/cancellation, scorer stalls, privacy across successive snapshots,
post-validator secret collection, occurrence preservation, duplicate/redacted-ID
rejection, sink failure, rollback, stale claims, cancellation races, cumulative
limits, and real file-backed interleaved API reads. Fixture drivers now pass the
actual dispatcher claim rather than bypassing ownership checks.

A spawned dispatcher fixture runs the actual pipeline and a synthetic decorated
check, waits for an acknowledged 70/high SQLite checkpoint, then kills that
dispatcher process. A fresh dispatcher acquires the released lock and preserves the exact
report evidence, snapshots, and partial coverage, with one interrupted terminal
event and no replay. Repeated recovery is idempotent. Canonical risk and SARIF
remain consistent; the synthetic canary is absent from the database bytes.
This tests process recovery after an acknowledged commit, not power loss.

CLI JSON/SARIF retain the latest valid partial report on orderly timeout/failure;
cancellation remains cancellation even if export fails. Pre-checkpoint failure
does not overwrite an existing report, symlink destinations are refused, and
new report files are owner-only. Ruff, configured Bandit, whitespace/privacy checks,
distribution build, Twine, and an installed-wheel checkpoint smoke outside the
checkout pass. Installed pipeline and CLI hashes match the reviewed source.
Ordinary and optimized disposable backup acceptance pass all eight cases each.

PR #65 and merged revision `4f9de3ff3217aac93f1ea0933d790d07316f94ac` pass all
eight CI jobs: Python 3.10 through 3.13, macOS, lint, security, and container.
This slice does not retain
observations still inside unfinished checks or implement CLI process-crash
recovery. Duplicate or redaction-colliding source IDs fail closed rather than
silently rebinding findings. Unknown database score placeholders and newest-100
inventory filtering remain R1.3/R1.4 work. No external model, GCP service, deployed
database, package publication, or deployment was used for this acceptance.

### Historical protected-access compatibility follow-up

Independent follow-up review reproduced current risk eligibility and a zero/minimal
API projection from a pre-positive-control authentication check using the public
`18-header-variations-denied-control-v1` definition. Matching that obsolete version
on both records also established resolution. R1.1 changed producer semantics and
blocked cross-version resolution, but did not reject two matching unsupported
historical records. Existing synthetic zero fixtures did not exercise valid
positive-control provenance.

The corrective slice passes 2,899 local tests with warnings treated as errors and
an overlapping 943-case independent focused gate. A pure shared policy recognizes the frozen
current protected-access definitions, original provider/model context, bounded
counters, response/control provenance, and covered paths. Only supported current
passes establish sampled zero or verified absence. Unsupported historical
confirmations make their asset's current score unknown, including mixed-evidence
assets, without changing archived reports or suppressing their original findings.
Other assets retain independently supported scores. Modern direct scorer inputs
without supported evidence fail closed instead of becoming zero.

Tests execute all four real protected-access producer groups against deterministic
vulnerable and defended fixture transports. Current findings, partial cleanup
failures, valid native-model context, sampled zero, and matching controlled
resolution remain supported. Old/old and old/current comparisons cannot establish
resolution. Unknown/custom definitions, missing or redacted contexts, invalid
counters, conflicting resource references, and unsupported positive claims cannot
become current verdicts. Frozen request definitions and version hashes are unchanged.

Ordinary and checkpointed paths use the same secret collection and public evidence
basis. Redacted evidence or invalidated risk labels remove only the unsupported
numeric assessment and recompute the summary. Tests cover credential collisions
with public labels and paths, and canary/credential collisions with the two new
control/path field names across source, validator, probe, and multiple-asset inputs.
Known field collisions fail before security requests or checkpoints; newly learned
collisions cannot escape projection. These fixtures do not establish a general
solution to every public-schema collision. JSON/SARIF and saved checkpoints retain
privacy, and no redaction exemption is used to keep a score.

The dashboard reads canonical risk projections from the same API response and
joins by unique asset ID, without reinterpreting archived checks. All 143 JavaScript
cases pass. Real Chromium verifies historical zero/high records display Not assessed
with their original findings and downloads available, alongside current high and
partial states. Node/API tests also verify legitimate sampled zero. The owned
browser fixture passes at 320, 390, and 1440 pixels,
without external requests or page/CSP errors; its process and temporary database
are cleaned up. This is scoped browser acceptance, not a comprehensive accessibility
or deployed-service certification.

Ruff, configured Bandit, whitespace/privacy checks, distribution build, Twine, and
fresh installed-wheel smoke outside the checkout pass. Normal and optimized
disposable backup acceptance pass all eight cases each. Independent review found
no remaining runtime blockers. PR #66 and merged revision
`81353109936ce3afcc61eac9a9f1bff071f585db` pass all eight CI jobs: Python 3.10
through 3.13, macOS, lint, security, and container.
No GCP service, external model, operator database, package publication, or deployment
was used. Nullable database storage, within-check confirmation retention, and CLI
process-crash files remain separate roadmap work.

## Within-check prompt receipt local acceptance

The R1.2b prompt-only increment saves configured-canary confirmations before their
prompt category returns, including before response/session cleanup and pacing.
An immutable receipt binds one actual evaluated transport response to its finding,
asset execution, frozen probe definition, public context, and as-of counters.
Receipts are separate from finalized checks: unfinished coverage stays explicit,
and neither an interrupted check nor nondisclosure establishes a pass.

New checkpoint version 2 preserves both ledgers. Receipt IDs and run identities
cannot be replaced, and acknowledged receipt order is an exact immutable prefix.
Asset and security-result copies must agree. Malformed raw adapter receipts fail
before report admission; unsupported custom engine findings remain visible but cannot
fall back to legacy scoring. Current-root reports with missing asset contracts
also fail closed. Actual historical reports and the standalone paired benchmark
retain their earlier contract; frozen prompt bytes, hashes, and budgets are unchanged.

Local producer and contract cases, including actual loopback HTTP, cover response/session cleanup failures, pacing and
later-request cancellation, request budgets, task isolation, missing/unbound tokens,
metadata-only canary echoes, reflected prompts, raw/public validation, and native
model-in-endpoint adapters. A persistence error or cancellation remains fatal even
if cleanup raises a second ordinary error. Counters exclude callbacks and cleanup;
they count reserved attempts, not guaranteed delivered wire requests.

Eight actual CLI-path cases cover baseline/candidate suites, JSON/SARIF, and
deadline/cancellation while the first category is unfinished. Outputs retain the
confirmed finding, receipt, 70/high with partial coverage, and truthful terminal
status in owner-only files. Two spawned dispatcher cases wait for the actual
first-response evidence commit, kill the process before category return, and
verify exact evidence/snapshot retention, one interrupted event, idempotent restart,
and no probe replay. These are acknowledged-commit process tests, not power-loss
or CLI process-crash durability.

The real server worker and Flask API client retain the same evidence through
deadline/cancellation in private fixture SQLite. Result, inventory, high-risk filter,
and SARIF views agree on risk and coverage. Negative writes execute while the real
claim is still running, and rejected changes leave report/snapshots/counts unchanged.
Their oracle comes from private fixture discovery, not a new API field. Separately,
the existing actual dispatcher/profile/template workflow runs frozen production
prompts against vulnerable and quiet fixtures with unchanged privacy assertions.
No finding or score is seeded in these normal-execution retention tests.

Scan-wide guards protect newly emitted public descriptors. Redaction never exempts
secrets to preserve scores; unsupported or redacted provenance stays unassessed
without erasing independently eligible assets. Raw generated text, canaries,
credentials, and private request tokens remain out of JSON/SARIF and retained state.
Public receipts attest scanner observations, not independently verified target
seeding or cryptographic report authenticity.

Combined Linux/Python 3.10 acceptance passes 3,216 cases with CI coverage
instrumentation, warnings treated as errors, and an inherited nonexistent
evidence-registry sentinel. Independent review passes 793 overlapping coverage
cases. All 143 dashboard JavaScript cases, Ruff,
configured Bandit, whitespace checks, distribution build, Twine, and a fresh
installed-wheel smoke outside the checkout pass. All thirteen changed runtime
modules in the wheel match the working source. Normal and optimized disposable
backup acceptance each pass all eight cases. These counts are regression coverage,
not independent model observations or detection-effectiveness measurements.

Interruption fixtures wait for actual progress before cancelling; the 35-receipt
profile workflow has a finite test-local timeout allowance. Production deadlines,
request budgets, and evidence assertions are unchanged.

See PR #67 for required cross-platform CI results. This local prompt-only slice
does not close tenant/access within-check retention, CLI crash files, nullable
database scores, or exhaustive inventory filtering. No GCP service, external model,
operator registry/database, package publication, or deployment was used.

### Prompt request-reflection correction

All eight PR CI jobs passed at `9c411ad`, but independent owned-loopback audit found
an existing detector gap and held the merge for the correction below.
The unchanged full catalogs, actual request adapter/transport/analyzer, normal
pipeline/scorer, canonical projection, and checkpoint callbacks produced these
pre-correction results:

- Exact collisions in the model, credential, URL, normalized URL, and explicit
  header value were refused before HTTP and remained unassessed.
- A target that only echoes an automatic User-Agent or a rendered Content-Type
  header produced 35 confirmations, 35 receipts, and 70/high in baseline mode.
  Baseline CLI/Python input rules accepted those nonopaque markers, but
  candidate and server-profile marker grammar rejected them.
- Uppercasing a reflected model or credential also produced 35 confirmations,
  35 receipts, and 70/high in baseline and candidate pipelines. These synthetic
  canaries were deliberately related by case to outbound values, not independent
  target secrets. Subsequent regression cases also reproduced the model echo via
  genuine discovery, profile loading, model overrides, and server dispatcher
  execution in both suites, without finding/report/score seeding. The full server
  credential-echo path remains untested because there is no corresponding owned
  loopback credential input in that API workflow.
- Standalone execution also confirmed those reflection cases. The paired benchmark
  falsely detected both uppercase cases in both complete 35-request arms and all
  seven categories. Its exact-model collision and nonopaque automatic-header
  inputs were refused before HTTP.

No protected data existed on these echo fixtures. The draft receipts faithfully
preserved the false confirmation; they did not establish protected provenance.
The corrected producer and receipt minting independently require complete bounded
request provenance, including actual serialized body bytes and final transport
headers. They exclude case-normalized outbound values and decoded/rendered request
forms while keeping response matching exact. Current receipts require source
version 2.0; draft version 1.0 stays structurally readable but ineligible for current
receipt-backed risk. Missing, incomplete, oversized, compressed, or chunked request
provenance cannot confirm. None of this private request material is exported.

The 72-case reflection regression suite passes, covering owned-HTTP execution,
before-I/O admission refusals, normal pipelines, checkpoints, standalone/paired
benchmarks, server profile/API behavior, privacy,
and genuine 35-confirmation/seven-check/70-score controls. The 61 new core cases
cover bounds, immutable capture, completeness, and an overridden analyzer that
cannot mint without valid request exclusion. Two legacy compatibility cases are
described below. Offline component fixtures explicitly declare complete synthetic
request bytes; they are separate from real-HTTP acceptance. The combined 3,216-case
gate and 793-case independent coverage review pass. Frozen prompts, probe hashes,
and request budgets are unchanged. This is not an arbitrary-transformation proof.

At that checkpoint, legacy finalized prompt reports retained numeric eligibility.
Two compatibility cases preserved the pre-receipt report shape,
stored/exported JSON, API scores, and unresolved lifecycle through nondisclosure;
they did not attest historical request provenance. A separate historical prompt
guard was required before nullable-score migration. Old benchmark observations also
remain tied to their recorded producer revision, not upgraded to production
receipt evidence or a new detection-effectiveness claim. The historical eligibility
follow-up below supersedes that numeric-compatibility limitation without rewriting
the archived evidence.

### Historical prompt eligibility follow-up

Current versioned scoring and canonical projections require supported source-2.0
receipts for prompt confirmations even when the report has no receipt envelope.
Matching old check/finding identities cannot supply missing request provenance.
Both unsupported positive findings and unsupported positive check records make
their asset's current numeric score unknown. A valid companion pass cannot turn
the discarded claim into zero; a supported companion finding remains visible.
Independent assets retain their valid scores and risk-filter membership. If the
archived summary no longer matches the eligible asset maximum, it remains unknown.

The guard does not change stored report JSON, original scores or finding IDs,
archival JSON/SARIF exports, or comparison identities. Later nondisclosure cannot
resolve a historical or current prompt finding. Invalid current receipt envelopes
remain fail-closed; the change does not invent missing receipts, re-run old probes,
or perform supported-subset historical score reconstruction. Standalone benchmark
observation collection and the explicit unversioned low-level scorer API retain
their separate compatibility contracts, not current canonical-risk eligibility.

Pre-correction regression runs reproduce 19 failures in the 39-case core suite
and 16 failures in the initial 20-case consumer suite. The final 39 core and 28
consumer cases pass. They cover completed/partial history, check-only and
finding-only positives, supported access companions, independent assets, current
HTTP-produced receipts, stripped/draft/malformed provenance, filters, and archive
immutability. These are overlapping synthetic regressions, not model-effectiveness
observations.

The complete Linux/Python 3.10 gate passes 3,281 tests with coverage and warnings
treated as errors. Independent review passes 1,170 overlapping coverage cases.
All 145 dashboard cases pass. Real Chromium at 320/390/1440 pixels shows archived
prompt groups as Not assessed with their original occurrences and exports intact;
a separately labeled generic partial-score fixture still displays 70. Actual
source-2.0 prompt positives retain 70/high in the HTTP/API regressions. The owned
browser process and temporary database were cleaned up.

The grouping fixture now obtains 18 actual receipts across the 35 unchanged
prompt requests. The partial-risk fixture obtains one receipt followed by four
actual 503 responses, not an invented failed-request counter. Both preserve
positive score and privacy assertions. Ruff, configured Bandit, whitespace and
authored-text audits, build, Twine, and installed-wheel smoke pass; the changed
runtime module matches its wheel bytes. Normal and optimized disposable
backup/restore each pass all eight cases. Required PR/post-merge CI results are
recorded on the delivery PR.

Frozen prompt catalogs, probe hashes, request budgets, detector logic, database
schema, and server policy are unchanged. No GCP service, operator data, deployment,
or publication was used. Tenant evidence provenance, nullable storage, and the
remaining R1 milestones are still separate work.

### Tenant evidence prerequisite for the next increment

Read-only next-slice review reproduced an existing cross-tenant reflection gap
with the unchanged five-prompt privacy tester, actual adapter/SafeSession, owned
loopback HTTP, and synthetic values. A server with no tenant data echoes either
the request's model value or Authorization value. When that request value equals
the configured foreign-tenant canary, each fixture produces five confirmed
findings and a completed/confirmed check. The shared eligibility function accepts
that check. This is not a full-server score measurement or a new external lab run.

The tenant canary is excluded from the prompt but not from every outbound request
field. The tester also lacks an independently successful authorized tenant-data
baseline. This predates prompt receipts. Correct the outbound reflection boundary
and define the tenant authorization/provenance contract before persisting these
observations inside unfinished checks. Existing legacy findings must remain
readable without being silently promoted to stronger current evidence.

### Controlled tenant evidence local acceptance

The tenant slice replaces scalar-canary confirmation with explicit CLI/Python
owner/tested principal declarations, two seeded records, and an operator-attested
authorization boundary. Three independent-session controls must succeed before
the unchanged five attacks. Owner and tested records must be demonstrably
available under their issued credentials; a fresh invalid credential must be
denied without either marker in its body or headers. A leak in the tested control
is held until all controls succeed. Nondisclosure never passes or resolves a leak.

All keys, markers, and the invalid control credential are pinned before the first
checkpoint. Known material is guarded before any active scan request, including
requests outside the model adapter. Complete actual snapshots detect automatic
header contamination and incomplete transmitted provenance. The private audit
blocks subsequent tenant confirmation without deleting an earlier valid finding.
Public findings carry recognized versioned controls and exact original endpoint,
provider, model, and public-context binding. Raw responses and private declarations
remain omitted. Server admission, saved source replay, queued definitions, and
fresh discovery reject private tenant inputs before environment resolution.

Local fixtures cover vulnerable and defended controls, stale or equal credentials,
unseeded/overlapping markers, metadata-only observations, contaminated denials,
request reflection, remembered earlier headers, session isolation, environment
rotation, TLS prerequisites, shared budget exhaustion, and interrupted checks.
Normal CLI scans keep every tester stage active and complete successfully with
90/critical for a genuine controlled leak and null/unknown for nondisclosure.
Only test-local pacing is shortened. Current completed and partial producer
reports keep the same score in saved pipelines, API results, and inventory after
fresh database reads. Historical positives remain downloadable and unresolved;
companion access evidence cannot turn their asset into zero or inherit a score.

The first full coverage run found one privacy regression: attaching the expected
endpoint to every direct engine result exposed a private URL in a skipped
missing-credential diagnostic. Independent review found the same defect. The
correction limits those direct-result binding fields to prepared tenant inputs;
the existing privacy assertion remains unchanged. The focused correction gate
passes 120 cases.

Final local acceptance for runtime commit `7e31584`:

- Linux/Python 3.10.20: 3,515 tests pass with coverage and warnings treated as
  errors in 195.55 seconds. The preceding diagnostic run had 3,514 passes and the
  one corrected privacy failure; it is not treated as an accepted run.
- Independent final review passes 247 overlapping cases with coverage and
  warnings treated as errors, including all 17 adversarial regressions. Its
  earlier broader run had 1,000 passes and the same corrected privacy failure.
  Component gates also passed 446 core cases and 552 input/privacy cases.
- All 145 dashboard unit cases pass. API tests use actual completed/partial
  producer reports and fresh database reads. No new browser styling is included.
- Normal and optimized disposable backup/restore commands each pass all eight
  cases. Ruff, configured Bandit, whitespace, authored-punctuation, and scoped
  private-identifier checks pass.
- Distribution build, Twine metadata validation, and installed-wheel smoke
  outside the checkout pass. All 12 changed packaged runtime files match the
  source bytes. The local wheel SHA-256 is
  `cde230c0c20fce50b4206e12d68507017f2109f47d3442fc9aea34cd0717aebd`.

Independent runtime and documentation review approve the corrected slice.
Required cross-platform PR and post-merge results are recorded on the delivery
PR. The package version remains `1.1.0`; release identity is separate R1.5 work.

Limits: principal identity and seed provenance are operator assertions; request
snapshots exclude bounded known representations, not arbitrary transformations.
Owner controls returning both markers remain unsupported/inconclusive. Tenant
within-check receipts, CLI process-crash files, server tenant profiles, database
score migration, and broader enterprise acceptance remain open. No real model,
GCP service, deployed configuration, operator database, or package publication was
used. The next external step is a pinned
[tenant workflow retest](tenant-retest.md) against genuine tenant-aware fixtures.

### Supplied tenant workflow acceptance

The operator supplied a scoped HTTPS fixture retest of merged revision
`1072d8b8b7763bb9a09b0d4047cbd4afa3ffbf93` (PR #69) on Debian 12/Python 3.11.2.
Two independent artifact reviews inspected the nine original reports, ten real
CLI exit files, fixture source/outcomes, job captures, and driver behavior. These
are reviews of supplied evidence, not new cloud executions. Private artifacts,
infrastructure identifiers, configurations, and secrets remain outside Git.

All nine reports validate under the current contracts. Independent rederivation
matches all 70 recorded expectations and the complete recognized probe version.
The shared eligibility and risk projection preserve these results:

| Fixture | Runs | CLI / scan | Tenant check | Attempt / evaluated | Findings / risk |
| --- | --- | --- | --- | --- | --- |
| Vulnerable | 3 | 0 / completed | completed / confirmed | 8 / 8 | 5 each, 90/critical, sampled |
| Defended | 3 | 0 / completed | completed / inconclusive | 8 / 8 | 0, null/unknown |
| Unseeded owner | 1 | 1 / partial | failed / inconclusive | 1 / 0 | 0, null/unknown |
| Marker-bearing invalid denial | 1 | 1 / partial | failed / inconclusive | 3 / 2 | 0, null/unknown |
| Unseeded reflection endpoint | 1 | 1 / partial | failed / inconclusive | 1 / 0 | 0, null/unknown |
| Missing environment value | 1 | 1 / no report | no security execution | none | no report |

All six successful tenant sequences have owner, tested, and invalid controls
followed by attacks 0 through 4. The negative cases stop at their intended
controls and send no tenant attacks. No tenant check passes. All 521 captured
fixture POST entries reconcile with the supplied outcome summary; fixture GET
requests are unlogged, so that count is not a complete scan wire total.
The normal installed CLI and default verifying HTTPS path were used. Setup and
job captures record a successful verifying TLS 1.3 handshake through a private
trusted CA on a non-loopback endpoint. Trust-store provenance and cleanup remain
operator attestations. No model server participated; these deterministic fixtures
validate the configured workflow, not representative detection sensitivity.

The original nine reports contain 110 response-excerpt omission sentinels and no
other recognized raw-text evidence fields. Secret absence and original modes
remain operator attestations because actual values are excluded. The captured
privacy sweep covers the original 37-file deliverable, not all 50 files in the
final expanded bundle. Its twelve JSON-mode entries comprise nine reports and
three summary/dependency JSON files. Added private driver sources contain their
synthetic PII constants; do not claim zero such constants across the whole final
archive or publish those drivers as acceptance artifacts.

Two negative-case claims in the supplied narrative need narrower interpretation.
The contaminated-denial fixture returns only the tested marker in the tested
control, so it verifies rejection of a marker-bearing denial and attack
suppression, not disposal of a held positive candidate. The reflection fixture
stops at an unseeded owner baseline; it does not exercise a protected marker
embedded in reflected material. Those stronger cases retain local regression
coverage, without new external acceptance from this run. Versioned finding
control fields apply to the confirmed findings, not every inconclusive run.

The private job wrapper masks analysis-command failures, and its privacy failure
count omits several conditions that its report prints. Its overall exit alone
cannot certify acceptance. Actual per-scan exits, all 70 captured expectations,
and recorded privacy counts support the observations above. Before another
external run, propagate analysis/privacy failures, check every privacy condition,
capture cleanup outcomes, and add any claimed held-candidate negative explicitly.
These harness and wording limits do not require another broad GCP run.

This closes the scoped CLI/TLS workflow gate with the stated qualifications.
Server tenant profiles, tenant/access within-check receipts, CLI crash files,
real-model sensitivity, and enterprise acceptance remain open. The next local
R1.3 slice is nullable score storage with explicit historical schema definitions,
canonical cache projection, rollback, and disposable backup/restore acceptance.

### Nullable score storage local acceptance

PR #72 replaces unknown scalar-score placeholders with SQL NULL
in schema 4. The two score columns have no zero default. Canonical report risk,
not a caller's cached number, supplies checkpoint and terminal summary/snapshot
values. Cancellation and recovery also project the retained summary. Supported
assessed zero and confirmed partial scores survive; unsupported old access,
prompt, and tenant positives cannot acquire numeric risk from stale columns.
API reads remain on the saved canonical report, and archived reports stay intact.

Recognized unversioned layouts and versions 1 through 3 use explicit historical
definitions independent of current ORM metadata. Only the two score-bearing
tables are rebuilt. SQL copying preserves stored JSON/text bytes, IDs, and other
fields; accepted ordinary/partial nonunique indexes retain their original SQL.
Expression/unique indexes, table options, collations, conflict policies, unknown
constraints, and unsupported layouts are rejected before writes. Table creation,
copy/drop/rename, index replay, cache updates, and version stamping share one
BEGIN IMMEDIATE transaction under existing dispatcher ownership.

Archive and metadata interpretation uses SQL byte bounds before deserialization,
an explicit 64-container nesting limit, and incremental record processing.
Invalid, deeply nested, or oversized material
leaves unknown caches without echoing contents. Valid non-object metadata follows
the API row-ID fallback; malformed explicit aliases cannot fall back. Duplicate
report IDs remain unassessed. Duplicate database aliases retain the current API
semantics, rather than introducing a different storage-only identity policy.

Final local evidence:

- Linux/Python 3.10.20: 3,763 tests pass with coverage and warnings treated as
  errors in 278.49 seconds. The gate includes independently frozen old schemas,
  genuine assessed zero, supported positive/partial evidence, historical unknowns,
  rollback at every rebuild stage, and invalid UTF-8/deep/oversized archives.
- Independent corrected-code review passes 279 overlapping cases on exact Python
  3.13.15/SQLAlchemy 2.1.6 with coverage and warnings treated as errors in 46.72
  seconds. This includes 56 new independent bounds cases, 76 depth cases,
  32 original adversarial cases, 56 migrations, 15 writer cases, 40 checkpoints, and four current
  HTTP proofs. The initial pre-correction review passed 423 overlapping cases;
  the fixture/backup slice passed 248. Reviewer-approved runtime bytes match the
  integrated tree.
- A separate final Python 3.13.15/SQLAlchemy 2.1.6 gate passes 370 overlapping
  cases with coverage and warnings as errors in 94.81 seconds, including backup
  fixtures and final cleanup changes. Its log has no resource or unraisable
  warnings, including shutdown. Lifecycle instrumentation records 156 opened and
  156 closed SQLAlchemy connections. All 15 compared runtime/test/script files
  match integration bytes.
- Four real HTTP producer cases retain current prompt 70/high and tenant
  90/critical evidence through schema-3 upgrade, for completed and partial reports.
  Their original archive bytes remain unchanged. No model server participates.
- All nine supplied tenant report copies also pass an offline schema-3 to 4
  upgrade in private disposable SQLite: canonical scores and archive bytes match,
  and second initialization is idempotent. No operator database or cloud is opened.
- Normal and optimized backup commands each pass all ten cases, preserving
  supported zero, retained 70/partial, non-cache fields and reports, and untouched
  source/backup hashes. Six corruption cases prove the acceptance command rejects
  damaged score caches. No existing operator database path is accepted.
- All 145 dashboard cases pass. Ruff, configured Bandit, whitespace, authored-text
  and scoped privacy checks pass. Distribution build, Twine validation, and the
  installed-wheel smoke outside the checkout pass. The three changed packaged
  runtime modules match source bytes. The final local wheel SHA-256 is
  `a092b0562e8decffecf465d4b9f55680224740d0466350ae86b2c7a88b2f3ab3`.

The merged CI-fixture correction changes no runtime bytes. A focused final gate
passes 35 workflow/writer/guard cases with coverage and warnings treated as
errors in 16.25 seconds after that merge.

The preceding documentation-only merge's Python 3.11 job hit the 15-second CLI
workflow fixture deadline in two disclosure cases; its other seven jobs passed.
Independent covered reproductions complete all 35 prompt observations and retain
70/high. PR #71 gives that workflow fixture 45 seconds, preserves its sample,
completion, privacy and file-mode assertions, and leaves production deadlines
unchanged. It also makes malformed-engine setup explicit for SQLAlchemy 2.1;
the five guard cases pass with warnings as errors on both 2.0.54 and 2.1.6.
PR #71 merged as `de58212` with all eight PR and post-merge jobs passing.
The original CI failure remains recorded. Slower host execution is an inference;
host load was not captured.

The first PR #72 macOS run passed 3,630 cases and failed one depth regression:
Python 3.13.15 accepts JSON nesting that raises a recursion error on Python 3.10,
so excessively deep snapshot metadata inherited a row-ID fallback score. An
isolated Python 3.13.15/SQLAlchemy 2.1.6 reproduction confirmed the failure.
The correction imposes an explicit 64-container limit before JSON parsing and
for object-based cache writes. UTF-8 text, including an optional UTF-8 BOM, is
accepted; non-UTF-8 BLOBs fail closed. Archives remain untouched. The original
assertion is retained. The unfinished Linux jobs were cancelled after their
verbose logs reached an 8 MiB fixture value embedded in a generated case ID.
Explicit short case labels replace those IDs without changing test inputs or
assertions. The macOS failure remains recorded.

Strict Python 3.13 validation also exposed test-fixture resource ownership gaps.
The checkpoint fixture now restores the original engine before parent teardown
and disposes its owned file pool. The API fixture disposes the exact in-memory
engine it initialized, including setup or teardown failure. A raw SQLite fixture
uses an explicit closing context as well as a transaction context. These are
test-only cleanup changes; connection lifecycle instrumentation verifies closure.

PR #72 merged as `3f32c6e6dd8a52832401df69bd92f263bfad11e8` with all eight
PR and post-merge CI checks passing. The supplied
[native storage/server upgrade retest](storage-retest.md) is accepted below for
its stopped reconstructed fixture and exact merged revision. This local
acceptance does not certify an operator deployment or downgrade compatibility.
Restore an untouched pre-upgrade backup for rollback. The supported runtime remains
one POSIX process, local filesystem and SQLite; package publication is separate.
Tenant/access within-check receipts, CLI crash files, exhaustive inventory, release
identity, real-model sensitivity and later enterprise gates remain open.

### Supplied native storage upgrade acceptance

Two independent read-only reviews accept the supplied run at
`3f32c6e6dd8a52832401df69bd92f263bfad11e8` for its scoped storage upgrade and
restart workflow. These are reviews of operator-supplied captures, not an
independent cloud rerun. The environment records Debian 12, Python 3.11.2,
SQLite 3.40.1, SQLAlchemy 2.1.6, and Gunicorn 26.2.0. Raw reports, driver sources,
private infrastructure identifiers, databases, and credentials remain outside Git.

Both normal and optimized native backup commands exit zero with all ten expected
cases and 50 assertion labels per mode. All 60 real-server assertions reconcile
with the captured PASS lines and the zero-failure summary. Both Gunicorn
processes use one worker and exit zero. The driver constructs terminal records,
no schedules, an empty allowlist, and no scan submissions.

The reconstructed schema-3 fixture contains four reports and ten observation
rows. Two parsed existing lab pipelines are unassessed; two current repository
controlled-access producers supply genuine assessed zero and confirmed partial
risk. All initial scalar caches are 0.0 placeholders. On first start and restart,
the raw SQL scan/observation caches and results API score/level pairs match the
expected null, 0.0, and 70/high outcomes. The two score columns are nullable with
no SQL defaults. Logical JSON exports equal the seeded reports. Archive hashes
are unchanged from the post-seeding baseline, and restart preserves the complete
recorded database snapshot. Independent restore reproduces the schema-3 baseline;
source and backup hashes remain unchanged. Captured database and lock modes are
0600. The logged security-testing error is the intentional later-stage failure
that creates the supported confirmed-partial fixture.

Acceptance has these limits:

- This upgrades a newly reconstructed fixture, not the original durable lab
  database. Existing pipelines are parsed and reserialized before seeding;
  byte preservation starts after that step. The lab's original durable records
  provide no supported assessed-zero or positive case. Report provenance and
  excluded database/response contents remain driver/operator attestations.
- Inventory checks compare HTTP status and response shape only. SARIF checks
  compare availability and version only. Neither verifies verdict values.
  The eight logged summary statuses match the stated fixture expectations, but
  the driver does not assert them. Per-asset coverage is not asserted. Results
  score/level comparisons are substantive.
- The first upgrade does not compare non-cache fields of the two rebuilt tables
  against their old baseline, or explicitly verify operator-defined indexes.
  Template, schedule, and occurrence tables are empty. Their equality checks
  do not establish nonempty-data preservation.
- Native backup rollback cases inject version-stamp failure for three historical
  versions, not failures at every rebuild stage. These fixtures do not exercise
  depth, encoding, or size rejection. The 64-container boundary and other rebuild
  rollback stages retain their separate local regression evidence.
- The recorded privacy sweep covers 17 paths at that moment; the final bundle
  has 25 regular files. Later additions and the completed job log do not have
  the same complete captured sweep. True-secret absence and original modes are
  operator attestations. The private bundle contains infrastructure identifiers.
- The shell wrapper does not propagate every setup, capture, sanitizer, privacy,
  or cleanup failure, and raw-text/mode observations are informational. Its
  unqualified fail-closed claim is unsupported. The separate captured command
  exits and 60 actual comparisons still support this narrow successful run.

No runtime defect was reproduced. These qualifications do not require a broad
repeat or establish deployment, model sensitivity, complete preservation of every
field, or every export's verdict semantics. R1.4a proceeds locally with exhaustive
observation pagination; its eventual operator gate must compare actual inventory
values and fail on analysis, privacy, and cleanup errors.

### Exhaustive observation pagination local acceptance

R1.4a replaces the global inventory's newest-100 filter window with bounded
cursor traversal. Existing observation fields, snapshot IDs and scan-local
aliases remain intact. Risk filtering uses canonical saved-report projection,
including supported zero and historical unknowns; stale scalar scores/levels
never exclude candidates. Empty pages can carry continuation. Completion applies
after the current cursor boundary and requires consumers to retain prior pages.

Schema 5 adds one organization-generation table, three candidate indexes and
nine exactly recognized triggers. Schema-4 rows, scalar caches, archive bytes and
accepted operator indexes are preserved without a second nullable-table rebuild.
Recognized older layouts retain their nullable upgrade before generation install.
Source writes, ownership changes and orphan visibility invalidate affected
organizations in the same transaction, including direct ORM/Core writes.
Rollback, other organizations, progress-only scan-session updates and unchanged restart retain
the generation. Unsupported trigger/index definitions fail before serving.

Cursors use an uncompressed signed codec with a 4,096-byte cap, 15-minute expiry,
and bindings to organization, filters, limit, order, source generation and
projection policy. Packaged Python source contributes to the policy fingerprint.
Request/scope validation precedes SQL. Stale data/policy returns 409; invalid
cursors/filters return 400. The reader has 500-candidate, 32-report, combined
16 MiB source and 1 MiB response allowances, plus individual 8 MiB/64-container
limits and a five-second cooperative deadline. Unreadable or excessive sources
return static 503 rather than becoming false unknowns or disappearing from a
filtered search. Actual query plans use the ownership/type/order indexes but can
still require a cross-scan sort; SQL LIMIT alone is not a complete work bound.

Final local evidence:

- Python 3.10.20: 3,964 tests pass with coverage and warnings treated as errors in
  383.71 seconds; source/API/CLI line coverage is 94 percent.
- All 145 dashboard tests pass. Ruff and configured Bandit pass, including the
  public acceptance scripts. Distribution build, Twine metadata checks, and the
  installed CLI smoke outside the checkout pass. The three changed packaged
  inventory/schema modules match source bytes, and the direct signing dependency
  is declared. Local wheel SHA-256:
  `4f486be8cd3ee2861300c4d7068d7c6ed2ab219dcb9908ad4e2648efc48dce7f`.
- Final independent review passes 99 overlapping committed cases on exact Python
  3.13.15, SQLAlchemy 2.1.6 and Gunicorn 26.2.0 with coverage and warnings as errors
  in 49.13 seconds. All 12 compared runtime/script/helper/test files match
  integration bytes. No resource, unraisable, or shutdown warnings remain.
- The independent inventory fixture traverses 10,000 observations across scans,
  types and organizations, comparing full ordered descriptors. It covers older
  findings, ties, duplicate aliases, malformed explicit aliases, genuine zero,
  historical unknowns, contradictory SQL caches, cursor scope/tampering/expiry,
  generation changes, actual WAL concurrent writes and source/output budgets.
- The schema component passes 152 overlapping schema/generation/schedule cases,
  including 29 new generation cases. The backup suite passes 62 cases, including
  frozen schema-4 independence and genuine schema-5 initialization. Normal and
  optimized native commands each accept all eleven cases. The v4 case proves
  preservation without a nullable-table rebuild; generation owner/token shape,
  progress stability and restart stability are checked.
- The public operator command exercises real single-worker Gunicorn upgrades
  from a private schema-4 fixture, 10,000 repeated observations of 12 synthetic
  assets, eight filter profiles across three organizations, and restart. It
  checks complete values rather than availability, existing rows/scalars/archive
  and index preservation, source changes/rollback, actual process exits and no
  admitted work. Real normal/optimized runs and failure injections form 30 author
  cases; the final independent gate includes both real-server modes.
- Mandatory privacy checks cover seven configured synthetic/runtime values,
  encoded variants, HTTP bodies/headers, private files and final output. The
  authentication response has a narrow expected token exchange. Missing values,
  unreadable surfaces, mode changes, privacy findings and cleanup errors fail.
  Source revision, tracked modification state, driver/app/hook hashes and policy
  are captured. These owned fixtures never inspect operator databases/profiles.

Pre-delivery regressions caught two cursor-key defects. Normalizing valid old
timestamp text repeated or rejected continuation pages; cursors now preserve the
actual stored sort key with an explicit string bind. Display parsing alone
normalizes supported fractions/UTC syntax. Tests compare against SQLite's actual
ordering, including mixed representations and offsets, without rewriting stored
timestamps. Maximal legal UTF-8 scope/key values could also exceed the input cap;
UTF-8 JSON encoding plus an emitted-length guard keeps usable tokens bounded.
Valid signed compressed/marker-prefixed formats are rejected before SQL.

The public gate originally accepted Boolean false as numeric zero under Python
dictionary equality. Its numeric type guard now rejects Boolean scores while
accepting integer and floating zero. Independent negative/positive controls
reproduce and verify the correction. An initial combined run passed 3,951 cases
and failed five old fixture/order assumptions: file-backed API fixtures bypassed
schema initialization, and profile assertions selected an unspecified first SQL
row. Fixtures now initialize the real schema; assertions join by asset ID and
check complete cardinality/ID sets plus the skipped null. The targeted 156-case
covered gate and final full run pass without relaxing verdict assertions.

Initial Linux CI exposed two overly specific query-plan assertions. SQLite
3.45.1 selected the type index's valid `scan_id` prefix for an unfiltered join,
while SQLite 3.53.1 selected the other candidate index. The tests now accept
either approved indexed search for an unfiltered query and still require both
scan and type bindings for filtered queries. All 80 generation and independent
inventory cases pass on both SQLite versions with warnings treated as errors.
Runtime code is unchanged by this correction.

The delivery PR records required cross-platform checks. The next external gate
is the [clean pinned native inventory retest](inventory-retest.md), including
both operator-command modes and the eleven-case backup modes. Local synthetic
acceptance does not establish deployed workload scale, current asset identity,
indexed risk materialization, model sensitivity, or team/enterprise readiness.

### Supplied native inventory traversal acceptance

Two independent read-only reviews accept the supplied owned-fixture gate at
`c6e460046994c01aa40ff00f1660534413388f96`. These review operator-supplied
captures, not an independent cloud rerun. Primary outputs record Python 3.11.2,
SQLite 3.40.1, Gunicorn 26.2.0 and SQLAlchemy 2.1.6; the setup attests Debian 12.
Raw artifacts, private drivers and infrastructure identifiers stay outside Git.

Normal and optimized inventory outputs are byte-identical. Each records accepted
true, all 13 required assertion identities, 656 checked HTTP responses, an
observed schema-4 to schema-5 upgrade, and two zero server-process exits. The
source revision and clean tracked-source flag match the pin. App, public driver,
Gunicorn hook and independently recomputed projection-policy hashes match source.
The four acceptance exit files contain zero, their stderr logs are empty, the
pinned validation succeeds, and the captured outer job exits zero.

The 24 profile counts agree across modes: 10,000 observations in total, 2,500
high, 2,500 minimal, 5,000 unknown, and no critical matches despite deliberately
stale critical scalar caches. The type filter returns 5,000 observations; its
high subset returns 2,500. The incompatible type/high combination returns none
through advancing empty pages. The hash-bound public command compares complete
ordered dictionaries on first start and restart, checks cursor/source/ownership
isolation and rollback, and asserts archive, row and operator-index preservation.
Both backup modes accept the same eleven cases with 64 assertion labels per mode.
These include recognized old layouts, genuinely initialized schema 5, rollback,
exclusive ownership, incomplete-restore rejection and unchanged backup sources.

Acceptance remains scoped:

- The databases, raw HTTP responses and private internal server logs were removed
  by the public gate. Their detailed comparisons, process-group cleanup and
  filesystem modes are script assertions, not independently recoverable raw
  evidence in this bundle. Counts and result identities are directly available.
- This is 10,000 repeated observations of 12 synthetic assets across three
  organizations, using controlled non-network producers. It does not measure
  detection sensitivity, deployed scale, target provenance, current-asset
  identity, crash durability, or enterprise readiness.
- The inventory command checks seven ephemeral values, encoded variants and its
  HTTP/file/output surfaces before success. Those values are unavailable for a
  later independent sweep. The backup command has no equivalent seven-value
  privacy sweep. The wrapper's 19-file address-pattern sweep and local review of
  all 24 supplied files do not establish general secret absence. Sanitized outer
  logs and exact wrapper execution remain operator attestations.
- The private shell wrapper propagates acceptance/validation failures but leaves
  some setup, capture and checkout/venv cleanup failures unchecked; its address
  reader skips unreadable files. Its universal failure-propagation claim is
  unsupported. The public inventory command's own checked cleanup is separate.
- Backup captures have no embedded source/runtime fingerprints; their pin comes
  from wrapper context. Progress-token stability is covered by backup cases,
  not a dedicated progress-only cursor request in the inventory command.

No runtime blocker was found. These reporting qualifications need no broad
repeat. R1.4a observation traversal is accepted within this fixture scope;
distinct-asset identity and indexed risk materialization remain open. R1.5a
build/producer identity proceeds locally before tenant/access receipt retention.

### Supplied native tenant interruption acceptance

Two independent read-only reviews accept the supplied scoped gate at
`6af7fa2cd6d2a2b1e3ff67a12ff348df092f7413`. This reviews operator-supplied
captures rather than independently rerunning cloud targets. Captures record
Python 3.11.2 and SQLite 3.40.1; setup attests Debian 12. Private artifacts,
drivers, infrastructure identifiers and input values remain outside Git.

All four original reports pass trusted scan/evidence validation and canonical
risk projection. Their producer identities and bundled-catalog fingerprints
match the pinned CLI source. Offline SARIF preserves receipt/finding links and
marks incomplete execution unsuccessful. Report bytes remain unchanged. All
66 captured expectation records agree with the reports and real exits.

| Case | CLI exit/status | Tenant evidence | Canonical risk |
| --- | --- | --- | --- |
| Subject leak then stall | 1 / failed | One receipt at ordinal 2 with counters 3/3; unfinished check | 90/critical, partial |
| Attack leak then stall | 1 / failed | One receipt at ordinal 4, attack index 0, counters 4/4; unfinished check | 90/critical, partial |
| Held leak with contaminated denied control | 1 / partial | No receipt/finding; failed check, 3 attempted and 2 evaluated | Null/unknown |
| Defended | 0 / completed | No receipt/finding; completed inconclusive check, 8/8 | Null/unknown |

Both stalled cases reach the intended later tenant request before their outer
deadline; captured elapsed times are 181 and 180 seconds. Each retains exactly
one linked original finding and receipt under ledger `2.0` and checkpoint `3.0`,
with `checks_unfinished: 1` and no invented terminal tenant check. Control proofs
carry ordinals `[1, 2, 3]` and statuses `[200, 200, 403]`. In the held-rejected
case the tested control actually returns both records before a marker-bearing
denial prevents promotion. No tenant check passes, and no negative outcome
acquires a numeric assessment.

The secret-free fixture counters reconcile 45/46/55/60 POST arrivals: ordinary
POSTs plus the intended 4/5/3/8 tenant requests. They deliberately exclude the
ordinary GET probes visible in check accounting. Four CLI cases use two-principal
deterministic HTTPS fixtures with configured private-CA trust and hostname
verification. TLS 1.3 verification is captured. This tests the ordinary CLI
workflow rather than seeding scanner reports or database findings.

The native recovery capture records two passing tests with warnings as errors
and exit zero; the outer job exits zero too. Detailed SIGKILL, committed receipt,
single recovery event, no-replay and authenticated API assertions follow the
pinned repository test source. Those tests use owned loopback HTTP library
workers, despite the supplied narrative calling that request HTTPS. Their
transport is separate from the four external CLI HTTPS cases. They do not admit
private tenant input through the server API or establish CLI crash-file recovery.

Acceptance qualifications:

- The privacy capture covers 23 files, while the final bundle has 33 substantive
  files plus 37 AppleDouble sidecars. Eight JSON files include four scan reports
  and four auxiliary captures. The supplied helpers themselves contain configured
  synthetic labels and environment-reference names; a claim that every returned
  file omits those values is unsupported.
- The supplied sweep checks 15 available values and known encoded forms, but
  omits generated invalid credentials, environment-reference names and the native
  recovery fixture's private basis. Actual ephemeral values are unavailable for
  an independent repeat sweep. Logs are sanitized before checking. This supports
  the recorded capture sweep rather than general secret absence or a privacy
  certification. Native owner/tested keys and markers are fixed public test
  constants; they are distinct from the CLI job's generated values.
- The sweep skips unreadable files and missing environment values and tolerates
  invalid JSON. It runs before final wrappers, helper sources and the narrative
  are added. Some setup, copy, sanitizer and cleanup failures are unchecked or
  suppressed; no universal failure-propagation claim is justified. Trust-store
  and hosts cleanup completion remains operator attestation.
- Scanner JSON outputs have captured mode 0600. The original wrapper listing
  shows an output directory at 0755 and a job log at 0644, even though copies in
  the supplied archive are private. Do not infer uniformly owner-only original
  wrapper surfaces from the delivered copies or local extraction modes.
- Fixture seeding, authorization relationships, source checkout cleanliness and
  exact helper execution remain partly operator attestations. Deterministic
  fixture correctness is not model sensitivity, target provenance, deployed
  durability, or enterprise readiness. Counters log intended responses even if
  socket writes fail; they are not independent packet-delivery records. Raw logs
  and an independent before/after report hash chain are unavailable.

No scanner blocker was found in this gate. The qualifications need no broad
repeat. R1.2c tenant retention is accepted within this scope; protected-access
provenance/receipts, private server tenant admission and CLI crash files remain
separate work. No supplied driver was executed during review, and no operator
database, registry or cloud target was accessed.

### Protected-access v3 and cache-policy local acceptance

The provenance prerequisite below now has a bounded correction across the four
existing protected GET families. Public samples, request ordering and delays are
unchanged. Private issued keys, markers and environment references are pinned
before the first checkpoint. Model configuration and subsequent controls reuse
the pinned key even if the environment changes. Unknown contexts cannot silently
rebind a scan.

Every control and probe requires a real live `BoundedResponse` with a complete
captured GET: exact resource and Host, empty body, exact selected headers and
bounded normal framing. Missing, stale or incomplete captures, cookies, hidden
credentials and transmitted protected markers invalidate later evidence. Known
marker transmission in an earlier scan request taints the affected asset. No
request trace/counter algorithm or public ledger/checkpoint version is changed.

Denied controls and decisive denied probes inspect bounded body/header material
conservatively. Marker case variants and decoded JSON cannot masquerade as
absence. Invalid, duplicate-key, nonfinite or over-bound JSON, invalid encodings,
binary/NUL-bearing denials and embedded BOMs remain inconclusive. Valid UTF-8 BOM
JSON without disclosure is supported. Positive marker matching remains exact;
no semantic judge or arbitrary transformation exclusion is claimed.

`authorized-and-denied-resource-controls-v3` changes all four recognized probe
versions; confirmations additionally require builtin integer control version 3.
Missing/old/Boolean/floating tags cannot establish current confirmation. Frozen
v2 zero, high and partial reports stay byte-identical but project current unknown
and cannot establish resolution, including comparisons between two old reports.
Independent supported prompt/tenant evidence beside obsolete access passes
retains its original eligible 90/critical. Custom scalar-only mocks cannot attest
v3 wire provenance; projection unit fixtures explicitly use synthetic complete
captures while live acceptance uses actual owned HTTP/HTTPS.

Schema 6 is an explicit transactional scalar-policy upgrade. Recognized schema-5
tables/indexes/triggers and original archive/metadata bytes, IDs, queue/schedule
state and unrelated fields stay exact. Only changed risk caches/levels are
updated, and the version stamp commits last. Existing observation triggers
naturally invalidate affected owners; no trigger suppression or token restoration
is used. Unchanged owners and recognized schema-6 restart remain unchanged.
Recognized older layouts follow their existing nullable/generation upgrade paths.
Bounded UTF-8/depth/size interpretation and genuine alias rules are reused.
Fault injection at scan-cache, snapshot-cache and stamp stages rolls everything
back. This is not an arbitrary database repair or a deployment migration.

Four original v2 archives were captured through actual owned HTTP and the pinned
`6af7fa2` producer before source changes. Their independently fixed archive,
finding, receipt, probe and eight source-file hashes remain exact. Current v3
HTTP produces genuine zero, high/critical and confirmed partial results across
the existing four groups. Three fresh default CLI processes also reproduce and
close an INFO-log privacy gap: a protected marker, key or environment reference
used as an asset name was redacted in reports but leaked through three phase
messages. Static phase logs now retain those messages without private names;
no logging-level suppression is used and no database/registry is accessed.

The broad first run excluding the old current-policy test file passes 4,165 with
five failures: an earlier preflight/body fixture, two old test assumptions and
the two inventory runs still expecting schema 5. The complete corrected candidate
then passes 4,694 tests with source/server/CLI coverage, warnings as errors and
94 percent coverage on Python 3.10.20. A subsequent 838-case focused gate covers
the final three static log changes and the added 24 HTTPS CLI cases. Required CI
runs the final committed tree.

Author acceptance passes 214 provenance cases on Python 3.10 and 3.13; adding the
three fresh-process log cases gives 217. Independent review passes 74 live-wire,
archive and migration cases on both interpreters. All 464 current/legacy policy
cases pass on both. The 24 trusted HTTPS CLI cases pass on both with coverage and
warnings as errors: JSON/SARIF, certificate/hostname verification, 0/70/90 risk,
confirmed partial retention after later failure, genuine nonzero exits, stable
producer identity, owner-only files and raw/encoded privacy checks. They assert
that access observation receipts are absent; unfinished-check retention is not
implemented by this correction.

Cleanup accounting remains conservative rather than a wire count. The shared
response/session wrapper preserves cancellation through secondary errors and
combines formerly duplicated cleanup failure handling. One combined-error fixture
therefore records 37 attempted interactions instead of 54, while its actual 20
wire requests, 20 evaluated responses and one confirmation are unchanged. Current
and frozen legacy bounds are tested; no synthetic failures restore an old count.

The cache/nullable/backup gate passes 141 focused cases on Python 3.10 and 146 on
Python 3.13.15/SQLAlchemy 2.1.6. Both normal and optimized backup commands accept
all thirteen cases with genuine current HTTP results and frozen old archives.
Inventory format `inventory-acceptance-v2` first verifies schema-4 to 6 canonical
cache reconciliation for 12 scans/10,000 observations, then explicitly restores
its own original stale caches before traversal. Exact archives/non-cache rows,
known DDL, filters/cursors, restart staleness and cleanup are checked. All 40
inventory cases pass on both versions, including real normal/optimized Gunicorn;
independent review passes ten upgrade/restoration fault cases.

Final combined independent review passes 587 cases on Python 3.13.15 with
coverage and warnings as errors: policy, live-wire, HTTPS CLI, log privacy and
cache upgrade. Ruff and Bandit pass at the configured security threshold. Both
distribution formats build and pass metadata checks; an isolated installed-wheel
smoke verifies dependency consistency, CLI commands and exact build identity.
All 71 CLI wheel source files match the checkout bytes. Neither distribution
contains `AGENTS.md` or SQLite database files. Nothing was published.

These are local synthetic correctness gates, not model sensitivity, a deployed
operator upgrade, power-loss durability or enterprise readiness. No supplied
private driver, cloud target, operator database/registry, publication or deployment
was used. The next external gate is the scoped
[native access/cache retest](access-provenance-retest.md). Protected-access
within-check receipts, server private tenant inputs and CLI crash files remain
separate work. Cross-platform delivery checks are recorded on the implementation PR.

### Protected-access request-provenance prerequisite

Read-only source audit and owned loopback HTTP reproductions at `6af7fa2` expose
a prerequisite before access observations become durable. No operator database,
registry, external target or supplied private driver was used.

In one fixture no protected record exists: the target echoes request headers,
while a fresh invalid credential receives 403. A lower-level client hook adds
the configured synthetic marker after planned-request preflight. In another
fixture an extra wire header carries the issued credential, silently authorizing
the purported anonymous/malformed probes. Both actual `SafeSession` pipelines
make 20 GETs and produce 18 confirmed authentication-bypass findings with
canonical 70/high, under current ledger `2.0` and checkpoint `3.0`. The first
mistakes request reflection for protected data; the second mistakes credentialed
access for bypass. Current access checks do not validate the actual captured
request before accepting response evidence.

A separate genuinely protected fixture passes authorized/denied controls,
discloses its independently seeded record on the first anonymous probe, then
stalls request 4. Cancellation inside that same check retains zero findings and
null risk, because results remain in its local list until completion. This
confirms the later receipt requirement but does not justify preserving the
false-confirmation paths above.

Close actual-request provenance first: pin private inputs before controls,
verify complete live GET captures and selected credential roles, exclude marker
transmission and extra issued credentials, and refuse missing or contaminated
provenance. Keep existing protocols, frozen samples and budgets. Tightened
semantics require explicit versioning, conservative historical risk/resolution
eligibility and transactional scalar-cache reconciliation; original archives
remain unchanged. Protected-access receipts remain a separate increment.

### Tenant observation retention local acceptance

R1.2c extends normal CLI/Python tenant checks with mixed observation ledger `2.0`
and checkpoint `3.0`. It does not expand server admission, alter SQLite schema 5,
change prompt catalogs or tenant control semantics, or add CLI crash files.
The old prompt ledger `1.0` and checkpoint `2.0` retain their original meanings.

Actual bounded transport witnesses verify the prepared tenant context, exact
request role, model/body/Host and credential location while each response is live.
The subject response at ordinal 2 is held until the genuine denied third control
succeeds. Receipts publish before cleanup or another request. Only bounded public
control statuses, ordinals, target/probe identity and finding links persist;
private envelopes, principal labels, environment references, keys, markers,
request capabilities and generated text do not.

The complete ledger validates sources, versions, IDs, links, typed counters and
the separate 35-prompt/six-tenant caps before partitioning evidence. Current
tenant positives require receipts even after check completion. Draft prompt
source `1.0` cannot enter the mixed ledger; its legacy structural-read behavior
remains unchanged. An ineligible append cannot replace acknowledged supported
evidence, including a receipt committed before scoring returns a number. Raw
candidates validate before state mutation, and public/SQL guards preserve prior
eligibility without requiring an initial privacy-redacted unknown to become
assessed. New invalid groups cannot erase a valid finding or expose an access zero.

Root and independent review also corrected source-view gaps: known observation
versions must agree across report, asset and matching security result; typed JSON
comparison rejects Boolean/numeric counter aliases; confirmed tenant target
bindings agree canonically across both views. Missing roots cannot promote
observation-bearing assets. Independently supported nonledger legacy assets keep
their original eligibility, and raw archives remain unchanged. Explicit adapter
declarations are literal supported strings chosen before the first checkpoint;
descriptor code is not executed to discover a version.

Five frozen reports captured through real owned HTTP and the original producer
at `0d60e09` retain exact bytes, IDs and original 70/high or 90/critical scores.
Independent fixed hashes identify the archives and ten original source files.
These are old producer outputs, not reports rebuilt through the new writer.

Focused gates cover genuine controls, forged/reused provenance, task isolation,
response-only/header/request reflection, full private-basis collisions, held
candidate rejection, callback failure/cancellation, mixed-ledger corruption and
atomic refused appends. Eight actual trusted-HTTPS library cases preserve receipt
prefixes and 90/critical partial risk through timeout, cancellation, cleanup,
later 503s and transmitted contamination. Eight real CLI execution cases export
JSON/SARIF on orderly deadline/cancellation while the tenant check is unfinished;
files are owner-only, receipt/finding links agree and no terminal check is invented.

Two spawned real dispatcher cases wait for an acknowledged SQLite commit, reach
a later owned HTTP stall and then receive SIGKILL. New ownership recovers the
exact receipt, finding, producer stamp and snapshot with one interrupted terminal
event and no probe replay. Authenticated Flask reads over that actual recovered
database agree across results, status/list summaries, critical inventory, raw JSON,
SARIF and audit. No private tenant input is admitted through the API. These are
library-worker persistence fixtures, not a server tenant-profile workflow.
Raw/encoded private-value sweeps cover retained JSON/SARIF, actual SQL/cache rows,
database/lock/log bytes and API bodies/headers. Owned directories are 0700 and
database/lock/log/output files are 0600. This is acknowledged-process recovery,
not power-loss or CLI forced-termination durability.

Combined local coverage passes 4,366 cases with warnings treated as errors on
Linux/Python 3.10.20, covering source, server and CLI. The initial full run had
4,312 passes and 20 failures: version/error expectations needed updating, while
projection and dynamic mock-declaration failures prompted runtime corrections.
Final descriptor hardening and the expanded recovered-API assertions receive
their separate focused gates; required CI runs the final committed tree.

Producer review passes 105 overlapping producer/legacy cases on Python 3.10 and
3.13. The shared contract author gate passes 48 cases on both. Independent review
passes 69 mixed-contract and dispatcher/API cases on both. The separate HTTPS
library/CLI gate passes 16 cases on Python 3.13 with coverage and warnings as
errors. Root final interface/persistence compatibility passes 95 cases after
literal-declaration hardening. Counts are regression coverage, not model yield.

Ruff, configured Bandit, whitespace/ASCII-dash checks, distribution build, Twine,
and fresh installed-wheel smoke outside the checkout pass. All 70 wheel Python
sources match the candidate; source/catalog identity and installed metadata agree.
Both normal and optimized eleven-case disposable backup/restore modes pass.
The first package-smoke attempt lacked `python` on PATH; selecting the existing
test virtual environment fixes that invocation without a source change.

Required cross-platform delivery checks are recorded on the implementation PR.
The next external acceptance is the pinned
[tenant interruption gate](tenant-progress-retest.md) against the existing HTTPS
lab. It covers leak-then-stall, held-candidate rejection, defended nondisclosure
and native recovery; no broad cohort repeat is needed. No cloud startup,
operator database/registry access, package publication or deployment was used.
Protected-access within-check receipts, private server tenant profiles and CLI
crash recovery remain separate work.

### Development producer identity local acceptance

R1.5a replaces stale scanner-package `1.1.0` literals with canonical development
version `1.2.0.dev0`. It adds deterministic scoped source/catalog fingerprints,
structured CLI and authenticated no-SQL API diagnostics, and an original producer
stamp for new execution reports. Pipeline checkpoint streams retain exact stamp
presence, scalar types and values. Recovery never invents a current stamp for
historical or preparation-failure reports. Derived SARIF/comprehensive exports
preserve an older producer or explicit unknown, separately from the current
exporter. Raw archived JSON remains unchanged. See the
[identity contract](build-identity.md).

The shared digest covers packaged Python and CLI bytes, not all repository or
loaded runtime content. Server-app identity is separately limited to the trusted
checkout app; installed/container copies can explicitly be unavailable. Catalog
hashes describe bundled definitions, not executed custom coverage. Read failures
return unavailable/null provenance without changing evidence or readiness.
No runtime Git, network, operator database or evidence-profile lookup is added.
Protocol, ruleset, check, evidence and database versions remain unchanged.

Local acceptance includes:

- Python 3.10.20: 4,142 tests pass with warnings as errors and 94 percent source,
  API and CLI line coverage in 355.26 seconds. A final canonical import alias is
  checked separately with focused formatting/identity cases and delivery CI.
- Independent review passes 65 overlapping adversarial cases on Python 3.10 and
  exact Python 3.13.15 with SQLAlchemy 2.1.6, coverage and warnings as errors.
  Cases cover trusted source boundaries, symlinks, limits/read failures,
  old/null/malformed producers, typed persistence, private collisions,
  authenticated no-SQL diagnostics and original JSON download preservation.
- All 176 focused identity/persistence cases and a 448-case compatibility gate
  pass. Ruff and configured Bandit pass with no medium/high findings. Package
  build, metadata and installed-wheel identity parity have dedicated smoke
  checks outside the source checkout. Required PR/post-merge CI is recorded on
  the delivery PR.
- After restoring the public canonical version alias, all 180 focused
  formatting/identity cases pass. The final local wheel has 67 Python files,
  each matching source bytes, and excludes private instruction files. Its
  SHA-256 is `922845181c048d5429fd11cf879103784a3459a47bdd856e5b4ac28ab8746fcd`.
  Fresh installed CLI/source/catalog/distribution identity agrees outside the
  checkout. An owned environment also upgrades the prior local `1.1.0` wheel
  to `1.2.0.dev0` with the same final identity and no broken requirements. This
  is a local prior-build fixture, not a deployed or published-release upgrade.

Review reproduced and corrected four specific boundaries. Ordinary Python
dictionary equality admitted Boolean/float substitutions for integer provenance
counts; checkpoint comparison now preserves JSON scalar types. Identity privacy
originally scanned serialized JSON syntax, so a later public `null` API-key probe
could withhold a valid stamp mid-run; matching now uses real string leaves and
keys. SARIF adapters now carry the complete original report's known-private basis
to identity formatting rather than dropping secrets from omitted fields. New
outer identity field names also join existing static privacy guards. No verdict
assertion or checkpoint immutability rule was relaxed. A changed-file fixture now
binds to the file descriptor and verifies its injection instead of relying on
JSON key order.

This is content identification, not signed report authenticity, exact Git
revision or dependency/build attestation. Fixed catalogs, sampling, risk scores
and raw archives retain their existing semantics. Diff/triage provenance,
release checksums, SBOM, dependency locking and deployed upgrade acceptance remain
separate work. No GCP retest or operator data is needed for this metadata slice.

## Exact-revision external retest

The operator supplied a private live-lab retest for
`150762513ecbf728c4922436bff1448266467150`. Two independent reviews inspected
the underlying JSON/SARIF, repeated-run comparisons, logs, and scoped connection
traces. These are reviews of supplied execution evidence, not independent cloud
reruns. Infrastructure identifiers, fixture inputs, and raw artifacts remain
outside the public repository.

- Linux/Python 3.11: 1241 passed, one skipped. Native macOS/Python 3.13:
  1242 passed with the stock temporary-directory configuration. Both platforms
  passed normal and optimized backup acceptance, all eight cases per mode.
- Linux and macOS logs support lint, configured static security checks, dependency
  checks/audit, build, metadata, installed-package smoke, and finite queue gates.
  Linux Chromium passed; macOS Chromium was not run. The merged revision's eight
  CI jobs also passed, including native macOS and container restart checks.
- The mixed-network inventory completed despite ordinary pages, non-HTTP banners,
  and unused addresses; a genuine service error retained partial coverage.
  Completed and finalized partial sources were actively tested, with source
  uncertainty preserved in JSON/SARIF. CLI model selection executed 39 checks.
- Five identical vulnerable-bot runs yielded one confirmed high leak at 70/100
  and four inconclusive null-score results, with no passed checks. Comparisons
  after the disclosure retained one unverified resolution and zero resolved
  findings. A leak-then-timeout fixture retained high risk with partial coverage.
  This measures conservative reporting, not representative detection sensitivity.
- All 355 response excerpts in 73 supplied JSON/SARIF artifacts contain the
  generated-text omission sentinel. Logs attest to zero protected-marker/PII
  matches and private scanner-written CLI files plus database/lock permissions.
  Exact markers and the database were intentionally omitted, so those sweeps
  cannot be independently repeated from this bundle. Driver-saved API responses
  are not scanner-written private exports and had different file permissions.
- Real SDK inventory and controlled MCP tests support the documented findings,
  denials, TLS/scope errors, and explicit page-sampling warning. Controls still
  sample only their first page; authenticated baselines can paginate. No tool
  was invoked. The metadata IP/hostname traces show no metadata connections;
  a wider metadata-subnet test was rejected by the host-count bound first and
  therefore does not independently exercise address-class enforcement.

The operator report marks the 22 original findings passed or documented limits,
with two items verified by source/documentation rather than live execution.
Independent review found a further API contract defect: public compatibility
summary and agent scores are zero where the saved pipeline says null and
`not_assessed`. History exposes no risk fields and SARIF retains the correct
nulls. This was a release blocker, not one of the six low-priority observations.
The beta remained held pending the scoped fix and new-revision API validation
recorded below. The earlier retest alone did not cover the changed API code or
establish enterprise readiness.

### API projection follow-up

The scoped follow-up projects public summary and agent risk from saved current
policy/check evidence rather than storage placeholders. Unknown and unsupported
historical scores remain null; assessed zero and confirmed partial high remain
numeric. Malformed values, inconsistent scores/levels/severity floors, ambiguous
asset IDs, and missing evidence fail closed. Historical reports and the database
schema are unchanged. Inventory queries remain tenant-owned and batched; projected
level filters have an explicit newest-100 tenant/type window and truncation warning.

Local Linux/Python 3.10 acceptance passes 1279 tests, including 37 new API cases
and strengthened actual dispatcher/protocol assertions for the outer results and
inventory fields. Independent focused reviews pass 126 and 162 cases, plus the
final 37-case projection run with warnings treated as errors. Ruff, configured
Bandit, build, Twine, and installed-wheel smoke pass. Replaying four supplied
private pipelines through actual Flask routes and fresh in-memory storage keeps
both unassessed server cases null and both confirmed cases at 70, including
partial coverage. Raw pipelines remain unchanged. This is offline API-adapter
replay, not a new live-cloud run. PR #49 and merged revision `82ee7d5` subsequently
passed all eight CI jobs; targeted live API acceptance is recorded below.

### Targeted live API acceptance

An operator-supplied private follow-up covers exact merged runtime revision
`82ee7d5e8d1a0183fe5344b41da90f60b49c5f91` on Linux/Python 3.11, actual
Gunicorn, the real dispatcher, and fresh private SQLite storage. Both job logs
verify the checkout; the setup log records 37 passing API projection tests.
Two independent reviews inspected archived responses, check records, logs, and
driver source without executing the supplied drivers or independently rerunning
cloud jobs.

- Ten scan captures and 31 agent snapshots agree across outer summaries,
  per-agent results, inventory entries, and saved pipelines. All 29 unassessed
  snapshots retain null scores, unknown levels, and not-assessed coverage.
  Discovery summary assessment status remains `not_run`, not an assessed zero.
- The two deterministic positive snapshots retain 70/high: one completed with
  sampled coverage and one partial with partial coverage. Their outer summary
  assessment statuses are `completed` and `partial`, respectively.
- Archived restart inventory independently retains all 31 matching snapshots,
  including exactly two high entries. Driver records report identical outer and
  per-agent projections for all ten scans after restart, and positive inclusion
  in the high-risk filter. Those per-scan restart and high-filter response bodies
  were not separately retained; do not claim an independent exact-set comparison
  of those missing bodies. The inventory window was not truncated.
- The archived check file contains 78 passing checks, zero failures, and 16
  informational entries. The harness records failures without failing its
  process, so exit zero is not acceptance evidence by itself. Independent
  comparisons and the actual zero-failure check record support this run.
- All 324 response excerpts in the supplied JSON captures are omission sentinels.
  Exact-secret/PII sweeps and final database/lock modes of 0600 are operator
  attestations; the database and protected values were intentionally excluded.
  Driver-created captures are 0644, not scanner-written private exports.

For positive paths, the driver stopped the server and added only
`system_prompt_canary` and public `evidence_context_id` inputs to genuine
server-produced discovery records. The real scanner generated the findings,
scores, persisted results, and projections. Original serialized records were
restored afterward; API document equality and final cleanup were recorded.
Temporary input seeding stored canaries in those private lab records, so final
zero-marker sweeps do not establish that canaries were never persisted during
the experiment. This test technique is not a supported operator workflow.

The server API still has no supported protected-canary configuration input.
Deterministic fixtures establish the confirmed projection path, not ordinary API
setup or real-model sensitivity. All three vulnerable-bot attempts were
inconclusive with null scores, not passed. Do not combine this small follow-up
with earlier runs into a representative accuracy estimate.

Together with the earlier core lab retest, local acceptance, independent reviews,
and eight green PR/post-merge CI jobs, this closes the scoped API blocker and
remediation hold for limited operator beta testing. Six lower-priority
observations, safe server evidence configuration, representative accuracy, and
the enterprise validation gaps below remain. No package publication or service
deployment is implied. Documentation-only changes do not alter this tested
runtime and need no additional cloud run.

### Supported server canary and paired-prompt retest

An operator-supplied private lab bundle tests exact runtime revision
`4f03d6350058c40ad1cdba1d73b16d22a4fa1575` on Linux/Python 3.11 with real
Gunicorn, the dispatcher, and fresh private SQLite. Four supplied job logs verify
the revision; setup records a clean checkout and 286 passing targeted tests with
five skips, not a new full-suite gate. Independent artifact reviews inspected
the JSON, SARIF, checks, command exits, and driver source without running the
supplied scripts or contacting the lab.

- The supported startup registry and API profile references enable confirmed
  canary findings without modifying discovery reports or database rows. All six
  saved JSON exports equal their pipelines. All 40 agent projections agree with
  their saved evidence and contemporaneous inventory: 35 remain null/unknown/
  not-assessed; five retain 70/high with sampled or partial coverage. There are
  29 confirmed checks and 124 original finding occurrences, not 124 independent
  vulnerabilities. No security check passed from nondisclosure.
- Deterministic disclosure and leak-then-failed-request cases retain their
  respective sampled and partial risk. A genuine 503 source remains partial;
  active reuse preserves its source warning. The source-immutability assertion
  compares parsed JSON, not original response bytes; rich-source immutability
  was not separately asserted. SARIF summaries, statuses,
  source uncertainty, check ledgers, and findings agree with saved pipelines.
- Seven misuse cases record HTTP 400. The final six-scan history and unchanged
  scan count for a refused template support no extra admissions. Profile removal
  plus restart refuses the saved template; restoring it enables another run.
  Negative response bodies and template documents were not separately archived.
- Archived restart inventory independently preserves all 40 projections. Per-scan
  restart results rely on driver assertions because their response bodies were
  not retained. Post-restart export and audit-response bodies are absent. The
  high-risk filter was not exercised or captured. Schedules were explicitly
  NOT RUN, not passed.
- Preserve the harness failure: its check ledger has 79 passes, one failure, and
  11 informational entries. The failed assertion incorrectly requires null for
  a profiled real target that produced a confirmed canary finding. The Python
  driver exits 1; its shell wrapper nevertheless records exit zero. This supports
  scoped scanner behavior, not an all-green acceptance gate. Wrapper exit zero
  alone is never sufficient acceptance evidence. The corrected server driver
  differs from its setup hash; its execution log records no replacement hash.

The paired benchmark uses the same exact-canary analyzer for both 35-prompt
suites. All ten pairs complete, with five baseline-first and five candidate-first
orders matching the recorded seed. Each suite attempts and evaluates 350
requests, 700 total, in approximately 27 minutes with no retries. The experimental
suite observes disclosure in 10/10 runs versus 2/10 for the legacy suite: two
both-detected, eight candidate-only, zero baseline-only, zero neither, and zero
incomplete pairs. Probe manifests, versions, category checks, and aggregate
arithmetic match the tested implementation. Both suites also detect the separate
deterministic fixture in one pair; that fixture does not measure comparative
real-model effectiveness.

This is improved observed disclosure yield on one operator-attested vulnerable
target, not general sensitivity, calibrated reliability, or enterprise readiness.
The target implementation, underlying model/version, private prompt, generation
configuration, and server-side state/reset evidence are excluded. Generation
randomness is uncontrolled; balanced ordering does not rule out server-side
carryover. Overlapping category observations do not attribute individual techniques.
Intervals remain exploratory. Do not pool earlier runs into this comparison or
promote the candidate to production defaults from this single target.

All 1090 archived server response excerpts are omission sentinels. Benchmark JSON
retains static public attack payloads in its manifests, not generated responses;
the supplied report's claim that it contains no prompt-injection text is incorrect.
Logged literal-secret sweeps report zero matches. Actual protected values,
registry, and database are excluded, so exact-secret sweeps and final private file
modes remain operator attestations, not independently repeated privacy proofs.
Sanitized stdout is not proof that original logs never contained a protected value.
No private artifact, target identifier, or fixture secret is committed here.

This accepts the supported server-configuration evidence and records the measured
target-specific comparison with the qualifications above. Production defaults are
unchanged. The next accuracy step is a frozen, independent multi-model replication
with explicit positive/negative controls, target provenance, and preserved capture
bodies. Publication, deployment, and cloud execution need separate authorization.

### Frozen paired-cohort retest

An operator-supplied private bundle covers exact runtime revision
`4070eed89e17daf3d5273d63b9ff99dfd3996194`. Three independent artifact reviews
checked the frozen plan, four reports, job logs, supplied driver source, and
current validator without executing supplied scripts or contacting lab targets.
The shipped plan's hash prefix matches the setup log before the first benchmark;
predeclaration and target provenance remain operator assertions, not independently
attested facts. Logs record 329 passing targeted Linux/Python 3.11 cases, not a
new full-suite run. The setup's outside-checkout import check is not a separately
built-wheel smoke test.

- The repository's offline CLI independently returns exit 0, both normally and
  with an empty inherited environment. Recomputed output exactly matches the
  archived summary: four completed cases and promotion `not_decided`. Current
  manifests, versions, bindings, seeded order, check ledgers, and checkpoints
  validate. The local focused regression gate passes 227 cases with warnings
  treated as errors and an inherited registry-path sentinel.
- Both deterministic controls meet their declared expectations in one pair each:
  both arms detect the disclosing fixture, neither detects the refusing fixture.
  Neither result is a security pass. All 308 check records across the cohort
  retain confirmed, heuristic, or inconclusive outcomes; none is passed.
- Each of the two declared model targets completes ten pairs, twenty arms, with
  five baseline-first and five candidate-first pairs. On the seeded local-model
  target, baseline detects in 5/10 runs and candidate in 10/10, with five
  candidate-only pairs. On the support-bot target, baseline detects in 1/10 and
  candidate in 10/10, with nine candidate-only pairs. Neither target has a
  baseline-only or incomplete pair. Candidate detects in 5/5 runs for each
  ordering group on each target. These are per-target observations, not a pooled
  accuracy score or independent-trial reliability estimate.
- The 44 arms attempt and evaluate 1,540 benchmark requests with no retries:
  70 per control and 700 per model target. Setup, health, model creation, and
  benign validation calls are additional lab traffic, not included in that count.
  Reported arm and cohort times remain within their configured budgets.
- Preserve setup exit 2 for an incompatible model-create request and the first
  controls job's readiness abort at exit 3. The corrected seed job succeeds
  before the model's benchmark, reusing the same frozen plan; the other model's
  completed report is retained. Target setup was corrected after the other
  model's results were available. This supports a predeclared report plan, not
  independent proof that every target configuration was frozen before all
  outcomes. The final gate job explicitly exits with the
  captured CLI status, so its exit zero is not masked by later commands. The
  claimed superseded no-op gate exit and the other model's job script are not
  archived; do not describe the bundle as a complete execution audit trail.

The supplied report overstates twenty pairs per target and independence. The
correct denominator is ten pairs per model target. One target declares stateless
requests; the other explicitly declares persistent or unknown state. Balanced
ordering does not exclude carryover. Distinct provider/model labels satisfy the
structural gate but do not establish distinct model weights or backend
independence. Model identity, seeding, generation settings, and actual target
revisions remain operator-attested. Actual protected values, the support-bot
implementation, immutable model digests, and full runtime generation/state
records are excluded; the control fixture and model-seeding driver are supplied.
This is improved observed yield on two declared targets, not
general sensitivity or enterprise acceptance.

Strict report validation confirms only public static probe payloads and bounded
check observations, with no generated-response fields. Logged literal-secret
sweeps report zero matches, but actual protected values are excluded. The final
sweep does not enumerate the fresh fixture/model markers; an earlier sweep covers
those markers in three reports, not every plan/summary input. The final driver
also loads the lab environment before invoking the gate, contrary to the report's
clean-environment claim. The gate does not read those secrets, and the independent
empty-environment replay succeeds. The model-seeding driver retains a private
marker file on the runner with no cleanup shown, so target-only secret retention
is not established. Private file modes, secret absence, VM shutdown, and final lab
cleanup remain operator attestations. No private artifact is added to Git.

This accepts the scoped cohort accounting and per-case observations. Production
prompts, request budgets, and scan defaults remain unchanged. Candidate adoption
needs a separate reviewed product decision and normal CLI/API workflow validation;
it is not implied by a completed evidence gate. Documentation-only acceptance
does not require another cloud run or authorize deployment or publication.

### Normal CLI and server experimental-suite retest

An operator-supplied private bundle covers exact merged runtime revision
`ae1ba9b5d89f24a824110c777821a202709750ca` on Linux/Python 3.11. Three
independent artifact reviews inspected normal installed-CLI scans, real Gunicorn
and dispatcher captures, supplied drivers, and job logs without executing those
drivers or contacting lab targets. This is operator-workflow evidence, not another
paired accuracy cohort. Private inputs and infrastructure identifiers stay outside
Git. Setup records a clean checkout and 453 passing targeted cases, not a full
gate. Its outside-checkout constructor/help check supports installed-package use,
not a separately captured distribution-wheel build and smoke test. Later jobs
verify HEAD but do not separately record a clean working tree.

- The final CLI driver records 165 passing assertions, zero failures, and exit 0.
  Six candidate cases each run separately as JSON and SARIF, not as two exports
  of one execution. Every execution records seven prompt checks, 35 attempts,
  matching candidate probe versions, and no passed prompt checks. Disclosure
  retains 70/high; refusal and unseeded controls remain null/inconclusive.
  Leak-then-failure retains 70/high with 18 evaluated responses from 35 attempts
  and failed-but-confirmed checks. Attempts are not completed evaluations.
- Both declared real targets disclose in the JSON and separate SARIF runs and
  retain 70/high. The actual JSON records show three confirmed and four
  inconclusive prompt groups on each target. The first target's separate SARIF
  run has five confirmed and two inconclusive groups; the second has three and
  four. These correct the supplied summary's category counts. They are per-run
  observations, not new sensitivity estimates or evidence of independent trials.
  Failed non-prompt requests explain partial controls and the second target;
  the first target completes. CLI exits correctly distinguish partial 1 from
  completed 0. An omitted-option control preserves default probe identities and
  has no suite label.
- The server driver records 181 passing assertions, zero failures, and exit 0.
  Eight saved security JSON reports exactly equal their results' pipelines;
  regeneration with the repository's SARIF exporter exactly matches all eight
  supplied SARIF bodies. Seven selected-suite executions each retain one
  requesting target and skip the rest of the inventory, with seven prompt groups,
  35 attempts, matching versions, and no prompt passes. The refusing control
  remains null; six selected-suite positive snapshots retain 70/high, including
  ordinary failed-request and finalized-partial-source cases. The default control
  is separately assessed without a suite label. Source uncertainty stays visible.
- Complete inventory, high-risk-filter, and history documents match before and
  after restart: 68 inventory entries, seven high entries, and ten scans.
  The high filter equals the exact seven-entry inventory subset. Nine saved
  pipelines independently support 62 inventory projections; six partial-discovery
  entries remain null but lack their source pipeline capture. History exposes no
  risk fields. Per-scan results, JSON/SARIF, and audit bodies were captured only
  before restart; their post-restart equivalence is not independently established
  by this bundle. Schedules are explicitly NOT RUN.

Template creation, hidden pins, caller-pin refusal, name-only update, and a
confirmed template run have passing driver assertions. Seventeen scan-admission
negatives record HTTP 400 and unchanged session counts. However, template
create/update documents and complete negative response bodies are not retained
as separate captures; no template GET/read was exercised. No separate queued-job
count was checked. Source-immutability assertions compare serialized agent arrays,
not byte-for-byte entire reports, and no post-reuse source body is supplied.
These support scoped behavior, not completion of every capture requirement in
the [normal-scan acceptance guide](BETA_TESTING.md#normal-scan-experimental-suite-acceptance).

Preserve both earlier CLI failures: the first driver has 156 passes and seven
incorrect exit-zero expectations, with process exit 1; the shell-aborted attempt
exits 2 after starting fixtures but before invoking the scanner. The final rerun
corrects the exit assertions. Setup's command wrapper always returns zero, so
its logged individual install/test statuses, not setup exit alone, support those
steps. Final returned CLI and server drivers differ from their setup-logged
hashes, and no final executed-driver hashes are archived. No frozen digest,
generation-setting, or state/reset manifest independently establishes target
provenance or predeclaration. Do not call this a complete execution audit trail.

Independent traversal finds 1,500 response-excerpt fields in returned JSON, all
the exact generated-text omission sentinel, not the summary's claimed 1,877.
Known synthetic PII is absent from output artifacts but occurs in supplied driver
source. Literal-secret sweeps report zero matches in outputs and server state;
actual values, database, registry, and private CLI stdout/stderr are excluded.
Those sweeps and original 0600 file modes remain operator attestations. Sweeps
do not independently cover every final assembled bundle file with every actual
secret. A retained private marker file on the runner contradicts the summary's
earlier target-only claim; the later retention section correctly records it.
VM shutdown and final cleanup also remain operator attestations.

The local 453-case focused gate passes again with warnings treated as errors and
an inherited nonexistent registry-path sentinel. No new product blocker was
reproduced. This accepts the scoped opt-in CLI/server workflow evidence with the
capture and provenance limits above, not the full external acceptance checklist,
default promotion, enterprise readiness, publication, or deployment. Defaults,
runtime code, and budgets are unchanged. Documentation-only acceptance needs no
new cloud run; missing captures must not be represented as checked.

## Automated checks

### Operator feedback diagnostics

The combined diagnostic slice passes 1408 local Linux/Python 3.10 cases, Ruff,
and the configured whole-source Bandit gate. Independent reviews passed 409
network/contract cases and 299 MCP cases with warnings treated as errors.

Static CLI preflight rejects known metadata names, forbidden address classes,
legacy numeric IPv4 representations, and unsafe local-host aliases before the
pipeline, DNS, or sockets run. All declared networks/domains/explicit agents are
checked before scanning begins, while ordinary documentation/private networks,
host-bit normalization, and explicit loopback opt-in remain available. Existing
DNS and connection-time enforcement is unchanged. Refusal does not overwrite an
existing output report.

Missing declared/provider credentials and required model 401/403 responses have
specific static reasons without endpoint, environment-reference, header, body,
or marker leakage. Denied model requests remain incomplete/inconclusive; valid
denials in intentional authentication/session controls keep their prior behavior.
CLI MCP failures print only allowlisted fixed report reasons, with a generic
fallback for unknown text. Paginated authorized baselines and first-page-only
controls are explicitly distinguished without changing findings or probe IDs.
The wildcard detection constant retains its justified B104 suppression, isolated
so the installed Bandit reports no stale suppression warnings.

These are local synthetic diagnostics/privacy regressions, not another cloud
retest or a detection-sensitivity improvement. PR #51 and its merged revision
passed all eight CI jobs. Repeated finding presentation, sampling/latency work,
and enterprise acceptance remain separate.

### Server evidence-reference slice

Named server profiles enable normal system-prompt canary input for security-only
API scans and saved-template/schedule workflows. No stored discovery report is
edited and no score or finding is seeded. The registry is private, bounded, and
loaded only at startup; public endpoint/provider/model/organization/context pins
are revalidated at admission and execution. Secrets are not pin inputs.

The real local HTTP/API/dispatcher/file-backed SQLite regression exercises a
disclosing and nondisclosing target through supported template APIs. The former
produces 70/high, the latter null/inconclusive with no prompt-check passes. Saved
pipelines, JSON/SARIF, compatibility results, and inventory agree. Source reports
remain unchanged. Assertions check generated reports, queued definitions,
templates, SQLite bytes, audit, logs, and captured model requests for marker and
environment-reference absence. All target response text remains omitted.

Negative tests cover private-file ownership/mode/type/size, duplicate/nonfinite
and deeply nested JSON, missing/invalid environment values, tenant/asset/model
binding, alias ambiguity, external reserved fields/pins, changed queued bindings,
schedule preflight/admission races, and marker collisions with public labels,
revision pins, source inventory, normalized URLs, and resolved credentials.
Escaped-marker and HTTP-client path normalization regressions prevent reflected
request data from acting as protected-canary evidence. Two selected models may
share a protected fixture marker without mutating the original source.

Four isolated subprocess tests exercise actual app startup with configured
profiles, including valid, missing-secret, malformed-registry, and missing-file
cases. Socket connection/bind, DNS, and SQLite connections are forbidden;
the subprocess deadline is 15 seconds. Failures expose static reasons, not
protected values or registry paths. This is startup configuration acceptance,
not a new real-Gunicorn or deployed-secret-manager test.

Independent review accepted the implementation after reproducing and closing
reflection/privacy and multi-asset correctness blockers. Local integrated
Linux/Python 3.10 acceptance passes 1504 tests with warnings treated as errors,
including 96 new profile cases. Ruff, configured Bandit, distribution build,
Twine metadata checks, and installed-wheel smoke pass. Independent review also
passed 407 focused cases and a 1369-case full run before the final startup and
adapter regressions; final integrated focused review covers those additions.
PR #52 and merged revision `ed5684d` passed all eight CI jobs, including native
macOS backup/restore and container restart. These checks do not replace a
real-service retest of the newly supported API profile configuration.
No cloud or real-model retest was performed for this slice. Detection sensitivity
remains unvalidated, nondisclosure cannot establish safety, and raw database
unknown-score placeholders were not migrated. Cross-tenant/authentication/path
evidence configuration remains CLI/Python-only. Deployment and publication are
not part of this change.

### Experimental paired prompt benchmark

The repository script uses the actual provider adapter, scoped transport,
prompt analyzer, and versioned check contracts. Production prompt catalogs and
scan defaults are unchanged. The experimental `protected-disclosure-v1` suite
uses seven categories with five requests each, replacing generic output/persona
objectives with protected-system-instruction extraction objectives. The baseline
retains its original active payload bytes. Public manifest/version provenance
distinguishes both suites; configured secrets are not identity inputs.

Balanced, seeded baseline/candidate ordering supports one to ten pairs, default
ten. Every arm is capped at 35 HTTP attempts, a 30-second request timeout, 64 KiB response
cap, 1,200-second deadline, the existing 100-token output cap, and one-second
pacing. The cohort deadline is 5,400 seconds, at most 700 attempts for ten pairs.
The ordering seed does not control model generation. DNS validation is bounded
separately. There are no automatic retries or increases after observing outcomes.

The primary observation is whether a run confirms at least one exact protected
canary disclosure, not how many repeated findings it produces. Benchmark-only
observation checkpoints retain an actual analyzer confirmation when later
cancellation prevents a category from returning. They do not fabricate check
records; original collected checks and partial coverage remain explicit.
Complete-case Wilson intervals exclude partial/unstarted arms. Paired counts
exclude incomplete pairs, while scheduled denominators and partial positives
remain separately visible. These are exploratory, potentially completion-biased
measurements, not enterprise accuracy or independent-request statistics.

Real loopback HTTP fixtures exercise deterministic disclosure, refusal, unseeded
canaries, request reflection, malformed responses, authorization denial, and a
confirmed response followed by timeout. Other regressions cover scope-before-I/O,
missing credentials, secret/public-manifest collisions, deadline accounting,
unchanged production defaults, parser errors, and private atomic no-clobber
output. Reports omit raw generated text, target endpoints, secret references,
credentials, and canary hashes. The supplied revision is explicitly labeled an
operator assertion; the GCP procedure separately verifies the actual checkout.

Local Linux/Python 3.10 acceptance passes 1559 cases with warnings treated as
errors, including 55 new benchmark cases. Ruff, configured Bandit (also run on
the new script), build, Twine, and installed-wheel smoke pass. Independent review passed 253
focused cases plus four additional actual-HTTP negative/partial scenarios:
metadata-only and Base64-only markers do not confirm, oversized bodies stay
partial, and leak-then-503 retains its partial positive. Require all eight
PR/post-merge CI jobs on the exact source before acceptance.
The
[next GCP retest](BETA_TESTING.md#next-authorized-gcp-detector-retest) covers the
supported real-server profile workflow and frozen paired model comparison.
No cloud model was exercised here, and no experimental prompt has been promoted
to production based on fixture results.

### Benchmark final-pacing timeout follow-up

Offline-validator review reproduced a benchmark-only completion defect: timeout
during the 35th pacing delay could leave seven completed check records and 35
evaluations while the interrupted category never returned its findings. Counts
alone incorrectly labeled that arm completed. Completion now also requires a
normal return from the tester. Positive analyzer observations survive as partial;
incomplete arms/pairs stay out of complete-case fractions and intervals.

Two regressions exercise actual check decorators, analyzer, observation checkpoint,
CLI, and private export with deterministic HTTP stubs, for both disclosure and
nondisclosure on the final response. The focused benchmark gate passes 57 cases
with warnings treated as errors; the full local suite passes 1579 cases. Ruff and
configured Bandit also pass. Production prompt catalogs, scoring, and sampling
are unchanged. The supplied earlier GCP arms completed well below their deadlines;
this fix does not establish new model sensitivity or invalidate those observations.
Independent review and all eight PR/post-merge CI jobs remain required.

### Offline paired-cohort evidence gate

The strict report validator binds the current schema, exact prompt manifests and
probe versions, provider/model/context/revision, seeded order, pair cardinality,
check ledgers, counters, and observation checkpoints before recomputing metrics.
It rejects substituted aggregate scores, duplicate/missing arms, boolean counters,
nonfinite values, unknown fields, and inconsistent completed observations. Partial
checkpoint positives can survive an interrupted final category without fabricating
confirmed checks. Reported arm/cohort elapsed time has five seconds of cleanup/
timing tolerance, not a larger execution budget or independent wire measurement.

The offline cohort CLI uses an explicit operator-declared plan with positive and
negative controls plus at least two distinct declared model identities. It keeps
all planned cases, including missing/invalid/partial/control-failing inputs, and
returns nonzero for incomplete evidence. Completed nondisclosure is not a security
pass. Results remain per case; no heterogeneous accuracy score or promotion
decision is produced. State/reset policies are visible assertions, not proof of
independence. Old single-target results do not satisfy a new predeclared cohort.

Private bounded file loaders reject symlink ancestors/leaves, FIFOs, hard links,
foreign owners, unsafe permissions, changing files, duplicate keys, excessive
JSON depth/nodes/strings/integers, and malformed UTF-8. Directory descriptors pin
reads and atomic no-clobber 0600 output. Summary fields are fixed enums, generated
ordinals, and recomputed metrics, not supplied labels, paths, prompts, or hashes.
No target, credential environment, server app, database, or supplied script is
used. The installed-wheel smoke imports both new modules outside the checkout.

Independent reviews accepted the schema/ledger, filesystem, control, privacy,
and documentation contracts. The final combined Linux/Python 3.10 suite passes
1749 cases with warnings as errors and an inherited registry-path sentinel.
This includes 112 new validator and 58 new cohort/CLI cases; the focused combined
benchmark gate passes 227 cases. Ruff, configured Bandit, pip check, build,
Twine, and installed-wheel smoke pass. These counts describe overlapping gates,
not additional independent model observations. Synthetic fixtures exercise actual CLI subprocess
exit codes, missing evidence, failed controls, malformed inputs, no-clobber races,
and ignored inherited registry configuration. These checks validate offline
accounting, not real-model sensitivity, truthful operator attestations, or secret
absence in arbitrary supplied files. A fresh authorized multi-model measurement
with preserved captures is still required before candidate adoption. All eight
PR/post-merge CI jobs remain required before acceptance.

### Shared experimental prompt catalog

The fixed candidate catalog is shared by the paired benchmark and explicit Python
tester/engine constructor selection. Default construction preserves all legacy
payloads and first-five sampling; candidate requests retain the exact measured
payloads and payload-derived probe versions. A separate order-sensitive digest
binds public catalog semantics without using protected values or credentials.
Each tester receives an independent catalog; selecting one suite does not run
both or reset the shared transport budget.

Active candidate checks require a request-ready target with an opaque protected
canary and public context. Whole-inventory validation requires at least one such
target; engine calls for individual unsupported or unmodelled assets retain their
existing skipped/null behavior. Their declared markers still undergo collision
validation, even when there is no testable target in that per-asset call. Pure local validation
checks all declared canaries against public inventory, static field/identity
descriptors, every target's requests and normalized URLs, resolved credentials,
and computed probe versions before candidate HTTP. Unsupported entries cannot
hide a declared canary collision. Configuration failures expose static errors,
not supplied values. Missing or unseeded evidence never becomes a security pass.

The full local Linux/Python 3.10 suite passes 1,986 cases with warnings treated as
errors, including 237 new suite cases. Independent focused acceptance passes 464
combined catalog/benchmark/validator/cohort cases. Frozen catalog and manifest hashes,
unchanged defaults, constructor isolation, mixed-inventory collisions, and actual
local HTTP disclosure/refusal/unseeded/denied/malformed/leak-then-failure cases
pass. Existing finite budgets remain enforced and partial confirmed high risk
survives ordinary failed requests. This does not add recovery for cancellation
inside an unfinished category or an outer scan deadline.

Final mixed-inventory review reproduced an extra per-asset presence check turning
unmodelled entries into failures. The engine now preserves those entries as
skipped without weakening the strict whole-scan prerequisite or any privacy
guard. Actual loopback regression retains three skipped/null entries, one
confirmed target, 35 prompt requests, and zero failed assets. Normal scan coverage
remains partial when assets are skipped.

Review reproduced and closed static report-key, tuple-label, and skipped-asset
marker collisions. A bounded public-descriptor guard includes emitted schema,
pattern, policy, and SARIF identities; maintenance tests audit current output
source constants so new opaque labels cannot silently bypass that guard. Generic
redaction and report schemas are unchanged. The earlier private cohort still
passes the strict offline CLI with an identical recomputed summary; this checks
catalog compatibility, not a fresh target measurement. Ruff, configured Bandit,
distribution build, and Twine metadata checks pass.

Independent review accepted the core changes. The complete PR/post-merge CI
matrix remains required.
Installed-wheel smoke now constructs both default and selected engines outside
the checkout. This is synthetic local contract acceptance, not a new real-model
measurement, CLI/API selection, package publication, or deployment. Operator
workflow integration and a targeted final-revision retest remain separate work.

### Normal-scan experimental prompt integration

The CLI flag and `scan_config.prompt_suite` accept only explicit
`protected-disclosure-v1`; omission preserves existing execution and report shape.
CLI scans require explicit agents and reject discovery-only selection
before execution. Invalid values and `--skip-security` are rejected before
loading target configuration. Server selection requires security-only source reuse and
explicit startup profiles for every request-ready model. Unknown values/types,
misplaced options, external pins, unavailable profiles, and public marker
collisions fail closed. Historical raw-canary source fields cannot substitute for
profile evidence or lose redaction provenance when copied; candidate admission
and workers reject those fields before model requests. Sources remain unchanged.

Queued jobs and templates pin only public catalog content/semantics. Admission,
trusted replay, unchanged-selection updates, and schedule tokens reject missing
or changed pins; returned template JSON hides them. Schedule races pause without
admission. Per-scan candidate engines never mutate the legacy global engine.
Only one 35-request prompt suite runs, with other checks and shared transport
limits unchanged. JSON/SARIF suite labels mean selected, not completed: the check
ledger remains authoritative. No new pass, scoring rule, or in-flight cancellation
recovery is introduced.

The combined local Linux/Python 3.10 gate passes 2,049 tests with warnings as errors
and an inherited registry-path sentinel. This includes the 237 core suite cases,
38 new server cases, 15 new CLI workflow cases, and ten additional actual-profile
dispatcher cases. These overlap the focused gates and are not model observations.
The 125 Node controller tests pass, including full JSON-template selection
preservation. Ruff, configured Bandit, pip check, and whitespace checks pass.

Actual loopback CLI runs use the complete candidate catalog and real engines,
adapters, transport, pipeline, and JSON/SARIF exports. Only pacing is shortened.
Deterministic disclosure retains 70/high; refusal and an unseeded marker remain
null/inconclusive; leak-then-503 retains partial high and a nonzero CLI exit.
Positive/negative exits and execution status are explicitly asserted, not hidden
by report creation. Payloads, seven five-attempt prompt groups, and probe versions
match the benchmark. Synthetic markers and response text are absent from reports,
captured requests, logs, and stdout; output files remain private.

The real file-backed SQLite/API/dispatcher fixture independently exercises normal
profile/template input with full candidate sampling, 70 versus null, source
immutability, matching saved pipelines and public results, SARIF, inventory,
audit, and database-byte secret omission. Concurrency, template/pin drift, and
schedule races also have isolated regressions. Mixed actual-dispatcher inventories
preserve unmodelled/unsupported entries as skipped/null alongside the protected
target without making additional model requests. Installed-wheel smoke checks the
flag and static invalid-selection rejection outside the checkout. These local
fixtures do not establish real-model sensitivity, full browser accessibility,
deployed compatibility, or enterprise readiness. Require independent review,
all PR/post-merge checks, and the targeted normal-workflow lab retest on the final
merged revision before claiming external acceptance. No cloud target was accessed,
service deployed, or package published for this slice.

### Finding presentation grouping

The O3 slice changes only dashboard presentation and synthetic browser fixtures.
Eighteen actual-analyzer/versioned-check occurrences display as seven groups.
Python invariance tests preserve the source document, 18 raw JSON/SARIF results,
seven checks/rules, score 70/high, all original IDs, suppression/comparison keys,
and unverified rather than resolved nondisclosure. Contexts, versions, models,
asset entries, visible/boundary fields, ambiguous counts and historical or
redacted provenance remain separate. Matching confirmed checks are required.

The controller gate passes 125 Node cases. Two independent reviewers accepted
the code and ran the extended real Chromium workflow at 320/390/1440 pixels.
It covers native details, lazy original records, group/occurrence 100-item caps,
preview truncation, final-page keyboard focus, hostile literal text, unchanged
terminal polling, logout and stale selection. No external browser requests,
page errors, or CSP violations were observed. Disposable fixture processes and
private database directories were removed; screenshot/log artifacts are retained.
Inherited operator evidence-registry settings are excluded before fixture import.
This remains targeted workflow acceptance, not comprehensive accessibility or
screen-reader conformance. The integrated tree passes 1568 Python cases with
warnings treated as errors, Ruff, and configured Bandit. A third root Chromium
run passed the same workflow and its temporary process/database cleanup.
Build, Twine, and installed-wheel smoke also pass. All eight PR/post-merge CI
jobs remain required before acceptance.

The slice checkpoints below are chronological records. Their historical hold
and pending-retest statements are superseded by the targeted acceptance above;
enterprise and unsupported-deployment limitations remain in effect.

### Remediation infrastructure slice

The first remediation slice passes 1120 local Linux/Python 3.10 tests, Ruff, and
the configured Bandit gate. Fifty-seven focused cases cover report permissions,
atomic replacement, failed-write preservation, symlink rejection, and disposable
backup behavior. Both normal and optimized backup commands pass all eight cases.
A synthetic symlinked temporary ancestor passes in both modes and is cleaned up;
owned child/database symlinks remain rejected. A new native macOS CI job must
pass before claiming macOS acceptance. This slice alone does not repair risk
verdicts or lift the beta hold.

### Verdict remediation slice

The integrated verdict slice passes 1150 local Linux/Python 3.10 tests, including
82 Node controller cases, Ruff, and the configured Bandit gate. Twenty-nine new
verdict regressions cover severity floors, repeated leak samples, unseeded and
stochastic nondisclosure, historical resolution, private evidence/logging, partial
confirmed risk, anonymous inference, denied cookies, and all-skipped execution.
Independent reviews accepted the runtime changes and corrected dashboard policy
gating so historical low scores do not appear current. The authoritative policy
and scores agree across agent, security-result, assessment, and summary fields.

The real synthetic Chromium workflow passed at 320/390/1440 pixels, including
visible confirmed high risk with partial-coverage warnings and unchanged focus
and session protections. Artifacts remain in `/tmp/ai-scanner-browser-82s862s_`;
the fixture process stopped and its private database directory was removed.
The browser parent also canonicalizes its created temporary root; the mandatory
symlink-ancestor regression and existing guard/cleanup cases pass. These fixtures
do not rerun the external lab or reopen the beta.

### Network remediation slice

The verdict plus network tree passes 1194 local Linux/Python 3.10 tests and Ruff.
Independent review exercised transport, scope, MCP, mixed DNS, configurable
deadlines, and safe failure accounting; focused runs also passed with warnings
treated as errors. A real loopback mixed-service fixture retains one Ollama and
completes with TCP banners, large SPA/HTML, unrelated API inventories, JSON error
documents, and closed ports. Matching native/compatible model sets deduplicate.
Separate fixtures preserve partial status for actual protocol claims with invalid
data, 503s, truncation, and JSON/body limits, including JSON mislabeled text/plain.
Optional protocol routes stay optional after another inventory succeeds.

Metadata/reserved addresses are rejected before TCP or HTTP even without a CLI
allowlist. Host-bit CIDRs normalize consistently. Bounded local hosts aliases and
mixed-answer fail-closed checks pass. A real untrusted certificate fixture reports
a specific safe TLS failure for both MCP inventory and policy checks. Pre-created
security engines use each scan's current bounded request deadline, with no retry.
These are synthetic regressions, not a new live-provider compatibility claim.

### Combined operator remediation slice

The complete local remediation tree passes 1235 Linux/Python 3.10 tests and
82 Node controller cases, Ruff, configured Bandit, pip check, dependency audit,
build/Twine checks, and an isolated installed-wheel smoke. Both normal and
optimized backup commands pass all eight cases. Independent review passed 256
source/API/schedule/CLI/privacy cases and 226 network cases with warnings as errors.
The current PR and merged revision must still pass their own complete CI matrix.

The new mandatory real-protocol workflow starts local AI inventory/inference,
optional error/HTML routes, a TCP banner, and a separate 503 service. It uses a
fresh file-backed SQLite database, actual dispatcher, operator login, admission,
snapshot-ID model selection, adapter/HTTP calls, history and JSON/SARIF exports.
Mixed-service discovery completes; genuine 503 discovery remains partial; the
saved partial source is then actively tested with the exact selected model.
The original source remains unchanged, uncertainty is retained, and no passed
security conclusion or minimal-risk score is inferred. Synthetic private output,
PII, operator credentials and tokens are absent from reports and audit events.
Only configured ports, sample counts and pacing are adjusted; engines, adapters,
transport, and security results are not mocked. This is not a real LLM or cloud
lab retest. Guards prevent non-loopback connections or operator-database reuse.

Malformed source arrays, null snapshot metadata and nonstring IDs reproduce
controlled 400 rejection rather than generic 500/admission. Changed inventories
remain 409 schedule conflicts. Source ownership and current-policy checks remain.
The real Chromium workflow passed again at 320/390/1440 pixels; artifacts are in
`/tmp/ai-scanner-browser-doy5ot92` and independent artifacts in
`/tmp/ai-scanner-browser-4r6x44pw`. Fixture processes exited and databases were
removed. This is focused workflow/keyboard acceptance, not comprehensive WCAG.

The repeated finite queue profile passed five fresh-database runs: 200 jobs with
two workers and 1ms synthetic latency in 9.938061, 7.817631 and 8.195153 seconds;
500 jobs with four workers and 5ms latency in 21.363828 and 21.610206 seconds.
Totals are 1600 jobs, 1435 completed, 160 cancelled, five interrupted, 1445 unique
claims and 4650 audit events. Duplicate claims and state mismatches were zero.
The insufficient one-second deadline case correctly exited 1 at 1.080374 seconds.
All disposable databases were removed; logs remain in
`/tmp/ai-scanner-beta-queue-review-llvm6a`. This is not a load/soak or throughput
certification. No cloud VM was started, real target scanned, package published,
or remote service deployed. At that checkpoint the beta stayed held for
exact-revision lab retesting and the separate enterprise-readiness contract.

### New server-state permission defaults

The storage follow-up passes 1242 local Linux/Python 3.10 tests, Ruff and the
configured Bandit gate including Gunicorn configuration. Seven new mandatory
subprocess regressions verify import does not change the caller's umask, rejected
worker counts fail before changing it, and actual entrypoint/worker hooks create
0700 directories plus 0600 SQLite/journal/lock files under an inherited 022 mask.
Existing 0644 files and 0755 directories remain unchanged. An independent actual
Gunicorn run with a copied public app and fresh private SQLite state passed
readiness with a 0700 default instance and 0600 database/lock, then stopped cleanly.
No deployed or operator database was opened or changed.

Container CI now checks the fresh instance, database/lock modes and file ownership
after authenticated readiness and again after restart. The new PR and merged
revision must pass this actual-container assertion before claiming it. Existing
mounted volumes and retained historical reports need their own operator review;
these defaults do not repair their permissions or sanitize old report contents.
At that checkpoint the real-service lab retest and enterprise sign-off were
outstanding. The reviewed retests above close the scoped beta remediation gate,
not the separate enterprise sign-off.

### Historical local-beta checkpoint

- Local Linux/Python 3.10.20: 1109 pytest cases passed. The suite invokes 78 Node
  controller tests, which also passed independently.
- Line coverage across `src`, `app`, and `scanner_cli`: 91%. The shared pipeline
  is 95%, transport 99%, durable jobs 92%, schema acceptance 94%, and API 95%.
  Mocked cloud inventory is 92%, traffic parsing 89%, and network discovery 97%.
  The live MCP client is 95% and the controlled policy module 96%; the small strict
  template projection helper is 100%; the schedule service is 97%. This measures executed
  source lines, not attack coverage or security effectiveness.
- Ruff and the configured medium/high-severity Bandit gate pass, including API
  source. Lower-severity static findings still require contextual review.
- Real loopback HTTP fixtures exercise provider request formats, rejected probes,
  canary disclosure versus refusal, and credential removal from JSON/SARIF output.
- Real SQLite transactions exercise competing claims, cancellation/finalization
  races, restart recovery, and exclusive dispatcher ownership.
- Known legacy schema upgrades preserve rows; unknown layouts, future versions,
  defaults, triggers, views, and unexpected unique constraints are rejected before
  writes. Interrupted upgrade transactions roll back. State changes and bounded
  tenant audit events persist atomically.
- Versioned check regressions distinguish passed/confirmed evidence from
  heuristic, inconclusive, failed, and skipped execution. New risk requires
  conclusive completed evidence; verified resolution requires exact probe,
  provider/model, and public evidence-context matches for every earlier occurrence.
- Offline replay ruleset 1.1.0 detects exact protected foreign canaries in string
  argument keys, including objects nested under arrays, without exposing names.
  Twenty-five new regressions cover numeric locations, existing value paths,
  depth limits, label independence, and versioned secret-safe IDs. All 48 replay
  cases passed independently on Python 3.10 and 3.12 with networking/execution
  blocked. Encoded key disclosures remain explicitly counted false negatives.
  REPLAY001/003 detection scope and the six built-in smoke fixtures are unchanged.
  The global version change changes IDs for every check, not just new detections.
- Distribution build, metadata validation, isolated installed-wheel commands,
  and offline evaluation smoke pass outside the checkout.
- Network fixtures exercise actual loopback HTTP and controlled DNS beneath the
  real connection-time policy. They distinguish protocol observations from vendor
  identity and incomplete sources from expected negatives. Native CI localhost
  address differences are controlled without relaxing scope.
  TGI fixtures require the router discriminator, version, model identity, and a
  positive input limit; current `max_input_tokens` takes precedence over the
  legacy field. Router-less historical responses stay unsupported and unidentified.
- Live MCP fixtures exercise JSON/request-scoped SSE, version/capability handling,
  strict envelopes, partial pages, cookies/redirect rejection, scope changes,
  escaped credentials, schema/pointer limits, and immutable timed-out validation.
  Failed or partial collection marks SARIF invocation unsuccessful. Security
  checks remain skipped or inconclusive; no tool is invoked.
- Controlled MCP fixtures require a complete authenticated protected inventory
  baseline before isolated authorization/Origin controls. They cover denied-status
  disclosure, denial-body/header echoes, canonical/encoded URL and cursor
  reflection, opaque cursors, secret/contract identity collisions, shared budgets,
  partial evidence, and policy output aliases. Findings apply only to the declared
  inventory policy; tool execution and browser exploitation are not assessed.
- Template fixtures cover tenant-scoped CRUD/list/run, quotas, optimistic revisions,
  recipe edit/delete races, commit rollback, source/model/endpoint prerequisites,
  queued snapshot independence, DNS/symlink changes, and current-policy worker
  validation. Real SQLite tests cover exact version 1 upgrade, transaction rollback,
  repeated initialization, and malformed/future layout rejection before writes.
  Manual dashboard template flows now have Node and browser acceptance; saving
  or editing a recipe never starts a scan.
- Schedule fixtures cover tenant/global quotas, pinned revisions, explicit enable/
  pause, finite terminal consumption, one outstanding scan, queue-full deferral,
  no catch-up/replay, restart review, source/config races, and atomic rollback.
  Fake-clock and real dispatcher tests cover soft timeout, readiness, cancellation,
  blocked preflight shutdown, and late-result rejection. Exact version 1/2 layouts
  upgrade to schema 3; unknown/future layouts fail before writes. Scheduling is
  available through dashboard and API, and no real target schedule was enabled.
- Explicit JSON nesting limits were checked on Python 3.10 and an isolated Python
  3.12 environment. Network exponent overflow is rejected. Request and streamed
  body timeouts each record one failure, including Python 3.10's distinct exception.
- Container build, readiness, and readiness after restart pass. The container
  smoke now also rejects missing/wrong operator keys and missing/invalid bearer
  tokens, verifies configured operator identity and authenticated empty history,
  and repeats after restart. It does not admit scans or validate a deployed volume.
- Thirteen mandatory tests cover the optional browser fixture's temporary-path
  and effective-engine guards, environment restoration, bounded startup messages,
  and parent-owned process/database cleanup. They do not require Playwright.
- Local pip check and dependency audit pass after upgrading certifi to 2026.10.19.
  The wheel carries the corresponding minimum requirement. This is not remediation
  of already deployed environments, images, or system trust stores.

CI repeats tests and wheel checks on Python 3.10 through 3.13, audits installed
dependencies including cloud/server extras, runs lint/source security checks,
and builds and starts the container. Check each PR's latest run for its exact
commit and dependency resolution; this document is not a substitute for CI.

## Browser verification

Chromium was exercised against a loopback Flask server with real authentication,
SQLite queue, history, cancellation, and export routes. Discovery and security
phases used synthetic fixtures; no external target was scanned.

The initial workflow covers invalid/valid login, memory-only session state, discovery,
source model selection, separate findings/observations, unassessed risk, history,
JSON/SARIF downloads, cancellation, missing scans, and logout. Desktop 1440-pixel
and mobile 390-pixel layouts were visually inspected without horizontal overflow.
The native fetch receiver failure found in this test now has a regression test.

The continuation fixture adds versioned check outcomes, skipped/failure reasons,
inconclusive and historical unassessed risk, cloud resource identities, real
transactional audit history, literal HTML-like fields, and exports despite an
unavailable audit route. It also verifies logout clearing and the absence of
page errors, external requests, and CSP violations. Discovery/security functions
remain synthetic; this does not validate a real model's behavior.

The template continuation exercises authenticated save/edit/run/delete, 25+2
paging, source/model/timeout preservation, stale revision conflicts, dirty-editor
discard, literal HTML names, denied targets, initial list 503 recovery, and 401
clearing. Fresh desktop 1440/mobile 390 screenshots were inspected with no
horizontal overflow, external requests, page errors, CSP violations, or browser
storage. Authentication, database, dispatcher, and API are real; scanning remains
synthetic.

The schedule continuation verifies reviewed saved pins, disabled creation with
no job, explicit enable/pause, real CAS and pin conflicts, policy/quota errors,
restart review, controlled due admission, outstanding-scan deletion rejection,
completed occurrence navigation, 25+2 schedule/occurrence paging, and deletion
preserving reports. It also covers initial list 503 recovery, logout, late
responses, 401 clearing, and literal HTML fields. Real desktop 1440/mobile 390
Chromium acceptance passed with no horizontal overflow, page errors, external
requests, CSP violations, or browser storage. Independent source review and 92
focused pytest cases passed on integrated head `9811587`.

Targeted real keyboard/API checks cover sign-in, create/open, enable/pause,
schedule/template deletion, logout, and 401. Focus moves to schedule identity
after explicit successful transitions, nearby Refresh after deletion, and the
operator key after sign-out. Background list/occurrence refresh does not move
focus. Labels, linked pin/bounds hints, polite notices, and 320/390/1440 layouts
were inspected. Stronger baseline control borders, linked scope/model hints,
named check/audit regions, final Show more focus, and completion announcements
were the next focused slice at that checkpoint. Screen-reader workflows and comprehensive
accessibility conformance were not evaluated. All fixture servers stopped;
the browser artifacts remain in `/tmp/ai-scanner-schedule-browser-rDbOYW`.

The accessibility continuation checks linked scope/model guidance, named scroll
regions, focus ownership at 36-record final pages and the 100-of-110 display cap,
unchanged terminal polling without report replacement or duplicate announcements,
all five terminal states, unavailable/historical reports, report recovery, stale
selection/logout/401, and unrelated notice preservation. Real Chromium reflow at
320/390/1440 pixels passes without horizontal overflow. Enabled borders measure
4.226:1 against white; the existing focus outline measures 3.407:1. No external
browser requests, CSP violations, page errors, or browser storage were observed.

The checked-in optional [browser workflow](DEVELOPMENT.md#optional-chromium-dashboard-checks)
uses actual Flask/authentication/SQLite with seeded synthetic reports, no real
provider calls, and no enabled schedules. Parent-owned temporary database cleanup
and fixture reaping passed on success, deliberate assertion failure, and browser
launch failure. Mandatory tests separately cover startup and forced cleanup paths.
Screenshots/logs are retained; fixture databases are removed. This is targeted
keyboard/DOM acceptance, not screen-reader interoperability or full WCAG conformance.

## Local queue acceptance

The default 200-job disposable SQLite workload passed with two workers:
179 completed, 20 cancelled, one interrupted, 181 unique claims, 582 audit events,
and consistent job/session/report states. A repeated integrated run took
8.227119 seconds (21.757 completed jobs/second) on schema version 3; no throughput
threshold is an acceptance criterion. Four-job acceptance passed and a deliberately insufficient
deadline reported failure. See [performance scope and reproducible commands](performance.md).

Installed AWS, Azure, and GCP SDK method signatures and resource/list schemas were
checked locally, including cloud extras. Tests use mocked responses without
provider credentials or real account requests. Use Python 3.11 or newer for cloud
inventory because the installed Google SDK warns about Python 3.10 support.

## Disposable backup/restore acceptance

The [local command](jobs.md#disposable-backuprestore-acceptance) passed all eight
cases with a five-second work deadline on Python 3.10 and 3.12. Normal and
optimized Python execution passed. Forty-two mandatory tests cover the command,
pre-connect engine/path guards, no-clobber copies, strict child results, bounded
output/deadlines, environment isolation, and process/database cleanup.

Stopped synthetic schema 1/2/3 databases retain exact schema and logical rows in
backup and restored files before initialization. The real initializer, job store,
dispatcher, and schedule recovery preserve completed evidence, agent snapshots,
audit history, templates, and existing occurrences. Synthetic queued work executes
once; active work becomes interrupted/cancelled without replay. Enabled schedules,
including an overdue schedule without outstanding work, pause for restart review
without preflight or admission. The second dispatcher restart leaves rows unchanged.

Injected version-stamp failures roll back schema 1/2 upgrades. Future versions and
competing dispatcher ownership fail before recovery without database changes.
A restored copy with a deleted report still passes SQLite integrity but is rejected
by logical comparison before startup. An independent copy of the untouched backup
retains original version/content; source and backup hashes remain unchanged.
Independent fault mutations also detected lost rows, changed completed metadata,
missing schedule recovery, and an improperly accepted future version.

No operator database was opened or target scanned. This covers local synthetic
content preservation, not deployed restore, online backup, old-binary compatibility,
crash durability, or release sign-off.

## Local-beta finish pass

The [beta guide](BETA_TESTING.md) defines a finite supported-scope gate and an
offline walkthrough using separate keys, a private fresh database, sanitized
settings, loopback binding, and the checked-in static SDK-import fixture.
CLI discovery of that fixture returns one OpenAI inventory observation, no
endpoint or finding, unexecuted security checks, and unassessed risk.

The new mandatory operator test uses actual authentication, current-policy
admission, template execution, repository discovery, the shared pipeline,
file-backed SQLite dispatcher, report/audit/JSON/SARIF routes, and one explicitly
enabled finite schedule occurrence. It verifies skipped security and unknown risk,
secret-free reports, and recipe/schedule deletion preserving reports. External
sockets, DNS, and process execution are forbidden; fixture source must never
execute. Independent Python 3.10/3.12 runs passed, alongside 200 focused author
tests. This is API-level acceptance, not a new full browser workflow.

The existing Chromium command passed normally with optimization disabled at
320/390/1440 pixels. Artifacts are in `/tmp/ai-scanner-browser-2p7pyzn4`.
Its fixture PID 2987229 was reaped and its temporary database directory removed.
Normal and optimized backup commands each passed all eight cases. Local build,
Twine, installed-wheel smoke, lint, configured Bandit gate, dependency audit, and
pip check passed. A focused independent security/correctness audit passed 314
cases and reproduced no must-fix blocker in the supported boundary; this is not
an exhaustive security certification.

The local Docker image built from unchanged application code at `647c6d1`
(`sha256:f90983133c6b11a8d6a02b17f261e75beb3bb57434bf07d91c3f6f444158ca52`)
passed authenticated checks before and after restart. The uniquely owned test
container was removed; no operator database, real target, or deployed volume was
used. CI repeats this behavior on the PR's exact source. The setup example now
passes the independent operator key instead of starting a server with login disabled.

Five sequential fresh-database queue runs passed on Linux/aarch64, Python 3.10.20,
SQLite 3.53.1. Every run had zero duplicate claims, consistent terminal states,
one terminal event per scan, and peak workers within its bound:

| Jobs | Workers | Synthetic latency (ms) | Elapsed (seconds) | Peak workers |
| --- | --- | --- | --- | --- |
| 200 | 2 | 1 | 8.823065 | 2 |
| 200 | 2 | 1 | 9.917252 | 1 |
| 200 | 2 | 1 | 8.919674 | 2 |
| 500 | 4 | 5 | 24.108064 | 4 |
| 500 | 4 | 5 | 22.384391 | 4 |

Totals: 1600 jobs, 1435 completed, 160 cancelled, five interrupted, 1445 unique
claims, and 4650 audit events. A separate 200-job/1000-ms case with a one-second
deadline exited 1 and reported incomplete state rather than success (1.083490
seconds). A parent-owned temporary root, sanitized environment, 90-second child
watchdog, and bounded kill/reap grace protected every run; all roots were removed.
The local driver is retained at `/tmp/ai-scanner-finish-queue-profile.py`.
This is finite queue regression repetition, not a long-duration soak, HTTP or
scheduler load test, production throughput claim, or performance threshold.

After the reviewed revision and merged commit pass all seven CI jobs, this gate
is ready for local operator beta testing. Stop feature expansion for that beta;
collect feedback under the guide's scope. M6 and the release-level gaps below
remain separate from that limited acceptance.

## Remaining validation gaps

The privacy cleanup excludes machine-local assistant instructions, lab setup, and
the legacy screenshot from the current Git tree, source distributions, and Docker
contexts. Two regressions check the public index and ignore policy. Fresh package
metadata has no personal author email; professional credit remains. Local originals
are retained. Repository and reachable-history pattern/context review found no
plausible live credentials, but is not proof that every possible secret is absent.
Existing history, published artifacts, and third-party copies were not rewritten
or erased. Future commits use the account's user-approved repository-local noreply
identity; global identity is unchanged.

- Real cloud account inventory and representative capture-format integration
  remain incomplete despite stronger mocked/format fixtures. Network samples
  three read-only protocol inventories and common ports, not all services. The
  API still normalizes domains to IPs and can miss hostname-dependent virtual
  hosts; TLS on nonstandard ports and authenticated inventories remain gaps.
- Provider fixtures do not establish compatibility with every live model or
  account configuration. No paid provider calls were made.
- Replay metrics describe synthetic or supplied labels, not representative
  production precision/recall. Passive MCP and read-only live inventory do not
  execute tools or test runtime authorization, Origin enforcement, or sandboxing.
  Controlled policy checks sample only explicit protected inventory fixtures and
  the first control page; they do not close those broader runtime gaps. Operator
  fixture provenance is trusted input, not independently verified attestation.
  The live client supports only MCP 2026-07-28 and its documented input-schema
  subset; legacy versions, OAuth acquisition, and broad interoperability remain gaps.
- PostgreSQL, distributed workers, network-filesystem locking, and overlapping
  server reloads are unsupported, not validated deployment options.
- Representative load/soak benchmarks, comprehensive accessibility evaluation,
  deployed upgrade/backup acceptance, enterprise identity, and tamper-resistant
  audit acceptance remain pending. Known SQLite upgrade tests and a synthetic
  queue workload do not close these release-level gaps.

## Synthetic evaluation registry isolation

The optional queue benchmark and API/local-lab/offline-operator fixtures must not
inherit or reuse an operator's startup evidence registry. Standalone queue and
backup runners clear the registry-path setting and reject a cached nonempty
registry before app-context, database, or schema access. Unit fixtures also
isolate cached registry objects and restore their original environment/object
on teardown. Normal configured server behavior is unchanged. Backup acceptance
retains its outer `SCAN_` child-environment filter; the inner entrypoint now also
clears the registry setting for direct child invocations.

Eight new bounded regressions cover missing/private paths with forbidden-open
guards, fresh imports, cached fixtures, restoration, and direct backup children.
The native macOS diagnostic run located a 20-second fixture timeout at the first
HTTP server constructor. That fixture now binds numeric server names without
reverse DNS; fresh and cached setup run with `getfqdn` and `gethostbyaddr`
forbidden. The 20-second child deadline and bounded traceback diagnostics remain.
A Linux symlink-ancestor regression verifies canonicalization of the owned
temporary root while preserving database leaf guards; native CI remains pending.
Before one additional quoted-identifier regression, the isolation branch passed
1566 full-suite cases with warnings treated as errors and an inherited nonexistent
registry path. Independent review passed 177 relevant cases. A final 55-case
backup/isolation/workflow gate includes the hostile-identifier and symlink regressions and
passes. Expanded Bandit covers both helpers; one narrow B608 suppression documents
the existing escaped SQLite identifier query, with a regression proving hostile
table-name text cannot alter other fixture tables. Ruff and whitespace checks pass.
The reporting slice contributes its own separately recorded tests; branch counts
should not be added as independent runs. Final combined CI, including native
macOS, remains required before acceptance.
This does not use an operator registry, database, or target, and does not replace
the separate browser isolation regression. All eight PR/post-merge CI jobs are
required on the final source before acceptance.

See [engineering milestones](ENGINEERING_PLAN.md), [development checks](DEVELOPMENT.md),
and [persistent job constraints](jobs.md).
