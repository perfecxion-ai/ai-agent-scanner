# Engineering plan

## Product direction

The revised direction, approved on 2026-10-22, is an open source tool for
discovering deployed AI applications and agents, proving specific security
boundary failures, and verifying remediation. Operators should be able to use a
fully local assessment path with bounded execution and privacy-safe evidence.
Leadership is an objective to measure, not a current market or accuracy claim.

The strategic review at `aae1863` found a credible assessment foundation, but
limited live-agent coverage, difficult configuration, and two additional evidence
correctness gaps. Earlier lab acceptance remains valid only within its recorded
scope; it does not close these newly reproduced gaps. The active roadmap below
supersedes the old delivery order, not the historical validation record.

Keep Python, Flask, the shared CLI/API pipeline, and the supported single-process,
POSIX, local-filesystem SQLite server. Prefer small reviewed improvements over a
rewrite. Distributed workers, PostgreSQL, and Kubernetes-first deployment are not
prerequisites for the next milestones. Publication, deployment, paid targets,
cloud startup, and live schedule enablement still need separate authorization.

## Active roadmap

| Milestone | Deliverables | Exit gate |
| --- | --- | --- |
| R1: Trustworthy results | Authorized positive controls; incremental durable evidence; canonical unknown scores; exhaustive inventory; accurate build identity | No false sampled pass or resolution from missing controls; earlier confirmations survive timeout/cancel/restart; unknown remains unknown in storage and exports; risk filters include older matching assets |
| R2: Useful application assessment | Custom HTTP/session adapter; guided prerequisites and bounded scan preview; actionable findings; offline CI policy gate; extension contracts | CLI/API produce consistent results on a reproducible vulnerable/defended application lab; new operators complete the workflow without raw JSON or maintainer assistance |
| R3: Meaningful live agent coverage | Indirect document/tool-result injection; cross-tenant retrieval; unauthorized tool selection/arguments and observed actions; public bounded benchmarks | Each supported objective has vulnerable/defended fixtures and explicit evidence criteria; held-out results report detection, false confirmations, incomplete coverage, and cost separately |
| R4: Team-ready beta | Identity and roles; scoped service credentials; actor-attributed audit; secret-provider integration; retention; operational and accessibility acceptance | Documented supported deployment passes independent access-control, workload, restart, backup/upgrade, and operator acceptance; no broader enterprise claim from fixture-only tests |

Release hygiene, public documentation, contributor support, and benchmark design
run alongside these milestones. R4 does not imply distributed execution. Live
tool tests must use explicit permissions and disposable side-effect destinations;
proposed calls and observed actions are distinct outcomes.

### Review findings and scoped delivery order

| Slice | Finding and work | Required acceptance | State |
| --- | --- | --- | --- |
| R1.1 | Generic authentication checks accept denied requests without a successful authorized resource baseline | Always-denied, unseeded, unavailable, and stale-credential controls cannot pass or resolve findings; valid positive/negative controls permit only bounded sampled claims; changed evidence semantics are versioned and private | Initial controls merged in PR #64. V3 actual-request provenance/denial correction and schema-6 historical cache reconciliation merged in PR #79 with all eight PR/post-merge checks. Scoped native Python 3.11.2/SQLite 3.40.1 access, backup and inventory acceptance passes with recorded private-harness qualifications |
| R1.2 | Outer deadlines can discard findings produced before a later stage stalls | Sanitized check/asset checkpoints survive later timeout, cancellation, and process recovery; terminal writes are transactional; unfinished checks remain incomplete; no active probe replay | Completed-check and prompt/tenant/access receipts have qualified native acceptance. R1.2e CLI crash files merged in PR #83; PR #84 manual CI and current main pass all eight checks. Scoped native Python 3.11.2 acceptance passes 119 cases, packaging and installed recovery with recorded harness/privacy limits; future families and private API inputs remain separate |
| R1.3 | Database score columns retain unknown as `0.0`; historical evidence also needs current eligibility guards | Shared canonical eligibility rejects unsupported historical control semantics without rewriting reports; versioned migration preserves legitimate assessed zero, rejects unsupported layouts, and passes rollback plus backup/restore fixtures | Merged in PR #72 with all local, independent, and eight PR/post-merge CI gates passed; scoped native reconstructed-fixture upgrade/restart accepted with recorded qualifications |
| R1.4 | Risk filtering considers only the newest 100 inventory records | Stable asset identity is separate from observations; indexed filters and cursor pagination are exhaustive and tenant-scoped; a 10,000-observation synthetic fixture has no missing/duplicate pages | R1.4a traversal, R1.4b1 grouping and R1.4b2a group risk indexes have qualified native acceptance. R1.4b2b1 shares strict observation/group risk attribution and passes the 5,563-case local gate. Observation-index acceleration is deferred behind the guided HTTP workflow; dashboard groups and logical findings remain separate |
| R1.5 | Main is far beyond the public release but still identifies itself as `1.1.0` | Release/development identity includes reproducible source and catalog provenance; artifacts have tested install/upgrade paths, checksums, and an SBOM; publication remains separately authorized | R1.5a development/content identity passes local and independent gates; required delivery CI is recorded on its PR. Release checksums, SBOM, dependency/build attestation and deployed upgrade acceptance remain open |
| R2.1 | Hardwired testers and provider formats limit application coverage | Versioned target, scenario, evidence-evaluator, and shared-budget contracts support a custom HTTP/session adapter; a reference extension needs no route or orchestrator edits | R2.1a implements one HTTP JSON prompt-disclosure path with exact POST mapping and versioned evidence. Guided CLI, independent HTTP/HTTPS/recovery checks and the installed-wheel workflow pass locally. Final delivery CI and scoped native acceptance remain required; server admission, stateful sessions and broader extension contracts remain open |
| R2.2 | Advanced model/evidence/suite setup depends on manual identifiers and JSON | Guided discovery-to-assessment flow and CLI setup/diagnostics/preview expose ready, unsupported, missing, and inapplicable prerequisites; secret references never become ordinary saved values | R2.2a implements guided private target setup, an offline target/scope/readiness preview and active assessment without manual agent JSON or asset IDs. Local and installed-wheel acceptance pass; native, dashboard and server configuration gates remain open |
| R2.3 | Findings and exits need clearer remediation and policy meaning | Logical findings preserve occurrences, explain boundary/evidence/control/verification, and avoid uncalibrated numeric confidence; offline CI evaluation distinguishes policy violations, missing required coverage, and invalid reports | Planned |
| R3.1 | Private, narrow cohorts do not establish general detection performance | Public reproducible vulnerable/defended pairs, held-out targets, fixed budgets, executed-driver identities, preserved captures, real exit codes, and explicit model/state provenance; no pooled heterogeneous accuracy | Planned |
| R3.2 | Offline replay and MCP inventory do not test live retrieval or actions | Add one deeply supported agent integration and controlled MCP actions with per-objective positive/negative fixtures; missing traces cannot prove defenses; no uncontrolled external effects | Planned |
| R4.1 | Current server is single-operator, not a team authorization product | OIDC/roles and scoped service credentials enforce tested ownership boundaries; attributable audit and secret rotation have explicit contracts before broader deployment claims | Planned |
| R4.2 | Synthetic queue and backup checks do not establish operational readiness | Bounded load/soak, full-disk and stalled-target behavior, retention, deployed upgrade/restore, and comprehensive accessibility have separate recorded acceptance | Planned |
| OSS.1 | Release lag, sparse contributor guidance, conflicting license headers, and chronological docs inhibit adoption | Clarify ownership/license headers without silently relicensing; publish task-oriented docs, reference extensions, contribution/issue templates, current roadmap, and a turnkey local lab; obtain external operator/contributor feedback | Planned |

R1.1 is the first implementation slice. Its interrupted-check accounting
prerequisite must land before or with the positive controls: cancellation after
successful controls must not produce a passed check. R1.2 needs a reviewed
persistence contract before implementation, including which completed checks and in-progress
observations can safely be saved. R1.3 and R1.4 must share canonical risk semantics
without silently rewriting historical findings. R2.1 and R3.1 design may proceed
in parallel, but new execution surfaces must retain existing scope, privacy, and
resource limits. The narrower HTTP adapter precedes a broad plugin ecosystem.

R1.2 should land in separately reviewed increments: first correct interrupted
check status, then persist completed check results through later failures and
CLI/server termination, then retain actual confirmed observations from inside
unfinished checks. The last increment needs a versioned progress/evidence
contract, not a benchmark boolean or invented completed check. R1.2 remains open
until both completed-check and in-progress confirmation recovery pass. Recovery
must never replay an active probe to recreate lost evidence.

Before within-check persistence and score migration, close the historical
protected-access eligibility gap. A matching obsolete probe version is not proof
that an issued-credential positive control ran. Current scoring and resolution
must recognize supported public probe semantics and valid counters through one
shared contract. Preserve archived reports and findings, including unsupported
confirmations, without presenting them as current verified risk or resolution.
Unknown/custom protected-access probe definitions fail closed until they have supported evidence
provenance. Do not change frozen current catalogs merely to reinterpret history.

The checkpoint design uses scan-local immutable check/finding pairs and the
shared report/risk projection, not a second scorer or global-engine state. A
nonterminal SQLite transaction must bind the current worker and checkpoint
sequence, preserve snapshot identity, and atomically save report/snapshots/counts
without clearing cancellation or marking completion. Stale or terminal writes
must be rejected. Every checkpoint must pass existing redaction and validation
before storage; bounded inline writes fail closed with a static error. Recovery
preserves committed evidence and truthful failed/cancelled/interrupted job states.
Tests must include commit rollback, cancellation races, stale writes, bounded
contention, and child-process termination after an acknowledged commit.

CLI orderly timeout/cancellation should export the same retained partial evidence
with a nonzero exit. An in-memory accumulator is not CLI process-crash durability;
that claim needs a separate explicit private checkpoint-file contract and tests.
Within-check observations need real provenance/counters before the next await.
Neither missing evidence nor an interrupted category can establish a pass.

R1.2b begins with prompt-disclosure observations only. Its reviewed design uses
immutable, per-asset execution receipts bound to one reserved request and evaluated
response. Receipts and finalized checks are distinct ledgers; `checks_unfinished`
counts receipt-backed checks lacking a terminal record, including after recovery.
New-mode prompt confirmations require supported receipts even after completion;
unsupported custom catalogs remain visible but cannot fall back to legacy scoring.
Historical reports and standalone benchmark observations remain readable, but
matching finalized checks cannot replace source-2.0 receipts for current versioned
prompt risk. The historical follow-up makes unsupported positive claims unknown
per asset, without inventing zero from a companion pass or recalculating archived
scores. Preserve archive contents and never resolve those claims from nondisclosure.
The explicit unversioned low-level scorer compatibility API remains distinct from
canonical current projections. See [acceptance](VALIDATION.md#historical-prompt-eligibility-follow-up).
Privacy guards cover newly emitted descriptors before security work, and every
projection uses the same secret basis. Acceptance must interrupt the same category
after an acknowledged receipt, not merely stop a later category. Tenant/access
receipts and CLI crash files remain explicit follow-ups.

Next-slice review reproduced a tenant correctness prerequisite: a local endpoint
without tenant data can echo a configured canary supplied as the model or
Authorization value and produce five eligible confirmed findings. The existing
guard excludes only prompt reflection, and no authorized tenant-data baseline
establishes provenance. Correct this boundary and define positive/negative tenant
controls before extending within-check receipts to tenant observations. Preserve
historical reports but do not mistake their recorded claims for supported current
evidence. See the [scoped reproduction](VALIDATION.md#tenant-evidence-prerequisite-for-the-next-increment).
The tenant implementation uses explicit private CLI/Python declarations, two
issued principals, an operator-attested authorization boundary, and owner/tested/
invalid controls before the unchanged five attacks. All private values are pinned
before checkpoints. Shared request guards and actual private snapshots prevent
known outbound contamination from supporting later findings. Current eligibility
requires the original endpoint/provider/model/context, recognized control version,
and bounded finalized-check accounting. Historical tenant positives remain
unassessed without changing archived evidence. Server admission, source replay,
queued execution, and discovered inputs reject private tenant declarations before
credential resolution. The supplied
[tenant CLI/TLS retest](VALIDATION.md#supplied-tenant-workflow-acceptance) closes
that scoped workflow gate. This does not close tenant within-check retention or
establish representative model sensitivity. Nullable storage now uses schema 4,
explicit historical definitions, canonical scalar caches, and a transactional
two-table rebuild. Supported zero and partial findings survive; unsupported risk
becomes SQL NULL without rewriting archives. Local rollback, backup/restore and
actual current HTTP-evidence cases pass. See
[acceptance](VALIDATION.md#nullable-score-storage-local-acceptance) and the scoped
[native-server upgrade gate](storage-retest.md). The supplied native run now
closes the scoped reconstructed-fixture upgrade/restart gate with
[recorded qualifications](VALIDATION.md#supplied-native-storage-upgrade-acceptance).
Inventory pagination and release identity remain separate R1 slices.

R1.4a first makes observation traversal exhaustive without changing snapshot IDs,
scan-local asset aliases, selected-scan history, or report exports. Cursor scope
must bind ownership, normalized filters, ordering, page size, projection policy,
and a generation invalidated transactionally by relevant source writes. A
timestamp watermark alone cannot detect changed checkpoint reports. Evaluate
risk from saved canonical evidence, never stale scalar columns. Bound candidate
and projection work; sparse filters may return an empty page with continuation.
Uninterpretable or oversized source material must produce an explicit incomplete
operation, not silently hide a potentially matching finding. Distinct-asset
identity and indexed risk projections need their own semantics and acceptance.
The R1.4a implementation now passes 3,964 local coverage tests with warnings as
errors and a final independent 99-case Python 3.13 gate. Its schema-5 triggers
cover direct ORM/Core source changes and ownership moves, and canonical pages
never prefilter with scalar risk caches. Actual 10,000-observation query plans
use ownership/candidate indexes but still sort across scans. The read deadline
and source/output allowances bound the operation separately. See
[local evidence](VALIDATION.md#exhaustive-observation-pagination-local-acceptance)
and the [accepted native gate](VALIDATION.md#supplied-native-inventory-traversal-acceptance).
This does not provide a deduplicated current-asset view or an authoritative
indexed risk cache.
R1.5a producer/build identity and tenant/access receipts are now delivered below.
R1.4b1 now implements conservative public-target groups with latest canonical risk
separate from original finding history. Missing or quiet evidence does not resolve
an earlier confirmation. Schema 7 derives bounded, sealed publications from saved
sources while preserving schema-6 rows and caches. Focused tests and normal and
optimized real-server gates traverse 10,000 observations across three organizations.
See [contract](asset-groups.md), [local evidence](VALIDATION.md#public-target-grouping-local-acceptance)
and the [native failure review](VALIDATION.md#supplied-native-asset-group-gate-failure-and-portability-correction).
The correction preserves the [180-second native gate](asset-groups-retest.md),
prepares source SQL once per reader, and permits either recognized indexed
readiness-count plan while retaining the exact staging lookup. The fresh supplied
run at `1b164df8bdd4361dc92ef17b917bc1e63291fa91` closes the R1.4b1 native gate:
normal/optimized runs take 129.273/135.675 seconds with all fourteen assertions,
10,000 observations, 24 groups and zero pagination retries. Both fourteen-case
backup modes, 309 focused tests (two deselected), all real step/driver/job exits
and the 37-record capture reconciliation pass. See
[scoped native acceptance](VALIDATION.md#supplied-native-asset-group-acceptance)
for source/runtime reconciliation and producer-attestation, privacy and private
wrapper limits. The original failed gate and historical CI failures remain
recorded; a longer diagnostic never replaced them. R1.4b2 authoritative
source-bound risk indexes, dashboard group views and logical-finding consolidation
need separate semantics and acceptance. Group IDs do not establish credential or
principal equivalence; history counts occurrences rather than unique vulnerabilities.
Keep release publication, artifact attestations and the rest of R1.5 separate.

R1.4b2a adds `risk_level` filters for group lists through six canonical facts in
the existing sealed publication. Schema 8 adds nullable columns and one partial
index while preserving frozen schema-7 sources and cache fields. The complete
readiness proof precedes SQL filtering; selected candidates are reopened and all
six facts compared with their saved source. Unknown remains null, and earlier
confirmed history never promotes the latest risk. Signed cursors bind normalized
filters, and actual continuation plans use the timestamp range. Full readiness
still counts all source/publication rows; this is not constant-time inventory.
The partial risk index repeats the constant head flag as a key to avoid SQLite
cost ties with the older page index on continuation ranges. Controlled regressions
cover both valid index creation orders and older, tied and newer nonmatches.
Focused and independent tests pass on SQLite 3.40.1, 3.45.1 and 3.53.1. The extended
local compatibility gate retains the original 10,000-observation oracle and
180-second budget, with separate positive risk controls. See
[local acceptance](VALIDATION.md#indexed-group-risk-local-acceptance) and
[delivery PR #89](https://github.com/perfecxion-ai/ai-agent-scanner/pull/89).
The supplied native run at merged
`c12ceadcc6c830d73e1d484f17b45c06f07c329b` closes R1.4b2a's scoped gate on
Python 3.11.2/SQLite 3.40.1. Normal/optimized modes accept all seventeen assertions
in 150.237/150.768 seconds under the unchanged 180-second budget. Both fifteen-case
backup modes, 447 focused tests (two deselected), all real exits and all 24
risk-filter digests pass; source and expected-result manifest checks reconcile
locally. See [native acceptance](VALIDATION.md#supplied-native-indexed-group-risk-acceptance)
for absent Mac captures, private-wrapper, privacy and backup-scope qualifications.
The observation API retains its current alias-based eligibility; sharing the
stricter grouped target binding with it needs an explicit compatibility decision
before indexed observation acceleration. This acceptance does not close that
separate slice or the remaining roadmap work.

R1.4b2b1 now shares bounded safe-alias eligibility, unique report-agent selection,
strict JSON decoding and snapshot provider/model/endpoint binding between
observation reads and group staging. A different valid selector keeps the original
observation with null risk; malformed or duplicate source members return an
incomplete operation. Archives and scalar caches are unchanged. Raw SQLite
timestamp ordering, signed cursors and existing work bounds remain in force.
The local warnings-as-errors coverage gate passes 5,563 tests; independent review
passes 42 cases on SQLite 3.40.1 and 3.53.1. Both updated real-server inventory
modes retain the 10,000-observation oracle and unchanged 120-second budget.
See [acceptance](VALIDATION.md#shared-observation-source-binding-local-acceptance).
Required delivery checks are recorded on the implementation PR. This is a
schema-8 compatibility correction, without observation-index acceleration.

After this correction, the delivery priority moved to R2.1a/R2.2a guided HTTP assessment.
The current inventory path has native 10,000-observation acceptance; easier
application assessment addresses the larger operator usability and coverage gap.
Keep observation-index acceleration as a separate R1.4 follow-up. The first new
workflow supports one exact HTTP JSON POST, one selected generated-response field,
explicit private credential/canary references, fresh sessions and seven bounded
protected prompt groups. It must preserve evidence through failure and recovery,
leave quiet results inconclusive, and offer a preview without target requests.
Deliver setup and active execution together, with owned HTTP/HTTPS fixtures and
an installed-CLI operator workflow. Request one scoped native retest after that
complete workflow passes local and required CI gates, rather than a separate
cloud run for the attribution correction. Model sensitivity remains a separate
frozen-cohort question; this sequence does not close R2 or establish enterprise
readiness.

The complete CLI workflow now passes local acceptance. `target init` creates a
private selected profile; `assess --plan` shows its public mapping, network scope,
prerequisites and budgets without a target request; `assess` runs the seven
protected prompt groups. It supports one exact JSON POST and a selected string
response, without a model placeholder or provider-specific path rewriting.
Credentials and canaries resolve from declared references once. The new HTTP
receipt source binds the adapter through reports, scoring, checkpoints and
recovery; ordinary scan defaults and existing provider evidence retain their
contracts. See [operator setup](http-application-assessment.md) and
[local acceptance](VALIDATION.md#guided-http-application-local-acceptance).
The fresh installed wheel passes the complete 77-request fixture workflow outside
the checkout. A narrow inventory-reader correction reuses SQL and original
target identities without weakening per-row binding or work limits. The
validation record retains the original full pass, refreshed coverage run and
corrected permission-fixture result separately. Required CI collects 5,865 cases;
it and the scoped
[native operator retest](http-assessment-retest.md) remain delivery gates.
This closes neither full R2 CLI/API parity nor representative detection accuracy.

R1.5a uses canonical `1.2.0.dev0`, scoped deterministic source/catalog hashes,
immutable new-run producer stamps and distinct exporter identity. Historical raw
archives are not relabeled. Full local validation passes 4,142 cases, and
independent review passes 65 overlapping cases on Python 3.13. See
[contract and limits](build-identity.md) and
[acceptance](VALIDATION.md#development-producer-identity-local-acceptance).
R1.5a merged in PR #76 with all eight PR and post-merge checks passing.
Tenant-only R1.2c now uses mixed ledger `2.0` and checkpoint `3.0`, with live
request/response witnesses, acknowledged eligibility preservation and canonical
tenant target matching. The local coverage gate passes 4,366 cases; 95 final
focused cases cover literal adapter-declaration hardening. Actual HTTPS/CLI
interruption and library dispatcher recovery retain genuine 90/critical partial
evidence without replay or secret retention. See
[acceptance](VALIDATION.md#tenant-observation-retention-local-acceptance) and the
[scoped native gate](tenant-progress-retest.md). PR #77 merged as `6af7fa2` with
all eight PR and post-merge checks passing. The supplied four-case native gate
and two recovery tests now pass with recorded harness/privacy qualifications;
see [native acceptance](VALIDATION.md#supplied-native-tenant-interruption-acceptance).
Protected-access provenance/receipts, private server tenant profiles and CLI
crash files remain separate increments. Do not expand the native gate into
another cohort accuracy claim.
Before protected-access receipts, close the independently reproduced actual-request
provenance gap: a transport-added marker or issued credential can make current
access probes falsely confirm an unauthorized read. Static planned-request checks
do not establish what was transmitted. Pin controls privately, verify complete
actual GET provenance and selected credential roles, and issue new evidence
semantics. Preserve raw historical reports while withholding unsupported current
risk/resolution; reconcile older SQL caches explicitly under the supported schema
upgrade path. This prerequisite does not add receipts, new GET protocols or server
admission. See [reproduction](VALIDATION.md#protected-access-request-provenance-prerequisite).
That prerequisite now has local v3 acceptance across all four existing GET
families. Inputs are pinned before checkpoints, captured requests bind the exact
resource and selected credential role, and unsupported/disclosing denials remain
inconclusive. Older v2 risk/resolution is unsupported without rewriting archives.
Schema 6 refreshes only necessary scalar caches, with normal affected-owner
trigger invalidation and no refresh on recognized restart. The full candidate
passes 4,694 coverage cases; 838 final focused cases include the static phase-log
privacy correction. Independent live-wire, schema and HTTPS CLI reviews pass.
See [acceptance](VALIDATION.md#protected-access-v3-and-cache-policy-local-acceptance)
and the [native gate](access-provenance-retest.md). Access receipts remain a
separate next slice; no ledger/checkpoint or server-admission expansion is included.
PR #79 merged as `a9b2718` with all eight PR/post-merge checks passed. The supplied
native retest accepts 337 targeted cases, both thirteen-case backups and both
schema-4 to 6 inventory runs; all 109 captured expectations reconcile. This is
synthetic platform correctness, with documented wrapper/privacy limits, not an
operator upgrade or sensitivity gate. See
[qualified acceptance](VALIDATION.md#supplied-native-access-and-cache-policy-acceptance).

R1.2d adds protected-access observations using ledger 3/checkpoint 4, without
changing the frozen readers, GET samples, request budgets or schema 6. Each
modern confirmation requires live private request/response capability, successful
issued/invalid controls and an immutable receipt before the next cleanup or
request. Numeric selectors preserve exact catalog identity without exporting
credential values. Frozen finalized-v3 archives remain supported; stripped modern
envelopes cannot gain their fallback. PR #81 merged as `0797857` after local,
independent and all eight PR/post-merge checks passed. The supplied native gate
accepts 230 targeted tests, both thirteen-case backups and both inventory modes,
with 110 captured checks reconciled and documented private-harness limits. See
[qualified acceptance](VALIDATION.md#supplied-native-protected-access-retention-acceptance).
That increment does not add private API inputs or CLI process-crash files.
R1.2e separately adds a fresh private `--checkpoint-dir` and offline `recover`.
The shared public evidence is persisted before callback acknowledgement without
resuming probes or storing private configuration. Nonterminal recovery remains
partial; actual terminal status is preserved. The full local gate passes 5,102
coverage tests, including 119 new cases and independent real CLI SIGKILL review.
See [acceptance](VALIDATION.md#cli-process-crash-checkpoint-local-acceptance),
[file contract](cli-checkpoints.md) and [scoped native gate](cli-checkpoint-retest.md).
PR #83 merged as `1d790bf` and PR #84 manual CI as `49c1041`, each after all eight
PR checks; all eight checks on current main also pass with unchanged runtime.
The supplied native gate accepts 119 cases, build/Twine and installed recovery on
Python 3.11.2, with 23 captured checks reconciled. See
[qualified native acceptance](VALIDATION.md#supplied-native-cli-checkpoint-acceptance).
This closes the implemented CLI process-recovery gate for current evidence
families. Private API admission, future evidence families, deployed durability and
later roadmap slices remain separate work.
The prompt audit also reproduces false confirmations from case-changed outbound
values and transport-added headers. PR #67 now requires a complete private
request snapshot to exclude these marker sources before confirmation and receipt
minting. Source version 2.0 distinguishes the tightened receipt semantics from
the unmerged draft. Response matching remains exact, frozen probe bytes/hashes and
budgets are unchanged, and missing or incomplete request provenance cannot confirm. This does
not prove independent target-side seeding or exclusion of arbitrary transformations.
See the [reflection correction evidence](VALIDATION.md#prompt-request-reflection-correction).

Proposed R2 usability acceptance is five unfamiliar operators completing the
public vulnerable/defended lab within 15 minutes without editing JSON or receiving
maintainer help. This is a future gate, not an existing measurement. Public
benchmarks must report per-objective confirmed yield, false confirmations,
inconclusive/error/coverage rates, and requests/tokens/time to confirmation.
Competitor comparisons require compatible objectives and equal budgets; prompt
counts, framework mappings, test counts, and code coverage are not effectiveness
metrics. Adaptive prompts follow observable evidence criteria and session/reset
support; model-based judges alone cannot upgrade a claim to confirmed.

### Market reference points

The review compared documented capabilities, not measured head-to-head results:
[Promptfoo](https://www.promptfoo.dev/docs/red-team/strategies/) for application
workflows and multi-turn strategies, [garak](https://github.com/NVIDIA/garak) for
modular model probing, [PyRIT](https://github.com/microsoft/PyRIT/blob/main/doc/code/framework.md)
for composable execution and scoring, [Giskard](https://github.com/Giskard-AI/giskard-oss)
for scenario-based agent/RAG testing, [Snyk Agent Scan](https://github.com/snyk/agent-scan)
for installed agent-component discovery, and
[Cisco MCP Scanner](https://github.com/cisco-ai-defense/mcp-scanner) for focused
MCP analysis. [AgentDojo](https://github.com/ethz-spylab/agentdojo) is a candidate
complement to deployment-level fixtures, not a replacement for them.

## Prior limited-beta evidence

The [remediation gate](BETA_REMEDIATION.md) is closed for limited single-operator
beta testing on runtime revision `82ee7d5`. Reviewed lab evidence and the targeted
API retest support the core fixes, including unknown-risk projection. This is not
enterprise sign-off. Conservative nondisclosure reporting does not establish
representative detection sensitivity. The subsequent server evidence-reference
slice adds supported system-prompt canary profiles, separate from API score
correctness; direct modification of stored reports is not a supported workflow.
Other server authorization evidence inputs and enterprise secret management
remain outside this slice.

The bounded prompt benchmark now has a reviewed target-specific lab comparison:
the experimental extraction-focused suite observes disclosure in 10/10 completed
runs versus 2/10 for the unchanged production sample, at equal 35-request budgets.
This is one operator-attested vulnerable target, not general sensitivity. The
supported server canary input also has real-server lab evidence without report
edits. The harness retains one incorrect assertion, and missing capture bodies
limit acceptance; see [reviewed qualifications](VALIDATION.md#supported-server-canary-and-paired-prompt-retest).
The next accuracy priority is independent frozen multi-model replication with
explicit controls and target provenance before candidate adoption. Production
defaults remain unchanged. PR #51 addresses O1/O2/O4/O5/O6 without changing evidence
verdicts or claiming stronger detection.

The offline cohort gate supports that replication without executing targets. It
requires predeclared positive/negative controls and at least two declared model
identities, validates current paired-report ledgers, and preserves missing,
invalid, partial, and failed-control cases with nonzero exit. Its private summary
does not pool targets or promote a candidate. Plan timing, model identity, canary
placement, and state/reset policy remain operator assertions, not verified facts.
See [the protocol](BETA_TESTING.md#offline-multi-model-evidence-gate).
The supplied `4070eed` cohort now passes independent offline replay: both controls
meet expectations, and each declared model completes ten balanced-order pairs.
Candidate observes disclosure in 10/10 runs on each target versus baseline 5/10
and 1/10 at equal request budgets. This accepts per-target observations and
accounting, not general sensitivity, backend independence, or candidate promotion.
State, provenance, setup failures, incomplete audit captures, and privacy limits
remain explicit in [the reviewed retest](VALIDATION.md#frozen-paired-cohort-retest).
A separately reviewed opt-in normal-scan workflow is the next product decision;
production defaults remain unchanged.
The shared-catalog foundation now exposes explicit Python constructor selection
with strict protected-evidence prerequisites, isolated catalogs, unchanged probe
hashes, and an order-sensitive public catalog digest. CLI/API and saved-definition
integration have separate acceptance below; this foundation does not change normal
operator defaults or establish additional model accuracy.
The normal-scan integration adds exact opt-in CLI/API selection, protected profile
coverage, private catalog pins, per-scan engine isolation, and saved-template /
schedule revalidation. Existing scans remain unchanged when the field is omitted.
No benchmark checkpoint or heuristic can become fabricated finding evidence.
The next external checkpoint validates these actual operator paths at the final
merged revision, not general accuracy or enterprise readiness.
The supplied `ae1ba9b` retest now supports those normal CLI/server paths with
independent artifact review and no new product blocker. Confirmed controls and
both declared real targets retain 70/high; refusing and unseeded controls stay
null. Complete inventory/filter/history documents survive restart, but missing
per-scan restart/template/refusal/source captures and incomplete driver provenance
prevent claiming the full external checklist. See the
[qualified workflow acceptance](VALIDATION.md#normal-cli-and-server-experimental-suite-retest).
This is not another accuracy cohort or default-promotion decision. Documentation
acceptance needs no new cloud run; enterprise validation remains separate.
The dashboard now groups compatible prompt occurrences for display only, with
original records available in bounded details. Raw findings, scores, exports,
and lifecycle IDs remain unchanged.
Keep raw database unknown-score migration separate; new consumers must use saved
pipeline verdicts and canonical projections rather than treating placeholder
zeros as assessments. No enterprise readiness claim follows from these slices.

Build a defensible AI asset inventory and security assessment tool for security
engineers. Preserve local CLI use and add a reliable single-operator server.
Enterprise identity, distributed execution, and additional attack surfaces follow
the core correctness work. Prefer incremental replacement to a wholesale rewrite.

## Delivery rules

- Use short branches, frequent scoped commits, and pull requests.
- An independent agent reviews each implementation before merge.
- Merge only after review findings are resolved and required checks pass.
- Keep review comments brief, specific, and tied to the diff or test evidence.
- GitHub cannot accept an author's approval of their own PR. Record the independent
  review as a comment when the author and reviewer share one GitHub account.
- Verify global, local, and effective Git identities and every remote before each
  commit, push, and PR mutation. Use the perfecXion account for this repository.
- Never include Unicode em dash or en dash characters in new text.
- Do not publish a package or deploy a service as part of a PR merge.

## Evaluation at 4115546

The repository has 33 Python files and 88 test functions. Discovery, security,
risk, compliance, and reporting have useful module boundaries. The current test
suite concentrates on security heuristics and framework mappings. Discovery,
API authorization, persistence, packaging, and deployed behavior need regression
coverage. Documentation overstates both test count and security guarantees.

Priority defects found by three independent reviews:

1. Anonymous callers can mint tokens for arbitrary users and organizations.
2. Scan result and status routes do not enforce organization ownership.
3. Web scans discard security and risk output; repeat discoveries reuse row IDs.
4. Security-only mode has no source of assets to test.
5. Broad keyword matches confuse refusals, generated examples, and successful
   HTTP responses with proven vulnerabilities.
6. The wheel does not explicitly include the module used by its console script.
7. Scans use unbounded daemon threads and process-local state.
8. Discovery conflates assets without endpoints and over-identifies generic APIs.
9. Outbound requests and local file sources lack a shared scope policy.
10. Dependency declarations drift, and CI ignores dependency audit failures.

These are source-review findings, not evidence of exploitation in a deployment.

## Historical milestones and acceptance

M1 through M6 record the original build-out. R1 through R4 above govern the next
delivery sequence. Implemented subsets and their limits remain recorded below;
the strategic review does not retroactively expand any acceptance claim.

| Milestone | Work | Acceptance |
| --- | --- | --- |
| M1: Stabilization | Auth, tenant isolation, wheel, CI, persisted results, conservative evidence, discovery correctness | Regression tests reproduce original failures; wheel works outside source tree; isolated fixture scans pass |
| M2: Core contracts | Typed scan, asset, finding and evidence records; shared CLI/API pipeline; versioned probes and reports; scope and transport policy | CLI and API agree on results; every active request is bounded and scoped; errors remain distinct from clean results |
| M3: Execution | Durable jobs, cancellation, deadlines, bounded concurrency, migrations, readiness and audit events | Restart/retry/cancel tests; no lost findings; documented SQLite and PostgreSQL limits |
| M4: Coverage | MCP configuration and tool analysis, indirect injection, RAG canaries, output sinks, agency and supply-chain checks; passive infrastructure discovery | Positive and negative fixtures per rule; measured precision/recall; explicit supported protocols and skipped tests |
| M5: Workflows | Inventory changes, finding suppression and lifecycle, report exports, templates, scheduling and integrations | End-to-end operator flows; tenant-scoped changes and exports; accessible UI |
| M6: Release candidate | Performance, security review, deployment and upgrade docs, package/container verification | Reproducible release checks; known limitations recorded; no unreviewed critical defects |

## Architecture decisions

- Keep Python and Flask initially; isolate orchestration from HTTP routes.
- A discovery observation is not a confirmed asset vulnerability.
- A failed or unsupported probe cannot count as a passed security test.
- Require an explicit oracle or protected canary for claims of exploitation.
- Store scan snapshots separately from stable asset identity.
- Treat framework references as review mappings, never compliance certification.
- Keep single-operator credentials server-side and do not accept tenant identity
  from a login request. OIDC is a separate deployment capability.
- Add durable execution behind a shared runner contract; retain a local CLI mode.
- Use local fixtures and synthetic data for tests; external paid targets require
  configured credentials and a request budget.

## Progress

- The 2026-10-22 review establishes the active R1 through R4 roadmap. R1.1 is
  merged with local, independent, and all eight PR/post-merge checks passing.
  R1.2 remains open. Completed-check persistence is merged in PR #65 with local,
  independent, and all eight PR/post-merge gates passing. In-progress confirmation
  recovery requires a separate contract. Historical protected-access eligibility
  is merged in PR #66 with all local, independent, and PR/post-merge CI gates passed.
  The prompt-only within-check evidence slice passes 3,216 local coverage tests and 793
  overlapping independent cases; required CI results are recorded on PR #67. Tenant/access
  and CLI crash-file gates remain separate. See
  [review evidence](VALIDATION.md#strategic-review-and-revised-roadmap) and
  [local control acceptance](VALIDATION.md#protected-access-positive-control-local-acceptance),
  [checkpoint acceptance](VALIDATION.md#finalized-check-checkpoint-local-acceptance),
  [compatibility acceptance](VALIDATION.md#historical-protected-access-compatibility-follow-up),
  and [prompt receipt acceptance](VALIDATION.md#within-check-prompt-receipt-local-acceptance).
- Historical prompt eligibility now requires source-2.0 receipts for current
  versioned assessments without rewriting archives or resolving old findings.
  Local acceptance passes 3,281 coverage tests and 1,170 overlapping independent
  cases; see [acceptance](VALIDATION.md#historical-prompt-eligibility-follow-up).
  PR #68 and merged revision `a8ea520` pass all eight CI jobs. Tenant provenance
  controls and historical eligibility pass 3,515 local coverage tests and 247
  overlapping independent review cases; see
  [acceptance](VALIDATION.md#controlled-tenant-evidence-local-acceptance). PR #69
  merged as `1072d8b` with all eight PR/post-merge jobs passing. The supplied
  tenant CLI/TLS retest closes its scoped workflow gate with
  [recorded qualifications](VALIDATION.md#supplied-tenant-workflow-acceptance).
  Nullable score storage passes 3,763 local coverage tests and 279 overlapping
  independent Python 3.13 cases, including current prompt/tenant HTTP proofs,
  transactional rollback and both ten-case backup modes. The delivery PR records required CI;
  the scoped native-server upgrade retest remains the external gate. Real-model
  sensitivity remains open.
- Evaluation completed by architecture, security, and delivery reviewers.
- M1 has implemented operator authentication, scan ownership, package/CI repairs,
  persisted results, conservative evidence checks, and initial discovery fixes.
  Integration review and release validation continue; this is not a production
  readiness declaration.
- M2 has a shared CLI/API pipeline, typed scan/asset/finding/evidence contracts,
  versioned result snapshots and check records, bounded transport, and server
  scope enforcement. Nineteen probe groups record execution and evidence
  outcomes. New risk assessment requires matching confirmed check/finding evidence
  or a completed protected-access sampled pass; confirmed partial execution retains
  its observed risk with a coverage warning. Prompt/tenant nondisclosure cannot pass;
  exact versioned evidence is required for verified finding resolution. This
  accounts for implemented sampled groups, not every possible attack surface.
- M3 has a durable SQLite queue, exclusive startup recovery, bounded workers,
  cooperative cancellation, deadlines, and readiness checks. Race and restart
  tests pass. Known SQLite schema upgrades and transactional tenant audit history
  have acceptance tests. A bounded local synthetic load workload verifies unique
  claims, worker limits, terminal consistency, and audit records. PostgreSQL/distributed coordination and a general
  migration framework remain outside the supported deployment boundary.
  Disposable stopped-SQLite backup/restore acceptance now preserves exact schema
  1/2/3 contents before upgrade, retained evidence, and one-time queued execution.
  It rejects incomplete copies, failed/future upgrades, and competing ownership;
  enabled schedules pause for review and a second restart is idempotent.
  This is synthetic local acceptance, not deployed backup or crash durability.
- M4 has passive MCP configuration/schema checks and offline replay for indirect
  markers, RAG tenant canaries, and tool authorization requests. Replay ruleset
  1.1.0 closes a reproduced exact-canary disclosure miss in argument property names,
  with numeric secret-safe locations and nested positive/negative regressions.
  Encoded disclosures remain known misses, not security passes. A scoped CLI
  adapter collects read-only MCP 2026-07-28 Streamable HTTP inventory with bounded
  JSON/SSE and schema analysis. Inventory does not test runtime authorization,
  Origin enforcement, tool behavior, or exploitability. A separate controlled
  CLI checks declared protected inventory authorization and Origin boundaries
  only after an authenticated canary baseline. Its fixture provenance is operator
  declared; it does not invoke tools or establish browser exploitation. These fixtures
  do not establish live attack coverage. Broader live integrations, output sinks,
  supply-chain checks, and representative accuracy benchmarks remain pending.
- M5 has scoped history and exports, a redesigned dashboard, source model
  selection, inventory/finding comparison, expiring suppressions, check evidence,
  and paginated operational audit history. Tenant-owned API templates use shared
  admission, revision checks, bounded quota, and current-policy/source revalidation.
  Manual dashboard template workflows have Node and real browser acceptance.
  Finite API schedules pin template revisions, start disabled, require restart
  review, and atomically admit bounded occurrences through the shared queue.
  One-slot read-only preflight preserves cancellation and rejects late results.
  Scheduling originally upgraded exact version 1/2 SQLite layouts to version 3;
  current startup follows with the schema-4 nullable-score migration. Schedule
  dashboard controls have independent controller, browser, and targeted keyboard
  acceptance. Explicit review gates creation and enablement; loading never enables.
  Focused accessibility acceptance now covers control contrast, linked guidance,
  named scroll regions, focus ownership, terminal feedback, and stale report notices.
  An optional synthetic Chromium harness and mandatory isolation/cleanup tests
  make those regressions reproducible without contacting real targets.
  External integrations and comprehensive accessibility acceptance remain pending.
- M6 remains pending. Package and container CI are foundations, not completion of
  performance testing, deployment review, migration validation, or release sign-off.
  A finite [local-beta gate](BETA_TESTING.md) adds actual offline operator
  workflow acceptance, authenticated container restart checks, repeated bounded
  queue runs, and isolated setup instructions. External lab feedback exposed gaps
  beyond that infrastructure gate. The [remediation gate](BETA_REMEDIATION.md)
  records reviewed verdict/privacy fixes, mixed-network/source/CLI regressions,
  native macOS acceptance, and exact-revision API projection retesting. Its
  limited-beta acceptance retains explicit fixture and accuracy qualifications.
  This does not complete M6 or the deferred enterprise-readiness roadmap.

Discovery now has bounded traffic-format and mocked cloud SDK acceptance,
resource-specific cloud identity, typed read-only network inventories, and
explicit incomplete-source status. DNS/TCP work and JSON nesting are bounded;
shared protocol responses do not identify vendor ownership, and unknown hostname
exposure is not labeled internet-facing. Real
provider accounts and representative capture corpora still need validation.
CI actions are pinned and uploaded distributions are downloaded and compared.
