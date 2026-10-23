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
| R1.1 | Generic authentication checks accept denied requests without a successful authorized resource baseline | Always-denied, unseeded, unavailable, and stale-credential controls cannot pass or resolve findings; valid positive/negative controls permit only bounded sampled claims; changed evidence semantics are versioned and private | Merged in PR #64; local, independent, and all eight PR/post-merge CI gates passed |
| R1.2 | Outer deadlines can discard findings produced before a later stage stalls | Sanitized check/asset checkpoints survive later timeout, cancellation, and process recovery; terminal writes are transactional; unfinished checks remain incomplete; no active probe replay | Completed-check persistence merged in PR #65 with all gates passed. Prompt-only within-check receipts pass local acceptance and focused review; PR/CI pending. Tenant/access receipts and CLI crash recovery remain separate gates |
| R1.3 | Database score columns retain unknown as `0.0`; historical authentication evidence also needs current eligibility guards | Shared canonical eligibility rejects unsupported historical control semantics without rewriting reports; versioned migration preserves legitimate assessed zero, rejects unsupported layouts, and passes rollback plus backup/restore fixtures | Historical-evidence prerequisite merged in PR #66 with all local, independent, and PR/post-merge CI gates passed. Migration follows |
| R1.4 | Risk filtering considers only the newest 100 inventory records | Stable asset identity is separate from observations; indexed filters and cursor pagination are exhaustive and tenant-scoped; a 10,000-observation synthetic fixture has no missing/duplicate pages | Planned |
| R1.5 | Main is far beyond the public release but still identifies itself as `1.1.0` | Release/development identity includes reproducible source and catalog provenance; artifacts have tested install/upgrade paths, checksums, and an SBOM; publication remains separately authorized | Planned |
| R2.1 | Hardwired testers and provider formats limit application coverage | Versioned target, scenario, evidence-evaluator, and shared-budget contracts support a custom HTTP/session adapter; a reference extension needs no route or orchestrator edits | Planned |
| R2.2 | Advanced model/evidence/suite setup depends on manual identifiers and JSON | Guided discovery-to-assessment flow and CLI setup/diagnostics/preview expose ready, unsupported, missing, and inapplicable prerequisites; secret references never become ordinary saved values | Planned |
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
Actual legacy reports and standalone benchmark execution retain their old contract.
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
Include the unchanged prompt detector in the follow-up audit for protected-marker
reflection from non-prompt request material; its current receipts prove observed
matches, not independent target-side seeding.

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
  The prompt-only within-check evidence slice passes 3,081 local tests and 762
  overlapping independent cases; PR/CI acceptance remains pending. Tenant/access
  and CLI crash-file gates remain separate. See
  [review evidence](VALIDATION.md#strategic-review-and-revised-roadmap) and
  [local control acceptance](VALIDATION.md#protected-access-positive-control-local-acceptance),
  [checkpoint acceptance](VALIDATION.md#finalized-check-checkpoint-local-acceptance),
  [compatibility acceptance](VALIDATION.md#historical-protected-access-compatibility-follow-up),
  and [prompt receipt acceptance](VALIDATION.md#within-check-prompt-receipt-local-acceptance).
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
  Exact version 1/2 SQLite upgrades initialize schema version 3. Schedule
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
