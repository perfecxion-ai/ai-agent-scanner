# Engineering plan

## Product direction

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

## Milestones and acceptance

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
