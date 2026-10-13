# Engineering plan

## Product direction

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
- M2 has a shared CLI/API pipeline, versioned result snapshots, bounded transport,
  and server scope enforcement. Uniform typed domain contracts and full probe
  coverage accounting remain incomplete.
- M3 has a durable SQLite queue, exclusive startup recovery, bounded workers,
  cooperative cancellation, deadlines, and readiness checks. Race and restart
  tests pass. PostgreSQL/distributed coordination, comprehensive migrations,
  and audit acceptance remain pending.
- M4 has passive MCP configuration/schema checks and offline replay for indirect
  markers, RAG tenant canaries, and tool authorization requests. These fixtures
  do not establish live attack coverage. Broader live integrations, output sinks,
  supply-chain checks, and representative accuracy benchmarks remain pending.
- M5 has scoped history and exports, a redesigned dashboard, source model
  selection, inventory/finding comparison, and expiring suppressions. Scheduling,
  external integrations, and comprehensive accessibility acceptance remain pending.
- M6 remains pending. Package and container CI are foundations, not completion of
  performance testing, deployment review, migration validation, or release sign-off.
