# Changelog

## Unreleased

These changes are engineering work on the current branch, not a published release.

### Security and correctness

- Require configured operator authentication and scope scan access to its organization.
- Add server-owned network and filesystem boundaries, bounded admission, scan
  deadlines, connection-time address checks, and request/response budgets.
- Replace keyword-only vulnerability claims with conservative evidence requirements.
  Separate heuristic observations from confirmed findings and preserve incomplete status.
- Remove retention claims based solely on conversational recall.
- Redact recognized credentials in nested reports and omit issued cookie values.
- Persist a bounded SQLite job queue with exclusive recovery, cooperative cancellation,
  current-policy revalidation, and readiness checks.
- Upgrade recognized SQLite layouts transactionally and reject unknown schemas
  before writes; persist tenant-owned state-transition audit history.
- Bound traffic and cloud inventory work, preserve resource identities, and keep
  source failures distinct from successful empty discovery.
- Replace weak network signatures with typed read-only inventories, canonical
  hostname identity, bounded DNS/TCP/JSON work, and unknown hostname exposure.
- Count HTTP request/body timeouts consistently across supported Python versions.

### Results and interfaces

- Persist versioned scan snapshots, findings, and risk results; keep repeated
  discoveries separate and support organization-scoped JSON/SARIF exports.
- Share a scan pipeline between CLI and API; support explicit agent configuration
  and security-only runs from eligible source scans.
- Add passive local MCP configuration and tool-schema assessment with versioned rules.
- Add scoped read-only live MCP inventory with bounded JSON/SSE pagination and
  schema analysis, secret-safe reports, explicit skipped runtime-security checks,
  and accurate incomplete SARIF execution status.
- Add controlled protected MCP inventory checks with explicit local policy,
  authenticated fixture baselines, isolated credential/Origin controls, shared
  budgets, and conservative JSON/SARIF evidence. No tools are invoked.
- Add offline replay fixtures for indirect markers, foreign-tenant document
  canaries, and tool-request policies, with labeled confusion and accuracy metrics.
- Add explicit model/protocol adapters, tenant-owned scan history, and source model selection.
- Redesign the operator dashboard with local assets, cancellation, and authenticated exports.
- Compare saved reports and apply exact-match expiring suppressions without changing evidence.
- Record versioned execution and evidence outcomes for existing probe groups;
  require conclusive check evidence for new risk assessments and exact passed
  provenance for verified resolution.
- Show check evidence, cloud resource IDs, and bounded audit history in the dashboard.
- Add tenant-owned API scan templates with revision checks, bounded quotas,
  shared admission, and current-policy revalidation. Preserve queued snapshots
  after recipe edits or deletion; upgrade exact SQLite version 1 layouts to 2.

### Delivery and documentation

- Include the CLI entry point in distributions and test installed wheels outside
  the source checkout.
- Gate publication on CI, including tests, lint, package checks, dependency audit,
  and container smoke checks.
- Document current boundaries and remove unsupported claims of complete framework
  coverage, enterprise controls, and production security guarantees.
- Pin CI actions and verify uploaded distribution contents after downloading them.
- Add disposable SQLite queue-load acceptance with deterministic state and audit invariants.
- Verify the installed live MCP command and its lazily loaded implementation.

### Still incomplete

- Comprehensive migrations, PostgreSQL coordination, and distributed workers.
- Enterprise identity, scheduling, external integrations, and audit guarantees.
- Live coverage of all MCP, indirect injection, RAG, multimodal, and supply-chain scenarios.
- Representative accuracy and performance benchmarks and release-candidate acceptance.

See [engineering milestones](docs/ENGINEERING_PLAN.md) for acceptance criteria.
