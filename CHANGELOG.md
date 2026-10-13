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

### Results and interfaces

- Persist versioned scan snapshots, findings, and risk results; keep repeated
  discoveries separate and support organization-scoped JSON/SARIF exports.
- Share a scan pipeline between CLI and API; support explicit agent configuration
  and security-only runs from eligible source scans.
- Add passive local MCP configuration and tool-schema assessment with versioned rules.
- Add offline replay fixtures for indirect markers, foreign-tenant document
  canaries, and tool-request policies, with labeled confusion and accuracy metrics.

### Delivery and documentation

- Include the CLI entry point in distributions and test installed wheels outside
  the source checkout.
- Gate publication on CI, including tests, lint, package checks, dependency audit,
  and container smoke checks.
- Document current boundaries and remove unsupported claims of complete framework
  coverage, enterprise controls, and production security guarantees.

### Still incomplete

- Durable execution, restart recovery, comprehensive migrations, and distributed workers.
- Enterprise identity, complete finding lifecycle workflows, and audit guarantees.
- Live coverage of all MCP, indirect injection, RAG, multimodal, and supply-chain scenarios.
- Representative accuracy and performance benchmarks and release-candidate acceptance.

See [engineering milestones](docs/ENGINEERING_PLAN.md) for acceptance criteria.
