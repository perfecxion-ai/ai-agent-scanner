# Engineering validation checkpoint

Date: 2026-10-13. This records the beta build-out, not a release certification.
The integrated application under review is in PR #13; operating guidance and
expanded delivery checks are in PR #14. Neither merge publishes a package.

## Automated checks

- Local Linux/Python 3.10.20: 422 pytest cases passed. The suite invokes 11 Node
  controller tests, which also passed independently.
- Line coverage across `src`, `app`, and `scanner_cli`: 78%. The shared pipeline
  is 96%, transport 95%, durable jobs 91%, and API 90%. This measures executed
  source lines, not attack coverage or security effectiveness.
- Ruff and the configured medium/high-severity Bandit gate pass, including API
  source. Lower-severity static findings still require contextual review.
- Real loopback HTTP fixtures exercise provider request formats, rejected probes,
  canary disclosure versus refusal, and credential removal from JSON/SARIF output.
- Real SQLite transactions exercise competing claims, cancellation/finalization
  races, restart recovery, and exclusive dispatcher ownership.
- Distribution build, metadata validation, isolated installed-wheel commands,
  and offline evaluation smoke pass outside the checkout.
- Container build, readiness, and readiness after restart pass.

CI repeats tests and wheel checks on Python 3.10 through 3.13, audits installed
dependencies including cloud/server extras, runs lint/source security checks,
and builds and starts the container. Check each PR's latest run for its exact
commit and dependency resolution; this document is not a substitute for CI.

## Browser verification

Chromium was exercised against a loopback Flask server with real authentication,
SQLite queue, history, cancellation, and export routes. Discovery and security
phases used synthetic fixtures; no external target was scanned.

The workflow covers invalid/valid login, memory-only session state, discovery,
source model selection, separate findings/observations, unassessed risk, history,
JSON/SARIF downloads, cancellation, missing scans, and logout. Desktop 1440-pixel
and mobile 390-pixel layouts were visually inspected without horizontal overflow.
The native fetch receiver failure found in this test now has a regression test.

## Remaining validation gaps

- Cloud discovery and traffic parsing have low line coverage (10% and 16% at this
  checkpoint). Real provider SDK and capture-format integration remains incomplete.
- Provider fixtures do not establish compatibility with every live model or
  account configuration. No paid provider calls were made.
- Replay metrics describe synthetic or supplied labels, not representative
  production precision/recall. Passive MCP checks do not execute tools.
- PostgreSQL, distributed workers, network-filesystem locking, and overlapping
  server reloads are unsupported, not validated deployment options.
- Load/soak benchmarks, comprehensive accessibility evaluation, upgrade migrations,
  enterprise identity, and tamper-resistant audit acceptance remain pending.

See [engineering milestones](ENGINEERING_PLAN.md), [development checks](DEVELOPMENT.md),
and [persistent job constraints](jobs.md).
