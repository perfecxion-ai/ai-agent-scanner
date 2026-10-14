# Engineering validation checkpoint

Date: 2026-10-13. This records the beta build-out, not a release certification.
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

## Automated checks

- Local Linux/Python 3.10.20: 1026 pytest cases passed. The suite invokes 64 Node
  controller tests, which also passed independently.
- Line coverage across `src`, `app`, and `scanner_cli`: 90%. The shared pipeline
  is 95%, transport 99%, durable jobs 92%, schema acceptance 94%, and API 94%.
  Mocked cloud inventory is 92%, traffic parsing 89%, and network discovery 97%.
  The live MCP client and controlled policy module are each 96%; the small strict
  template projection helper is 100%; the schedule service is 96%. This measures executed
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
- Container build, readiness, and readiness after restart pass.

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
remain the next focused acceptance slice. Screen-reader workflows and comprehensive
accessibility conformance were not evaluated. All fixture servers stopped;
the browser artifacts remain in `/tmp/ai-scanner-schedule-browser-rDbOYW`.

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

## Remaining validation gaps

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

See [engineering milestones](ENGINEERING_PLAN.md), [development checks](DEVELOPMENT.md),
and [persistent job constraints](jobs.md).
