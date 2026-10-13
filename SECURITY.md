# Security policy

AI Agent Scanner is a defensive assessment tool for systems within your authorized
scope. Active probes send adversarial prompts and authentication attempts and can
consume target resources. The scanner does not guarantee that a target agent will
avoid side effects when processing those requests. Use isolated fixtures and
synthetic secrets when testing agent behavior.

## Deployment boundary

The web application supports one configured operator and organization. It does
not provide SSO, user enrollment, granular roles, or enterprise tenant provisioning.
Set independent random `SECRET_KEY` and `OPERATOR_API_KEY` values. An unset
operator key disables token issuance and protected API access. Use TLS and an
access-controlled proxy for remote access; enforce login throttling there.

JWTs expire after one hour. Signing out clears the browser's copy but does not
revoke a copied token. Rotating `SECRET_KEY` invalidates existing tokens.
Rotating only the operator key prevents subsequent login with the old key.
See [authentication details](docs/authentication.md).

API targets are denied by default. Configure authorized network ranges and trusted
filesystem roots. Loopback additionally requires explicit opt-in. Cloud discovery
through the API is disabled. Connection-time policy rejects out-of-scope resolved
addresses, redirects are disabled, and requests and response bodies are bounded.
Filesystem preflight is not a sandbox: allowed roots must not be concurrently
modified by untrusted users. See [scan policy and limits](docs/scan-policy.md).

Keep one server process using file-backed SQLite on a local POSIX filesystem.
Exclusive dispatcher ownership protects startup recovery; overlapping reloads
are unsupported. Queued jobs resume after restart, but active jobs become
interrupted without replaying probes. Cancellation and deadlines are cooperative:
synchronous operations must return before they take effect. General database
migrations and distributed execution are not implemented. See [job lifecycle](docs/jobs.md).

## Data handling and evidence

JSON/SARIF exports remove recognized credential fields and credential-bearing URL
components. Issued cookie values are not included in cookie findings. Redaction
does not guarantee removal of arbitrary sensitive data in model output, source
files, or unfamiliar credential formats. Treat reports and the database as
sensitive. Enforce encryption, backups, access restrictions, and retention in
your deployment; the application does not supply a general encryption-at-rest,
automated retention, or immutable audit-log feature.

Heuristic observations are separated from confirmed findings. Request failures
and incomplete phases must not be interpreted as passed tests. Canaries require
operator-controlled provenance. Same-session recall is not a retention violation,
and framework mappings do not certify regulatory compliance.

MCP configuration review and transcript evaluation are offline operations. They
do not start configured commands, connect to servers, fetch schemas, or execute
tool calls. Their results describe supplied configuration or fixtures only.

## Reporting a vulnerability

Send security reports to **scott@perfecxion.ai**. Include the affected commit or
version, a minimal reproduction, expected and observed behavior, and impact.
Use synthetic credentials and remove customer data. Coordinate privately before
publishing exploit details. Response times depend on maintainer availability;
there is no guaranteed response SLA.

There is no published long-term support matrix. Review the current source,
changelog, dependency audit, and open advisories before deploying a version.
