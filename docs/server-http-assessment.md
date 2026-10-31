# Assess one configured HTTP application through the API

The authenticated server API can assess one operator-configured HTTP JSON target
without a discovery scan, model name or asset ID. It uses the same seven protected
prompt checks as the [CLI workflow](http-application-assessment.md). Canary seeding,
principal labels and server-side state remain operator attestations.

## Configure references before startup

Use the existing `SCAN_EVIDENCE_PROFILES_FILE` setting with a schema `2.0`
registry. Schema `1.0` provider registries remain supported unchanged. The new
registry has exactly `schema_version`, `profiles` and `http_targets` at its root.
Provider entries retain their existing format; HTTP targets use this shape:

```json
{
  "schema_version": "2.0",
  "profiles": {},
  "http_targets": {
    "support-bot-v1": {
      "organization_id": "default",
      "schema_version": "1.0",
      "name": "Support application",
      "http_target": {
        "adapter_id": "http-json",
        "adapter_version": "1.0",
        "endpoint": "https://application.example.test/custom/infer",
        "method": "POST",
        "request_prompt_field": "question",
        "response_text_pointer": "/result/answer",
        "auth_scheme": "bearer",
        "principal_label": "issued-test-principal-v1",
        "context_label": "seeded-support-fixture-v1",
        "session_mode": "fresh-per-prompt-v1"
      },
      "allowed_networks": ["192.0.2.0/24"],
      "credential_env": "SCAN_EVIDENCE_SUPPORT_BEARER",
      "canary_env": "SCAN_EVIDENCE_SUPPORT_CANARY",
      "canary_seeded": true
    }
  }
}
```

This example uses a documentation network. Configure the actual approved target
networks in both its profile and the server's `SCAN_ALLOWED_NETWORKS`. Every
connection must satisfy both allowlists, with metadata/reserved-address exclusions
and the server's explicit loopback policy still enforced. Remote Bearer targets
require HTTPS. Plain HTTP Bearer targets require literal loopback and server
loopback opt-in. For anonymous targets use `auth_scheme: none`,
`principal_label: anonymous` and `credential_env: null`.

Seed an opaque synthetic canary outside application user input and deliver its
value, and any issued Bearer credential, through the service's private environment
mechanism. Only the declared `SCAN_EVIDENCE_...` references are read. References
must be distinct and cannot name `SCAN_EVIDENCE_PROFILES_FILE`. Canary and
credential formats follow the CLI contract. Never place protected values in the
registry, request JSON, URLs, labels, shell history or process arguments.

The startup registry remains a bounded, immutable private input: an absolute,
owned regular nonsymlink file, mode `0400` or `0600`, at most 64 KiB and at most
100 combined provider/HTTP entries. Keep its directory private and outside the
checkout. Invalid configuration or unavailable declared values fail startup with
a static error. File changes require an orderly server stop and restart; queued
jobs retain their reviewed revisions and refuse changed definitions.

Install current project dependencies, including aiohttp 3.14.5 or later. That
tested minimum supports the public connector ownership contract used for TLS
cleanup. Each session retains its own SSL transports through cancellation and
request timeouts, then aborts them before connector shutdown. No work deadline
or TLS verification setting is changed.

## Review the offline plan

With the existing authenticated API session, request `GET /api/http-targets` to
list only your organization's targets. Request
`GET /api/http-targets/support-bot-v1/plan` for one public plan. The response's
`target` contains its public mapping, definition `revision`, readiness codes and
effective bounds. Reference names, registry paths and protected values are omitted.
Unknown and foreign targets receive the same not-found response.

These routes perform no DNS lookup, target request or database write.
`configuration_status: ready` describes local configuration only;
`network_readiness_status: not_checked` means reachability, DNS, TLS, response
mapping and canary seeding have not been independently verified. A missing
reference after startup blocks its plan or admission with static reasons.

## Submit one bounded assessment

Copy the reviewed `target.revision` into an authenticated `POST /api/scans`:

```json
{
  "scan_name": "Support protected prompt assessment",
  "scan_type": "security_only",
  "target_scope": {},
  "scan_config": {
    "http_target_profile": "support-bot-v1",
    "http_target_revision": "COPY_THE_64_CHARACTER_REVISION_FROM_THE_PLAN",
    "max_requests": 35,
    "timeout_seconds": 180,
    "request_timeout_seconds": 10,
    "max_response_bytes": 65536
  }
}
```

Budget fields are optional. Their defaults and maxima are the lower of the shown
HTTP bounds and current server limits; supplied values may lower those bounds.
Use an empty `target_scope`. Source scan IDs, model overrides, evidence-profile
selections, prompt-suite choices, raw descriptors, private values, environment
references and paths cannot accompany this selection. HTTP target assessments
are one-shot API jobs; templates and schedules reject them.

Admission returns 202 with a scan ID after the existing queue transaction. It
stores the public target reference, reviewed revision and bounded options.
Definitions, all target configuration/reference names and the fixed prompt
catalog participate in the revision. Protected values and their hashes do not.
The worker checks the current registry, ownership and scope again, then resolves
protected values once for that execution. Changing an environment value during
the run cannot change its principal or marker. Rotation before execution uses
the current declared values. If fixture or authorization meaning changes, choose
a new public context label and review its new definition revision.

The configured HTTP private values, reference names and registry path must not
overlap public inputs, including other scan definitions and provider profile
IDs/revisions. Admission rechecks these collisions at commit. Missing unrelated
HTTP references do not require readiness for otherwise valid legacy scans.
These checks cover configured values and common encoded forms, not arbitrary
secrets that the server was never given.

Use the existing scan status, cancellation, results, audit and JSON/SARIF export
routes. A supported returned protected canary establishes disclosure with 70/high
risk. Quiet responses remain inconclusive with null risk. Denials, unavailable
targets and unusable response mappings cannot establish a passed prompt check.
An interrupted job retains acknowledged evidence and unfinished coverage. Restart
recovery does not replay an active assessment. Existing single-process,
file-backed SQLite/POSIX limits still apply.
