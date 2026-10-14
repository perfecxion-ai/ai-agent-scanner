# Controlled MCP inventory policy checks

`mcp-check` samples declared authorization and Origin controls for protected
tool inventory. It never invokes tools. `mcp-live` remains an inventory-only
command with runtime checks skipped by default.

Use an authorized lab fixture whose `tools/list` inventory contains a randomly
named synthetic protected tool. Its name is a protected canary, not a normal
production tool name or a value the server merely reflects. Supply the name and
an already-issued authorized bearer credential through environment variables.
Do not include either value in the policy, command line, endpoint, or report.

## Trusted local policy

```json
{
  "version": 1,
  "endpoint": "http://127.0.0.1:8000/mcp",
  "evidence_context_id": "lab-fixture-policy-v1",
  "fixture_provenance": "operator_protected_tool",
  "protected_tool_name_env": "MCP_FIXTURE_TOOL",
  "authorization_required": true,
  "origins": {
    "allowed": "https://trusted.example",
    "denied": "https://denied.example"
  }
}
```

This declaration is trusted operator input, not independently verified fixture
attestation. Confirm separately that unauthenticated callers and the denied
Origin must not receive this tool metadata. Do not substitute arbitrary public
tool enumeration for protected provenance.

The policy supports exactly these fields. `origins` is optional; when present,
both distinct origins are required. `null`, unknown fields, duplicate JSON keys,
nonfinite values, and files above 64 KiB are rejected. The endpoint must match
`--endpoint` exactly. Context IDs are public, 1 to 128 ASCII characters, beginning
with a letter or digit and otherwise using letters, digits, `.`, `_`, `:`, or `-`.
Never encode credentials or canaries in a context ID. Rotate the context whenever
the protected fixture, principal, or canary changes.

The protected name must be 16 to 128 characters from letters, digits, `.`, `_`,
`~`, `/`, `+`, and `-`. Use a random opaque synthetic name. Credentials retain the
[live client's visible ASCII requirements](mcp-live.md). Values that overlap
request fields, public evidence identities, or fixed report text are rejected
before networking so reflection or redaction cannot fabricate evidence or corrupt
check records. Canonical wire and repeatedly percent-decoded endpoint forms are
checked without changing the endpoint. More than 16 changing percent-decoding
rounds are unsupported.

Origins must be canonical serialized ASCII HTTP(S) origins: scheme, host, and
optional nondefault port only. Paths, userinfo, query, fragment, percent escapes,
uppercase/default-port variants, and trailing slashes are rejected. These strings
are request headers only; the scanner does not contact their hosts.

```bash
ai-agent-scanner mcp-check \
  --endpoint http://127.0.0.1:8000/mcp \
  --allow-network 127.0.0.1/32 \
  --allow-loopback \
  --api-key-env MCP_FIXTURE_BEARER \
  --policy protected-mcp-policy.json \
  --output mcp-policy-report.json
```

Set the referenced environment variables separately using your secret-management
workflow. The output must differ from the policy input, including symlink and
hardlink aliases; this is checked before HTTP requests.

## Probe sequence and evidence

1. Collect a complete current-protocol authorized baseline with the allowed
   Origin, when configured. Discovery must advertise supported tools; all pages
   must validate, and the collected inventory must contain the exact protected
   tool name. Incomplete, rejected,
   or canary-free baselines cannot establish passes and prevent security probes.
2. Repeat the first `tools/list` page with the same body and allowed Origin but
   without Authorization. No other request input changes.
3. If declared, repeat that page with the same authorized credential and body but
   the denied Origin. No other request input changes.

The baseline and each condition use fresh cookie-free sessions, with redirects
and environment proxies disabled. One shared scope policy, request budget,
response-byte budget, and overall deadline cover the whole sequence. Connection
addresses are revalidated. A baseline cursor containing the protected name,
including a percent-encoded representation, is
never sent back; collection stops without running controls. No retry, legacy
negotiation, OAuth flow, alternate URL, resource read, or tool call is attempted.
Cursor values remain opaque strings, not URLs; only bounded percent decoding
checks marker overlap, with more than 16 changing rounds unsupported.

A fully valid matching-ID inventory page returning the exact protected tool
confirms a violation of the declared protected inventory policy. This remains
disclosure evidence even if the HTTP status claims 401 or 403. A malformed page,
an error message echo, or a tool name appearing only in ignored metadata cannot
confirm inventory disclosure.

After a valid protected baseline, a fully consumed empty or strictly valid
JSON-RPC error body without the protected marker in the body or response headers
can establish a sampled denial:
401 or 403 for missing authorization, exactly 403 for denied Origin. Error bodies
may omit the RPC ID; if present, it must exactly match. Arbitrary HTML/text,
malformed errors, oversized or interrupted bodies, mixed result/error envelopes,
and marker echoes never establish a pass. Origin 401 is inconclusive because
authentication failure is not proof of Origin-policy enforcement.

Controls sample only the first inventory page. A successful empty/public page,
missing canary, or pagination cursor is inconclusive, never a pass. Controls do
not follow cursors. One confirmed finding survives a later failed condition.
Passes apply only to these sampled fixture conditions, not all principals,
origins, tool execution, sandboxing, browser exploitability, or DNS rebinding.
Overall risk remains `not_assessed`, and tool execution remains skipped.

## Reports and limits

JSON and `--format sarif` retain check execution/outcome, public context, protocol,
public endpoint, and probe provenance. Probe versions fingerprint only the public
policy definition; canary/credential values, environment references, and their
digests are excluded. Finding IDs derive only from public rule, endpoint, and
context. Reports contain no raw inventory names, schemas, descriptions, cursor,
server error body, token, or canary. Escaped canary/credential forms are removed.
Check contracts are validated again after redaction.

Limits and supported schema/protocol subset match [live inventory](mcp-live.md):
32 requests, 1 MiB per response, 4 MiB total, 10 baseline pages, 200 tools per
inventory, bounded JSON/schema complexity, 5-second requests, and a 20-second
asynchronous deadline. Schema node work is shared across conditions. Thread
shutdown can wait for already-started bounded work, so this is not a hard process
wall-clock or CPU guarantee.

An incomplete check writes the available report and exits nonzero. Completed
collection can still contain inconclusive or skipped checks and exits zero.
Confirmed findings do not by themselves change the exit code. SARIF marks failed
or partial runs unsuccessful, while retaining earlier confirmed findings.

Local loopback fixtures cover positive baselines, real denials/disclosures,
reflection, malformed/partial responses, secret removal, resource limits, and
output aliases. They do not validate real deployments. The current
[Streamable HTTP specification](https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http)
requires 403 for an invalid supplied Origin and permits an error body without an
ID. This client tests the explicit fixture policy, not an automatic compliance
or browser exploitability verdict.
