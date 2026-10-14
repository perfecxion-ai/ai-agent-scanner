# Read-only live MCP inventory

`mcp-live` collects public tool schemas from an already-running MCP server. It
supports MCP protocol `2026-07-28` over Streamable HTTP only. The existing `mcp`
command remains passive: it does not connect to servers or launch processes.

```bash
ai-agent-scanner mcp-live \
  --endpoint http://127.0.0.1:8000/mcp \
  --allow-network 127.0.0.1/32 \
  --allow-loopback \
  --output mcp-inventory.json
```

Use an explicitly authorized lab endpoint. `--allow-network` is required and
repeatable. Loopback additionally requires `--allow-loopback`. Non-loopback
endpoints require HTTPS. Hostnames must resolve entirely within the allowlist;
both DNS preflight and connection-time validation enforce scope. Plaintext
connections must remain loopback even if DNS changes. Metadata, link-local,
multicast and reserved destinations remain forbidden. Redirects and environment
proxies are disabled. Endpoint credentials, query strings and fragments are
rejected. A literal loopback address avoids mixed IPv4/IPv6 hostname ambiguity.

For an already-issued bearer token, provide its environment variable name with
`--api-key-env MCP_ACCESS_TOKEN`. The value must be a nonempty visible ASCII token
without spaces or control characters, at most 8192 characters. Missing or unsafe
values fail before HTTP requests. The scanner sends Authorization on every request,
ignores Set-Cookie and protocol session headers, and does not acquire OAuth tokens.
Do not put token values on the command line or in endpoint URLs.

## Supported protocol behavior

The scanner sends `server/discover`, validates advertised version/capabilities,
then paginates `tools/list` only when the server advertises tools. Each POST has
matching protocol metadata and HTTP headers. JSON and bounded request-scoped SSE
responses are supported, including LF, CRLF and CR framing, UTF-8 BOM, comments,
and discarded progress/log notifications. Every decoded JSON message has a
64-container nesting limit, including ignored metadata and notifications. Each
result must match its request ID.
Duplicate keys, nonfinite numbers, batches, server requests, malformed envelopes,
unknown result types, and input-required results are rejected. An absent
`resultType` is interpreted as complete, as required for compatibility by the
current base protocol.

There is no initialization handshake, protocol session, GET fallback, legacy
transport support, stream resumption or automatic retry. Older MCP servers need
the passive command or a separately implemented versioned adapter.

Tool input/output schemas receive bounded JSON Schema 2020-12 syntax validation.
Unsupported dialects fail explicitly. Schema references are not resolved, and
schemas are not used to invoke tools or evaluate arguments. Header annotations
receive conservative syntax/reachability checks. This does not establish full
MCP interoperability or safe tool behavior.

Input analysis currently requires an explicit `type: object` root, matching the
passive analyzer. Otherwise-valid missing-type, union-type or composition-only
input schemas are outside this supported subset and produce an explicit
unsupported-root reason and incomplete inventory, not a security pass or an
invalid-schema claim. Output schemas support any valid object-form 2020-12
schema, including array and primitive output types.

## Limits and result meaning

Hard work caps are 32 requests, 1 MiB per response, 4 MiB total response data,
10 inventory pages, 200 tools, 4 KiB per cursor, 256 data-bearing SSE events per
response, schema depth 32, schema field names of at most 256 UTF-8 bytes, and
10,000 schema nodes across the collected inventory. Field-name bounds also
prevent long shared prefixes from amplifying report pointers.
Cursors remain opaque; an empty string is valid. Repeated cursors stop collection.
Responses and SSE notifications count toward byte budgets.

The asynchronous deadline is 20 seconds overall, including DNS and parsing/schema
tasks, with 5 seconds per HTTP request. Cancellation closes active HTTP responses.
DNS and bounded validation execute off the event loop. Python thread shutdown may
wait for already-started work to finish; these deadlines are not a hard process
wall-clock or CPU guarantee. Timed-out schema work cannot alter a returned report.

Reports distinguish completed collection, failed collection, and partial results.
Validated earlier pages survive later failures. Missing tools capability is an
explicit skipped prerequisite. Completed inventory is recorded as inconclusive
security evidence; risk remains unassessed. Authorization, Origin enforcement,
and tool-execution checks are skipped, not passed. Open command/path/URL schema
parameters remain heuristic observations, not confirmed vulnerabilities.

Reports never retain raw schemas, tool names/descriptions, server instructions,
cursors, session headers, tokens, or server error messages. Configured credentials
are removed even if echoed into schema pointers, and observation IDs derive from
the sanitized pointers. No commands, tools, resource reads, subscriptions, icons,
external references, authentication metadata or secondary destinations are fetched.

JSON is the default format; `--format sarif` retains live mode, version, check
outcomes and limitations. Failed or partial collection writes the available report
and exits nonzero. Successful collection and skipped tools capability exit zero;
neither means that runtime security passed.

## Protocol references and acceptance

This intentionally narrow client follows the current official
[Streamable HTTP](https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http),
[versioning](https://modelcontextprotocol.io/specification/2026-07-28/basic/versioning),
[discovery](https://modelcontextprotocol.io/specification/2026-07-28/server/discover),
[base protocol](https://modelcontextprotocol.io/specification/2026-07-28/basic/index),
[tools](https://modelcontextprotocol.io/specification/2026-07-28/server/tools), and
[pagination](https://modelcontextprotocol.io/specification/2026-07-28/server/utilities/pagination)
contracts. JSON Schema syntax uses the bundled metaschemas in
[jsonschema](https://python-jsonschema.readthedocs.io/en/stable/validate/).

`tests/test_mcp_live.py` uses real loopback HTTP/SSE fixtures and synthetic tokens.
It covers protocol success, malformed/adversarial responses, partial pagination,
scope and DNS changes, credential echo, cookies, redirects, byte/work caps,
timeouts, and unchanged snapshots after cancelled validation. These tests do not
establish compatibility with external servers or exercise protected tool actions.
