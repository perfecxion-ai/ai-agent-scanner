# Passive MCP assessment

```bash
ai-agent-scanner mcp --config client-config.json --output mcp-report.json
ai-agent-scanner mcp --tools saved-tools.json --format sarif --output mcp.sarif
```

Either input can be used alone or both together. Output defaults to stdout.
Inputs are local UTF-8 JSON files up to 2 MiB. Invalid JSON, duplicate keys,
unsupported input shapes, and malformed known fields produce an error and a
nonzero exit. Configuration findings do not change the command exit status.

Configuration accepts a `mcpServers` object or a `servers` object mapping server
names to entries. An entry needs a string `command` or HTTP(S) `url`; supported
optional fields are `args` (string array), `env` and `headers` (string maps), and
`host`, `bind`, or `listen` (strings). These client configuration conventions are
not themselves the MCP wire protocol. Other client-specific fields are ignored.

Tool inventory accepts `{"tools": [...]}` or a saved JSON-RPC response with
`{"result": {"tools": [...]}}`. Each tool requires `name` and an `inputSchema`
declaring object type. Tool descriptions and annotations are never instructions.

Ruleset `1.0.0` contains:

| Rule | Evidence |
| --- | --- |
| MCP001 | Wildcard address in URL, bind field, or recognized launch argument. Configured address only; no live listener inferred. |
| MCP002 | HTTP URL outside literal loopback addresses and `localhost`. Private-network addresses still require transport protection. |
| MCP003 | Literal value in credential-shaped env/header/argument fields or URL userinfo/query. No values copied into reports. |
| MCP004 | Direct shell interpreter launch, reported as an observation. |
| MCP005 | Recognized automatic confirmation flag, reported as an observation because meaning varies by executable. |
| MCP006 | Command, path, or URL string parameter lacking `enum` or `const`, reported as an observation. |

`${NAME}`, `$NAME`, and `%NAME%` are treated as secret references in recognized
credential fields. References are never expanded. Embedded credentials in arbitrary
shell scripts, unfamiliar key names, or unrecognized formats may not be detected.
Reports contain JSON pointers to evidence, not raw configuration values or tool
descriptions. SARIF retains evidence status and ruleset version in properties.

No processes are started, URLs fetched, hosts resolved, or MCP tools invoked.
This is a configuration review, not an exploitation test. Loopback HTTP is not
flagged as remote plaintext, but authentication and Origin protections still
matter. No conclusion is made about live authorization, DNS rebinding protection,
tenant boundaries, sandboxing, package integrity, or tool implementation behavior.
Tool schema references are not resolved; only visible properties, array items,
and composition branches are examined, to a maximum nesting depth of 32.
Pattern and format constraints are not equivalent to operation or destination
allowlists. An unrestricted schema is not proof that runtime validation is absent.

The rules use the versioned MCP transport and tool specifications as reference,
not a claim of full protocol compliance. The transport specification recommends
loopback binding for local servers and requires Origin validation. The tool
specification describes input schemas and treats tool metadata as untrusted.
Sources: [MCP transports, 2025-11-25](https://modelcontextprotocol.io/specification/2025-11-25/basic/transports),
[MCP tools, 2025-11-25](https://modelcontextprotocol.io/specification/2025-11-25/server/tools).
