# AI Agent Scanner

Discover AI integrations and assess configured targets with a local CLI or a
single-operator web application. Findings carry evidence; uncertain indicators
remain observations. This project is a beta, not a compliance certification or
a comprehensive test of every AI attack surface.

## Install and try locally

Python 3.10 through 3.13 are supported.

```bash
git clone https://github.com/perfecxion-ai/ai-agent-scanner.git
cd ai-agent-scanner
python -m venv .venv
. .venv/bin/activate
python -m pip install .
ai-agent-scanner --help
```

Run the built-in offline evaluation fixtures without a model or API key:

```bash
ai-agent-scanner evaluate --output fixture-metrics.json
```

To discover an already running local Ollama service, scan only its host:

```bash
ai-agent-scanner discover --network 127.0.0.1/32 --output local-inventory.json
```

This runs network discovery, not model generation or a complete vulnerability
assessment. Discovery checks service signatures on common ports, including
Ollama's default port. It samples read-only model inventories and identifies
protocol compatibility, not vendor ownership. See [network discovery boundaries](docs/network-discovery.md).
A missing service can produce an empty inventory.
The shared scan budget defaults to 500 DNS/TCP/HTTP attempts and a 1 MiB
response limit; exhausted budgets produce incomplete results. Local CLI targets
are operator-selected. Server scans additionally require explicit allowlists.

## Supported workflows

| Workflow | What it does | What it does not establish |
| --- | --- | --- |
| Discovery | Looks for service signatures, code integrations, supported traffic records, and optional cloud inventory | Complete asset inventory or exploitability |
| Active security probes | Sends prompt, access-control, and privacy probes to configured endpoints | Successful testing when the provider rejects requests or the adapter is unsupported |
| Passive MCP review | Inspects local configuration and saved tool schemas; emits JSON or SARIF | Live MCP authorization, sandbox enforcement, or tool exploitation |
| Read-only live MCP inventory | Collects bounded public tool schemas from an explicitly scoped, already-running MCP endpoint | Authorization/Origin enforcement, tool execution, or complete MCP interoperability |
| Controlled MCP policy checks | Compares protected inventory against an explicit fixture policy with an authenticated positive control | Browser exploitation, tool-execution authorization, or an overall security pass |
| Offline replay | Compares recorded outputs and tool requests against explicit policies and labels | Production accuracy, a live injection campaign, or proof of tool execution |
| Reporting | Preserves findings, observations, phase status, and risk estimates; exports JSON/SARIF | Compliance certification or a standardized CVSS score |
| Saved scan templates | Stores tenant-owned API recipes and manually admits runs under current server policy | Dashboard template controls, scheduled runs, or credential storage |

```bash
ai-agent-scanner discover --repository ./src --output code-inventory.json
ai-agent-scanner scan --config lab-targets.json --output results.json
ai-agent-scanner scan --config lab-targets.json --format sarif --output results.sarif
ai-agent-scanner mcp --config mcp-client.json --output mcp-review.json
ai-agent-scanner mcp --tools saved-tools.json --format sarif --output mcp.sarif
ai-agent-scanner mcp-live --endpoint http://127.0.0.1:8000/mcp --allow-network 127.0.0.1/32 --allow-loopback --output mcp-inventory.json
ai-agent-scanner mcp-check --endpoint http://127.0.0.1:8000/mcp --allow-network 127.0.0.1/32 --allow-loopback --api-key-env MCP_ACCESS_TOKEN --policy mcp-policy.json --output mcp-checks.json
ai-agent-scanner evaluate --suite lab-transcripts.json --output metrics.json
ai-agent-scanner diff --before baseline.json --after results.json --output changes.json
ai-agent-scanner triage --report results.json --policy suppressions.json --output triaged.json
```

Scan configuration accepts `target_scope` for discovery or `agents` for direct
security testing. For example, discovery configuration can contain:

```json
{
  "target_scope": {
    "network_ranges": ["127.0.0.1/32"],
    "include_network": true
  }
}
```

Use `scan --skip-security --config lab-targets.json` for discovery-only output.
Explicit agent entries require `id`, `name`, `endpoint`, and `provider`. Active
model probes also require an explicitly selected model and a supported protocol;
missing configuration produces skipped results. See [provider adapters](docs/provider-adapters.md)
for model and environment-based credential configuration.
Protected canaries and response markers are optional evidence configuration;
the scanner cannot infer their provenance. See [scan configuration](docs/scan-results.md)
and [detection evidence](docs/detection-evidence.md) before active testing.
Cloud discovery requires `python -m pip install '.[cloud]'` and provider-specific
configuration. Use Python 3.11 or newer for the cloud SDKs. See
[discovery inputs and bounds](docs/discovery-inputs.md). The web API does not
accept caller-supplied cloud credentials.

The `mcp-live` command supports only the documented MCP `2026-07-28` Streamable
HTTP inventory subset. It never launches configured commands or invokes tools,
and completed collection leaves runtime security unassessed. See
[live MCP scope, credentials, and limits](docs/mcp-live.md).
The separate `mcp-check` command requires an endpoint-bound local policy, an
issued bearer credential, and an operator-seeded protected fixture tool. It
tests only the declared inventory boundary, never invokes tools, and keeps
missing prerequisites or canary-free responses distinct from passed checks.
See [controlled MCP policy checks](docs/mcp-policy.md).

## Web application

The supported identity model is one operator and one configured organization.
Authentication, scan ownership, and target policy are enforced server-side.
For a local checkout:

```bash
python -m pip install '.[server]'
export SECRET_KEY="$(openssl rand -hex 32)"
export OPERATOR_API_KEY="$(openssl rand -hex 32)"
export OPERATOR_ORGANIZATION_ID=local-lab
export SCAN_ALLOWED_NETWORKS=127.0.0.1/32
export SCAN_ALLOW_LOOPBACK=true
gunicorn -c gunicorn.conf.py --bind 127.0.0.1:5000 --workers 1 --threads 4 app:app
```

Enter the generated operator key in the dashboard at `http://127.0.0.1:5000`.
The browser keeps its bearer token in memory. Store deployment secrets outside
version control. `.env.example` lists supported server settings; the application
does not automatically load a `.env` file.

The dispatcher requires one server process, file-backed SQLite, and a local POSIX
filesystem. Queued scans survive restart; interrupted active probes are not replayed.
Stop the server before replacing it; overlapping reloads are unsupported. The
dashboard supports scan history, cancellation, authenticated exports, and
[check evidence and audit history](docs/dashboard-evidence.md). For
security-only runs, select a completed source scan and [models for its assets](docs/source-model-selection.md).
The authenticated [template API](docs/scan-templates.md) saves existing scan
definitions with revision checks and bounded tenant quotas. Manual runs share
the scan queue and revalidate current scope and source prerequisites. Template
editing or deletion does not change an already admitted job. Dashboard template
controls and scheduling are not implemented yet.
Review [persistent jobs](docs/jobs.md), [authentication](docs/authentication.md),
[server scan policy](docs/scan-policy.md), and [development/container instructions](docs/DEVELOPMENT.md)
before deployment. Startup upgrades only [known SQLite layouts](docs/jobs.md#schema-upgrades);
it is not a general schema migration system.

## Interpreting results

A refusal is not a successful injection. Generated example PII is not proven
data leakage. HTTP 200 or an administrative keyword alone is not authorization
bypass. Confirmed disclosure checks need a seeded protected canary; authentication
checks need protected response evidence and a denied control.

Failed, skipped, and partial tests remain distinguishable from completed checks.
[Versioned check records](docs/result-contracts.md) separate execution from
passed, confirmed, heuristic, and inconclusive evidence. New risk estimates
require conclusive completed check evidence; an empty finding
list does not mean a target is secure. Framework references and the `coverage`
command describe mappings and implementation scope, not verified compliance.
Review retained evidence before acting on any finding.

## Limits and roadmap

- Distributed execution, PostgreSQL job coordination, comprehensive schema
  migrations, and hard cancellation of synchronous libraries remain unfinished.
- Enterprise identity, granular roles, production tenant provisioning, and
  immutable audit trails are not implemented.
- Passive MCP analysis, read-only live inventory, and offline RAG/injection/tool
  replay do not replace runtime authorization, tool-behavior, or live attack tests.
- Discovery and provider compatibility are incomplete. Transport errors and
  unsupported responses limit coverage; request budgets can truncate a scan.
- Secret redaction reduces exposure but is not a general data-loss prevention
  guarantee. Reports may contain sensitive target responses or source evidence.
- Scheduling, external integrations, representative performance evaluation, and release
  hardening remain part of the [engineering plan](docs/ENGINEERING_PLAN.md).

See [passive MCP scope](docs/mcp-assessment.md), [replay schema and metrics](docs/replay-evaluations.md),
[report comparison and suppression policy](docs/report-workflows.md),
[local queue acceptance](docs/performance.md),
[security policy](SECURITY.md), and [changelog](CHANGELOG.md).

## Development

```bash
python -m pip install '.[dev]'
python -m pytest tests/
ruff check .
```

CI also builds distributions, tests the installed CLI outside the checkout,
audits dependencies, and builds the container. Publication is a separate release
action. The project is licensed under [GPL-3.0-only](LICENSE).
