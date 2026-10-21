# Scan results

The API stores versioned results in the `scan_result` table. Server startup validates
and upgrades known SQLite schemas under the dispatcher lock. Stop the server and
back up the database before upgrading; see [schema upgrades](jobs.md#schema-upgrades).
Do not use `db.create_all()` as an upgrade command; it bypasses schema acceptance.
Older scans remain readable but do not have JSON/SARIF reports or reusable security-only inputs.

`GET /api/scans/<id>/results` includes a `pipeline` object with schema version `1.0`.
`GET /api/scans/<id>/report?format=json` returns that complete object.
Use `format=sarif` for SARIF 2.1.0 findings. All routes require the scan's organization.

Each scan stores a separate agent snapshot ID. Its `asset_id` identifies the original discovered
asset, so repeated scans no longer collide on database primary keys. Security states are
`not_tested`, `skipped`, `completed`, `partial`, or `failed`. Failed required
checks retain available evidence and make the scan `partial`.
Missing endpoints are skipped. Risk is unknown (`null` in versioned JSON) unless assessment ran.
New assessment requires a confirmed finding matched to its validated confirmed
check, even with partial execution, or a completed protected-access sampled pass.
Prompt and tenant nondisclosure are inconclusive, not passes.
`risk_assessment_status` and the risk-assessed summary
counts distinguish completed execution from an actual assessment. See
[versioned check contracts](result-contracts.md).
Legacy numeric columns retain zero for compatibility; use the versioned result's state and risk.
The scanner's existing detection heuristics are not evidence that an endpoint is safe.

Security-only scans use `scan_config.source_scan_id` to load a terminal completed
or partial scan from the same organization. A partial source must have a finalized
versioned report and usable inventory matching its saved asset snapshots. Cancelled,
failed, interrupted, and in-progress scans cannot be reused. Target policy and
source ownership are checked again when queued work executes. Partial source
coverage stays explicit in the derived report's `source_inventory` object; testing
saved assets does not fill gaps in the original discovery.
`model_overrides` accepts either a stable `asset_id` or that source's snapshot `id`,
normalizes selections to stable IDs, and rejects aliases that select one asset twice.
Source endpoints whose query or credentials were redacted cannot be replayed: supply
fresh explicit configuration through the CLI instead. Discovery-only scans do not run security
tests. JSON preserves findings and risk assessments; SARIF includes execution completeness so
skipped, failed, and discovery-only runs are not represented as clean security executions.

Execution uses a durable SQLite queue within one server process. Restarting resumes
queued work and marks previously active jobs interrupted without replaying probes.
It does not backfill historical reports. See [persistent jobs](jobs.md).

## CLI

`ai-agent-scanner scan` uses the same versioned pipeline and JSON/SARIF exporter as the API.
Empty discovery still writes a report. Partial scans write available results and exit nonzero.
Targets support repeated `--network`, `--domain`, `--repository`, and `--traffic` options.
`--config local.json` accepts a `target_scope` object, including `cloud_accounts` for cloud
discovery. CLI targets are explicitly authorized local inputs; API server allowlists do not apply.
Reserved and metadata addresses remain forbidden, and loopback requires
`--allow-loopback`. Shared limits are `--max-requests`, `--max-response-bytes`, and
`--timeout-seconds`, and `--request-timeout-seconds` (default 30, maximum 300);
see [CLI bounds](../README.md#supported-workflows). Server requests instead obey
the configured `SCAN_REQUEST_TIMEOUT_SECONDS` and hard scan deadline. Timeout
configuration does not enable retries or additional security controls.
After discovery, select models with repeatable `--model-override ASSET_ID=MODEL`
using exact stable IDs from `agents[].id`. Unknown or ambiguous selections stop
before active probes, and never assign models to unrelated providers.
Security scans with assets but no completed checks exit nonzero, preserving the
report rather than representing skipped work as successful testing. Report files
are written atomically with owner-only permissions, and symlink destinations fail.

To test known agents without discovery, provide an `agents` array in the configuration:

```json
{"agents":[{"id":"lab-agent","name":"Lab agent","provider":"openai","model":"YOUR_LAB_MODEL",
"endpoint":"https://lab.example.test/v1/chat/completions",
"system_prompt_canary":"unique-operator-seeded-canary","evidence_context_id":"lab-seed-v1"}]}
```

Seed canaries in the lab target before scanning; do not include them in submitted user prompts.
Supported evidence configuration includes `system_prompt_canary`, `cross_tenant_canary`,
`authentication_required`, `protected_response_marker`, and `protected_path_markers`.
Markers must have at least 16 characters. These values are inputs for evidence checks,
not provider credentials. Reports omit agent credentials, canaries, endpoint query strings,
and arbitrary metadata; supported exposure metadata remains available for risk assessment.
