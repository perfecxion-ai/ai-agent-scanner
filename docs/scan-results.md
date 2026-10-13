# Scan results

The API stores versioned results in the `scan_result` table. Existing installations must run
`flask --app app shell`, then `db.create_all()` before serving requests after upgrading.
This adds the table without rewriting existing scan records. Back up the database first.
Older scans remain readable but do not have JSON/SARIF reports or reusable security-only inputs.

`GET /api/scans/<id>/results` includes a `pipeline` object with schema version `1.0`.
`GET /api/scans/<id>/report?format=json` returns that complete object.
Use `format=sarif` for SARIF 2.1.0 findings. All routes require the scan's organization.

Each scan stores a separate agent snapshot ID. Its `asset_id` identifies the original discovered
asset, so repeated scans no longer collide on database primary keys. Security states are
`not_tested`, `skipped`, `completed`, or `failed`. Failed testing makes the scan `partial`.
Missing endpoints are skipped. Risk is unknown (`null` in versioned JSON) unless assessment ran.
Legacy numeric columns retain zero for compatibility; use the versioned result's state and risk.
The scanner's existing detection heuristics are not evidence that an endpoint is safe.

Security-only scans use `scan_config.source_scan_id` to load a completed scan from the same
organization. The source must have versioned results. Discovery-only scans do not run security
tests. JSON preserves findings and risk assessments; SARIF includes execution completeness so
skipped, failed, and discovery-only runs are not represented as clean security executions.

Execution remains in process: restarting the server interrupts running work. This release does
not introduce a durable worker queue, retry recovery, or historical result backfill.
