# Saved scan templates

Templates save the existing API scan configuration for manual reuse. They do not
start scans when created or edited or configure external delivery. Separately,
[finite API schedules](scan-schedules.md) pin a reviewed template revision and
require explicit enabling. Every route requires the operator's authenticated
organization; foreign and missing template IDs both return 404.

## Dashboard

After signing in, **Save form as new template** stores the current scan form,
including security-only source and model selections, without starting a scan.
The saved-template list uses bounded 25-item pages. Select a recipe and choose
**Load** to inspect its complete four-field JSON definition. **Update template**
replaces that definition using the displayed revision. The separate editor keeps
advanced target and configuration fields intact rather than reconstructing them
from the simpler new-scan form. Server validation still rejects unsupported fields.

**Run saved revision** admits the displayed saved recipe, not unsaved editor text.
The admitted scan opens in the results panel. Stale revisions require reloading;
failed updates and runs retain the editor. Unsaved edits block loading or saving
another recipe until you update or explicitly **Discard editor changes**. Refreshing
the list does not replace editor contents. **Delete recipe** removes the template
only, not existing jobs. Logout clears the recipe list and editor; no token or
template definition is stored in browser storage. These controls never run on a
timer or enable an automatic scan.

## API

`POST /api/templates` accepts the same four definition fields as a scan:

```json
{
  "scan_name": "Lab inventory",
  "scan_type": "discovery_only",
  "target_scope": {"domains": ["lab.example.test"]},
  "scan_config": {"timeout_seconds": 120}
}
```

Successful creation returns 201 with `template`, including its ID, revision, UTC
creation/update timestamps, and saved definition. `GET /api/templates/<id>` returns
that definition. `GET /api/templates?limit=25&offset=0` returns tenant-owned
summaries, a total, and pagination fields. Limit is 1..100 and offset is 0..100000.
Lists omit target/configuration details; fetch a template individually to edit it.

`PUT /api/templates/<id>` replaces the entire definition and requires its current
integer `revision` alongside the four fields. A successful update increments the
revision. A stale revision returns 409 without modifying the recipe. Revision is
bounded to 1..2147483647; a recipe at the maximum cannot be updated.

`POST /api/templates/<id>/run` requires a JSON object. Send `{}` to run the latest
recipe or `{"revision": 1}` to require a displayed revision. Configuration
overrides are not accepted. A recipe changed during validation returns 409; a
deleted recipe returns 404. A successful admission returns 202 with `scan_id`,
exactly like direct scan creation. A full shared queue returns 429.

`DELETE /api/templates/<id>` deletes only the saved recipe. Existing queued or
running scans retain their independent configuration snapshot. Use the scan
cancellation endpoint to cancel a job; deleting or editing its template does not
cancel it. Names need not be unique. Edits/deletion pause referencing schedules
transactionally, without changing their pinned revision or cancelling admitted jobs.

## Limits and credentials

Definitions are capped at 16 KiB of UTF-8 JSON, including applied defaults.
`SCAN_MAX_TEMPLATES` defaults to 64 templates per organization and can be configured
from 1 to 1024. Template quota checks and writes are serialized with admission
inside the supported single server process. This is not distributed coordination.

Supported modes are `discovery_only`, `full`, and `security_only`. Existing target,
model-selection, timeout, host, filesystem, and transport limits still apply.
Cloud inventory remains CLI-only. Unknown definition/configuration/target fields,
control characters, and non-finite JSON are rejected. Credentials, headers,
cookies, authentication options, canaries, and endpoint overrides are not template
fields. URLs containing user information or a query are rejected rather than
silently rewritten.

Do not paste secrets into scan names, model names, paths, or any other identifiers.
The field contract excludes credential options; it cannot prove that arbitrary
user-provided identifiers contain no secret. Templates are configuration records,
not an encrypted secret store. They do not persist prompts or model responses.

## Current-policy revalidation

Creation and updates validate current server policy and replay prerequisites but
do not enqueue a job or send a model request. DNS resolution and bounded local
filesystem inspection are part of that validation. Declared domains and absolute
path text are retained instead of saving creation-time DNS answers or resolved
symlink destinations. Relative paths remain unsupported, as in direct API scans.

Run admission validates the declaration again, then commits the scan, queue row,
and minimal admitted audit event together. Workers resolve domains and inspect
paths again under current server allowlists and limits before execution. A changed
DNS answer, symlink target, allowlist, or limit can reject a previously saved or
queued recipe. Preflight validation does not hold the admission lock.
Connection-time checks still apply; this does not close the documented concurrent
filesystem modification boundary for trusted local inputs.

Security-only templates require a completed, tenant-owned source scan with
versioned results and assets. Redacted source endpoints cannot be replayed.
Selected asset/model IDs and current endpoint policy are checked at creation,
update, admission, and worker execution. Templates store only the source scan ID
and model selections, not a copy of credentials or protected canaries.

Template operations do not append definition contents to scan audit history.
Successful runs use the existing admission/claim/cancellation/terminal events.
This history is operational and is not tamper-resistant.

## Database upgrade

Templates introduced `scan_template` in schema version 2. Current startup uses
version 3 for finite scheduling. Exact version 1 layouts add the template and
two schedule tables; exact version 2 layouts add only the schedule tables.
Each upgrade updates the version stamp in one SQLite transaction. Existing scan,
job, result, asset, audit, and template rows are preserved. Fresh databases and
previously supported unversioned layouts initialize directly to version 3. See
[job and upgrade constraints](jobs.md).

No template feature changes the single-process, file-backed SQLite, POSIX, local
filesystem deployment boundary. Stop the server and take a consistent database
backup before upgrading. Deployment and package publication are separate actions.
