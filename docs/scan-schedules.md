# Finite scan schedules

Schedules admit a finite number of scans from one reviewed, tenant-owned template
revision. Creation is disabled by default. Only an explicit authenticated enable
action starts the timer. The dashboard and API share this contract; there is no
cron expression, infinite recurrence, external delivery, or automatic enabling.

Every route requires the operator's organization. Foreign and missing IDs both
return 404. Schedule responses contain operational fields, not recipe contents,
credentials, source results, or raw validation errors.

## Dashboard

Load a saved template in the complete-definition editor, review its displayed ID,
revision, targets, and configuration, then check **I reviewed the displayed saved
template revision**. Set an integer interval and finite count and choose
**Create disabled schedule**. Unsaved editor text is never scheduled; discard or
save edits and review the resulting saved revision first. Creation resets the
review confirmation and does not admit a scan.

The schedule list uses 25-item pages. **Open schedule** displays the pinned
template and schedule revisions, state and pause reason, admitted/remaining count,
outstanding scan, interval, and UTC due time. Opening or refreshing never enables
or adopts a changed recipe. To choose **Enable reviewed schedule**, load and
explicitly review the exact pinned saved template revision above. Template edits
or deletion require a replacement schedule rather than a silent rebind. Explicit
**Pause schedule** prevents future admission but does not cancel admitted scans.

Refresh detail to observe dispatcher changes; schedules are not polled or enabled
by this page. Occurrences use bounded 25-item pages, ordered oldest first, with UTC
timestamps. **Open admitted scan** uses the existing results/status/audit view.
**Delete schedule** is available only when inactive with no outstanding scan, and
the server rechecks that constraint. Deletion preserves admitted scans and reports.

Revision and current-policy conflicts retain the displayed details and recipe;
refresh and review before retrying. Failed list/detail/occurrence requests leave
authenticated refresh controls available. Logout and expired sessions clear all
schedule details, recipe definitions, and pending-response state. Nothing is
stored in browser storage. These operator controls do not authorize running real
target schedules during engineering validation.

## API

`POST /api/schedules` requires exactly these fields:

```json
{
  "template_id": "reviewed-template-id",
  "template_revision": 1,
  "interval_seconds": 3600,
  "total_runs": 4
}
```

Creation returns 201 with `schedule`, including its ID, pinned template revision,
state `disabled`, schedule revision 1, admitted count 0, and UTC timestamps.
Intervals are integer seconds from 60 to 2592000 (30 days). Total runs is an
integer from 1 to 100. Credentials, tenant overrides, enabled flags, initial
timestamps, configuration overrides, and other fields are rejected.

`GET /api/schedules` lists the authenticated organization's schedules.
`GET /api/schedules/<id>` returns a schedule. Lists accept `limit` from 1 to 100
(default 25) and `offset` from 0 to 100000. Responses include a total and pagination.

`POST /api/schedules/<id>/enable` and `/pause` require exactly
`{"revision": 1}` with the currently displayed schedule revision. A stale
revision returns 409. Enable rechecks the pinned template and source/current
policy before setting the first due time to now plus the interval. It does not
immediately enqueue a scan. Pause prevents future admission but does not cancel
an outstanding scan. Use the scan cancellation endpoint to cancel that job.

`GET /api/schedules/<id>/occurrences` returns bounded, ordinal-ordered occurrence
mappings with scan IDs and UTC timestamps. It accepts the same pagination fields.
Use existing scan status, result, and audit routes to inspect each admitted job.

`DELETE /api/schedules/<id>` requires an inactive schedule with no outstanding
scan. Pause and wait for dispatcher terminal bookkeeping if necessary. Deletion
removes the schedule and its occurrence mappings only; admitted scans, reports,
and scan audit history remain accessible. Schedules cannot be edited or rebound.
Create a replacement to adopt a different reviewed recipe or recurrence.

## Recurrence and finite accounting

A schedule has at most one outstanding queued, running, or cancellation-requested
scan. After that scan becomes terminal, the next due time is observation time
plus the interval. Slow or overdue schedules do not backfill missed slots or
enqueue a catch-up burst. Pausing and enabling again starts a fresh interval;
an already outstanding job still prevents a second admission.

Every committed admission consumes one of the finite runs. Completed, partial,
failed, cancelled, and interrupted jobs are all consumed, with no automatic
retry or replay. After its final outstanding job becomes terminal, the schedule
becomes `completed`. A completed/exhausted schedule cannot be enabled again.

A full shared scan queue defers admission for 60 seconds without consuming a run.
Queue-full deferrals are rate-limited, not limited by a separate attempt count or
wall-clock expiry. Policy is revalidated on the next attempt. The finite bound is
the number of admitted scans, not an expiration date or number of validation
attempts. Paused schedules require operator review before resuming.

## Policy, templates, and restart

Security-only templates may reference operator-configured
[system-prompt canary profiles](detection-evidence.md#server-system-prompt-canary-profiles).
Creation, enable, preflight, admission, and worker execution revalidate their
public bindings and marker availability. A missing or changed binding fails
closed; no canary value is stored in a schedule or its policy token. Registry
changes require a controlled server restart and enabled schedules pause for
review. Secret-only rotation is not detected as a public binding revision; use
new profile/context versions for changed protected fixtures.

Creation, enable, and each admission use the existing strict template/scan
validator. This can resolve DNS and inspect bounded local files, but does not send
model requests. Server policy and security-only source identity are captured
before and after preflight and compared again before the admission transaction.
Template revision, schedule revision/state, queue quota, and shutdown are checked
at that final boundary. Workers separately revalidate current DNS, filesystem,
source, endpoint, and server policy before execution. Connection-time network
enforcement still applies. These checks do not eliminate the documented concurrent
modification boundary for trusted local files.

Template edits or deletion pause referencing non-completed schedules in the same
transaction, with `template_changed` or `template_deleted`. The pin never silently
adopts a new recipe; create a replacement schedule. Previously admitted jobs keep
their independent snapshots and are not cancelled by recipe changes.

Exclusive dispatcher ownership precedes schema upgrades, job recovery, and
schedule recovery. Startup pauses previously enabled schedules with
`restart_review`, requiring explicit review and enable. Already queued jobs keep
existing queue recovery semantics; active jobs are interrupted or cancelled and
never replayed. Disabled and operator-paused schedules stay inactive.

Other fixed pause reasons are `operator_paused`, `policy_review`,
`preflight_failed`, `preflight_timeout`, and `revision_limit`. These are operational
reasons, not security outcomes. Inspect current prerequisites rather than treating
a paused schedule as a passed assessment.

## Bounded service and persistence

`SCAN_MAX_SCHEDULES` defaults to 64 per organization (configurable 1..1024).
`SCAN_MAX_SCHEDULES_GLOBAL` defaults to 256 globally (1..4096). Each schedule has
at most 100 occurrence mappings. Existing queue, worker, request, response,
filesystem, and execution deadline limits still apply.

The owning dispatcher has one scheduling preflight slot. Its worker is read-only;
only the dispatcher performs final admission. No DNS or filesystem preflight runs
in the dispatcher cancellation loop. Each tick processes at most one completed
occurrence or one due candidate. Persistence errors use a one-second internal
retry backoff and make readiness fail while unresolved.

Preflight has a 60-second soft deadline. The dispatcher pauses the schedule with
`preflight_timeout`, retains the unfinished slot, and becomes unready while it is
occupied. It never admits the late result or adds queued executor work. Completion
releases the slot and restores readiness if persistence is healthy. Cancellation
processing for existing scan jobs continues. This is not hard thread, DNS, or
process cancellation; blocked synchronous libraries can still delay process exit.
Shutdown invalidates results before ownership release. A late read-only preflight
cannot enqueue work in an old process after a replacement dispatcher starts.

Schema version 3 adds `scan_schedule` and `scan_occurrence`. Exact version 2
databases add both tables and update the version stamp transactionally; exact
version 1 databases also add `scan_template`. Existing records are preserved.
Fresh and recognized unversioned layouts initialize directly to version 3.
An admitted occurrence, its count/pointer, scan, queue row, and admitted audit event
commit together; a failed transaction leaves none of them partially admitted.

The supported deployment remains one process, file-backed SQLite, POSIX, and a
local filesystem. Stop the server and take a consistent backup before upgrading.
See [persistent job constraints](jobs.md) and [template contract](scan-templates.md).
No schedule feature authorizes package publication or deployment.
