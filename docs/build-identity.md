# Build and report identity

The canonical package version is `1.2.0.dev0`, declared in `src/_version.py` and
read by Setuptools. CLI version output, server health and MCP client information
use that same value. This development identity does not publish a release.
Database, report, check, evidence, ruleset and MCP protocol versions are separate
contracts and are unchanged by this feature.

## Current diagnostics

```bash
ai-agent-scanner --version
ai-agent-scanner build-info --json
```

An authenticated `GET /api/build` returns `success` and a `build` object for the
running server. It uses existing operator authentication and performs no SQL.
The health endpoint retains its simple package version. These diagnostics do not
start a scan, load an evidence profile, resolve a target or invoke a model.

The identity object contains:

| Field | Meaning |
| --- | --- |
| `identity_schema_version` | Supported identity representation, currently `1.0` |
| `package_version` | Canonical scanner development version |
| `component` | `library`, `cli`, or `server` caller context |
| `source` | Status and SHA-256 for the scoped packaged Python content |
| `server_app` | Separately scoped checkout server digest, or explicit unavailability |
| `catalogs` | Status, identifiers, hashes and counts for bundled prompt definitions |

The `scanner-python-v1` source digest covers sorted public relative names and
raw bytes of `src/**/*.py` plus `scanner_cli.py`, using length-delimited records.
It excludes documentation, tests, bytecode, timestamps, installed metadata,
dependencies, server templates/static files and the source-only app entrypoint.
The same bytes produce the same digest in a checkout and installed wheel.

The source-only server digest uses the separate `server-app-python-v1` namespace.
It is available only when the loaded app is the trusted scanner checkout's
`app.py`. An unrelated embedding application's file is not inspected. The wheel
excludes the server entrypoint, and the container copies that file separately,
so installed/container server-app identity can be explicitly unavailable while
the packaged scanner fingerprint remains available.

Source reads use bounded regular files and directory descriptors without
following source symlinks. Missing, unreadable or excessive material produces
an `unavailable` status and null digest, without raw paths or exception text.
Fingerprints describe a process-lifetime snapshot under the supported immutable
installation assumption. Restart after changing code. A library diagnostic
before scanner-app import does not permanently cache the app's absence.

Catalog identity describes complete bundled baseline and protected-disclosure
definitions, including their counts and the existing protected suite pin and
semantics. It does not describe executed coverage or claim that a customized
tester used those definitions. Per-check probe versions and recorded execution
remain authoritative. Frozen prompts, sampling and evidence eligibility are
unchanged.

No Git command, network call, environment/configuration read or caller-selected
path contributes to this helper. These are content identifiers, not a Git SHA,
signed authenticity, dependency/SBOM attestation, detection result or security
certification. Resolved dependencies can differ even with equal scanner digests.

## Saved producer and current exporter

New pipeline, MCP, replay and paired-benchmark execution reports capture
`producer_identity` before their execution work. A pipeline copies that same
stamp into every acknowledged checkpoint and final report. The durable store
rejects producer replacement, removal or later stamping of an unstamped
checkpoint, including changes hidden by Python numeric equality. Recovery keeps
the original stamp. Preparation failures that never produce a pipeline report
retain unknown producer identity.

Derived comprehensive and SARIF formats distinguish the saved producer from
`exporter_identity`, the software formatting the output now. A valid older
producer version and digests remain older values. Missing historical producer
identity is shown as null, with current exporter information kept separate.
Comprehensive text summaries label the two versions separately. Raw saved JSON
downloads and archived report bytes receive no retrospective producer stamp.
Diff and triage output retain their existing format in this slice.

Privacy can withhold an identity. Protected values matching an identity string value or
nested descriptor make that producer explicitly null. An export of an explicitly
null or malformed producer also withholds exporter identity and its version, so
it cannot reintroduce a known protected fingerprint after secret context is gone.
This differs from an absent historical stamp. Protected values overlapping the
outer `producer_identity` or `exporter_identity` field names are refused with a
static error, because JSON keys are preserved by ordinary redaction.

The paired-benchmark validator accepts an optional valid producer stamp or null
while retaining its existing strict ledger, manifest and metric checks. Old
unstamped benchmark reports remain supported. Identity alone never upgrades an
evidence verdict or changes a risk score.

## Validation and remaining work

Installed-wheel smoke runs outside the checkout and compares source/catalog
identity, CLI version and distribution metadata. Local tests cover source
boundaries, historical producers, checkpoint immutability, privacy collisions
and authenticated diagnostics without SQL. This slice requires no GCP retest or
operator database access.

Release checksums, SBOMs, dependency locking, signed build provenance, exact
repository revision attestation and deployed install/upgrade acceptance remain
separate R1.5 work. Publication and deployment retain their separate authorization.
