# Server scan policy

API scans require both operator authentication and server-owned target boundaries.
Targets are denied by default. The local CLI has a separate explicit operator
scope; these environment settings govern API scans.

Set `SCAN_ALLOWED_NETWORKS` to comma-separated authorized CIDRs. For a local lab,
use `SCAN_ALLOWED_NETWORKS=127.0.0.1/32` with `SCAN_ALLOW_LOOPBACK=true`. Both
settings are required to enable loopback targets. Metadata, link-local,
multicast, unspecified, and IPv4-mapped IPv6 targets remain forbidden.

Domains are resolved to addresses during API validation. Every returned address
must be allowed. Discovery receives only those literal targets, so it does not
guess subdomains or repeat DNS resolution. This uses IP-based service discovery;
virtual hosts requiring a particular Host header or TLS SNI are not supported
by that discovery path.

Set `SCAN_ALLOWED_PATH_ROOTS` to absolute directories separated by the platform
path separator (`:` on Linux). Repository URLs are not accepted by the API.
Paths must resolve beneath an allowed root. Preflight rejects nested symlinks,
special files, and requests exceeding file count or byte budgets. Roots must
contain trusted files that are not concurrently modified during a scan;
preflight is not a filesystem sandbox. File content may appear in scan evidence.
Cloud scans through the API are disabled until server-owned cloud configuration
and credential boundaries are implemented.

Request limits:

| Limit | Default |
| --- | --- |
| JSON request body | 64 KiB |
| Entries per target field | 32 |
| Addresses per individual network | 1024 |
| Aggregate addresses (`SCAN_MAX_HOSTS`) | 1024 |
| Files and directories (`SCAN_MAX_FILES`) | 10000 |
| Individual file | 16 MiB |
| Aggregate input files | 256 MiB |
| Concurrent scans (`MAX_CONCURRENT_SCANS`) | 2 |
| Queued scans (`SCAN_MAX_QUEUED`) | 32 |
| Scan deadline (`SCAN_TIMEOUT_SECONDS`) | 300 seconds |

The supported modes are `discovery_only`, `full`, and `security_only`.
Security-only requests specify `scan_config.source_scan_id`, referring to a
completed scan in the authenticated organization. They cannot add new targets.
The stored asset endpoints must still satisfy the current server allowlist.
Requests may shorten the scan deadline with `scan_config.timeout_seconds`, but
cannot raise the server maximum.
Security-only requests may also include `scan_config.model_overrides`, mapping
existing source asset IDs to model names. This field cannot change endpoints,
providers, or credentials, and is rejected for other scan modes.

Invalid scopes return 400. Unknown or foreign source scans return the same 404.
Oversized bodies return 413. Accepted scans return 202 after the scan and job are
committed together. A full queue returns 429 without creating another scan.
Deadlines cancel asynchronous work and mark failures; synchronous code must
return before cancellation can take effect. Saved scopes are validated again
against current server policy when a queued job starts. See
[persistent jobs](jobs.md) for recovery and cancellation behavior.
