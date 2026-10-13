# Discovery input boundaries

## Recorded traffic

Traffic discovery reads captured HAR entries, JSON objects or arrays, JSON-lines
records, and text access-log lines containing a complete HTTP request URL.
Structured records accept `url`, `uri`, `request_url`, or `target` in the record
or its `request` object. Relative paths without an authority, compressed files,
packet captures, and arbitrary prose mentions are not supported.

Known provider authorities establish an observed service request. Shared API
paths do not identify a vendor: an unknown proxy using `/v1/chat/completions`
is not labeled OpenAI. Requests do not establish deployment exposure, successful
model execution, or vulnerabilities. Query strings, fragments, and URL userinfo
are removed from output; request headers and bodies are not retained.

Each provider and normalized endpoint has a deterministic asset ID. Each request
record contributes once to the endpoint count. The analyzer reads at most 16 MiB
per file, 64 MiB per source, 50 files, 10,000 directory entries, and 100,000
records per file. UTF-8 is required. Symlinks are rejected.

A missing, unreadable, malformed, or oversized selected source increments the
active scan's failure count. Valid records from other files are preserved and
the shared pipeline reports a partial result. Direct use without an active scan
budget raises an explicit error for incomplete input.
