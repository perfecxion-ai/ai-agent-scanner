# CLI checkpoint recovery

Use `--checkpoint-dir` on `scan` or `discover` to preserve public report
checkpoints during that execution. The directory must be new; its parent must
already exist. Keep ordinary output outside the checkpoint directory.
Keep both reports and checkpoint directories outside public source checkouts.

```bash
ai-agent-scanner scan --config lab-targets.json \
  --checkpoint-dir ./checkpoint-run-001 --output ./results.json
```

After the process stops, export the saved evidence:

```bash
ai-agent-scanner recover --checkpoint-dir ./checkpoint-run-001 \
  --output ./recovered.json
ai-agent-scanner recover --checkpoint-dir ./checkpoint-run-001 \
  --format sarif --output ./recovered.sarif
```

Recovery reads local saved evidence and writes a derived export. It does not
resume the scan, send requests, resolve credentials, load scan configuration,
or open a server database or evidence-profile registry. Keep the original
checkpoint directory for subsequent exports. Start any new assessment with a
different directory.

An interrupted execution has unknown completion. Its recovered report has
`status: partial`, retains its existing checks and findings, and includes a
static explanation. Recovery exits nonzero after writing that report. It cannot
invent a pass or finish an unfinished check. A terminal snapshot preserves the
actual completed, partial, failed or cancelled status; only completed recovery
exits zero. A scan can finish before its ordinary output file is written, so a
terminal completed snapshot can remain recoverable after an output error.

Without `--checkpoint-dir`, CLI behavior remains unchanged: checkpoints stay in
memory and orderly timeout or cancellation can export retained partial evidence.
Forced process termination can lose that in-memory state.

## Storage contract

This opt-in format supports POSIX and a local filesystem. A fresh directory is
created with mode 0700. Its `.lock` and `latest.json` files are owned regular
files with mode 0600 and one hard link. The scanner holds an exclusive,
nonblocking lock throughout execution; recovery takes the same lock through
export and refuses a live writer or another recovery process.

The final directory and files are opened without following symlinks. Existing
ancestor symlinks, including macOS temporary-directory aliases, are canonicalized
before the final directory is pinned. A checkpoint directory or file with an
unexpected type, owner, permission or link count is refused. This boundary
protects against other Unix users; it does not protect against a malicious
process running as the same user or root.

`latest.json` contains a versioned envelope:

```json
{
  "format": "ai-agent-scanner-cli-checkpoint",
  "version": "1.0",
  "execution_id": "a per-execution UUID",
  "state": "checkpoint or terminal",
  "report": {}
}
```

The nested report is the shared pipeline's already-redacted public report,
including its original producer identity, check contracts, observation receipts
and checkpoint sequence. It contains no resumable private configuration.
Envelope version 1 is separate from checkpoint versions 1 through 4 and evidence
ledger versions 1 through 3. Existing readers and archived reports retain their
meanings. The writer pins execution identity and evidence prefixes and refuses
regression. Current public envelope labels are checked against the pinned private
evidence basis before the first report is written.

Each update uses an owner-only temporary file in the pinned directory, flushes
and fsyncs that file, atomically replaces `latest.json`, then fsyncs the
directory before acknowledging the callback. Validation or persistence failure
stops further execution. Failure before replacement preserves the previous
snapshot. Failure after replacement can leave a complete newer snapshot without
an acknowledged write. Recovery uses its recorded state: a checkpoint remains
incomplete, while a terminal snapshot preserves the actual result.
The guarantee is retention of previously acknowledged evidence, not exclusion
of a later coherent unacknowledged update.

Each report is limited to 8 MiB and 64 nested containers. The existing 4,096
callback and 128 MiB aggregate limits remain, with bounded file-envelope overhead
and one additional terminal snapshot. Forced termination during a write can
leave one private staging file; recovery never promotes its contents. Unexpected
entries or unsafe staging files cause refusal.

Recovery bounds the file before parsing, rejects malformed or unsupported
envelopes and evidence contracts, and validates the report through the shared
contracts. A local file and content fingerprint are not cryptographic proof of
authenticity or target provenance. Do not treat a supplied file as a trusted
verdict merely because it parses. Recovery cannot independently reconstruct
private credentials or canaries for another privacy sweep.

No active scan is replayed, and no existing checkpoint directory is reused for
writing. Files are retained for the operator to manage; no automatic deletion or
secure-erasure promise is made. Process-kill recovery is tested separately from
power loss, disk failure, network filesystems and deployed operational acceptance.
