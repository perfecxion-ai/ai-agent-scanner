# Models for saved discovery assets

Discovery may identify a model server without selecting a model. Active provider
probes need a model, so those assets otherwise receive a skipped result.

The security-only API contract extends `scan_config` with `model_overrides`:

```json
{
  "scan_type": "security_only",
  "scan_config": {
    "source_scan_id": "completed-source-scan-id",
    "model_overrides": {
      "source-asset-id": "llama3.2:latest"
    }
  }
}
```

Use the `id` from the source report's `agents` array, not a database row ID or an
asset name. The map can contain up to 100 entries. IDs and model names must be
strings of 1-256 characters without surrounding whitespace or control characters.
Empty maps preserve existing selections. Unlisted source assets keep their
existing model, if any.

Integration order is part of the security boundary:

1. Validate request shape with `validate_model_overrides` and allow the field only
   for security-only scans.
2. Authorize the completed source scan against the caller's organization.
3. Apply `apply_model_overrides` to its saved asset snapshot. Unknown IDs and
   duplicate source IDs are errors. The source snapshot is not modified.
4. Revalidate source endpoints against current server policy and run the probes.

Overrides cannot change endpoint, provider, headers, or credential references.
Model text is literal; no environment references, templates, or shell expressions
are expanded. This contract does not add an API mechanism for selecting environment
credentials. Existing provider authentication and server scope controls still apply.
An unsupported provider, missing credentials, or a model conflicting with a complete
Gemini endpoint remains unexecutable. A selected model does not guarantee it is
available on the target; rejected generation requests produce incomplete results.

The API validates selections before queue admission and applies them again when
the job executes. Queued work remains subject to the current server scope policy.
