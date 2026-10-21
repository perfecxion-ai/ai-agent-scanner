"""Allowlisted CLI diagnostics, never endpoint, credential, or response text."""


_PUBLIC_FAILURE_REASONS = frozenset({
    "MCP endpoint hostname could not be resolved",
    "MCP endpoint is outside the allowed scope",
    "MCP transport policy rejected inventory",
    "MCP TLS certificate verification failed",
    "MCP TLS negotiation failed",
    "MCP transport failed or timed out",
    "Plaintext MCP requires loopback",
    "MCP access denied; inventory not evaluated",
    "MCP HTTP request rejected",
    "MCP request rejected",
    "Unsupported MCP protocol version",
    "Invalid MCP JSON",
    "MCP JSON nesting limit exceeded",
    "Invalid MCP response envelope",
    "Invalid MCP error envelope",
    "Incomplete or unsupported MCP result",
    "Unsupported MCP response content type",
    "MCP stream event limit exceeded",
    "MCP total response limit exceeded",
    "MCP stream ended without a complete response",
    "MCP schema complexity limit exceeded",
    "Invalid MCP tool schema",
    "Unsupported MCP schema dialect",
    "Unsupported MCP input schema root; explicit object type required",
    "Invalid MCP schema header annotation",
    "Invalid or excessive MCP tool inventory",
    "Invalid or duplicate MCP tool name",
    "Invalid MCP tool metadata",
    "Invalid or excessive MCP pagination cursor",
    "Invalid MCP discovery result",
    "Invalid MCP server capability",
    "Invalid MCP tools capability",
    "Repeated MCP pagination cursor",
    "MCP pagination limit exceeded",
    "Invalid MCP inventory response",
    "Protected MCP tool name overlaps serialized request data",
    "Invalid or unsupported MCP baseline discovery",
    "Invalid MCP baseline capability",
    "MCP baseline does not advertise supported tools",
    "Protected MCP tool name overlaps baseline cursor",
    "Repeated MCP baseline cursor",
    "MCP baseline pagination limit exceeded",
    "MCP policy baseline or deadline failed",
    "MCP policy control was unusable",
    "MCP policy deadline exhausted",
})


def public_failure_reason(report):
    """Select only an exact static failure reason already present in a report."""
    candidates = [report.get("reason")]
    candidates.extend(check.get("reason") for check in report.get("checks", [])
                      if isinstance(check, dict) and check.get("status") == "failed")
    return next((value for value in candidates
                 if isinstance(value, str) and value in _PUBLIC_FAILURE_REASONS), None)
