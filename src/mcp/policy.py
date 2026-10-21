"""Explicit, read-only protected MCP inventory policy checks."""

import asyncio
import hashlib
import json
import os
import re
from pathlib import Path
from urllib.parse import unquote

import aiohttp
from yarl import URL

from src.core.contracts import CHECK_SCHEMA_VERSION, CheckRecord, validate_checks
from src.core.redaction import redact_secrets
from src.core.scope import ScopeResolutionError, ScopeValidationError
from src.core.transport import SafeSession, TransportPolicyError, scan_transport
from src.mcp import live


MAX_POLICY_BYTES = 65536
_CONTEXT = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_MARKER = re.compile(r"[A-Za-z0-9._~/+-]{16,128}\Z")
_FIELDS = {"version", "endpoint", "evidence_context_id", "fixture_provenance",
           "protected_tool_name_env", "authorization_required"}
_TEXT = {
    "baseline_missing": "Protected fixture tool was absent from baseline",
    "baseline_valid": "Authorized protected inventory baseline observed",
    "control_unusable": "MCP policy control was unusable",
    "control_sample": "Sampled protected inventory policy control only",
    "baseline_failed": "MCP policy baseline or deadline failed",
    "deadline": "MCP policy deadline exhausted",
    "origin_missing": "Origin policy not declared",
    "prerequisite": "Protected baseline prerequisite unavailable",
    "execution": "Tool execution is not implemented",
    "remediation": "Enforce the declared protected inventory policy before returning tool metadata.",
    "auth_disclosure": "A complete tool inventory page disclosed the protected fixture tool under the denied unauthenticated condition.",
    "origin_disclosure": "A complete tool inventory page disclosed the protected fixture tool under the denied Origin condition.",
}
_LIMITATIONS = [
    "Checks cover only the explicitly declared protected inventory fixture policy.",
    "Controls sample the first tools/list page; canary absence never establishes a pass.",
    "Origin rejection is not a browser exploitability or DNS rebinding assessment.",
    "No tools, commands, OAuth flows, alternate URLs, or legacy protocols are invoked.",
    "Operator fixture provenance is declared, not independently attested.",
    "Overall risk and tool execution remain unassessed.",
]


def load_policy(path):
    """Read a small strict JSON policy without exposing its contents in errors."""
    with Path(path).open("rb") as stream:
        data = stream.read(MAX_POLICY_BYTES + 1)
    if len(data) > MAX_POLICY_BYTES:
        raise ValueError("MCP policy input limit exceeded")
    try:
        return live._decode(data)
    except live.LiveError:
        raise ValueError("Invalid MCP policy JSON") from None


def _origin(value):
    if (not isinstance(value, str) or len(value) > 1024 or "%" in value
            or any(not 0x21 <= ord(char) <= 0x7e for char in value)):
        raise ValueError("Invalid serialized MCP Origin")
    try:
        url = URL(value)
        if (url.scheme not in {"http", "https"} or url.user is not None
                or url.query_string or url.fragment or str(url.origin()) != value):
            raise ValueError()
    except ValueError:
        raise ValueError("Invalid serialized MCP Origin") from None
    return value


def _decoded_forms(value):
    forms = [value]
    for _ in range(16):
        decoded = unquote(value)
        if decoded == value:
            return forms
        forms.append(decoded)
        value = decoded
    raise ValueError("MCP policy value has excessive percent encoding")


def _endpoint_forms(endpoint):
    return [str(URL(endpoint)), *_decoded_forms(endpoint)]


def _validate(policy, endpoint, headers, api_key_env):
    if (not isinstance(policy, dict) or set(policy) - _FIELDS - {"origins"}
            or not _FIELDS <= set(policy) or type(policy["version"]) is not int
            or policy["version"] != 1 or policy["endpoint"] != endpoint
            or policy["fixture_provenance"] != "operator_protected_tool"
            or policy["authorization_required"] is not True
            or not isinstance(policy["evidence_context_id"], str)
            or not _CONTEXT.fullmatch(policy["evidence_context_id"])):
        raise ValueError("Invalid endpoint-bound MCP policy")
    name = policy["protected_tool_name_env"]
    if not isinstance(name, str) or not live._ENV_NAME.fullmatch(name):
        raise ValueError("Invalid MCP protected tool environment reference")
    marker = os.environ.get(name)
    if not marker or not _MARKER.fullmatch(marker):
        raise ValueError("Missing or invalid MCP protected tool name")
    if "Authorization" not in headers:
        raise ValueError("Protected MCP policy checks require an issued bearer credential")
    origins = policy.get("origins")
    if "origins" in policy:
        if not isinstance(origins, dict) or set(origins) != {"allowed", "denied"}:
            raise ValueError("MCP Origin policy requires allowed and denied origins")
        allowed, denied = _origin(origins["allowed"]), _origin(origins["denied"])
        if allowed == denied:
            raise ValueError("MCP policy origins must differ")
    # The marker must not be sent or derivable from configured request fields.
    credential = headers["Authorization"].removeprefix("Bearer ")
    endpoints = _endpoint_forms(endpoint)
    fields = [*endpoints, name, api_key_env, policy["evidence_context_id"],
              "policy-baseline", "policy-control", "server/discover", "tools/list",
              "ai-agent-scanner", "1.1.0", live.PROTOCOL_VERSION,
              "io.modelcontextprotocol/protocolVersion", "io.modelcontextprotocol/clientInfo",
              "io.modelcontextprotocol/clientCapabilities", *headers.keys(), *headers.values()]
    if origins:
        fields.extend(origins.values())
    fields.extend(f"inventory-{number}" for number in range(1, live.MAX_REQUESTS + 1))
    reserved = ["MCP.authorization", "MCP.origin", "MCP.policy_baseline", "MCP.tool_execution",
                "live_policy_checks", "mcp_protected_inventory_disclosure", "runtime_policy",
                "validated_positive_control", live.PROTOCOL_VERSION, "1.0.0", CHECK_SCHEMA_VERSION]
    reserved.extend(rule + ".protected_inventory" for rule in reserved[:4])
    reserved.extend(("completed", "skipped", "failed", "passed", "confirmed", "heuristic",
                     "inconclusive", "not_evaluated", "partial", "not_assessed", "high", "/tools"))
    reserved.extend(_TEXT.values())
    reserved.extend(_LIMITATIONS)
    fields.extend(reserved)
    declared_fields = [*endpoints, policy["evidence_context_id"], *(origins.values() if origins else ())]
    public_fields = [*declared_fields, *reserved]
    if (any(marker in value for value in fields if isinstance(value, str))
            or marker in credential or credential in marker
            or any(credential in value for value in public_fields)
            or any(value in credential for value in declared_fields)):
        raise ValueError("Protected MCP tool name overlaps request or credential data")
    return marker, origins


def _sent(marker, endpoint, headers, request_id, method, cursor=None):
    if marker in json.dumps([endpoint, headers, live._message(request_id, method, cursor)]):
        raise live.LiveError("Protected MCP tool name overlaps serialized request data")


async def _baseline(session, endpoint, state, headers, marker):
    _sent(marker, endpoint, headers, f"inventory-{state.budget.requests + 1}", "server/discover")
    discovery = await live._request(session, endpoint, "server/discover", state, headers)
    versions, capabilities = discovery.get("supportedVersions"), discovery.get("capabilities")
    if (not isinstance(versions, list) or not versions or len(versions) > 32
            or not all(isinstance(value, str) and len(value) <= 32 for value in versions)
            or live.PROTOCOL_VERSION not in versions or not isinstance(capabilities, dict)):
        raise live.LiveError("Invalid or unsupported MCP baseline discovery")
    for key in ("tools", "resources", "prompts", "logging", "completions", "extensions"):
        if key in capabilities and not isinstance(capabilities[key], dict):
            raise live.LiveError("Invalid MCP baseline capability")
    tools = capabilities.get("tools")
    if tools is None or ("listChanged" in tools and not isinstance(tools["listChanged"], bool)):
        raise live.LiveError("MCP baseline does not advertise supported tools")
    cursor, seen = None, set()
    for _ in range(live.MAX_PAGES):
        request_id = "policy-control" if cursor is None else f"policy-page-{state.pages}"
        _sent(marker, endpoint, headers, request_id, "tools/list", cursor)
        result = await live._request(session, endpoint, "tools/list", state, headers, cursor, request_id)
        page = live._State(state.budget, schema_nodes=state.schema_nodes,
                           tools=list(state.tools), names=set(state.names), pages=state.pages)
        cursor = await asyncio.to_thread(live._tools, result, page)
        state.tools, state.names = page.tools, page.names
        state.pages, state.schema_nodes = page.pages, page.schema_nodes
        if cursor is None:
            return
        if any(marker in value for value in _decoded_forms(cursor)):
            raise live.LiveError("Protected MCP tool name overlaps baseline cursor")
        if cursor in seen:
            raise live.LiveError("Repeated MCP baseline cursor")
        seen.add(cursor)
    raise live.LiveError("MCP baseline pagination limit exceeded")


def _contains(value, marker):
    pending = [value]
    while pending:
        node = pending.pop()
        if isinstance(node, str) and marker in node:
            return True
        if isinstance(node, dict):
            pending.extend(node.keys())
            pending.extend(node.values())
        elif isinstance(node, list):
            pending.extend(node)
    return False


async def _control(session, endpoint, state, headers, marker, origin=False):
    request_id = "policy-control"
    _sent(marker, endpoint, headers, request_id, "tools/list")
    async with session.request("POST", endpoint, headers={**headers, "Mcp-Method": "tools/list"},
                               json=live._message(request_id, "tools/list"),
                               timeout=aiohttp.ClientTimeout(total=live.REQUEST_TIMEOUT)) as response:
        if response.status == 200:
            result = await live._body(response, state, request_id)
            page = live._State(state.budget, schema_nodes=state.schema_nodes)
            await asyncio.to_thread(live._tools, result, page)
            state.schema_nodes = page.schema_nodes
            state.evaluated += 1
            return "confirmed" if marker in page.names else "inconclusive"
        if response.status not in {401, 403}:
            raise live.LiveError("MCP policy control returned an unexpected HTTP status")
        header_echo = any(marker in key or marker in value for key, value in response.headers.items())
        data = bytearray()
        async for chunk in response.content.iter_chunked(8192):
            state.total_bytes += len(chunk)
            if state.total_bytes > live.MAX_TOTAL_BYTES:
                raise live.LiveError("MCP total response limit exceeded")
            data.extend(chunk)
        if not data:
            state.evaluated += 1
            return "passed" if not header_echo and (not origin or response.status == 403) else "inconclusive"
        media = response.headers.get("Content-Type", "").split(";", 1)[0].strip().lower()
        if media != "application/json":
            raise live.LiveError("Unsupported MCP policy denial body")
        message = await asyncio.to_thread(live._decode, bytes(data))
        # A denial status cannot hide valid protected inventory in its body.
        if isinstance(message, dict) and "result" in message:
            result = live._rpc(message, request_id)
            page = live._State(state.budget, schema_nodes=state.schema_nodes)
            await asyncio.to_thread(live._tools, result, page)
            state.schema_nodes = page.schema_nodes
            state.evaluated += 1
            return "confirmed" if marker in page.names else "inconclusive"
        if (not isinstance(message, dict) or message.get("jsonrpc") != "2.0"
                or "method" in message or "result" in message
                or ("id" in message and message["id"] != request_id)
                or ("id" in message and type(message["id"]) is not str)
                or not isinstance(message.get("error"), dict)
                or type(message["error"].get("code")) is not int
                or not isinstance(message["error"].get("message"), str)):
            raise live.LiveError("Invalid MCP policy denial envelope")
        state.evaluated += 1
        if header_echo or marker.encode() in data or _contains(message, marker):
            return "inconclusive"
        return "passed" if not origin or response.status == 403 else "inconclusive"


def _record(rule, status, outcome, attempts=0, evaluated=0, reason=None, context=None):
    return CheckRecord(rule, rule + ".protected_inventory", live.PROTOCOL_VERSION + ":1",
                       status, outcome, attempts, evaluated, reason, context).to_dict()


def _finding(rule, context, endpoint):
    identity = hashlib.sha256(json.dumps([rule, endpoint, context]).encode()).hexdigest()[:20]
    return {"id": identity, "rule_id": rule, "ruleset_version": "1.0.0", "endpoint": endpoint,
            "probe_id": rule + ".protected_inventory", "probe_version": live.PROTOCOL_VERSION + ":1",
            "vulnerability_type": "mcp_protected_inventory_disclosure", "severity": "high",
            "evidence_status": "confirmed", "evidence_context_id": context,
            "control_status": "validated_positive_control",
            "description": _TEXT["origin_disclosure" if rule == "MCP.origin" else "auth_disclosure"],
            "remediation": _TEXT["remediation"],
            "confidence": 1.0, "source": "runtime_policy", "json_pointer": "/tools"}


def _version(policy):
    definition = {key: policy[key] for key in ("version", "endpoint", "fixture_provenance",
                                               "authorization_required", "evidence_context_id")}
    if "origins" in policy:
        definition["origins"] = policy["origins"]
    return live.PROTOCOL_VERSION + ":1:" + hashlib.sha256(json.dumps(definition, sort_keys=True).encode()).hexdigest()


async def check(endpoint, allowed_networks, policy, allow_loopback=False, api_key_env=None):
    """Check declared protected inventory controls, never tool execution or browsers."""
    scope, url = live._policy(endpoint, allowed_networks, allow_loopback)
    headers, secrets = live._headers(api_key_env)
    marker, origins = _validate(policy, endpoint, headers, api_key_env)
    secrets.update((marker, marker.replace("~", "~0").replace("/", "~1")))
    context = policy["evidence_context_id"]
    version = _version(policy)
    identities = [version, *(_finding(rule, context, endpoint)["id"] for rule in ("MCP.authorization", "MCP.origin"))]
    if any(secret in value for secret in secrets for value in identities):
        raise ValueError("MCP credential or protected name overlaps public evidence identity")
    budget = live._Budget(allowed_networks=tuple(str(value) for value in scope.allowed_networks),
                          allow_loopback=allow_loopback, max_requests=live.MAX_REQUESTS,
                          max_response_bytes=live.MAX_RESPONSE_BYTES,
                          plaintext_loopback_only=url.scheme == "http")
    state = live._State(budget)
    records, findings = [], []
    reason, baseline_valid = None, False
    active_control = None
    baseline_headers = {**headers, **({"Origin": origins["allowed"]} if origins else {})}

    async def run():
        nonlocal baseline_valid, active_control
        addresses = await asyncio.to_thread(scope.addresses, url.hostname)
        if url.scheme == "http" and any(not value.network_address.is_loopback for value in addresses):
            raise live.LiveError("Plaintext MCP requires loopback")
        with scan_transport(budget):
            async with SafeSession(cookie_jar=aiohttp.DummyCookieJar()) as session:
                await _baseline(session, endpoint, state, baseline_headers, marker)
            if marker not in state.names:
                records.append(_record("MCP.policy_baseline", "completed", "inconclusive", budget.requests,
                                       state.evaluated, _TEXT["baseline_missing"], context))
                return
            baseline_valid = True
            records.append(_record("MCP.policy_baseline", "completed", "inconclusive", budget.requests,
                                   state.evaluated, _TEXT["baseline_valid"], context))
            conditions = [("MCP.authorization", {key: value for key, value in baseline_headers.items()
                                                 if key != "Authorization"}, False)]
            if origins:
                conditions.append(("MCP.origin", {**baseline_headers, "Origin": origins["denied"]}, True))
            for rule, control_headers, origin in conditions:
                before = (budget.requests, state.evaluated)
                active_control = (rule, before)
                try:
                    async with SafeSession(cookie_jar=aiohttp.DummyCookieJar()) as session:
                        outcome = await _control(session, endpoint, state, control_headers, marker, origin)
                except (live.LiveError, TransportPolicyError, aiohttp.ClientError, TimeoutError,
                        asyncio.TimeoutError, ValueError, TypeError, RecursionError):
                    records.append(_record(rule, "failed", "inconclusive", budget.requests - before[0],
                                           state.evaluated - before[1], _TEXT["control_unusable"], context))
                    active_control = None
                    continue
                records.append(_record(rule, "completed", outcome, budget.requests - before[0],
                                       state.evaluated - before[1],
                                       _TEXT["control_sample"], context))
                if outcome == "confirmed":
                    findings.append(_finding(rule, context, endpoint))
                active_control = None

    try:
        await asyncio.wait_for(run(), timeout=live.OVERALL_TIMEOUT)
    except ScopeResolutionError:
        reason = "MCP endpoint hostname could not be resolved"
    except aiohttp.ClientConnectorCertificateError:
        reason = "MCP TLS certificate verification failed"
    except aiohttp.ClientSSLError:
        reason = "MCP TLS negotiation failed"
    except (live.LiveError, ScopeValidationError, TransportPolicyError, aiohttp.ClientError,
            TimeoutError, asyncio.TimeoutError, ValueError, TypeError, RecursionError):
        reason = _TEXT["baseline_failed"]
    if active_control:
        rule, before = active_control
        records.append(_record(rule, "failed", "inconclusive", budget.requests - before[0],
                               state.evaluated - before[1], _TEXT["deadline"], context))
    if not records:
        records.append(_record("MCP.policy_baseline", "failed", "inconclusive", budget.requests,
                               state.evaluated, reason, context))
    for rule in ("MCP.authorization", "MCP.origin"):
        if not any(record["rule_id"] == rule for record in records):
            if rule == "MCP.origin" and not origins:
                records.append(_record(rule, "skipped", "not_evaluated", reason=_TEXT["origin_missing"], context=context))
            elif not baseline_valid:
                records.append(_record(rule, "skipped", "not_evaluated", reason=_TEXT["prerequisite"], context=context))
            else:
                records.append(_record(rule, "failed", "inconclusive", reason=_TEXT["deadline"], context=context))
    records.append(_record("MCP.tool_execution", "skipped", "not_evaluated",
                           reason=_TEXT["execution"], context=context))
    for item in records + findings:
        item["probe_version"] = version
    failed = reason or any(record["status"] == "failed" for record in records)
    report = {"ruleset_version": "1.0.0", "mode": "live_policy_checks", "endpoint": endpoint,
              "protocol_version": live.PROTOCOL_VERSION, "check_schema_version": CHECK_SCHEMA_VERSION,
              "status": "partial" if failed and state.evaluated else "failed" if failed else "completed",
              "risk_assessment_status": "not_assessed", "evidence_context_id": context,
              "requests_attempted": budget.requests, "responses_evaluated": state.evaluated,
              "response_bytes": state.total_bytes, "reason": reason, "checks": records,
              "findings": findings, "observations": [],
              "limitations": list(_LIMITATIONS)}
    public = redact_secrets(report, secrets)
    validate_checks(public["checks"])
    return public
