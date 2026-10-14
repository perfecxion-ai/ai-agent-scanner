"""Read-only, bounded MCP 2026-07-28 Streamable HTTP inventory."""

import asyncio
import hashlib
import ipaddress
import json
import math
import os
import re
from dataclasses import dataclass, field
from urllib.parse import urlsplit

import aiohttp
from jsonschema import Draft202012Validator, SchemaError

from src.core.contracts import CHECK_SCHEMA_VERSION, CheckRecord
from src.core.redaction import redact_secrets
from src.core.scope import ScopePolicy, ScopeValidationError
from src.core.transport import SafeSession, ScanBudget, TransportPolicyError, scan_transport
from src.mcp.assessment import _unique_object, assess


PROTOCOL_VERSION = "2026-07-28"
MAX_REQUESTS = 32
MAX_RESPONSE_BYTES = 1024 * 1024
MAX_TOTAL_BYTES = 4 * 1024 * 1024
MAX_PAGES = 10
MAX_TOOLS = 200
MAX_CURSOR_BYTES = 4096
MAX_SCHEMA_DEPTH = 32
MAX_SCHEMA_NODES = 10000
OVERALL_TIMEOUT = 20
REQUEST_TIMEOUT = 5
MAX_EVENTS = 256
SCHEMA_DIALECT = "https://json-schema.org/draft/2020-12/schema"
_ENV_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")
_HEADER_TOKEN = re.compile(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+\Z")


class LiveError(ValueError):
    """Fixed public reason, never a server-supplied error message."""


@dataclass
class _Budget(ScanBudget):
    plaintext_loopback_only: bool = False

    def check_address(self, address):
        super().check_address(address)
        if self.plaintext_loopback_only and not ipaddress.ip_address(address).is_loopback:
            raise TransportPolicyError("Plaintext MCP requires loopback")


@dataclass
class _State:
    budget: ScanBudget
    total_bytes: int = 0
    evaluated: int = 0
    pages: int = 0
    schema_nodes: int = 0
    tools: list = field(default_factory=list)
    names: set = field(default_factory=set)


def _decode(data):
    def finite_float(value):
        number = float(value)
        if not math.isfinite(number):
            raise ValueError()
        return number
    try:
        return json.loads(data.decode("utf-8"), object_pairs_hook=_unique_object,
                          parse_float=finite_float,
                          parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
    except (ValueError, UnicodeError, RecursionError):
        raise LiveError("Invalid MCP JSON") from None


def _rpc(message, request_id):
    if (not isinstance(message, dict) or message.get("jsonrpc") != "2.0"
            or "method" in message or type(message.get("id")) is not type(request_id)
            or message.get("id") != request_id
            or ("result" in message) == ("error" in message)):
        raise LiveError("Invalid MCP response envelope")
    if "error" in message:
        error = message["error"]
        if not isinstance(error, dict) or type(error.get("code")) is not int or not isinstance(error.get("message"), str):
            raise LiveError("Invalid MCP error envelope")
        if error["code"] == -32022:
            raise LiveError("Unsupported MCP protocol version")
        raise LiveError("MCP request rejected")
    result = message["result"]
    if not isinstance(result, dict) or result.get("resultType", "complete") != "complete":
        raise LiveError("Incomplete or unsupported MCP result")
    return result


def _notification(message):
    # No capabilities or progress tokens are advertised, and no data is exported.
    return (isinstance(message, dict) and message.get("jsonrpc") == "2.0"
            and "id" not in message and "result" not in message and "error" not in message
            and message.get("method") in {"notifications/message", "notifications/progress"}
            and isinstance(message.get("params", {}), dict))


async def _body(response, state, request_id):
    media = response.headers.get("Content-Type", "").split(";", 1)[0].strip().lower()
    if media not in {"application/json", "text/event-stream"}:
        raise LiveError("Unsupported MCP response content type")
    data = bytearray()
    event_lines = []
    events = 0
    skip_lf = False
    first_line = True

    async def consume_event():
        nonlocal events
        if not event_lines:
            return None
        events += 1
        if events > MAX_EVENTS:
            raise LiveError("MCP stream event limit exceeded")
        message = await asyncio.to_thread(_decode, b"\n".join(event_lines))
        event_lines.clear()
        if _notification(message):
            return None
        return _rpc(message, request_id)

    async for chunk in response.content.iter_chunked(8192):
        state.total_bytes += len(chunk)
        if state.total_bytes > MAX_TOTAL_BYTES:
            raise LiveError("MCP total response limit exceeded")
        if skip_lf:
            if chunk.startswith(b"\n"):
                chunk = chunk[1:]
            skip_lf = False
        data.extend(chunk)
        if media == "application/json":
            continue
        while b"\n" in data or b"\r" in data:
            positions = [value for value in (data.find(b"\n"), data.find(b"\r")) if value >= 0]
            position = min(positions)
            line = bytes(data[:position])
            is_cr = data[position] == 13
            end = position + 1
            if is_cr and end < len(data) and data[end] == 10:
                end += 1
            elif is_cr and end == len(data):
                skip_lf = True
            data = data[end:]
            if first_line:
                line = line.removeprefix(b"\xef\xbb\xbf")
                first_line = False
            if not line:
                result = await consume_event()
                if result is not None:
                    return result
            elif line.startswith(b"data:"):
                value = line[5:]
                event_lines.append(value[1:] if value.startswith(b" ") else value)
            elif line == b"data":
                event_lines.append(b"")
            # SSE comments, event, id, retry and unknown fields do not execute.
    if media == "text/event-stream":
        raise LiveError("MCP stream ended without a complete response")
    return _rpc(await asyncio.to_thread(_decode, bytes(data)), request_id)


async def _request(session, endpoint, method, state, headers, cursor=None):
    request_id = f"inventory-{state.budget.requests + 1}"
    params = {"_meta": {
        "io.modelcontextprotocol/protocolVersion": PROTOCOL_VERSION,
        "io.modelcontextprotocol/clientInfo": {"name": "ai-agent-scanner", "version": "1.1.0"},
        "io.modelcontextprotocol/clientCapabilities": {},
    }}
    if cursor is not None:
        params["cursor"] = cursor
    request_headers = {**headers, "Mcp-Method": method}
    async with session.request("POST", endpoint, headers=request_headers,
                               json={"jsonrpc": "2.0", "id": request_id, "method": method, "params": params},
                               timeout=aiohttp.ClientTimeout(total=REQUEST_TIMEOUT)) as response:
        if response.status in {401, 403}:
            raise LiveError("MCP access denied; inventory not evaluated")
        if response.status != 200:
            # An error body cannot establish inventory; never expose its message.
            if response.status == 400:
                await _body(response, state, request_id)
            raise LiveError("MCP HTTP request rejected")
        result = await _body(response, state, request_id)
        state.evaluated += 1
        return result


def _bounded_schema(schema, state):
    pending = [(schema, 0)]
    while pending:
        node, depth = pending.pop()
        state.schema_nodes += 1
        if depth > MAX_SCHEMA_DEPTH or state.schema_nodes > MAX_SCHEMA_NODES:
            raise LiveError("MCP schema complexity limit exceeded")
        if isinstance(node, dict):
            pending.extend((value, depth + 1) for value in node.values())
        elif isinstance(node, list):
            pending.extend((value, depth + 1) for value in node)


def _schema(schema, state, input_schema=True):
    if not isinstance(schema, dict) or (input_schema and schema.get("type") != "object"):
        raise LiveError("Invalid MCP tool schema")
    _bounded_schema(schema, state)
    # Validate the syntax, not tool instances. check_schema uses bundled metaschemas.
    # No reference resolution or instance execution occurs here.
    dialect = schema.get("$schema", SCHEMA_DIALECT)
    if not isinstance(dialect, str) or dialect.rstrip("#") != SCHEMA_DIALECT:
        raise LiveError("Unsupported MCP schema dialect")
    try:
        Draft202012Validator.check_schema(schema)
    except (SchemaError, ValueError, RecursionError, TypeError, OverflowError):
        raise LiveError("Invalid MCP tool schema") from None
    headers = set()
    pending = [(schema, True)]
    while pending:
        node, reachable = pending.pop()
        if not isinstance(node, dict):
            continue
        if "$schema" in node and (not isinstance(node["$schema"], str) or node["$schema"].rstrip("#") != SCHEMA_DIALECT):
            raise LiveError("Unsupported MCP schema dialect")
        if input_schema and "x-mcp-header" in node:
            value = node["x-mcp-header"]
            if (not reachable or not isinstance(value, str) or not _HEADER_TOKEN.fullmatch(value)
                    or value.lower() in headers or node.get("type") not in {"string", "integer", "boolean"}):
                raise LiveError("Invalid MCP schema header annotation")
            headers.add(value.lower())
        for key in ("properties", "patternProperties", "$defs", "dependentSchemas"):
            if isinstance(node.get(key), dict):
                pending.extend((child, reachable and key == "properties") for child in node[key].values())
        for key in ("items", "additionalProperties", "unevaluatedProperties", "unevaluatedItems", "contains", "not", "if", "then", "else", "propertyNames", "contentSchema"):
            if isinstance(node.get(key), dict):
                pending.append((node[key], False))
        for key in ("anyOf", "oneOf", "allOf", "prefixItems"):
            if isinstance(node.get(key), list):
                pending.extend((child, False) for child in node[key])


def _tools(result, state):
    tools = result.get("tools")
    if not isinstance(tools, list) or len(state.tools) + len(tools) > MAX_TOOLS:
        raise LiveError("Invalid or excessive MCP tool inventory")
    names = set(state.names)
    for tool in tools:
        if (not isinstance(tool, dict) or not isinstance(tool.get("name"), str)
                or not tool["name"] or len(tool["name"]) > 128 or tool["name"] in names):
            raise LiveError("Invalid or duplicate MCP tool name")
        names.add(tool["name"])
        for key in ("description", "title"):
            if key in tool and not isinstance(tool[key], str):
                raise LiveError("Invalid MCP tool metadata")
        if "annotations" in tool:
            annotations = tool["annotations"]
            if not isinstance(annotations, dict):
                raise LiveError("Invalid MCP tool metadata")
            for key in ("readOnlyHint", "destructiveHint", "idempotentHint", "openWorldHint"):
                if key in annotations and not isinstance(annotations[key], bool):
                    raise LiveError("Invalid MCP tool metadata")
            if "title" in annotations and not isinstance(annotations["title"], str):
                raise LiveError("Invalid MCP tool metadata")
        _schema(tool.get("inputSchema"), state)
        if "outputSchema" in tool:
            _schema(tool["outputSchema"], state, input_schema=False)
    cursor = result.get("nextCursor")
    if cursor is not None and (not isinstance(cursor, str) or len(cursor.encode("utf-8")) > MAX_CURSOR_BYTES):
        raise LiveError("Invalid or excessive MCP pagination cursor")
    # Only append after validating the entire page. Prior pages survive failures.
    state.tools.extend(tools)
    state.names = names
    state.pages += 1
    return cursor


def _headers(api_key_env):
    headers = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream",
               "MCP-Protocol-Version": PROTOCOL_VERSION}
    secrets = set()
    if api_key_env is not None:
        if not isinstance(api_key_env, str) or not _ENV_NAME.fullmatch(api_key_env):
            raise ValueError("Invalid MCP credential environment variable name")
        value = os.environ.get(api_key_env)
        if (not value or len(value) > 8192
                or any(not 0x21 <= ord(char) <= 0x7e for char in value)):
            raise ValueError("MCP credential is missing or not a visible ASCII token")
        headers["Authorization"] = f"Bearer {value}"
        secrets.update((value, f"Bearer {value}"))
        # Schema field names become escaped JSON Pointer components in findings.
        # Remove those representations before computing public observation IDs.
        secrets.update(secret.replace("~", "~0").replace("/", "~1") for secret in tuple(secrets))
    return headers, secrets


def _policy(endpoint, allowed_networks, allow_loopback):
    if not allowed_networks or not isinstance(allow_loopback, bool):
        raise ValueError("MCP live inventory requires explicit allowed CIDRs")
    if not isinstance(endpoint, str) or len(endpoint) > 4096 or any(ord(char) <= 32 or ord(char) == 127 for char in endpoint):
        raise ValueError("Invalid MCP endpoint")
    try:
        url = urlsplit(endpoint)
        port = url.port
    except ValueError:
        raise ValueError("Invalid MCP endpoint") from None
    if (url.scheme not in {"http", "https"} or not url.hostname or url.username is not None
            or url.password is not None or url.query or url.fragment
            or (port is not None and not 1 <= port <= 65535)):
        raise ValueError("MCP endpoint must be HTTP(S) without credentials, query, or fragment")
    policy = ScopePolicy.from_config({"SCAN_ALLOWED_NETWORKS": allowed_networks,
                                      "SCAN_ALLOW_LOOPBACK": allow_loopback})
    for value in allowed_networks:
        policy.network(value)
    return policy, url


async def inventory(endpoint, allowed_networks, allow_loopback=False, api_key_env=None):
    """Return bounded inventory and heuristic schema observations, never call tools."""
    policy, url = _policy(endpoint, allowed_networks, allow_loopback)
    headers, secrets = _headers(api_key_env)
    budget = _Budget(allowed_networks=tuple(str(value) for value in policy.allowed_networks),
                     allow_loopback=allow_loopback, max_requests=MAX_REQUESTS,
                     max_response_bytes=MAX_RESPONSE_BYTES, plaintext_loopback_only=url.scheme == "http")
    state = _State(budget)
    reason = None
    unsupported = False

    async def collect():
        nonlocal unsupported
        addresses = await asyncio.to_thread(policy.addresses, url.hostname)
        if url.scheme == "http" and any(not value.network_address.is_loopback for value in addresses):
            raise LiveError("Plaintext MCP requires loopback")
        with scan_transport(budget):
            async with SafeSession(cookie_jar=aiohttp.DummyCookieJar()) as session:
                discovery = await _request(session, endpoint, "server/discover", state, headers)
                versions = discovery.get("supportedVersions")
                capabilities = discovery.get("capabilities")
                if (not isinstance(versions, list) or not versions or len(versions) > 32
                        or not all(isinstance(value, str) and len(value) <= 32 for value in versions)
                        or not isinstance(capabilities, dict)):
                    raise LiveError("Invalid MCP discovery result")
                if PROTOCOL_VERSION not in versions:
                    raise LiveError("Unsupported MCP protocol version")
                for key in ("tools", "resources", "prompts", "logging", "completions", "extensions"):
                    if key in capabilities and not isinstance(capabilities[key], dict):
                        raise LiveError("Invalid MCP server capability")
                tools_capability = capabilities.get("tools")
                if tools_capability is None:
                    unsupported = True
                    return
                if "listChanged" in tools_capability and not isinstance(tools_capability["listChanged"], bool):
                    raise LiveError("Invalid MCP tools capability")
                cursor = None
                seen = set()
                for _ in range(MAX_PAGES):
                    result = await _request(session, endpoint, "tools/list", state, headers, cursor)
                    # Validation runs off the event loop against disposable state.
                    # A timed-out thread cannot later mutate the returned report.
                    page_state = _State(budget, schema_nodes=state.schema_nodes,
                                        tools=list(state.tools), names=set(state.names), pages=state.pages)
                    cursor = await asyncio.to_thread(_tools, result, page_state)
                    state.tools, state.names = page_state.tools, page_state.names
                    state.pages, state.schema_nodes = page_state.pages, page_state.schema_nodes
                    if cursor is None:
                        return
                    if cursor in seen:
                        raise LiveError("Repeated MCP pagination cursor")
                    seen.add(cursor)
                raise LiveError("MCP pagination limit exceeded")

    try:
        await asyncio.wait_for(collect(), timeout=OVERALL_TIMEOUT)
    except LiveError as exc:
        reason = str(exc)
    except ScopeValidationError:
        reason = "MCP endpoint is outside the allowed scope"
    except TransportPolicyError:
        reason = "MCP transport policy rejected inventory"
    except (aiohttp.ClientError, TimeoutError, asyncio.TimeoutError):
        reason = "MCP transport failed or timed out"
    except (ValueError, TypeError, RecursionError):
        reason = "Invalid MCP inventory response"
    status = "partial" if reason and state.evaluated else "failed" if reason else "completed"
    check_status = "failed" if reason else "skipped" if unsupported else "completed"
    report = assess(tools={"tools": state.tools})
    report.update(mode="live_inventory", protocol_version=PROTOCOL_VERSION, endpoint=endpoint,
                  status=status, tools_assessed=len(state.tools), pages_assessed=state.pages,
                  servers_assessed=1 if state.evaluated else 0,
                  check_schema_version=CHECK_SCHEMA_VERSION, risk_assessment_status="not_assessed",
                  requests_attempted=budget.requests, responses_evaluated=state.evaluated,
                  response_bytes=state.total_bytes, reason=reason,
                  checks=[CheckRecord("MCP.inventory", "MCP.inventory.readonly", "2026-07-28:1",
                                      check_status, "not_evaluated" if unsupported else "inconclusive",
                                      budget.requests, 0 if unsupported else state.evaluated,
                                      reason or ("Server does not advertise tools" if unsupported else
                                                 "Inventory does not verify runtime security")).to_dict()])
    for rule in ("MCP.authorization", "MCP.origin", "MCP.tool_execution"):
        report["checks"].append(CheckRecord(rule, rule + ".unsupported", "2026-07-28:1",
                                            "skipped", "not_evaluated", reason="Runtime probe not implemented").to_dict())
    report["limitations"] = [
        "Only MCP 2026-07-28 server/discover and tools/list over Streamable HTTP are supported.",
        "Inventory and public schema observations do not verify security or exploitability.",
        "No commands, tools, resource reads, subscriptions, or OAuth discovery are executed.",
        "No legacy initialization, protocol sessions, GET fallback, or SSE resumption is supported.",
        "JSON Schema 2020-12 syntax is checked with bounded depth/nodes; references are not resolved.",
        "Server instructions, descriptions, annotations, icons and identity are untrusted data.",
        "Authorization, Origin enforcement, sandboxing and tool behavior are not tested.",
    ]
    public = redact_secrets(report, secrets)
    for finding in public["findings"] + public["observations"]:
        # Do not retain a digest of a credential echoed into a schema field name.
        identity = f'{finding["rule_id"]}:{finding["source"]}:{finding["json_pointer"]}'
        finding["id"] = hashlib.sha256(identity.encode()).hexdigest()[:20]
    return public
