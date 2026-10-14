"""Real loopback acceptance for bounded, read-only MCP protocol inventory."""

import asyncio
import hashlib
import json
import socket
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import patch

import pytest
from click.testing import CliRunner

from scanner_cli import cli
from src.core.scope import ScopePolicy
from src.core.transport import PolicyResolver
from src.mcp import to_sarif
from src.mcp import live


def tool(name="public_tool", **schema):
    return {"name": name, "inputSchema": {"type": "object", "properties": {}, **schema}}


def discovery(**values):
    return {"supportedVersions": [live.PROTOCOL_VERSION], "capabilities": {"tools": {}}, **values}


def result(request, payload):
    return {"jsonrpc": "2.0", "id": request["id"], "result": payload}


@pytest.fixture
def server():
    requests = []
    state = {"dispatch": lambda request, headers: result(request, discovery() if request["method"] == "server/discover" else {"tools": [tool()]})}

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_POST(self):
            request = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            requests.append((request, dict(self.headers)))
            response = state["dispatch"](request, self.headers)
            status, headers, body = response if isinstance(response, tuple) else (200, {"Content-Type": "application/json"}, json.dumps(response).encode())
            self.send_response(status)
            for name, value in headers.items():
                self.send_header(name, value)
            if not callable(body):
                self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            try:
                if callable(body):
                    body(self.wfile)
                else:
                    self.wfile.write(body)
            except (BrokenPipeError, ConnectionResetError):
                pass

        def do_GET(self):
            requests.append(("GET", dict(self.headers)))
            self.send_response(405)
            self.end_headers()

    http = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=http.serve_forever, kwargs={"poll_interval": .01}, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{http.server_port}/mcp", state, requests
    http.shutdown()
    http.server_close()
    thread.join(timeout=2)


@pytest.fixture(autouse=True)
def no_process_execution():
    with patch.object(subprocess, "Popen", side_effect=AssertionError("Process launch forbidden")):
        yield


def collect(server, **kwargs):
    return asyncio.run(live.inventory(server[0], ("127.0.0.1/32",), allow_loopback=True, **kwargs))


def test_complete_inventory_is_not_a_security_pass(server):
    report = collect(server)
    assert report["status"] == "completed"
    assert report["mode"] == "live_inventory"
    assert report["tools_assessed"] == 1
    assert report["requests_attempted"] == report["responses_evaluated"] == 2
    assert report["risk_assessment_status"] == "not_assessed"
    assert report["checks"][0]["outcome"] == "inconclusive"
    assert all(check["outcome"] != "passed" for check in report["checks"])
    assert all(check["status"] == "skipped" for check in report["checks"][1:])
    for request, headers in server[2]:
        assert request["method"] in {"server/discover", "tools/list"}
        assert request["params"]["_meta"]["io.modelcontextprotocol/protocolVersion"] == live.PROTOCOL_VERSION
        assert request["params"]["_meta"]["io.modelcontextprotocol/clientCapabilities"] == {}
        assert headers["MCP-Protocol-Version"] == live.PROTOCOL_VERSION
        assert headers["Mcp-Method"] == request["method"]
        assert "MCP-Session-Id" not in headers
        assert "Authorization" not in headers
    sarif = to_sarif(report)
    assert sarif["runs"][0]["properties"]["mode"] == "live_inventory"
    assert sarif["runs"][0]["properties"]["checks"] == report["checks"]


def test_live_schema_observations_do_not_export_raw_untrusted_data(server):
    secret = "fixture-server-message-never-export"
    def dispatch(request, headers):
        data = discovery(instructions=secret, _meta={"io.modelcontextprotocol/serverInfo": {"name": secret}}) if request["method"] == "server/discover" else {
            "tools": [{**tool(properties={"command": {"type": "string"}}), "description": secret,
                       "icons": [{"src": "http://forbidden.example/icon"}], "annotations": {"readOnlyHint": True}}]}
        return result(request, data)
    server[1]["dispatch"] = dispatch
    with patch.object(socket, "getaddrinfo", side_effect=AssertionError("Secondary resolution forbidden")):
        report = collect(server)
    assert report["status"] == "completed"
    assert report["findings"] == []
    assert report["observations"][0]["rule_id"] == "MCP006"
    rendered = json.dumps(report)
    assert secret not in rendered and "forbidden.example" not in rendered
    assert len(server[2]) == 2


def test_sse_notifications_and_multiline_final_response(server):
    def dispatch(request, headers):
        data = discovery() if request["method"] == "server/discover" else {"resultType": "complete", "tools": [tool()]}
        notification = json.dumps({"jsonrpc": "2.0", "method": "notifications/message", "params": {"data": "ignored"}})
        payload = json.dumps(result(request, data), indent=2)
        body = ": keepalive\r\n\r\nevent: message\r\ndata: " + notification + "\r\n\r\n" + "\r\n".join("data: " + line for line in payload.splitlines()) + "\r\n\r\n"
        return 200, {"Content-Type": "text/event-stream; charset=utf-8"}, body.encode()
    server[1]["dispatch"] = dispatch
    assert collect(server)["status"] == "completed"


@pytest.mark.parametrize("separator", [b"\n", b"\r\n", b"\r"])
def test_sse_line_separators_utf8_bom_and_chunk_boundaries(server, separator):
    def dispatch(request, headers):
        data = discovery() if request["method"] == "server/discover" else {"tools": []}
        body = b"\xef\xbb\xbfdata: " + json.dumps(result(request, data)).encode() + separator + separator
        def streamed(stream):
            for byte in body:
                stream.write(bytes([byte]))
                stream.flush()
        return 200, {"Content-Type": "text/event-stream"}, streamed
    server[1]["dispatch"] = dispatch
    report = collect(server)
    assert report["status"] == "completed" and report["tools_assessed"] == 0


def test_valid_page_survives_later_malformed_page(server):
    def dispatch(request, headers):
        if request["method"] == "server/discover":
            data = discovery()
        elif "cursor" not in request["params"]:
            data = {"tools": [tool(properties={"command": {"type": "string"}})], "nextCursor": "private-cursor"}
        else:
            data = {"tools": [{"name": "invalid"}]}
        return result(request, data)
    server[1]["dispatch"] = dispatch
    report = collect(server)
    assert report["status"] == "partial" and report["tools_assessed"] == 1
    assert report["pages_assessed"] == 1 and len(report["observations"]) == 1
    assert "private-cursor" not in json.dumps(report)


def test_empty_cursor_is_paginated_and_not_exported(server):
    def dispatch(request, headers):
        if request["method"] == "server/discover":
            return result(request, discovery())
        if "cursor" not in request["params"]:
            return result(request, {"tools": [tool("first")], "nextCursor": ""})
        assert request["params"]["cursor"] == ""
        return result(request, {"tools": [tool("second")]})
    server[1]["dispatch"] = dispatch
    report = collect(server)
    assert report["status"] == "completed" and report["tools_assessed"] == 2
    assert report["pages_assessed"] == 2 and len(server[2]) == 3
    assert "nextCursor" not in json.dumps(report)


def test_repeated_empty_cursor_preserves_previous_valid_pages(server):
    def dispatch(request, headers):
        return result(request, discovery() if request["method"] == "server/discover" else {
            "tools": [tool(str(len(server[2])))], "nextCursor": ""})
    server[1]["dispatch"] = dispatch
    report = collect(server)
    assert report["status"] == "partial"
    assert report["tools_assessed"] == 2 and report["pages_assessed"] == 2
    assert report["reason"] == "Repeated MCP pagination cursor"


@pytest.mark.parametrize("payload", [[], {}, {"jsonrpc": "1.0", "id": "inventory-1", "result": {}},
    {"jsonrpc": "2.0", "id": 1, "result": {}},
    {"jsonrpc": "2.0", "id": "inventory-2", "result": {}},
    {"jsonrpc": "2.0", "id": "inventory-1", "result": {}, "error": {}},
    {"jsonrpc": "2.0", "id": "inventory-1", "method": "sampling/createMessage", "params": {}},
    {"jsonrpc": "2.0", "id": "inventory-1", "error": {"code": True, "message": "never-export"}},
    {"jsonrpc": "2.0", "id": "inventory-1", "result": {"resultType": "input_required"}},
    {"jsonrpc": "2.0", "id": "inventory-1", "result": {"resultType": "unknown"}}])
def test_bad_rpc_envelopes_are_not_success(server, payload):
    server[1]["dispatch"] = lambda request, headers: payload
    report = collect(server)
    assert report["status"] == "failed" and report["tools_assessed"] == 0
    assert "never-export" not in json.dumps(report)


@pytest.mark.parametrize("body", [b'{"jsonrpc":"2.0","id":"inventory-1","id":"inventory-1","result":{}}',
    b'{"jsonrpc":"2.0","id":"inventory-1","result":{"a":NaN}}',
    b'{"jsonrpc":"2.0","id":"inventory-1","result":{"a":1e999}}', b'\xff', b'{', b'[' * 1100 + b']' * 1100])
def test_invalid_json_and_duplicate_keys_fail(server, body):
    server[1]["dispatch"] = lambda request, headers: (200, {"Content-Type": "application/json"}, body)
    assert collect(server)["status"] == "failed"


@pytest.mark.parametrize("data", [discovery(supportedVersions=[]), discovery(supportedVersions=["2025-11-25"]),
    discovery(supportedVersions=[True]), discovery(capabilities=[]), discovery(capabilities={"tools": []}),
    discovery(capabilities={"tools": {"listChanged": 1}})])
def test_invalid_discovery_and_legacy_do_not_trigger_fallback(server, data):
    server[1]["dispatch"] = lambda request, headers: result(request, data)
    report = collect(server)
    assert report["status"] == "partial" and len(server[2]) == 1
    assert not any(request["method"] == "initialize" for request, _ in server[2])


def test_no_tools_capability_is_an_explicit_skipped_prerequisite(server):
    server[1]["dispatch"] = lambda request, headers: result(request, discovery(capabilities={"resources": {}}))
    report = collect(server)
    assert report["status"] == "completed" and len(server[2]) == 1
    assert report["checks"][0]["status"] == "skipped"
    assert report["checks"][0]["outcome"] == "not_evaluated"


@pytest.mark.parametrize("status", [202, 301, 302, 400, 401, 403, 404, 405, 500])
def test_http_failure_is_not_inventory_and_no_redirect_or_get(server, status):
    server[1]["dispatch"] = lambda request, headers: (status, {"Content-Type": "application/json", "Location": "http://forbidden.example", "WWW-Authenticate": 'Bearer resource_metadata="http://forbidden.example"'}, b'{"message":"fixture-private-server-message"}')
    report = collect(server)
    assert report["status"] == "failed" and len(server[2]) == 1
    assert "fixture-private-server-message" not in json.dumps(report)


def test_modern_unsupported_version_error_is_fixed_and_no_retry(server):
    server[1]["dispatch"] = lambda request, headers: (400, {"Content-Type": "application/json"}, json.dumps({
        "jsonrpc": "2.0", "id": request["id"], "error": {"code": -32022, "message": "private-message", "data": {"supported": ["private-version"]}}}).encode())
    report = collect(server)
    assert report["reason"] == "Unsupported MCP protocol version"
    assert "private-" not in json.dumps(report)


@pytest.mark.parametrize("data", [{"tools": {}}, {"tools": [tool(), tool()]}, {"tools": [{"name": "bad"}]},
    {"tools": [tool(properties={"x": {"type": "not-a-type"}})]},
    {"tools": [tool(**{"$schema": "http://json-schema.org/draft-07/schema#"})]},
    {"tools": [tool(**{"$schema": 2})]}, {"tools": [], "nextCursor": 2},
    {"tools": [], "nextCursor": "x" * 4097},
    {"tools": [tool(properties={"url": {"type": "string", "x-mcp-header": "bad\r\nheader"}})]},
    {"tools": [tool(properties={"url": {"type": "string", "x-mcp-header": "Name"}, "path": {"type": "string", "x-mcp-header": "name"}})]},
    {"tools": [tool(anyOf=[{"type": "string", "x-mcp-header": "Name"}])]}])
def test_invalid_tools_schemas_and_cursors_are_partial_not_clean(server, data):
    server[1]["dispatch"] = lambda request, headers: result(request, discovery() if request["method"] == "server/discover" else data)
    report = collect(server)
    assert report["status"] == "partial" and report["tools_assessed"] == 0
    assert report["checks"][0]["status"] == "failed"


def test_external_schema_reference_is_never_fetched(server):
    remote = "http://forbidden.example/schema"
    server[1]["dispatch"] = lambda request, headers: result(request, discovery() if request["method"] == "server/discover" else {
        "tools": [tool(properties={"value": {"$ref": remote}})]})
    with patch.object(socket, "getaddrinfo", side_effect=AssertionError("Reference resolution forbidden")):
        report = collect(server)
    assert report["status"] == "completed" and remote not in json.dumps(report)
    assert len(server[2]) == 2


@pytest.mark.parametrize("schema", [{"type": "array", "items": {"type": "string"}},
    {"type": "string"}, {"type": "number"}, {"type": "boolean"}, {"type": "null"}, {},
    {"type": "array", "items": {"type": "string", "x-mcp-header": "not-an-input-header"}}])
def test_output_schemas_accept_arbitrary_structured_json_types(server, schema):
    server[1]["dispatch"] = lambda request, headers: result(request, discovery() if request["method"] == "server/discover" else {
        "tools": [{**tool(), "outputSchema": schema}]})
    report = collect(server)
    assert report["status"] == "completed" and report["tools_assessed"] == 1
    assert report["checks"][0]["outcome"] == "inconclusive"


@pytest.mark.parametrize("secret", ["fixture-live-bearer-never-export", "fixture/live/token", "fixture~live~token", "fixture~/live/~token"])
def test_credential_echo_in_schema_pointer_and_cookie_never_persist(server, monkeypatch, secret):
    monkeypatch.setenv("MCP_FIXTURE_TOKEN", secret)
    def dispatch(request, headers):
        assert headers["Authorization"] == "Bearer " + secret
        assert "Cookie" not in headers
        data = discovery() if request["method"] == "server/discover" else {
            "tools": [tool(properties={"options": {"type": "object", "properties": {secret: {"type": "object", "properties": {"command": {"type": "string"}}}}}})]}
        return 200, {"Content-Type": "application/json", "Set-Cookie": "auth=" + secret, "MCP-Session-Id": secret}, json.dumps(result(request, data)).encode()
    server[1]["dispatch"] = dispatch
    report = collect(server, api_key_env="MCP_FIXTURE_TOKEN")
    assert report["status"] == "completed"
    assert report["observations"] and "[redacted]" in json.dumps(report)
    assert secret not in json.dumps(report) and secret not in json.dumps(to_sarif(report))
    escaped = secret.replace("~", "~0").replace("/", "~1")
    assert escaped not in json.dumps(report) and escaped not in json.dumps(to_sarif(report))
    finding = report["observations"][0]
    public_identity = f'{finding["rule_id"]}:{finding["source"]}:{finding["json_pointer"]}'
    assert finding["id"] == hashlib.sha256(public_identity.encode()).hexdigest()[:20]


@pytest.mark.parametrize("env,value", [("BAD\nNAME", "token"), ("MCP_FIXTURE_TOKEN", None),
    ("MCP_FIXTURE_TOKEN", ""), ("MCP_FIXTURE_TOKEN", "token\r\nHeader:value"),
    ("MCP_FIXTURE_TOKEN", "token with space"), ("MCP_FIXTURE_TOKEN", "nonascii-\u00e9")])
def test_missing_or_unsafe_credentials_rejected_before_http(server, monkeypatch, env, value):
    if value is not None:
        monkeypatch.setenv(env, value)
    else:
        monkeypatch.delenv(env, raising=False)
    with pytest.raises(ValueError):
        collect(server, api_key_env=env)
    assert server[2] == []


@pytest.mark.parametrize("suffix", ["?token=x", "#fragment", "?ordinary=value"])
def test_query_and_fragment_urls_rejected(server, suffix):
    with pytest.raises(ValueError):
        asyncio.run(live.inventory(server[0] + suffix, ("127.0.0.1/32",), True))
    assert server[2] == []


def test_explicit_allowlist_and_loopback_opt_in_required(server):
    with pytest.raises(ValueError):
        asyncio.run(live.inventory(server[0], ()))
    with pytest.raises(ValueError):
        asyncio.run(live.inventory(server[0], ("127.0.0.1/32",)))
    report = asyncio.run(live.inventory(server[0], ("10.0.0.0/8",), True))
    assert report["status"] == "failed" and report["requests_attempted"] == 0
    assert server[2] == []


def test_plaintext_remote_address_is_rejected_before_http():
    report = asyncio.run(live.inventory("http://10.2.3.4/mcp", ("10.0.0.0/8",)))
    assert report["status"] == "failed" and report["requests_attempted"] == 0
    assert report["reason"] == "Plaintext MCP requires loopback"


def test_connection_time_plaintext_rebinding_is_rejected(server, monkeypatch):
    async def changed(self, host, port=0, family=socket.AF_INET):
        self.budget.check_address("10.2.3.4")
        raise AssertionError("Address should have been refused")
    monkeypatch.setattr(ScopePolicy, "addresses", lambda self, hostname: [self.network("127.0.0.1/32")])
    monkeypatch.setattr(PolicyResolver, "resolve", changed)
    report = asyncio.run(live.inventory(server[0].replace("127.0.0.1", "fixture.example"),
                                      ("127.0.0.1/32", "10.0.0.0/8"), True))
    assert report["status"] == "failed" and server[2] == []


@pytest.mark.parametrize("limit", ["MAX_PAGES", "MAX_TOOLS", "MAX_REQUESTS", "MAX_SCHEMA_NODES", "MAX_TOTAL_BYTES"])
def test_hard_budget_limits_are_incomplete(server, monkeypatch, limit):
    monkeypatch.setattr(live, limit, 1)
    def dispatch(request, headers):
        return result(request, discovery() if request["method"] == "server/discover" else {
            "tools": [tool(str(len(server[2]))), tool("other")], "nextCursor": "next"})
    server[1]["dispatch"] = dispatch
    report = collect(server)
    assert report["status"] in {"failed", "partial"}
    assert all(check["outcome"] != "passed" for check in report["checks"])


def test_response_byte_limit_is_enforced(server):
    server[1]["dispatch"] = lambda request, headers: (200, {"Content-Type": "application/json"}, b" " * (live.MAX_RESPONSE_BYTES + 1))
    report = collect(server)
    assert report["status"] == "failed" and report["response_bytes"] <= live.MAX_RESPONSE_BYTES


def test_deep_schema_is_bounded(server):
    schema = {"type": "string"}
    for _ in range(33):
        schema = {"type": "object", "properties": {"nested": schema}}
    server[1]["dispatch"] = lambda request, headers: result(request, discovery() if request["method"] == "server/discover" else {"tools": [{"name": "deep", "inputSchema": schema}]})
    assert collect(server)["reason"] == "MCP schema complexity limit exceeded"


@pytest.mark.parametrize("body", [b"data: {}\n\n", b": keepalive\n\n", b'data: {"jsonrpc":"2.0","id":"inventory-1","result":{}}',
    b'data: {"jsonrpc":"2.0","id":"server-call","method":"sampling/createMessage","params":{}}\n\n'])
def test_incomplete_and_invalid_sse_never_passes(server, body):
    server[1]["dispatch"] = lambda request, headers: (200, {"Content-Type": "text/event-stream"}, body)
    assert collect(server)["status"] == "failed"


def test_sse_event_limit_counts_ignored_notifications(server, monkeypatch):
    monkeypatch.setattr(live, "MAX_EVENTS", 2)
    notification = b'data: {"jsonrpc":"2.0","method":"notifications/message","params":{}}\n\n'
    server[1]["dispatch"] = lambda request, headers: (200, {"Content-Type": "text/event-stream"}, notification * 3)
    assert collect(server)["reason"] == "MCP stream event limit exceeded"


def test_request_timeout_bounds_a_stalled_stream(server, monkeypatch):
    monkeypatch.setattr(live, "REQUEST_TIMEOUT", .05)
    def stalled(stream):
        stream.write(b": comment\n\n")
        stream.flush()
        time.sleep(.2)
    server[1]["dispatch"] = lambda request, headers: (200, {"Content-Type": "text/event-stream"}, stalled)
    started = time.monotonic()
    report = collect(server)
    assert time.monotonic() - started < 1
    assert report["status"] == "failed" and "timed out" in report["reason"]


@pytest.mark.asyncio
async def test_dns_runs_off_event_loop_with_overall_timeout(server, monkeypatch):
    monkeypatch.setattr(live, "OVERALL_TIMEOUT", .02)
    def slow(self, hostname):
        time.sleep(.1)
        return [self.network("127.0.0.1/32")]
    monkeypatch.setattr(ScopePolicy, "addresses", slow)
    started = time.monotonic()
    report = await live.inventory(server[0], ("127.0.0.1/32",), True)
    assert time.monotonic() - started < .09
    assert report["status"] == "failed" and server[2] == []


@pytest.mark.asyncio
async def test_timed_out_schema_validation_cannot_change_returned_snapshot(server, monkeypatch):
    monkeypatch.setattr(live, "OVERALL_TIMEOUT", .03)
    original = live._tools
    def slow(result, state):
        time.sleep(.12)
        return original(result, state)
    monkeypatch.setattr(live, "_tools", slow)
    report = await live.inventory(server[0], ("127.0.0.1/32",), True)
    assert report["status"] == "partial" and report["tools_assessed"] == 0
    frozen = json.dumps(report)
    await asyncio.sleep(.15)
    assert json.dumps(report) == frozen


@pytest.mark.parametrize("media", ["text/html", "application/octet-stream", "", "application/jsonp"])
def test_unsupported_content_types_do_not_parse_as_mcp(server, media):
    server[1]["dispatch"] = lambda request, headers: (200, {"Content-Type": media}, b'{}')
    assert collect(server)["status"] == "failed"


def test_forbidden_broad_cidr_rejected_before_dns(server):
    with patch.object(ScopePolicy, "addresses", side_effect=AssertionError("Preflight must reject scope first")):
        with pytest.raises(ValueError):
            asyncio.run(live.inventory(server[0], ("0.0.0.0/0",), True))
    assert server[2] == []


def test_cli_live_json_sarif_and_incomplete_exit_status(server):
    args = ["mcp-live", "--endpoint", server[0], "--allow-network", "127.0.0.1/32", "--allow-loopback"]
    result = CliRunner().invoke(cli, args)
    assert result.exit_code == 0, result.output
    assert json.loads(result.output)["mode"] == "live_inventory"
    result = CliRunner().invoke(cli, [*args, "--format", "sarif"])
    assert result.exit_code == 0 and json.loads(result.output)["version"] == "2.1.0"
    server[1]["dispatch"] = lambda request, headers: (401, {"Content-Type": "application/json"}, b'{}')
    result = CliRunner().invoke(cli, args)
    assert result.exit_code == 1 and '"status": "failed"' in result.output


@pytest.mark.parametrize("status", ["failed", "partial", "completed"])
def test_live_sarif_execution_status_does_not_claim_incomplete_success(server, status):
    report = collect(server)
    report["status"] = status
    sarif = to_sarif(report)
    assert sarif["runs"][0]["invocations"][0]["executionSuccessful"] == (status == "completed")
    assert sarif["runs"][0]["properties"]["checks"][0]["outcome"] == "inconclusive"


def test_passive_sarif_retains_successful_execution_default():
    from src.mcp import assess
    assert to_sarif(assess(tools={"tools": []}))["runs"][0]["invocations"][0]["executionSuccessful"] is True


def test_cli_requires_explicit_allowlist_and_hides_invalid_credential(server):
    assert CliRunner().invoke(cli, ["mcp-live", "--endpoint", server[0]]).exit_code == 2
    result = CliRunner().invoke(cli, ["mcp-live", "--endpoint", server[0], "--allow-network", "127.0.0.1/32",
                                    "--allow-loopback", "--api-key-env", "private-invalid-name\n"])
    assert result.exit_code == 1 and "private-invalid-name" not in result.output
