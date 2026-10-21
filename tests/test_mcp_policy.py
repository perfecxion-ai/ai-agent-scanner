"""Controlled protected inventory policy acceptance using synthetic loopback data."""

import asyncio
import hashlib
import json
import os
import threading

import pytest
from click.testing import CliRunner

from scanner_cli import cli
from src.mcp import live, to_sarif
from src.mcp import policy as checks
from tests import test_mcp_live as fixture_support
from tests.test_mcp_live import discovery, result, tool

server = fixture_support.server
no_process_execution = fixture_support.no_process_execution


MARKER = "fixture-protected-tool-1234567890"
CREDENTIAL = "fixture-bearer-value-1234567890"
ALLOWED = "https://trusted.example"
DENIED = "https://denied.example"


@pytest.fixture(autouse=True)
def environment(monkeypatch):
    monkeypatch.setenv("MCP_FIXTURE_TOOL", MARKER)
    monkeypatch.setenv("MCP_FIXTURE_BEARER", CREDENTIAL)


def policy(server, origins=True):
    value = {"version": 1, "endpoint": server[0], "evidence_context_id": "lab-fixture-v1",
             "fixture_provenance": "operator_protected_tool", "protected_tool_name_env": "MCP_FIXTURE_TOOL",
             "authorization_required": True}
    if origins:
        value["origins"] = {"allowed": ALLOWED, "denied": DENIED}
    return value


def configure(server, auth=None, origin=None):
    def dispatch(request, headers):
        if request["method"] == "server/discover":
            return result(request, discovery())
        if headers.get("Authorization") is None:
            return auth(request) if auth else (401, {}, b"")
        if headers.get("Origin") == DENIED:
            return origin(request) if origin else (403, {}, b"")
        return result(request, {"tools": [tool(MARKER)]})
    server[1]["dispatch"] = dispatch


def collect(server, value=None):
    return asyncio.run(checks.check(server[0], ("127.0.0.1/32",), value or policy(server),
                                   allow_loopback=True, api_key_env="MCP_FIXTURE_BEARER"))


def record(report, name):
    return next(value for value in report["checks"] if value["rule_id"] == name)


def test_protected_baseline_and_sampled_denials_pass_only_scoped_checks(server):
    configure(server)
    report = collect(server)
    assert report["status"] == "completed" and report["risk_assessment_status"] == "not_assessed"
    assert record(report, "MCP.authorization")["outcome"] == "passed"
    assert record(report, "MCP.origin")["outcome"] == "passed"
    assert record(report, "MCP.tool_execution")["status"] == "skipped"
    assert report["requests_attempted"] == report["responses_evaluated"] == 4
    requests = server[2]
    assert len(requests) == 4
    assert requests[0][1]["Authorization"] == requests[1][1]["Authorization"] == requests[3][1]["Authorization"]
    assert requests[0][1]["Origin"] == requests[1][1]["Origin"] == requests[2][1]["Origin"] == ALLOWED
    assert "Authorization" not in requests[2][1] and requests[3][1]["Origin"] == DENIED
    assert all(request["method"] in {"server/discover", "tools/list"} for request, _ in requests)
    assert MARKER not in json.dumps(requests)
    assert MARKER not in json.dumps(report) and CREDENTIAL not in json.dumps(report)
    assert requests[1][0] == requests[2][0] == requests[3][0]


@pytest.mark.parametrize("rule", ["MCP.authorization", "MCP.origin"])
@pytest.mark.parametrize("status", [200, 401, 403])
def test_typed_protected_tool_return_confirms_even_under_denial_status(server, rule, status):
    def response(request):
        return status, {"Content-Type": "application/json"}, json.dumps(result(request, {"tools": [tool(MARKER)]})).encode()
    configure(server, auth=response if rule == "MCP.authorization" else None,
              origin=response if rule == "MCP.origin" else None)
    report = collect(server)
    assert record(report, rule)["outcome"] == "confirmed"
    assert len(report["findings"]) == 1
    finding = report["findings"][0]
    assert finding["rule_id"] == rule and finding["control_status"] == "validated_positive_control"
    rendered = json.dumps(to_sarif(report))
    assert MARKER not in rendered and CREDENTIAL not in rendered
    assert hashlib.sha256(MARKER.encode()).hexdigest() not in rendered
    assert report["evidence_context_id"] in rendered
    sarif = to_sarif(report)
    assert sarif["runs"][0]["results"][0]["locations"][0]["logicalLocations"][0]["name"] == server[0]
    assert sarif["runs"][0]["results"][0]["properties"]["control_status"] == "validated_positive_control"


@pytest.mark.parametrize("payload", [{"tools": []}, {"tools": [tool()]},
                                      {"tools": [tool()], "nextCursor": "private-cursor"}])
def test_public_or_canary_free_control_page_is_inconclusive_and_not_paginated(server, payload):
    configure(server, auth=lambda request: result(request, payload), origin=lambda request: result(request, payload))
    report = collect(server)
    assert record(report, "MCP.authorization")["outcome"] == "inconclusive"
    assert record(report, "MCP.origin")["outcome"] == "inconclusive"
    assert report["findings"] == [] and len(server[2]) == 4
    assert record(report, "MCP.authorization")["reason"] == checks._TEXT["sample_missing"]
    assert record(report, "MCP.origin")["reason"] == checks._TEXT["sample_missing"]
    assert "private-cursor" not in json.dumps(report)


def test_protected_tool_on_later_page_reports_sample_coverage_warning(server):
    def dispatch(request, headers):
        if request["method"] == "server/discover":
            return result(request, discovery())
        if request.get("params", {}).get("cursor"):
            return result(request, {"tools": [tool(MARKER)]})
        return result(request, {"tools": [tool()], "nextCursor": "page-two"})
    server[1]["dispatch"] = dispatch
    report = collect(server)
    assert report["findings"] == []
    for name in ("MCP.authorization", "MCP.origin"):
        assert record(report, name)["outcome"] == "inconclusive"
        assert record(report, name)["reason"] == checks._TEXT["sample_missing"]
    assert len(server[2]) == 5
    assert sum(bool(request.get("params", {}).get("cursor")) for request, _ in server[2]) == 1
    assert MARKER not in json.dumps(report)


def test_origin_401_is_not_origin_enforcement_pass(server):
    configure(server, origin=lambda request: (401, {}, b""))
    assert record(collect(server), "MCP.origin")["outcome"] == "inconclusive"


@pytest.mark.parametrize("status", [401, 403])
@pytest.mark.parametrize("omit_id", [True, False])
def test_strict_error_denial_can_pass_with_absent_id(server, status, omit_id):
    def denied(request):
        message = {"jsonrpc": "2.0", "error": {"code": -32000, "message": "Denied"}}
        if not omit_id:
            message["id"] = request["id"]
        return status, {"Content-Type": "application/json"}, json.dumps(message).encode()
    configure(server, auth=denied, origin=denied)
    report = collect(server)
    assert record(report, "MCP.authorization")["outcome"] == "passed"
    assert record(report, "MCP.origin")["outcome"] == ("passed" if status == 403 else "inconclusive")


@pytest.mark.parametrize("where", ["message", "data", "metadata", "escaped"])
def test_canary_echo_in_error_or_metadata_never_passes_or_confirms(server, where):
    def denied(request):
        error = {"code": -32000, "message": "Denied"}
        message = {"jsonrpc": "2.0", "id": request["id"], "error": error}
        if where == "metadata":
            message["_meta"] = {MARKER: "ignored"}
        else:
            error["message" if where in {"message", "escaped"} else "data"] = MARKER
        body = json.dumps(message).encode()
        if where == "escaped":
            body = body.replace(MARKER.encode(), b"".join(f"\\u{ord(char):04x}".encode() for char in MARKER))
        return 403, {"Content-Type": "application/json"}, body
    configure(server, auth=denied, origin=denied)
    report = collect(server)
    assert all(record(report, name)["outcome"] == "inconclusive" for name in ("MCP.authorization", "MCP.origin"))
    assert report["findings"] == [] and MARKER not in json.dumps(report)


@pytest.mark.parametrize("body", [b"Denied", b"[]", b'{"jsonrpc":"2.0","error":{}}',
                                  b'{"jsonrpc":"2.0","error":{"code":true,"message":"Denied"}}',
                                  b'{"jsonrpc":"2.0","id":null,"error":{"code":1,"message":"Denied"}}',
                                  b'{"jsonrpc":"2.0","method":"x","error":{"code":1,"message":"Denied"}}',
                                  b'{"jsonrpc":"2.0","result":{},"error":{"code":1,"message":"Denied"}}'])
def test_invalid_denials_are_failed_inconclusive_not_passed(server, body):
    def denied(request):
        return 403, {"Content-Type": "application/json"}, body
    configure(server, auth=denied, origin=denied)
    report = collect(server)
    assert report["status"] == "partial" and report["findings"] == []
    assert all(record(report, name)["status"] == "failed" for name in ("MCP.authorization", "MCP.origin"))
    assert not to_sarif(report)["runs"][0]["invocations"][0]["executionSuccessful"]


@pytest.mark.parametrize("payload", [{"tools": []}, {"tools": [tool()]}, {"tools": [tool(MARKER), {"name": "bad"}]}])
def test_missing_or_invalid_protected_baseline_prevents_security_requests(server, payload):
    server[1]["dispatch"] = lambda request, headers: result(request, discovery() if request["method"] == "server/discover" else payload)
    report = collect(server)
    assert len(server[2]) == 2 and report["findings"] == []
    assert record(report, "MCP.authorization")["status"] == record(report, "MCP.origin")["status"] == "skipped"


@pytest.mark.parametrize("status", [401, 403, 404, 500])
def test_denied_baseline_is_not_security_pass(server, status):
    server[1]["dispatch"] = lambda request, headers: (status, {}, b"")
    report = collect(server)
    assert report["status"] == "failed" and len(server[2]) == 1
    assert record(report, "MCP.authorization")["status"] == "skipped"


@pytest.mark.parametrize("encoded", [False, True])
def test_canary_baseline_cursor_is_never_reflected_in_requests(server, encoded):
    cursor = f"%{ord(MARKER[0]):02x}" + MARKER[1:] if encoded else MARKER
    server[1]["dispatch"] = lambda request, headers: result(request, discovery() if request["method"] == "server/discover" else
                                                           {"tools": [tool(MARKER)], "nextCursor": "prefix" + cursor})
    report = collect(server)
    assert report["status"] == "partial" and len(server[2]) == 2
    assert MARKER not in json.dumps(server[2])
    assert record(report, "MCP.authorization")["status"] == "skipped"


def test_optional_origin_policy_is_explicitly_skipped(server):
    configure(server)
    report = collect(server, policy(server, origins=False))
    assert len(server[2]) == 3 and record(report, "MCP.origin")["status"] == "skipped"
    assert all("Origin" not in headers for _, headers in server[2])


@pytest.mark.parametrize("edit", [
    {"version": True}, {"version": 2}, {"endpoint": "http://127.0.0.1/other"},
    {"fixture_provenance": "inferred"}, {"authorization_required": False},
    {"evidence_context_id": "spaces not allowed"}, {"protected_tool_name_env": "bad env"},
    {"unknown": True}, {"origins": {"allowed": ALLOWED}},
    {"origins": None},
    {"origins": {"allowed": ALLOWED, "denied": ALLOWED}},
    {"origins": {"allowed": ALLOWED + "/", "denied": DENIED}},
    {"origins": {"allowed": "https://user@trusted.example", "denied": DENIED}},
    {"origins": {"allowed": "https://trusted.example?q=x", "denied": DENIED}},
    {"origins": {"allowed": "https://trusted.example\r\nHeader:x", "denied": DENIED}},
])
def test_invalid_policy_fails_before_requests(server, edit):
    value = {**policy(server), **edit}
    with pytest.raises(ValueError):
        collect(server, value)
    assert server[2] == []


@pytest.mark.parametrize("marker", ["short", "x" * 129, "x" * 16 + "\n", "unicode-\u00e9-1234567890", CREDENTIAL,
                                    CREDENTIAL + "longer", "https://trusted.example", "io.modelcontextprotocol/clientInfo"])
def test_invalid_or_reflectable_canary_rejected_before_requests(server, monkeypatch, marker):
    monkeypatch.setenv("MCP_FIXTURE_TOOL", marker)
    with pytest.raises(ValueError):
        collect(server)
    assert server[2] == []


def test_credentials_cannot_overlap_public_context(server, monkeypatch):
    monkeypatch.setenv("MCP_FIXTURE_BEARER", "lab-fixture-v1")
    with pytest.raises(ValueError):
        collect(server)
    assert server[2] == []


def test_missing_envs_and_missing_credential_fail_before_requests(server, monkeypatch):
    monkeypatch.delenv("MCP_FIXTURE_TOOL")
    with pytest.raises(ValueError):
        collect(server)
    monkeypatch.setenv("MCP_FIXTURE_TOOL", MARKER)
    with pytest.raises(ValueError):
        asyncio.run(checks.check(server[0], ("127.0.0.1/32",), policy(server), allow_loopback=True))
    assert server[2] == []


def test_prior_confirmation_survives_later_error(server):
    configure(server, auth=lambda request: result(request, {"tools": [tool(MARKER)]}),
              origin=lambda request: (500, {}, b""))
    report = collect(server)
    assert report["status"] == "partial" and len(report["findings"]) == 1
    assert record(report, "MCP.authorization")["outcome"] == "confirmed"
    assert record(report, "MCP.origin")["status"] == "failed"


def test_one_shared_request_budget_across_conditions(server, monkeypatch):
    configure(server)
    monkeypatch.setattr(live, "MAX_REQUESTS", 3)
    report = collect(server)
    assert len(server[2]) == 3 and report["requests_attempted"] == 3 and report["status"] == "partial"
    assert record(report, "MCP.authorization")["outcome"] == "passed"
    assert record(report, "MCP.origin")["status"] == "failed"


def test_denial_body_resource_limits_cannot_pass(server, monkeypatch):
    configure(server, auth=lambda request: (403, {"Content-Type": "application/json"}, b" " * 1000))
    monkeypatch.setattr(live, "MAX_RESPONSE_BYTES", 500)
    report = collect(server)
    assert record(report, "MCP.authorization")["status"] == "failed"
    assert report["status"] == "partial"


def test_cookies_cannot_cross_conditions(server):
    original = {"dispatch": None}
    configure(server)
    original["dispatch"] = server[1]["dispatch"]
    def dispatch(request, headers):
        response = original["dispatch"](request, headers)
        if isinstance(response, tuple):
            return response
        return 200, {"Content-Type": "application/json", "Set-Cookie": "session=fixture"}, json.dumps(response).encode()
    server[1]["dispatch"] = dispatch
    assert collect(server)["status"] == "completed"
    assert all("Cookie" not in headers for _, headers in server[2])


def test_shared_deadline_preserves_confirmation_and_counts_active_control(server, monkeypatch):
    release = threading.Event()
    def stalled(request):
        def stream(output):
            release.wait(1)
        return 200, {"Content-Type": "text/event-stream"}, stream
    configure(server, auth=lambda request: result(request, {"tools": [tool(MARKER)]}), origin=stalled)
    monkeypatch.setattr(live, "OVERALL_TIMEOUT", .1)
    try:
        report = collect(server)
    finally:
        release.set()
    assert report["status"] == "partial" and len(report["findings"]) == 1
    assert record(report, "MCP.origin")["requests_attempted"] == 1
    assert record(report, "MCP.origin")["status"] == "failed"


@pytest.mark.parametrize("alias", ["same", "symlink", "hardlink"])
def test_cli_refuses_policy_overwrite_before_network(server, tmp_path, alias):
    source = tmp_path / "policy.json"
    source.write_text(json.dumps(policy(server)))
    destination = source if alias == "same" else tmp_path / "alias.json"
    if alias == "symlink":
        destination.symlink_to(source)
    elif alias == "hardlink":
        os.link(source, destination)
    args = ["mcp-check", "--endpoint", server[0], "--allow-network", "127.0.0.1/32", "--allow-loopback",
            "--api-key-env", "MCP_FIXTURE_BEARER", "--policy", str(source), "--output", str(destination)]
    response = CliRunner().invoke(cli, args)
    assert response.exit_code == 1 and server[2] == []
    assert json.loads(source.read_text()) == policy(server)


def test_cli_json_sarif_and_failure_status(server, tmp_path):
    source = tmp_path / "policy.json"
    source.write_text(json.dumps(policy(server)))
    args = ["mcp-check", "--endpoint", server[0], "--allow-network", "127.0.0.1/32", "--allow-loopback",
            "--api-key-env", "MCP_FIXTURE_BEARER", "--policy", str(source)]
    configure(server)
    response = CliRunner().invoke(cli, args)
    assert response.exit_code == 0 and json.loads(response.output)["mode"] == "live_policy_checks"
    response = CliRunner().invoke(cli, [*args, "--format", "sarif"])
    assert response.exit_code == 0 and json.loads(response.output)["runs"][0]["invocations"][0]["executionSuccessful"]
    configure(server, auth=lambda request: (500, {}, b""))
    response = CliRunner().invoke(cli, args)
    assert response.exit_code == 1 and '"status": "partial"' in response.output


@pytest.mark.parametrize("body", [b"[]", b'{"version":1,"version":1}', b"1e999", b"x" * 65537])
def test_invalid_policy_files_are_bounded_or_rejected_before_http(server, tmp_path, body):
    path = tmp_path / "invalid.json"
    path.write_bytes(body)
    args = ["mcp-check", "--endpoint", server[0], "--allow-network", "127.0.0.1/32", "--allow-loopback",
            "--api-key-env", "MCP_FIXTURE_BEARER", "--policy", str(path)]
    assert CliRunner().invoke(cli, args).exit_code == 1 and server[2] == []


def test_changed_public_policy_changes_version_without_secret_hashes(server, monkeypatch):
    configure(server)
    first = collect(server)
    value = policy(server)
    value["origins"]["denied"] = "https://other-denied.example"
    second = collect(server, value)
    assert record(first, "MCP.origin")["probe_version"] != record(second, "MCP.origin")["probe_version"]
    monkeypatch.setenv("MCP_FIXTURE_TOOL", "fixture-rotated-tool-1234567890")
    third = collect(server)
    assert record(first, "MCP.authorization")["probe_version"] == record(third, "MCP.authorization")["probe_version"]
    assert record(third, "MCP.authorization")["status"] == "skipped"


@pytest.mark.parametrize("marker", ["MCP.authorization", "protected_inventory", "name\":\"ai-agent-scanner", "fixture/tool~protected-1234567890"])
def test_reserved_or_serialized_markers_reject_and_escaped_safe_marker_is_sanitized(server, monkeypatch, marker):
    monkeypatch.setenv("MCP_FIXTURE_TOOL", marker)
    if marker.startswith("fixture/"):
        def dispatch(request, headers):
            if request["method"] == "server/discover":
                return result(request, discovery())
            if headers.get("Authorization") is None or headers.get("Origin") == DENIED:
                return result(request, {"tools": [tool(marker, properties={marker: {"type": "string"}})]})
            return result(request, {"tools": [tool(marker)]})
        server[1]["dispatch"] = dispatch
        report = collect(server)
        assert len(report["findings"]) == 2
        assert marker not in json.dumps(report) and marker.replace("~", "~0").replace("/", "~1") not in json.dumps(report)
    else:
        with pytest.raises(ValueError):
            collect(server)
        assert server[2] == []


@pytest.mark.parametrize("status", [200, 401, 403])
def test_invalid_control_page_containing_canary_cannot_confirm(server, status):
    def invalid(request):
        return status, {"Content-Type": "application/json"}, json.dumps(result(request, {
            "tools": [tool(MARKER), {"name": "invalid"}]})).encode()
    configure(server, auth=invalid, origin=invalid)
    report = collect(server)
    assert report["findings"] == [] and report["status"] == "partial"
    assert record(report, "MCP.authorization")["status"] == record(report, "MCP.origin")["status"] == "failed"


def test_canary_in_nested_denial_key_and_data_is_inconclusive(server):
    def denied(request):
        message = {"jsonrpc": "2.0", "error": {"code": -32000, "message": "Denied",
                   "data": [{"nested": {MARKER: [MARKER]}}]}}
        return 403, {"Content-Type": "application/json"}, json.dumps(message).encode()
    configure(server, auth=denied, origin=denied)
    report = collect(server)
    assert report["findings"] == [] and record(report, "MCP.origin")["outcome"] == "inconclusive"


def test_shared_total_body_budget_includes_denial_bodies(server, monkeypatch):
    def denied(request):
        data = {"jsonrpc": "2.0", "error": {"code": -32000, "message": "x" * 1000}}
        return 403, {"Content-Type": "application/json"}, json.dumps(data).encode()
    configure(server, auth=denied)
    monkeypatch.setattr(live, "MAX_TOTAL_BYTES", 800)
    report = collect(server)
    assert record(report, "MCP.authorization")["status"] == "failed" and report["status"] == "partial"


def test_control_redirect_is_not_followed(server):
    configure(server, auth=lambda request: (302, {"Location": "http://unscoped.example/mcp"}, b""))
    report = collect(server)
    assert record(report, "MCP.authorization")["status"] == "failed" and len(server[2]) == 4


def test_loopback_scope_is_enforced_before_network(server):
    with pytest.raises(ValueError):
        asyncio.run(checks.check(server[0], (), policy(server), allow_loopback=True, api_key_env="MCP_FIXTURE_BEARER"))
    with pytest.raises(ValueError):
        asyncio.run(checks.check(server[0], ("127.0.0.1/32",), policy(server), api_key_env="MCP_FIXTURE_BEARER"))
    assert server[2] == []


@pytest.mark.parametrize("secret", [MARKER, CREDENTIAL])
@pytest.mark.parametrize("depth", [1, 2, 3])
def test_encoded_secret_endpoint_is_rejected_before_http(server, secret, depth):
    escaped = f"%{ord(secret[0]):02x}" + secret[1:]
    for _ in range(depth - 1):
        escaped = escaped.replace("%", "%25")
    endpoint = server[0] + "/" + escaped
    value = {**policy(server), "endpoint": endpoint}
    with pytest.raises(ValueError):
        asyncio.run(checks.check(endpoint, ("127.0.0.1/32",), value,
                                 allow_loopback=True, api_key_env="MCP_FIXTURE_BEARER"))
    assert server[2] == []


def test_percent_encoded_origin_is_not_a_supported_serialized_origin(server):
    value = policy(server)
    value["origins"]["denied"] = "https://%66" + MARKER[1:] + ".example"
    with pytest.raises(ValueError):
        collect(server, value)
    assert server[2] == []


@pytest.mark.parametrize("credential", ["passed", "completed", "confirmed", "skipped", "failed", "high", "inconclusive",
                                       "not_evaluated", "live_policy_checks", "validated_positive_control"])
def test_credentials_cannot_corrupt_public_evidence_contract(server, monkeypatch, credential):
    monkeypatch.setenv("MCP_FIXTURE_BEARER", credential)
    with pytest.raises(ValueError):
        collect(server)
    assert server[2] == []


@pytest.mark.parametrize("identity", ["version", "finding"])
def test_credentials_cannot_collide_with_generated_public_identity(server, monkeypatch, identity):
    value = policy(server)
    generated = (checks._version(value).rsplit(":", 1)[-1] if identity == "version" else
                 checks._finding("MCP.authorization", value["evidence_context_id"], server[0])["id"])
    monkeypatch.setenv("MCP_FIXTURE_BEARER", generated[:16])
    with pytest.raises(ValueError):
        collect(server)
    assert server[2] == []


def test_excessive_percent_decoding_rounds_are_rejected_without_rewriting_target(server):
    endpoint = server[0] + "/%" + "25" * 17 + "66"
    value = {**policy(server), "endpoint": endpoint}
    with pytest.raises(ValueError):
        asyncio.run(checks.check(endpoint, ("127.0.0.1/32",), value,
                                 allow_loopback=True, api_key_env="MCP_FIXTURE_BEARER"))
    assert server[2] == [] and value["endpoint"] == endpoint


@pytest.mark.parametrize("header", ["X-Fixture", "Set-Cookie"])
def test_header_only_marker_denial_echo_is_not_passed_or_confirmed(server, header):
    configure(server, auth=lambda request: (403, {header: MARKER}, b""),
              origin=lambda request: (403, {header: MARKER}, b""))
    report = collect(server)
    assert report["findings"] == []
    assert record(report, "MCP.authorization")["outcome"] == record(report, "MCP.origin")["outcome"] == "inconclusive"
    assert MARKER not in json.dumps(report)


@pytest.mark.parametrize("cursor", ["http://[", "", "not a URL ? #"])
def test_baseline_cursor_is_opaque_not_a_url(server, cursor):
    def dispatch(request, headers):
        if request["method"] == "server/discover":
            return result(request, discovery())
        if headers.get("Authorization") is None:
            return 401, {}, b""
        if headers.get("Origin") == DENIED:
            return 403, {}, b""
        if "cursor" not in request["params"]:
            return result(request, {"tools": [tool()], "nextCursor": cursor})
        assert request["params"]["cursor"] == cursor
        return result(request, {"tools": [tool(MARKER)]})
    server[1]["dispatch"] = dispatch
    report = collect(server)
    assert report["status"] == "completed" and len(server[2]) == 5
    assert record(report, "MCP.authorization")["outcome"] == record(report, "MCP.origin")["outcome"] == "passed"
    assert server[2][2][0]["params"]["cursor"] == cursor
