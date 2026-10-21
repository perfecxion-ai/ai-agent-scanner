"""Static MCP CLI failures preserve diagnostics without echoing private inputs."""

import asyncio
import json
import ssl
from datetime import datetime, timedelta, timezone

import pytest
from aiohttp import web
from click.testing import CliRunner
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from scanner_cli import cli
from src.core.scope import ScopePolicy, ScopeResolutionError
from src.mcp import live
from src.mcp.diagnostics import public_failure_reason
from tests import test_mcp_policy as fixtures
from tests.test_mcp_live import discovery, result, tool


server = fixtures.server
no_process_execution = fixtures.no_process_execution
environment = fixtures.environment


def invoke(command, endpoint, tmp_path, fmt="json", output=True, allowed="127.0.0.1/32"):
    args = [command, "--endpoint", endpoint, "--allow-network", allowed,
            "--allow-loopback", "--api-key-env", "MCP_FIXTURE_BEARER", "--format", fmt]
    if command == "mcp-check":
        path = tmp_path / "policy.json"
        path.write_text(json.dumps(fixtures.policy((endpoint,))))
        args.extend(("--policy", str(path)))
    if output:
        args.extend(("--output", str(tmp_path / "report.json")))
    return CliRunner().invoke(cli, args)


def assert_failure(response, expected, endpoint):
    assert response.exit_code == 1, response.output
    assert expected in response.stderr
    for private in (endpoint, "MCP_FIXTURE_BEARER", "MCP_FIXTURE_TOOL",
                    fixtures.MARKER, fixtures.CREDENTIAL, "private-response-body"):
        assert private not in response.stderr


@pytest.mark.parametrize("command", ["mcp-live", "mcp-check"])
@pytest.mark.parametrize("fmt", ["json", "sarif"])
@pytest.mark.parametrize("output", [False, True])
def test_denied_baseline_cli_has_specific_static_reason(server, tmp_path, command, fmt, output):
    server[1]["dispatch"] = lambda request, headers: (
        401, {"Content-Type": "text/plain"},
        f"private-response-body {fixtures.CREDENTIAL} {fixtures.MARKER}".encode())
    response = invoke(command, server[0], tmp_path, fmt, output)
    assert_failure(response, "MCP access denied; inventory not evaluated", server[0])
    if output:
        assert (tmp_path / "report.json").exists()


@pytest.mark.parametrize("command", ["mcp-live", "mcp-check"])
@pytest.mark.parametrize("case,expected", [
    ("dns", "MCP endpoint hostname could not be resolved"),
    ("scope", "MCP endpoint is outside the allowed scope"),
    ("plaintext", "Plaintext MCP requires loopback"),
    ("timeout", "MCP transport failed or timed out"),
])
def test_cli_resolution_scope_plaintext_and_timeout_reasons(server, tmp_path, monkeypatch, command, case, expected):
    endpoint = server[0]
    allowed = "127.0.0.1/32"
    if case == "dns":
        def unresolved(self, hostname):
            raise ScopeResolutionError("private-response-body resolver detail")
        monkeypatch.setattr(ScopePolicy, "addresses", unresolved)
    elif case == "scope":
        endpoint = "https://127.0.0.2/private-path"
    elif case == "plaintext":
        endpoint, allowed = "http://192.0.2.1/private-path", "192.0.2.1/32"
    else:
        async def timeout(*args, **kwargs):
            raise asyncio.TimeoutError("private-response-body timeout detail")
        monkeypatch.setattr(live, "_request", timeout)
    response = invoke(command, endpoint, tmp_path, allowed=allowed)
    assert_failure(response, expected, endpoint)
    report = json.loads((tmp_path / "report.json").read_text())
    assert report["reason"] == expected
    assert report["status"] == "failed"
    assert all(check["outcome"] != "passed" for check in report["checks"])
    assert not server[2]


def test_failed_controls_use_safe_failed_check_reason_when_report_reason_is_null(server, tmp_path):
    fixtures.configure(server, auth=lambda request: (500, {}, b"private-response-body"))
    response = invoke("mcp-check", server[0], tmp_path)
    assert_failure(response, "MCP policy control was unusable", server[0])
    report = json.loads((tmp_path / "report.json").read_text())
    assert report["reason"] is None and report["status"] == "partial"


@pytest.mark.parametrize("command", ["mcp-live", "mcp-check"])
def test_invalid_server_json_uses_static_cli_reason(server, tmp_path, command):
    server[1]["dispatch"] = lambda request, headers: (
        200, {"Content-Type": "application/json"}, b"private-response-body")
    assert_failure(invoke(command, server[0], tmp_path), "Invalid MCP JSON", server[0])


@pytest.mark.parametrize("reason", [None, 1, [], {}, "private-response-body",
                                      "MCP TLS certificate verification failed\nprivate-response-body"])
def test_diagnostic_selector_never_returns_unrecognized_report_text(reason):
    assert public_failure_reason({"reason": reason, "checks": []}) is None
    assert public_failure_reason({"checks": [{"status": "failed", "reason": reason}]}) is None


def test_diagnostic_selector_does_not_print_completed_or_skipped_reasons():
    assert public_failure_reason({"checks": [
        {"status": status, "reason": "MCP TLS certificate verification failed"}
        for status in ("completed", "skipped")]}) is None


@pytest.mark.asyncio
@pytest.mark.parametrize("command", ["mcp-live", "mcp-check"])
async def test_real_untrusted_tls_cli_reason_is_safe(tmp_path, command):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "private-response-body")])
    now = datetime.now(timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=1)).not_valid_after(now + timedelta(days=1))
            .sign(key, hashes.SHA256()))
    key_path, cert_path = tmp_path / "key.pem", tmp_path / "cert.pem"
    key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                          serialization.NoEncryption()))
    key_path.chmod(0o600)
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert_path, key_path)
    app = web.Application()
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0, ssl_context=context)
    await site.start()
    endpoint = f"https://127.0.0.1:{site._server.sockets[0].getsockname()[1]}/private-path"
    try:
        response = await asyncio.to_thread(invoke, command, endpoint, tmp_path)
    finally:
        await runner.cleanup()
    assert_failure(response, "MCP TLS certificate verification failed", endpoint)


def test_single_page_baseline_also_describes_control_sampling(server):
    fixtures.configure(server)
    report = fixtures.collect(server)
    baseline = fixtures.record(report, "MCP.policy_baseline")
    assert "all returned pages" in baseline["reason"]
    assert "controls sample the first page only" in baseline["reason"]
    assert baseline["outcome"] == "inconclusive"
    assert fixtures.record(report, "MCP.authorization")["outcome"] == "passed"


def test_incomplete_baseline_does_not_claim_complete_paginated_collection(server):
    def dispatch(request, headers):
        if request["method"] == "server/discover":
            return result(request, discovery())
        if request.get("params", {}).get("cursor"):
            return 500, {}, b"private-response-body"
        return result(request, {"tools": [tool(fixtures.MARKER)], "nextCursor": "private-cursor"})
    server[1]["dispatch"] = dispatch
    report = fixtures.collect(server)
    baseline = fixtures.record(report, "MCP.policy_baseline")
    assert baseline["status"] == "failed" and report["status"] == "partial"
    assert "all returned pages" not in baseline["reason"]
    assert fixtures.record(report, "MCP.authorization")["status"] == "skipped"
    assert "private-cursor" not in json.dumps(report)
