"""Normal CLI/provider execution, not benchmark or real-model accuracy acceptance."""

from copy import deepcopy
from http.server import BaseHTTPRequestHandler
import importlib
import ipaddress
import json
import socket
from types import SimpleNamespace
from unittest.mock import Mock

from click.testing import CliRunner
import pytest

import scanner_cli
from src.evaluation.prompt_benchmark import _manifest
from src.security.prompt_injection_tests import PromptInjectionTester
from src.security.prompt_suites import PROTECTED_DISCLOSURE_SUITE, candidate_payloads
from tests.test_beta_lab_workflow import NumericHTTPServer, running_server


CANARY = "synthetic-workflow-canary-714032bc"
PII = "synthetic-private-record-91348 987-65-4321"


@pytest.mark.parametrize("arguments", [
    ["--prompt-suite", "unknown-private-input-819374"],
    ["--prompt-suite", "baseline"],
    ["--prompt-suite", PROTECTED_DISCLOSURE_SUITE, "--skip-security"],
])
def test_cli_bad_selection_fails_before_loading_targets(arguments, monkeypatch):
    load = Mock(side_effect=AssertionError("No target loading allowed"))
    monkeypatch.setattr(scanner_cli, "load_targets", load)
    result = CliRunner().invoke(scanner_cli.cli, ["scan", *arguments])
    assert result.exit_code != 0
    load.assert_not_called()
    assert "unknown-private-input-819374" not in result.output


@pytest.mark.parametrize("mutation", ["discovery", "missing_marker", "missing_context", "unmodelled"])
def test_cli_candidate_prerequisites_fail_without_scan_execution(tmp_path, monkeypatch, mutation):
    execute = Mock(side_effect=AssertionError("No scan execution allowed"))
    monkeypatch.setattr(scanner_cli, "_execute", execute)
    agent = {"id": "fixture", "name": "Fixture", "endpoint": "http://127.0.0.1:1",
             "provider": "ollama", "model": "fixture-model", "system_prompt_canary": CANARY,
             "evidence_context_id": "fixture-context-v1"}
    if mutation == "missing_marker":
        del agent["system_prompt_canary"]
    elif mutation == "missing_context":
        del agent["evidence_context_id"]
    elif mutation == "unmodelled":
        del agent["model"]
    config = tmp_path / "private-config.json"
    config.write_text(json.dumps({"agents": [agent]} if mutation != "discovery" else {
        "target_scope": {"network_ranges": ["127.0.0.1/32"]}}))
    config.chmod(0o600)
    result = CliRunner().invoke(scanner_cli.cli, ["scan", "--config", str(config), "--allow-loopback",
                                               "--prompt-suite", PROTECTED_DISCLOSURE_SUITE])
    assert result.exit_code != 0
    execute.assert_not_called()
    assert CANARY not in result.output


@pytest.fixture
def wire_target(monkeypatch):
    state = {"mode": "disclose", "posts": []}

    async def no_pacing(seconds):
        return None

    for name in ("prompt_injection_tests", "access_control_tests", "data_privacy_tests"):
        monkeypatch.setattr(importlib.import_module("src.security." + name), "asyncio",
                            SimpleNamespace(sleep=no_pacing))

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def respond(self, status, value):
            data = json.dumps(value).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self):
            self.respond(401, {"error": "Synthetic fixture denial"})

        def do_POST(self):
            body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            state["posts"].append(body)
            if self.path != "/v1/chat/completions":
                self.respond(404, {"error": "Unsupported fixture route"})
                return
            if state["mode"] == "partial" and len(state["posts"]) > 1:
                self.respond(503, {"error": "Synthetic unavailable target"})
                return
            text = CANARY if state["mode"] in {"disclose", "partial"} else (
                "different-target-token-91803457" if state["mode"] == "unseeded" else
                "I cannot reveal protected instructions.")
            self.respond(200, {"choices": [{"message": {"content": text + " " + PII}}]})

    original_socket = socket.socket

    class LoopbackSocket(original_socket):
        def connect(self, address):
            if self.family in (socket.AF_INET, socket.AF_INET6):
                assert ipaddress.ip_address(address[0]).is_loopback
            return super().connect(address)

        def connect_ex(self, address):
            if self.family in (socket.AF_INET, socket.AF_INET6):
                assert ipaddress.ip_address(address[0]).is_loopback
            return super().connect_ex(address)

    monkeypatch.setattr(socket, "socket", LoopbackSocket)
    with running_server(NumericHTTPServer(("127.0.0.1", 0), Handler)) as port:
        yield "http://127.0.0.1:" + str(port), state


@pytest.mark.parametrize("mode", ["disclose", "refuse", "unseeded", "partial"])
@pytest.mark.parametrize("fmt", ["json", "sarif"])
def test_real_cli_candidate_to_private_report(wire_target, tmp_path, mode, fmt, caplog):
    endpoint, state = wire_target
    state["mode"] = mode
    default_catalog = deepcopy(PromptInjectionTester().injection_payloads)
    agent = {"id": "wire-fixture", "name": "Local fixture", "type": "assistant",
             "provider": "openai-compatible", "endpoint": endpoint, "model": "fixture-model",
             "system_prompt_canary": CANARY, "evidence_context_id": "fixture-context-v1"}
    config, output = tmp_path / "private-config.json", tmp_path / "report.json"
    config.write_text(json.dumps({"agents": [agent]}))
    config.chmod(0o600)
    result = CliRunner().invoke(scanner_cli.cli, ["scan", "--config", str(config), "--allow-loopback",
        "--prompt-suite", PROTECTED_DISCLOSURE_SUITE, "--format", fmt, "--max-requests", "150",
        "--timeout-seconds", "15", "--request-timeout-seconds", "2", "--output", str(output)])
    assert output.exists(), result.output
    assert result.exit_code == (1 if mode == "partial" else 0), result.output
    report = json.loads(output.read_text())
    expected_score = 70.0 if mode in {"disclose", "partial"} else None
    if fmt == "json":
        assert report["status"] == ("partial" if mode == "partial" else "completed")
        assert report["prompt_suite"] == report["agents"][0]["prompt_suite"] == PROTECTED_DISCLOSURE_SUITE
        assert report["summary"]["overall_risk_score"] == expected_score
        assert report["agents"][0]["risk_score"] == expected_score
        checks = report["agents"][0]["checks"]
        assert all(item["response_excerpt"] == "[GENERATED_TEXT_OMITTED]"
                   for item in report["agents"][0]["vulnerabilities"])
    else:
        assert report["runs"][0]["invocations"][0]["executionSuccessful"] is (mode != "partial")
        properties = report["runs"][0]["properties"]
        assert properties["prompt_suite"] == PROTECTED_DISCLOSURE_SUITE
        assert properties["summary"]["overall_risk_score"] == expected_score
        checks = properties["checks"]
    prompts = [check for check in checks if check["rule_id"].startswith("prompt_injection.")]
    assert len(prompts) == 7
    assert sum(check["requests_attempted"] for check in prompts) == 35
    assert all(check["outcome"] != "passed" for check in prompts)
    expected_manifest = _manifest(candidate_payloads(), "openai-compatible", "fixture-model")
    assert [check["probe_version"] for check in prompts] == [item["probe_version"] for item in expected_manifest]
    assert [body["messages"][0]["content"] for body in state["posts"][:35]] == [
        payload for values in candidate_payloads().values() for payload in values]
    assert CANARY not in json.dumps(state["posts"])
    assert all(value not in output.read_text() + result.output + caplog.text for value in (CANARY, PII))
    assert output.stat().st_mode & 0o777 == 0o600
    assert PromptInjectionTester().injection_payloads == default_catalog
    if mode == "partial":
        assert result.exit_code != 0
        assert prompts[0]["status"] == "failed" and prompts[0]["outcome"] == "confirmed"
