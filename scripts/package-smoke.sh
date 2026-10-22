#!/bin/sh
# Install the wheel in isolation and execute its CLI outside the source tree.
set -eu

wheel_path=$(realpath "$1")
smoke_dir=$(mktemp -d)
trap 'rm -rf "$smoke_dir"' EXIT
python -m venv "$smoke_dir/venv"
"$smoke_dir/venv/bin/python" -m pip install --quiet "$wheel_path"
cd "$smoke_dir"
unset PYTHONPATH
"$smoke_dir/venv/bin/python" -m pip check
"$smoke_dir/venv/bin/ai-agent-scanner" --version
"$smoke_dir/venv/bin/ai-agent-scanner" --help
"$smoke_dir/venv/bin/ai-agent-scanner" scan --help
"$smoke_dir/venv/bin/python" -c 'from click.testing import CliRunner; from scanner_cli import cli; runner = CliRunner(); assert "--prompt-suite" in runner.invoke(cli, ["scan", "--help"]).output; assert "--prompt-suite" not in runner.invoke(cli, ["discover", "--help"]).output; result = runner.invoke(cli, ["scan", "--prompt-suite", "unsupported-private-input-71403"]); assert result.exit_code == 2 and "unsupported-private-input-71403" not in result.output'
"$smoke_dir/venv/bin/ai-agent-scanner" coverage
"$smoke_dir/venv/bin/ai-agent-scanner" mcp --help
"$smoke_dir/venv/bin/ai-agent-scanner" mcp-live --help
"$smoke_dir/venv/bin/ai-agent-scanner" mcp-check --help
"$smoke_dir/venv/bin/python" -c 'from src.mcp.live import PROTOCOL_VERSION, inventory; assert PROTOCOL_VERSION == "2026-07-28"; assert callable(inventory)'
"$smoke_dir/venv/bin/python" -c 'from src.mcp.policy import check, load_policy; assert callable(check) and callable(load_policy)'
"$smoke_dir/venv/bin/python" -c 'from src.evaluation.prompt_benchmark import BenchmarkConfig, benchmark; assert callable(BenchmarkConfig) and callable(benchmark)'
"$smoke_dir/venv/bin/python" -c 'from src.security.prompt_suites import PROTECTED_DISCLOSURE_SUITE, candidate_payloads; from src.security.security_engine import SecurityTestEngine; suite = PROTECTED_DISCLOSURE_SUITE; assert sum(map(len, candidate_payloads().values())) == 35; assert SecurityTestEngine(prompt_suite=suite).prompt_suite == suite; assert SecurityTestEngine().prompt_suite is None'
"$smoke_dir/venv/bin/python" -c 'from src.evaluation.benchmark_validation import validate_report; from src.evaluation.benchmark_cohort import evaluate_cohort; assert callable(validate_report) and callable(evaluate_cohort)'
"$smoke_dir/venv/bin/python" -c 'from src.core.schedules import ScheduleService, schedule_definition; assert callable(ScheduleService); assert schedule_definition({"template_id": "fixture", "template_revision": 1, "interval_seconds": 60, "total_runs": 1})["total_runs"] == 1'
"$smoke_dir/venv/bin/ai-agent-scanner" diff --help
"$smoke_dir/venv/bin/ai-agent-scanner" triage --help
"$smoke_dir/venv/bin/ai-agent-scanner" evaluate --output fixture-metrics.json
"$smoke_dir/venv/bin/python" -c 'import json; result = json.load(open("fixture-metrics.json")); assert result["mode"] == "offline_replay"; assert result["metrics"]["case_count"] == 6'
