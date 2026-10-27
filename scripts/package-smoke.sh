#!/bin/sh
# Install the wheel in isolation and execute its CLI outside the source tree.
set -eu

wheel_path=$(realpath "$1")
smoke_dir=$(mktemp -d)
trap 'rm -rf "$smoke_dir"' EXIT
python - "$smoke_dir/source-build.json" <<'PY'
import json
from pathlib import Path
import sys

from src.core.build_identity import current_identity

identity = current_identity(component='cli')
if identity['source']['status'] != 'available' or identity['catalogs']['status'] != 'available':
    raise SystemExit('Source build identity is unavailable')
Path(sys.argv[1]).write_text(json.dumps(identity), encoding='utf-8')
PY
python -m venv "$smoke_dir/venv"
"$smoke_dir/venv/bin/python" -m pip install --quiet "$wheel_path"
cd "$smoke_dir"
unset PYTHONPATH
"$smoke_dir/venv/bin/python" -m pip check
"$smoke_dir/venv/bin/ai-agent-scanner" --version
"$smoke_dir/venv/bin/ai-agent-scanner" build-info --json > "$smoke_dir/installed-build.json"
"$smoke_dir/venv/bin/python" - "$smoke_dir/source-build.json" "$smoke_dir/installed-build.json" <<'PY'
from importlib.metadata import version
import json
from pathlib import Path
import sys

from scanner_cli import VERSION
from src._version import __version__
from src.core.build_identity import current_identity

expected = json.loads(Path(sys.argv[1]).read_text(encoding='utf-8'))
actual = json.loads(Path(sys.argv[2]).read_text(encoding='utf-8'))
if actual != expected or actual != current_identity(component='cli'):
    raise SystemExit('Installed source/catalog identity differs from checkout')
if not VERSION == __version__ == version('ai-agent-scanner') == actual['package_version']:
    raise SystemExit('Installed package, CLI and build versions differ')
print('Installed build identity matches checkout and distribution metadata')
PY
"$smoke_dir/venv/bin/ai-agent-scanner" --help
"$smoke_dir/venv/bin/ai-agent-scanner" scan --help
"$smoke_dir/venv/bin/ai-agent-scanner" recover --help
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
mkdir "$smoke_dir/fixture-source"
printf '%s\n' 'from openai import OpenAI' 'client = OpenAI()' > "$smoke_dir/fixture-source/application.py"
"$smoke_dir/venv/bin/ai-agent-scanner" discover --repository "$smoke_dir/fixture-source" --output fixture-discovery.json --checkpoint-dir "$smoke_dir/checkpoint"
"$smoke_dir/venv/bin/ai-agent-scanner" recover --checkpoint-dir "$smoke_dir/checkpoint" --output fixture-recovered.json
"$smoke_dir/venv/bin/python" - <<'PY'
import json
from pathlib import Path

original = json.loads(Path('fixture-discovery.json').read_text())
recovered = json.loads(Path('fixture-recovered.json').read_text())
if original != recovered or recovered['status'] != 'completed':
    raise SystemExit('Installed CLI checkpoint recovery changed the saved report')
if recovered['summary']['overall_risk_score'] is not None:
    raise SystemExit('Discovery checkpoint recovery invented a risk score')
directory = Path('checkpoint')
if directory.stat().st_mode & 0o777 != 0o700:
    raise SystemExit('Installed CLI checkpoint directory is not private')
if any(path.stat().st_mode & 0o777 != 0o600 for path in directory.iterdir()):
    raise SystemExit('Installed CLI checkpoint files are not private')
print('Installed CLI checkpoint recovery preserves completed discovery and unknown risk')
PY
