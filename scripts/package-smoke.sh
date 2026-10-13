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
"$smoke_dir/venv/bin/ai-agent-scanner" coverage
"$smoke_dir/venv/bin/ai-agent-scanner" mcp --help
"$smoke_dir/venv/bin/ai-agent-scanner" diff --help
"$smoke_dir/venv/bin/ai-agent-scanner" triage --help
"$smoke_dir/venv/bin/ai-agent-scanner" evaluate --output fixture-metrics.json
"$smoke_dir/venv/bin/python" -c 'import json; result = json.load(open("fixture-metrics.json")); assert result["mode"] == "offline_replay"; assert result["metrics"]["case_count"] == 6'
