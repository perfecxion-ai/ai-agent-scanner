"""Run dependency-free browser-controller tests when Node is available."""

import shutil
import subprocess
from pathlib import Path

import pytest


def test_dashboard_controller():
    node = shutil.which('node')
    if not node:
        pytest.skip('Node is required for dashboard controller tests')
    root = Path(__file__).resolve().parents[1]
    subprocess.run([node, '--test', 'tests/dashboard.test.cjs'], cwd=root, check=True,
                   capture_output=True, text=True, timeout=30)
