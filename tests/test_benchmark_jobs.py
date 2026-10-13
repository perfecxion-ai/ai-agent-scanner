"""The load script must fail before touching a cached application's database."""

import argparse
import importlib.util
import os
from pathlib import Path
from unittest.mock import Mock, patch

import pytest

from tests.test_api_auth import api as api


def test_cached_application_engine_is_rejected_before_database_access(api, tmp_path):
    server, _ = api
    spec = importlib.util.spec_from_file_location(
        "benchmark_jobs", Path(__file__).resolve().parents[1] / "scripts" / "benchmark-jobs.py")
    benchmark = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(benchmark)
    initialize = Mock()
    benchmark.initialize_schema = initialize
    args = argparse.Namespace(jobs=4, workers=1, latency_ms=0, timeout_seconds=1)
    before = dict(os.environ)
    with patch.dict(os.environ), patch.object(server.db.engine, "connect") as connect:
        with pytest.raises(ValueError, match="requested temporary SQLite database"):
            benchmark.run(args, tmp_path / "never-created.sqlite")
        connect.assert_not_called()
        initialize.assert_not_called()
    assert dict(os.environ) == before
    assert not (tmp_path / "never-created.sqlite").exists()
