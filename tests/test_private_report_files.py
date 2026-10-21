"""Generated reports must not inherit a world-readable default umask."""

import os
import stat

import pytest

from src.core.files import write_private_text
from src.reporting.report_generator import ReportGenerator
from src.reporting.sarif_output import write_sarif


def test_report_write_is_private_and_unicode_safe(tmp_path):
    destination = tmp_path / "report.json"
    previous = os.umask(0o022)
    try:
        assert write_private_text(destination, '{"text": "caf\u00e9"}') == destination
    finally:
        os.umask(previous)
    assert stat.S_IMODE(destination.stat().st_mode) == 0o600
    assert destination.read_text(encoding="utf-8") == '{"text": "caf\u00e9"}'
    assert list(tmp_path.iterdir()) == [destination]


def test_replacing_existing_report_tightens_permissions(tmp_path):
    destination = tmp_path / "report.json"
    destination.write_text("old")
    destination.chmod(0o644)
    write_private_text(destination, "new")
    assert destination.read_text() == "new"
    assert stat.S_IMODE(destination.stat().st_mode) == 0o600


@pytest.mark.parametrize("dangling", [False, True])
def test_destination_symlink_is_rejected_without_touching_target(tmp_path, dangling):
    target = tmp_path / "target"
    if not dangling:
        target.write_text("do not replace")
    destination = tmp_path / "report.json"
    destination.symlink_to(target)
    with pytest.raises(ValueError, match="symlink"):
        write_private_text(destination, "new")
    assert destination.is_symlink()
    assert target.exists() is not dangling
    if not dangling:
        assert target.read_text() == "do not replace"


def test_failed_replace_preserves_previous_report_and_removes_temporary(tmp_path, monkeypatch):
    destination = tmp_path / "report.json"
    destination.write_text("old")

    def fail(*args):
        raise OSError("injected write failure")

    monkeypatch.setattr(os, "replace", fail)
    with pytest.raises(OSError, match="injected"):
        write_private_text(destination, "new")
    assert destination.read_text() == "old"
    assert list(tmp_path.iterdir()) == [destination]


@pytest.mark.parametrize("fmt", ["json", "txt", "sarif"])
def test_exporters_write_private_files(tmp_path, fmt):
    destination = tmp_path / ("report." + fmt)
    if fmt == "sarif":
        write_sarif([], str(destination))
    else:
        ReportGenerator().save_report({}, str(destination), fmt=fmt)
    assert stat.S_IMODE(destination.stat().st_mode) == 0o600
