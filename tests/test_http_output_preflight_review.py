"""Independent path-alias controls for the HTTP assessment preflight."""

from pathlib import Path
from unittest.mock import Mock

from click.testing import CliRunner
import pytest

import scanner_cli
import src.core.http_target_profiles as profiles
from tests.test_http_target_profiles import CANARY, CANARY_ENV, document


@pytest.fixture
def selected_profile(tmp_path, monkeypatch):
    monkeypatch.setenv(CANARY_ENV, CANARY)
    path = tmp_path / 'private' / 'target.json'
    profiles.create_http_target_profile(path, document())
    return path


@pytest.mark.parametrize('kind', ['two-leaf-cycle', 'two-parent-cycle', 'missing-before-dotdot', 'nul'])
def test_invalid_paths_fail_before_preparation_with_static_errors(selected_profile, tmp_path, monkeypatch, kind):
    first, second = tmp_path / CANARY, tmp_path / 'second-link'
    if kind in {'two-leaf-cycle', 'two-parent-cycle'}:
        first.symlink_to(second)
        second.symlink_to(first)
        output = first if kind == 'two-leaf-cycle' else first / 'report.json'
    elif kind == 'missing-before-dotdot':
        output = tmp_path / CANARY / '..' / 'report.json'
    else:
        output = str(first) + '\x00.json'
    original_resolve = Path.resolve

    def resolve(path, strict=False):
        if kind in {'two-leaf-cycle', 'two-parent-cycle'} and path == output and not strict:
            return path.absolute()
        return original_resolve(path, strict=strict)

    monkeypatch.setattr(Path, 'resolve', resolve)
    before = selected_profile.read_bytes()
    blocked = Mock(side_effect=AssertionError('Invalid output reached private preparation or execution'))
    monkeypatch.setattr(profiles, 'prepare_http_profile', blocked)
    monkeypatch.setattr(scanner_cli, '_execute', blocked)
    result = CliRunner().invoke(scanner_cli.cli, ['assess', '--profile', str(selected_profile),
        '--output', str(output), '--allow-loopback'])
    assert result.exit_code != 0
    assert 'Target profile is unavailable or unsafe' in result.output
    assert CANARY not in result.output and str(selected_profile) not in result.output
    blocked.assert_not_called()
    assert selected_profile.read_bytes() == before


def test_profile_alias_with_parent_link_and_dotdot_is_refused(selected_profile, tmp_path, monkeypatch):
    reports = tmp_path / 'reports'
    reports.mkdir()
    alias = tmp_path / 'reports-alias'
    alias.symlink_to(reports, target_is_directory=True)
    output = alias / '..' / selected_profile.parent.name / selected_profile.name
    before = selected_profile.read_bytes()
    blocked = Mock(side_effect=AssertionError('Profile alias reached private preparation or execution'))
    monkeypatch.setattr(profiles, 'prepare_http_profile', blocked)
    monkeypatch.setattr(scanner_cli, '_execute', blocked)
    result = CliRunner().invoke(scanner_cli.cli, ['assess', '--profile', str(selected_profile),
        '--output', str(output), '--allow-loopback'])
    assert result.exit_code != 0 and 'Target profile is unavailable or unsafe' in result.output
    assert str(output) not in result.output and str(selected_profile) not in result.output
    blocked.assert_not_called()
    assert selected_profile.read_bytes() == before


@pytest.mark.parametrize('existing', [False, True])
def test_preflight_accepts_nested_canonical_ancestors_without_writes(selected_profile, tmp_path, monkeypatch, existing):
    reports = tmp_path / 'reports'
    reports.mkdir()
    nested = reports / 'nested'
    nested.mkdir()
    first, second = tmp_path / 'first-alias', tmp_path / 'second-alias'
    first.symlink_to(reports, target_is_directory=True)
    second.symlink_to(first, target_is_directory=True)
    output = second / 'nested' / '..' / 'report.json'
    real_output = reports / 'report.json'
    if existing:
        real_output.write_text('Preserve until execution')
    before = {path.relative_to(tmp_path): path.lstat() for path in tmp_path.rglob('*')}
    original = Path.resolve

    def strict_only(path, strict=False):
        assert strict, 'Preflight must not depend on non-strict resolution semantics'
        return original(path, strict=True)

    monkeypatch.setattr(Path, 'resolve', strict_only)
    scanner_cli._validate_assessment_output(selected_profile, output)
    after = {path.relative_to(tmp_path): path.lstat() for path in tmp_path.rglob('*')}
    assert set(after) == set(before)
    assert all((after[path].st_ino, after[path].st_mode, after[path].st_size) ==
               (identity.st_ino, identity.st_mode, identity.st_size) for path, identity in before.items())
    if existing:
        assert real_output.read_text() == 'Preserve until execution'
    else:
        assert not real_output.exists()
