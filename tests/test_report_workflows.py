import json
from copy import deepcopy
from datetime import datetime, timezone

import pytest
from click.testing import CliRunner

from scanner_cli import cli
from src.reporting.workflows import apply_policy, compare_reports, inventory


def report(findings=True, status='completed', endpoint='https://example.test/api'):
    return {'schema_version': '1.0', 'scan_type': 'full', 'status': status, 'summary': {},
            'agents': [{'id': 'random-snapshot', 'provider': 'test', 'name': 'fixture',
                        'endpoint': endpoint, 'security_status': 'completed',
                        'vulnerabilities': [{'id': 'random-finding', 'vulnerability_type': 'prompt_injection',
                                             'severity': 'high', 'timestamp': 'old'}] if findings else []}]}


def policy(asset_key, expiry='2030-01-01T00:00:00Z'):
    return {'suppressions': [{'asset_key': asset_key, 'rule_id': 'prompt_injection',
                             'rationale': 'Lab fixture approved through expiry', 'expires_at': expiry}]}


def test_diff_ignores_random_ids_and_timestamps():
    before = report()
    after = deepcopy(before)
    after['agents'][0]['id'] = 'different-snapshot'
    after['agents'][0]['vulnerabilities'][0].update(id='different-finding', timestamp='new')
    result = compare_reports(before, after)
    assert len(result['persistent']) == 1
    assert result['newly_observed'] == result['resolved'] == []


@pytest.mark.parametrize('status', ['partial', 'failed', 'interrupted'])
def test_incomplete_scan_cannot_resolve(status):
    result = compare_reports(report(), report(False, status))
    assert result['resolved'] == []
    assert len(result['resolution_unverified']) == 1


def test_completed_same_asset_resolves_but_missing_asset_does_not():
    after = report(False)
    assert compare_reports(report(), after)['resolved'] == []
    after['agents'][0]['checks'] = [{'rule_id': 'other_rule', 'status': 'passed'}]
    assert compare_reports(report(), after)['resolved'] == []
    after['agents'][0]['checks'] = [{'rule_id': 'prompt_injection', 'status': 'passed'}]
    assert compare_reports(report(), after)['resolved'] == []
    before = report()
    before['agents'][0]['vulnerabilities'][0].update(
        probe_id='fixture.sample', probe_version='1:fixture', evidence_context_id='lab-policy-v1')
    after['agents'][0]['checks'] = [{'rule_id': 'prompt_injection', 'probe_id': 'fixture.sample',
                                   'probe_version': '1:fixture', 'status': 'completed',
                                   'outcome': 'passed', 'responses_evaluated': 1, 'requests_attempted': 1,
                                   'evidence_context_id': 'lab-policy-v1'}]
    assert compare_reports(before, after)['resolved'] == []
    assert len(compare_reports(before, after)['resolution_unverified']) == 1
    after['agents'] = []
    result = compare_reports(report(), after)
    assert result['resolved'] == []
    assert len(result['inventory_not_observed']) == 1


def test_endpointless_fallback_is_explicit_and_not_verified_resolution():
    result = compare_reports(report(endpoint=None), report(False, endpoint=None))
    assert result['resolved'] == []
    assert len(result['resolution_unverified']) == 1
    assets, _ = inventory(report(endpoint=None))
    assert next(iter(assets.values()))['identity_basis'] == 'provider_name_fallback'


@pytest.mark.parametrize('redacted_side', ['before', 'after'])
def test_redacted_endpoint_on_either_side_prevents_resolution(redacted_side):
    before, after = report(), report(False)
    after['agents'][0]['checks'] = [{'rule_id': 'prompt_injection', 'status': 'passed'}]
    (before if redacted_side == 'before' else after)['agents'][0]['endpoint_redacted'] = True
    result = compare_reports(before, after)
    assert result['resolved'] == []
    assert len(result['resolution_unverified']) == 1


def test_policy_expiry_and_source_immutability():
    source = report()
    original = deepcopy(source)
    asset_key = next(iter(inventory(source)[0]))
    now = datetime(2026, 10, 13, tzinfo=timezone.utc)
    result = apply_policy(source, policy(asset_key), now)
    assert result['summary']['suppressed_findings'] == 1
    assert result['summary']['active_findings'] == 0
    assert source == original
    expired = apply_policy(source, policy(asset_key, '2026-01-01T00:00:00Z'), now)
    assert expired['summary']['active_findings'] == 1
    assert expired['summary']['expired_suppressions'] == 1


@pytest.mark.parametrize('field,value', [('rationale', ''), ('expires_at', '2030-01-01'),
                                       ('asset_key', '*'), ('rule_id', '')])
def test_invalid_policy_rejected(field, value):
    source = report()
    rules = policy(next(iter(inventory(source)[0])))
    rules['suppressions'][0][field] = value
    with pytest.raises(ValueError):
        apply_policy(source, rules)


def test_cli_diff_and_source_overwrite_protection(tmp_path):
    before, after, output = (tmp_path / name for name in ('before.json', 'after.json', 'diff.json'))
    before.write_text(json.dumps(report()))
    after.write_text(json.dumps(report(False)))
    runner = CliRunner()
    result = runner.invoke(cli, ['diff', '--before', str(before), '--after', str(after), '--output', str(output)])
    assert result.exit_code == 0, result.output
    assert len(json.loads(output.read_text())['resolution_unverified']) == 1
    original = before.read_text()
    result = runner.invoke(cli, ['diff', '--before', str(before), '--after', str(after), '--output', str(before)])
    assert result.exit_code != 0
    assert before.read_text() == original


def test_ambiguous_assets_are_not_suppressed():
    source = report()
    source['agents'].append(deepcopy(source['agents'][0]))
    rules = policy(next(iter(inventory(source)[0])))
    derived = apply_policy(source, rules, datetime(2026, 10, 13, tzinfo=timezone.utc))
    assert derived['summary']['suppressed_findings'] == 0
    assert len(derived['active_findings'][0]['occurrences']) == 2


def test_cli_triage_writes_derived_file(tmp_path):
    source, rules, output = (tmp_path / name for name in ('source.json', 'policy.json', 'triage.json'))
    source.write_text(json.dumps(report()))
    rules.write_text(json.dumps({'suppressions': []}))
    result = CliRunner().invoke(cli, ['triage', '--report', str(source), '--policy', str(rules),
                                     '--output', str(output)])
    assert result.exit_code == 0, result.output
    assert json.loads(output.read_text())['summary']['active_findings'] == 1
