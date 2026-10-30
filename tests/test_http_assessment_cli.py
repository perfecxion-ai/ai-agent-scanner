"""Guided CLI setup and planning without target or operator configuration I/O."""

import json
import socket
import sys
from unittest.mock import Mock

from click.testing import CliRunner
import pytest

import scanner_cli
from src.core.http_target_profiles import create_http_target_profile
from tests.test_http_application_core import application as application
from tests.test_http_target_profiles import CANARY, CANARY_ENV, CREDENTIAL, CREDENTIAL_ENV, document


@pytest.fixture
def profile(tmp_path, monkeypatch):
    monkeypatch.setenv(CANARY_ENV, CANARY)
    monkeypatch.setenv(CREDENTIAL_ENV, CREDENTIAL)
    path = tmp_path / 'private' / 'target.json'
    create_http_target_profile(path, document())
    return path


def wizard_input(*, bearer=False, seeded=True):
    fields = ['http://127.0.0.1:19876/chat', '', '', '/answer/text', 'bearer' if bearer else '']
    if bearer:
        fields.extend([CREDENTIAL_ENV, 'authorized-principal-v1'])
    fields.extend([CANARY_ENV, 'fixture-context-v1', 'yes' if seeded else 'no'])
    return '\n'.join(fields) + '\n'


@pytest.mark.parametrize('bearer', [False, True])
def test_wizard_creates_a_private_usable_profile_without_echo_or_network(tmp_path, monkeypatch, bearer):
    monkeypatch.setenv(CANARY_ENV, CANARY)
    monkeypatch.setenv(CREDENTIAL_ENV, CREDENTIAL)
    network = Mock(side_effect=AssertionError('Setup cannot contact a target'))
    monkeypatch.setattr(socket, 'getaddrinfo', network)
    monkeypatch.setattr(socket, 'socket', network)
    monkeypatch.setitem(sys.modules, 'app', None)
    path = tmp_path / 'private' / 'wizard.json'
    result = CliRunner().invoke(scanner_cli.cli, ['target', 'init', 'Support bot', '--output', str(path)],
                                input=wizard_input(bearer=bearer))
    assert result.exit_code == 0, result.output
    assert 'Private target profile created.' in result.output
    assert all(value not in result.output for value in (CANARY, CREDENTIAL, CANARY_ENV, CREDENTIAL_ENV,
                                                      str(path), 'http://127.0.0.1:19876/chat'))
    value = json.loads(path.read_text())
    assert value['http_target']['request_prompt_field'] == 'question'
    assert value['http_target']['response_text_pointer'] == '/answer/text'
    assert value['http_target']['auth_scheme'] == ('bearer' if bearer else 'none')
    assert value['allowed_networks'] == ['127.0.0.1/32']
    assert value['credential_env'] == (CREDENTIAL_ENV if bearer else None)
    assert path.stat().st_mode & 0o777 == 0o600 and path.parent.stat().st_mode & 0o777 == 0o700
    network.assert_not_called()


def test_wizard_does_not_claim_an_unseeded_target_is_ready(tmp_path):
    path = tmp_path / 'private' / 'target.json'
    result = CliRunner().invoke(scanner_cli.cli, ['target', 'init', 'Support bot', '--output', str(path)],
                                input=wizard_input(seeded=False))
    assert result.exit_code != 0 and 'Seed a synthetic protected canary' in result.output
    assert not path.exists() and not path.parent.exists()


def test_wizard_can_record_unavailable_references_without_claiming_readiness(tmp_path, monkeypatch):
    monkeypatch.delenv(CANARY_ENV, raising=False)
    monkeypatch.delenv(CREDENTIAL_ENV, raising=False)
    path = tmp_path / 'private' / 'target.json'
    runner = CliRunner()
    result = runner.invoke(scanner_cli.cli, ['target', 'init', 'Support bot', '--output', str(path)],
                           input=wizard_input(bearer=True))
    assert result.exit_code == 0, result.output
    preview = runner.invoke(scanner_cli.cli, ['assess', '--profile', str(path), '--plan', '--allow-loopback'])
    assert preview.exit_code == 2
    assert set(json.loads(preview.output)['reason_codes']) == {
        'protected_canary_reference_unavailable', 'credential_reference_unavailable'}


def test_wizard_from_an_ordinary_checkout_creates_only_the_selected_private_child(tmp_path, monkeypatch):
    monkeypatch.setenv(CANARY_ENV, CANARY)
    checkout = tmp_path / 'ordinary-checkout'
    checkout.mkdir(mode=0o755)
    (checkout / 'unrelated.txt').write_text('Preserve working directory contents')
    monkeypatch.chdir(checkout)
    result = CliRunner().invoke(scanner_cli.cli, ['target', 'init', 'Support bot', '--output',
                                                'private-targets/support-bot.json'], input=wizard_input())
    assert result.exit_code == 0, result.output
    assert checkout.stat().st_mode & 0o777 == 0o755
    assert (checkout / 'unrelated.txt').read_text() == 'Preserve working directory contents'
    assert (checkout / 'private-targets').stat().st_mode & 0o777 == 0o700
    assert (checkout / 'private-targets/support-bot.json').stat().st_mode & 0o777 == 0o600


def test_plan_is_json_and_performs_no_execution_output_or_checkpoint_work(profile, monkeypatch, tmp_path):
    blocked = Mock(side_effect=AssertionError('Plan cannot execute or write a report'))
    monkeypatch.setattr(scanner_cli, '_execute', blocked)
    monkeypatch.setattr(scanner_cli, 'write_private_text', blocked)
    monkeypatch.setattr(socket, 'socket', blocked)
    monkeypatch.setattr(socket, 'getaddrinfo', blocked)
    output, checkpoint = tmp_path / 'report.json', tmp_path / 'checkpoint'
    result = CliRunner().invoke(scanner_cli.cli, ['assess', '--profile', str(profile), '--plan', '--allow-loopback',
                                '--output', str(output), '--checkpoint-dir', str(checkpoint)])
    assert result.exit_code == 0, result.output
    value = json.loads(result.output)
    assert value['configuration_status'] == 'ready' and value['selected_rule_count'] == 7
    assert value['maximum_prompt_http_attempts'] == value['shared_attempt_budget'] == 35
    assert value['network_readiness_status'] == 'not_checked'
    assert value['target'] == {
        'name': 'Support application', 'http_target': document()['http_target'],
        'allowed_networks': ['127.0.0.1/32']}
    descriptor = value['target']['http_target']
    assert descriptor['endpoint'] == 'http://127.0.0.1:19876/chat'
    assert descriptor['request_prompt_field'] == 'question' and descriptor['response_text_pointer'] == '/answer/text'
    assert descriptor['auth_scheme'] == 'none' and descriptor['principal_label'] == 'anonymous'
    assert value['overall_timeout_seconds'] == 180 and value['request_timeout_seconds'] == 10
    assert value['max_response_bytes'] == 65536
    assert all(secret not in result.output for secret in (CANARY, CREDENTIAL, CANARY_ENV, str(profile)))
    assert not output.exists() and not checkpoint.exists()
    blocked.assert_not_called()


def test_plan_displays_public_bearer_identity_without_private_references(tmp_path, monkeypatch):
    monkeypatch.setenv(CANARY_ENV, CANARY)
    monkeypatch.setenv(CREDENTIAL_ENV, CREDENTIAL)
    path = tmp_path / 'private' / 'bearer.json'
    create_http_target_profile(path, document(bearer=True))
    result = CliRunner().invoke(scanner_cli.cli, ['assess', '--profile', str(path), '--plan', '--allow-loopback'])
    assert result.exit_code == 0, result.output
    target = json.loads(result.output)['target']
    assert target['http_target']['auth_scheme'] == 'bearer'
    assert target['http_target']['principal_label'] == 'authorized-test-v1'
    assert target['http_target']['context_label'] == 'support-protected-fixture-v1'
    assert target['allowed_networks'] == ['127.0.0.1/32']
    assert all(secret not in result.output for secret in (CANARY, CREDENTIAL, CANARY_ENV, CREDENTIAL_ENV, str(path)))


def test_missing_reference_prints_blocked_plan_with_nonzero_exit(profile, monkeypatch):
    monkeypatch.delenv(CANARY_ENV)
    result = CliRunner().invoke(scanner_cli.cli, ['assess', '--profile', str(profile), '--plan', '--allow-loopback'])
    assert result.exit_code == 2
    assert json.loads(result.output)['reason_codes'] == ['protected_canary_reference_unavailable']
    assert CANARY_ENV not in result.output and str(profile) not in result.output


@pytest.mark.parametrize('option', ['--max-requests', '--max-response-bytes', '--timeout-seconds',
                                    '--request-timeout-seconds', '--format'])
def test_invalid_option_values_have_static_errors(profile, option):
    result = CliRunner().invoke(scanner_cli.cli, ['assess', '--profile', str(profile), option, CANARY])
    assert result.exit_code != 0 and CANARY not in result.output


@pytest.mark.parametrize('count', ['0', '36'])
def test_assessment_request_budget_cannot_exceed_the_selected_sample_contract(profile, count):
    result = CliRunner().invoke(scanner_cli.cli, ['assess', '--profile', str(profile), '--max-requests', count])
    assert result.exit_code != 0


@pytest.mark.parametrize('value', ['nan', 'NaN', 'inf', '-inf'])
def test_nonfinite_request_timeouts_refused_before_profile_or_environment_access(profile, monkeypatch, value):
    import src.core.http_target_profiles as profiles
    load = Mock(side_effect=AssertionError('Invalid bounds must fail before profile loading'))
    monkeypatch.setattr(profiles, 'load_http_target_profile', load)
    result = CliRunner().invoke(scanner_cli.cli, ['assess', '--profile', str(profile), '--plan',
                                                '--request-timeout-seconds', value])
    assert result.exit_code != 0 and value not in result.output
    load.assert_not_called()


def test_missing_profile_path_and_report_alias_errors_do_not_echo_private_paths(profile, tmp_path):
    missing = tmp_path / CANARY / 'absent.json'
    result = CliRunner().invoke(scanner_cli.cli, ['assess', '--profile', str(missing), '--plan'])
    assert result.exit_code != 0 and CANARY not in result.output and str(missing) not in result.output
    before = profile.read_bytes()
    result = CliRunner().invoke(scanner_cli.cli, ['assess', '--profile', str(profile), '--output', str(profile),
                                '--allow-loopback'])
    assert result.exit_code != 0 and str(profile) not in result.output
    assert profile.read_bytes() == before


def test_report_path_resolution_failure_has_a_static_error(profile, tmp_path):
    loop = tmp_path / CANARY
    loop.symlink_to(loop)
    result = CliRunner().invoke(scanner_cli.cli, ['assess', '--profile', str(profile), '--output', str(loop),
                                                '--allow-loopback'])
    assert result.exit_code != 0 and CANARY not in result.output and str(loop) not in result.output
    assert 'Target profile is unavailable or unsafe' in result.output


def test_new_entrypoint_passes_only_the_selected_target_and_explicit_budget(profile, monkeypatch, tmp_path):
    from src.core.http_application_runtime import get_http_target
    captured = {}
    async def execute(scope, agents, output, fmt, mode, verbose, max_requests, max_response_bytes,
                      timeout_seconds, allow_loopback, **kwargs):
        assert scope is None and len(agents) == 1 and mode == 'security_only'
        assert agents[0]['model'] is None and agents[0]['provider'] == 'http-json'
        assert get_http_target(agents[0]).canary == CANARY
        captured.update(kwargs, max_requests=max_requests, max_response_bytes=max_response_bytes,
                        timeout_seconds=timeout_seconds, allow_loopback=allow_loopback)
    monkeypatch.setattr(scanner_cli, '_execute', execute)
    result = CliRunner().invoke(scanner_cli.cli, ['assess', '--profile', str(profile), '--allow-loopback',
                                '--output', str(tmp_path / 'report.json')])
    assert result.exit_code == 0, result.output
    assert captured == {'max_requests': 35, 'max_response_bytes': 65536, 'timeout_seconds': 180,
                        'allow_loopback': True, 'request_timeout_seconds': 10,
                        'prompt_suite': 'protected-disclosure-v1', 'checkpoint_dir': None,
                        'assessment_objective': 'protected-prompt-disclosure-v1',
                        'allowed_networks': ('127.0.0.1/32',)}


@pytest.mark.parametrize('status,confirmed,expected', [
    ('completed', True, 'Confirmed disclosure'), ('partial', True, 'Confirmed disclosure; partial assessment'),
    ('completed', False, 'Inconclusive'), ('failed', False, 'Assessment incomplete'),
])
def test_terminal_summary_does_not_count_repeated_occurrences_as_separate_vulnerabilities(status, confirmed, expected):
    from click.testing import CliRunner
    @scanner_cli.click.command()
    def summary():
        scanner_cli._assessment_summary({'status': status, 'security_results': [{
            'checks': [{'requests_attempted': 5, 'responses_evaluated': 4}],
            'vulnerabilities': [{'evidence_status': 'confirmed'}] * 4 if confirmed else [],
        }]})
    result = CliRunner().invoke(summary)
    minimum = 'known minimum ' if status != 'completed' else ''
    assert result.exit_code == 0 and result.output == expected + ': ' + minimum + '4 responses evaluated from 5 attempts. Report written.\n'
    assert 'vulnerabilities' not in result.output


def test_terminal_counters_use_source_local_maxima_without_counting_duplicate_views():
    identity = {'rule_id': 'prompt_injection.system_prompt_extraction', 'probe_id': 'prompt.sample',
                'probe_version': 'owned-probe', 'evidence_context_id': 'owned-context'}
    sources = [
        {'agent_id': 'one', 'checks': [{**identity, 'requests_attempted': 5, 'responses_evaluated': 5}],
         'check_evidence': [{**identity, 'requests_attempted': 1, 'responses_evaluated': 1}]},
        {'agent_id': 'two', 'checks': [{**identity, 'requests_attempted': 2, 'responses_evaluated': 2}],
         'check_evidence': [{**identity, 'requests_attempted': 1, 'responses_evaluated': 1}]},
    ]
    @scanner_cli.click.command()
    def summary():
        scanner_cli._assessment_summary({'status': 'completed', 'security_results': sources, 'agents': sources})
    result = CliRunner().invoke(summary)
    assert result.exit_code == 0
    assert result.output == 'Inconclusive: 7 responses evaluated from 7 attempts. Report written.\n'


@pytest.mark.asyncio
async def test_terminal_summary_counts_genuine_unfinished_disclosure_receipts(application):
    from src.core.contracts import confirmed_findings
    from tests.test_http_application_core import assess
    endpoint, _ = application
    snapshots = []
    await assess(endpoint, maximum=1, checkpoints=snapshots)
    snapshot = next(value for value in snapshots if value.get('security_results')
                    and value['security_results'][0].get('check_evidence')
                    and not sum(check['requests_attempted'] for check in value['security_results'][0]['checks']))
    source = snapshot['security_results'][0]
    assert confirmed_findings(source), 'The precondition must be supported live-response disclosure evidence'
    # The receipt can precede numeric scoring; its live evidence is supported.
    assert source['check_evidence'][0]['requests_attempted'] == source['check_evidence'][0]['responses_evaluated'] == 1
    @scanner_cli.click.command()
    def summary():
        scanner_cli._assessment_summary(snapshot)
    result = CliRunner().invoke(summary)
    assert result.exit_code == 0
    assert result.output == ('Confirmed disclosure; partial assessment: known minimum '
                             '1 response evaluated from 1 attempt. Report written.\n')


@pytest.mark.parametrize('mode,score', [('leak', 70), ('quiet', None)])
@pytest.mark.parametrize('fmt', ['json', 'sarif'])
def test_actual_wizard_plan_and_assessment_custom_route(application, tmp_path, monkeypatch, mode, score, fmt):
    from tests.test_http_application_core import MARKER
    endpoint, state = application
    state['mode'] = mode
    monkeypatch.setenv(CANARY_ENV, MARKER)
    profile = tmp_path / 'private' / 'wizard-profile.json'
    inputs = '\n'.join([endpoint, '', '', '/result/answer', '', CANARY_ENV, 'owned-cli-fixture-v1', 'yes']) + '\n'
    runner = CliRunner()
    setup = runner.invoke(scanner_cli.cli, ['target', 'init', 'Application fixture', '--output', str(profile)],
                          input=inputs)
    assert setup.exit_code == 0, setup.output
    preview = runner.invoke(scanner_cli.cli, ['assess', '--profile', str(profile), '--plan', '--allow-loopback'])
    assert preview.exit_code == 0 and json.loads(preview.output)['configuration_status'] == 'ready'
    assert state['requests'] == []
    output = tmp_path / 'assessment.json'
    result = runner.invoke(scanner_cli.cli, ['assess', '--profile', str(profile), '--allow-loopback',
                           '--output', str(output), '--format', fmt])
    assert result.exit_code == 0, result.output
    assert len(state['requests']) == 35 and all(row[0] == '/custom/assistant' for row in state['requests'])
    report = json.loads(output.read_text())
    if fmt == 'json':
        assert report['summary']['overall_risk_score'] == score
        assert len(report['agents'][0]['checks']) == 7
        assert all(check['outcome'] != 'passed' for check in report['agents'][0]['checks'])
    else:
        assert report['runs'][0]['properties']['summary']['overall_risk_score'] == score
        assert len(report['runs'][0]['properties']['checks']) == 7
    assert ('Confirmed disclosure' if mode == 'leak' else 'Inconclusive') in result.output
    assert '35 responses evaluated from 35 attempts' in result.output
    assert all(value not in output.read_text() + result.output + preview.output + setup.output
               for value in (MARKER, CANARY_ENV, str(profile)))
    assert output.stat().st_mode & 0o777 == 0o600
