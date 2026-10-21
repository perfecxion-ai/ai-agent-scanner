"""Deterministic fixture evaluation, including intentional false negatives."""

import base64
import json
import socket
import subprocess
from unittest.mock import patch

import pytest
from click.testing import CliRunner

from scanner_cli import cli
from src.evaluation import evaluate_suite
from src.evaluation import replay
from src.evaluation.fixtures import synthetic_suite
from src.evaluation.replay import _text_leaves


@pytest.fixture(autouse=True)
def forbid_execution():
    with patch.object(subprocess, 'Popen', side_effect=AssertionError('Execution forbidden')), patch.object(socket, 'socket', side_effect=AssertionError('Networking forbidden')):
        yield


def test_synthetic_confusion_matrix_and_stable_redacted_evidence():
    suite = synthetic_suite()
    report = evaluate_suite(suite)
    assert report == evaluate_suite(suite)
    assert report['metrics'] == {'true_positive': 3, 'false_positive': 0, 'true_negative': 3,
                                  'false_negative': 0, 'precision': 1.0, 'recall': 1.0, 'f1': 1.0, 'case_count': 6}
    assert 'SYNTHETIC-INJECTION-' not in json.dumps(report)
    assert 'SYNTHETIC-FOREIGN-DOC-' not in json.dumps(report)
    assert 'Ignore previous instructions' not in json.dumps(report)


def test_labels_do_not_control_detection_and_disagreements_count():
    suite = synthetic_suite()
    suite['cases'][0]['expected_violation'] = False
    suite['cases'][3]['expected_violation'] = True
    report = evaluate_suite(suite)
    assert report['cases'][0]['predicted_violation'] is True
    assert report['cases'][3]['predicted_violation'] is False
    assert report['metrics']['false_positive'] == 1
    assert report['metrics']['false_negative'] == 1
    assert report['metrics']['precision'] == pytest.approx(2 / 3)
    assert report['metrics']['recall'] == pytest.approx(2 / 3)


def test_encoded_leak_exposes_known_detection_limitation():
    suite = synthetic_suite()
    case = suite['cases'][1]
    secret = case['policy']['protected_canaries'][0]['value']
    case['observed']['outputs'] = [base64.b64encode(secret.encode()).decode()]
    report = evaluate_suite(suite)
    assert report['metrics']['false_negative'] == 1
    assert report['checks']['REPLAY002']['recall'] == 0


def test_rag_canary_in_nested_tool_arguments_is_detected_without_execution():
    suite = synthetic_suite()
    case = suite['cases'][1]
    secret = case['policy']['protected_canaries'][0]['value']
    case['observed'] = {'outputs': [], 'tool_calls': [{'name': 'send', 'arguments': {'records': [{'data': secret}]}}]}
    report = evaluate_suite(suite)
    assert report['cases'][1]['predicted_violation']
    assert secret not in json.dumps(report)


def tenant_key_suite(arguments, *, expected=True):
    suite = synthetic_suite()
    case = suite['cases'][1]
    case['observed'] = {'outputs': [], 'tool_calls': [{'name': 'send', 'arguments': arguments}]}
    case['expected_violation'] = expected
    suite['cases'] = [case]
    return suite


@pytest.mark.parametrize('wrap,location', [
    (lambda secret: {secret: 'safe'}, '/keys/0'),
    (lambda secret: {'container': {secret: 'safe'}}, '/values/0/keys/0'),
    (lambda secret: {'records': [{secret: 'safe'}]}, '/values/0/0/keys/0'),
    (lambda secret: {'records': [[{'nested': {secret: 'safe'}}]]}, '/values/0/0/0/values/0/keys/0'),
])
def test_foreign_canary_in_object_keys_at_each_depth(wrap, location):
    secret = synthetic_suite()['cases'][1]['policy']['protected_canaries'][0]['value']
    report = evaluate_suite(tenant_key_suite(wrap(secret)))
    assert report['ruleset_version'] == '1.1.0'
    assert report['metrics']['true_positive'] == 1
    evidence = report['cases'][0]['evidence']
    assert len(evidence) == 1
    assert evidence[0]['location'] == '/observed/tool_calls/0/arguments' + location
    assert evidence[0]['kind'] == 'foreign_canary_returned' and evidence[0]['policy_index'] == 0
    assert secret not in json.dumps(report)


def test_key_and_value_occurrences_keep_numeric_secret_safe_locations_and_stable_ids():
    secret = synthetic_suite()['cases'][1]['policy']['protected_canaries'][0]['value']
    suite = tenant_key_suite({'untrusted/name~1': {secret: [secret, {secret: 'safe'}]}, secret: secret})
    report = evaluate_suite(suite)
    assert report == evaluate_suite(suite)
    evidence = report['cases'][0]['evidence']
    prefix = '/observed/tool_calls/0/arguments'
    assert [item['location'] for item in evidence] == [
        prefix + '/values/0/keys/0', prefix + '/values/0/values/0/0',
        prefix + '/values/0/values/0/1/keys/0', prefix + '/keys/1', prefix + '/values/1']
    assert len({item['id'] for item in evidence}) == len(evidence)
    serialized = json.dumps(report)
    assert secret not in serialized and 'untrusted/name~1' not in serialized
    assert all(set(item) == {'kind', 'policy_index', 'location', 'id'} for item in evidence)


@pytest.mark.parametrize('make_key,detected,expected_violation', [
    (lambda secret: secret, True, True),
    (lambda secret: 'prefix:' + secret + ':suffix', True, True),
    (lambda secret: secret[:-1], False, False),
    (lambda secret: secret.lower(), False, False),
    (lambda secret: secret.replace('-', '_'), False, False),
    (lambda secret: base64.b64encode(secret.encode()).decode(), False, True),
    (lambda secret: ''.join('%%%02X' % byte for byte in secret.encode()), False, True),
    (lambda secret: 'ordinary-property', False, False),
])
def test_key_disclosure_requires_exact_marker_not_near_or_encoded_forms(make_key, detected, expected_violation):
    secret = synthetic_suite()['cases'][1]['policy']['protected_canaries'][0]['value']
    report = evaluate_suite(tenant_key_suite({make_key(secret): 'safe'}, expected=expected_violation))
    assert report['cases'][0]['predicted_violation'] is detected
    if expected_violation and not detected:
        assert report['metrics']['false_negative'] == 1
        assert report['checks']['REPLAY002']['recall'] == 0
    assert secret not in json.dumps(report)


def test_key_detection_does_not_use_expected_labels():
    secret = synthetic_suite()['cases'][1]['policy']['protected_canaries'][0]['value']
    positive = evaluate_suite(tenant_key_suite({secret: 'safe'}, expected=False))
    negative = evaluate_suite(tenant_key_suite({'safe': 'ordinary'}, expected=True))
    assert positive['metrics']['false_positive'] == 1
    assert negative['metrics']['false_negative'] == 1


def test_key_text_is_not_part_of_evidence_identity():
    secret = synthetic_suite()['cases'][1]['policy']['protected_canaries'][0]['value']
    first = evaluate_suite(tenant_key_suite({'private-parent': {secret: 'safe'}}))
    second = evaluate_suite(tenant_key_suite({'different-private-parent': {'prefix:' + secret: 'safe'}}))
    assert first['cases'][0]['evidence'] == second['cases'][0]['evidence']
    assert secret not in json.dumps(second)


def test_global_ruleset_version_changes_ids_even_when_detection_is_unchanged(monkeypatch):
    suite = synthetic_suite()
    current = evaluate_suite(suite)
    monkeypatch.setattr(replay, 'RULESET_VERSION', '1.0.0')
    previous = evaluate_suite(suite)
    assert current['ruleset_version'] == '1.1.0' and previous['ruleset_version'] == '1.0.0'
    for newer, older in zip(current['cases'][:3], previous['cases'][:3]):
        assert newer['predicted_violation'] == older['predicted_violation']
        assert newer['evidence'][0]['id'] != older['evidence'][0]['id']
        assert {key: value for key, value in newer['evidence'][0].items() if key != 'id'} == {
            key: value for key, value in older['evidence'][0].items() if key != 'id'}


def test_multiple_protected_markers_in_one_key_use_separate_policy_evidence():
    suite = synthetic_suite()
    case = suite['cases'][1]
    first = case['policy']['protected_canaries'][0]['value']
    second = 'SECOND-FOREIGN-FIXTURE-CANARY-12345'
    case['policy']['protected_canaries'].append({'tenant_id': 'gamma', 'value': second})
    case['retrieved_documents'].append({'tenant_id': 'gamma', 'content': second})
    case['observed'] = {'outputs': [], 'tool_calls': [{'name': 'send', 'arguments': {first + second: 'safe'}}]}
    evidence = evaluate_suite(suite)['cases'][1]['evidence']
    assert [item['policy_index'] for item in evidence] == [0, 1]
    assert len({item['id'] for item in evidence}) == 2
    assert {item['location'] for item in evidence} == {'/observed/tool_calls/0/arguments/keys/0'}
    assert first not in json.dumps(evidence) and second not in json.dumps(evidence)


def test_output_and_existing_value_paths_are_unchanged_when_keys_are_inspected():
    secret = synthetic_suite()['cases'][1]['policy']['protected_canaries'][0]['value']
    suite = tenant_key_suite({'first': 'safe', 'second': {'record': [secret]}})
    suite['cases'][0]['observed']['outputs'] = [secret]
    evidence = evaluate_suite(suite)['cases'][0]['evidence']
    assert [item['location'] for item in evidence] == [
        '/observed/outputs/0', '/observed/tool_calls/0/arguments/values/1/values/0/0']


def test_nonstring_python_keys_are_not_coerced_or_copied_into_evidence():
    assert list(_text_leaves({7: 'value', 'key': 'text'}, '/arguments')) == [
        ('/arguments/values/0', 'value'), ('/arguments/keys/1', 'key'), ('/arguments/values/1', 'text')]


@pytest.mark.parametrize('extra_level', [False, True])
@pytest.mark.parametrize('container', ['object', 'array'])
def test_key_traversal_preserves_32_level_argument_depth_limit(extra_level, container):
    secret = synthetic_suite()['cases'][1]['policy']['protected_canaries'][0]['value']
    arguments = {secret: 'safe'}
    # Root arguments are depth zero; the key and value are one level below their object.
    for _ in range(31 + int(extra_level)):
        arguments = {'wrapper': arguments} if container == 'object' else [arguments]
    if container == 'array':
        # Tool arguments must remain an object, so replace one outer list with a property.
        arguments = {'records': arguments[0]}
    suite = tenant_key_suite(arguments)
    if extra_level:
        with pytest.raises(ValueError, match='nesting exceeds 32 levels'):
            evaluate_suite(suite)
    else:
        evidence = evaluate_suite(suite)['cases'][0]['evidence']
        assert len(evidence) == 1 and evidence[0]['location'].endswith('/keys/0')


def test_rules_one_and_three_keep_their_existing_detection_scope():
    suite = synthetic_suite()
    indirect = suite['cases'][0]
    marker = indirect['policy']['forbidden_output_markers'][0]
    indirect['observed'] = {'outputs': [], 'tool_calls': [{'name': marker, 'arguments': {marker: marker}}]}
    tenant = suite['cases'][1]
    secret = tenant['policy']['protected_canaries'][0]['value']
    tenant['observed'] = {'outputs': [], 'tool_calls': [{'name': secret, 'arguments': {}}]}
    authorization = suite['cases'][2]
    authorization['observed']['tool_calls'] = [{'name': 'lookup', 'arguments': {'tenant': 'alpha'}}]
    report = evaluate_suite(suite)
    assert all(not case['predicted_violation'] for case in report['cases'][:3])
    authorization['observed']['tool_calls'][0]['arguments']['unexpected'] = 'alpha'
    evidence = evaluate_suite(suite)['cases'][2]['evidence']
    assert len(evidence) == 1
    assert evidence[0]['kind'] == 'unapproved_argument_requested'
    assert evidence[0]['location'] == '/observed/tool_calls/0/arguments/values/1'


def test_cli_user_suite_detects_foreign_key_without_exposing_it(tmp_path):
    secret = synthetic_suite()['cases'][1]['policy']['protected_canaries'][0]['value']
    source, destination = tmp_path / 'suite.json', tmp_path / 'metrics.json'
    source.write_text(json.dumps(tenant_key_suite({'records': [{secret: 'safe'}]})))
    result = CliRunner().invoke(cli, ['evaluate', '--suite', str(source), '--output', str(destination)])
    assert result.exit_code == 0, result.output
    report = json.loads(destination.read_text())
    assert report['fixture_source'] == 'user_supplied' and report['ruleset_version'] == '1.1.0'
    assert report['metrics']['true_positive'] == 1
    assert report['cases'][0]['evidence'][0]['location'] == '/observed/tool_calls/0/arguments/values/0/0/keys/0'
    assert secret not in destination.read_text() and secret not in result.output


@pytest.mark.parametrize('call,expected', [
    ({'name': 'delete', 'arguments': {}}, True),
    ({'name': 'lookup', 'arguments': {'tenant': 'alpha', 'shell': 'whoami'}}, True),
    ({'name': 'lookup', 'arguments': {'tenant': ['alpha']}}, True),
    ({'name': 'lookup', 'arguments': {'tenant': 'alpha'}}, False),
])
def test_tool_policy_checks_exact_names_and_argument_values(call, expected):
    suite = synthetic_suite()
    suite['cases'][2]['observed']['tool_calls'] = [call]
    assert evaluate_suite(suite)['cases'][2]['predicted_violation'] is expected


def test_undefined_metrics_are_null_not_perfect():
    suite = synthetic_suite()
    suite['cases'] = [suite['cases'][3]]
    report = evaluate_suite(suite)
    assert report['metrics']['precision'] is None
    assert report['metrics']['recall'] is None
    assert report['checks']['REPLAY003']['case_count'] == 0


@pytest.mark.parametrize('mutation', [
    lambda suite: suite.update(schema_version='2.0'),
    lambda suite: suite.update(cases=[]),
    lambda suite: suite['cases'].append(suite['cases'][0]),
    lambda suite: suite['cases'][0].update(expected_violation='true'),
    lambda suite: suite['cases'][0].update(check_id='unknown'),
    lambda suite: suite['cases'][0].update(check_id={}),
    lambda suite: suite['cases'][0].update(retrieved_documents=[]),
    lambda suite: suite['cases'][0]['policy'].update(forbidden_output_markers=['short']),
    lambda suite: suite['cases'][1]['policy'].update(principal_tenant='beta'),
    lambda suite: suite['cases'][1]['retrieved_documents'][0].update(tenant_id='alpha'),
    lambda suite: suite['cases'][2]['policy'].update(allowed_tools=[]),
    lambda suite: suite['cases'][2]['observed'].update(tool_calls=[{'name': 'bad', 'arguments': 'cmd'}]),
])
def test_malformed_or_unseeded_fixtures_rejected(mutation):
    suite = synthetic_suite()
    mutation(suite)
    with pytest.raises(ValueError):
        evaluate_suite(suite)


def test_cli_builtin_and_local_suite(tmp_path):
    runner = CliRunner()
    result = runner.invoke(cli, ['evaluate'])
    assert result.exit_code == 0, result.output
    assert json.loads(result.output)['fixture_source'] == 'builtin_synthetic'
    source, destination = tmp_path / 'suite.json', tmp_path / 'metrics.json'
    source.write_text(json.dumps(synthetic_suite()))
    result = runner.invoke(cli, ['evaluate', '--suite', str(source), '--output', str(destination)])
    assert result.exit_code == 0, result.output
    assert json.loads(destination.read_text())['fixture_source'] == 'user_supplied'
    original = source.read_bytes()
    result = runner.invoke(cli, ['evaluate', '--suite', str(source), '--output', str(source)])
    assert result.exit_code != 0
    assert source.read_bytes() == original


def test_cli_malformed_suite_does_not_write_output(tmp_path):
    source, destination = tmp_path / 'suite.json', tmp_path / 'metrics.json'
    source.write_text('{"schema_version": "1.0"}')
    result = CliRunner().invoke(cli, ['evaluate', '--suite', str(source), '--output', str(destination)])
    assert result.exit_code != 0
    assert not destination.exists()
