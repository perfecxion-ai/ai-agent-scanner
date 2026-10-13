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
from src.evaluation.fixtures import synthetic_suite


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
