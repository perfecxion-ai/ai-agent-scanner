"""Frozen benchmark report acceptance, with no network or supplied lab drivers."""

from copy import deepcopy
import json
import socket
from unittest.mock import AsyncMock

import pytest

from src.core.contracts import CHECK_INTERRUPTED_REASON, record_interaction
from src.core.transport import current_budget
from src.evaluation import benchmark_validation as validator
from src.evaluation import prompt_benchmark as producer
from tests.request_provenance_fixture import declared_request_evidence


MARKER = 'synthetic-validator-marker-826f15'
EXPECTED = {'provider': 'ollama', 'model': 'fixture-model', 'evidence_context_id': 'fixture-context-v1',
            'operator_asserted_revision': 'a' * 40, 'pairs': 2, 'seed': 19}


@pytest.fixture
async def report(monkeypatch):
    """Run the actual producer, analyzer and checked categories without sockets."""
    monkeypatch.setenv('SCAN_EVIDENCE_VALIDATOR_FIXTURE', MARKER)
    monkeypatch.setattr(producer.ScopePolicy, 'addresses', lambda *args: ['127.0.0.1'])
    monkeypatch.setattr('asyncio.sleep', AsyncMock())
    def forbidden(*args, **kwargs):
        pytest.fail('Validator fixture must not access the network')
    monkeypatch.setattr(socket.socket, 'connect', forbidden)
    monkeypatch.setattr(socket, 'getaddrinfo', forbidden)

    async def response(self, agent, category, payload):
        current_budget().reserve('http://127.0.0.1')
        record_interaction(True)
        text = MARKER if category in {'system_prompt_extraction', 'role_manipulation'} else 'No disclosure.'
        finding = self._analyze_response(agent, category, payload, json.dumps({'response': text}), 200,
                                        request_evidence=declared_request_evidence(agent, payload))
        if finding and finding['evidence_status'] == 'confirmed':
            self.detected_categories.add(category)
        return finding

    monkeypatch.setattr(producer._ObservedTester, '_test_single_payload', response)
    config = producer.BenchmarkConfig('http://127.0.0.1:1', EXPECTED['provider'], EXPECTED['model'],
                                     EXPECTED['evidence_context_id'], 'SCAN_EVIDENCE_VALIDATOR_FIXTURE',
                                     EXPECTED['operator_asserted_revision'], ('127.0.0.1/32',), True,
                                     pairs=EXPECTED['pairs'], seed=EXPECTED['seed'])
    return await producer.benchmark(config)


def refresh(document):
    document['status'] = 'completed' if all(run['status'] == 'completed' for run in document['runs']) else 'partial'
    document['metrics'] = producer.summarize(document['runs'], document['scheduled_pairs'])


def assert_invalid(document, expected=EXPECTED):
    before = deepcopy(document)
    expected_before = deepcopy(expected)
    with pytest.raises(validator.ReportValidationError) as caught:
        validator.validate_report(document, expected)
    assert str(caught.value) == 'Benchmark report validation failed'
    assert document == before
    assert expected == expected_before
    assert MARKER not in str(caught.value)


def test_actual_producer_report_recomputed_without_mutation_or_labels(report):
    before = deepcopy(report)
    expected_before = deepcopy(EXPECTED)
    result = validator.validate_report(report, EXPECTED)
    assert result == {'status': 'completed', 'metrics': producer.summarize(report['runs'], 2)}
    assert report == before and EXPECTED == expected_before
    assert all(value not in json.dumps(result) for value in (MARKER, 'fixture-model', 'fixture-context-v1', 'a' * 40))
    result['metrics']['arms']['baseline']['detected'] = 0
    assert report == before


@pytest.mark.parametrize('interrupted', [False, True])
def test_partial_checkpoint_can_outlive_confirmed_category_record(report, interrupted):
    run = report['runs'][0]
    run.update(status='partial', requests_attempted=1, responses_evaluated=1,
               checks=run['checks'][:1], detected_categories=['system_prompt_extraction'])
    run['checks'][0].update(outcome='inconclusive', requests_attempted=1, responses_evaluated=1,
                            reason=validator._ABSENCE)
    if interrupted:
        run['checks'][0].update(status='failed', reason=CHECK_INTERRUPTED_REASON)
    refresh(report)
    result = validator.validate_report(report, EXPECTED)
    assert result['status'] == 'partial'
    assert result['metrics']['arms'][run['arm']]['partial_detected'] == 1
    assert result['metrics']['paired_complete_cases']['incomplete'] == 1


@pytest.mark.parametrize('mutation', ['completed_run', 'not_last', 'multiple', 'confirmed', 'unknown_reason'])
def test_interruption_reason_requires_one_final_inconclusive_check_in_partial_run(report, mutation):
    run = report['runs'][0]
    run['status'] = 'partial'
    run['checks'][-1].update(status='failed', outcome='inconclusive', reason=CHECK_INTERRUPTED_REASON)
    if mutation == 'completed_run':
        run['status'] = 'completed'
    elif mutation == 'not_last':
        run['checks'][-1].update(status='completed', reason=validator._ABSENCE)
        run['checks'][0].update(status='failed', outcome='inconclusive', reason=CHECK_INTERRUPTED_REASON)
    elif mutation == 'multiple':
        run['checks'][0].update(status='failed', outcome='inconclusive', reason=CHECK_INTERRUPTED_REASON)
    elif mutation == 'confirmed':
        run['checks'][-1]['outcome'] = 'confirmed'
        run['detected_categories'] = sorted(run['detected_categories'] + ['payload_injection'])
    else:
        run['checks'][-1]['reason'] = CHECK_INTERRUPTED_REASON + MARKER
    refresh(report)
    assert_invalid(report)


def test_not_run_suffix_has_scheduled_denominators(report):
    for index, run in enumerate(report['runs']):
        if index:
            run.update(status='not_run', detected=False, requests_attempted=0, responses_evaluated=0,
                       checks=[], detected_categories=[], detection_outcome='not_evaluated')
            del run['elapsed_seconds']
    refresh(report)
    result = validator.validate_report(report, EXPECTED)
    assert result['status'] == 'partial'
    assert result['metrics']['arms']['candidate']['not_run'] >= 1


def test_all_not_run_and_unobserved_completed_are_valid(report):
    for run in report['runs']:
        run.update(detected=False, detected_categories=[], detection_outcome='not_observed_in_complete_run')
        for check in run['checks']:
            check.update(outcome='inconclusive', reason=validator._ABSENCE)
    refresh(report)
    assert validator.validate_report(report, EXPECTED)['status'] == 'completed'
    for run in report['runs']:
        run.update(status='not_run', requests_attempted=0, responses_evaluated=0,
                   checks=[], detection_outcome='not_evaluated')
        del run['elapsed_seconds']
    refresh(report)
    result = validator.validate_report(report, EXPECTED)
    assert result['metrics']['arms']['baseline']['complete_case_wilson_95'] is None


@pytest.mark.parametrize('kind', ['failed_confirmed', 'failed_inconclusive', 'skipped', 'heuristic'])
def test_genuine_partial_check_outcomes(report, kind):
    run = report['runs'][0]
    run.update(status='partial', checks=run['checks'][:1], detected=False,
               detected_categories=[], requests_attempted=5, responses_evaluated=0,
               detection_outcome='incomplete_without_observation')
    check = run['checks'][0]
    if kind.startswith('failed'):
        check.update(status='failed', outcome=kind.removeprefix('failed_'), reason=validator._DENIAL,
                     responses_evaluated=1 if kind == 'failed_confirmed' else 0)
    elif kind == 'skipped':
        check.update(status='skipped', outcome='not_evaluated', reason='No response was evaluated',
                     responses_evaluated=0)
    else:
        check.update(outcome='heuristic', reason=None)
    run['responses_evaluated'] = check['responses_evaluated']
    if kind == 'failed_confirmed':
        run.update(detected=True, detected_categories=['system_prompt_extraction'],
                   detection_outcome='shared_analyzer_observation')
    refresh(report)
    assert validator.validate_report(report, EXPECTED)['status'] == 'partial'


@pytest.mark.asyncio
async def test_actual_producer_pre_http_rejection_is_valid_partial(report, monkeypatch):
    async def rejected(self, agent, category, payload):
        current_budget().rejections += 1
        record_interaction(False)
        return None
    monkeypatch.setattr(producer._ObservedTester, '_test_single_payload', rejected)
    config = producer.BenchmarkConfig('http://127.0.0.1:1', EXPECTED['provider'], EXPECTED['model'],
                                     EXPECTED['evidence_context_id'], 'SCAN_EVIDENCE_VALIDATOR_FIXTURE',
                                     EXPECTED['operator_asserted_revision'], ('127.0.0.1/32',), True,
                                     pairs=2, seed=19)
    document = await producer.benchmark(config)
    assert all(run['requests_attempted'] == 0 and len(run['checks']) == 7 for run in document['runs'])
    assert sum(check['requests_attempted'] for check in document['runs'][0]['checks']) == 35
    assert validator.validate_report(document, EXPECTED)['status'] == 'partial'


@pytest.mark.parametrize('field,value', [
    ('schema_version', '2.0'), ('benchmark', MARKER), ('candidate_hypothesis', MARKER),
    ('interpretation', MARKER), ('fixture_provenance', MARKER), ('detection_source', MARKER),
    ('provider', 'openai'), ('model', 'other-model'), ('evidence_context_id', 'other-context'),
    ('operator_asserted_revision', 'b' * 40), ('scheduled_pairs', True), ('seed', True),
    ('status', 'partial'), ('runtime', {'python': MARKER}), ('manifests', {}), ('budgets', {}),
])
def test_altered_top_contract_rejected(report, field, value):
    report[field] = value
    assert_invalid(report)


@pytest.mark.parametrize('location', ['top', 'runtime', 'budget', 'manifest', 'run', 'check', 'metrics'])
def test_unknown_fields_never_reflected(report, location):
    target = {'top': report, 'runtime': report['runtime'], 'budget': report['budgets'],
              'manifest': report['manifests']['baseline'][0], 'run': report['runs'][0],
              'check': report['runs'][0]['checks'][0], 'metrics': report['metrics']}[location]
    target[MARKER] = MARKER
    assert_invalid(report)


@pytest.mark.parametrize('mutation', ['payload', 'category_order', 'payload_count', 'budget_bool',
                                    'runtime_long', 'runtime_control', 'check_limit', 'run_limit'])
def test_suite_budget_and_collection_bounds(report, mutation):
    manifest = report['manifests']['baseline']
    if mutation == 'payload':
        manifest[0]['payloads'][0] = MARKER
    elif mutation == 'category_order':
        manifest.reverse()
    elif mutation == 'payload_count':
        manifest[0]['payloads'].pop()
    elif mutation == 'budget_bool':
        report['budgets']['pacing_seconds'] = True
    elif mutation == 'runtime_long':
        report['runtime']['system'] = 'x' * 129
    elif mutation == 'runtime_control':
        report['runtime']['system'] = 'fixture\n' + MARKER
    elif mutation == 'check_limit':
        report['runs'][0]['checks'] *= 2
    else:
        report['runs'] *= 6
    assert_invalid(report)


@pytest.mark.parametrize('mutation', ['missing', 'duplicate', 'swapped', 'wrong_pair', 'wrong_arm', 'not_run_hole'])
def test_pair_structure_precedes_metrics(report, mutation):
    if mutation == 'missing':
        report['runs'].pop()
    elif mutation == 'duplicate':
        report['runs'][1] = deepcopy(report['runs'][0])
    elif mutation == 'swapped':
        report['runs'][0], report['runs'][1] = report['runs'][1], report['runs'][0]
    elif mutation == 'wrong_pair':
        report['runs'][0]['pair'] = True
    elif mutation == 'wrong_arm':
        report['runs'][0]['arm'] = MARKER
    else:
        run = report['runs'][0]
        run.update(status='not_run', detected=False, requests_attempted=0, responses_evaluated=0,
                   checks=[], detected_categories=[], detection_outcome='not_evaluated')
        del run['elapsed_seconds']
        refresh(report)
    assert_invalid(report)


@pytest.mark.parametrize('mutation', ['missing', 'duplicate', 'swapped', 'version', 'context', 'rule',
                                    'passed', 'unknown_reason', 'status', 'count', 'bool', 'outcome'])
def test_strict_check_contract(report, mutation):
    checks = report['runs'][0]['checks']
    if mutation == 'missing':
        checks.pop()
    elif mutation == 'duplicate':
        checks[1] = deepcopy(checks[0])
    elif mutation == 'swapped':
        checks[0], checks[1] = checks[1], checks[0]
    else:
        key, value = {'version': ('probe_version', '1:' + '0' * 64), 'context': ('evidence_context_id', MARKER),
                      'rule': ('rule_id', MARKER), 'passed': ('outcome', 'passed'),
                      'unknown_reason': ('reason', MARKER), 'status': ('status', 'unknown'),
                      'count': ('responses_evaluated', 6), 'bool': ('requests_attempted', True),
                      'outcome': ('outcome', MARKER)}[mutation]
        checks[0][key] = value
    assert_invalid(report)


@pytest.mark.parametrize('value', [True, -1, 36, 35.0, float('nan'), float('inf'), MARKER])
@pytest.mark.parametrize('field', ['requests_attempted', 'responses_evaluated'])
def test_run_counters_strict(report, field, value):
    report['runs'][0][field] = value
    assert_invalid(report)


@pytest.mark.parametrize('value', [True, -1, float('nan'), float('inf'), 1205.000001, 6601, MARKER])
def test_elapsed_bounded(report, value):
    report['runs'][0]['elapsed_seconds'] = value
    assert_invalid(report)


def test_bounded_timing_grace_and_cohort_total(report):
    report['runs'][0]['elapsed_seconds'] = 1205
    assert validator.validate_report(report, EXPECTED)['status'] == 'completed'
    expected = dict(EXPECTED, pairs=10)
    original = {run['arm']: deepcopy(run) for run in report['runs']}
    report.update(scheduled_pairs=10, runs=[])
    report['budgets']['max_requests'] = 700
    for pair, order in enumerate(producer.paired_order(10, expected['seed'])):
        for arm in order:
            run = deepcopy(original[arm])
            run.update(pair=pair, elapsed_seconds=270.25)
            report['runs'].append(run)
    refresh(report)
    assert validator.validate_report(report, expected)['status'] == 'completed'
    report['runs'][0]['elapsed_seconds'] += 0.000001
    assert_invalid(report, expected)


@pytest.mark.parametrize('mutation', ['unvisited', 'earlier_unconfirmed', 'zero_evaluated'])
def test_partial_checkpoint_only_last_interrupted_evaluated_category(report, mutation):
    run = report['runs'][0]
    run.update(status='partial', detection_outcome='shared_analyzer_observation')
    if mutation == 'unvisited':
        run.update(checks=run['checks'][:1], requests_attempted=5, responses_evaluated=5,
                   detected_categories=['instruction_bypass', 'system_prompt_extraction'])
    elif mutation == 'earlier_unconfirmed':
        run['checks'][0].update(outcome='inconclusive', reason=validator._ABSENCE)
    else:
        run['checks'][0].update(status='failed', outcome='inconclusive', reason=validator._FAILURE,
                                responses_evaluated=0)
        run['responses_evaluated'] -= 5
    refresh(report)
    assert_invalid(report)


@pytest.mark.parametrize('mutation', ['missing', 'duplicate', 'unknown', 'unsorted', 'detected_bool', 'outcome'])
def test_completed_checkpoint_matches_confirmed_checks(report, mutation):
    run = report['runs'][0]
    if mutation == 'missing':
        run['detected_categories'] = []
        run['detected'] = False
    elif mutation == 'duplicate':
        run['detected_categories'] *= 2
    elif mutation == 'unknown':
        run['detected_categories'] = [MARKER]
    elif mutation == 'unsorted':
        run['detected_categories'].reverse()
    elif mutation == 'detected_bool':
        run['detected'] = 1
    else:
        run['detection_outcome'] = MARKER
    refresh(report)
    assert_invalid(report)


@pytest.mark.parametrize('mutation', ['integer_bool', 'float_int', 'float_nan', 'float_forged', 'interval', 'pair', 'text'])
def test_metrics_full_shape_and_strict_numeric_types(report, mutation):
    arm = report['metrics']['arms']['baseline']
    if mutation == 'integer_bool':
        arm['scheduled'] = True
    elif mutation == 'float_int':
        arm['complete_case_hit_fraction'] = 1
    elif mutation == 'float_nan':
        arm['complete_case_hit_fraction'] = float('nan')
    elif mutation == 'float_forged':
        arm['complete_case_hit_fraction'] -= 0.000001
    elif mutation == 'interval':
        arm['complete_case_wilson_95'].append(0.0)
    elif mutation == 'pair':
        report['metrics']['paired_complete_cases']['both_detected'] += 1
    else:
        report['metrics']['uncertainty_limit'] = MARKER
    assert_invalid(report)


def test_tight_float_roundoff_tolerated_but_output_recomputed(report):
    original = deepcopy(report['metrics'])
    report['metrics']['arms']['baseline']['complete_case_wilson_95'][0] += 1e-14
    assert validator.validate_report(report, EXPECTED)['metrics'] == original


@pytest.mark.parametrize('field,value', [('pairs', True), ('pairs', 0), ('pairs', 11), ('seed', True),
                                        ('seed', -1), ('seed', 2**32), ('model', MARKER + ' '),
                                        ('evidence_context_id', 'x' * 129), ('provider', 'bad'),
                                        ('operator_asserted_revision', 'bad')])
def test_expected_configuration_is_also_strict(report, field, value):
    expected = dict(EXPECTED, **{field: value})
    assert_invalid(report, expected)


@pytest.mark.parametrize('value', [None, [], MARKER, True, 3])
def test_non_object_inputs_static(value):
    with pytest.raises(validator.ReportValidationError, match='^Benchmark report validation failed$'):
        validator.validate_report(value, EXPECTED)
    with pytest.raises(validator.ReportValidationError, match='^Benchmark report validation failed$'):
        validator.validate_report({}, value)
