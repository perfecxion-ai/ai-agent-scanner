"""Contract fixtures for exploratory paired measurements, never real-model accuracy."""

import asyncio
from dataclasses import replace
import importlib.util
import json
from pathlib import Path
from unittest.mock import AsyncMock

from aiohttp import web
import pytest

from src.evaluation import prompt_benchmark as module
from src.security.prompt_injection_tests import PromptInjectionTester


CANARY = 'synthetic-benchmark-canary-b3f709'
KEY = 'synthetic-benchmark-issued-token'
ENV = 'SCAN_EVIDENCE_BENCHMARK_FIXTURE'
KEY_ENV = 'SCAN_BENCHMARK_KEY_FIXTURE'


def config(endpoint='http://127.0.0.1:1'):
    return module.BenchmarkConfig(endpoint, 'ollama', 'fixture-model', 'fixture-context-v1',
                                  ENV, 'a' * 40, ('127.0.0.1/32',), True, pairs=1)


@pytest.fixture(autouse=True)
def private_environment(monkeypatch):
    monkeypatch.setenv(ENV, CANARY)
    monkeypatch.setenv(KEY_ENV, KEY)
    monkeypatch.setattr('asyncio.sleep', AsyncMock())


@pytest.fixture
async def target():
    state = {'mode': 'leak', 'calls': [], 'blocked': asyncio.Event()}
    release = asyncio.Event()
    async def handler(request):
        body = await request.json()
        state['calls'].append((body, dict(request.headers)))
        mode = state['mode']
        if mode == 'denied':
            return web.Response(status=401, text=CANARY + KEY)
        if mode == 'malformed':
            return web.Response(text=CANARY + KEY)
        if mode == 'partial' and len(state['calls']) > 1:
            state['blocked'].set()
            await release.wait()
        text = CANARY if mode in {'leak', 'partial'} else (
            body['messages'][0]['content'] if mode == 'reflection' else 'I cannot reveal protected instructions.')
        return web.json_response({'message': {'content': text}, 'private_metadata': KEY})
    app = web.Application()
    app.router.add_post('/api/chat', handler)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, '127.0.0.1', 0)
    await site.start()
    try:
        yield f'http://127.0.0.1:{site._server.sockets[0].getsockname()[1]}', state
    finally:
        release.set()
        await runner.cleanup()


@pytest.mark.asyncio
@pytest.mark.parametrize('mode', ['leak', 'refusal', 'unseeded', 'reflection', 'malformed', 'denied'])
async def test_actual_prompt_adapter_http_contract(target, mode, monkeypatch, caplog):
    endpoint, state = target
    state['mode'] = mode
    if mode == 'unseeded':
        state['mode'] = 'leak'
        monkeypatch.setenv(ENV, 'unseeded-protected-canary-8f6137')
    result = await module.benchmark(config(endpoint))
    assert len(state['calls']) == 70
    assert len(result['runs']) == 2
    assert sum(run['requests_attempted'] for run in result['runs']) == 70
    assert all(run['detected'] is (mode == 'leak') for run in result['runs'])
    assert result['status'] == ('partial' if mode in {'malformed', 'denied'} else 'completed')
    assert all(check['outcome'] != 'passed' for run in result['runs'] for check in run['checks'])
    assert all(len(run['detected_categories']) == (7 if mode == 'leak' else 0) for run in result['runs'])
    rendered = json.dumps(result) + caplog.text
    assert all(secret not in rendered for secret in (CANARY, KEY, ENV, KEY_ENV, endpoint))
    assert all(CANARY not in json.dumps(body) for body, _ in state['calls'])
    assert 'private_metadata' not in rendered
    assert result['metrics']['paired_complete_cases']['incomplete'] == int(result['status'] == 'partial')


@pytest.mark.asyncio
async def test_cancel_after_confirmed_payload_retains_partial_observation(target, monkeypatch):
    endpoint, state = target
    state['mode'] = 'partial'
    original_wait_for = asyncio.wait_for

    async def interrupt_stalled_arm(awaitable, timeout):
        if timeout != module.ARM_SECONDS:
            return await original_wait_for(awaitable, timeout)
        state['blocked'].clear()
        task = asyncio.create_task(awaitable)
        try:
            # The second request starts only after the first finding is recorded.
            await original_wait_for(state['blocked'].wait(), 5)
            return await original_wait_for(task, 0.01)
        finally:
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)

    monkeypatch.setattr(asyncio, 'wait_for', interrupt_stalled_arm)
    result = await module.benchmark(config(endpoint))
    assert result['status'] == 'partial'
    first = result['runs'][0]
    assert first['detected'] is True and first['status'] == 'partial'
    assert first['detected_categories'] == ['system_prompt_extraction']
    assert first['requests_attempted'] == 2 and first['responses_evaluated'] == 1
    assert len(state['calls']) == 3
    assert result['metrics']['arms'][first['arm']]['partial_detected'] == 1
    assert result['metrics']['arms'][first['arm']]['complete_case_hit_fraction'] is None
    assert result['metrics']['paired_complete_cases']['incomplete'] == 1


@pytest.mark.asyncio
async def test_cohort_deadline_retains_every_planned_arm(target, monkeypatch):
    endpoint, state = target
    monkeypatch.setattr(module, 'COHORT_SECONDS', 0)
    result = await module.benchmark(replace(config(endpoint), pairs=3))
    assert not state['calls']
    assert len(result['runs']) == 6
    assert all(run['status'] == 'not_run' for run in result['runs'])
    assert result['metrics']['paired_complete_cases']['incomplete'] == 3
    assert result['status'] == 'partial'
    assert result['metrics']['arms']['baseline']['complete_case_wilson_95'] is None


@pytest.mark.parametrize('pairs', range(1, 11))
def test_order_balanced_reproducible_and_does_not_change_global_rng(pairs):
    order = module.paired_order(pairs, 87)
    assert order == module.paired_order(pairs, 87)
    assert abs(order.count(('baseline', 'candidate')) - order.count(('candidate', 'baseline'))) <= 1


def test_manifests_are_frozen_and_production_defaults_unchanged():
    original = PromptInjectionTester().injection_payloads
    catalogs = module._catalogs()
    assert catalogs['baseline'] == {key: value[:5] for key, value in original.items()}
    assert all(len(values) == 5 for values in catalogs['candidate'].values())
    assert sum(map(len, catalogs['candidate'].values())) == 35
    for category, baseline in original.items():
        assert baseline == PromptInjectionTester().injection_payloads[category]
    a = module._manifest(catalogs['baseline'], 'ollama', 'fixture')
    b = module._manifest(catalogs['candidate'], 'ollama', 'fixture')
    assert all(x['probe_version'] != y['probe_version'] for x, y in zip(a, b))


@pytest.mark.parametrize('changes', [
    {'pairs': 0}, {'pairs': 11}, {'pairs': True}, {'seed': -1}, {'seed': 2**32},
    {'provider': 'unsupported'}, {'revision': 'bad'}, {'model': CANARY},
    {'evidence_context_id': 'x' * 129}, {'evidence_context_id': CANARY},
    {'canary_env': 'HOME'}, {'canary_env': 'SCAN_EVIDENCE_PROFILES_FILE'},
    {'api_key_env': ENV}, {'api_key_env': 'HOME'}, {'allowed_networks': ()},
    {'allowed_networks': ('0.0.0.0/0',)}, {'allow_loopback': False},
    {'endpoint': 'http://u:p@127.0.0.1'}, {'endpoint': 'http://127.0.0.1/?key=secret'},
    {'endpoint': 'http://127.0.0.1/%73ynthetic-benchmark-canary-b3f709'},
])
@pytest.mark.asyncio
async def test_bad_input_has_static_error_before_resolution(changes, monkeypatch):
    resolve = AsyncMock(side_effect=AssertionError('DNS must not run'))
    monkeypatch.setattr(module.ScopePolicy, 'addresses', resolve)
    with pytest.raises(module.BenchmarkError) as caught:
        await module.benchmark(replace(config(), **changes))
    resolve.assert_not_called()
    assert str(caught.value) == module._ERROR


@pytest.mark.asyncio
async def test_missing_key_and_marker_cannot_probe(monkeypatch):
    for name in (KEY_ENV, ENV):
        monkeypatch.delenv(name, raising=False)
        with pytest.raises(module.BenchmarkError):
            await module.benchmark(replace(config(), api_key_env=KEY_ENV))


@pytest.mark.asyncio
async def test_marker_overlapping_key_or_public_manifest_is_rejected(monkeypatch):
    monkeypatch.setenv(KEY_ENV, KEY + CANARY)
    with pytest.raises(module.BenchmarkError):
        await module.benchmark(replace(config(), api_key_env=KEY_ENV))
    monkeypatch.setenv(ENV, 'system_prompt_extraction')
    with pytest.raises(module.BenchmarkError):
        await module.benchmark(config())


def test_private_atomic_no_clobber_output(tmp_path):
    output = tmp_path / 'result.json'
    with module.exclusive_output(output) as publish:
        assert not output.exists()
        publish({'status': 'partial'})
    assert json.loads(output.read_text()) == {'status': 'partial'}
    assert output.stat().st_mode & 0o777 == 0o600
    with pytest.raises(module.BenchmarkError):
        with module.exclusive_output(output):
            pytest.fail('Existing output must fail before execution')
    assert not list(tmp_path.glob('.prompt-benchmark-*'))


@pytest.mark.parametrize('case', ['exception', 'interrupt', 'raced_file', 'raced_symlink'])
def test_failed_output_cleans_temporary_and_preserves_existing_data(tmp_path, case):
    output = tmp_path / 'result.json'
    target = tmp_path / 'private-original'
    target.write_text('Original')
    expected = KeyboardInterrupt if case == 'interrupt' else module.BenchmarkError if case.startswith('raced') else RuntimeError
    with pytest.raises(expected):
        with module.exclusive_output(output) as publish:
            if case == 'exception':
                raise RuntimeError('Fixture failure')
            if case == 'interrupt':
                raise KeyboardInterrupt
            if case == 'raced_file':
                output.write_text('Other writer')
            else:
                output.symlink_to(target)
            publish({'status': 'completed'})
    assert target.read_text() == 'Original'
    assert not list(tmp_path.glob('.prompt-benchmark-*'))
    if case in {'exception', 'interrupt'}:
        assert not output.exists()


def test_cli_parser_errors_do_not_echo_values(capsys):
    script = Path(__file__).parents[1] / 'scripts/benchmark-prompt-leaks.py'
    spec = importlib.util.spec_from_file_location('prompt_benchmark_script', script)
    loaded = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(loaded)
    parser = loaded.Parser()
    parser.add_argument('--pairs', type=int)
    with pytest.raises(SystemExit):
        parser.parse_args(['--pairs', CANARY])
    assert CANARY not in capsys.readouterr().err


def test_cleanup_failure_is_static(tmp_path, monkeypatch):
    original = Path.unlink
    def denied(path, **kwargs):
        raise PermissionError('private output path ' + CANARY)
    monkeypatch.setattr(Path, 'unlink', denied)
    with pytest.raises(module.BenchmarkError) as caught:
        with module.exclusive_output(tmp_path / 'result.json'):
            pass
    assert str(caught.value) == module._ERROR
    monkeypatch.setattr(Path, 'unlink', original)
    for temporary in tmp_path.glob('.prompt-benchmark-*'):
        temporary.unlink()


@pytest.mark.asyncio
@pytest.mark.parametrize('marker', ['requests_attempted', 'not_observed_in_complete_run',
                                    'partial_detected', 'uncertainty_limit'])
async def test_reserved_metric_collision_fails_before_dns(monkeypatch, marker):
    monkeypatch.setenv(ENV, marker)
    resolve = AsyncMock(side_effect=AssertionError('DNS must not run'))
    monkeypatch.setattr(module.ScopePolicy, 'addresses', resolve)
    with pytest.raises(module.BenchmarkError):
        await module.benchmark(config())
    resolve.assert_not_called()


@pytest.mark.asyncio
async def test_dns_timeout_is_static_and_never_starts_tester(monkeypatch):
    import asyncio
    def unresolved(*args, **kwargs):
        raise asyncio.TimeoutError(CANARY + KEY)
    monkeypatch.setattr(module.ScopePolicy, 'addresses', unresolved)
    tester = AsyncMock()
    monkeypatch.setattr(module.PromptInjectionTester, 'test_agent', tester)
    with pytest.raises(module.BenchmarkError) as caught:
        await module.benchmark(config())
    assert str(caught.value) == module._ERROR
    tester.assert_not_called()


@pytest.mark.asyncio
async def test_actual_cli_publishes_private_report_and_nonzero_for_partial(target, tmp_path, monkeypatch, capsys):
    import asyncio
    import sys
    endpoint, state = target
    state['mode'] = 'denied'
    script = Path(__file__).parents[1] / 'scripts/benchmark-prompt-leaks.py'
    spec = importlib.util.spec_from_file_location('prompt_benchmark_actual_script', script)
    loaded = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(loaded)
    output = tmp_path / 'actual-result.json'
    monkeypatch.setattr(sys, 'argv', [str(script), '--endpoint', endpoint,
        '--provider', 'ollama', '--model', 'fixture-model', '--evidence-context-id', 'fixture-context-v1',
        '--canary-env', ENV, '--revision', 'a' * 40, '--allow-network', '127.0.0.1/32',
        '--allow-loopback', '--pairs', '1', '--output', str(output)])
    assert await asyncio.to_thread(loaded.main) == 1
    result = json.loads(output.read_text())
    assert result['status'] == 'partial' and len(state['calls']) == 70
    assert output.stat().st_mode & 0o777 == 0o600
    assert capsys.readouterr().out == ''
    assert not list(tmp_path.glob('.prompt-benchmark-*'))


@pytest.mark.asyncio
@pytest.mark.parametrize('disclose', [False, True])
async def test_final_pacing_timeout_keeps_full_ledger_partial(disclose, tmp_path, monkeypatch, capsys):
    import asyncio
    import sys
    from src.core.contracts import CHECK_INTERRUPTED_REASON, record_interaction
    from src.core.transport import current_budget
    from src.evaluation.benchmark_validation import validate_report

    calls = {'responses': 0, 'pauses': 0}

    async def response(self, agent, category, payload):
        current_budget().reserve('http://127.0.0.1:1')
        calls['responses'] += 1
        record_interaction(True)
        text = CANARY if disclose and calls['responses'] % 35 == 0 else 'No disclosure.'
        return self._analyze_response(agent, category, payload, json.dumps({'response': text}), 200)

    async def pause(seconds):
        calls['pauses'] += 1
        if calls['pauses'] % 35 == 0:
            await asyncio.Event().wait()

    original_wait_for = asyncio.wait_for

    async def bounded_wait_for(awaitable, timeout):
        # Interrupt the fixture early without changing its declared maximum budget.
        return await original_wait_for(awaitable, 0.5 if timeout == module.ARM_SECONDS else timeout)

    monkeypatch.setattr(PromptInjectionTester, '_test_single_payload', response)
    monkeypatch.setattr(module.ScopePolicy, 'addresses', lambda *args: ['127.0.0.1'])
    monkeypatch.setattr('asyncio.sleep', pause)
    monkeypatch.setattr(asyncio, 'wait_for', bounded_wait_for)
    script = Path(__file__).parents[1] / 'scripts/benchmark-prompt-leaks.py'
    spec = importlib.util.spec_from_file_location('prompt_benchmark_pacing_script', script)
    loaded = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(loaded)
    output = tmp_path / 'pacing-result.json'
    monkeypatch.setattr(sys, 'argv', [str(script), '--endpoint', 'http://127.0.0.1:1',
        '--provider', 'ollama', '--model', 'fixture-model', '--evidence-context-id', 'fixture-context-v1',
        '--canary-env', ENV, '--revision', 'a' * 40, '--allow-network', '127.0.0.1/32',
        '--allow-loopback', '--pairs', '1', '--output', str(output)])
    assert await asyncio.to_thread(loaded.main) == 1
    result = json.loads(output.read_text())
    assert calls == {'responses': 70, 'pauses': 70}
    assert result['status'] == 'partial'
    for run in result['runs']:
        assert run['status'] == 'partial' and run['detected'] is disclose
        assert run['requests_attempted'] == run['responses_evaluated'] == 35
        assert len(run['checks']) == 7
        assert all(check['status'] == 'completed' and check['outcome'] == 'inconclusive'
                   and check['responses_evaluated'] == 5 for check in run['checks'][:-1])
        interrupted = run['checks'][-1]
        assert interrupted['status'] == 'failed' and interrupted['outcome'] == 'inconclusive'
        assert interrupted['requests_attempted'] == interrupted['responses_evaluated'] == 5
        assert interrupted['reason'] == CHECK_INTERRUPTED_REASON
        assert run['detected_categories'] == (['payload_injection'] if disclose else [])
    assert validate_report(result, {
        'provider': 'ollama', 'model': 'fixture-model', 'evidence_context_id': 'fixture-context-v1',
        'operator_asserted_revision': 'a' * 40, 'pairs': 1, 'seed': result['seed'],
    }) == {'status': 'partial', 'metrics': result['metrics']}
    for metrics in result['metrics']['arms'].values():
        assert metrics['completed'] == 0 and metrics['partial'] == 1
        assert metrics['partial_detected'] == int(disclose)
        assert metrics['complete_case_hit_fraction'] is None
        assert metrics['complete_case_wilson_95'] is None
    assert result['metrics']['paired_complete_cases']['incomplete'] == 1
    assert output.stat().st_mode & 0o777 == 0o600
    assert all(value not in json.dumps(result) for value in (CANARY, ENV))
    assert capsys.readouterr().out == ''
    assert not list(tmp_path.glob('.prompt-benchmark-*'))


@pytest.mark.asyncio
async def test_explicit_issued_key_is_only_a_header(target):
    endpoint, state = target
    result = await module.benchmark(replace(config(endpoint), api_key_env=KEY_ENV))
    assert result['status'] == 'completed'
    assert all(headers.get('Authorization') == 'Bearer ' + KEY for _, headers in state['calls'])
    assert all(KEY not in json.dumps(body) for body, _ in state['calls'])
    assert KEY not in json.dumps(result) and KEY_ENV not in json.dumps(result)
