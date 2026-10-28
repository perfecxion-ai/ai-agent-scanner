"""The owned gate retries only its documented, bounded unavailable response."""

from copy import deepcopy
import importlib.util
import json
from pathlib import Path
from urllib.error import URLError

import pytest


SCRIPT = Path(__file__).resolve().parents[1] / 'scripts/acceptance-asset-groups.py'
spec = importlib.util.spec_from_file_location('owned_asset_group_retry_gate', SCRIPT)
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)

UNAVAILABLE = {'success': False, 'error': 'Asset group projection unavailable',
               'code': 'asset_group_projection_unavailable'}


class Clock:
    def __init__(self, seconds=100):
        self.seconds, self.sleeps = seconds, []

    def sleep(self, seconds):
        assert 0 < seconds <= min(0.2, self.seconds)
        self.sleeps.append(seconds)
        self.seconds -= seconds


class Server:
    def __init__(self, responses, clock, phase='initial'):
        self.responses, self.clock, self.phase = list(responses), clock, phase
        self.calls, self.remaining_calls = [], 0

    def remaining(self):
        self.remaining_calls += 1
        gate.require(self.clock.seconds > 0, 'overall_timeout')
        return self.clock.seconds

    def request(self, path, *, organization):
        self.calls.append((path, organization))
        response = self.responses.pop(0) if len(self.responses) > 1 else self.responses[0]
        if isinstance(response, Exception):
            raise response
        return deepcopy(response)


def success(items, *, field='asset_groups', complete=True, cursor=None):
    return 200, {'success': True, field: items, 'coverage': {'search_complete': complete}, 'next_cursor': cursor}


@pytest.mark.parametrize('field,path,limit', [
    ('asset_groups', '/api/asset-groups', 2),
    ('history', '/api/asset-groups/owned-group/history', 100),
])
def test_retry_keeps_continuation_url_owner_items_and_phase_counter(monkeypatch, field, path, limit):
    clock, stats = Clock(), {'initial': 0, 'restart': 0}
    monkeypatch.setattr(gate.time, 'sleep', clock.sleep)
    server = Server([success([{'id': 'first'}], field=field, complete=False, cursor='owned-cursor+/='),
                     (503, UNAVAILABLE), success([{'id': 'second'}], field=field)], clock, 'restart')
    assert gate.page_all(server, 'owned-owner', path, field, stats=stats) == [{'id': 'first'}, {'id': 'second'}]
    assert server.calls == [(path + f'?limit={limit}', 'owned-owner'),
                            (path + f'?limit={limit}&cursor=owned-cursor%2B%2F%3D', 'owned-owner'),
                            (path + f'?limit={limit}&cursor=owned-cursor%2B%2F%3D', 'owned-owner')]
    assert stats == {'initial': 0, 'restart': 1}
    assert clock.sleeps == [0.2]
    assert server.remaining_calls == 4


def test_retry_then_stale_cursor_fails_without_restarting_traversal(monkeypatch):
    clock, stats = Clock(), {'initial': 0, 'restart': 0}
    monkeypatch.setattr(gate.time, 'sleep', clock.sleep)
    server = Server([success(['first'], complete=False, cursor='held'), (503, UNAVAILABLE),
                     (409, {'success': False, 'error': 'Owned stale cursor', 'code': 'stale_cursor'})], clock)
    with pytest.raises(gate.GateFailure, match='^page_http_409$'):
        gate.page_all(server, 'owned-owner', '/api/asset-groups', 'asset_groups', stats=stats)
    assert len(server.calls) == 3 and server.calls[1] == server.calls[2]
    assert stats == {'initial': 1, 'restart': 0}


def test_persistent_unavailable_has_finite_per_page_retry_cap(monkeypatch):
    clock, stats = Clock(), {'initial': 0, 'restart': 0}
    monkeypatch.setattr(gate.time, 'sleep', clock.sleep)
    server = Server([(503, UNAVAILABLE)], clock)
    with pytest.raises(gate.GateFailure, match='^page_unavailable$'):
        gate.page_all(server, 'owned-owner', '/api/asset-groups', 'asset_groups', stats=stats)
    assert len(server.calls) == gate.MAX_PAGE_RETRIES + 1 == 26
    assert len(clock.sleeps) == stats['initial'] == gate.MAX_PAGE_RETRIES == 25
    assert len(set(server.calls)) == 1 and stats['restart'] == 0


def test_retry_cap_resets_for_each_successfully_advanced_page(monkeypatch):
    clock, stats = Clock(), {'initial': 0, 'restart': 0}
    monkeypatch.setattr(gate.time, 'sleep', clock.sleep)
    server = Server([(503, UNAVAILABLE)] * 25 + [success(['first'], complete=False, cursor='held')]
                    + [(503, UNAVAILABLE)] * 25 + [success(['second'])], clock)
    assert gate.page_all(server, 'owned-owner', '/api/asset-groups', 'asset_groups', stats=stats) == ['first', 'second']
    assert len(server.calls) == 52 and stats == {'initial': 50, 'restart': 0}
    assert len(clock.sleeps) == 50


def test_original_deadline_clamps_backoff_and_fails_persistent_unavailable(monkeypatch):
    clock, stats = Clock(0.35), {'initial': 0, 'restart': 0}
    monkeypatch.setattr(gate.time, 'sleep', clock.sleep)
    server = Server([(503, UNAVAILABLE)], clock)
    with pytest.raises(gate.GateFailure, match='^overall_timeout$'):
        gate.page_all(server, 'owned-owner', '/api/asset-groups', 'asset_groups', stats=stats)
    assert clock.sleeps == [0.2, pytest.approx(0.15)]
    assert len(server.calls) == 2 and stats == {'initial': 1, 'restart': 0}
    assert clock.seconds == 0


def test_expired_deadline_refuses_first_attempt(monkeypatch):
    clock, stats = Clock(0), {'initial': 0, 'restart': 0}
    monkeypatch.setattr(gate.time, 'sleep', clock.sleep)
    server = Server([success([])], clock)
    with pytest.raises(gate.GateFailure, match='^overall_timeout$'):
        gate.page_all(server, 'owned-owner', '/api/asset-groups', 'asset_groups', stats=stats)
    assert not server.calls and not clock.sleeps and stats == {'initial': 0, 'restart': 0}


def test_deadline_expiring_during_response_refuses_backoff_and_another_attempt(monkeypatch):
    clock, stats = Clock(), {'initial': 0, 'restart': 0}
    monkeypatch.setattr(gate.time, 'sleep', clock.sleep)
    server = Server([(503, UNAVAILABLE)], clock)
    original = server.request

    def request(*args, **kwargs):
        result = original(*args, **kwargs)
        clock.seconds = 0
        return result

    monkeypatch.setattr(server, 'request', request)
    with pytest.raises(gate.GateFailure, match='^overall_timeout$'):
        gate.page_all(server, 'owned-owner', '/api/asset-groups', 'asset_groups', stats=stats)
    assert len(server.calls) == 1 and not clock.sleeps and stats == {'initial': 0, 'restart': 0}


def test_gate_failure_output_initializes_numeric_phase_counters(capsys):
    assert gate.main(['--timeout-seconds', '0']) == 2
    output = json.loads(capsys.readouterr().out)
    assert output['accepted'] is False and output['failure_codes'] == ['invalid_arguments']
    assert output['page_retries'] == {'initial': 0, 'restart': 0}
    assert all(type(value) is int for value in output['page_retries'].values())


@pytest.mark.parametrize('body', [
    None, [], {}, {'success': False, 'error': 'Owned unavailable'},
    {**UNAVAILABLE, 'code': 'different_unavailable'}, {**UNAVAILABLE, 'success': 0},
    {**UNAVAILABLE, 'success': True}, {**UNAVAILABLE, 'error': ''},
    {**UNAVAILABLE, 'error': None}, {**UNAVAILABLE, 'error': 1},
    {**UNAVAILABLE, 'detail': 'Owned private value must not become failure text'},
])
def test_wrong_or_malformed_unavailable_envelopes_fail_without_retry(monkeypatch, body):
    clock, stats = Clock(), {'initial': 0, 'restart': 0}
    monkeypatch.setattr(gate.time, 'sleep', clock.sleep)
    server = Server([(503, body)], clock)
    with pytest.raises(gate.GateFailure, match='^page_http_503$'):
        gate.page_all(server, 'owned-owner', '/api/asset-groups', 'asset_groups', stats=stats)
    assert len(server.calls) == 1 and not clock.sleeps and stats == {'initial': 0, 'restart': 0}


@pytest.mark.parametrize('status,code', [(400, 'page_http_400'), (401, 'page_http_401'),
                                      (404, 'page_http_404'), (409, 'page_http_409'),
                                      (500, 'page_http_500'), (504, 'page_http_504'),
                                      (418, 'page_http_error'), ('private-status', 'page_http_error'),
                                      (503.0, 'page_http_error'), (200.0, 'page_http_error')])
def test_other_http_statuses_have_static_failures_without_retry(monkeypatch, status, code):
    clock = Clock()
    monkeypatch.setattr(gate.time, 'sleep', clock.sleep)
    server = Server([(status, UNAVAILABLE)], clock)
    with pytest.raises(gate.GateFailure, match='^' + code + '$'):
        gate.page_all(server, 'owned-owner', '/api/asset-groups', 'asset_groups')
    assert len(server.calls) == 1 and not clock.sleeps


@pytest.mark.parametrize('body', [None, [], {}, {'success': False, 'asset_groups': []},
                                {'success': True, 'asset_groups': {}},
                                {'success': True, 'asset_groups': None}])
def test_bad_success_page_shape_is_not_retried(monkeypatch, body):
    clock = Clock()
    monkeypatch.setattr(gate.time, 'sleep', clock.sleep)
    server = Server([(200, body)], clock)
    with pytest.raises(gate.GateFailure, match='^page_failed$'):
        gate.page_all(server, 'owned-owner', '/api/asset-groups', 'asset_groups')
    assert len(server.calls) == 1 and not clock.sleeps


@pytest.mark.parametrize('error', [URLError('Owned private transport location'), TimeoutError('Owned timeout'),
                                 gate.GateFailure('response_byte_limit')])
def test_transport_and_response_failures_propagate_without_retry(monkeypatch, error):
    clock, stats = Clock(), {'initial': 0, 'restart': 0}
    monkeypatch.setattr(gate.time, 'sleep', clock.sleep)
    server = Server([error], clock)
    with pytest.raises(type(error)) as caught:
        gate.page_all(server, 'owned-owner', '/api/asset-groups', 'asset_groups', stats=stats)
    assert caught.value is error
    assert len(server.calls) == 1 and not clock.sleeps and stats == {'initial': 0, 'restart': 0}


def test_repeated_cursor_is_still_rejected_after_retry(monkeypatch):
    clock, stats = Clock(), {'initial': 0, 'restart': 0}
    monkeypatch.setattr(gate.time, 'sleep', clock.sleep)
    server = Server([success(['first'], complete=False, cursor='same'), (503, UNAVAILABLE),
                     success(['second'], complete=False, cursor='same')], clock)
    with pytest.raises(gate.GateFailure, match='^nonadvancing_or_false_completion$'):
        gate.page_all(server, 'owned-owner', '/api/asset-groups', 'asset_groups', stats=stats)
    assert len(server.calls) == 3 and server.calls[1] == server.calls[2]
    assert stats == {'initial': 1, 'restart': 0}
