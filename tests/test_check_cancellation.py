"""Cancelled probes retain counters without manufacturing completion or evidence."""

import asyncio
from contextlib import nullcontext
from unittest.mock import Mock

import pytest

from src.core.contracts import (
    CHECK_INTERRUPTED_REASON,
    checked,
    collect_checks,
    record_interaction,
    validate_checks,
)
from src.core.transport import ScanBudget, current_budget, scan_transport


TARGET = {'provider': 'ollama', 'model': 'fixture', 'evidence_context_id': 'fixture-context'}


def probe_type(oracle):
    class Probe:
        @checked('authentication_bypass', 'cancellation-fixture', oracle=oracle)
        async def run(self, agent, ready, *, evaluated=1, failed=False, pending=False, block=True):
            for valid in [True] * evaluated + ([False] if failed else []):
                if current_budget():
                    current_budget().reserve('http://127.0.0.1:1')
                record_interaction(valid, decisive=True)
            if pending and current_budget():
                current_budget().reserve('http://127.0.0.1:1')
            ready.set()
            if block:
                await asyncio.Event().wait()
            return []
    return Probe


@pytest.mark.asyncio
@pytest.mark.parametrize('evaluated,failed,pending', [
    (0, False, False), (1, False, False), (5, False, False),
    (1, True, False), (1, False, True),
])
@pytest.mark.parametrize('with_budget', [False, True])
async def test_task_cancellation_cannot_pass_an_authentication_oracle(evaluated, failed, pending, with_budget):
    oracle = Mock(return_value=True)
    probe = probe_type(oracle)()
    ready = asyncio.Event()
    budget = ScanBudget(allow_loopback=True)
    with scan_transport(budget) if with_budget else nullcontext(), collect_checks() as checks:
        task = asyncio.create_task(probe.run(TARGET, ready, evaluated=evaluated, failed=failed, pending=pending))
        try:
            await asyncio.wait_for(ready.wait(), timeout=1)
        finally:
            task.cancel('private-cancellation-detail')
            with pytest.raises(asyncio.CancelledError):
                await task
    assert task.cancelled()
    assert len(checks) == 1
    check = checks[0]
    assert check['status'] == 'failed'
    assert check['outcome'] == 'inconclusive'
    assert check['reason'] == CHECK_INTERRUPTED_REASON
    assert check['responses_evaluated'] == evaluated
    assert check['requests_attempted'] == evaluated + int(failed) + int(pending and with_budget)
    assert 'private-cancellation-detail' not in str(checks)
    validate_checks(checks)
    oracle.assert_not_called()
    # Cancellation is not an extra HTTP request or failed HTTP response.
    assert budget.requests == (evaluated + int(failed) + int(pending) if with_budget else 0)
    assert budget.failures == budget.rejections == 0


@pytest.mark.asyncio
async def test_wait_for_timeout_keeps_failed_record_and_restores_accounting_context():
    oracle = Mock(return_value=True)
    probe = probe_type(oracle)()
    ready = asyncio.Event()
    with collect_checks() as checks:
        with pytest.raises((TimeoutError, asyncio.TimeoutError)):
            await asyncio.wait_for(probe.run(TARGET, ready, evaluated=5), timeout=0.01)
    assert ready.is_set()
    assert checks[0]['status'] == 'failed'
    assert checks[0]['outcome'] == 'inconclusive'
    assert checks[0]['requests_attempted'] == checks[0]['responses_evaluated'] == 5
    oracle.assert_not_called()
    record_interaction(True, decisive=True)
    with collect_checks() as completed:
        assert await probe.run(TARGET, asyncio.Event(), block=False) == []
    assert completed[0]['status'] == 'completed'
    assert completed[0]['outcome'] == 'passed'
    assert completed[0]['requests_attempted'] == completed[0]['responses_evaluated'] == 1
    oracle.assert_called_once_with(TARGET)
    assert checks[0]['responses_evaluated'] == 5


def test_event_loop_shutdown_propagates_cancellation_and_records_incomplete_check():
    oracle = Mock(return_value=True)
    probe = probe_type(oracle)()
    ready = None

    async def start():
        nonlocal ready
        ready = asyncio.Event()
        task = asyncio.create_task(probe.run(TARGET, ready))
        await asyncio.wait_for(ready.wait(), timeout=1)
        return task

    with collect_checks() as checks:
        task = asyncio.run(start())
    assert task.cancelled() and ready.is_set()
    assert checks[0]['status'] == 'failed'
    assert checks[0]['outcome'] == 'inconclusive'
    assert checks[0]['reason'] == CHECK_INTERRUPTED_REASON
    assert checks[0]['requests_attempted'] == checks[0]['responses_evaluated'] == 1
    oracle.assert_not_called()
