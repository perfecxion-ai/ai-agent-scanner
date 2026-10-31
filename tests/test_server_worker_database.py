"""Owned worker database teardown preserves lifecycle ownership and failures."""

from contextlib import contextmanager
import os
from pathlib import Path
import runpy
import sys
from types import SimpleNamespace

import pytest


ROOT = Path(__file__).resolve().parents[1]


def invoke(monkeypatch, *, remove_fails=False, engine_fails=False,
           stop_result=True, context_fails=False, owner=True):
    events, acknowledgements = [], []
    active = False

    @contextmanager
    def context():
        nonlocal active
        events.append('context-enter')
        if context_fails:
            raise OSError('synthetic-private-context')
        active = True
        try:
            yield
        finally:
            events.append('context-exit')
            active = False

    def remove():
        assert active
        events.append('remove')
        if remove_fails:
            raise OSError('synthetic-private-session')

    def dispose(number):
        assert active
        events.append('dispose-' + str(number))
        if number == 1 and engine_fails:
            raise OSError('synthetic-private-engine')

    def stop():
        events.append('stop')
        return stop_result

    database = SimpleNamespace(session=SimpleNamespace(remove=remove),
        engines={None: SimpleNamespace(dispose=lambda: dispose(1)),
                 'second': SimpleNamespace(dispose=lambda: dispose(2))})
    monkeypatch.setitem(sys.modules, 'app', SimpleNamespace(
        app=SimpleNamespace(app_context=context), db=database, stop_job_dispatcher=stop))
    worker = SimpleNamespace(pid=os.getpid() if owner else os.getpid() + 1,
        sockets=[SimpleNamespace(close=lambda: events.append('listener'))],
        log=SimpleNamespace(info=lambda message, *args: acknowledgements.append(message % args)))
    error = None
    try:
        runpy.run_path(str(ROOT / 'gunicorn.conf.py'))['worker_exit'](None, worker)
    except RuntimeError as caught:
        error = str(caught)
    return events, acknowledgements, error


@pytest.mark.parametrize('remove_fails', [False, True])
@pytest.mark.parametrize('engine_fails', [False, True])
def test_all_owned_database_resources_attempted_before_ack(monkeypatch, remove_fails, engine_fails):
    events, acknowledgements, error = invoke(monkeypatch,
        remove_fails=remove_fails, engine_fails=engine_fails)
    assert events == ['stop', 'context-enter', 'remove', 'dispose-1',
                      'dispose-2', 'context-exit', 'listener']
    if remove_fails or engine_fails:
        assert error == 'Server worker cleanup failed: database'
        assert acknowledgements == []
    else:
        assert error is None
        assert acknowledgements == ['Scan worker cleanup ok pid=' + str(os.getpid())]


@pytest.mark.parametrize('stop_result', [False, None])
def test_incomplete_dispatcher_prevents_database_disposal(monkeypatch, stop_result):
    events, acknowledgements, error = invoke(monkeypatch, stop_result=stop_result)
    assert events == ['stop', 'listener']
    assert acknowledgements == []
    assert error == 'Server worker cleanup failed: dispatcher'


def test_application_context_failure_closes_listener_without_ack(monkeypatch):
    events, acknowledgements, error = invoke(monkeypatch, context_fails=True)
    assert events == ['stop', 'context-enter', 'listener']
    assert acknowledgements == []
    assert error == 'Server worker cleanup failed: database'


def test_master_avoids_dispatcher_database_and_listener_cleanup(monkeypatch):
    assert invoke(monkeypatch, owner=False) == ([], [], None)

