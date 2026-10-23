"""Private task-bound HTTP observation tokens, never serialized into reports."""

import asyncio
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass


_trace = ContextVar('request_trace', default=None)


@dataclass
class RequestTrace:
    task: object
    identity: tuple
    requests: int = 0
    evaluated: int = 0
    failed: bool = False
    cancelled: bool = False
    authorization_denied: bool = False
    sample: tuple | None = None


@dataclass
class _RequestToken:
    trace: RequestTrace
    ordinal: int
    response: object = None
    active: bool = True
    evaluated: bool = False
    valid: bool = False
    published: bool = False
    body: bytes | None = None
    status: int | None = None
    request_evidence: object = None


def current_trace():
    trace = _trace.get()
    return trace if trace is not None and trace.task is asyncio.current_task() else None


@contextmanager
def trace_requests(trace):
    token = _trace.set(trace)
    try:
        yield
    finally:
        _trace.reset(token)


@contextmanager
def prompt_sample(index, category, payload):
    trace = current_trace()
    previous = trace.sample if trace else None
    if trace is not None:
        trace.sample = (index, category, payload)
    try:
        yield
    finally:
        if trace is not None:
            trace.sample = previous


def reserved_request():
    """Called only by transport after a request passes budget reservation."""
    trace = _trace.get()
    if trace is None:
        return None
    if trace.task is not asyncio.current_task():
        raise ValueError('Request evidence cannot cross task ownership')
    trace.requests += 1
    return _RequestToken(trace, trace.requests)


def bind_response(token, response):
    if token is not None:
        if token.response is not None:
            raise ValueError('Request evidence response is already bound')
        token.response = response
        token.status = response.status
        token.request_evidence = response._request_evidence


def capture_body(token, response, body):
    if token is not None:
        if token.response is not response or not token.active or token.body is not None:
            raise ValueError('Request evidence body is already bound')
        token.body = body


def close_request(token):
    if token is not None:
        token.active = False


def cancel_request(token=None):
    trace = token.trace if token is not None else current_trace()
    if trace is not None:
        trace.cancelled = True


def response_token(response, *, evaluated=False):
    token = getattr(response, '_evidence_token', None)
    trace = current_trace()
    if (not isinstance(token, _RequestToken) or trace is None
            or token.trace is not trace or not token.active or token.response is not response
            or (evaluated and not (token.evaluated and token.valid))):
        return None
    return token


def evaluate_response(response, valid, *, status_code=None):
    """Count an actual live response at most once, without counting cleanup."""
    trace = current_trace()
    if trace is None:
        return False
    token = response_token(response)
    if token is None or token.evaluated or type(valid) is not bool:
        trace.failed = True
        return False
    if valid and not isinstance(token.body, bytes):
        trace.failed = True
        return False
    token.evaluated = True
    token.valid = valid
    trace.evaluated += int(valid)
    trace.failed |= not valid
    trace.authorization_denied |= not valid and status_code in (401, 403)
    return True


def fail_request():
    trace = current_trace()
    if trace is not None:
        trace.failed = True
