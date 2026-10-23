"""Declared complete request bytes for offline component fixtures, not HTTP proof."""

import json
from types import SimpleNamespace

from aiohttp.http import SERVER_SOFTWARE
from yarl import URL

from src.core.request_provenance import RequestCapture
from src.utils.request_builder import construct_agent_request


def declared_wire_request(method, url, *, headers=None, json_body=None):
    """Match the complete request our substituted socket-facing client declares."""
    url = URL(url)
    body = json.dumps(json_body).encode('utf-8') if json_body is not None else b''
    outgoing = {'Host': url.raw_authority, 'Accept': '*/*', 'User-Agent': SERVER_SOFTWARE,
                **(headers or {}), 'Content-Length': str(len(body))}
    info = SimpleNamespace(method=method, url=url, real_url=url, headers=outgoing)
    return body, info


def declared_request_evidence(agent, payload):
    """Exercise capture and sealing for a synthetic offline analyzer response."""
    request = construct_agent_request(agent, payload)
    assert request is not None
    body, info = declared_wire_request(request['method'], request['url'],
                                      headers=request.get('headers'), json_body=request.get('json'))
    capture = RequestCapture()
    capture.sent_headers(info.method, str(info.url), info.headers)
    capture.sent_chunk(info.method, str(info.url), body)
    evidence = capture.seal(SimpleNamespace(request_info=info))
    assert evidence is not None
    return evidence
