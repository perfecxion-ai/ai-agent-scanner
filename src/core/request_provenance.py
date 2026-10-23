"""Bounded private outbound material for conservative reflection exclusion."""

from dataclasses import dataclass
import json
from urllib.parse import unquote, urlsplit


MAX_REQUEST_BODY = 128 * 1024
MAX_REQUEST_HEADERS = 64 * 1024
MAX_REQUEST_URL = 16 * 1024
MAX_HEADER_COUNT = 256


@dataclass(frozen=True, repr=False)
class RequestEvidence:
    """Private complete request snapshot; never place this object in a report."""

    method: str
    url: str
    headers: tuple
    body: bytes


def _headers(value):
    pairs, size = [], 0
    for key, item in value.items():
        if (len(pairs) >= MAX_HEADER_COUNT or not isinstance(key, str) or not isinstance(item, str)
                or len(key) + len(item) > MAX_REQUEST_HEADERS):
            raise ValueError('Incomplete outbound request provenance')
        size += len(key.encode('utf-8')) + len(item.encode('utf-8'))
        if size > MAX_REQUEST_HEADERS:
            raise ValueError('Incomplete outbound request provenance')
        pairs.append((key, item))
    if not pairs:
        raise ValueError('Incomplete outbound request provenance')
    return tuple(pairs)


def _complete_body(method, headers, body):
    lengths = [value for key, value in headers if key.casefold() == 'content-length']
    if any(key.casefold() in {'transfer-encoding', 'content-encoding'} for key, _ in headers):
        return False
    if lengths:
        return (len(lengths) == 1 and len(lengths[0]) <= 10 and lengths[0].isascii()
                and lengths[0].isdigit() and int(lengths[0]) == len(body))
    return not body and method in {'GET', 'HEAD', 'OPTIONS', 'DELETE'}


class RequestCapture:
    """One request's bounded trace, sealed once against its response metadata."""

    def __init__(self):
        self.method = self.url = self.headers = None
        self.body = bytearray()
        self.failed = self.closed = False

    def sent_headers(self, method, url, headers):
        if self.closed or self.failed:
            return
        try:
            if (self.headers is not None or not isinstance(method, str) or not 1 <= len(method) <= 16
                    or not isinstance(url, str) or not 1 <= len(url) <= MAX_REQUEST_URL):
                raise ValueError('Incomplete outbound request provenance')
            self.method, self.url, self.headers = method, url, _headers(headers)
        except (TypeError, ValueError, AttributeError):
            self.failed = True

    def sent_chunk(self, method, url, chunk):
        if self.closed or self.failed:
            return
        if (method != self.method or url != self.url or not isinstance(chunk, bytes)
                or len(self.body) + len(chunk) > MAX_REQUEST_BODY):
            self.failed = True
            self.body.clear()
            return
        self.body.extend(chunk)

    def seal(self, response):
        if self.closed:
            return None
        self.closed = True
        try:
            info = response.request_info
            if (self.failed or self.headers is None or info.method != self.method
                    or str(info.url) != self.url or str(info.real_url) != self.url
                    or _headers(info.headers) != self.headers):
                return None
            if not _complete_body(self.method, self.headers, self.body):
                return None
            return RequestEvidence(self.method, self.url, self.headers, bytes(self.body))
        except (TypeError, ValueError, AttributeError):
            return None
        finally:
            self.body.clear()


def _strings(value, depth=0, budget=None):
    if budget is None:
        budget = [0, 0]
    budget[0] += 1
    if depth > 16 or budget[0] > 8192:
        raise ValueError('Unsupported outbound request material')
    if isinstance(value, str):
        budget[1] += len(value)
        if budget[1] > MAX_REQUEST_BODY + MAX_REQUEST_HEADERS + MAX_REQUEST_URL:
            raise ValueError('Unsupported outbound request material')
        yield value
    elif isinstance(value, dict):
        for key, item in value.items():
            yield from _strings(key, depth + 1, budget)
            yield from _strings(item, depth + 1, budget)
    elif isinstance(value, (list, tuple)):
        for item in value:
            yield from _strings(item, depth + 1, budget)
    elif value is not None and type(value) not in (int, float, bool):
        raise ValueError('Unsupported outbound request material')


def _excluded(marker, material):
    if not isinstance(marker, str) or not marker or len(marker) > MAX_REQUEST_BODY:
        return False
    needle = marker.casefold()
    return all(needle not in value.casefold() for value in material)


def known_request_excludes_canary(request, marker):
    """Reject known adapter collisions before a connection or request starts."""
    try:
        strings = list(_strings(request))
        encoded = json.dumps(request, ensure_ascii=False)
        if len(encoded) > MAX_REQUEST_BODY:
            return False
        url = request['url']
        from yarl import URL
        normalized = str(URL(url))
        headers = request.get('headers', {})
        lines = '\r\n'.join(f'{key}: {value}' for key, value in headers.items())
        compact = '\r\n'.join(f'{key}:{value}' for key, value in headers.items())
        return _excluded(marker, [*strings, encoded, str(request), normalized,
                                  unquote(normalized), unquote(unquote(normalized)),
                                  lines, lines.replace('\r\n', '\n'), compact])
    except (TypeError, ValueError, KeyError, AttributeError, RecursionError):
        return False


def request_excludes_canary(evidence, marker):
    """Outbound comparison is casefolded; response confirmation stays exact."""
    if not isinstance(evidence, RequestEvidence):
        return False
    try:
        if (not isinstance(evidence.method, str) or not 1 <= len(evidence.method) <= 16
                or not isinstance(evidence.url, str) or not 1 <= len(evidence.url) <= MAX_REQUEST_URL
                or not isinstance(evidence.headers, tuple) or not 1 <= len(evidence.headers) <= MAX_HEADER_COUNT
                or not isinstance(evidence.body, bytes) or len(evidence.body) > MAX_REQUEST_BODY):
            return False
        pairs = evidence.headers
        if (any(not isinstance(pair, tuple) or len(pair) != 2
                or not all(isinstance(value, str) for value in pair) for pair in pairs)
                or any(len(key) + len(value) > MAX_REQUEST_HEADERS for key, value in pairs)
                or sum(len(key.encode('utf-8')) + len(value.encode('utf-8'))
                       for key, value in pairs) > MAX_REQUEST_HEADERS
                or not _complete_body(evidence.method, pairs, evidence.body)):
            return False
        body = evidence.body.decode('utf-8')
        decoded = json.loads(body) if body else None
        headers = dict(pairs)
        parts = urlsplit(evidence.url)
        target = parts.path or '/'
        if parts.query:
            target += '?' + parts.query
        lines = '\r\n'.join(f'{key}: {value}' for key, value in pairs)
        compact = '\r\n'.join(f'{key}:{value}' for key, value in pairs)
        material = [evidence.method, evidence.url, unquote(evidence.url), unquote(unquote(evidence.url)),
                    target, unquote(target), lines, lines.replace('\r\n', '\n'), compact,
                    f'{evidence.method} {target} HTTP/1.1\r\n{lines}',
                    json.dumps(headers, ensure_ascii=False), str(headers), body, str(decoded),
                    json.dumps(decoded, ensure_ascii=False), *_strings(pairs), *_strings(decoded)]
        return _excluded(marker, material)
    except (TypeError, ValueError, AttributeError, RecursionError):
        return False
