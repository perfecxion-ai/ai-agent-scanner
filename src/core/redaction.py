"""Remove configured credentials and credential-bearing URLs from reports."""

import re
from http.cookies import SimpleCookie, CookieError
from urllib.parse import parse_qsl, unquote, urlsplit, urlunsplit


_SENSITIVE = ('secret', 'token', 'password', 'canary', 'marker', 'apikey', 'authorization')
_URL = re.compile(r'https?://[^\s<>"\']+')


def sensitive_key(key):
    normalized = re.sub(r'[^a-z0-9]', '', str(key).lower())
    return normalized in ('cookie', 'setcookie') or any(word in normalized for word in _SENSITIVE)


def collect_secrets(value):
    secrets = set()
    if isinstance(value, dict):
        for key, item in value.items():
            if sensitive_key(key) and isinstance(item, str) and item:
                secrets.add(item)
                if item.lower().startswith(('bearer ', 'basic ')):
                    secrets.add(item.split(' ', 1)[1])
                if str(key).lower().replace('-', '') in ('cookie', 'setcookie'):
                    try:
                        parsed = SimpleCookie()
                        parsed.load(item)
                        secrets.update(cookie.value for cookie in parsed.values() if cookie.value)
                    except CookieError:
                        pass
            if sensitive_key(key) and isinstance(item, dict):
                secrets.update(entry for entry in item.values() if isinstance(entry, str) and entry)
            secrets.update(collect_secrets(item))
    elif isinstance(value, list):
        for item in value:
            secrets.update(collect_secrets(item))
    elif isinstance(value, str):
        for match in _URL.finditer(value):
            try:
                url = urlsplit(match.group())
                secrets.update(unquote(item) for item in (url.username, url.password) if item)
                secrets.update(item for key, item in parse_qsl(url.query) if sensitive_key(key) and item)
            except ValueError:
                continue
    return secrets


def _clean_url(match):
    try:
        url = urlsplit(match.group())
        return urlunsplit((url.scheme, url.netloc.rsplit('@', 1)[-1], url.path, '', ''))
    except ValueError:
        return '[redacted URL]'


def redact_secrets(value, secrets):
    if isinstance(value, dict):
        return {key: '[redacted]' if sensitive_key(key) and key not in ('endpoint_redacted',)
                else redact_secrets(item, secrets) for key, item in value.items()}
    if isinstance(value, list):
        return [redact_secrets(item, secrets) for item in value]
    if isinstance(value, str):
        value = _URL.sub(_clean_url, value)
        for secret in sorted(secrets, key=len, reverse=True):
            value = value.replace(secret, '[redacted]')
    return value
