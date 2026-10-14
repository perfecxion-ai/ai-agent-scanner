"""Strict, bounded saved scan definitions without credential options."""

import json
import re
from copy import deepcopy
from urllib.parse import urlsplit

from src.core.scope import ScopeValidationError, bounded_integer


MAX_TEMPLATE_BYTES = 16 * 1024
DEFINITION_FIELDS = frozenset({"scan_name", "scan_type", "target_scope", "scan_config"})
_URL = re.compile(r'https?://[^\s<>"\']+', re.IGNORECASE)


def project_template(data):
    """Reject unsupported input before storing a projected existing scan recipe."""
    if not isinstance(data, dict) or set(data) - DEFINITION_FIELDS:
        raise ScopeValidationError("Templates accept only scan_name, scan_type, target_scope, and scan_config")
    try:
        encoded = json.dumps(data, ensure_ascii=False, allow_nan=False).encode("utf-8")
    except (TypeError, ValueError, RecursionError, UnicodeError) as exc:
        raise ScopeValidationError("Template must be finite, valid JSON") from exc
    if len(encoded) > MAX_TEMPLATE_BYTES:
        raise ScopeValidationError("Template exceeds the 16 KiB definition limit")
    # Unknown nested fields are rejected by the same scan validator used at execution.
    pending = [data]
    while pending:
        item = pending.pop()
        if isinstance(item, dict):
            pending.extend(item.keys())
            pending.extend(item.values())
        elif isinstance(item, list):
            pending.extend(item)
        elif isinstance(item, str):
            if any(ord(char) < 32 or ord(char) == 127 for char in item):
                raise ScopeValidationError("Template strings cannot contain control characters")
            for match in _URL.finditer(item):
                try:
                    url = urlsplit(match.group())
                except ValueError as exc:
                    raise ScopeValidationError("Invalid URL in template") from exc
                if url.username is not None or url.password is not None or url.query:
                    raise ScopeValidationError("Templates cannot contain credential-bearing or query URLs")
    return deepcopy(data)


def template_revision(value):
    return bounded_integer(value, "revision", 2**31 - 1)
