"""Shared inventory error and raw timestamp parsing primitives."""

from datetime import datetime
import re


class InventoryError(ValueError):
    """Only static text crosses the public error boundary."""

    def __init__(self, status, code, message):
        super().__init__(message)
        self.status, self.code, self.message = status, code, message


def _timestamp(value):
    if not isinstance(value, str) or not value or len(value.encode('utf-8')) > 64:
        raise ValueError('Invalid timestamp')
    # Normalize only display parsing for Python 3.10, which requires three or
    # six fractional digits and an explicit UTC offset. The sort key stays raw.
    normalized = re.sub(r'([0-9]{2}:[0-9]{2}:[0-9]{2})[.,]([0-9]+)',
                        lambda match: match[1] + '.' + match[2][:6].ljust(6, '0'), value)
    if normalized.endswith('Z'):
        if not re.search(r'[0-9]{2}:[0-9]{2}(?::[0-9]{2}(?:\.[0-9]+)?)?Z\Z', normalized):
            raise ValueError('Invalid UTC timestamp')
        normalized = normalized[:-1] + '+00:00'
    return datetime.fromisoformat(normalized)
