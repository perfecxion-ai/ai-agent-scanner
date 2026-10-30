"""Bounded canonical risk values for scalar storage caches."""

import json
import re

from src.core.contracts import MAX_CHECKPOINT_BYTES
from src.core.risk_projection import project_report_risk


MAX_STORED_RISK_BYTES = MAX_CHECKPOINT_BYTES
MAX_STORED_RISK_DEPTH = 64
_MALFORMED = (TypeError, ValueError, KeyError, AttributeError, OverflowError, RecursionError, UnicodeError)
_JSON_MARKS = re.compile(r'["\\\[\]{}]')


def stored_json_text(raw):
    """Bound UTF8 JSON before parsing; other byte encodings stay unassessed."""
    if not isinstance(raw, bytes) or len(raw) > MAX_STORED_RISK_BYTES:
        return None
    try:
        text = raw.decode('utf-8-sig')
    except UnicodeError:
        return None
    depth, quoted, escaped_at = 0, False, -1
    for match in _JSON_MARKS.finditer(text):
        position, mark = match.start(), match.group()
        if quoted:
            if position == escaped_at:
                escaped_at = -1
                continue
            escaped_at = position + 1 if mark == '\\' else -1
            if mark == '"':
                quoted = False
        elif mark == '"':
            quoted = True
        elif mark in '[{':
            depth += 1
            if depth > MAX_STORED_RISK_DEPTH:
                return None
        elif mark in ']}':
            depth -= 1
            if depth < 0:
                return None
        else:
            return None
    return text if depth == 0 and not quoted else None


def _minimum_scalar_bytes(value):
    if isinstance(value, str):
        return len(value) + 2
    if value is None:
        return 4
    if isinstance(value, bool):
        return 4 if value else 5
    if isinstance(value, int):
        return max(1, value.bit_length() // 4)
    return 1 if isinstance(value, float) else None


def _object_within_bounds(value):
    """Walk iterator frames, bounding depth, cycles and expanded byte cost."""
    containers = (dict, list, tuple)
    if not isinstance(value, containers):
        minimum = _minimum_scalar_bytes(value)
        return minimum is not None and minimum <= MAX_STORED_RISK_BYTES
    active = {id(value)}
    stack = [[id(value), iter(value.items() if isinstance(value, dict) else value),
              isinstance(value, dict), True]]
    minimum = 2
    while stack:
        frame = stack[-1]
        try:
            child = next(frame[1])
        except StopIteration:
            active.remove(frame[0])
            stack.pop()
            continue
        if not frame[3]:
            minimum += 1  # Comma between entries.
        frame[3] = False
        if frame[2]:
            key, child = child
            if not isinstance(key, (str, int, float, bool)) and key is not None:
                return False
            minimum += (len(key) + 2 if isinstance(key, str) else 3) + 1
        if isinstance(child, containers):
            if len(stack) >= MAX_STORED_RISK_DEPTH or id(child) in active:
                return False
            minimum += 2
            active.add(id(child))
            stack.append([id(child), iter(child.items() if isinstance(child, dict) else child),
                          isinstance(child, dict), True])
        else:
            cost = _minimum_scalar_bytes(child)
            if cost is None:
                return False
            minimum += cost
        if minimum > MAX_STORED_RISK_BYTES:
            return False
    return minimum <= MAX_STORED_RISK_BYTES


def _bounded(value):
    return _object_within_bounds(value) and len(json.dumps(
        value, ensure_ascii=True, allow_nan=False,
        separators=(',', ':')).encode('utf-8')) <= MAX_STORED_RISK_BYTES


def project_stored_risk(report):
    """Interpret current evidence without changing the archived report."""
    try:
        if _bounded(report):
            return project_report_risk(report)
    except _MALFORMED:
        pass
    return {'overall_risk_score': None, 'risk_assessment_status': 'not_assessed'}, {}


def snapshot_stored_risk(per_asset_map, snapshot_id, metadata):
    """Select legacy scalar caches by alias; public readers also bind saved targets."""
    try:
        if not _bounded(metadata):
            return None, 'unknown'
        metadata = metadata if isinstance(metadata, dict) else {}
        identifier = metadata.get('asset_id', snapshot_id)
        if not isinstance(identifier, str) or not identifier:
            return None, 'unknown'
        projected = per_asset_map.get(identifier, {})
        return projected.get('risk_score'), projected.get('risk_level', 'unknown')
    except _MALFORMED:
        return None, 'unknown'
