"""Bounded canonical risk values for scalar storage caches."""

import json

from src.core.contracts import MAX_CHECKPOINT_BYTES
from src.core.risk_projection import project_report_risk


MAX_STORED_RISK_BYTES = MAX_CHECKPOINT_BYTES
_MALFORMED = (TypeError, ValueError, KeyError, AttributeError, OverflowError, RecursionError, UnicodeError)


def _bounded(value):
    return len(json.dumps(value, ensure_ascii=True, allow_nan=False,
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
    """Use exactly the public API's explicit alias or snapshot-ID fallback."""
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
