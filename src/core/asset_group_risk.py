"""Canonical risk facts stored only in the derived group publication."""

from math import isfinite

from src.risk.risk_assessor import risk_level_for_score


RISK_FIELDS = ('risk_score', 'risk_level', 'risk_coverage_status',
               'risk_assessment_status', 'risk_scoring_policy', 'security_status')
RISK_LEVELS = frozenset({'critical', 'high', 'medium', 'low', 'minimal', 'unknown'})
_SECURITY_STATUSES = frozenset({'completed', 'partial', 'failed', 'skipped', 'not_tested', 'unknown'})


def risk_descriptor(value):
    """Reject incomplete staging facts; a missing descriptor is not unknown risk."""
    facts = {name: value[name] for name in RISK_FIELDS}
    if facts['security_status'] not in _SECURITY_STATUSES:
        raise ValueError('Invalid derived risk descriptor')
    score = facts['risk_score']
    if score is None:
        if any(facts[name] != expected for name, expected in (
                ('risk_level', 'unknown'), ('risk_coverage_status', 'not_assessed'),
                ('risk_assessment_status', 'not_assessed'), ('risk_scoring_policy', None))):
            raise ValueError('Invalid derived unknown descriptor')
    elif (type(score) not in {int, float} or not isfinite(score) or not 0 <= score <= 100
            or facts['risk_level'] != risk_level_for_score(score)
            or facts['risk_scoring_policy'] != 'severity-floor-v2'
            or facts['security_status'] not in {'completed', 'partial', 'failed'}
            or facts['risk_coverage_status'] != (
                'sampled' if facts['security_status'] == 'completed' else 'partial')
            or facts['risk_assessment_status'] != (
                'completed' if facts['security_status'] == 'completed' else 'partial')):
        raise ValueError('Invalid derived assessed descriptor')
    return facts
