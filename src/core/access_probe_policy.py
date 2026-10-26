"""Pure current protected-access definitions and conservative evidence eligibility."""

from dataclasses import dataclass
from functools import lru_cache
import hashlib
import json
from types import MappingProxyType


ACCESS_CONTROL_VERSION = 'authorized-and-denied-resource-controls-v3'
ACCESS_CONTROL_STATUS = 'authorized_marker_verified_and_invalid_credential_denied'
PROTECTED_CONTROL_VERSION = 3
PUBLIC_ACCESS_FIELDS = ('protected_control_version', 'protected_path_index')
PROTECTED_ACCESS_RULES = frozenset({
    'authentication_bypass', 'weak_credentials', 'weak_api_key', 'authorization_bypass',
})
DEFAULT_WEAK_CREDENTIALS = (
    ('admin', 'admin'), ('admin', 'password'), ('admin', '123456'), ('admin', ''),
    ('test', 'test'), ('user', 'user'), ('guest', 'guest'), ('api', 'api'),
    ('demo', 'demo'), ('root', 'root'),
)
DEFAULT_TEST_API_KEYS = (
    'test-key', 'demo-key', 'dev-key', 'api-key', '123456789',
    'sk-1234567890abcdef', 'Bearer test', 'test_key_123', 'development', 'staging',
)
DEFAULT_SENSITIVE_PATHS = (
    '/admin', '/admin/', '/administrator', '/api/admin', '/api/v1/admin',
    '/admin/users', '/admin/config', '/system', '/debug', '/internal',
    '/../admin', '/./admin', '/%2e%2e/admin', '/admin%00', '/admin.php', '/admin.json',
)
PROTECTED_ACCESS_PATHS = DEFAULT_SENSITIVE_PATHS[:8]


def access_probe_definition(rule_id, *, sample=None):
    """Use the producer's exact public definition, including customized samples."""
    if rule_id == 'authentication_bypass':
        return ['18-header-variations', ACCESS_CONTROL_VERSION]
    if rule_id == 'weak_credentials':
        return [list(DEFAULT_WEAK_CREDENTIALS[:5] if sample is None else sample), ACCESS_CONTROL_VERSION]
    if rule_id == 'weak_api_key':
        return [list(DEFAULT_TEST_API_KEYS[:5] if sample is None else sample),
                'six-header-variations-v1', ACCESS_CONTROL_VERSION]
    if rule_id == 'authorization_bypass':
        return ['admin-path-sample-v1', list(PROTECTED_ACCESS_PATHS if sample is None else sample),
                ACCESS_CONTROL_VERSION]
    raise ValueError('Unsupported protected-access rule')


@dataclass(frozen=True)
class SupportedAccessProbe:
    """Public sample identity; max_requests bounds recorded legacy accounting."""

    rule_id: str
    probe_id: str
    probe_version: str
    protected_paths: tuple[str, ...]
    expected_pass_responses: int
    max_requests: int


def _public_text(value, maximum):
    return (isinstance(value, str) and 0 < len(value) <= maximum
            and value == value.strip() and '[redacted' not in value.casefold()
            and not any(ord(char) < 32 or ord(char) == 127 for char in value))


def _version(rule, provider, model, paths=()):
    identity = [access_probe_definition(rule), provider, model]
    if rule == 'authorization_bypass':
        identity.append(list(paths))
    return '1:' + hashlib.sha256(json.dumps(identity, sort_keys=True).encode()).hexdigest()


@lru_cache(maxsize=128)
def _authorization_probes(provider, model):
    """At most 255 ordered subsets per bounded public provider/model pair."""
    probes = {}
    for mask in range(1, 1 << len(PROTECTED_ACCESS_PATHS)):
        paths = tuple(path for index, path in enumerate(PROTECTED_ACCESS_PATHS) if mask & (1 << index))
        version = _version('authorization_bypass', provider, model, paths)
        probes[version] = SupportedAccessProbe('authorization_bypass', 'authorization_bypass.sample',
                                               version, paths, 3 * len(paths), 4 * len(paths))
    return MappingProxyType(probes)


def protected_access_probe(check, *, provider, model):
    """Recognize current frozen probes without importing engines or credentials.

    Callers must supply original context keys, not turn missing metadata into
    None. An explicit model None is legitimate for native endpoint adapters.
    """
    if (not isinstance(check, dict) or not _public_text(provider, 64)
            or (model is not None and not _public_text(model, 256))):
        return None
    rule, probe, version = (check.get(key) for key in ('rule_id', 'probe_id', 'probe_version'))
    if (not isinstance(rule, str) or rule not in PROTECTED_ACCESS_RULES
            or probe != rule + '.sample' or not isinstance(version, str) or len(version) != 66
            or not version.startswith('1:') or any(char not in '0123456789abcdef' for char in version[2:])):
        return None
    if rule == 'authorization_bypass':
        return _authorization_probes(provider, model).get(version)
    if version != _version(rule, provider, model):
        return None
    # Cleanup errors can be recorded after a response was already evaluated.
    # These are conservative legacy accounting bounds, not wire-request totals.
    count, maximum = {'authentication_bypass': (20, 56), 'weak_credentials': (7, 12),
                      'weak_api_key': (32, 37)}[rule]
    return SupportedAccessProbe(rule, probe, version, (), count, maximum)


def _counters(check):
    attempts, evaluated = check.get('requests_attempted'), check.get('responses_evaluated')
    if type(attempts) is not int or type(evaluated) is not int or not 0 <= evaluated <= attempts:
        return None
    return attempts, evaluated


def _context(check):
    return ('evidence_context_id' in check
            and (check['evidence_context_id'] is None
                 or (_public_text(check['evidence_context_id'], 128)
                     and '[' not in check['evidence_context_id'] and ']' not in check['evidence_context_id'])))


def protected_access_pass(check, *, provider, model):
    """Only a full current controlled sample can establish a sampled pass."""
    current = protected_access_probe(check, provider=provider, model=model)
    if current is None or not _context(check):
        return False
    return (check.get('status') == 'completed' and check.get('outcome') == 'passed'
            and check.get('reason') is None
            and _counters(check) == (current.expected_pass_responses, current.expected_pass_responses))


def _literal_redaction_matches(value, original):
    if not isinstance(value, str) or not 0 < len(value) <= 128:
        return False
    if value == original:
        return True
    marker = '[redacted]'
    literal = value.replace(marker, '')
    if not 1 <= value.count(marker) <= 8 or '[' in literal or ']' in literal:
        return False
    parts = value.split(marker)
    if not original.startswith(parts[0]):
        return False
    # Match only bounded literal redactions of this exact public constant. Each
    # placeholder must replace at least one character; no regex backtracking.
    positions = {len(parts[0])}
    for suffix in parts[1:]:
        positions = {end + len(suffix) for start in positions
                     for end in range(start + 1, len(original) + 1)
                     if original.startswith(suffix, end)}
    return len(original) in positions


def _protected_path_matches(finding, current):
    path = finding.get('path')
    if 'protected_path_index' not in finding:
        return path in current.protected_paths
    index = finding['protected_path_index']
    if type(index) is not int or not 0 <= index < len(PROTECTED_ACCESS_PATHS):
        return False
    original = PROTECTED_ACCESS_PATHS[index]
    return original in current.protected_paths and _literal_redaction_matches(path, original)


def _protected_controls_match(finding):
    status = finding.get('control_status')
    version = finding.get('protected_control_version')
    return (type(version) is int and version == PROTECTED_CONTROL_VERSION
            and _literal_redaction_matches(status, ACCESS_CONTROL_STATUS))


def protected_access_confirmation(check, finding, *, provider, model):
    """Keep genuine partial confirmations, never old or unsupported semantics."""
    current = protected_access_probe(check, provider=provider, model=model)
    if (current is None or not isinstance(finding, dict) or not _context(check) or not _context(finding)
            or check.get('outcome') != 'confirmed' or finding.get('evidence_status') != 'confirmed'
            or finding.get('vulnerability_type') != current.rule_id
            or not _protected_controls_match(finding)
            or type(finding.get('status_code')) is not int or not 200 <= finding['status_code'] < 300
            or any(check.get(key) != finding.get(key)
                   for key in ('rule_id', 'probe_id', 'probe_version', 'evidence_context_id'))
            or (current.protected_paths and not _protected_path_matches(finding, current))):
        return False
    counts = _counters(check)
    if counts is None:
        return False
    attempts, evaluated = counts
    if check.get('status') == 'failed':
        return (isinstance(check.get('reason'), str)
                and 3 <= evaluated <= current.expected_pass_responses
                and evaluated <= attempts <= current.max_requests)
    if check.get('status') != 'completed' or check.get('reason') is not None:
        return False
    if current.rule_id == 'weak_api_key':
        return 7 <= evaluated == attempts <= current.expected_pass_responses
    return counts == (current.expected_pass_responses, current.expected_pass_responses)
