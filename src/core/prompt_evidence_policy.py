"""Pure bounded eligibility for configured-canary prompt observation receipts."""

from functools import lru_cache
import hashlib
import json
import uuid

from src.core.prompt_catalog import baseline_payloads, candidate_payloads


CHECK_EVIDENCE_SCHEMA_VERSION = '1.0'
EVIDENCE_SOURCE = 'protected_system_canary_match'
MAX_CHECK_EVIDENCE = 35
PUBLIC_EVIDENCE_FIELDS = (
    'check_evidence_schema_version', 'check_evidence_run_id', 'check_evidence',
    'check_evidence_id', 'finding_id', 'sample_index', 'sequence', 'request_ordinal',
    'requests_attempted', 'responses_evaluated', 'source_version', 'source', 'run_id',
    EVIDENCE_SOURCE, 'confirmed_observations_and_finalized_checks', 'checks_unfinished',
)
_FIELDS = frozenset((
    'id', 'run_id', 'agent_id', 'rule_id', 'probe_id', 'probe_version',
    'evidence_context_id', 'finding_id', 'sample_index', 'sequence',
    'request_ordinal', 'requests_attempted', 'responses_evaluated', 'source', 'source_version',
))
_CATALOGS = tuple(tuple((category, tuple(payloads[:5])) for category, payloads in catalog.items())
                  for catalog in (baseline_payloads(), candidate_payloads()))


def _text(value, limit, *, brackets=True):
    return (isinstance(value, str) and 1 <= len(value) <= limit and value == value.strip()
            and all(ord(char) >= 32 and ord(char) != 127 for char in value)
            and '[redact' not in value.casefold()
            and (brackets or '[' not in value and ']' not in value))


def _uuid(value):
    if not isinstance(value, str) or len(value) != 36:
        return False
    try:
        return str(uuid.UUID(value)) == value
    except ValueError:
        return False


@lru_cache(maxsize=128)
def _probes(provider, model):
    probes = {}
    for catalog in _CATALOGS:
        for category, payloads in catalog:
            definition = {'semantics': 'nondisclosure-inconclusive-v2', 'payloads': list(payloads)}
            version = '1:' + hashlib.sha256(json.dumps([definition, provider, model], sort_keys=True).encode()).hexdigest()
            probes[('prompt_injection.' + category, version)] = payloads
    return probes


def prompt_probe_payloads(rule_id, probe_id, probe_version, *, provider, model):
    """Recognize only exact public first-five definitions and bounded context."""
    if (not _text(provider, 64) or model is not None and not _text(model, 256)
            or not isinstance(rule_id, str) or len(rule_id) > 128
            or probe_id != rule_id + '.sample'
            or not isinstance(probe_version, str) or len(probe_version) != 66):
        return None
    return _probes(provider, model).get((rule_id, probe_version))


def prompt_claim(finding):
    return (isinstance(finding, dict)
            and (finding.get('vulnerability_type') == 'prompt_injection'
                 or isinstance(finding.get('rule_id'), str)
                 and finding['rule_id'].startswith('prompt_injection.')))


def has_evidence_contract(asset):
    if not isinstance(asset, dict):
        return False
    return any(key in asset for key in (
        'check_evidence_schema_version', 'check_evidence_run_id', 'check_evidence')) or any(
            isinstance(finding, dict) and 'check_evidence_id' in finding
            for name in ('vulnerabilities', 'observations') for finding in (
                asset.get(name, []) if isinstance(asset.get(name, []), list) else []))


def validate_prompt_evidence(asset, *, strict=True):
    try:
        return _validate_prompt_evidence(asset, strict=strict)
    except (TypeError, ValueError, KeyError, OverflowError):
        raise ValueError('Invalid prompt observation evidence') from None


def _validate_prompt_evidence(asset, *, strict=True):
    """Validate receipts and final reconciliation without mutating archived data."""
    def invalid():
        raise ValueError('Invalid prompt observation evidence')

    if not isinstance(asset, dict):
        invalid()
    if not has_evidence_contract(asset):
        return asset
    if asset.get('check_evidence_schema_version') != CHECK_EVIDENCE_SCHEMA_VERSION:
        invalid()
    receipts, findings, checks = asset.get('check_evidence'), asset.get('vulnerabilities', []), asset.get('checks', [])
    if (not isinstance(receipts, list) or len(receipts) > MAX_CHECK_EVIDENCE
            or not isinstance(findings, list) or not all(isinstance(value, dict) for value in findings)
            or not isinstance(checks, list) or not all(isinstance(value, dict) for value in checks)):
        invalid()
    run_id = asset.get('check_evidence_run_id')
    identifier = _uuid if strict else lambda value: isinstance(value, str) and 1 <= len(value) <= 128
    if ('check_evidence_run_id' in asset and not identifier(run_id)) or receipts and not identifier(run_id):
        invalid()
    if receipts and not all(key in asset for key in ('provider', 'model')):
        invalid()
    seen, occurrences, groups, rules = set(), set(), {}, {}
    for receipt in receipts:
        if (not isinstance(receipt, dict) or set(receipt) != _FIELDS
                or not identifier(receipt['id']) or receipt['id'] in seen
                or not identifier(receipt['finding_id']) or receipt['finding_id'] in occurrences
                or receipt['run_id'] != run_id
                or receipt['agent_id'] != asset.get('agent_id', asset.get('id'))
                or not isinstance(receipt['agent_id'], str) or not 1 <= len(receipt['agent_id']) <= 256
                or strict and not _text(receipt['agent_id'], 256)
                or any(not isinstance(receipt[key], str) or not 1 <= len(receipt[key]) <= limit
                       for key, limit in (('rule_id', 128), ('probe_id', 160), ('probe_version', 128)))
                or receipt['source'] != EVIDENCE_SOURCE or receipt['source_version'] != '1.0'):
            invalid()
        seen.add(receipt['id'])
        occurrences.add(receipt['finding_id'])
        context = receipt['evidence_context_id']
        if context is not None and (not isinstance(context, str) or not 1 <= len(context) <= 128
                                    or strict and not _text(context, 128, brackets=False)):
            invalid()
        for key in ('sequence', 'request_ordinal', 'requests_attempted', 'responses_evaluated'):
            if type(receipt[key]) is not int or not 1 <= receipt[key] <= 5:
                invalid()
        index = receipt['sample_index']
        if (type(index) is not int or not 0 <= index < 5
                or receipt['request_ordinal'] != receipt['requests_attempted']
                or receipt['responses_evaluated'] > receipt['requests_attempted']
                or receipt['requests_attempted'] > index + 1):
            invalid()
        payloads = prompt_probe_payloads(receipt['rule_id'], receipt['probe_id'], receipt['probe_version'],
                                        provider=asset['provider'], model=asset['model'])
        if strict and payloads is None:
            invalid()
        matches = [finding for finding in findings if finding.get('id') == receipt['finding_id']]
        if len(matches) != 1:
            invalid()
        finding = matches[0]
        if (finding.get('check_evidence_id') != receipt['id']
                or finding.get('evidence_status') != 'confirmed'
                or finding.get('vulnerability_type') != 'prompt_injection'
                or strict and finding.get('severity') != 'high'
                or finding.get('category') != receipt['rule_id'].removeprefix('prompt_injection.')
                or finding.get('agent_id') != receipt['agent_id']
                or strict and finding.get('payload') != payloads[index]
                or type(finding.get('status_code')) is not int or not 200 <= finding['status_code'] < 300
                or any(key not in finding or finding[key] != receipt[key]
                       for key in ('rule_id', 'probe_id', 'probe_version', 'evidence_context_id'))):
            invalid()
        identity = tuple(receipt[key] for key in ('rule_id', 'probe_id', 'probe_version', 'evidence_context_id'))
        if receipt['rule_id'] in rules and rules[receipt['rule_id']] != identity:
            invalid()
        rules[receipt['rule_id']] = identity
        previous = groups.setdefault(identity, [])
        if receipt['sequence'] != len(previous) + 1 or previous and any(
                receipt[key] <= previous[-1][key]
                for key in ('sample_index', 'request_ordinal', 'responses_evaluated')):
            invalid()
        previous.append(receipt)
    for finding in findings:
        if (strict and prompt_claim(finding) and finding.get('evidence_status') == 'confirmed'
                and finding.get('id') not in occurrences):
            invalid()
        if 'check_evidence_id' in finding and finding.get('id') not in occurrences:
            invalid()
    if any(isinstance(value, dict) and 'check_evidence_id' in value
           for value in asset.get('observations', [])):
        invalid()
    if strict:
        for check in checks:
            rule = check.get('rule_id')
            if isinstance(rule, str) and rule.startswith('prompt_injection.'):
                identity = tuple(check.get(key) for key in ('rule_id', 'probe_id', 'probe_version', 'evidence_context_id'))
                if check.get('outcome') == 'passed' or check.get('outcome') == 'confirmed' and identity not in groups:
                    invalid()
    for identity, group in groups.items():
        terminal = [check for check in checks if check.get('rule_id') == identity[0]]
        if len(terminal) > 1:
            invalid()
        if terminal:
            check = terminal[0]
            if (tuple(check.get(key) for key in ('rule_id', 'probe_id', 'probe_version', 'evidence_context_id')) != identity
                    or check.get('status') not in {'completed', 'failed'} or check.get('outcome') != 'confirmed'
                    or any(type(check.get(key)) is not int or not group[-1][key] <= check[key] <= 5
                           for key in ('requests_attempted', 'responses_evaluated'))
                    or check['responses_evaluated'] > check['requests_attempted']):
                invalid()
    return asset
