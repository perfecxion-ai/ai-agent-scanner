"""Pure bounded policy for receipt-backed protected-resource observations."""

import json
import re

from yarl import URL

from src.core.access_probe_policy import (
    ACCESS_CONTROL_STATUS, ACCESS_EVIDENCE_SOURCE, PROTECTED_ACCESS_PATHS, PROTECTED_ACCESS_RULES,
    PROTECTED_CONTROL_VERSION, SupportedAccessProbe, _literal_redaction_matches, _protected_path_matches,
    _public_text, protected_access_probe,
)
from src.core.tenant_observation_policy import COMMON_RECEIPT_FIELDS
from src.core.request_provenance import MAX_HEADER_COUNT, MAX_REQUEST_HEADERS, _strings


MAX_ACCESS_CHECK_EVIDENCE = 36
ACCESS_RECEIPT_FIELDS = COMMON_RECEIPT_FIELDS | {'access_target', 'control_proof'}
ACCESS_CAPS = {'authentication_bypass': 18, 'weak_credentials': 5, 'weak_api_key': 5, 'authorization_bypass': 8}
_JSON_MARKS = re.compile(r'["\\\[\]{}]')


def access_denial_absent(body, headers, marker):
    """The unchanged v3 bounded absence oracle, shared with live witnesses."""
    try:
        if not isinstance(body, bytes):
            return False
        text = body.decode('utf-8-sig')
        pairs = tuple(headers.items())
        if ('\x00' in text or '\ufeff' in text or marker.casefold() in text.casefold()
                or len(pairs) > MAX_HEADER_COUNT or any(not isinstance(value, str) for pair in pairs for value in pair)
                or sum(len(value.encode()) for pair in pairs for value in pair) > MAX_REQUEST_HEADERS
                or any(marker.casefold() in value.casefold() for pair in pairs for value in pair)):
            return False
        if not text.lstrip().startswith(('{', '[', '"')):
            return True
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
                if depth > 16:
                    return False
            elif mark in ']}':
                depth -= 1
                if depth < 0:
                    return False
            else:
                return False
        if depth or quoted:
            return False
        def unique(items):
            value = {}
            for key, item in items:
                if key in value:
                    raise ValueError('Ambiguous denial response')
                value[key] = item
            return value
        def constant(value):
            raise ValueError('Invalid denial response')
        decoded = json.loads(text, object_pairs_hook=unique, parse_constant=constant)
        return not any('\x00' in value or '\ufeff' in value or marker.casefold() in value.casefold()
                       for value in _strings(decoded))
    except (TypeError, ValueError, KeyError, AttributeError, UnicodeError, OverflowError, RecursionError):
        return False


def access_claim(value):
    return isinstance(value, dict) and any(isinstance(value.get(key), str) and value[key] in PROTECTED_ACCESS_RULES
                                         for key in ('rule_id', 'vulnerability_type'))


def access_target(asset, *, protected_path_index=None, strict=True):
    endpoint, provider, model, context = (asset.get(key) for key in ('endpoint', 'provider', 'model', 'evidence_context_id'))
    text = _public_text if strict else lambda value, maximum: type(value) is str and 1 <= len(value) <= maximum
    if (not text(endpoint, 16384) or not text(provider, 64)
            or model is not None and not text(model, 256)
            or context is not None and (not text(context, 128) or strict and ('[' in context or ']' in context))):
        raise ValueError('Invalid public access target')
    if protected_path_index is not None:
        if type(protected_path_index) is not int or not 0 <= protected_path_index < len(PROTECTED_ACCESS_PATHS):
            raise ValueError('Invalid public access target')
    if not strict and '[redact' in endpoint.casefold():
        return dict(endpoint=endpoint, provider=provider, model=model, evidence_context_id=context)
    url = URL(endpoint)
    if url.scheme not in {'http', 'https'} or not url.host or url.user is not None or url.query_string or url.fragment or '%' in endpoint:
        raise ValueError('Invalid public access target')
    return dict(endpoint=str(url), provider=provider, model=model, evidence_context_id=context)


def receipt_fields(receipt):
    rule = receipt.get('rule_id')
    return ACCESS_RECEIPT_FIELDS | ({'protected_path_index'} if rule == 'authorization_bypass' else
                                   {'sample_index', 'header_index'} if rule == 'weak_api_key' else {'sample_index'})


def _probe(value, asset, strict):
    probe = protected_access_probe(value, provider=asset.get('provider'), model=asset.get('model'))
    rule = value.get('rule_id')
    if probe is None and not strict and rule in ACCESS_CAPS:
        # Structural redacted reads stay bounded; eligibility always uses strict recognition.
        maximum = {'authentication_bypass': 20, 'weak_credentials': 7, 'weak_api_key': 32, 'authorization_bypass': 24}[rule]
        return SupportedAccessProbe(rule, value.get('probe_id'), value.get('probe_version'),
                                    PROTECTED_ACCESS_PATHS if rule == 'authorization_bypass' else (), 0, maximum, True)
    return probe


def validate_access_receipts(asset, receipts, *, strict=True):
    def invalid():
        raise ValueError('Invalid protected access observation evidence')
    if len(receipts) > MAX_ACCESS_CHECK_EVIDENCE:
        invalid()
    groups = {}
    findings, checks = asset.get('vulnerabilities', []), asset.get('checks', [])
    for receipt in receipts:
        rule = receipt.get('rule_id')
        probe = _probe(receipt, asset, strict)
        if (set(receipt) != receipt_fields(receipt) or rule not in ACCESS_CAPS
                or receipt['source'] != ACCESS_EVIDENCE_SOURCE or receipt['source_version'] != '1.0'
                or probe is None or not probe.requires_receipt):
            invalid()
        target = receipt['access_target']
        if (type(target) is not dict or set(target) != {'endpoint', 'provider', 'model', 'evidence_context_id'}
                or any(type(target.get(key)) is not str or not 1 <= len(target[key]) <= maximum
                       for key, maximum in (('endpoint', 16384), ('provider', 64)))
                or any(target.get(key) is not None and (type(target[key]) is not str or not 1 <= len(target[key]) <= maximum)
                       for key, maximum in (('model', 256), ('evidence_context_id', 128)))
                or target.get('evidence_context_id') != receipt['evidence_context_id']):
            invalid()
        expected = access_target(asset, protected_path_index=receipt.get('protected_path_index'), strict=strict)
        if target != expected:
            invalid()
        if rule == 'authorization_bypass':
            index = receipt['protected_path_index']
            if type(index) is not int or not 0 <= index < 8 or PROTECTED_ACCESS_PATHS[index] not in probe.protected_paths:
                invalid()
            sample = index
        else:
            sample = receipt['sample_index']
            if type(sample) is not int or not 0 <= sample < ACCESS_CAPS[rule]:
                invalid()
        if rule == 'weak_api_key' and (type(receipt['header_index']) is not int or not 0 <= receipt['header_index'] < 6):
            invalid()
        controls = receipt['control_proof']
        if (type(controls) is not dict or set(controls) != {'request_ordinals', 'status_codes'}
                or type(controls['request_ordinals']) is not list or len(controls['request_ordinals']) != 2
                or type(controls['status_codes']) is not list or len(controls['status_codes']) != 2
                or any(type(value) is not int for value in (*controls['request_ordinals'], *controls['status_codes']))
                or not 200 <= controls['status_codes'][0] < 300 or controls['status_codes'][1] not in (401, 403)):
            invalid()
        if any(type(receipt[key]) is not int or not 1 <= receipt[key] <= probe.max_requests
               for key in ('sequence', 'request_ordinal', 'requests_attempted', 'responses_evaluated')):
            invalid()
        ordinal = receipt['request_ordinal']
        if (receipt['requests_attempted'] != ordinal or not 3 <= receipt['responses_evaluated'] <= ordinal
                or controls['request_ordinals'][1] != controls['request_ordinals'][0] + 1
                or not 1 <= controls['request_ordinals'][0] < controls['request_ordinals'][1] < ordinal):
            invalid()
        if rule == 'authorization_bypass':
            if ordinal != controls['request_ordinals'][1] + 1:
                invalid()
        elif controls['request_ordinals'] != [1, 2]:
            invalid()
        if rule in {'authentication_bypass', 'weak_credentials'} and not 3 <= ordinal <= 3 + sample:
            invalid()
        if rule == 'weak_api_key' and not 3 + receipt['header_index'] <= ordinal <= 3 + 6 * sample + receipt['header_index']:
            invalid()
        matching = [value for value in findings if value.get('id') == receipt['finding_id']]
        if len(matching) != 1:
            invalid()
        finding = matching[0]
        if (finding.get('vulnerability_type') != rule or finding.get('evidence_status') != 'confirmed'
                or finding.get('agent_id') != receipt['agent_id'] or finding.get('check_evidence_id') != receipt['id']
                or type(finding.get('protected_control_version')) is not int or finding['protected_control_version'] != PROTECTED_CONTROL_VERSION
                or not _literal_redaction_matches(finding.get('control_status'), ACCESS_CONTROL_STATUS)
                or type(finding.get('status_code')) is not int or not 200 <= finding['status_code'] < 300
                or strict and finding.get('severity') != ('critical' if rule == 'weak_credentials' else 'high')
                or any(finding.get(key) != receipt[key] for key in (
                    'rule_id', 'probe_id', 'probe_version', 'evidence_context_id', 'access_target'))
                or any((key in finding) != (key in receipt) or key in receipt and (
                    type(finding.get(key)) is not int or finding[key] != receipt[key])
                    for key in ('sample_index', 'header_index', 'protected_path_index'))
                or rule == 'authorization_bypass' and not _protected_path_matches(finding, probe)):
            invalid()
        identity = tuple(receipt[key] for key in ('rule_id', 'probe_id', 'probe_version', 'evidence_context_id'))
        group = groups.setdefault(rule, [])
        if (len(group) >= ACCESS_CAPS[rule] or receipt['sequence'] != len(group) + 1
                or group and (any(receipt[key] <= group[-1][key] for key in (
                    'request_ordinal', 'responses_evaluated'))
                    or sample <= group[-1].get('protected_path_index', group[-1].get('sample_index'))
                    or identity != tuple(group[-1][key] for key in (
                        'rule_id', 'probe_id', 'probe_version', 'evidence_context_id')))):
            invalid()
        group.append(receipt)
    linked = {receipt['finding_id'] for receipt in receipts}
    if any(access_claim(value) and value.get('evidence_status') == 'confirmed' and value.get('id') not in linked for value in findings):
        invalid()
    for check in checks:
        if access_claim(check) and check.get('outcome') == 'passed':
            probe = _probe(check, asset, strict)
            if probe is None or not probe.requires_receipt:
                invalid()
        if not access_claim(check) or check.get('outcome') != 'confirmed':
            continue
        group = groups.get(check.get('rule_id'), [])
        if not group:
            invalid()
    for rule, group in groups.items():
        terminal = [check for check in checks if check.get('rule_id') == rule]
        if not terminal:
            continue
        check, last = terminal[0], group[-1]
        probe = _probe(check, asset, strict)
        if (len(terminal) != 1 or probe is None or not probe.requires_receipt
                or check.get('status') not in {'completed', 'failed'} or check.get('outcome') != 'confirmed'
                or any(check.get(key) != last[key] for key in ('rule_id', 'probe_id', 'probe_version', 'evidence_context_id'))
                or any(type(check.get(key)) is not int or not last[key] <= check[key] <= probe.max_requests
                       for key in ('requests_attempted', 'responses_evaluated'))
                or check['responses_evaluated'] > check['requests_attempted']
                or check['status'] == 'completed' and (
                    check['requests_attempted'] != check['responses_evaluated']
                    or probe.expected_pass_responses and check['requests_attempted'] != probe.expected_pass_responses
                    and rule != 'weak_api_key')):
            invalid()
    return asset
