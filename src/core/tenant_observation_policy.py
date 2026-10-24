"""Pure public validation for controlled tenant response observations."""

from src.core.tenant_probe_policy import (
    TENANT_CONTROL_STATUS, TENANT_CONTROL_VERSION, TENANT_MAX_REQUESTS, TENANT_RULE,
    tenant_claim, tenant_probe_version as tenant_probe_version, tenant_target,
)


TENANT_EVIDENCE_SOURCE = 'controlled_tenant_response'
TENANT_EVIDENCE_SOURCE_VERSION = '1.0'
MAX_TENANT_CHECK_EVIDENCE = 6
COMMON_RECEIPT_FIELDS = frozenset({
    'id', 'run_id', 'agent_id', 'rule_id', 'probe_id', 'probe_version', 'evidence_context_id',
    'finding_id', 'sequence', 'request_ordinal', 'requests_attempted', 'responses_evaluated',
    'source', 'source_version',
})
TENANT_RECEIPT_FIELDS = COMMON_RECEIPT_FIELDS | {
    'tenant_target', 'tenant_observation_source', 'control_proof',
}


def _text(value, maximum):
    return (type(value) is str and 1 <= len(value) <= maximum and value == value.strip()
            and '[redact' not in value.casefold() and all(ord(mark) >= 32 and ord(mark) != 127 for mark in value))


def _bounded_target(value):
    return (type(value) is dict and set(value) == {'endpoint', 'provider', 'model', 'evidence_context_id'}
            and all(type(value[key]) is str and 1 <= len(value[key]) <= maximum for key, maximum in (
                ('endpoint', 4096), ('provider', 64), ('model', 256), ('evidence_context_id', 128))))


def validate_tenant_receipts(asset, receipts, *, strict=True):
    """No positive or absence claim is inferred from an unfinished check."""
    def invalid():
        raise ValueError('Invalid tenant observation evidence')
    if len(receipts) > MAX_TENANT_CHECK_EVIDENCE:
        invalid()
    findings, checks = asset.get('vulnerabilities', []), asset.get('checks', [])
    group, binding, proof = [], None, None
    expected = None
    if strict and receipts:
        try:
            expected = tenant_target(*(asset.get(key) for key in ('endpoint', 'provider', 'model', 'evidence_context_id')))
        except ValueError:
            invalid()
    for receipt in receipts:
        source = receipt.get('tenant_observation_source')
        fields = TENANT_RECEIPT_FIELDS | ({'tenant_attack_index'} if source == 'attack' else set())
        if (set(receipt) != fields or receipt['source'] != TENANT_EVIDENCE_SOURCE
                or receipt['source_version'] != TENANT_EVIDENCE_SOURCE_VERSION
                or receipt['rule_id'] != TENANT_RULE or receipt['probe_id'] != TENANT_RULE + '.sample'
                or not _bounded_target(receipt['tenant_target'])
                or receipt['evidence_context_id'] != receipt['tenant_target']['evidence_context_id']):
            invalid()
        if strict and (receipt['tenant_target'] != expected
                       or receipt['probe_version'] != tenant_probe_version(asset['provider'], asset['model'])
                       or not _text(receipt['evidence_context_id'], 128)):
            invalid()
        controls = receipt['control_proof']
        if (type(controls) is not dict or set(controls) != {'request_ordinals', 'status_codes'}
                or type(controls['request_ordinals']) is not list or len(controls['request_ordinals']) != 3
                or any(type(value) is not int for value in controls['request_ordinals'])
                or controls['request_ordinals'] != [1, 2, 3]
                or type(controls['status_codes']) is not list or len(controls['status_codes']) != 3
                or any(type(value) is not int for value in controls['status_codes'])
                or not all(200 <= value < 300 for value in controls['status_codes'][:2])
                or controls['status_codes'][2] not in (401, 403)):
            invalid()
        if any(type(receipt[key]) is not int or not 1 <= receipt[key] <= TENANT_MAX_REQUESTS
               for key in ('sequence', 'request_ordinal', 'requests_attempted', 'responses_evaluated')):
            invalid()
        if receipt['sequence'] > MAX_TENANT_CHECK_EVIDENCE or receipt['responses_evaluated'] > receipt['requests_attempted']:
            invalid()
        if source == 'subject_control':
            if (receipt['request_ordinal'], receipt['requests_attempted'], receipt['responses_evaluated']) != (2, 3, 3):
                invalid()
        elif source == 'attack':
            index = receipt['tenant_attack_index']
            if (type(index) is not int or not 0 <= index < 5 or receipt['request_ordinal'] != 4 + index
                    or receipt['requests_attempted'] != receipt['request_ordinal'] or receipt['responses_evaluated'] < 4):
                invalid()
        else:
            invalid()
        matches = [finding for finding in findings if finding.get('id') == receipt['finding_id']]
        if len(matches) != 1:
            invalid()
        finding = matches[0]
        if (finding.get('check_evidence_id') != receipt['id']
                or finding.get('vulnerability_type') != TENANT_RULE or finding.get('evidence_status') != 'confirmed'
                or finding.get('agent_id') != receipt['agent_id']
                or type(finding.get('tenant_control_version')) is not int
                or finding['tenant_control_version'] != TENANT_CONTROL_VERSION
                or finding.get('control_status') != TENANT_CONTROL_STATUS
                or finding.get('tenant_target') != receipt['tenant_target']
                or finding.get('tenant_observation_source') != source
                or ('tenant_attack_index' in finding) != ('tenant_attack_index' in receipt)
                or finding.get('tenant_attack_index') != receipt.get('tenant_attack_index')
                or type(finding.get('status_code')) is not int or not 200 <= finding['status_code'] < 300
                or source == 'subject_control' and finding['status_code'] != controls['status_codes'][1]
                or strict and finding.get('severity') != 'critical'
                or any(finding.get(key) != receipt[key] for key in (
                    'rule_id', 'probe_id', 'probe_version', 'evidence_context_id'))):
            invalid()
        identity = tuple(receipt[key] for key in ('rule_id', 'probe_id', 'probe_version', 'evidence_context_id'))
        if binding is not None and (identity != binding or controls != proof or receipt['tenant_target'] != group[0]['tenant_target']):
            invalid()
        binding, proof = identity, controls
        if receipt['sequence'] != len(group) + 1 or group and any(
                receipt[key] <= group[-1][key] for key in ('request_ordinal', 'requests_attempted', 'responses_evaluated')):
            invalid()
        group.append(receipt)
    linked = {receipt['finding_id'] for receipt in receipts}
    if any(tenant_claim(finding) and finding.get('evidence_status') == 'confirmed'
           and finding.get('id') not in linked for finding in findings):
        invalid()
    terminal = [check for check in checks if tenant_claim(check)]
    if any(check.get('outcome') == 'passed' or check.get('outcome') == 'confirmed' and not group for check in terminal):
        invalid()
    if group and terminal:
        check = terminal[0]
        if (len(terminal) != 1 or tuple(check.get(key) for key in (
                'rule_id', 'probe_id', 'probe_version', 'evidence_context_id')) != binding
                or check.get('status') not in {'completed', 'failed'} or check.get('outcome') != 'confirmed'
                or any(type(check.get(key)) is not int or not group[-1][key] <= check[key] <= TENANT_MAX_REQUESTS
                       for key in ('requests_attempted', 'responses_evaluated'))
                or check['responses_evaluated'] > check['requests_attempted']
                or check['status'] == 'completed' and (check['requests_attempted'], check['responses_evaluated']) != (8, 8)
                or strict and check['status'] == 'failed' and not _text(check.get('reason'), 1024)):
            invalid()
    return asset
