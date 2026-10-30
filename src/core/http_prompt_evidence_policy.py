"""Exact public source-3 prompt receipts for the explicit HTTP objective."""

from src.core.http_application_policy import (
    HTTP_PROMPT_RULES, HTTP_SOURCE_VERSION, http_prompt_payloads, validate_http_agent,
)
from src.core.prompt_evidence_policy import EVIDENCE_SOURCE, _FIELDS, _uuid


HTTP_RECEIPT_FIELDS = _FIELDS | {'http_target_binding'}


def validate_http_prompt_evidence(asset):
    def invalid():
        raise ValueError('Invalid HTTP application prompt evidence')

    validate_http_agent(asset)
    if ('status' in asset and 'security_status' in asset
            and asset['status'] != asset['security_status']):
        invalid()
    if asset.get('check_evidence_schema_version') != '3.0':
        invalid()
    receipts, findings, checks = (asset.get('check_evidence'), asset.get('vulnerabilities', []),
                                 asset.get('checks', []))
    observations = asset.get('observations', [])
    if (type(receipts) is not list or len(receipts) > 35
            or type(findings) is not list or any(type(value) is not dict for value in findings)
            or type(checks) is not list or any(type(value) is not dict for value in checks)
            or type(observations) is not list or any(type(value) is not dict for value in observations)):
        invalid()
    run = asset.get('check_evidence_run_id')
    if ('check_evidence_run_id' in asset or receipts) and not _uuid(run):
        invalid()
    finding_ids = set()
    for finding in findings:
        if (type(finding.get('id')) is not str or not 1 <= len(finding['id']) <= 256
                or finding['id'] in finding_ids):
            invalid()
        finding_ids.add(finding['id'])
    seen, linked, groups = set(), set(), {}
    for receipt in receipts:
        if (type(receipt) is not dict or set(receipt) != HTTP_RECEIPT_FIELDS
                or any(not _uuid(receipt[name]) for name in ('id', 'finding_id', 'run_id'))
                or receipt['id'] in seen or receipt['finding_id'] in linked
                or receipt['run_id'] != run
                or receipt['agent_id'] != asset.get('agent_id', asset.get('id'))
                or receipt['source'] != EVIDENCE_SOURCE or receipt['source_version'] != HTTP_SOURCE_VERSION
                or receipt['http_target_binding'] != asset['http_target_binding']
                or receipt['evidence_context_id'] != asset['evidence_context_id']):
            invalid()
        seen.add(receipt['id'])
        linked.add(receipt['finding_id'])
        payloads = http_prompt_payloads(receipt['rule_id'], receipt['probe_id'], receipt['probe_version'], asset)
        if payloads is None:
            invalid()
        for name in ('sequence', 'request_ordinal', 'requests_attempted', 'responses_evaluated'):
            if type(receipt[name]) is not int or not 1 <= receipt[name] <= 5:
                invalid()
        index = receipt['sample_index']
        if (type(index) is not int or not 0 <= index < 5
                or receipt['request_ordinal'] != receipt['requests_attempted']
                or not receipt['responses_evaluated'] <= receipt['requests_attempted'] <= index + 1):
            invalid()
        matches = [finding for finding in findings if finding.get('id') == receipt['finding_id']]
        if len(matches) != 1:
            invalid()
        finding = matches[0]
        if (finding.get('check_evidence_id') != receipt['id']
                or finding.get('agent_id') != receipt['agent_id']
                or finding.get('evidence_status') != 'confirmed' or finding.get('severity') != 'high'
                or finding.get('vulnerability_type') != 'prompt_injection'
                or finding.get('category') != receipt['rule_id'].removeprefix('prompt_injection.')
                or finding.get('payload') != payloads[index]
                or type(finding.get('status_code')) is not int or not 200 <= finding['status_code'] < 300
                or any(finding.get(name) != receipt[name] for name in (
                    'rule_id', 'probe_id', 'probe_version', 'evidence_context_id', 'http_target_binding'))):
            invalid()
        identity = tuple(receipt[name] for name in ('rule_id', 'probe_id', 'probe_version', 'evidence_context_id'))
        previous = groups.setdefault(identity, [])
        if (receipt['sequence'] != len(previous) + 1 or previous and any(
                receipt[name] <= previous[-1][name] for name in (
                    'sample_index', 'request_ordinal', 'responses_evaluated'))):
            invalid()
        previous.append(receipt)
    for value in [*findings, *observations]:
        if value.get('rule_id') not in HTTP_PROMPT_RULES or value.get('vulnerability_type') != 'prompt_injection':
            invalid()
        if value.get('evidence_status') == 'confirmed' and value.get('id') not in linked:
            invalid()
        if 'check_evidence_id' in value and value.get('id') not in linked:
            invalid()
    if any('check_evidence_id' in value for value in observations):
        invalid()
    rules = set()
    for check in checks:
        rule = check.get('rule_id')
        if (rule not in HTTP_PROMPT_RULES or rule in rules
                or check.get('status') not in {'completed', 'failed', 'skipped'}
                or check.get('outcome') not in {'confirmed', 'heuristic', 'inconclusive', 'not_evaluated'}
                or check.get('reason') is not None and not isinstance(check['reason'], str)):
            invalid()
        rules.add(rule)
        if (any(type(check.get(name)) is not int or not 0 <= check[name] <= 5
                for name in ('requests_attempted', 'responses_evaluated'))
                or check['responses_evaluated'] > check['requests_attempted']):
            invalid()
        if (check['status'] == 'completed' and check['responses_evaluated'] < 1
                or check['outcome'] == 'confirmed' and check['responses_evaluated'] < 1
                or (check['status'] == 'skipped') != (check['outcome'] == 'not_evaluated')
                or check['status'] == 'skipped' and check['responses_evaluated']):
            invalid()
        if check['status'] == 'completed' and (
                check['requests_attempted'] != 5 or check['responses_evaluated'] != 5):
            invalid()
        if check.get('probe_version') == '1:unexecuted':
            if (check.get('status') != 'skipped' or check.get('outcome') != 'not_evaluated'
                    or check.get('requests_attempted') != 0 or check.get('responses_evaluated') != 0):
                invalid()
            continue
        if (http_prompt_payloads(rule, check.get('probe_id'), check.get('probe_version'), asset) is None
                or check.get('evidence_context_id') != asset['evidence_context_id']):
            invalid()
        identity = tuple(check.get(name) for name in ('rule_id', 'probe_id', 'probe_version', 'evidence_context_id'))
        group = groups.get(identity)
        if check.get('outcome') == 'confirmed' and not group:
            invalid()
        if group and (check.get('status') not in {'completed', 'failed'} or check.get('outcome') != 'confirmed'
                      or any(type(check.get(name)) is not int or not group[-1][name] <= check[name] <= 5
                             for name in ('requests_attempted', 'responses_evaluated'))):
            invalid()
    # Live mint candidates and acknowledged unfinished prefixes have no terminal
    # execution status. A public completed execution must finish its whole scope.
    if asset.get('security_status', asset.get('status')) == 'completed' and (
            rules != set(HTTP_PROMPT_RULES) or any(check['status'] != 'completed' for check in checks)):
        invalid()
    return asset
