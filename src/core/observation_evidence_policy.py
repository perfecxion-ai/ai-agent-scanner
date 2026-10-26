"""Versioned complete-ledger dispatch, with frozen legacy prompt semantics."""

from src.core.prompt_evidence_policy import (
    EVIDENCE_SOURCE, _FIELDS as PROMPT_RECEIPT_FIELDS, _uuid, has_evidence_contract,
    validate_prompt_evidence,
)
from src.core.tenant_observation_policy import (
    MAX_TENANT_CHECK_EVIDENCE, TENANT_EVIDENCE_SOURCE, TENANT_RECEIPT_FIELDS, validate_tenant_receipts,
)
from src.core.tenant_probe_policy import tenant_claim
from src.core.access_observation_policy import ACCESS_EVIDENCE_SOURCE, MAX_ACCESS_CHECK_EVIDENCE, access_claim, receipt_fields, validate_access_receipts


CHECK_EVIDENCE_SCHEMA_VERSION = '3.0'
SUPPORTED_CHECK_EVIDENCE_SCHEMA_VERSIONS = frozenset({'1.0', '2.0', '3.0'})
MAX_PROMPT_CHECK_EVIDENCE = 35
MAX_CHECK_EVIDENCE = MAX_PROMPT_CHECK_EVIDENCE + MAX_TENANT_CHECK_EVIDENCE + MAX_ACCESS_CHECK_EVIDENCE


def is_supported_evidence_version(value):
    return type(value) is str and value in SUPPORTED_CHECK_EVIDENCE_SCHEMA_VERSIONS


def is_mixed_evidence_version(value):
    return type(value) is str and value in {'2.0', '3.0'}


def checkpoint_evidence_version(value):
    return {'2.0': '1.0', '3.0': '2.0', '4.0': '3.0'}.get(value) if type(value) is str else None


def validate_observation_evidence(asset, *, strict=True):
    """Validate every source and link before any source-specific projection."""
    try:
        if not has_evidence_contract(asset):
            return asset
        version = asset.get('check_evidence_schema_version')
        if version == '1.0':
            return validate_prompt_evidence(asset, strict=strict)
        if not is_mixed_evidence_version(version):
            raise ValueError('Unsupported observation evidence schema')
        return _validate_mixed(asset, strict=strict, modern=version == '3.0')
    except (TypeError, ValueError, KeyError, AttributeError, OverflowError, RecursionError):
        raise ValueError('Invalid observation evidence') from None


def _validate_mixed(asset, *, strict, modern=False):
    def invalid():
        raise ValueError('Invalid observation evidence')
    receipts, findings, checks = asset.get('check_evidence'), asset.get('vulnerabilities', []), asset.get('checks', [])
    if (type(receipts) is not list or len(receipts) > (MAX_CHECK_EVIDENCE if modern else 41)
            or type(findings) is not list or any(type(finding) is not dict for finding in findings)
            or type(checks) is not list or any(type(check) is not dict for check in checks)):
        invalid()
    identifier = _uuid if strict else lambda value: type(value) is str and 1 <= len(value) <= 128
    run_id = asset.get('check_evidence_run_id')
    if ('check_evidence_run_id' in asset and not identifier(run_id)) or receipts and not identifier(run_id):
        invalid()
    finding_ids = set()
    for finding in findings:
        if 'id' in finding:
            if type(finding['id']) is not str or not 1 <= len(finding['id']) <= 256 or finding['id'] in finding_ids:
                invalid()
            finding_ids.add(finding['id'])
    seen, linked, kinds = set(), set(), {EVIDENCE_SOURCE: [], TENANT_EVIDENCE_SOURCE: []}
    if modern:
        kinds[ACCESS_EVIDENCE_SOURCE] = []
    for receipt in receipts:
        if type(receipt) is not dict or type(receipt.get('source')) is not str or receipt['source'] not in kinds:
            invalid()
        source = receipt['source']
        fields = (receipt_fields(receipt) if source == ACCESS_EVIDENCE_SOURCE else PROMPT_RECEIPT_FIELDS
                  if source == EVIDENCE_SOURCE else TENANT_RECEIPT_FIELDS | (
                      {'tenant_attack_index'} if receipt.get('tenant_observation_source') == 'attack' else set()))
        if (set(receipt) != fields or not identifier(receipt['id']) or receipt['id'] in seen
                or not identifier(receipt['finding_id']) or receipt['finding_id'] in linked
                or receipt['run_id'] != run_id
                or receipt['agent_id'] != asset.get('agent_id', asset.get('id'))
                or type(receipt['agent_id']) is not str or not 1 <= len(receipt['agent_id']) <= 256
                or any(type(receipt[key]) is not str or not 1 <= len(receipt[key]) <= maximum
                       for key, maximum in (('rule_id', 128), ('probe_id', 160), ('probe_version', 128)))
                or any(type(receipt[key]) is not int for key in (
                    'sequence', 'request_ordinal', 'requests_attempted', 'responses_evaluated'))):
            invalid()
        # Draft prompt source 1.0 belongs only to the frozen legacy reader.
        # A mixed-format writer must not acknowledge it and erase prior risk.
        allowed = ('2.0',) if source == EVIDENCE_SOURCE else ('1.0',)
        if type(receipt['source_version']) is not str or receipt['source_version'] not in allowed:
            invalid()
        seen.add(receipt['id'])
        linked.add(receipt['finding_id'])
        matches = [finding for finding in findings if finding.get('id') == receipt['finding_id']]
        if (len(matches) != 1 or matches[0].get('check_evidence_id') != receipt['id']
                or (tenant_claim(matches[0]) if source == EVIDENCE_SOURCE else
                    not access_claim(matches[0]) if source == ACCESS_EVIDENCE_SOURCE else not tenant_claim(matches[0]))
                or modern and source == EVIDENCE_SOURCE and access_claim(matches[0])):
            invalid()
        kinds[source].append(receipt)
    if any('check_evidence_id' in finding and (finding.get('id') not in linked
                                             or finding['check_evidence_id'] not in seen) for finding in findings):
        invalid()
    observations = asset.get('observations', [])
    if type(observations) is not list or any(type(value) is not dict or 'check_evidence_id' in value for value in observations):
        invalid()
    if len(kinds[EVIDENCE_SOURCE]) > MAX_PROMPT_CHECK_EVIDENCE:
        invalid()
    # The frozen validator receives only globally checked prompt links. Never
    # partition unknown or malformed receipts away before validating the ledger.
    prompt = dict(asset, check_evidence_schema_version='1.0', check_evidence=kinds[EVIDENCE_SOURCE],
                  vulnerabilities=[finding for finding in findings if not tenant_claim(finding) and not (modern and access_claim(finding))],
                  checks=[check for check in checks if not tenant_claim(check) and not (modern and access_claim(check))])
    validate_prompt_evidence(prompt, strict=strict)
    validate_tenant_receipts(asset, kinds[TENANT_EVIDENCE_SOURCE], strict=strict)
    if modern:
        validate_access_receipts(asset, kinds[ACCESS_EVIDENCE_SOURCE], strict=strict)
    return asset
