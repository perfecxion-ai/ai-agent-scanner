"""Unsupported tenant claims remain archived without becoming current scores."""

from copy import deepcopy
import hashlib
import json

import pytest

from src.core.contracts import CheckRecord, confirmed_findings
from src.reporting.workflows import compare_reports
from src.security.data_privacy_tests import DataPrivacyTester
from tests.test_api_auth import api as api, headers
from tests.test_api_risk_projection import outputs
from tests.test_historical_prompt_projection import (
    access_asset, assert_archive_unchanged, assert_unknown, seed_archived,
)
from tests.test_prompt_legacy_compatibility import legacy_prompt_report


def legacy_tenant_report(*, partial=False):
    """Retain the actual pre-control definition and finalized-check shape."""
    prompts = DataPrivacyTester().tenant_isolation_prompts[:5]
    definition = {'semantics': 'nondisclosure-inconclusive-v2', 'prompts': prompts}
    version = '1:' + hashlib.sha256(json.dumps(
        [definition, 'ollama', 'fixture-model'], sort_keys=True).encode()).hexdigest()
    rule = 'tenant_isolation_violation'
    check = CheckRecord(rule, rule + '.sample', version, 'completed', 'confirmed', 5, 5,
                        evidence_context_id='historical-fixture-v1').to_dict()
    finding = {key: check[key] for key in ('rule_id', 'probe_id', 'probe_version', 'evidence_context_id')}
    finding.update(id='historical-tenant-finding', agent_id='stable-asset',
                   vulnerability_type=rule, severity='critical', evidence_status='confirmed',
                   prompt=prompts[0], response_excerpt='[GENERATED_TEXT_OMITTED]')
    report = legacy_prompt_report(partial=partial)
    report['summary']['overall_risk_score'] = 90
    report['agents'][0].update(checks=[check], vulnerabilities=[finding],
                               risk_score=90, risk_level='critical')
    return report


@pytest.mark.asyncio
@pytest.mark.parametrize('partial', [False, True])
@pytest.mark.parametrize('companion', ['none', 'passed', 'confirmed'])
async def test_historical_tenant_claim_cannot_inherit_companion_score(api, partial, companion):
    module, client = api
    archived = legacy_tenant_report(partial=partial)
    asset = archived['agents'][0]
    supported = []
    if companion != 'none':
        access = await access_asset(disclose=companion == 'confirmed', identifier=asset['id'])
        asset['checks'].extend(access['checks'])
        asset['vulnerabilities'].extend(access['vulnerabilities'])
        supported = access['vulnerabilities']
    original = deepcopy(archived)
    seed_archived(module, archived)
    results, listed = outputs(module, client)
    assert results['summary']['overall_risk_score'] is None
    assert_unknown(results['agents'][0])
    assert_unknown(listed)
    assert confirmed_findings(asset) == supported
    assert results['pipeline'] == original
    for level in ('minimal', 'high', 'critical'):
        assert client.get('/api/agents?risk_level=' + level, headers=headers(module)).json['agents'] == []
    assert_archive_unchanged(module, client, original)


@pytest.mark.asyncio
@pytest.mark.parametrize('disclose', [False, True])
async def test_independent_supported_asset_remains_in_risk_filters(api, disclose):
    module, client = api
    archived = legacy_tenant_report()
    current = await access_asset(disclose=disclose)
    archived['agents'].append(current)
    seed_archived(module, archived)
    for _ in range(2):
        module.db.session.remove()
        results = client.get('/api/scans/fixture/results', headers=headers(module)).json['results']
        assets = {asset['asset_id']: asset for asset in results['agents']}
        assert_unknown(assets['stable-asset'])
        assert assets['controlled-asset']['risk_score'] == current['risk_score']
        assert results['summary']['overall_risk_score'] is None
        rows = client.get('/api/agents?risk_level=' + current['risk_level'], headers=headers(module)).json['agents']
        assert [row['asset_id'] for row in rows] == ['controlled-asset']
        assert_archive_unchanged(module, client, archived)


@pytest.mark.parametrize('outcome', ['passed', 'inconclusive'])
def test_old_tenant_claim_never_resolves_from_a_quiet_sample(outcome):
    archived = legacy_tenant_report()
    quiet = deepcopy(archived)
    quiet['agents'][0]['vulnerabilities'] = []
    quiet['agents'][0]['checks'][0]['outcome'] = outcome
    comparison = compare_reports(archived, quiet)
    assert comparison['resolved'] == []
    assert len(comparison['resolution_unverified']) == 1
    assert comparison['resolution_unverified'][0]['occurrences'] == archived['agents'][0]['vulnerabilities']
