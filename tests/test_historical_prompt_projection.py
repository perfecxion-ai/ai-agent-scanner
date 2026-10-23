"""Canonical risk rejects historical prompt claims while archives remain intact."""

from copy import deepcopy
import json

import pytest

from src.core.contracts import confirmed_findings
from src.core.pipeline import to_sarif
from src.core.risk_projection import project_report_risk
from src.reporting.workflows import compare_reports
from tests.controlled_access import result as controlled_result, target as controlled_target
from tests.test_api_auth import api as api, headers
from tests.test_api_risk_projection import outputs, seed
from tests.test_prompt_legacy_compatibility import legacy_prompt_report
from tests.test_prompt_request_reflection import (
    CANARY, echo_target as echo_target, fixture_agent,
    pacing_and_isolation as pacing_and_isolation, pipeline,
)


def seed_archived(module, document, *, scan_id='fixture', tenant='tenant-a'):
    """Store supplied archive fixtures with deliberately untrusted numeric columns."""
    assets = document['agents']
    seed(module, document, scan_id=scan_id, tenant=tenant, alias=assets[0]['id'], db_score=99)
    for index, asset in enumerate(assets):
        identifier = scan_id + '-snapshot' + (f'-{index}' if index else '')
        if index:
            snapshot = module.DiscoveredAgentModel(
                id=identifier, scan_id=scan_id, agent_name='Archive fixture',
                agent_type='assistant', discovery_method='fixture', risk_score=99,
                risk_level='critical', metadata_json={'asset_id': asset['id']})
            module.db.session.add(snapshot)
        else:
            snapshot = module.db.session.get(module.DiscoveredAgentModel, identifier)
        snapshot.vulnerabilities = deepcopy(asset['vulnerabilities'])
    module.db.session.commit()


def assert_unknown(item):
    assert item['risk_score'] is None
    assert item['risk_level'] == 'unknown'
    assert item['risk_coverage_status'] == 'not_assessed'
    assert item['risk_assessment_status'] == 'not_assessed'
    assert item['risk_scoring_policy'] is None


def assert_archive_unchanged(module, client, original, *, scan_id='fixture'):
    encoded = json.dumps(original, sort_keys=True)
    for fmt, expected in (('json', original), ('sarif', to_sarif(original))):
        exported = client.get(f'/api/scans/{scan_id}/report?format={fmt}', headers=headers(module))
        assert exported.status_code == 200 and exported.json == expected
        assert exported.headers['Cache-Control'] == 'no-store'
    stored = module.db.session.get(module.ScanResult, scan_id).result
    assert json.dumps(stored, sort_keys=True) == encoded
    assert module.db.session.get(module.ScanSession, scan_id).overall_risk_score == 99
    assert all(row.risk_score == 99 for row in
               module.DiscoveredAgentModel.query.filter_by(scan_id=scan_id).all())


async def access_asset(*, disclose, identifier='controlled-asset'):
    actual = await controlled_result(controlled_target(id=identifier, provider='ollama'), disclose=disclose)
    return {
        'id': identifier, 'name': 'Controlled resource', 'provider': actual['provider'],
        'model': actual['model'], 'endpoint': 'http://192.0.2.2/resource',
        'security_status': actual['status'], 'checks': actual['checks'],
        'vulnerabilities': actual['vulnerabilities'], 'risk_score': 70 if disclose else 0,
        'risk_level': 'high' if disclose else 'minimal', 'risk_scoring_policy': 'severity-floor-v2',
        'risk_coverage_status': 'sampled',
    }


@pytest.mark.asyncio
@pytest.mark.parametrize('disclose', [False, True])
@pytest.mark.parametrize('partial', [False, True])
@pytest.mark.parametrize('historical_shape', ['paired', 'check_only', 'finding_only'])
async def test_same_asset_historical_positive_cannot_be_salvaged_by_current_access_evidence(
        api, disclose, partial, historical_shape):
    module, client = api
    archived = legacy_prompt_report(partial=partial)
    asset = archived['agents'][0]
    if historical_shape == 'check_only':
        asset['vulnerabilities'] = []
    elif historical_shape == 'finding_only':
        asset['checks'] = []
    access = await access_asset(disclose=disclose, identifier=asset['id'])
    asset['checks'].extend(access['checks'])
    asset['vulnerabilities'].extend(access['vulnerabilities'])
    original = deepcopy(archived)
    seed_archived(module, archived)

    results, listed = outputs(module, client)
    assert results['summary']['overall_risk_score'] is None
    assert_unknown(results['agents'][0])
    assert_unknown(listed)
    assert confirmed_findings(asset) == access['vulnerabilities']
    assert results['agents'][0]['vulnerabilities'] == original['agents'][0]['vulnerabilities']
    assert results['pipeline'] == original
    assert client.get('/api/agents?risk_level=minimal', headers=headers(module)).json['agents'] == []
    assert client.get('/api/agents?risk_level=high', headers=headers(module)).json['agents'] == []
    assert_archive_unchanged(module, client, original)


@pytest.mark.asyncio
@pytest.mark.parametrize('historical_score,disclose', [(70, False), (70, True), (90, True)])
async def test_independent_asset_keeps_supported_score_and_filter_membership(
        api, historical_score, disclose):
    module, client = api
    archived = legacy_prompt_report()
    archived['agents'][0].update(risk_score=historical_score,
                                  risk_level='critical' if historical_score == 90 else 'high')
    archived['summary']['overall_risk_score'] = historical_score
    current = await access_asset(disclose=disclose)
    archived['agents'].append(current)
    original = deepcopy(archived)
    seed_archived(module, archived)
    seed_archived(module, archived, scan_id='other-tenant', tenant='tenant-b')

    for _ in range(2):
        # Expire the ORM session to repeat actual database-backed reads.
        module.db.session.remove()
        response = client.get('/api/scans/fixture/results', headers=headers(module))
        assert response.status_code == 200
        results = response.json['results']
        rows = {row['asset_id']: row for row in results['agents']}
        assert_unknown(rows['stable-asset'])
        assert rows['controlled-asset']['risk_score'] == current['risk_score']
        expected_summary = current['risk_score'] if current['risk_score'] == historical_score else None
        assert results['summary']['overall_risk_score'] == expected_summary
        assert results['pipeline'] == original
        listed = client.get('/api/agents', headers=headers(module)).json['agents']
        assert {row['id'] for row in listed} == {'fixture-snapshot', 'fixture-snapshot-1'}
        by_asset = {row['asset_id']: row for row in listed}
        assert_unknown(by_asset['stable-asset'])
        assert by_asset['controlled-asset']['risk_score'] == current['risk_score']
        filtered = client.get('/api/agents?risk_level=' + current['risk_level'], headers=headers(module))
        assert [row['id'] for row in filtered.json['agents']] == ['fixture-snapshot-1']
        assert client.get('/api/agents?risk_level=critical', headers=headers(module)).json['agents'] == []
        assert client.get('/api/scans/other-tenant/results', headers=headers(module)).status_code == 404
        assert_archive_unchanged(module, client, original)


@pytest.mark.asyncio
@pytest.mark.parametrize('suite', [None, 'protected-disclosure-v1'])
@pytest.mark.parametrize('partial', [False, True])
async def test_actual_prompt_receipts_remain_current_next_to_separate_historical_scan(
        api, echo_target, monkeypatch, suite, partial):
    module, client = api
    endpoint, state = echo_target
    checkpoints = []
    completed = await pipeline(fixture_agent(endpoint, 'leak', monkeypatch), suite, checkpoints)
    current = next(report for report in checkpoints if report['summary']['overall_risk_score'] == 70) if partial else completed
    assert state['calls'] and current['agents'][0]['check_evidence']
    assert all(receipt['source_version'] == '2.0' for receipt in current['agents'][0]['check_evidence'])
    assert current['agents'][0]['risk_coverage_status'] == ('partial' if partial else 'sampled')
    # Compare the actual serializable report, not Python-only tuple values.
    current = json.loads(json.dumps(current))
    original = deepcopy(current)
    seed_archived(module, legacy_prompt_report(), scan_id='historical')
    seed_archived(module, current)

    results, listed = outputs(module, client)
    assert results['summary']['overall_risk_score'] == 70
    assert results['pipeline'] == original
    for item in (results['agents'][0], listed):
        assert item['risk_score'] == 70
        assert item['risk_level'] == 'high'
        assert item['risk_coverage_status'] == ('partial' if partial else 'sampled')
    assert [row['id'] for row in client.get(
        '/api/agents?risk_level=high', headers=headers(module)).json['agents']] == ['fixture-snapshot']
    assert [row['id'] for row in client.get(
        '/api/agents?risk_level=unknown', headers=headers(module)).json['agents']] == ['historical-snapshot']
    assert_archive_unchanged(module, client, original)
    assert CANARY not in json.dumps([results, listed, original])


@pytest.mark.asyncio
@pytest.mark.parametrize('mutation', ['missing', 'empty', 'draft', 'malformed', 'finding_reference'])
async def test_invalidated_actual_receipts_never_fall_back_to_finalized_prompt_checks(
        api, echo_target, monkeypatch, mutation):
    module, client = api
    endpoint, _ = echo_target
    archived = json.loads(json.dumps(await pipeline(fixture_agent(endpoint, 'leak', monkeypatch), None)))
    assert archived['summary']['overall_risk_score'] == 70
    for asset in (archived['agents'][0], archived['security_results'][0]):
        if mutation == 'missing':
            for key in ('check_evidence_schema_version', 'check_evidence_run_id', 'check_evidence'):
                asset.pop(key, None)
            for finding in asset['vulnerabilities']:
                finding.pop('check_evidence_id', None)
        elif mutation == 'empty':
            asset['check_evidence'] = []
        elif mutation == 'draft':
            for receipt in asset['check_evidence']:
                receipt['source_version'] = '1.0'
        elif mutation == 'malformed':
            asset['check_evidence'][0]['sequence'] = True
        else:
            asset['vulnerabilities'][0]['check_evidence_id'] = 'unsupported-reference'
    if mutation == 'missing':
        archived.pop('check_evidence_schema_version')
    original = deepcopy(archived)
    seed_archived(module, archived)

    results, listed = outputs(module, client)
    assert results['summary']['overall_risk_score'] is None
    assert_unknown(results['agents'][0])
    assert_unknown(listed)
    assert results['pipeline'] == original
    assert results['agents'][0]['vulnerabilities'] == original['agents'][0]['vulnerabilities']
    assert_archive_unchanged(module, client, original)


@pytest.mark.parametrize('quiet_outcome', ['inconclusive', 'passed'])
def test_historical_prompt_disclosure_never_resolves_from_quiet_or_obsolete_pass(quiet_outcome):
    archived = legacy_prompt_report()
    original = deepcopy(archived)
    quiet = deepcopy(archived)
    quiet['agents'][0]['vulnerabilities'] = []
    quiet['agents'][0]['checks'][0]['outcome'] = quiet_outcome
    quiet['agents'][0]['risk_score'] = quiet['summary']['overall_risk_score'] = None
    quiet['agents'][0]['risk_level'] = 'unknown'
    quiet['risk_assessment_status'] = 'not_assessed'
    result = compare_reports(archived, quiet)
    assert result['resolved'] == []
    assert len(result['resolution_unverified']) == 1
    assert result['resolution_unverified'][0]['occurrences'] == archived['agents'][0]['vulnerabilities']
    assert archived == original
    assert project_report_risk(archived)[1]['stable-asset']['risk_score'] is None
