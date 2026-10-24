"""API risk fields must not expose database compatibility placeholders as verdicts."""

from tests.claimed_execution import execute_scan

from copy import deepcopy
from datetime import datetime, timedelta

import pytest

from src.core.contracts import CheckRecord
from src.risk.risk_assessor import RiskAssessment
from tests.test_api_auth import api as api, headers
from tests.test_pipeline import add_scan, asset, engines
from tests.controlled_access import result as controlled_result


def report(score=None, *, partial=False):
    assessed = score is not None
    rule = 'fixture.disclosure' if score else 'authorization_bypass'
    check = CheckRecord(rule, 'fixture.probe', '1', 'completed',
                        'confirmed' if score else 'passed', 1, 1).to_dict()
    findings = [{'rule_id': rule, 'probe_id': 'fixture.probe', 'probe_version': '1',
                 'severity': 'high', 'evidence_status': 'confirmed'}] if score else []
    agent = {'id': 'stable-asset', 'name': 'Fixture', 'security_status': 'partial' if partial else 'completed',
             'checks': [check] if assessed else [], 'vulnerabilities': findings,
             'risk_score': score, 'risk_level': 'high' if score else 'minimal' if assessed else 'unknown',
             'risk_scoring_policy': 'severity-floor-v2' if assessed else None,
             'risk_coverage_status': 'partial' if partial else 'sampled' if assessed else 'not_assessed'}
    return {'schema_version': '1.0', 'check_schema_version': '1.0',
            'status': 'partial' if partial else 'completed',
            'risk_assessment_status': 'partial' if partial else 'completed' if assessed else 'not_assessed',
            'agents': [agent], 'summary': {'overall_risk_score': score}}


def seed(module, value, *, scan_id='fixture', tenant='tenant-a', alias='stable-asset', db_score=0):
    module.db.session.add(module.ScanSession(
        id=scan_id, organization_id=tenant, scan_name='Fixture', scan_type='full',
        status='completed', target_scope={}, scan_config={}, overall_risk_score=db_score))
    module.db.session.add(module.DiscoveredAgentModel(
        id=scan_id + '-snapshot', scan_id=scan_id, agent_name='Fixture', agent_type='assistant',
        discovery_method='fixture', risk_score=db_score, risk_level='critical',
        metadata_json={'asset_id': alias, 'security_status': 'failed'} if alias else {}))
    if value is not None:
        module.db.session.add(module.ScanResult(scan_id=scan_id, result=value))
    module.db.session.commit()


def outputs(module, client, scan_id='fixture'):
    response = client.get(f'/api/scans/{scan_id}/results', headers=headers(module))
    assert response.status_code == 200, response.json
    listed = client.get('/api/agents', headers=headers(module))
    assert listed.status_code == 200, listed.json
    return response.json['results'], next(item for item in listed.json['agents'] if item['id'] == scan_id + '-snapshot')


@pytest.mark.parametrize('kind', ['unassessed', 'missing_report', 'legacy', 'unversioned_policy'])
def test_unknown_and_historical_scores_are_not_current_verdicts(api, kind):
    module, client = api
    value = report()
    if kind == 'missing_report':
        value = None
    elif kind in {'legacy', 'unversioned_policy'}:
        value = report(6.58)
        if kind == 'legacy':
            value.pop('check_schema_version')
        else:
            value['agents'][0].pop('risk_scoring_policy')
    original = deepcopy(value)
    seed(module, value, db_score=0 if kind == 'unassessed' else 99)
    results, listed = outputs(module, client)
    assert results['summary']['overall_risk_score'] is None
    assert results['summary']['risk_assessment_status'] == 'not_assessed'
    for item in (results['agents'][0], listed):
        assert item['risk_score'] is None
        assert item['risk_level'] == 'unknown'
        assert item['risk_coverage_status'] == 'not_assessed'
        assert item['risk_scoring_policy'] is None
    assert results['pipeline'] == original
    assert module.db.session.get(module.ScanSession, 'fixture').overall_risk_score == (0 if kind == 'unassessed' else 99)


@pytest.mark.parametrize('score,partial', [(70, True), (0, False)])
@pytest.mark.parametrize('alias', ['stable-asset', None])
@pytest.mark.asyncio
async def test_current_evidence_preserves_high_partial_and_true_zero(api, score, partial, alias):
    module, client = api
    value = report(score, partial=partial)
    if score == 0:
        actual = await controlled_result()
        value['agents'][0].update({key: actual[key] for key in ('provider', 'model', 'checks')})
    if alias is None:
        value['agents'][0]['id'] = 'fixture-snapshot'
    seed(module, value, alias=alias, db_score=99)
    results, listed = outputs(module, client)
    assert results['summary']['overall_risk_score'] == score
    assert results['summary']['risk_assessment_status'] == ('partial' if partial else 'completed')
    for item in (results['agents'][0], listed):
        assert item['risk_score'] == score
        assert item['risk_level'] == ('high' if score else 'minimal')
        assert item['risk_scoring_policy'] == 'severity-floor-v2'
        assert item['risk_coverage_status'] == ('partial' if partial else 'sampled')
        assert item['risk_assessment_status'] == ('partial' if partial else 'completed')
        assert item['security_status'] == ('partial' if partial else 'completed')


@pytest.mark.parametrize('mutation', ['no_checks', 'inconclusive', 'missing_finding', 'wrong_asset',
                                     'duplicate_asset', 'failed_assessment', 'invalid_score',
                                     'missing_coverage', 'malformed_agents', 'invalid_alias',
                                     'inconsistent_coverage'])
def test_current_policy_without_matching_evidence_is_unassessed(api, mutation):
    module, client = api
    value = report(70, partial=True)
    agent = value['agents'][0]
    if mutation == 'no_checks':
        agent['checks'] = []
    elif mutation == 'inconclusive':
        agent['checks'][0]['outcome'] = 'inconclusive'
    elif mutation == 'missing_finding':
        agent['vulnerabilities'] = []
    elif mutation == 'wrong_asset':
        agent['id'] = 'other-asset'
    elif mutation == 'duplicate_asset':
        value['agents'].append(deepcopy(agent))
    elif mutation == 'failed_assessment':
        value['risk_assessment_status'] = 'failed'
    elif mutation == 'missing_coverage':
        agent.pop('risk_coverage_status')
    elif mutation == 'malformed_agents':
        value['agents'] = None
    elif mutation == 'invalid_alias':
        pass
    elif mutation == 'inconsistent_coverage':
        agent['risk_coverage_status'] = 'sampled'
    else:
        agent['risk_score'] = True
    seed(module, value)
    if mutation == 'invalid_alias':
        snapshot = module.db.session.get(module.DiscoveredAgentModel, 'fixture-snapshot')
        snapshot.metadata_json = {'asset_id': ['stable-asset']}
        module.db.session.commit()
    results, listed = outputs(module, client)
    assert results['agents'][0]['risk_score'] is None
    assert listed['risk_score'] is None


def test_projected_filters_and_tenant_ownership(api):
    module, client = api
    seed(module, report(70, partial=True), db_score=0)
    seed(module, report(0), scan_id='other-tenant', tenant='tenant-b', db_score=99)
    response = client.get('/api/agents?risk_level=high', headers=headers(module))
    assert [item['id'] for item in response.json['agents']] == ['fixture-snapshot']
    assert client.get('/api/agents?risk_level=critical', headers=headers(module)).json['agents'] == []
    assert client.get('/api/scans/other-tenant/results', headers=headers(module)).status_code == 404
    assert client.get('/api/scans/other-tenant/report', headers=headers(module)).status_code == 404


@pytest.mark.parametrize('field', ['risk_assessment_status', 'security_status', 'risk_level',
                                  'risk_coverage_status', 'risk_scoring_policy'])
@pytest.mark.parametrize('malformed', [[], {}])
def test_malformed_persisted_enums_fail_closed_without_api_error(api, field, malformed):
    module, client = api
    value = report(70, partial=True)
    target = value if field == 'risk_assessment_status' else value['agents'][0]
    target[field] = malformed
    seed(module, value)
    results, listed = outputs(module, client)
    assert results['summary']['overall_risk_score'] is None
    for item in (results['agents'][0], listed):
        assert item['risk_score'] is None
        assert item['risk_level'] == 'unknown'


@pytest.mark.parametrize('score,level', [(10 ** 1000, 'critical'), (-1, 'minimal'),
                                       (70, 'minimal'), (0, 'minimal')])
def test_malformed_or_inconsistent_scores_are_not_promoted(api, score, level):
    module, client = api
    value = report(70, partial=True)
    value['agents'][0].update(risk_score=score, risk_level=level)
    value['summary']['overall_risk_score'] = score
    seed(module, value)
    results, listed = outputs(module, client)
    assert results['summary']['overall_risk_score'] is None
    assert results['agents'][0]['risk_score'] is None
    assert listed['risk_score'] is None


def test_filtered_inventory_finds_canonical_risk_beyond_newest_100(api):
    module, client = api
    seed(module, report(70, partial=True))
    oldest = datetime(2020, 1, 1)
    module.db.session.get(module.DiscoveredAgentModel, 'fixture-snapshot').discovered_at = oldest
    for index in range(100):
        module.db.session.add(module.DiscoveredAgentModel(
            id=f'newer-{index:03}', scan_id='fixture', agent_name='Newer fixture',
            agent_type='assistant', discovery_method='fixture', risk_level='high',
            metadata_json={'asset_id': f'unassessed-{index}'},
            discovered_at=oldest + timedelta(seconds=index + 1)))
    module.db.session.commit()
    response = client.get('/api/agents?risk_level=high', headers=headers(module))
    assert response.status_code == 200
    assert [item['id'] for item in response.json['agents']] == ['fixture-snapshot']
    assert response.json['agents'][0]['risk_score'] == 70
    assert response.json['agents'][0]['risk_level'] == 'high'
    assert response.json['next_cursor'] is None
    coverage = response.json['coverage']
    assert coverage['search_complete'] is True
    assert coverage['evaluated_candidates'] == 101
    assert coverage['window_limit'] == 100
    assert coverage['window_truncated'] is False
    assert coverage['risk_level_filter_scope'] == 'tenant_type_assets_cursor_pages'
    assert coverage['warning'] is None
    complete = client.get('/api/agents?agent_type=other', headers=headers(module)).json
    assert complete['coverage']['window_truncated'] is False
    assert complete['coverage']['warning'] is None
    assert complete['coverage']['search_complete'] is True


@pytest.mark.asyncio
@pytest.mark.parametrize('mode', ['discovery_only', 'full'])
async def test_actual_pipeline_and_api_preserve_null_in_storage(api, monkeypatch, mode):
    module, client = api
    discovery, security, _ = engines([asset()])
    monkeypatch.setattr(module, 'discovery_engine', discovery)
    monkeypatch.setattr(module, 'security_engine', security)
    monkeypatch.setattr(module, 'risk_assessor', RiskAssessment())
    add_scan(module, 'fixture', mode=mode)
    await execute_scan(module, 'fixture', mode, {}, {})
    module.db.session.expire_all()
    response = client.get('/api/scans/fixture/results', headers=headers(module))
    assert response.status_code == 200, response.json
    results = response.json['results']
    expected = 90 if mode == 'full' else None
    assert results['summary']['overall_risk_score'] == expected
    assert results['agents'][0]['risk_score'] == expected
    assert results['pipeline']['summary']['overall_risk_score'] == expected
    assert results['pipeline']['agents'][0]['risk_score'] == expected
    listed = client.get('/api/agents', headers=headers(module)).json['agents'][0]
    assert listed['risk_score'] == expected
    assert listed['id'] != listed['asset_id'] == 'stable-asset'
    assert module.db.session.get(module.ScanSession, 'fixture').overall_risk_score == expected
    assert module.DiscoveredAgentModel.query.filter_by(scan_id='fixture').one().risk_score == expected
