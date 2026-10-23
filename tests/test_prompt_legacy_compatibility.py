"""Pre-receipt prompt scores remain archived claims, not fresh request proof."""

from copy import deepcopy
import hashlib
import json

import pytest

from src.core.contracts import CheckRecord
from src.core.pipeline import to_sarif
from src.core.prompt_catalog import baseline_payloads
from src.core.risk_projection import project_report_risk
from src.reporting.workflows import compare_reports
from tests.test_api_auth import api as api, headers
from tests.test_api_risk_projection import outputs, seed


def legacy_prompt_report(*, partial=False):
    """Use the finalized-check report shape emitted before prompt receipts."""
    payloads = baseline_payloads()['system_prompt_extraction'][:5]
    definition = {'semantics': 'nondisclosure-inconclusive-v2', 'payloads': payloads}
    version = '1:' + hashlib.sha256(json.dumps(
        [definition, 'ollama', 'fixture-model'], sort_keys=True).encode()).hexdigest()
    rule = 'prompt_injection.system_prompt_extraction'
    check = CheckRecord(rule, rule + '.sample', version, 'completed', 'confirmed', 5, 5,
                        evidence_context_id='historical-fixture-v1').to_dict()
    finding = {key: check[key] for key in ('rule_id', 'probe_id', 'probe_version', 'evidence_context_id')}
    finding.update(id='historical-prompt-finding', agent_id='stable-asset',
                   vulnerability_type='prompt_injection', category='system_prompt_extraction',
                   severity='high', evidence_status='confirmed', payload=payloads[0],
                   status_code=200, response_excerpt='[GENERATED_TEXT_OMITTED]')
    return {
        'schema_version': '1.0', 'check_schema_version': '1.0', 'scan_type': 'security_only',
        'status': 'partial' if partial else 'completed',
        'risk_assessment_status': 'partial' if partial else 'completed',
        'summary': {'overall_risk_score': 70},
        'agents': [{
            'id': 'stable-asset', 'name': 'Historical fixture', 'provider': 'ollama',
            'model': 'fixture-model', 'endpoint': 'http://192.0.2.1:11434',
            'security_status': 'partial' if partial else 'completed',
            'checks': [check], 'vulnerabilities': [finding],
            'risk_score': 70, 'risk_level': 'high', 'risk_scoring_policy': 'severity-floor-v2',
            'risk_coverage_status': 'partial' if partial else 'sampled',
        }],
    }


@pytest.mark.parametrize('partial', [False, True])
def test_legacy_prompt_score_is_unknown_without_rewriting_archived_evidence(api, partial):
    module, client = api
    archived = legacy_prompt_report(partial=partial)
    encoded = json.dumps(archived, sort_keys=True)
    seed(module, archived)

    results, listed = outputs(module, client)
    summary, agents = project_report_risk(archived)
    assert summary['overall_risk_score'] is None
    assert summary['risk_assessment_status'] == 'not_assessed'
    assert results['summary']['overall_risk_score'] is None
    for item in (agents['stable-asset'], results['agents'][0], listed):
        assert item['risk_score'] is None
        assert item['risk_level'] == 'unknown'
        assert item['risk_assessment_status'] == 'not_assessed'
        assert item['risk_coverage_status'] == 'not_assessed'
        assert item['risk_scoring_policy'] is None
    assert results['pipeline'] == archived
    exported = client.get('/api/scans/fixture/report?format=json', headers=headers(module))
    assert exported.status_code == 200 and exported.json == archived
    stored = module.ScanResult.query.filter_by(scan_id='fixture').one().result
    assert json.dumps(stored, sort_keys=True) == encoded
    assert json.dumps(exported.json, sort_keys=True) == encoded
    sarif = client.get('/api/scans/fixture/report?format=sarif', headers=headers(module))
    assert sarif.status_code == 200 and sarif.json == to_sarif(archived)
    assert sarif.json['runs'][0]['properties']['summary']['overall_risk_score'] == 70
    assert sarif.json['runs'][0]['results'][0]['properties']['vulnerability_id'] == 'historical-prompt-finding'
    assert client.get('/api/agents?risk_level=high', headers=headers(module)).json['agents'] == []
    assert [item['id'] for item in client.get(
        '/api/agents?risk_level=unknown', headers=headers(module)).json['agents']] == ['fixture-snapshot']
    assert 'check_evidence_schema_version' not in archived
    assert all('check_evidence' not in item for item in archived['agents'])

    quiet = deepcopy(archived)
    quiet.update(status='completed', risk_assessment_status='not_assessed')
    quiet['summary']['overall_risk_score'] = None
    quiet['agents'][0].update(security_status='completed', vulnerabilities=[], risk_score=None,
                              risk_level='unknown', risk_scoring_policy=None,
                              risk_coverage_status='not_assessed')
    quiet['agents'][0]['checks'][0]['outcome'] = 'inconclusive'
    comparison = compare_reports(archived, quiet)
    assert comparison['resolved'] == []
    assert len(comparison['resolution_unverified']) == 1
    assert comparison['resolution_unverified'][0]['occurrences'] == archived['agents'][0]['vulnerabilities']
    assert json.dumps(archived, sort_keys=True) == encoded
