"""Reject ineligible extensions before replacing acknowledged evidence or SQL caches."""

from copy import deepcopy

import pytest

from src.core.contracts import CheckpointError, validate_checkpoint_report
from src.core.pipeline import _CheckpointState
from src.risk.risk_assessor import RiskAssessment
from tests.legacy_observation_fixtures import legacy_report
from tests.test_job_checkpoints import (
    api as api, checkpoint_store as checkpoint_store, projection, save, store as store,
)
from tests.test_jobs import result
from tests.test_tenant_observation_contracts import unknown_probe_extension


def baseline():
    value = legacy_report('prompt-unfinished-checkpoint')
    value['scan_id'] = 'checkpoint'
    value['checkpoint'].update(version='3.0', sequence=1)
    value['check_evidence_schema_version'] = '2.0'
    for asset in [*value['agents'], *value['security_results']]:
        asset['check_evidence_schema_version'] = '2.0'
    value['agents'][0]['discovery_method'] = 'fixture'
    return value


def invalid_extension(kind):
    value = unknown_probe_extension()
    value['scan_id'] = 'checkpoint'
    value['checkpoint']['sequence'] = 2
    value['agents'][0]['discovery_method'] = 'fixture'
    if kind == 'unbacked-finding':
        for asset in [*value['agents'], *value['security_results']]:
            asset['check_evidence'].pop()
            asset['vulnerabilities'][-1].pop('check_evidence_id')
    return value


@pytest.mark.parametrize('kind', ['unknown-probe', 'unbacked-finding'])
@pytest.mark.parametrize('final', [False, True])
@pytest.mark.parametrize('scored', [False, True])
def test_bad_append_cannot_replace_sql_receipts_even_before_scoring(checkpoint_store, kind, final, scored):
    previous = baseline()
    if not scored:
        previous['risk_assessments'] = []
        previous['risk_assessment_status'] = 'not_assessed'
        previous['summary']['overall_risk_score'] = None
        previous['agents'][0].update(risk_score=None, risk_level='unknown',
                                     risk_coverage_status='not_assessed', risk_scoring_policy=None)
    assert save(checkpoint_store, previous)
    before = projection(checkpoint_store)
    candidate = invalid_extension(kind)
    # Redacted historical read shapes remain structurally readable; an append
    # must also preserve evidence eligibility before any write is acknowledged.
    validate_checkpoint_report(candidate, final=final)
    assert not save(checkpoint_store, candidate, final=final)
    assert result(checkpoint_store[0], 'checkpoint') == previous
    assert projection(checkpoint_store) == before


@pytest.mark.asyncio
@pytest.mark.parametrize('kind', ['unknown-probe', 'unbacked-finding'])
async def test_bad_raw_finish_leaves_checkpoint_state_and_callback_unchanged(kind):
    previous = baseline()
    saved = []
    async def sink(value):
        saved.append(deepcopy(value))
    state = _CheckpointState(previous['agents'], RiskAssessment(), 'security_only', None, set(), sink,
                             evidence_enabled=True, evidence_schema_version='2.0')
    state.results[0] = deepcopy(previous['security_results'][0])
    original = deepcopy(state.results)
    with pytest.raises((CheckpointError, ValueError)):
        await state.finish(0, invalid_extension(kind)['security_results'][0])
    assert state.results == original
    assert saved == []
