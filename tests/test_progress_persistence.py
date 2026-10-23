"""Append-only progress storage guards; execution acceptance uses real producers."""

from copy import deepcopy

import pytest

from src.core.jobs import _evidence_extension
from tests.test_job_checkpoints import report


def projection():
    # This fixture tests structural extension, not receipt eligibility or scoring.
    value = report()
    value['checkpoint'].update(version='2.0', coverage='confirmed_observations_and_finalized_checks')
    value['check_evidence_schema_version'] = '1.0'
    value['agents'][0].update(
        check_evidence_schema_version='1.0',
        check_evidence_run_id='7c0206ee-05b3-4e4b-91c3-7d90a8b06154',
        check_evidence=[{'id': 'first', 'sequence': 1}, {'id': 'second', 'sequence': 2}],
    )
    return value


@pytest.mark.parametrize('mutation', [
    'drop_contract', 'drop_run', 'change_run', 'change_schema', 'drop_receipt',
    'rewrite_receipt', 'reorder_receipts', 'remove_all', 'downgrade_checkpoint',
])
def test_receipt_projection_cannot_regress_acknowledged_state(mutation):
    before = projection()
    after = deepcopy(before)
    agent = after['agents'][0]
    if mutation == 'drop_contract':
        agent.pop('check_evidence_schema_version')
    elif mutation == 'drop_run':
        agent.pop('check_evidence_run_id')
    elif mutation == 'change_run':
        agent['check_evidence_run_id'] = 'another-execution'
    elif mutation == 'change_schema':
        agent['check_evidence_schema_version'] = 'future'
    elif mutation == 'drop_receipt':
        agent['check_evidence'].pop()
    elif mutation == 'rewrite_receipt':
        agent['check_evidence'][0]['sequence'] = 3
    elif mutation == 'reorder_receipts':
        agent['check_evidence'].reverse()
    elif mutation == 'remove_all':
        agent.pop('check_evidence')
    else:
        after['checkpoint'].update(version='1.0', coverage='finalized_checks_only')
    original = deepcopy(before)
    assert not _evidence_extension(before, after)
    assert before == original


def test_receipt_projection_accepts_identical_or_appended_evidence():
    before = projection()
    assert _evidence_extension(before, deepcopy(before))
    after = deepcopy(before)
    after['agents'][0]['check_evidence'].append({'id': 'third', 'sequence': 3})
    assert _evidence_extension(before, after)
    assert len(before['agents'][0]['check_evidence']) == 2


def test_legacy_checkpoint_can_gain_but_never_drop_progress_contract():
    before = report()
    after = projection()
    assert _evidence_extension(before, after)
    assert not _evidence_extension(after, before)


@pytest.mark.parametrize('field', ['check_evidence_run_id', 'check_evidence'])
def test_empty_receipt_ledger_still_pins_its_execution(field):
    before = projection()
    before['agents'][0]['check_evidence'] = []
    after = deepcopy(before)
    after['agents'][0].pop(field)
    assert not _evidence_extension(before, after)


def test_pending_empty_ledger_can_gain_its_execution_identity():
    pending = projection()
    pending['agents'][0]['check_evidence'] = []
    pending['agents'][0].pop('check_evidence_run_id')
    assert _evidence_extension(pending, deepcopy(pending))
    started = deepcopy(pending)
    started['agents'][0]['check_evidence_run_id'] = projection()['agents'][0]['check_evidence_run_id']
    assert _evidence_extension(pending, started)
    assert _evidence_extension(started, projection())
    assert not _evidence_extension(started, pending)


def test_nonempty_receipt_ledger_requires_execution_identity():
    before = projection()
    before['agents'][0]['check_evidence'] = []
    before['agents'][0].pop('check_evidence_run_id')
    after = projection()
    after['agents'][0].pop('check_evidence_run_id')
    assert not _evidence_extension(before, after)
