"""Durable checkpoint streams preserve their original producer identity."""

from copy import deepcopy

import pytest

from src.core.build_identity import current_identity
from tests.test_job_checkpoints import (
    api as api, checkpoint_store as checkpoint_store, projection, report, save,
    store as store,
)
from tests.test_jobs import result, state


@pytest.mark.parametrize('final', [False, True], ids=['checkpoint', 'final'])
@pytest.mark.parametrize('change', ['replace', 'remove', 'stamp_historical'])
def test_acknowledged_producer_cannot_change(checkpoint_store, final, change):
    store, _, _ = checkpoint_store
    original = report()
    if change != 'stamp_historical':
        original['producer_identity'] = current_identity()
    assert save(checkpoint_store, original)
    before = projection(checkpoint_store)
    newer = report(1 if final else 2)
    if change == 'replace':
        newer['producer_identity'] = deepcopy(original['producer_identity'])
        newer['producer_identity']['package_version'] = '1.2.0.dev1'
    elif change == 'stamp_historical':
        newer['producer_identity'] = current_identity()
    assert not save(checkpoint_store, newer, final=final)
    assert result(store, 'checkpoint') == original
    assert projection(checkpoint_store) == before
    assert state(store, 'checkpoint') == 'running'


@pytest.mark.parametrize('identity', ['current', 'withheld', 'historical'])
def test_unchanged_producer_survives_checkpoint_and_recovery(checkpoint_store, identity):
    store, _, _ = checkpoint_store
    original = report()
    if identity != 'historical':
        original['producer_identity'] = current_identity() if identity == 'current' else None
    assert save(checkpoint_store, original)
    newer = deepcopy(original)
    newer['checkpoint']['sequence'] = 2
    assert save(checkpoint_store, newer)
    store.finish('checkpoint', 'Fixture interruption', owner='worker')
    recovered = result(store, 'checkpoint')
    assert ('producer_identity' in recovered) == ('producer_identity' in original)
    assert recovered.get('producer_identity') == original.get('producer_identity')
    assert recovered['checkpoint']['sequence'] == 2
    assert state(store, 'checkpoint') == 'failed'
