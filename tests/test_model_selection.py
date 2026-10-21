"""Model overrides cannot alter target identity or credential configuration."""

from copy import deepcopy
from unittest.mock import patch

import pytest

from src.core.model_selection import apply_model_overrides, canonical_model_overrides, validate_model_overrides


def assets():
    return [{'id': 'asset-1', 'name': 'Lab', 'endpoint': 'http://127.0.0.1:11434/api/tags',
             'provider': 'ollama', 'metadata': {'environment': 'development'}},
            {'id': 'asset-2', 'name': 'Second', 'endpoint': 'https://fixture.test/v1/models',
             'provider': 'vllm', 'model': 'existing-model'}]


def test_model_selection_copies_source_and_changes_only_selected_model():
    source = assets()
    original = deepcopy(source)
    selected = apply_model_overrides(source, {'asset-1': 'llama3.2:latest'})
    assert source == original
    assert selected[0] == {**original[0], 'model': 'llama3.2:latest'}
    assert selected[1] == original[1]
    selected[0]['metadata']['environment'] = 'test'
    assert source == original


def test_existing_models_and_empty_selection_preserved():
    assert apply_model_overrides(assets(), {}) == assets()
    assert apply_model_overrides(assets(), {'asset-2': 'namespace/replacement'})[1]['model'] == 'namespace/replacement'


@pytest.mark.parametrize('overrides', [None, [], 'model', {'asset-1': {}},
    {'asset-1': {'endpoint': 'https://attacker.test', 'api_key_env': 'SECRET_KEY'}},
    {'asset-1': False}, {'asset-1': ''}, {'asset-1': ' leading'}, {'asset-1': 'trailing '},
    {'asset-1': 'model\nheader'}, {'asset-1': 'x' * 257}, {'': 'model'}, {7: 'model'},
    {'x' * 257: 'model'}, {f'asset-{i}': 'model' for i in range(101)}])
def test_malformed_or_unbounded_overrides_rejected(overrides):
    with pytest.raises(ValueError):
        validate_model_overrides(overrides)


@pytest.mark.parametrize('unknown', ['missing', 'endpoint', 'provider', 'api_key_env'])
def test_unknown_asset_ids_rejected_without_changing_source(unknown):
    source = assets()
    with pytest.raises(ValueError, match='unknown source asset'):
        apply_model_overrides(source, {unknown: 'arbitrary-value'})
    assert source == assets()


def test_duplicate_source_ids_rejected():
    source = assets()
    source[1]['id'] = source[0]['id']
    with pytest.raises(ValueError, match='unique'):
        apply_model_overrides(source, {'asset-1': 'model'})


def test_validation_does_not_read_environment_or_execute():
    with patch('os.getenv', side_effect=AssertionError('No environment access')), patch('subprocess.Popen', side_effect=AssertionError('No execution')):
        selected = apply_model_overrides(assets(), {'asset-1': '${SECRET_KEY}'})
    # Even environment-reference-like model text remains a literal model name.
    assert selected[0]['model'] == '${SECRET_KEY}'


def test_maximum_sized_map_accepted():
    selections = {f'asset-{i}': 'model' for i in range(100)}
    assert validate_model_overrides(selections) == selections


def test_snapshot_aliases_are_canonical_and_bounded_to_source():
    assert canonical_model_overrides(assets(), {'snapshot-1': 'chosen'}, {'snapshot-1': 'asset-1'}) == {'asset-1': 'chosen'}
    with pytest.raises(ValueError, match='ambiguous'):
        canonical_model_overrides(assets(), {}, {'asset-2': 'asset-1'})
    with pytest.raises(ValueError, match='more than once'):
        canonical_model_overrides(assets(), {'asset-1': 'one', 'snapshot-1': 'two'}, {'snapshot-1': 'asset-1'})
