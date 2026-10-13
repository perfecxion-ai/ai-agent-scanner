"""Bounded model selection for existing, authorized source assets."""

from copy import deepcopy


MAX_MODEL_OVERRIDES = 100
MAX_MODEL_LENGTH = 256
MAX_ASSET_ID_LENGTH = 256


def _bounded_string(value, maximum):
    return (isinstance(value, str) and 0 < len(value) <= maximum
            and value == value.strip() and not any(ord(char) < 32 or ord(char) == 127 for char in value))


def validate_model_overrides(overrides):
    """Validate only an asset-ID to model-name map; never resolve credentials."""
    if not isinstance(overrides, dict) or len(overrides) > MAX_MODEL_OVERRIDES:
        raise ValueError('model_overrides must be an object with at most 100 entries')
    for asset_id, model in overrides.items():
        if not _bounded_string(asset_id, MAX_ASSET_ID_LENGTH):
            raise ValueError('model_overrides asset IDs must contain 1-256 characters without surrounding whitespace or controls')
        if not _bounded_string(model, MAX_MODEL_LENGTH):
            raise ValueError('model_overrides models must contain 1-256 characters without surrounding whitespace or controls')
    return dict(overrides)


def apply_model_overrides(source_agents, overrides):
    """Copy source assets and set model only, rejecting unknown or ambiguous IDs.

    Call after the server has authorized source-scan ownership and before target
    policy validation and execution. This does not authorize targets or models.
    """
    selections = validate_model_overrides(overrides)
    if not isinstance(source_agents, list):
        raise ValueError('Source assets must be an array')
    by_id = {}
    for agent in source_agents:
        if not isinstance(agent, dict) or not _bounded_string(agent.get('id'), MAX_ASSET_ID_LENGTH):
            raise ValueError('Source assets require valid IDs')
        if agent['id'] in by_id:
            raise ValueError('Source asset IDs must be unique')
        by_id[agent['id']] = agent
    if selections.keys() - by_id.keys():
        raise ValueError('model_overrides references an unknown source asset')
    selected = deepcopy(source_agents)
    for agent in selected:
        if agent['id'] in selections:
            agent['model'] = selections[agent['id']]
    return selected
