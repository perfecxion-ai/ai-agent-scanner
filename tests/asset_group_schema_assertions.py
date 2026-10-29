"""Check the derived group extension without changing historical definitions."""


GROUP_OBJECT_NAMES = frozenset({
    'asset_group_index', 'asset_group_publication',
    'sqlite_autoindex_asset_group_index_1', 'sqlite_autoindex_asset_group_publication_1',
    'ux_asset_group_head', 'ix_asset_group_head_page', 'ix_asset_group_history',
    'ix_asset_group_head_risk_page',
    'aiscan_asset_group_index_insert', 'aiscan_asset_group_index_update', 'aiscan_asset_group_index_delete',
})


def assert_group_extension(before, after):
    """All old SQL stays exact; only the two derived tables and their objects appear."""
    assert set(before) <= set(after)
    assert {row[1] for row in set(after) - set(before)} == GROUP_OBJECT_NAMES


def assert_group_risk_extension(before, after):
    """Schema 7 may add only the six nullable facts and exact partial risk index."""
    previous, current = {row[1]: row for row in before}, {row[1]: row for row in after}
    assert set(current) - set(previous) == {'ix_asset_group_head_risk_page'}
    assert all(current[name] == value for name, value in previous.items() if name != 'asset_group_index')
    marker = 'projection_policy VARCHAR(64) NOT NULL'
    old_sql = previous['asset_group_index'][3]
    assert old_sql.count(marker) == 1
    extra = (', risk_score FLOAT, risk_level VARCHAR(20), risk_coverage_status VARCHAR(32), '
             'risk_assessment_status VARCHAR(32), risk_scoring_policy VARCHAR(64), security_status VARCHAR(32)')
    assert current['asset_group_index'][:3] == previous['asset_group_index'][:3]
    assert current['asset_group_index'][3] == old_sql.replace(marker, marker + extra, 1)
    assert current['ix_asset_group_head_risk_page'] == (
        'index', 'ix_asset_group_head_risk_page', 'asset_group_index',
        'CREATE INDEX ix_asset_group_head_risk_page ON asset_group_index (organization_id, build_id, '
        'publication_nonce, source_generation, projection_policy, is_latest, risk_level, observed_at_us DESC, group_id) '
        'WHERE is_latest = 1')


def without_group_rows(rows):
    result = dict(rows)
    for name in ('asset_group_index', 'asset_group_publication'):
        assert not result.pop(name, [])
    return result
