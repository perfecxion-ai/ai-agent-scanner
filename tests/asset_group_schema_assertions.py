"""Check the narrow schema 7 extension without changing historical definitions."""


GROUP_OBJECT_NAMES = frozenset({
    'asset_group_index', 'asset_group_publication',
    'sqlite_autoindex_asset_group_index_1', 'sqlite_autoindex_asset_group_publication_1',
    'ux_asset_group_head', 'ix_asset_group_head_page', 'ix_asset_group_history',
    'aiscan_asset_group_index_insert', 'aiscan_asset_group_index_update', 'aiscan_asset_group_index_delete',
})


def assert_group_extension(before, after):
    """All old SQL stays exact; only the two derived tables and their objects appear."""
    assert set(before) <= set(after)
    assert {row[1] for row in set(after) - set(before)} == GROUP_OBJECT_NAMES


def without_group_rows(rows):
    result = dict(rows)
    for name in ('asset_group_index', 'asset_group_publication'):
        assert not result.pop(name, [])
    return result
