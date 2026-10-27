"""A stopped SQLite backup preserves a published group cache and its sources."""

from contextlib import closing
import sqlite3
import time

from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from werkzeug.datastructures import MultiDict

from src.core.asset_groups import AssetGroupProjector, group_page, parse_group_request
from src.core.schema import initialize_schema
from tests.test_asset_group_schema import current_metadata, fingerprint, seed_source


def test_stopped_backup_restores_nonempty_publication_without_rebuild_or_source_changes(tmp_path):
    source, restored = tmp_path / 'owned-source.sqlite', tmp_path / 'owned-restored.sqlite'
    metadata = current_metadata()
    tables = {key: metadata.tables[name] for key, name in {
        'index': 'asset_group_index', 'publication': 'asset_group_publication',
        'observations': 'discovered_agent', 'scans': 'scan_session',
        'reports': 'scan_result', 'generations': 'inventory_generation',
    }.items()}
    original = create_engine('sqlite:///' + str(source))
    try:
        initialize_schema(original, metadata)
        with original.begin() as connection:
            seed_source(connection, metadata)
        projector = AssetGroupProjector(original, tables)
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            if projector.step().published:
                break
        else:
            raise AssertionError('Owned source did not publish')
        with Session(original) as session:
            before_page = group_page(session, parse_group_request(MultiDict(), 'tenant-a', 'owned-key'),
                                     'owned-key', tables)
        assert len(before_page['asset_groups']) == 1
        before = fingerprint(original)
        assert len(before[1]['asset_group_index']) == len(before[1]['asset_group_publication']) == 1
    finally:
        original.dispose()
    with closing(sqlite3.connect(source.as_uri() + '?mode=ro', uri=True)) as connection:
        with closing(sqlite3.connect(restored)) as target:
            connection.backup(target)
    recovered = create_engine('sqlite:///' + str(restored))
    try:
        assert fingerprint(recovered) == before
        initialize_schema(recovered, metadata)
        assert fingerprint(recovered) == before
        with Session(recovered) as session:
            after_page = group_page(session, parse_group_request(MultiDict(), 'tenant-a', 'owned-key'),
                                    'owned-key', tables)
        assert after_page == before_page
        assert AssetGroupProjector(recovered, tables).step().state == 'idle'
        assert fingerprint(recovered) == before
    finally:
        recovered.dispose()
