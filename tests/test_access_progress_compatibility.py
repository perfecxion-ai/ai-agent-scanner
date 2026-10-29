"""Adding durable access observations preserves the accepted v3 archive meaning."""

from copy import deepcopy
import hashlib

import pytest
from sqlalchemy import event

from src.core import schema
from src.core.contracts import validate_scan_result
from src.core.risk_projection import project_report_risk
from tests.legacy_access_v3_fixtures import (
    legacy_access_v3_archive, legacy_access_v3_manifest, legacy_access_v3_report,
)
from tests.test_access_cache_policy_upgrade import (
    api as api, database as database, caches, seed, state,
)
from tests.asset_group_schema_assertions import assert_group_extension, assert_group_risk_extension, without_group_rows


@pytest.mark.parametrize('name', ['zero', 'high', 'partial', 'mixed'])
def test_frozen_v3_archive_keeps_its_original_supported_risk(name):
    before = legacy_access_v3_archive(name)
    manifest = legacy_access_v3_manifest()['archives'][name]
    report = legacy_access_v3_report(name)
    validate_scan_result(report)
    summary, assets = project_report_risk(report)
    assert report['check_evidence_schema_version'] == '2.0'
    assert report['checkpoint']['version'] == '3.0'
    assert summary['overall_risk_score'] == manifest['original_score']
    asset = assets[report['agents'][0]['id']]
    assert (asset['risk_score'], asset['risk_level'], asset['risk_coverage_status']) == (
        manifest['original_score'], manifest['original_level'], manifest['original_coverage'])
    assert hashlib.sha256(before).hexdigest() == manifest['sha256']
    assert legacy_access_v3_archive(name) == before


@pytest.mark.parametrize('version', [5, 6, 7, 8])
def test_existing_v3_caches_need_no_reclassification_during_derived_schema_extension(database, version):
    module, engine = database
    manifest = legacy_access_v3_manifest()['archives']
    documents = []
    for name, expected in manifest.items():
        documents.append((name, legacy_access_v3_report(name), legacy_access_v3_archive(name),
                          expected['original_score'], expected['original_level']))
    seed(engine, documents, version=min(version, 7))
    if version == 8:
        # Initialize the current fixture before recording the idempotence baseline.
        schema.initialize_schema(engine, module.db.metadata)
    before_definitions, before_rows = state(engine)
    before_caches = caches(engine)
    statements = []

    def observe(_connection, _cursor, statement, _parameters, _context, _many):
        statements.append(statement)

    event.listen(engine, 'before_cursor_execute', observe)
    try:
        schema.initialize_schema(engine, module.db.metadata)
    finally:
        event.remove(engine, 'before_cursor_execute', observe)
    definitions, rows = state(engine)
    expected_rows = deepcopy(before_rows)
    expected_rows['schema_version'] = [(1, 8)]
    assert schema.SCHEMA_VERSION == 8
    if version < 7:
        assert_group_extension(before_definitions, definitions)
        assert without_group_rows(rows) == expected_rows
    elif version == 7:
        assert_group_risk_extension(before_definitions, definitions)
        assert rows == expected_rows
    else:
        assert definitions == before_definitions and rows == expected_rows
    assert caches(engine) == before_caches
    writes = [statement for statement in statements if statement.upper().startswith(
        ('UPDATE ', 'INSERT ', 'DELETE ', 'CREATE ', 'DROP ', 'ALTER '))]
    data_writes = [statement for statement in writes if not statement.upper().startswith('CREATE ')]
    assert len(data_writes) == (1 if version < 7 else 7 if version == 7 else 0)
    if version < 8:
        assert data_writes[-1].startswith('UPDATE schema_version SET version=')
    if version == 7:
        assert all(statement.startswith('ALTER TABLE asset_group_index ADD COLUMN ')
                   for statement in data_writes[:-1])
