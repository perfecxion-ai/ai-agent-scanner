"""Portable risk-cache depth bounds, independent of Python recursion limits."""

import json

import pytest

from src.core import schema, stored_risk
from src.core.schema import initialize_schema
from tests.controlled_access import result as access_result
from tests.test_control_evidence_projections import report as access_report
from tests.test_api_auth import api as api
from tests.test_nullable_independent_review import old_database as old_database, seed, cache


PROJECTED = {'fixture': {'risk_score': 70.0, 'risk_level': 'high'}}


def nesting(depth, leaf=0):
    value = leaf
    for _ in range(depth):
        value = [value]
    return value


def raw_nesting(depth, *, objects=False, leaf=b'0'):
    before, after = (b'{"child":', b'}') if objects else (b'[', b']')
    return before * depth + leaf + after * depth


@pytest.mark.parametrize('depth', [0, 1, 63, 64, 65, 2000], ids=['scalar', 'one', 'below', 'limit', 'over', 'deep'])
@pytest.mark.parametrize('objects', [False, True], ids=['arrays', 'objects'])
def test_raw_container_limit_is_explicit(depth, objects):
    parsed = schema._decode(raw_nesting(depth, objects=objects))
    if depth > 64:
        assert parsed is schema._INVALID_JSON
        return
    assert parsed is not schema._INVALID_JSON
    for _ in range(depth):
        parsed = parsed['child'] if objects else parsed[0]
    assert parsed == 0


@pytest.mark.parametrize('leaf', [
    pytest.param('[[]]{{}}' * 100, id='delimiters'),
    pytest.param('quote " then slash \\ and escaped quote \\" [{}]', id='escaped-quotes'),
    pytest.param('\\' * 101 + '"' + '\\' * 100 + '[{}]', id='odd-even-backslashes'),
    pytest.param('\u2603 \U0001f9ea [ ] { } "', id='unicode'),
])
@pytest.mark.parametrize('ascii_only', [False, True], ids=['utf8', 'escaped-ascii'])
def test_strings_do_not_inflate_raw_container_depth(leaf, ascii_only):
    encoded = json.dumps(leaf, ensure_ascii=ascii_only).encode('utf-8')
    value = schema._decode(raw_nesting(64, leaf=encoded))
    assert value is not schema._INVALID_JSON
    for _ in range(64):
        value = value[0]
    assert value == leaf


def test_utf8_bom_keeps_the_same_depth_boundary():
    parsed = schema._decode(b'\xef\xbb\xbf' + raw_nesting(64))
    assert parsed is not schema._INVALID_JSON
    assert schema._decode(b'\xef\xbb\xbf' + raw_nesting(65)) is schema._INVALID_JSON


@pytest.mark.parametrize('encoding', ['utf-16', 'utf-32'], ids=['utf16', 'utf32'])
def test_non_utf8_raw_material_cannot_bypass_the_lexical_bound(encoding):
    raw = raw_nesting(1).decode().encode(encoding)
    assert schema._decode(raw) is schema._INVALID_JSON


@pytest.mark.parametrize('raw', [
    pytest.param(b'"unterminated', id='unterminated-string'),
    pytest.param(b'"slash\\"', id='escaped-final-quote'),
    pytest.param(b'{"x": [0}', id='mismatched-delimiters'),
    pytest.param(b'[0]]', id='extra-close'),
    pytest.param(b'\xef\xbb\xbf\xef\xbb\xbf[]', id='duplicate-bom'),
    pytest.param(b'[]\x00', id='trailing-nul'),
])
def test_depth_screen_never_replaces_json_validation(raw):
    assert schema._decode(raw) is schema._INVALID_JSON


@pytest.mark.parametrize('depth, accepted', [(63, True), (64, False)], ids=['limit', 'over'])
def test_overwritten_duplicate_keys_still_count_in_raw_depth(depth, accepted):
    raw = b'{"aux":' + raw_nesting(depth) + b',"aux":0}'
    parsed = schema._decode(raw)
    assert (parsed is not schema._INVALID_JSON) is accepted
    if accepted:
        assert parsed == {'aux': 0}


@pytest.mark.parametrize('depth', [1, 63, 64, 65, 2000], ids=['one', 'below', 'limit', 'over', 'deep'])
def test_writer_metadata_uses_the_same_container_limit(depth):
    metadata = {'asset_id': 'fixture', 'aux': nesting(depth - 1)}
    expected = (70.0, 'high') if depth <= 64 else (None, 'unknown')
    assert stored_risk.snapshot_stored_risk(PROJECTED, 'fixture', metadata) == expected


@pytest.mark.parametrize('kind', ['direct', 'indirect'], ids=['self-cycle', 'cross-cycle'])
def test_cyclic_writer_graph_is_unknown_without_mutating_it(kind):
    loop = []
    metadata = {'asset_id': 'fixture', 'aux': loop}
    loop.append(loop if kind == 'direct' else metadata)
    assert stored_risk.snapshot_stored_risk(PROJECTED, 'fixture', metadata) == (None, 'unknown')
    assert metadata['aux'] is loop
    assert loop[0] is (loop if kind == 'direct' else metadata)


@pytest.mark.parametrize('depth, expected', [(62, 70.0), (63, None)], ids=['shared-at-limit', 'shared-over-limit'])
def test_shared_references_are_not_cycles_and_depth_is_path_specific(depth, expected):
    shared = [0]
    metadata = {'asset_id': 'fixture', 'shallow': shared, 'deep': nesting(depth, shared)}
    # Root object + wrappers + the shared list determines the deepest path.
    assert stored_risk.snapshot_stored_risk(PROJECTED, 'fixture', metadata) == (
        expected, 'high' if expected is not None else 'unknown')
    assert metadata['shallow'] is shared
    value = metadata['deep']
    for _ in range(depth):
        value = value[0]
    assert value is shared


@pytest.mark.parametrize('key', [0, -127, True, False, None, 1e-300, '', '\u2603"[]'],
                         ids=['zero', 'negative', 'true', 'false', 'null', 'float', 'empty', 'escaped'])
def test_mixed_dictionary_keys_accept_exact_serialized_byte_budget(monkeypatch, key):
    metadata = {'asset_id': 'fixture', 'aux': {key: '\u2603"\\\n'}}
    size = len(json.dumps(metadata, ensure_ascii=True, allow_nan=False, separators=(',', ':')).encode('utf-8'))
    monkeypatch.setattr(stored_risk, 'MAX_STORED_RISK_BYTES', size)
    assert stored_risk.snapshot_stored_risk(PROJECTED, 'fixture', metadata) == (70.0, 'high')
    monkeypatch.setattr(stored_risk, 'MAX_STORED_RISK_BYTES', size - 1)
    assert stored_risk.snapshot_stored_risk(PROJECTED, 'fixture', metadata) == (None, 'unknown')


@pytest.fixture
async def supported_report():
    return access_report(await access_result(disclose=True), score=70)


@pytest.mark.asyncio
@pytest.mark.parametrize('depth, expected', [(63, 70.0), (64, None)], ids=['limit', 'over'])
async def test_writer_report_limit_preserves_supported_evidence_only_in_bounds(supported_report, depth, expected):
    supported_report['review_aux'] = nesting(depth)
    before = supported_report['review_aux']
    summary, projected = stored_risk.project_stored_risk(supported_report)
    assert summary['overall_risk_score'] == expected
    if expected is None:
        assert projected == {}
    else:
        assert projected['fixture']['risk_score'] == expected
    assert supported_report['review_aux'] is before


@pytest.mark.asyncio
@pytest.mark.parametrize('depth', [64, 65, 2000], ids=['limit', 'over', 'deep'])
@pytest.mark.parametrize('column', ['metadata', 'report'])
async def test_real_upgrade_depth_policy_keeps_archives_exact(old_database, supported_report, depth, column):
    module, engine, _ = old_database
    raw_report = json.dumps(supported_report).encode()
    if column == 'report':
        raw_report = raw_report[:-1] + b',"review_aux":' + raw_nesting(depth - 1) + b'}'
        raw_metadata = b'{"asset_id":"fixture"}'
    else:
        raw_metadata = raw_nesting(depth)
    seed(old_database, raw_report, metadata=raw_metadata, row_id='fixture')
    initialize_schema(engine, module.db.metadata)
    expected_summary = None if column == 'report' and depth > 64 else 70.0
    expected_asset = 70.0 if depth <= 64 else None
    assert cache(engine) == (expected_summary, (expected_asset, 'high' if expected_asset is not None else 'unknown'))
    with engine.connect() as connection:
        assert connection.exec_driver_sql('SELECT CAST(result AS BLOB) FROM scan_result').scalar_one() == raw_report
        assert connection.exec_driver_sql('SELECT CAST(metadata AS BLOB) FROM discovered_agent').scalar_one() == raw_metadata
