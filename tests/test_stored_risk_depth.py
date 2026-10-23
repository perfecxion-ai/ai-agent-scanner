"""Storage interpretation has the same finite depth limit on every Python."""

import json
from unittest.mock import Mock

import pytest

from src.core import schema, stored_risk
from tests.test_api_risk_projection import report


def nested(depth, kind='list'):
    result = 0
    for index in range(depth):
        selected = kind if kind != 'mixed' else ('dict', 'list', 'tuple')[index % 3]
        result = {'value': result} if selected == 'dict' else (result,) if selected == 'tuple' else [result]
    return result


@pytest.mark.parametrize('kind', ['list', 'tuple', 'dict', 'mixed'])
@pytest.mark.parametrize('depth,expected', [(0, True), (1, True), (64, True), (65, False), (2000, False)])
def test_writer_depth_counts_containers_without_recursion(kind, depth, expected):
    assert stored_risk._bounded(nested(depth, kind)) is expected


@pytest.mark.parametrize('depth,expected', [(0, True), (1, True), (64, True), (65, False), (2000, False)])
def test_raw_array_depth_is_checked_before_parser(monkeypatch, depth, expected):
    raw = b'[' * depth + b'0' + b']' * depth
    if expected:
        assert schema._decode(raw) is not schema._INVALID_JSON
    else:
        parse = Mock(side_effect=AssertionError('Too-deep input must not reach JSON parsing'))
        monkeypatch.setattr(schema.json, 'loads', parse)
        assert schema._decode(raw) is schema._INVALID_JSON
        parse.assert_not_called()


@pytest.mark.parametrize('depth,expected', [(64, True), (65, False)])
def test_raw_object_depth_includes_root_object(depth, expected):
    raw = b'{"value":' * depth + b'0' + b'}' * depth
    assert (schema._decode(raw) is not schema._INVALID_JSON) is expected


@pytest.mark.parametrize('text', [
    '[]{}' * 1000, 'quote " then brackets [[]]}}', 'slash \\ then quote " and bracket [',
    '\\' * 7 + '"' + '[' * 100, '\\' * 8 + '"' + ']' * 100,
    '\u0100 brackets and an emoji \U0001f642 [{}]',
])
def test_structural_characters_inside_strings_never_increase_depth(text):
    document = {'message': text, 'empty': [], 'child': {'value': 'tail'}}
    raw = json.dumps(document, ensure_ascii=False).encode('utf-8')
    assert schema._decode(raw) == document
    assert stored_risk._bounded(document)


@pytest.mark.parametrize('raw', [
    b'{"message":"\\u005b\\u007b\\u0022\\u005c","tail":[]}',
    b'{"message":"line\\n\\t\\r \\/ quote\\\" slash\\\\","tail":{}}',
])
def test_ordinary_escaped_characters_do_not_escape_later_structural_tokens(raw):
    assert schema._decode(raw) == json.loads(raw.decode('utf-8'))


@pytest.mark.parametrize('encoding', ['utf-16', 'utf-16-le', 'utf-16-be', 'utf-32', 'utf-32-le', 'utf-32-be'])
def test_other_json_byte_encodings_stay_unassessed(encoding):
    raw = '[0]'.encode(encoding)
    assert schema._decode(raw) is schema._INVALID_JSON


def test_utf8_bom_is_allowed_without_changing_depth_boundary():
    raw = b'\xef\xbb\xbf' + b'[' * 64 + b'0' + b']' * 64
    assert schema._decode(raw) is not schema._INVALID_JSON
    too_deep = b'\xef\xbb\xbf' + b'[' * 65 + b'0' + b']' * 65
    assert schema._decode(too_deep) is schema._INVALID_JSON


@pytest.mark.parametrize('raw', [b'"unterminated', b'"trailing\\', b']', b'}', b'[}', b'{broken', b'"\xff"'])
def test_malformed_json_stays_unassessed(raw):
    assert schema._decode(raw) is schema._INVALID_JSON


@pytest.mark.parametrize('kind', ['list', 'dict', 'tuple_indirect'])
def test_cycles_fail_before_serialization(monkeypatch, kind):
    if kind == 'dict':
        value = {}
        value['self'] = value
    else:
        value = []
        value.append((value,) if kind == 'tuple_indirect' else value)
    dump = Mock(side_effect=AssertionError('Cycles must not reach JSON serialization'))
    monkeypatch.setattr(stored_risk.json, 'dumps', dump)
    assert stored_risk.snapshot_stored_risk({}, 'asset', value) == (None, 'unknown')
    assert stored_risk.project_stored_risk(value) == (
        {'overall_risk_score': None, 'risk_assessment_status': 'not_assessed'}, {})
    dump.assert_not_called()


def test_repeated_references_are_distinct_serialized_occurrences():
    child = {'value': [1, 2, 3]}
    value = [child, child, {'nested': child}]
    assert stored_risk._bounded(value)


def test_exponential_shared_graph_hits_expanded_byte_bound_before_serialization(monkeypatch):
    value = 'x'
    for _ in range(50):
        value = [value, value]
    monkeypatch.setattr(stored_risk, 'MAX_STORED_RISK_BYTES', 128)
    dump = Mock(side_effect=AssertionError('Oversized expanded graph must not be serialized'))
    monkeypatch.setattr(stored_risk.json, 'dumps', dump)
    assert stored_risk.snapshot_stored_risk({}, 'asset', value) == (None, 'unknown')
    dump.assert_not_called()


@pytest.mark.parametrize('value', [
    None, True, False, 0, -123, 1.25, '', 'text with "quotes" and \\slashes',
    '\u0100', [], {}, (1, 'two'), [1, 2, {'a': 3}],
    {None: False, 3: 'three', 2.5: [], '': {'child': None}},
])
def test_byte_estimate_never_rejects_a_value_within_exact_json_limit(monkeypatch, value):
    length = len(json.dumps(value, ensure_ascii=True, allow_nan=False, separators=(',', ':')).encode('utf-8'))
    monkeypatch.setattr(stored_risk, 'MAX_STORED_RISK_BYTES', length)
    assert stored_risk._bounded(value)
    monkeypatch.setattr(stored_risk, 'MAX_STORED_RISK_BYTES', length - 1)
    assert not stored_risk._bounded(value)


@pytest.mark.parametrize('padding_depth,expected', [(63, 70.0), (64, None)])
def test_report_writer_applies_limit_before_projecting_unused_nested_material(padding_depth, expected):
    document = report(70, partial=True)
    document['padding'] = nested(padding_depth)
    summary, _ = stored_risk.project_stored_risk(document)
    assert summary['overall_risk_score'] == expected


@pytest.mark.parametrize('padding_depth,expected', [(63, 70.0), (64, None)])
def test_snapshot_writer_does_not_fall_back_after_depth_failure(padding_depth, expected):
    projected = {'asset': {'risk_score': 70.0, 'risk_level': 'high'}}
    metadata = {'asset_id': 'asset', 'padding': nested(padding_depth)}
    assert stored_risk.snapshot_stored_risk(projected, 'asset', metadata) == (
        expected, 'unknown' if expected is None else 'high')


@pytest.mark.parametrize('metadata', [None, '[]{}' * 100, [0], nested(64)])
def test_shallow_nonobject_metadata_keeps_api_snapshot_fallback(metadata):
    projected = {'snapshot': {'risk_score': 0.0, 'risk_level': 'minimal'}}
    assert stored_risk.snapshot_stored_risk(projected, 'snapshot', metadata) == (0.0, 'minimal')
