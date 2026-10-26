"""Original access-v2 producer archives captured before wire-guard changes.

These fixed public JSON bytes come from actual owned HTTP, the four original
GET check wrappers and the pipeline at the pinned revision. No producer is
imported here. Never regenerate these archives through a new writer. Original
scores are recorded history; current eligibility is a separate assertion.
"""

import hashlib
import json
from pathlib import Path


LEGACY_ACCESS_REVISION = '6af7fa2cd6d2a2b1e3ff67a12ff348df092f7413'
LEGACY_ACCESS_SHA256 = {
    'zero': '61cc4cf5ab94acf7523e53d9f315bcb1808047992f7c95ca12fb2a2cd1cd3af8',
    'high': 'd03ef3d41002ff0b87ca22845a125da29f96624d05f31aa54dbdcc446d7b84e4',
    'partial': '6f076effbd3d7623e0762d09758f45824abda1a8f9cee6284a81ed90279e5386',
    'mixed': '1f8e7387f2c53ef336346fdbeaddc6734bbfb5a4685354a61d532253f1e1e30d',
}
LEGACY_ACCESS_NAMES = tuple(LEGACY_ACCESS_SHA256)
_MANIFEST_SHA256 = '085d8ca21a4f095b33681968f0663f4da0d1cd7cd5d79017d46e3b8a92bb5b96'
_ROOT = Path(__file__).parent / 'fixtures' / 'legacy_access'


def legacy_access_archive(name):
    """Return the immutable public archive, rejecting changed or unknown inputs."""
    expected = LEGACY_ACCESS_SHA256[name]
    raw = (_ROOT / (name + '.json')).read_bytes()
    if hashlib.sha256(raw).hexdigest() != expected:
        raise ValueError('Frozen access archive changed')
    return raw


def legacy_access_report(name):
    """Load an independent copy without restamping or recomputing its history."""
    return json.loads(legacy_access_archive(name))


def legacy_access_manifest():
    """Return independently frozen original scores, IDs, probes and source hashes."""
    raw = (_ROOT / 'manifest.json').read_bytes()
    if hashlib.sha256(raw).hexdigest() != _MANIFEST_SHA256:
        raise ValueError('Frozen access manifest changed')
    return json.loads(raw)
