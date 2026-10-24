"""Frozen public archives produced by owned HTTP fixtures before tenant receipts.

These files were captured once at the fixed revision below. Never regenerate
them through current producers. Actual SafeSession requests, original check
wrappers, prompt receipts, canonical scoring and pipeline checkpoint projection
produced the archives. Only owned loopback targets were contacted. UUIDs and
timestamps were fixed at capture; keys, marker values, private labels and
environment references are absent. The helper imports no scanner producer.

The source hashes in manifest.json identify the original producer definitions.
Archive digests and expected identities are fixed separately from current code.
These are compatibility fixtures, not signed attestations or model evaluations.
"""

import hashlib
import json
from pathlib import Path


LEGACY_PRODUCER_REVISION = '0d60e09219212fd0f946367806e40661bbbe7ffc'
LEGACY_ARCHIVE_SHA256 = {
    'prompt-unfinished-checkpoint': '5a2e5d6b65e2762a5145cefd2f02c4d6d667132b48099193f75fb4721c515911',
    'prompt-final': 'f8a3b3b4bbda5206ca8d13d9745cff0d7ea00f52e8c14502961ad62ce422d3bc',
    'subject-final': 'cde8916984844168abe21bdb28725f4abd02b9867a6ae5f2f24bf6c7688a9466',
    'attack-final': 'b86b836a1c56cfde0785be1e10c4465b9743b6028e5c3d8471f8947bcc7c3176',
    'subject-partial-final': 'ca54df5a009d103e37cb71be7ef7b06004305def68b9819afeb4710014cff80c',
}
LEGACY_NAMES = tuple(LEGACY_ARCHIVE_SHA256)
_MANIFEST_SHA256 = '5a88d26b720307305fa7e90a051767848b1c9996a4512a17ba46f567324a4d94'
_FIXTURES = Path(__file__).parent / 'fixtures' / 'legacy_observations'


def legacy_archive(name):
    """Return original public bytes, refusing edits or arbitrary file paths."""
    expected = LEGACY_ARCHIVE_SHA256[name]
    raw = (_FIXTURES / (name + '.json')).read_bytes()
    if hashlib.sha256(raw).hexdigest() != expected:
        raise ValueError('Frozen legacy archive changed')
    return raw


def legacy_report(name):
    """Load an independent copy without restamping or rebuilding the archive."""
    return json.loads(legacy_archive(name))


def legacy_manifest():
    """Return the independently frozen expected IDs, probes and source hashes."""
    raw = (_FIXTURES / 'manifest.json').read_bytes()
    if hashlib.sha256(raw).hexdigest() != _MANIFEST_SHA256:
        raise ValueError('Frozen legacy manifest changed')
    return json.loads(raw)
