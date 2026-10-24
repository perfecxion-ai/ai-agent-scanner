"""A valid signature does not authorize compressed cursor payload formats."""

import base64
import hashlib
import zlib

import pytest
from itsdangerous import TimestampSigner
from sqlalchemy import event

from tests.test_api_auth import api as api, headers
from tests.test_inventory_independent import populate


@pytest.mark.parametrize('marker', [False, True], ids=['compressed-bytes', 'compression-marker'])
def test_signed_compressed_cursor_payload_is_rejected_before_sql(api, marker):
    module, client = api
    populate(module, 60)
    initial = client.get('/api/agents', query_string={'limit': 1}, headers=headers(module))
    assert initial.status_code == 200, initial.json
    signer = TimestampSigner(module.app.config['SECRET_KEY'], salt='aiscan-inventory-v1',
                             digest_method=hashlib.sha256)
    payload = signer.unsign(initial.json['next_cursor'])
    raw = base64.urlsafe_b64decode(payload + b'=' * (-len(payload) % 4))
    compressed = base64.urlsafe_b64encode(zlib.compress(raw)).rstrip(b'=')
    token = signer.sign((b'.' if marker else b'') + compressed).decode('ascii')
    assert len(token) < 4096
    statements = []
    def observed(connection, cursor, statement, parameters, context, executemany):
        statements.append(statement)
    event.listen(module.db.engine, 'before_cursor_execute', observed)
    try:
        response = client.get('/api/agents', query_string={'limit': 1, 'cursor': token}, headers=headers(module))
    finally:
        event.remove(module.db.engine, 'before_cursor_execute', observed)
    assert response.status_code == 400, response.json
    assert response.json['code'] == 'invalid_cursor'
    assert statements == []
