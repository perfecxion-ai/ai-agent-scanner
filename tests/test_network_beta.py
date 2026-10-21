"""Real local TLS and scoped resolution regressions from beta findings."""

import json
import ssl
from datetime import datetime, timedelta, timezone

import pytest
from aiohttp import web
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from src.core.scope import ScopePolicy, ScopeResolutionError
from src.mcp import live, policy


@pytest.mark.asyncio
async def test_real_untrusted_tls_has_specific_secret_safe_failure(tmp_path, monkeypatch):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'synthetic-private-hostname')])
    now = datetime.now(timezone.utc)
    certificate = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
                   .public_key(key.public_key()).serial_number(x509.random_serial_number())
                   .not_valid_before(now - timedelta(minutes=1)).not_valid_after(now + timedelta(days=1))
                   .sign(key, hashes.SHA256()))
    key_path, cert_path = tmp_path / 'key.pem', tmp_path / 'cert.pem'
    key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                          serialization.NoEncryption()))
    key_path.chmod(0o600)
    cert_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert_path, key_path)
    app = web.Application()
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, '127.0.0.1', 0, ssl_context=context)
    await site.start()
    endpoint = f'https://127.0.0.1:{site._server.sockets[0].getsockname()[1]}/mcp'
    monkeypatch.setenv('BETA_TOOL_MARKER', 'synthetic-protected-tool-1234567890')
    monkeypatch.setenv('BETA_BEARER', 'synthetic-fixture-bearer-1234567890')
    declared = {'version': 1, 'endpoint': endpoint, 'evidence_context_id': 'beta-fixture-v1',
                'fixture_provenance': 'operator_protected_tool', 'protected_tool_name_env': 'BETA_TOOL_MARKER',
                'authorization_required': True}
    try:
        reports = [await live.inventory(endpoint, ('127.0.0.1/32',), allow_loopback=True),
                   await policy.check(endpoint, ('127.0.0.1/32',), declared,
                                      allow_loopback=True, api_key_env='BETA_BEARER')]
    finally:
        await runner.cleanup()
    for report in reports:
        assert report['status'] == 'failed'
        assert report['reason'] == 'MCP TLS certificate verification failed'
        assert not report['findings']
        assert 'synthetic-private-hostname' not in json.dumps(report)
        assert all(check['outcome'] != 'passed' for check in report['checks'])


@pytest.mark.asyncio
async def test_mcp_unresolved_hostname_is_not_mislabeled_as_scope_violation(monkeypatch):
    def unresolved(self, hostname):
        raise ScopeResolutionError('synthetic resolver detail must stay private')

    monkeypatch.setattr(ScopePolicy, 'addresses', unresolved)
    report = await live.inventory('https://fixture.invalid/mcp', ('192.0.2.0/24',))
    assert report['reason'] == 'MCP endpoint hostname could not be resolved'
    assert report['requests_attempted'] == 0
    assert 'synthetic resolver' not in json.dumps(report)
