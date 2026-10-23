"""Real access-check producers with a synthetic, non-network HTTP transport."""

from contextlib import contextmanager
from unittest.mock import AsyncMock, patch

from src.core.contracts import collect_checks
from src.core.transport import ScanBudget, current_budget, scan_transport
from src.security.access_control_tests import AccessControlTester


MARKER = 'protected-fixture-proof-70b45af2'
ISSUED = 'issued-fixture-key-8f14bce3'
REFERENCE = 'CONTROL_PROJECTION_FIXTURE_KEY'
METHODS = {
    'authentication_bypass': '_test_authentication_bypass',
    'weak_credentials': '_test_weak_credentials',
    'weak_api_key': '_test_api_key_security',
    'authorization_bypass': '_test_authorization_bypass',
}


def target(**overrides):
    return {'id': 'fixture', 'name': 'Fixture', 'type': 'assistant',
            'provider': 'openai-compatible', 'model': 'fixture-model',
            'endpoint': 'http://192.0.2.1/resource', 'metadata': {},
            'authentication_required': True, 'api_key_env': REFERENCE,
            'protected_response_marker': MARKER, 'protected_path_markers': {'/admin': MARKER},
            'evidence_context_id': 'controlled-resource-fixture-v1', **overrides}


@contextmanager
def transport(*, disclose=False):
    class Response:
        def __init__(self, status, body):
            self.status, self.body = status, body

        async def text(self):
            return self.body

    class Request:
        def __init__(self, url, headers):
            self.url, self.headers = url, headers

        async def __aenter__(self):
            current_budget().reserve(self.url)
            credential = next((value for key, value in self.headers.items()
                               if key.lower() in {'authorization', 'x-api-key', 'x-goog-api-key'}), '')
            if credential in {ISSUED, 'Bearer ' + ISSUED}:
                return Response(200, MARKER)
            if 'scanner-invalid-' in credential:
                return Response(401, 'Denied')
            return Response(200, MARKER) if disclose else Response(403, 'Denied')

        async def __aexit__(self, *args):
            return False

    class Session:
        def __init__(self, **kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return False

        def get(self, url, *, headers, allow_redirects):
            assert allow_redirects is False
            return Request(url, headers)

    with patch.dict('os.environ', {REFERENCE: ISSUED}), \
            patch('src.security.access_control_tests.SafeSession', Session), \
            patch('src.security.access_control_tests.asyncio.sleep', AsyncMock()):
        yield


async def result(agent=None, *, rule='authentication_bypass', disclose=False):
    agent = target() if agent is None else agent
    with transport(disclose=disclose), scan_transport(ScanBudget()), collect_checks() as checks:
        findings = await getattr(AccessControlTester(), METHODS[rule])(agent)
    return {'agent_id': agent['id'], 'agent_name': agent['name'],
            'provider': agent['provider'], 'model': agent['model'],
            'status': 'completed' if checks[0]['status'] == 'completed' else 'partial',
            'check_schema_version': '1.0', 'checks': checks, 'vulnerabilities': findings}
