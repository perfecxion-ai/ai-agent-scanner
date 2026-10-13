"""Sensitive inputs and target-issued credentials never enter report exports."""

import json

import pytest

from src.core.redaction import collect_secrets, redact_secrets
from src.core.pipeline import run_pipeline, to_sarif
from tests.test_pipeline import asset, engines


@pytest.mark.parametrize('field,value,secret', [
    ('x-api-key', 'fixture-api-secret', 'fixture-api-secret'),
    ('Authorization', 'Bearer fixture-bearer-secret', 'fixture-bearer-secret'),
    ('endpoint', 'https://name:fixture-password@host/?api_key=fixture-query-secret', 'fixture-query-secret'),
    ('endpoint', 'https://name:fixture-password@host/', 'fixture-password'),
])
def test_credential_encodings_are_collected(field, value, secret):
    secrets = collect_secrets({field: value})
    assert secret in secrets
    output = redact_secrets({'description': f'Exposed {secret}', 'url': value}, secrets)
    assert secret not in json.dumps(output)


@pytest.mark.asyncio
async def test_target_cookie_and_url_credentials_absent_from_json_and_sarif():
    target = asset('https://fixture.invalid/?api_key=fixture-query-secret')
    target['headers'] = {'x-api-key': 'fixture-api-secret', 'authorization': 'Bearer fixture-bearer-secret'}
    discovery, security, risk = engines([target])
    result = security.test_agents.return_value[0]
    result['vulnerabilities'][0].update({
        'cookie': 'session=issued-secret; HttpOnly',
        'full_url': target['endpoint'],
        'description': 'fixture-query-secret fixture-api-secret fixture-bearer-secret issued-secret',
    })
    report = await run_pipeline(discovery, security, risk, None)
    for output in (report, to_sarif(report)):
        serialized = json.dumps(output)
        for secret in ('issued-secret', 'fixture-query-secret', 'fixture-api-secret', 'fixture-bearer-secret'):
            assert secret not in serialized
    assert report['agents'][0]['endpoint_redacted'] is True
