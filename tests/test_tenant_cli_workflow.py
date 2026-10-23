"""Normal CLI scans exercise every tester stage against owned HTTP controls."""

import asyncio
import json
from types import SimpleNamespace
from unittest.mock import AsyncMock

from aiohttp import web
from click.testing import CliRunner
import pytest

import scanner_cli
from tests.test_tenant_controls import (
    configured_agent, prepared_environment as prepared_environment,
    OWNER_KEY, TESTED_KEY, OWNER_MARKER, TESTED_MARKER,
)
from src.core.tenant_probe_policy import TENANT_CONTROL_PROMPT, TENANT_ATTACK_PROMPTS


@pytest.fixture
async def cli_tenant_server():
    state = dict(mode='leak', calls=[])
    async def handler(request):
        if request.method != 'POST' or request.path != '/api/chat':
            await request.read()
            return web.json_response({'status': 'fixture ready'})
        body = await request.json()
        prompt = body['messages'][0]['content']
        key = request.headers.get('Authorization', '').removeprefix('Bearer ')
        state['calls'].append(dict(key=key, prompt=prompt))
        if key == OWNER_KEY and prompt == TENANT_CONTROL_PROMPT:
            text = OWNER_MARKER
        elif key == TESTED_KEY and prompt == TENANT_CONTROL_PROMPT:
            text = TESTED_MARKER
        elif key != TESTED_KEY:
            return web.Response(status=403, text='Denied')
        elif state['mode'] == 'leak' and prompt in TENANT_ATTACK_PROMPTS:
            text = OWNER_MARKER
        else:
            text = 'No foreign records disclosed'
        return web.json_response({'message': {'content': text}})
    application = web.Application()
    application.router.add_route('*', '/{tail:.*}', handler)
    runner = web.AppRunner(application)
    await runner.setup()
    site = web.TCPSite(runner, '127.0.0.1', 0)
    await site.start()
    try:
        yield f'http://127.0.0.1:{site._server.sockets[0].getsockname()[1]}', state
    finally:
        await runner.cleanup()


@pytest.mark.asyncio
@pytest.mark.parametrize('mode, expected', [('leak', 90.0), ('secure', None)])
async def test_full_cli_pipeline_retains_genuine_tenant_verdict(
        cli_tenant_server, monkeypatch, tmp_path, caplog, mode, expected):
    endpoint, state = cli_tenant_server
    state['mode'] = mode
    for module in ('prompt_injection_tests', 'access_control_tests', 'data_privacy_tests'):
        monkeypatch.setattr('src.security.' + module + '.asyncio', SimpleNamespace(
            sleep=AsyncMock(), CancelledError=asyncio.CancelledError))
    agent = configured_agent(endpoint)
    config, output = tmp_path / 'private-input.json', tmp_path / 'report.json'
    config.write_text(json.dumps({'agents': [agent]}))
    config.chmod(0o600)
    def invoke():
        return CliRunner().invoke(scanner_cli.cli, [
            'scan', '--config', str(config), '--allow-loopback', '--max-requests', '500',
            '--timeout-seconds', '45', '--request-timeout-seconds', '2', '--output', str(output)])
    result = await asyncio.wait_for(asyncio.to_thread(invoke), timeout=55)
    assert result.exit_code == 0, result.output
    report = json.loads(output.read_text())
    assert report['status'] == 'completed'
    assert report['summary']['overall_risk_score'] == expected
    asset = report['agents'][0]
    assert asset['risk_score'] == expected
    assert asset['risk_level'] == ('critical' if expected else 'unknown')
    checks = asset['checks']
    assert any(check['rule_id'].startswith('prompt_injection.') and check['status'] == 'completed'
               for check in checks)
    assert any(check['rule_id'] == 'unauthenticated_inference' and check['status'] == 'completed'
               for check in checks)
    tenant = next(check for check in checks if check['rule_id'] == 'tenant_isolation_violation')
    assert tenant['status'] == 'completed'
    assert tenant['outcome'] == ('confirmed' if expected else 'inconclusive')
    assert tenant['requests_attempted'] == tenant['responses_evaluated'] == 8
    assert len(state['calls']) > 8
    serialized = output.read_text() + result.output + caplog.text
    private_values = [OWNER_KEY, TESTED_KEY, OWNER_MARKER, TESTED_MARKER]
    private_values.extend(call['key'] for call in state['calls'] if call['key'])
    private_values.extend(actor[field] for actor in agent['tenant_evidence'].values()
                          if isinstance(actor, dict) for field in ('api_key_env', 'canary_env') if field in actor)
    assert all(value not in serialized for value in private_values)
    assert output.stat().st_mode & 0o777 == 0o600
