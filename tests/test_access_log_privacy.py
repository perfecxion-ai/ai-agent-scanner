"""Fresh default CLI phase logs never emit protected agent-name collisions."""

import base64
import json
import os
from pathlib import Path
import subprocess
import sys
from urllib.parse import quote

import pytest

from tests.access_provenance_fixture import ISSUED, MARKER, REFERENCE


ROOT = Path(__file__).resolve().parents[1]
PHASES = ('Testing prompt injection checks', 'Testing access controls', 'Testing data privacy checks')
CHILD = r'''
import asyncio
import json
import logging
import os
from pathlib import Path
import sys
from unittest.mock import AsyncMock, patch

source, destination, kind = Path(sys.argv[1]), Path(sys.argv[2]), sys.argv[3]
sys.path.insert(0, str(source))
profiles = destination / 'private-profiles.json'
profiles.write_text('Synthetic registry must not be read')
profiles.chmod(0o600)
os.environ['SCAN_EVIDENCE_PROFILES_FILE'] = str(profiles)
guarded = []

def audit(event, arguments):
    if event == 'sqlite3.connect':
        guarded.append('database')
        raise AssertionError('Logging fixture cannot access databases')
    if event == 'open' and arguments and str(arguments[0]) == str(profiles):
        guarded.append('profiles')
        raise AssertionError('Logging fixture cannot read private profiles')

sys.addaudithook(audit)

import click
import scanner_cli
from src.core.files import write_private_text
from src.security.security_engine import SecurityTestEngine
from tests.access_provenance_fixture import ISSUED, MARKER, REFERENCE, access_target

class Capture(logging.Handler):
    def __init__(self):
        super().__init__()
        self.records = []
    def emit(self, record):
        self.records.append({'logger': record.name, 'level': record.levelname, 'message': record.getMessage()})

async def main():
    assert logging.getLogger().level == logging.WARNING
    assert logging.getLogger().handlers == []
    private = {'marker': MARKER, 'key': ISSUED, 'reference': REFERENCE}[kind]
    capture = Capture()
    for suffix in ('prompt_injection_tests', 'access_control_tests', 'data_privacy_tests'):
        logger = logging.getLogger('src.security.' + suffix)
        assert logger.level == logging.NOTSET and logger.propagate
        logger.addHandler(capture)
    engine = SecurityTestEngine()
    engine.prompt_tester.injection_payloads = {}
    for name in ('_test_unauthenticated_inference', '_test_rate_limiting', '_test_session_management'):
        setattr(engine.access_tester, name, AsyncMock(return_value=[]))
    for name in ('_test_pii_disclosure', '_test_tenant_isolation', '_test_data_retention',
                 '_test_privacy_compliance', '_test_error_information_disclosure'):
        setattr(engine.privacy_tester, name, AsyncMock(return_value=[]))
    called = []
    def tracked(label, actual):
        async def execute(agent):
            called.append(label)
            return await actual(agent)
        return execute
    for label, tester in (('prompt', engine.prompt_tester), ('access', engine.access_tester),
                          ('privacy', engine.privacy_tester)):
        assert tester.test_agent.__func__.__module__.startswith('src.security.')
        tester.test_agent = tracked(label, tester.test_agent)
    output = destination / 'report.json'
    async with access_target() as (agent, state):
        agent['name'] = private
        error = None
        with patch.object(scanner_cli, 'SecurityTestEngine', return_value=engine):
            try:
                await scanner_cli._execute(None, [agent], str(output), 'json', 'security_only', False,
                    max_requests=100, max_response_bytes=16384, timeout_seconds=10,
                    request_timeout_seconds=2, allow_loopback=True)
            except click.ClickException as exception:
                error = str(exception)
        wire_count = len(state.calls)
    metadata = {'root_level': logging.getLogger().level, 'phase_calls': called,
                'wire_count': wire_count, 'error': error, 'forbidden_accesses': guarded}
    write_private_text(str(destination / 'metadata.json'), json.dumps(metadata))
    write_private_text(str(destination / 'phase-logs.json'), json.dumps(capture.records))

asyncio.run(main())
'''


def private_forms(value):
    encoded = (base64.b64encode(value.encode()).decode(), base64.urlsafe_b64encode(value.encode()).decode())
    return {value, quote(value, safe=''), json.dumps(value)[1:-1], *encoded,
            *(item.rstrip('=') for item in encoded)}


@pytest.mark.parametrize('kind', ['marker', 'key', 'reference'])
def test_fresh_cli_logs_static_phases_and_redacts_protected_agent_names(tmp_path, kind):
    destination = tmp_path.resolve()
    environment = {key: value for key, value in os.environ.items() if key in {'PATH', 'LANG', 'LC_ALL', 'LC_CTYPE'}}
    process = subprocess.run([sys.executable, '-I', '-Werror', '-c', CHILD, str(ROOT), str(destination), kind],
                             cwd=destination, env=environment, capture_output=True, text=True, timeout=30)
    assert process.returncode == 0, process.stderr
    metadata = json.loads((destination / 'metadata.json').read_text())
    records_text = (destination / 'phase-logs.json').read_text()
    records = json.loads(records_text)
    report_text = (destination / 'report.json').read_text()
    report = json.loads(report_text)
    assert metadata['root_level'] == 20
    assert metadata['phase_calls'] == ['prompt', 'access', 'privacy']
    assert metadata['forbidden_accesses'] == []
    assert [record['message'] for record in records] == list(PHASES)
    assert all(record['level'] == 'INFO' for record in records)
    assert all(message in process.stderr for message in PHASES)
    assert report['agents'][0]['name'] == '[redacted]'
    assert report['security_results'][0]['agent_name'] == '[redacted]'
    combined = process.stdout + process.stderr + records_text + report_text
    assert all(form.casefold() not in combined.casefold()
               for value in (MARKER, ISSUED, REFERENCE) for form in private_forms(value))
    if kind == 'marker':
        assert metadata['wire_count'] == 0
        assert metadata['error'] == 'No security checks completed; configure an explicit model or inspect skipped prerequisites'
        assert report['summary']['overall_risk_score'] is None
    else:
        assert metadata['wire_count'] == 62
        assert metadata['error'] is None
        assert report['status'] == 'completed' and report['summary']['overall_risk_score'] == 0
    for name in ('report.json', 'metadata.json', 'phase-logs.json'):
        assert (destination / name).stat().st_mode & 0o777 == 0o600
