"""Kill the real dispatcher after first-response evidence, before category return."""

import asyncio
from datetime import datetime, timezone
import json
import os

import pytest
from sqlalchemy import MetaData, create_engine

from src.core.jobs import JobDispatcher, JobStore, current_claim_owner
from src.core.pipeline import run_pipeline
from src.core.transport import ScanBudget, scan_transport
from src.risk.risk_assessor import RiskAssessment
from src.security.prompt_suites import PROTECTED_DISCLOSURE_SUITE
from tests.prompt_progress_fixture import CANARY, disclosure_target, unfinished_prompt_engine
from tests.test_api_auth import api as api
from tests import test_checkpoint_recovery as finalized_recovery


def _run_prompt_checkpoint_process(database, acknowledgement, prompt_suite):
    os.environ['DATABASE_URL'] = 'sqlite:///:memory:'
    os.environ['SECRET_KEY'] = 'progress-process-signing-key-' * 4
    os.environ['OPERATOR_API_KEY'] = 'progress-process-operator-key'
    os.environ['OPERATOR_ORGANIZATION_ID'] = 'tenant-a'
    os.environ.pop('SCAN_EVIDENCE_PROFILES_FILE', None)
    from app import _snapshot_rows

    engine = create_engine('sqlite:///' + database)
    metadata = MetaData()
    metadata.reflect(bind=engine)
    store = JobStore(engine, metadata.tables['scan_job'], metadata.tables['scan_session'],
                     metadata.tables['scan_result'], metadata.tables['audit_event'])
    with disclosure_target() as (asset, calls):
        asset['id'] = 'recovery-asset'

        def run(scan_id, cancelled):
            latest = None
            observed_at = datetime.now(timezone.utc)

            async def persist(report):
                nonlocal latest
                report['scan_id'] = scan_id
                accepted = store.save_checkpoint(
                    scan_id, report, metadata.tables['discovered_agent'],
                    _snapshot_rows(scan_id, report, observed_at), owner=current_claim_owner(scan_id))
                if not accepted:
                    raise RuntimeError('Fixture checkpoint rejected')
                latest = report

            def acknowledge_after_response():
                # All checkpoint callbacks have returned, including scoring. The
                # first finding has not returned to its unfinished prompt category.
                assert latest is not None
                assert latest['summary']['overall_risk_score'] == 70
                assert latest['summary']['checks_unfinished'] == 1
                assert latest['summary']['checks_completed'] == 0
                current = latest['agents'][0]
                assert len(current['check_evidence']) == len(current['vulnerabilities']) == 1
                receipt = current['check_evidence'][0]
                assert receipt['finding_id'] == current['vulnerabilities'][0]['id']
                assert receipt['requests_attempted'] == receipt['responses_evaluated'] == 1
                assert not any(check['rule_id'] == receipt['rule_id'] for check in current['checks'])
                assert len(calls) == 1 and CANARY not in json.dumps(calls)
                acknowledgement.send(('committed', latest['checkpoint']['sequence']))

            security = unfinished_prompt_engine(acknowledge_after_response, prompt_suite=prompt_suite)
            with scan_transport(ScanBudget(allowed_networks=('127.0.0.1/32',), allow_loopback=True,
                                           max_requests=5, max_response_bytes=8192)):
                asyncio.run(run_pipeline(None, security, RiskAssessment(), None, 'security_only',
                                         agents=[asset], checkpoint_callback=persist))

        dispatcher = JobDispatcher(store, run, workers=1, poll_seconds=0.01)
        dispatcher.start()
        asyncio.run(asyncio.Event().wait())


def prompt_checkpoint_process(database, acknowledgement):
    _run_prompt_checkpoint_process(database, acknowledgement, None)


def candidate_checkpoint_process(database, acknowledgement):
    _run_prompt_checkpoint_process(database, acknowledgement, PROTECTED_DISCLOSURE_SUITE)


@pytest.mark.skipif(os.name != 'posix', reason='Supported dispatcher requires POSIX')
@pytest.mark.parametrize('child', [prompt_checkpoint_process, candidate_checkpoint_process])
def test_killed_unfinished_prompt_preserves_real_receipt_without_replay(api, tmp_path, monkeypatch, child):
    # Reuse the exact stopped-process, claim, snapshot, restart, privacy, and
    # canonical risk assertions from finalized-check recovery. Only the producer
    # changes: this child acknowledges genuine first-response prompt evidence.
    monkeypatch.setattr(finalized_recovery, 'checkpoint_process', child)
    monkeypatch.setattr(finalized_recovery, 'PRIVATE_CANARY', CANARY)
    finalized_recovery.test_killed_dispatcher_preserves_acknowledged_evidence_without_replay(api, tmp_path)
