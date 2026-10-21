"""Private synthetic fixture started only by dashboard-browser-smoke.py."""

import argparse
import asyncio
import json
import os
from pathlib import Path
import secrets
import signal
import sys
import tempfile
from types import SimpleNamespace


def fixture_database(directory):
    """Accept only an empty, direct temporary fixture directory."""
    directory = Path(directory)
    if (not directory.is_absolute() or directory.resolve() != directory or directory.is_symlink()
            or directory.parent != Path(tempfile.gettempdir()).resolve()
            or not directory.name.startswith("ai-scanner-browser-db-") or not directory.is_dir()
            or any(directory.iterdir())):
        raise ValueError("Fixture requires a new empty temporary database directory")
    return directory / "fixture.db"


def guard_database(engine, database):
    actual = engine.url.database
    if (engine.dialect.name != "sqlite" or not actual or actual == ":memory:" or engine.url.query
            or Path(actual).resolve() != database.resolve()):
        raise ValueError("Fixture engine does not target the owned temporary SQLite database")


def main(directory):
    database = fixture_database(directory)
    os.environ.update(
        SECRET_KEY=secrets.token_hex(32), OPERATOR_API_KEY="browser-fixture-operator",
        OPERATOR_ORGANIZATION_ID="browser-fixture", DATABASE_URL="sqlite:///" + str(database),
        SCAN_ALLOWED_NETWORKS="127.0.0.1/32", SCAN_ALLOW_LOOPBACK="true",
        SCAN_ALLOWED_PATH_ROOTS="", MAX_CONCURRENT_SCANS="1", SCAN_TIMEOUT_SECONDS="60",
    )
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    import app
    from flask import abort, jsonify, request
    from werkzeug.serving import make_server

    with app.app.app_context():
        guard_database(app.db.engine, database)

    async def discover(scope):
        await asyncio.sleep(0)
        return []

    async def empty(values):
        return []

    app.discovery_engine = SimpleNamespace(discover_agents=discover)
    app.security_engine = SimpleNamespace(test_agents=empty)
    app.risk_assessor = SimpleNamespace(assess_risks=empty)
    control_key = secrets.token_hex(24)

    @app.app.route("/fixture/state", methods=["POST"])
    def state():
        data = request.get_json()
        if request.headers.get("X-Fixture-Key") != control_key:
            abort(403)
        if data.get("id") != "fixture-running" or data.get("status") not in ("running", "completed"):
            abort(400)
        row = app.db.session.get(app.ScanSession, data["id"])
        row.status, row.progress = data["status"], 20 if data["status"] == "running" else 100
        app.db.session.commit()
        return jsonify(success=True)

    def stop(*_):
        raise SystemExit(0)

    signal.signal(signal.SIGTERM, stop)
    server = None
    try:
        app.start_job_dispatcher()
        with app.app.app_context():
            for status in ("completed", "partial", "failed", "cancelled", "interrupted", "running"):
                identifier = "fixture-" + status
                checks = [dict(rule_id=f"fixture.check.{index}", status="completed", outcome="inconclusive",
                               requests_attempted=1, responses_evaluated=1, reason="Synthetic fixture only")
                          for index in range(110 if status == "partial" else 36)]
                report = dict(schema_version="1.0", check_schema_version="1.0", scan_id=identifier,
                              status=status, scan_type="full", risk_assessment_status="not_assessed",
                              agents=[dict(id="fixture-asset", name="<fixture>", provider="synthetic",
                                           security_status="completed", checks=checks, vulnerabilities=[])],
                              security_results=[], summary=dict(agents_tested=0, overall_risk_score=0))
                if status == "partial":
                    check = dict(rule_id="prompt_injection.system_prompt_extraction", probe_id="fixture-sample",
                                 probe_version="fixture-v2", status="failed", outcome="confirmed",
                                 requests_attempted=2, responses_evaluated=1, reason="Synthetic partial coverage")
                    checks[0] = check
                    report["risk_assessment_status"] = "partial"
                    report["summary"]["overall_risk_score"] = 70
                    report["agents"][0].update(
                        security_status="partial", risk_score=70, risk_scoring_policy="severity-floor-v2",
                        risk_coverage_status="partial", vulnerabilities=[dict(
                            rule_id=check["rule_id"], probe_id=check["probe_id"], probe_version=check["probe_version"],
                            evidence_status="confirmed", severity="high", title="Synthetic protected disclosure",
                            description="Fixture only; no generated text or protected value is stored")])
                app.db.session.add(app.ScanSession(id=identifier, organization_id="browser-fixture",
                    scan_name=identifier, scan_type="full", status=status, progress=20 if status == "running" else 100,
                    target_scope={}, scan_config={}))
                app.db.session.add(app.ScanResult(scan_id=identifier, result=report))
            app.db.session.commit()
        server = make_server("127.0.0.1", 0, app.app, threaded=True)
        print(json.dumps(dict(port=server.server_port, control_key=control_key)), flush=True)
        server.serve_forever()
    finally:
        if server:
            server.server_close()
        app.stop_job_dispatcher()
        with app.app.app_context():
            app.db.session.remove()
            app.db.engine.dispose()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", required=True)
    main(parser.parse_args().directory)
