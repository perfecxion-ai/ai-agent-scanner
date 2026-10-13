"""
AI Agent Scanner — Flask Web Application and REST API

Provides a web dashboard and REST API for managing AI agent discovery
scans, security testing, and risk assessment.

Environment variables:
    SECRET_KEY          — Required. Used for JWT signing and Flask sessions.
    DATABASE_URL        — Database URI (default: sqlite:///ai_agent_scanner.db)
    ALLOWED_ORIGINS     — Comma-separated CORS origins (default: http://localhost:5000)
    PORT                — Listen port (default: 5000)
    FLASK_DEBUG         — Enable debug mode (default: false)
"""

import os
import threading
import asyncio
import hmac
import uuid
from contextlib import suppress
from datetime import datetime, timezone
from typing import Dict, Any

from flask import Flask, render_template, request, jsonify, g
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy import String, DateTime, Integer, Float, Boolean, Text, JSON, select
from werkzeug.exceptions import HTTPException

from src.discovery.discovery_engine import DiscoveryEngine, DiscoveryScope
from src.security.security_engine import SecurityTestEngine
from src.risk.risk_assessor import RiskAssessment
from src.compliance.compliance_engine import ComplianceEngine
from src.reporting.report_generator import ReportGenerator
from src.utils.auth import require_auth, create_jwt_token
from src.utils.helpers import generate_scan_id
from src.core.pipeline import run_pipeline, to_sarif
from src.core.model_selection import apply_model_overrides
from src.core.scope import bounded_integer, validate_request, validate_agent_endpoints, ScopeValidationError
from src.core.transport import ScanBudget, scan_transport, TransportPolicyError
from src.core.jobs import JobStore, JobDispatcher, TERMINAL_STATES

# ---------------------------------------------------------------------------
# App factory
# ---------------------------------------------------------------------------

app = Flask(__name__)

# --- SECRET_KEY: fail loudly if not set (except in debug/testing) ---
_secret = os.environ.get("SECRET_KEY")
_debug = os.environ.get("FLASK_DEBUG", "false").lower() == "true"
if not _secret and (not _debug or os.environ.get("OPERATOR_API_KEY")):
    raise RuntimeError(
        "SECRET_KEY environment variable must be set in production. "
        "It is also required whenever operator authentication is enabled."
    )
app.config["SECRET_KEY"] = _secret or "dev-only-insecure-key-do-not-use-in-prod"

app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get(
    "DATABASE_URL", "sqlite:///ai_agent_scanner.db"
)
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["OPERATOR_API_KEY"] = os.environ.get("OPERATOR_API_KEY", "")
app.config["OPERATOR_ORGANIZATION_ID"] = os.environ.get("OPERATOR_ORGANIZATION_ID", "default")
app.config["MAX_CONTENT_LENGTH"] = 64 * 1024
app.config["SCAN_ALLOWED_NETWORKS"] = tuple(filter(None, (
    value.strip() for value in os.environ.get("SCAN_ALLOWED_NETWORKS", "").split(",")
)))
app.config["SCAN_ALLOWED_PATH_ROOTS"] = tuple(filter(None, os.environ.get(
    "SCAN_ALLOWED_PATH_ROOTS", ""
).split(os.pathsep)))
app.config["SCAN_ALLOW_LOOPBACK"] = os.environ.get("SCAN_ALLOW_LOOPBACK", "false").lower() == "true"
for _setting, _default, _maximum in (
    ("SCAN_MAX_HOSTS", 1024, 65536), ("SCAN_MAX_FILES", 10000, 100000),
    ("SCAN_TIMEOUT_SECONDS", 300, 3600), ("MAX_CONCURRENT_SCANS", 2, 32),
    ("SCAN_MAX_REQUESTS", 500, 10000), ("SCAN_MAX_RESPONSE_BYTES", 1048576, 16777216),
    ("SCAN_MAX_QUEUED", 32, 10000),
):
    app.config[_setting] = bounded_integer(int(os.environ.get(_setting, _default)), _setting, _maximum)

# --- CORS: restricted to explicit origins ---
_allowed_origins = os.environ.get("ALLOWED_ORIGINS", "http://localhost:5000")
CORS(app, resources={r"/api/*": {"origins": _allowed_origins.split(",")}})

# --- Database ---
db = SQLAlchemy(app)

# --- Core engines ---
discovery_engine = DiscoveryEngine()
security_engine = SecurityTestEngine()
risk_assessor = RiskAssessment()
compliance_engine = ComplianceEngine()
report_generator = ReportGenerator()

# --- Thread-safe scan tracking ---
_active_scans: Dict[str, Dict[str, Any]] = {}
_scans_lock = threading.Lock()
_admission_lock = threading.Lock()
_dispatcher_lock = threading.Lock()
_job_dispatcher = None

VERSION = "1.1.0"


class SourceReplayError(ValueError):
    """A persisted source requires new explicit target configuration."""


# ---------------------------------------------------------------------------
# Database models
# ---------------------------------------------------------------------------

def _utcnow():
    return datetime.now(timezone.utc)


class ScanSession(db.Model):
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    organization_id: Mapped[str] = mapped_column(String(64), nullable=False)
    scan_name: Mapped[str] = mapped_column(String(255), nullable=False)
    scan_type: Mapped[str] = mapped_column(String(50), nullable=False)
    status: Mapped[str] = mapped_column(String(50), nullable=False, default="pending")
    progress: Mapped[float] = mapped_column(Float, default=0.0)

    target_scope: Mapped[dict] = mapped_column(JSON)
    scan_config: Mapped[dict] = mapped_column(JSON)

    agents_discovered: Mapped[int] = mapped_column(Integer, default=0)
    vulnerabilities_found: Mapped[int] = mapped_column(Integer, default=0)
    critical_risks: Mapped[int] = mapped_column(Integer, default=0)
    overall_risk_score: Mapped[float] = mapped_column(Float, default=0.0)

    created_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)
    started_at: Mapped[datetime] = mapped_column(DateTime, nullable=True)
    completed_at: Mapped[datetime] = mapped_column(DateTime, nullable=True)

    created_by: Mapped[str] = mapped_column(String(255), nullable=True)
    user_ip: Mapped[str] = mapped_column(String(45), nullable=True)


class DiscoveredAgentModel(db.Model):
    __tablename__ = "discovered_agent"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    scan_id: Mapped[str] = mapped_column(String(64), nullable=False)

    agent_name: Mapped[str] = mapped_column(String(255), nullable=False)
    agent_type: Mapped[str] = mapped_column(String(100), nullable=False)
    provider: Mapped[str] = mapped_column(String(100), nullable=True)
    model_name: Mapped[str] = mapped_column(String(255), nullable=True)

    endpoint_url: Mapped[str] = mapped_column(Text, nullable=True)
    network_location: Mapped[str] = mapped_column(String(255), nullable=True)
    discovery_method: Mapped[str] = mapped_column(String(100), nullable=False)

    security_tested: Mapped[bool] = mapped_column(Boolean, default=False)
    vulnerabilities: Mapped[dict] = mapped_column(JSON, default=dict)
    risk_score: Mapped[float] = mapped_column(Float, default=0.0)
    risk_level: Mapped[str] = mapped_column(String(20), default="unknown")

    metadata_json: Mapped[dict] = mapped_column("metadata", JSON, default=dict)
    discovered_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)


class ScanResult(db.Model):
    """Complete versioned output; separate table preserves existing database schemas."""

    scan_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    result: Mapped[dict] = mapped_column(JSON, nullable=False)


class ScanJob(db.Model):
    """Persistent queue state; each scan has at most one execution attempt."""

    scan_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="queued", index=True)
    owner: Mapped[str] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=_utcnow)
    started_at: Mapped[datetime] = mapped_column(DateTime, nullable=True)
    completed_at: Mapped[datetime] = mapped_column(DateTime, nullable=True)


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route("/")
def dashboard():
    return render_template("dashboard.html")


@app.route("/api/auth/token", methods=["POST"])
def get_token():
    """Authenticate the configured operator; identity is controlled by the server."""
    expected = app.config["OPERATOR_API_KEY"]
    if not expected:
        return jsonify({"success": False, "error": "Operator authentication is not configured"}), 503
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({"success": False, "error": "JSON object required"}), 400
    supplied = data.get("api_key")
    if not isinstance(supplied, str) or not hmac.compare_digest(
        supplied.encode("utf-8"), expected.encode("utf-8")
    ):
        return jsonify({"success": False, "error": "Invalid credentials"}), 401

    token = create_jwt_token(
        {"user_id": "operator", "organization_id": app.config["OPERATOR_ORGANIZATION_ID"]},
        app.config["SECRET_KEY"],
    )
    response = jsonify({"success": True, "token": token})
    response.headers["Cache-Control"] = "no-store"
    return response


@app.route("/api/scans", methods=["GET"])
@require_auth
def list_scans():
    """List only the authenticated organization's saved scan summaries."""
    try:
        limit = int(request.args.get("limit", "25"))
        offset = int(request.args.get("offset", "0"))
    except ValueError:
        return jsonify({"success": False, "error": "Invalid pagination"}), 400
    if not 1 <= limit <= 100 or not 0 <= offset <= 100000:
        return jsonify({"success": False, "error": "Invalid pagination"}), 400
    query = ScanSession.query.filter_by(organization_id=g.user["organization_id"])
    scans = query.order_by(ScanSession.created_at.desc(), ScanSession.id.desc()).offset(offset).limit(limit).all()
    return jsonify({
        "success": True, "total": query.count(), "limit": limit, "offset": offset,
        "scans": [{
            "scan_id": scan.id, "scan_name": scan.scan_name, "scan_type": scan.scan_type,
            "status": scan.status, "created_at": scan.created_at.isoformat(),
            "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
            "agents_discovered": scan.agents_discovered,
            "vulnerabilities_found": scan.vulnerabilities_found,
        } for scan in scans],
    })


@app.route("/api/scans", methods=["POST"])
@require_auth
def start_scan():
    """Persist a scan and queue entry in one transaction."""
    try:
        scan_name, scan_type, target_scope, scan_config = validate_request(
            request.get_json(silent=True), app.config,
        )
        if scan_type == "security_only":
            source = ScanSession.query.filter_by(
                id=scan_config["source_scan_id"], organization_id=g.user["organization_id"],
            ).first()
            if source is None:
                return jsonify({"success": False, "error": "Source scan not found"}), 404
            if source.status != "completed":
                return jsonify({"success": False, "error": "Source scan must be completed"}), 400
            previous = db.session.get(ScanResult, source.id)
            if not previous:
                return jsonify({"success": False, "error": "Source scan has no versioned results"}), 400
            if any(agent.get("endpoint_redacted") for agent in previous.result.get("agents", [])):
                return jsonify({"success": False, "error": "Source endpoints were redacted; supply fresh targets"}), 400
            try:
                apply_model_overrides(previous.result.get("agents", []), scan_config.get("model_overrides", {}))
            except ValueError as exc:
                raise ScopeValidationError(str(exc)) from exc
            source_agents = DiscoveredAgentModel.query.filter_by(scan_id=source.id).all()
            if not source_agents:
                return jsonify({"success": False, "error": "Source scan has no assets"}), 400
            validate_agent_endpoints([{"endpoint": agent.endpoint_url} for agent in source_agents], app.config)

        scan_id = generate_scan_id()
        scan_session = ScanSession(
            id=scan_id,
            organization_id=g.user["organization_id"],
            scan_name=scan_name,
            scan_type=scan_type,
            target_scope=target_scope,
            scan_config=scan_config,
            created_by=g.user.get("user_id"),
            user_ip=request.remote_addr,
            status="queued",
        )
        with _admission_lock:
            if ScanJob.query.filter_by(status="queued").count() >= app.config["SCAN_MAX_QUEUED"]:
                return jsonify({"success": False, "error": "Scan queue is full"}), 429
            db.session.add(scan_session)
            db.session.add(ScanJob(scan_id=scan_id))
            db.session.commit()
        if _job_dispatcher:
            _job_dispatcher.wake()
        return jsonify({"success": True, "scan_id": scan_id, "message": "Scan queued"}), 202

    except ScopeValidationError as e:
        return jsonify({"success": False, "error": str(e)}), 400
    except HTTPException as e:
        return jsonify({"success": False, "error": e.description}), e.code
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error starting scan: {e}", exc_info=True)
        return jsonify({"success": False, "error": "Failed to start scan"}), 500


@app.route("/api/scans/<scan_id>/cancel", methods=["POST"])
@require_auth
def cancel_scan(scan_id):
    scan = ScanSession.query.filter_by(id=scan_id, organization_id=g.user["organization_id"]).first()
    if scan is None:
        return jsonify({"success": False, "error": "Scan not found"}), 404
    if scan.status in TERMINAL_STATES:
        return jsonify({"success": False, "error": "Scan is already terminal"}), 409
    status = _get_job_store().cancel(scan_id)
    if status is None:
        return jsonify({"success": False, "error": "Scan is not cancellable"}), 409
    if _job_dispatcher:
        _job_dispatcher.wake()
    return jsonify({"success": True, "scan_id": scan_id, "status": status}), 202


@app.route("/api/scans/<scan_id>/status")
@require_auth
def get_scan_status(scan_id):
    """Get current scan status and progress."""
    try:
        scan_session = ScanSession.query.filter_by(
            id=scan_id, organization_id=g.user["organization_id"]
        ).first()
        if not scan_session:
            return jsonify({"success": False, "error": "Scan not found"}), 404

        with _scans_lock:
            live = _active_scans.get(scan_id, {})

        return jsonify({
            "success": True,
            "scan_id": scan_id,
            "status": scan_session.status,
            "progress": scan_session.progress,
            "current_phase": live.get("current_phase", ""),
            "agents_discovered": scan_session.agents_discovered,
            "vulnerabilities_found": scan_session.vulnerabilities_found,
            "started_at": scan_session.started_at.isoformat() if scan_session.started_at else None,
            "estimated_completion": live.get("estimated_completion"),
        })

    except Exception as e:
        app.logger.error(f"Error fetching scan status: {e}", exc_info=True)
        return jsonify({"success": False, "error": "Internal server error"}), 500


@app.route("/api/scans/<scan_id>/results")
@require_auth
def get_scan_results(scan_id):
    """Get complete scan results."""
    try:
        scan_session = ScanSession.query.filter_by(
            id=scan_id, organization_id=g.user["organization_id"]
        ).first()
        if not scan_session:
            return jsonify({"success": False, "error": "Scan not found"}), 404

        agents = DiscoveredAgentModel.query.filter_by(scan_id=scan_id).all()
        persisted = db.session.get(ScanResult, scan_id)

        results = {
            "scan_info": {
                "id": scan_session.id,
                "name": scan_session.scan_name,
                "type": scan_session.scan_type,
                "status": scan_session.status,
                "created_at": scan_session.created_at.isoformat(),
                "completed_at": scan_session.completed_at.isoformat() if scan_session.completed_at else None,
            },
            "summary": {
                "agents_discovered": scan_session.agents_discovered,
                "vulnerabilities_found": scan_session.vulnerabilities_found,
                "critical_risks": scan_session.critical_risks,
                "overall_risk_score": scan_session.overall_risk_score,
            },
            "agents": [
                {
                    "id": agent.id,
                    "asset_id": agent.metadata_json.get("asset_id", agent.id),
                    "security_status": agent.metadata_json.get("security_status", "unknown"),
                    "name": agent.agent_name,
                    "type": agent.agent_type,
                    "provider": agent.provider,
                    "endpoint": agent.endpoint_url,
                    "risk_score": agent.risk_score,
                    "risk_level": agent.risk_level,
                    "vulnerabilities": agent.vulnerabilities,
                    "discovered_at": agent.discovered_at.isoformat(),
                }
                for agent in agents
            ],
        }
        results["pipeline"] = persisted.result if persisted else None

        return jsonify({"success": True, "results": results})

    except Exception as e:
        app.logger.error(f"Error fetching results: {e}", exc_info=True)
        return jsonify({"success": False, "error": "Internal server error"}), 500


@app.route("/api/scans/<scan_id>/report")
@require_auth
def export_scan_report(scan_id):
    scan = ScanSession.query.filter_by(id=scan_id, organization_id=g.user["organization_id"]).first()
    if not scan:
        return jsonify({"success": False, "error": "Scan not found"}), 404
    result = db.session.get(ScanResult, scan_id)
    if not result:
        return jsonify({"success": False, "error": "Report not available"}), 409
    output_format = request.args.get("format", "json")
    if output_format not in {"json", "sarif"}:
        return jsonify({"success": False, "error": "Supported formats: json, sarif"}), 400
    response = jsonify(to_sarif(result.result) if output_format == "sarif" else result.result)
    response.headers["Cache-Control"] = "no-store"
    return response


@app.route("/api/agents")
@require_auth
def list_agents():
    """List all discovered agents across scans."""
    try:
        org_id = g.user["organization_id"]
        risk_level = request.args.get("risk_level")
        agent_type = request.args.get("agent_type")

        query = db.session.query(DiscoveredAgentModel).join(
            ScanSession, DiscoveredAgentModel.scan_id == ScanSession.id
        ).filter(ScanSession.organization_id == org_id)

        if risk_level:
            query = query.filter(DiscoveredAgentModel.risk_level == risk_level)
        if agent_type:
            query = query.filter(DiscoveredAgentModel.agent_type == agent_type)

        agents = query.order_by(DiscoveredAgentModel.discovered_at.desc()).limit(100).all()

        return jsonify({
            "success": True,
            "agents": [
                {
                    "id": agent.id,
                    "name": agent.agent_name,
                    "type": agent.agent_type,
                    "provider": agent.provider,
                    "risk_score": agent.risk_score,
                    "risk_level": agent.risk_level,
                    "discovered_at": agent.discovered_at.isoformat(),
                }
                for agent in agents
            ],
        })

    except Exception as e:
        app.logger.error(f"Error listing agents: {e}", exc_info=True)
        return jsonify({"success": False, "error": "Internal server error"}), 500


@app.route("/health")
@app.route("/health/live")
def health_check():
    return jsonify({
        "status": "healthy",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "version": VERSION,
    })


@app.route("/health/ready")
def readiness_check():
    try:
        db.session.execute(select(1))
        db.session.execute(select(ScanJob.scan_id).limit(1))
        ready = bool(_job_dispatcher and _job_dispatcher.ready)
    except Exception:
        db.session.rollback()
        ready = False
    return jsonify({"status": "ready" if ready else "not_ready"}), 200 if ready else 503


# ---------------------------------------------------------------------------
# Background scan execution
# ---------------------------------------------------------------------------

def _get_job_store():
    return JobStore(db.engine, ScanJob.__table__, ScanSession.__table__, ScanResult.__table__)


def start_job_dispatcher():
    global _job_dispatcher
    with _dispatcher_lock:
        if _job_dispatcher is not None:
            return _job_dispatcher
        with app.app_context():
            db.create_all()
            dispatcher = JobDispatcher(_get_job_store(), _execute_job,
                                       workers=app.config["MAX_CONCURRENT_SCANS"])
            dispatcher.start()
        _job_dispatcher = dispatcher
        return dispatcher


def stop_job_dispatcher():
    if _job_dispatcher:
        _job_dispatcher.stop()


def _execute_job(scan_id, cancelled):
    with app.app_context():
        scan = db.session.get(ScanSession, scan_id)
        if not scan:
            raise ValueError("Job has no scan")
        # Queued jobs must obey the current server policy, not an earlier allowlist.
        _, scan_type, scope, options = validate_request({
            "scan_type": scan.scan_type, "scan_name": scan.scan_name,
            "target_scope": scan.target_scope, "scan_config": scan.scan_config,
        }, app.config)
    _run_scan_in_thread(scan_id, scan_type, scope, options, cancelled)


def _record_terminal(scan_id, status, error):
    with app.app_context():
        scan = db.session.get(ScanSession, scan_id)
        if not scan:
            return
        scan.status, scan.completed_at = status, datetime.now(timezone.utc)
        stored = db.session.get(ScanResult, scan_id)
        result = dict(stored.result) if stored else {
            "schema_version": "1.0", "scan_id": scan_id, "scan_type": scan.scan_type,
            "agents": [], "security_results": [], "risk_assessments": [], "summary": {},
        }
        result.update(status=status, error=error)
        if stored:
            stored.result = result
        else:
            db.session.add(ScanResult(scan_id=scan_id, result=result))
        db.session.commit()


async def _await_scan(scan_id, scan_type, target_scope, scan_config, cancelled):
    if cancelled is not None and cancelled.is_set():
        raise asyncio.CancelledError
    task = asyncio.create_task(_execute_scan(scan_id, scan_type, target_scope, scan_config))
    timeout = scan_config.get("timeout_seconds", app.config["SCAN_TIMEOUT_SECONDS"])
    deadline = asyncio.get_running_loop().time() + timeout
    try:
        while not task.done():
            if cancelled is not None and cancelled.is_set():
                raise asyncio.CancelledError
            remaining = deadline - asyncio.get_running_loop().time()
            if remaining <= 0:
                raise TimeoutError("Scan deadline exceeded")
            await asyncio.wait({task}, timeout=min(0.1, remaining))
        return await task
    finally:
        if not task.done():
            task.cancel()
            with suppress(asyncio.CancelledError):
                await task


def _run_scan_in_thread(scan_id: str, scan_type: str, target_scope: dict, scan_config: dict,
                        cancelled=None):
    """Run scan in a background thread with its own event loop."""
    loop = asyncio.new_event_loop()
    try:
        asyncio.set_event_loop(loop)
        budget = ScanBudget(
            allowed_networks=app.config["SCAN_ALLOWED_NETWORKS"],
            allow_loopback=app.config["SCAN_ALLOW_LOOPBACK"],
            max_requests=app.config["SCAN_MAX_REQUESTS"],
            max_response_bytes=app.config["SCAN_MAX_RESPONSE_BYTES"],
        )
        with scan_transport(budget):
            loop.run_until_complete(
                _await_scan(scan_id, scan_type, target_scope, scan_config, cancelled)
            )
        if budget.rejections or budget.failures:
            with app.app_context():
                stored = db.session.get(ScanResult, scan_id)
                session = db.session.get(ScanSession, scan_id)
                if stored and session:
                    session.status = "partial"
                    stored.result = {**stored.result, "status": "partial"}
                    db.session.commit()
                else:
                    raise TransportPolicyError("Scan encountered rejected or failed requests")
    except asyncio.CancelledError:
        with app.app_context():
            requested = _get_job_store().cancellation_requested(scan_id)
        status = "cancelled" if requested else "interrupted"
        _record_terminal(scan_id, status, "Scan cancelled" if requested else "Server stopped during scan")
    except TimeoutError:
        _record_terminal(scan_id, "failed", "Scan deadline exceeded")
    except Exception as e:
        app.logger.error(f"Scan thread error: {e}", exc_info=True)
        _record_terminal(scan_id, "failed", "Scan worker failed")
    finally:
        loop.close()
        with _scans_lock:
            _active_scans.pop(scan_id, None)


async def _execute_scan(scan_id: str, scan_type: str, target_scope: dict, scan_config: dict):
    """Execute the full scan pipeline."""

    # Mark scan as running
    with app.app_context():
        scan_session = db.session.get(ScanSession, scan_id)
        scan_session.status = "running"
        scan_session.started_at = datetime.now(timezone.utc)
        db.session.commit()

    try:
        with _scans_lock:
            _active_scans[scan_id] = {
                "current_phase": "Starting scan...",
                "progress": 0,
                "estimated_completion": None,
            }

        # Build a proper DiscoveryScope from the raw dict
        scope = DiscoveryScope(
            include_network=target_scope.get("include_network", True),
            include_repositories=target_scope.get("include_repositories", False),
            include_cloud=target_scope.get("include_cloud", False),
            include_traffic=target_scope.get("include_traffic", False),
            network_ranges=target_scope.get("network_ranges"),
            domains=target_scope.get("domains"),
            repositories=target_scope.get("repositories"),
            cloud_accounts=target_scope.get("cloud_accounts"),
            traffic_sources=target_scope.get("traffic_sources"),
        )

        source_agents = None
        if scan_type == "security_only":
            with app.app_context():
                current = db.session.get(ScanSession, scan_id)
                source = ScanSession.query.filter_by(
                    id=scan_config.get("source_scan_id"), organization_id=current.organization_id,
                    status="completed",
                ).first()
                if not source:
                    raise ValueError("Completed source scan required")
                previous = db.session.get(ScanResult, source.id)
                if not previous:
                    raise ValueError("Source scan has no versioned results")
                source_agents = previous.result["agents"]
                if any(agent.get("endpoint_redacted") for agent in source_agents):
                    raise SourceReplayError("Source endpoints were redacted; use fresh explicit target configuration")
                source_agents = apply_model_overrides(source_agents, scan_config.get("model_overrides", {}))
        _update_progress(scan_id, 10, "Running scan pipeline")
        result = await run_pipeline(discovery_engine, security_engine, risk_assessor,
                                    scope, scan_type, agents=source_agents,
                                    agent_validator=lambda agents: validate_agent_endpoints(agents, app.config))
        result["scan_id"] = scan_id
        _update_progress(scan_id, 95, "Saving results")

        # Save results
        with app.app_context():
            scan_session = db.session.get(ScanSession, scan_id)
            job = db.session.get(ScanJob, scan_id)
            if job and job.status == "cancel_requested":
                raise asyncio.CancelledError
            summary = result["summary"]
            scan_session.agents_discovered = summary["agents_discovered"]
            scan_session.vulnerabilities_found = summary["vulnerabilities_found"]
            scan_session.critical_risks = summary["critical_risks"]
            scan_session.overall_risk_score = summary["overall_risk_score"] or 0.0
            scan_session.status = result["status"]
            scan_session.completed_at = datetime.now(timezone.utc)
            scan_session.progress = 100.0

            db.session.add(ScanResult(scan_id=scan_id, result=result))
            for agent_data in result["agents"]:
                agent_record = DiscoveredAgentModel(
                    id=uuid.uuid4().hex,
                    scan_id=scan_id,
                    agent_name=agent_data["name"],
                    agent_type=agent_data["type"],
                    provider=agent_data.get("provider"),
                    endpoint_url=agent_data.get("endpoint"),
                    discovery_method=agent_data["discovery_method"],
                    security_tested=agent_data["security_status"] == "completed",
                    vulnerabilities=agent_data["vulnerabilities"],
                    risk_score=agent_data["risk_score"] or 0.0,
                    risk_level=agent_data["risk_level"],
                    metadata_json={**agent_data.get("metadata", {}), "asset_id": agent_data["id"],
                                   "security_status": agent_data["security_status"]},
                )
                db.session.add(agent_record)

            db.session.commit()

    except Exception as e:
        app.logger.error(f"Scan execution error: {e}", exc_info=True)
        with app.app_context():
            scan_session = db.session.get(ScanSession, scan_id)
            if scan_session:
                scan_session.status = "failed"
                scan_session.completed_at = datetime.now(timezone.utc)
                db.session.add(ScanResult(scan_id=scan_id, result={
                    "schema_version": "1.0", "scan_id": scan_id, "scan_type": scan_type,
                    "status": "failed", "error": str(e) if isinstance(e, SourceReplayError) else "Scan execution failed", "agents": [],
                    "summary": {},
                }))
                db.session.commit()


def _update_progress(scan_id: str, progress: float, phase: str):
    """Thread-safe progress update."""
    with _scans_lock:
        if scan_id in _active_scans:
            _active_scans[scan_id]["progress"] = progress
            _active_scans[scan_id]["current_phase"] = phase

    with app.app_context():
        scan_session = db.session.get(ScanSession, scan_id)
        if scan_session:
            scan_session.progress = progress
            db.session.commit()


# ---------------------------------------------------------------------------
# Startup
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    start_job_dispatcher()
    port = int(os.environ.get("PORT", 5000))
    try:
        app.run(host="127.0.0.1", port=port, debug=_debug, use_reloader=False)
    finally:
        stop_job_dispatcher()
