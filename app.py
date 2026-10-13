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
from datetime import datetime, timezone
from typing import Dict, Any

from flask import Flask, render_template, request, jsonify, g
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy import String, DateTime, Integer, Float, Boolean, Text, JSON

from src.discovery.discovery_engine import DiscoveryEngine, DiscoveryScope
from src.security.security_engine import SecurityTestEngine
from src.risk.risk_assessor import RiskAssessment
from src.compliance.compliance_engine import ComplianceEngine
from src.reporting.report_generator import ReportGenerator
from src.utils.auth import require_auth, create_jwt_token
from src.utils.helpers import generate_scan_id, validate_scan_scope
from src.core.pipeline import run_pipeline, to_sarif

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


@app.route("/api/scans", methods=["POST"])
@require_auth
def start_scan():
    """Start a new AI agent discovery and security scan."""
    try:
        data = request.get_json()

        scan_name = data.get("scan_name", f"Scan {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M')}")
        scan_type = data.get("scan_type", "full")
        target_scope = data.get("target_scope", {})
        scan_config = data.get("scan_config", {})

        is_valid, validation_error = validate_scan_scope(target_scope)
        if not is_valid:
            return jsonify({"success": False, "error": validation_error}), 400

        scan_id = generate_scan_id()
        scan_session = ScanSession(
            id=scan_id,
            organization_id=g.user["organization_id"],
            scan_name=scan_name,
            scan_type=scan_type,
            target_scope=target_scope,
            scan_config=scan_config,
            created_by=g.user.get("user_id"),
            user_ip=request.headers.get("X-Forwarded-For", request.remote_addr),
        )

        db.session.add(scan_session)
        db.session.commit()

        thread = threading.Thread(
            target=_run_scan_in_thread,
            args=(scan_id, scan_type, target_scope, scan_config),
            daemon=True,
        )
        thread.start()

        return jsonify({"success": True, "scan_id": scan_id, "message": "Scan started"})

    except Exception as e:
        app.logger.error(f"Error starting scan: {e}", exc_info=True)
        return jsonify({"success": False, "error": "Failed to start scan"}), 500


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
def health_check():
    return jsonify({
        "status": "healthy",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "version": VERSION,
    })


# ---------------------------------------------------------------------------
# Background scan execution
# ---------------------------------------------------------------------------

def _run_scan_in_thread(scan_id: str, scan_type: str, target_scope: dict, scan_config: dict):
    """Run scan in a background thread with its own event loop."""
    loop = asyncio.new_event_loop()
    try:
        asyncio.set_event_loop(loop)
        loop.run_until_complete(
            _execute_scan(scan_id, scan_type, target_scope, scan_config)
        )
    except Exception as e:
        app.logger.error(f"Scan thread error: {e}", exc_info=True)
        with app.app_context():
            scan_session = db.session.get(ScanSession, scan_id)
            if scan_session:
                scan_session.status = "failed"
                db.session.commit()
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
        _update_progress(scan_id, 10, "Running scan pipeline")
        result = await run_pipeline(discovery_engine, security_engine, risk_assessor,
                                    scope, scan_type, agents=source_agents)
        result["scan_id"] = scan_id
        _update_progress(scan_id, 95, "Saving results")

        # Save results
        with app.app_context():
            scan_session = db.session.get(ScanSession, scan_id)
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
    with app.app_context():
        db.create_all()

    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=_debug)
