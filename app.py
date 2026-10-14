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
from copy import deepcopy
from functools import wraps
from contextlib import suppress
from datetime import datetime, timedelta, timezone
from typing import Dict, Any

from flask import Flask, render_template, request, jsonify, g
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy import String, DateTime, Integer, Float, Boolean, Text, JSON, select, update
from werkzeug.exceptions import HTTPException, BadRequest, NotFound, TooManyRequests, Conflict

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
from src.core.transport import ScanBudget, scan_transport, current_budget
from src.core.jobs import JobStore, JobDispatcher, TERMINAL_STATES
from src.core.schema import initialize_schema, SCHEMA_VERSION
from src.core.templates import project_template, template_revision
from src.core.schedules import ScheduleService, schedule_definition

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
    ("SCAN_MAX_TEMPLATES", 64, 1024),
    ("SCAN_MAX_SCHEDULES", 64, 1024), ("SCAN_MAX_SCHEDULES_GLOBAL", 256, 4096),
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


class SchemaVersion(db.Model):
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    version: Mapped[int] = mapped_column(Integer, nullable=False)


class ScanTemplate(db.Model):
    """Tenant-owned recipe, not a queued job or a credential store."""

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    organization_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    scan_name: Mapped[str] = mapped_column(String(255), nullable=False)
    scan_type: Mapped[str] = mapped_column(String(50), nullable=False)
    target_scope: Mapped[dict] = mapped_column(JSON, nullable=False)
    scan_config: Mapped[dict] = mapped_column(JSON, nullable=False)
    revision: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    created_by: Mapped[str] = mapped_column(String(255), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=_utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=_utcnow)


class AuditEvent(db.Model):
    """Minimal transition history; never store scan inputs or response content."""

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    scan_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    organization_id: Mapped[str] = mapped_column(String(64), nullable=False)
    event: Mapped[str] = mapped_column(String(32), nullable=False)
    previous_status: Mapped[str] = mapped_column(String(32), nullable=True)
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=_utcnow)


class ScanSchedule(db.Model):
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    organization_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    template_id: Mapped[str] = mapped_column(String(64), nullable=False)
    template_revision: Mapped[int] = mapped_column(Integer, nullable=False)
    interval_seconds: Mapped[int] = mapped_column(Integer, nullable=False)
    total_runs: Mapped[int] = mapped_column(Integer, nullable=False)
    admitted_runs: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    revision: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    state: Mapped[str] = mapped_column(String(32), nullable=False, default="disabled")
    pause_reason: Mapped[str] = mapped_column(String(32), nullable=True)
    next_due_at: Mapped[datetime] = mapped_column(DateTime, nullable=True)
    outstanding_scan_id: Mapped[str] = mapped_column(String(64), nullable=True)
    created_by: Mapped[str] = mapped_column(String(255), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=_utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=_utcnow)


class ScanOccurrence(db.Model):
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    schedule_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    organization_id: Mapped[str] = mapped_column(String(64), nullable=False)
    scan_id: Mapped[str] = mapped_column(String(64), nullable=False)
    ordinal: Mapped[int] = mapped_column(Integer, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=_utcnow)


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route("/")
def dashboard():
    return render_template("dashboard.html")


@app.after_request
def response_boundaries(response):
    """Keep API data out of caches and restrict the dashboard to local resources."""
    if request.path == "/api" or request.path.startswith("/api/"):
        response.headers["Cache-Control"] = "no-store"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"
    if response.mimetype == "text/html":
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; "
            "object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"
        )
    return response


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
        definition = _prepare_scan(request.get_json(silent=True), g.user["organization_id"])
        db.session.rollback()
        with _admission_lock:
            scan_id = _queue_scan(definition, g.user["organization_id"],
                                  g.user.get("user_id"), request.remote_addr)
        return jsonify({"success": True, "scan_id": scan_id, "message": "Scan queued"}), 202

    except ScopeValidationError as e:
        db.session.rollback()
        return jsonify({"success": False, "error": str(e)}), 400
    except HTTPException as e:
        db.session.rollback()
        return jsonify({"success": False, "error": e.description}), e.code
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error starting scan: {e}", exc_info=True)
        return jsonify({"success": False, "error": "Failed to start scan"}), 500


def _prepare_scan(data, tenant, *, retain_declaration=True):
    """Validate current policy while retaining declared DNS and path intent."""
    name, mode, scope, options = validate_request(data, app.config)
    if mode == "security_only":
        source = ScanSession.query.filter_by(id=options["source_scan_id"], organization_id=tenant).first()
        if source is None:
            raise NotFound("Source scan not found")
        if source.status != "completed":
            raise BadRequest("Source scan must be completed")
        previous = db.session.get(ScanResult, source.id)
        if not previous:
            raise BadRequest("Source scan has no versioned results")
        if any(agent.get("endpoint_redacted") for agent in previous.result.get("agents", [])):
            raise BadRequest("Source endpoints were redacted; supply fresh targets")
        try:
            apply_model_overrides(previous.result.get("agents", []), options.get("model_overrides", {}))
        except ValueError as exc:
            raise ScopeValidationError(str(exc)) from exc
        source_agents = DiscoveredAgentModel.query.filter_by(scan_id=source.id).all()
        if not source_agents:
            raise BadRequest("Source scan has no assets")
        validate_agent_endpoints([{"endpoint": agent.endpoint_url} for agent in source_agents], app.config)
    elif retain_declaration:
        # Execution resolves these declarations again, rather than trusting stale DNS or symlinks.
        for key in ("network_ranges", "domains", "repositories", "traffic_sources"):
            scope[key] = deepcopy(data.get("target_scope", {}).get(key, []))
    return {"scan_name": name, "scan_type": mode, "target_scope": scope, "scan_config": options}


def _queue_scan(definition, tenant, actor, user_ip, *, before_commit=None):
    """Caller holds the admission lock; commit all admission records together."""
    if ScanJob.query.filter_by(status="queued").count() >= app.config["SCAN_MAX_QUEUED"]:
        raise TooManyRequests("Scan queue is full")
    scan_id = generate_scan_id()
    db.session.add(ScanSession(id=scan_id, organization_id=tenant, **deepcopy(definition),
                              created_by=actor, user_ip=user_ip, status="queued"))
    db.session.add(ScanJob(scan_id=scan_id))
    db.session.add(AuditEvent(scan_id=scan_id, organization_id=tenant, event="admitted", status="queued"))
    if before_commit is not None:
        before_commit(scan_id)
    db.session.commit()
    if _job_dispatcher:
        _job_dispatcher.wake()
    return scan_id


def _template_api(function):
    @wraps(function)
    def wrapped(*args, **kwargs):
        try:
            return function(*args, **kwargs)
        except ScopeValidationError as exc:
            db.session.rollback()
            return jsonify({"success": False, "error": str(exc)}), 400
        except HTTPException as exc:
            db.session.rollback()
            return jsonify({"success": False, "error": exc.description}), exc.code
        except Exception:
            db.session.rollback()
            app.logger.error("Saved scan operation failed")
            return jsonify({"success": False, "error": "Saved scan operation failed"}), 500
    return wrapped


def _owned_template(template_id, tenant):
    row = ScanTemplate.query.filter_by(id=template_id, organization_id=tenant).first()
    if row is None:
        raise NotFound("Template not found")
    return row


def _template_definition(row):
    return {key: deepcopy(getattr(row, key))
            for key in ("scan_name", "scan_type", "target_scope", "scan_config")}


def _template_json(row, *, definition=True):
    result = {"id": row.id, "scan_name": row.scan_name, "scan_type": row.scan_type,
              "revision": row.revision, "created_at": row.created_at.isoformat(),
              "updated_at": row.updated_at.isoformat()}
    if definition:
        result.update(_template_definition(row))
    return result


def _prepare_template(data, tenant):
    definition = _prepare_scan(project_template(data), tenant)
    # Defaults and normalized flags count toward the persisted document limit too.
    project_template(definition)
    return definition


@app.route("/api/templates", methods=["GET", "POST"])
@require_auth
@_template_api
def templates_collection():
    tenant = g.user["organization_id"]
    if request.method == "GET":
        try:
            limit, offset = int(request.args.get("limit", "25")), int(request.args.get("offset", "0"))
        except ValueError as exc:
            raise BadRequest("Invalid pagination") from exc
        if not 1 <= limit <= 100 or not 0 <= offset <= 100000:
            raise BadRequest("Invalid pagination")
        query = ScanTemplate.query.filter_by(organization_id=tenant)
        rows = query.order_by(ScanTemplate.updated_at.desc(), ScanTemplate.id.desc()).offset(offset).limit(limit).all()
        return jsonify({"success": True, "templates": [_template_json(row, definition=False) for row in rows],
                        "total": query.count(), "limit": limit, "offset": offset})
    definition = _prepare_template(request.get_json(silent=True), tenant)
    db.session.rollback()
    with _admission_lock:
        if ScanTemplate.query.filter_by(organization_id=tenant).count() >= app.config["SCAN_MAX_TEMPLATES"]:
            raise TooManyRequests("Template limit reached")
        row = ScanTemplate(id=uuid.uuid4().hex, organization_id=tenant,
                           created_by=g.user.get("user_id"), **definition)
        db.session.add(row)
        db.session.commit()
        return jsonify({"success": True, "template": _template_json(row)}), 201


@app.route("/api/templates/<template_id>", methods=["GET", "PUT", "DELETE"])
@require_auth
@_template_api
def template_item(template_id):
    tenant = g.user["organization_id"]
    row = _owned_template(template_id, tenant)
    if request.method == "GET":
        return jsonify({"success": True, "template": _template_json(row)})
    if request.method == "PUT":
        data = request.get_json(silent=True)
        if not isinstance(data, dict):
            raise BadRequest("JSON object required")
        revision = template_revision(data.get("revision"))
        if revision != row.revision or revision == 2**31 - 1:
            raise Conflict("Template revision changed; reload before updating")
        definition = _prepare_template({key: value for key, value in data.items() if key != "revision"}, tenant)
    db.session.rollback()
    with _admission_lock:
        row = _owned_template(template_id, tenant)
        if request.method == "DELETE":
            _pause_template_schedules(template_id, tenant, "template_deleted")
            db.session.delete(row)
            db.session.commit()
            return jsonify({"success": True})
        changed = db.session.execute(update(ScanTemplate).where(
            ScanTemplate.id == template_id, ScanTemplate.organization_id == tenant,
            ScanTemplate.revision == revision,
        ).values(**definition, revision=revision + 1, updated_at=_utcnow()))
        if changed.rowcount != 1:
            raise Conflict("Template revision changed; reload before updating")
        _pause_template_schedules(template_id, tenant, "template_changed")
        db.session.commit()
        db.session.refresh(row)
        return jsonify({"success": True, "template": _template_json(row)})


@app.route("/api/templates/<template_id>/run", methods=["POST"])
@require_auth
@_template_api
def run_template(template_id):
    tenant = g.user["organization_id"]
    row = _owned_template(template_id, tenant)
    revision = row.revision
    data = request.get_json(silent=True)
    if not isinstance(data, dict) or set(data) - {"revision"}:
        raise BadRequest("Template run requires a JSON object containing only optional revision")
    if "revision" in data and template_revision(data["revision"]) != revision:
        raise Conflict("Template revision changed; reload before running")
    definition = _prepare_template(_template_definition(row), tenant)
    db.session.rollback()
    with _admission_lock:
        row = _owned_template(template_id, tenant)
        if row.revision != revision:
            raise Conflict("Template revision changed; reload before running")
        scan_id = _queue_scan(definition, tenant, g.user.get("user_id"), request.remote_addr)
    return jsonify({"success": True, "scan_id": scan_id, "message": "Scan queued"}), 202


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


def _pause_template_schedules(template_id, tenant, reason):
    db.session.execute(update(ScanSchedule).where(
        ScanSchedule.template_id == template_id, ScanSchedule.organization_id == tenant,
        ScanSchedule.state != "completed",
    ).values(state="paused", pause_reason=reason, next_due_at=None,
             revision=db.func.min(ScanSchedule.revision + 1, 2**31 - 1), updated_at=_utcnow()))


def _owned_schedule(identifier, tenant):
    row = ScanSchedule.query.filter_by(id=identifier, organization_id=tenant).first()
    if row is None:
        raise NotFound("Schedule not found")
    return row


def _schedule_json(row):
    result = {key: getattr(row, key) for key in (
        "id", "template_id", "template_revision", "interval_seconds", "total_runs", "admitted_runs",
        "revision", "state", "pause_reason", "outstanding_scan_id")}
    for key in ("created_at", "updated_at", "next_due_at"):
        value = getattr(row, key)
        result[key] = value.replace(tzinfo=timezone.utc).isoformat() if value is not None else None
    return result


def _pagination():
    try:
        limit, offset = int(request.args.get("limit", "25")), int(request.args.get("offset", "0"))
    except ValueError as exc:
        raise BadRequest("Invalid pagination") from exc
    if not 1 <= limit <= 100 or not 0 <= offset <= 100000:
        raise BadRequest("Invalid pagination")
    return limit, offset


def _schedule_policy():
    return deepcopy({key: value for key, value in app.config.items() if key.startswith("SCAN_")})


def _schedule_token(definition, tenant):
    """Public configuration and source identity only; no DNS or filesystem work."""
    policy = _schedule_policy()
    source = None
    if definition["scan_type"] == "security_only":
        identifier = definition["scan_config"]["source_scan_id"]
        row = ScanSession.query.filter_by(id=identifier, organization_id=tenant).first()
        result = db.session.get(ScanResult, identifier)
        assets = DiscoveredAgentModel.query.filter_by(scan_id=identifier).order_by(
            DiscoveredAgentModel.id).limit(app.config["SCAN_MAX_HOSTS"] + 1).all()
        if row is None or row.status != "completed" or result is None or not assets:
            raise BadRequest("Source scan prerequisites changed")
        if len(assets) > app.config["SCAN_MAX_HOSTS"]:
            raise BadRequest("Source scan exceeds host budget")
        source = (row.id, row.status, deepcopy(result.result), [(item.id, item.endpoint_url) for item in assets])
    return policy, source


@app.route("/api/schedules", methods=["GET", "POST"])
@require_auth
@_template_api
def schedules_collection():
    tenant = g.user["organization_id"]
    if request.method == "GET":
        limit, offset = _pagination()
        query = ScanSchedule.query.filter_by(organization_id=tenant)
        rows = query.order_by(ScanSchedule.created_at.desc(), ScanSchedule.id.desc()).offset(offset).limit(limit).all()
        return jsonify({"success": True, "schedules": [_schedule_json(row) for row in rows],
                        "total": query.count(), "limit": limit, "offset": offset})
    data = schedule_definition(request.get_json(silent=True))
    template = _owned_template(data["template_id"], tenant)
    if template.revision != data["template_revision"]:
        raise Conflict("Template revision changed; create a schedule for the reviewed revision")
    declaration = _template_definition(template)
    before = _schedule_token(declaration, tenant)
    definition = _prepare_template(declaration, tenant)
    token = _schedule_token(definition, tenant)
    if before != token:
        raise Conflict("Source or policy changed during validation; review before creating")
    db.session.rollback()
    with _admission_lock:
        template = _owned_template(data["template_id"], tenant)
        if template.revision != data["template_revision"] or token != _schedule_token(definition, tenant):
            raise Conflict("Template, source, or policy changed; review before creating")
        if (ScanSchedule.query.filter_by(organization_id=tenant).count() >= app.config["SCAN_MAX_SCHEDULES"]
                or ScanSchedule.query.count() >= app.config["SCAN_MAX_SCHEDULES_GLOBAL"]):
            raise TooManyRequests("Schedule limit reached")
        row = ScanSchedule(id=uuid.uuid4().hex, organization_id=tenant,
                           created_by=g.user.get("user_id"), **data)
        db.session.add(row)
        db.session.commit()
        return jsonify({"success": True, "schedule": _schedule_json(row)}), 201


@app.route("/api/schedules/<identifier>", methods=["GET", "DELETE"])
@require_auth
@_template_api
def schedule_item(identifier):
    tenant = g.user["organization_id"]
    row = _owned_schedule(identifier, tenant)
    if request.method == "GET":
        return jsonify({"success": True, "schedule": _schedule_json(row)})
    db.session.rollback()
    with _admission_lock:
        row = _owned_schedule(identifier, tenant)
        if row.state == "enabled" or row.outstanding_scan_id is not None:
            raise Conflict("Pause the schedule and wait for its outstanding scan before deleting")
        ScanOccurrence.query.filter_by(schedule_id=identifier, organization_id=tenant).delete()
        db.session.delete(row)
        db.session.commit()
    return jsonify({"success": True})


@app.route("/api/schedules/<identifier>/occurrences")
@require_auth
@_template_api
def schedule_occurrences(identifier):
    tenant = g.user["organization_id"]
    _owned_schedule(identifier, tenant)
    limit, offset = _pagination()
    query = ScanOccurrence.query.filter_by(schedule_id=identifier, organization_id=tenant)
    rows = query.order_by(ScanOccurrence.ordinal).offset(offset).limit(limit).all()
    return jsonify({"success": True, "occurrences": [{"ordinal": row.ordinal, "scan_id": row.scan_id,
        "created_at": row.created_at.replace(tzinfo=timezone.utc).isoformat()} for row in rows],
        "total": query.count(), "limit": limit, "offset": offset})


@app.route("/api/schedules/<identifier>/<action>", methods=["POST"])
@require_auth
@_template_api
def schedule_action(identifier, action):
    if action not in {"enable", "pause"}:
        raise NotFound("Schedule action not found")
    tenant = g.user["organization_id"]
    row = _owned_schedule(identifier, tenant)
    data = request.get_json(silent=True)
    if not isinstance(data, dict) or set(data) != {"revision"}:
        raise BadRequest("Schedule action requires only revision")
    revision = template_revision(data["revision"])
    if row.revision != revision or revision == 2**31 - 1:
        raise Conflict("Schedule revision changed; reload before updating")
    if action == "enable":
        template = _owned_template(row.template_id, tenant)
        if template.revision != row.template_revision:
            raise Conflict("Pinned template changed; create a replacement schedule")
        declaration = _template_definition(template)
        before = _schedule_token(declaration, tenant)
        definition = _prepare_template(declaration, tenant)
        token = _schedule_token(definition, tenant)
        if before != token:
            raise Conflict("Source or policy changed during validation; review before enabling")
    db.session.rollback()
    with _admission_lock:
        row = _owned_schedule(identifier, tenant)
        if row.revision != revision:
            raise Conflict("Schedule revision changed; reload before updating")
        if row.state == "completed" or (action == "enable" and row.admitted_runs >= row.total_runs):
            raise Conflict("Finite schedule has no remaining occurrences")
        if action == "enable":
            template = _owned_template(row.template_id, tenant)
            if template.revision != row.template_revision or token != _schedule_token(definition, tenant):
                raise Conflict("Template, source, or policy changed; review before enabling")
            row.state, row.pause_reason = "enabled", None
            row.next_due_at = _utcnow() + timedelta(seconds=row.interval_seconds)
        else:
            row.state, row.pause_reason, row.next_due_at = "paused", "operator_paused", None
        row.revision += 1
        row.updated_at = _utcnow()
        db.session.commit()
        result = _schedule_json(row)
    if _job_dispatcher:
        _job_dispatcher.wake()
    return jsonify({"success": True, "schedule": result})


def _schedule_recover():
    with app.app_context(), _admission_lock:
        db.session.execute(update(ScanSchedule).where(ScanSchedule.state == "enabled").values(
            state="paused", pause_reason="restart_review", next_due_at=None,
            revision=db.func.min(ScanSchedule.revision + 1, 2**31 - 1), updated_at=_utcnow()))
        db.session.commit()


def _schedule_candidate():
    """One bounded DB maintenance transition or one due candidate per tick."""
    with app.app_context(), _admission_lock:
        now = _utcnow()
        row = ScanSchedule.query.join(ScanJob, ScanJob.scan_id == ScanSchedule.outstanding_scan_id).filter(
            ScanJob.status.in_(TERMINAL_STATES)).order_by(ScanSchedule.updated_at, ScanSchedule.id).first()
        if row is not None:
            row.outstanding_scan_id = None
            if row.admitted_runs >= row.total_runs:
                row.state, row.pause_reason, row.next_due_at = "completed", None, None
            elif row.state == "enabled":
                row.next_due_at = now + timedelta(seconds=row.interval_seconds)
            row.revision = min(row.revision + 1, 2**31 - 1)
            row.updated_at = now
            db.session.commit()
            return None
        row = ScanSchedule.query.filter(ScanSchedule.state == "enabled",
            ScanSchedule.outstanding_scan_id.is_(None), ScanSchedule.next_due_at <= now).order_by(
            ScanSchedule.next_due_at, ScanSchedule.id).first()
        if row is None:
            return None
        return {"id": row.id, "organization_id": row.organization_id, "revision": row.revision,
                "template_id": row.template_id, "template_revision": row.template_revision}


def _schedule_preflight(candidate):
    with app.app_context():
        try:
            template = ScanTemplate.query.filter_by(id=candidate["template_id"],
                organization_id=candidate["organization_id"]).first()
            if template is None:
                return {"error": "template_deleted"}
            if template.revision != candidate["template_revision"]:
                return {"error": "template_changed"}
            declaration = _template_definition(template)
            before = _schedule_token(declaration, candidate["organization_id"])
            definition = _prepare_template(declaration, candidate["organization_id"])
            token = _schedule_token(definition, candidate["organization_id"])
            if before != token:
                return {"error": "policy_review"}
            return {"definition": definition, "token": token}
        except (ScopeValidationError, HTTPException):
            return {"error": "policy_review"}
        finally:
            db.session.rollback()
            db.session.remove()


def _schedule_admit(candidate, result, stop):
    with app.app_context(), _admission_lock:
        if stop.is_set():
            return
        row = ScanSchedule.query.filter_by(id=candidate["id"], organization_id=candidate["organization_id"],
            revision=candidate["revision"], state="enabled", outstanding_scan_id=None).first()
        if row is None:
            return
        now = _utcnow()
        template = ScanTemplate.query.filter_by(id=row.template_id, organization_id=row.organization_id).first()
        reason = result.get("error")
        if template is None:
            reason = "template_deleted"
        elif template.revision != row.template_revision:
            reason = "template_changed"
        elif not reason:
            try:
                if result["token"] != _schedule_token(result["definition"], row.organization_id):
                    reason = "policy_review"
            except HTTPException:
                reason = "policy_review"
        if row.revision >= 2**31 - 1:
            reason = "revision_limit"
        if reason:
            row.state, row.pause_reason, row.next_due_at = "paused", reason, None
        elif row.admitted_runs >= row.total_runs:
            row.state, row.pause_reason, row.next_due_at = "completed", None, None
        elif ScanJob.query.filter_by(status="queued").count() >= app.config["SCAN_MAX_QUEUED"]:
            row.next_due_at = now + timedelta(seconds=60)
        else:
            def occurrence(scan_id):
                if stop.is_set():
                    raise Conflict("Scheduler stopped before admission")
                ordinal = row.admitted_runs + 1
                db.session.add(ScanOccurrence(id=f"{row.id}:{ordinal}", schedule_id=row.id,
                    organization_id=row.organization_id, scan_id=scan_id, ordinal=ordinal))
                row.admitted_runs = ordinal
                row.outstanding_scan_id = scan_id
                row.next_due_at = None
                row.revision += 1
                row.updated_at = now
            try:
                _queue_scan(result["definition"], row.organization_id, row.created_by, None, before_commit=occurrence)
            except Exception:
                db.session.rollback()
                raise
            return
        row.revision = min(row.revision + 1, 2**31 - 1)
        row.updated_at = now
        if not stop.is_set():
            db.session.commit()


def _schedule_service():
    return ScheduleService(_schedule_candidate, _schedule_preflight, _schedule_admit, _schedule_recover)


@app.route("/api/scans/<scan_id>/audit")
@require_auth
def scan_audit(scan_id):
    tenant = g.user["organization_id"]
    if not ScanSession.query.filter_by(id=scan_id, organization_id=tenant).first():
        return jsonify({"success": False, "error": "Scan not found"}), 404
    try:
        limit = int(request.args.get("limit", 100))
        after = int(request.args.get("after", 0))
        if not 1 <= limit <= 200 or not 0 <= after <= 2**63 - 1:
            raise ValueError("Pagination is outside supported bounds")
    except ValueError:
        return jsonify({"success": False, "error": "limit must be 1..200; after must be 0..9223372036854775807"}), 400
    events = AuditEvent.query.filter(AuditEvent.scan_id == scan_id,
                                    AuditEvent.organization_id == tenant,
                                    AuditEvent.id > after).order_by(AuditEvent.id).limit(limit).all()
    return jsonify({"success": True, "events": [{
        "id": row.id, "event": row.event, "previous_status": row.previous_status,
        "status": row.status, "created_at": row.created_at.isoformat(),
    } for row in events], "next_after": events[-1].id if events else after})


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
        if db.session.scalar(select(SchemaVersion.version).where(SchemaVersion.id == 1)) != SCHEMA_VERSION:
            raise RuntimeError("Schema not initialized")
        ready = bool(_job_dispatcher and _job_dispatcher.ready)
    except Exception:
        db.session.rollback()
        ready = False
    return jsonify({"status": "ready" if ready else "not_ready"}), 200 if ready else 503


# ---------------------------------------------------------------------------
# Background scan execution
# ---------------------------------------------------------------------------

def _get_job_store():
    return JobStore(db.engine, ScanJob.__table__, ScanSession.__table__, ScanResult.__table__,
                    AuditEvent.__table__)


def start_job_dispatcher():
    global _job_dispatcher
    with _dispatcher_lock:
        if _job_dispatcher is not None:
            return _job_dispatcher
        with app.app_context():
            dispatcher = JobDispatcher(_get_job_store(), _execute_job,
                                       workers=app.config["MAX_CONCURRENT_SCANS"],
                                       initialize=lambda: initialize_schema(db.engine, db.metadata),
                                       service=_schedule_service())
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
        definition = _prepare_scan({
            "scan_type": scan.scan_type, "scan_name": scan.scan_name,
            "target_scope": scan.target_scope, "scan_config": scan.scan_config,
        }, scan.organization_id, retain_declaration=False)
    _run_scan_in_thread(scan_id, definition["scan_type"], definition["target_scope"],
                        definition["scan_config"], cancelled)


def _record_terminal(scan_id, status, error):
    with app.app_context():
        _get_job_store().finish(scan_id, error, status=status)


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
                if not stored:
                    raise RuntimeError("Rejected or failed transport produced no report")
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
        budget = current_budget()
        if budget and (budget.rejections or budget.failures):
            result["status"] = "partial"
        _update_progress(scan_id, 95, "Saving results")

        # Save results
        with app.app_context():
            snapshots = []
            for agent_data in result["agents"]:
                snapshots.append(dict(
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
                    metadata={**agent_data.get("metadata", {}), "asset_id": agent_data["id"],
                                   "security_status": agent_data["security_status"]},
                ))
            _get_job_store().save_result(scan_id, result, DiscoveredAgentModel.__table__, snapshots)

    except Exception as e:
        app.logger.error(f"Scan execution error: {e}", exc_info=True)
        _record_terminal(scan_id, "failed", str(e) if isinstance(e, SourceReplayError) else "Scan execution failed")


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
