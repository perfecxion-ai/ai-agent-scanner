"""Authentication and tenant boundaries using an isolated in-memory database."""

import importlib
import sys
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import jwt
import pytest

from src.utils.auth import JWT_AUDIENCE, JWT_ISSUER, create_jwt_token


@pytest.fixture
def api(monkeypatch):
    monkeypatch.delenv("SCAN_EVIDENCE_PROFILES_FILE", raising=False)
    monkeypatch.setenv("SECRET_KEY", "test-signing-key-" * 4)
    monkeypatch.setenv("DATABASE_URL", "sqlite:///:memory:")
    monkeypatch.setenv("OPERATOR_API_KEY", "test-operator-key")
    monkeypatch.setenv("OPERATOR_ORGANIZATION_ID", "tenant-a")
    module = sys.modules.get("app") or importlib.import_module("app")
    monkeypatch.setattr(module, "_evidence_profiles", module.load_evidence_profiles(None))
    module.app.config.update(TESTING=True, OPERATOR_API_KEY="test-operator-key",
                             OPERATOR_ORGANIZATION_ID="tenant-a",
                             SCAN_ALLOWED_NETWORKS=("192.0.2.0/24",),
                             SCAN_ALLOWED_PATH_ROOTS=(), SCAN_ALLOW_LOOPBACK=False)
    monkeypatch.setattr(module, "_job_dispatcher", None)
    with module.app.app_context():
        assert module.db.engine.url.database == ":memory:"
        module.initialize_schema(module.db.engine, module.db.metadata)
        yield module, module.app.test_client()
        module.db.session.remove()
        module.db.drop_all()


def headers(module, organization="tenant-a"):
    token = create_jwt_token({"user_id": "operator", "organization_id": organization},
                             module.app.config["SECRET_KEY"])
    return {"Authorization": f"Bearer {token}"}


@pytest.mark.parametrize("body", [{}, {"user_id": "admin"}, {"api_key": "wrong"}, {"api_key": 1}])
def test_token_requires_credential(api, body):
    _, client = api
    assert client.post("/api/auth/token", json=body).status_code == 401


def test_token_identity_is_server_assigned(api):
    module, client = api
    response = client.post("/api/auth/token", json={"api_key": "test-operator-key",
                           "user_id": "admin", "organization_id": "tenant-b"})
    assert response.status_code == 200
    assert response.headers["Cache-Control"] == "no-store"
    claims = jwt.decode(response.json["token"], module.app.config["SECRET_KEY"],
                        algorithms=["HS256"], audience=JWT_AUDIENCE, issuer=JWT_ISSUER)
    assert claims["user_id"] == "operator"
    assert claims["organization_id"] == "tenant-a"


def test_unconfigured_login_fails_closed(api):
    module, client = api
    module.app.config["OPERATOR_API_KEY"] = ""
    assert client.post("/api/auth/token", json={"api_key": ""}).status_code == 503
    assert client.get("/api/agents", headers=headers(module)).status_code == 503


@pytest.mark.parametrize("body", [[], "text", None])
def test_login_rejects_non_object_body(api, body):
    _, client = api
    assert client.post("/api/auth/token", json=body).status_code == 400


@pytest.mark.parametrize("mutation", ["expired", "issuer", "audience", "signature"])
def test_invalid_token_rejected(api, mutation):
    module, client = api
    payload = {"user_id": "operator", "organization_id": "tenant-a", "iss": JWT_ISSUER,
               "aud": JWT_AUDIENCE, "iat": datetime.now(timezone.utc) - timedelta(hours=2),
               "exp": datetime.now(timezone.utc) + timedelta(hours=1)}
    key = module.app.config["SECRET_KEY"]
    if mutation == "expired":
        payload["exp"] = datetime.now(timezone.utc) - timedelta(hours=1)
    elif mutation == "issuer":
        payload["iss"] = "other-app"
    elif mutation == "audience":
        payload["aud"] = "other-api"
    else:
        key = "wrong-signing-key-" * 4
    token = jwt.encode(payload, key, algorithm="HS256")
    assert client.get("/api/agents", headers={"Authorization": f"Bearer {token}"}).status_code == 401


@pytest.mark.parametrize("claim", ["exp", "iat", "iss", "aud", "user_id", "organization_id"])
def test_missing_claim_rejected(api, claim):
    module, client = api
    payload = {"user_id": "operator", "organization_id": "tenant-a", "iss": JWT_ISSUER,
               "aud": JWT_AUDIENCE, "iat": datetime.now(timezone.utc),
               "exp": datetime.now(timezone.utc) + timedelta(hours=1)}
    del payload[claim]
    token = jwt.encode(payload, module.app.config["SECRET_KEY"], algorithm="HS256")
    assert client.get("/api/agents", headers={"Authorization": f"Bearer {token}"}).status_code == 401


@pytest.mark.parametrize("value", [None, "", " ", 42, {}])
def test_invalid_tenant_rejected(api, value):
    module, client = api
    token = create_jwt_token({"user_id": "operator", "organization_id": value},
                             module.app.config["SECRET_KEY"])
    assert client.get("/api/agents", headers={"Authorization": f"Bearer {token}"}).status_code == 401


def test_scan_routes_and_list_are_tenant_scoped(api):
    module, client = api
    for tenant in ("tenant-a", "tenant-b"):
        module.db.session.add(module.ScanSession(id=tenant, organization_id=tenant,
                              scan_name=tenant, scan_type="discovery_only", target_scope={}, scan_config={}))
        module.db.session.add(module.DiscoveredAgentModel(id=tenant, scan_id=tenant,
                              agent_name=tenant, agent_type="test", discovery_method="test"))
    module.db.session.commit()
    for endpoint in ("status", "results"):
        assert client.get(f"/api/scans/tenant-a/{endpoint}", headers=headers(module)).status_code == 200
        other = client.get(f"/api/scans/tenant-b/{endpoint}", headers=headers(module))
        missing = client.get(f"/api/scans/missing/{endpoint}", headers=headers(module))
        assert other.status_code == missing.status_code == 404
        assert other.json == missing.json
        assert client.get(f"/api/scans/tenant-a/{endpoint}").status_code == 401
    agents = client.get("/api/agents", headers=headers(module)).json["agents"]
    assert [agent["id"] for agent in agents] == ["tenant-a"]


def test_scan_created_in_authenticated_organization(api):
    module, client = api
    with patch.object(module.threading, "Thread") as thread:
        response = client.post("/api/scans", headers=headers(module), json={
            "organization_id": "tenant-b", "scan_type": "discovery_only",
            "target_scope": {"include_network": True, "network_ranges": ["192.0.2.1/32"]}})
        assert response.status_code == 202
        thread.assert_not_called()
    scan = module.db.session.get(module.ScanSession, response.json["scan_id"])
    assert scan.organization_id == "tenant-a"
    assert scan.created_by == "operator"
