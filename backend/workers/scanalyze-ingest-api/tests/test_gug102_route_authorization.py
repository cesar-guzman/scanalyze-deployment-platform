"""GUG-102 route-level authorization regression tests."""
from __future__ import annotations

from fastapi import Depends, FastAPI
from fastapi.routing import APIRoute
from fastapi.testclient import TestClient

from app.api.v1.router import router as v1_router
from app.auth import AuthContext, get_auth_context
from app.authorization import (
    ROUTE_ACTION_POLICY_ATTRIBUTE,
    require_export_access,
    require_read_access,
    require_write_access,
)
from app.errors import register_exception_handlers


CUSTOMER_ID = "cust_01ARZ3NDEKTSV4RRFFQ69G5FAW"
DEPLOYMENT_ID = "dep_01ARZ3NDEKTSV4RRFFQ69G5FAV"


def _m2m_context(
    *actions: str,
    token_scopes: tuple[str, ...] = (),
) -> AuthContext:
    return AuthContext(
        customer_id=CUSTOMER_ID,
        deployment_id=DEPLOYMENT_ID,
        principal_type="m2m",
        subject="synthetic-service-principal",
        client_id="synthetic-m2m-client",
        scopes=token_scopes,
        granted_actions=actions,
        auth_source="m2m_identity_binding_v1",
    )


def _policy_client(auth: AuthContext) -> TestClient:
    app = FastAPI()
    register_exception_handlers(app)

    @app.get("/read")
    def read_route(context: AuthContext = Depends(require_read_access)):
        return {"principal_type": context.principal_type}

    @app.post("/write")
    def write_route(context: AuthContext = Depends(require_write_access)):
        return {"principal_type": context.principal_type}

    @app.get("/export")
    def export_route(context: AuthContext = Depends(require_export_access)):
        return {"principal_type": context.principal_type}

    app.dependency_overrides[get_auth_context] = lambda: auth
    return TestClient(app)


def test_read_action_cannot_post_or_export() -> None:
    client = _policy_client(_m2m_context("read"))

    assert client.get("/read").status_code == 200
    assert client.post("/write").status_code == 403
    assert client.get("/export").status_code == 403


def test_write_action_can_post_but_cannot_export() -> None:
    client = _policy_client(_m2m_context("write"))

    assert client.post("/write").status_code == 200
    assert client.get("/export").status_code == 403


def test_read_and_admin_actions_can_export() -> None:
    client = _policy_client(_m2m_context("read", "admin"))

    assert client.get("/export").status_code == 200


def test_extra_token_scopes_cannot_elevate_route_actions() -> None:
    client = _policy_client(
        _m2m_context(
            "read",
            token_scopes=("synthetic-read", "synthetic-write", "synthetic-admin"),
        )
    )

    assert client.post("/write").status_code == 403
    assert client.get("/export").status_code == 403


def test_user_and_local_principals_keep_existing_route_behavior() -> None:
    for principal_type in ("user", "local_mock"):
        context = AuthContext(
            customer_id="legacy-customer",
            principal_type=principal_type,
            subject="synthetic-user",
            auth_source="local_mock" if principal_type == "local_mock" else "cognito_jwt",
        )
        client = _policy_client(context)

        assert client.get("/read").status_code == 200
        assert client.post("/write").status_code == 200
        assert client.get("/export").status_code == 200


EXPECTED_ROUTE_POLICIES = {
    ("POST", "/api/v1/documents"): frozenset({"write"}),
    ("POST", "/api/v1/documents/{document_id}/submit"): frozenset({"write"}),
    ("GET", "/api/v1/documents/{document_id}"): frozenset({"read"}),
    ("GET", "/api/v1/documents/{document_id}/result"): frozenset({"read", "admin"}),
    ("GET", "/api/v1/documents/{document_id}/artifacts"): frozenset({"read"}),
    ("GET", "/api/v1/documents/{document_id}/download"): frozenset({"read", "admin"}),
    ("GET", "/api/v1/documents/{document_id}/artifacts/{artifact_id}/download"): frozenset({"read", "admin"}),
    ("POST", "/api/v1/batches"): frozenset({"write"}),
    ("GET", "/api/v1/batches/{batch_id}"): frozenset({"read"}),
    ("GET", "/api/v1/batches/{batch_id}/documents"): frozenset({"read"}),
    ("GET", "/api/v1/batches/{batch_id}/manifest"): frozenset({"read", "admin"}),
    ("GET", "/api/v1/batches/{batch_id}/exports/json"): frozenset({"read", "admin"}),
    ("GET", "/api/v1/batches/{batch_id}/exports/csv"): frozenset({"read", "admin"}),
    ("GET", "/api/v1/batches/{batch_id}/exports/zip"): frozenset({"read", "admin"}),
    ("GET", "/api/v1/analytics/dashboard"): frozenset({"read"}),
    ("GET", "/api/v1/analytics/overview"): frozenset({"read"}),
    ("GET", "/api/v1/analytics/pages-by-user"): frozenset({"read"}),
    ("GET", "/api/v1/analytics/by-day"): frozenset({"read"}),
    ("GET", "/api/v1/analytics/by-batch"): frozenset({"read"}),
    ("GET", "/api/v1/analytics/by-doc-type"): frozenset({"read"}),
    ("GET", "/api/v1/analytics/costs"): frozenset({"read"}),
    ("GET", "/api/v1/analytics/export-ine"): frozenset({"read", "admin"}),
    ("GET", "/api/v1/addons/employee-profiles/status"): frozenset({"read"}),
    ("GET", "/api/v1/addons/employee-profiles/export/csv"): frozenset({"read", "admin"}),
    ("POST", "/api/v1/addons/employee-profiles/generate"): frozenset({"write"}),
    ("GET", "/api/v1/addons/employee-profiles/jobs/{job_id}"): frozenset({"read"}),
    ("GET", "/api/v1/addons/employee-profiles"): frozenset({"read", "admin"}),
    ("GET", "/api/v1/addons/employee-profiles/{profile_id}/export/json"): frozenset({"read", "admin"}),
    ("GET", "/api/v1/addons/employee-profiles/{profile_id}/export/csv"): frozenset({"read", "admin"}),
    ("GET", "/api/v1/addons/employee-profiles/{profile_id}"): frozenset({"read", "admin"}),
}


def test_every_protected_route_has_the_reviewed_explicit_policy() -> None:
    actual = {}
    for route in v1_router.routes:
        if not isinstance(route, APIRoute):
            continue
        policy_dependencies = [
            dependency.call
            for dependency in route.dependant.dependencies
            if hasattr(dependency.call, ROUTE_ACTION_POLICY_ATTRIBUTE)
        ]
        assert len(policy_dependencies) == 1, (
            f"{route.path} must have exactly one explicit action policy"
        )
        required_actions = getattr(
            policy_dependencies[0],
            ROUTE_ACTION_POLICY_ATTRIBUTE,
        )
        for method in route.methods:
            actual[(method, route.path)] = required_actions

    assert actual == EXPECTED_ROUTE_POLICIES
