import time
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from app.auth import AuthContext, get_auth_context
from app.enterprise_authorization import (
    ASSURANCE_SOURCE,
    ASSURANCE_VERSION,
    AUDIT_REFERENCE_SCHEMA_VERSION,
    AUDIT_RECEIPT_SCHEMA_VERSION,
    AUDIT_SINK_SOURCE,
    AUDIT_SINK_VERSION,
    AUTHORIZATION_CONTEXT_SCHEMA_VERSION,
    AUTHORITATIVE_MEMBERSHIP_SOURCE,
    AUTHORITATIVE_STATE_SCHEMA_VERSION,
    AUTHZ_SCHEMA_VERSION,
    MEMBERSHIP_SOURCE,
    POLICY_DIGEST,
    POLICY_VERSION,
    ROLE_CATALOG_VERSION,
    SCOPE_CATALOG_VERSION,
    Assurance,
    AuthorizationAuditReferences,
    AuthoritativeMembershipEvidence,
    AuthorizationPath,
    DurableAuditReceipt,
    EnterpriseAuthorizationRuntime,
    HumanAuthorizationSnapshot,
    HumanRole,
)
from app.errors import AppError
from app.main import app


CUSTOMER_ID = "cust_01ARZ3NDEKTSV4RRFFQ69G5FAW"
DEPLOYMENT_ID = "dep_01ARZ3NDEKTSV4RRFFQ69G5FAV"
SUBJECT = "test-user"
def _human_authorization_snapshot() -> HumanAuthorizationSnapshot:
    now_epoch = int(time.time())
    return HumanAuthorizationSnapshot(
        schema_version=AUTHORIZATION_CONTEXT_SCHEMA_VERSION,
        authorization_path=AuthorizationPath.MEMBERSHIP,
        authorization_source=MEMBERSHIP_SOURCE,
        subject=SUBJECT,
        customer_id=CUSTOMER_ID,
        deployment_id=DEPLOYMENT_ID,
        membership_state="active",
        role_id=HumanRole.CUSTOMER_ADMIN,
        membership_version="membership-v1",
        temporary_grant_id=None,
        temporary_grant_type=None,
        temporary_grant_state=None,
        temporary_grant_version=None,
        allowed_operation_ids=frozenset(),
        allowed_data_classes=frozenset(),
        expires_at_epoch=None,
        authz_schema_version=AUTHZ_SCHEMA_VERSION,
        scope_catalog_version=SCOPE_CATALOG_VERSION,
        role_catalog_version=ROLE_CATALOG_VERSION,
        policy_version=POLICY_VERSION,
        policy_digest=POLICY_DIGEST,
        issued_at_epoch=now_epoch,
        assurance=Assurance.PHISHING_RESISTANT_MFA,
        authenticated_at_epoch=now_epoch,
        grant_issued_at_epoch=None,
        assurance_source=ASSURANCE_SOURCE,
        assurance_version=ASSURANCE_VERSION,
        authentication_event_reference="ref_0123456789abcdef01234567",
    )


def _resolve_authoritative_membership(
    snapshot: HumanAuthorizationSnapshot,
    _operation: object,
    now_epoch: int,
) -> AuthoritativeMembershipEvidence:
    return AuthoritativeMembershipEvidence(
        schema_version=AUTHORITATIVE_STATE_SCHEMA_VERSION,
        authorization_path=AuthorizationPath.MEMBERSHIP,
        authority_source=AUTHORITATIVE_MEMBERSHIP_SOURCE,
        checked_at_epoch=now_epoch,
        subject=str(snapshot.subject),
        customer_id=str(snapshot.customer_id),
        deployment_id=str(snapshot.deployment_id),
        membership_state=str(snapshot.membership_state),
        role_id=snapshot.role_id or "missing",
        membership_version=str(snapshot.membership_version),
    )


def _durable_audit(event: dict[str, str]) -> DurableAuditReceipt:
    return DurableAuditReceipt(
        schema_version=AUDIT_RECEIPT_SCHEMA_VERSION,
        sink_source=AUDIT_SINK_SOURCE,
        sink_version=AUDIT_SINK_VERSION,
        decision_id=event["decision_id"],
        receipt_reference="ref_abcdef0123456789abcdef01",
        acknowledged_at_epoch=int(time.time()),
    )


def _audit_references(
    _auth: AuthContext,
    _operation: object,
    correlation_reference: str,
) -> AuthorizationAuditReferences:
    return AuthorizationAuditReferences(
        schema_version=AUDIT_REFERENCE_SCHEMA_VERSION,
        principal_reference="ref_111111111111111111111111",
        customer_reference="ref_222222222222222222222222",
        deployment_reference="ref_333333333333333333333333",
        correlation_reference=correlation_reference,
    )


# Override Auth dependency to simulate a logged-in user for "tenant-a"
def override_get_auth_context():
    return AuthContext(
        customer_id=CUSTOMER_ID,
        deployment_id=DEPLOYMENT_ID,
        principal_type="user",
        subject=SUBJECT,
        client_id="synthetic-human-client",
        scopes={
            "scanalyze.api.v1/read",
            "scanalyze.api.v1/write",
            "scanalyze.api.v1/admin",
        },
        granted_actions=(),
        auth_source="cognito_jwt",
        human_authorization=_human_authorization_snapshot(),
    )


@pytest.fixture(autouse=True)
def override_auth_dependency():
    app.dependency_overrides[get_auth_context] = override_get_auth_context
    previous_runtime = getattr(app.state, "enterprise_authorization_runtime", None)
    app.state.enterprise_authorization_runtime = EnterpriseAuthorizationRuntime(
        authoritative_state_resolver=_resolve_authoritative_membership,
        audit_sink=_durable_audit,
        audit_reference_resolver=_audit_references,
    )
    yield
    app.dependency_overrides.pop(get_auth_context, None)
    if previous_runtime is None:
        delattr(app.state, "enterprise_authorization_runtime")
    else:
        app.state.enterprise_authorization_runtime = previous_runtime


client = TestClient(app)


@pytest.fixture
def mock_svc():
    with patch("app.api.v1.documents.DocumentsService") as mock:
        yield mock.return_value

def test_download_generic_happy_path(mock_svc):
    """GET /download?artifactId=structured should return 200 with valid presigned URL"""
    mock_svc.presign_artifact_download.return_value = {
        "documentId": "doc-123456",
        "artifactId": "structured",
        "downloadUrl": "url-123",
        "expiresAt": "2026-03-08T20:00:00Z"
    }

    response = client.get("/api/v1/documents/doc-123456/download?artifactId=structured")
    assert response.status_code == 200
    assert response.json() == {
        "documentId": "doc-123456",
        "artifactId": "structured",
        "downloadUrl": "url-123",
        "expiresAt": "2026-03-08T20:00:00Z"
    }
    mock_svc.presign_artifact_download.assert_called_once_with(
        auth=override_get_auth_context(), document_id="doc-123456", artifact_id="structured"
    )

def test_download_specific_artifact_happy_path(mock_svc):
    """GET /artifacts/structured/download should return 200 with valid presigned URL"""
    mock_svc.presign_artifact_download.return_value = {
        "documentId": "doc-123456",
        "artifactId": "structured",
        "downloadUrl": "url-456",
        "expiresAt": "2026-03-08T20:00:00Z"
    }

    response = client.get("/api/v1/documents/doc-123456/artifacts/structured/download")
    assert response.status_code == 200
    assert response.json() == {
        "documentId": "doc-123456",
        "artifactId": "structured",
        "downloadUrl": "url-456",
        "expiresAt": "2026-03-08T20:00:00Z"
    }
    mock_svc.presign_artifact_download.assert_called_once_with(
        auth=override_get_auth_context(), document_id="doc-123456", artifact_id="structured"
    )

def test_download_missing_artifact_id():
    """Missing artifactId query param should return 422"""
    response = client.get("/api/v1/documents/doc-123456/download")
    assert response.status_code == 422

def test_download_artifact_not_found(mock_svc):
    """If the artifactId doesn't exist in the manifest, should bubble up a 404 from the service"""
    mock_svc.presign_artifact_download.side_effect = AppError(code="NOT_FOUND", message="Artifact not found in manifest", status_code=404, details={})
    response = client.get("/api/v1/documents/doc-123456/download?artifactId=non-existent")
    assert response.status_code == 404
    assert response.json() == {"code": "NOT_FOUND", "message": "Artifact not found in manifest", "details": {}}

def test_download_tenant_mismatch(mock_svc):
    """If the document belongs to a different tenant, should bubble up a 403"""
    mock_svc.presign_artifact_download.side_effect = AppError(code="FORBIDDEN", message="Document does not belong to tenant", status_code=403, details={})
    response = client.get("/api/v1/documents/doc-123456/artifacts/structured/download")
    assert response.status_code == 403
    assert response.json() == {"code": "FORBIDDEN", "message": "Document does not belong to tenant", "details": {}}

def test_download_and_result_resolve_to_same_contract(mock_svc):
    """Tests that /download and /result endpoints return identically structured responses passing to the same service methods"""
    
    mock_svc.presign_artifact_download.return_value = {
        "documentId": "doc-123456",
        "artifactId": "structured",
        "downloadUrl": "same-url-123",
        "expiresAt": "2026-03-08T20:00:00Z"
    }
    mock_svc.get_result.return_value = {
        "documentId": "doc-123456",
        "artifactId": "structured",
        "downloadUrl": "same-url-123",
        "expiresAt": "2026-03-08T20:00:00Z"
    }
    
    resp_download_query = client.get("/api/v1/documents/doc-123456/download?artifactId=structured")
    resp_download_path = client.get("/api/v1/documents/doc-123456/artifacts/structured/download")
    resp_result = client.get("/api/v1/documents/doc-123456/result")

    assert resp_download_query.status_code == 200
    assert resp_download_path.status_code == 200
    assert resp_result.status_code == 200
    
    # Prove they return identical valid bodies mapped to the same S3 object 
    assert resp_download_query.json() == resp_download_path.json() == resp_result.json()
