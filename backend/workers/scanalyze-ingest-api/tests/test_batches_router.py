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
    with patch("app.api.v1.batches.BatchesService") as mock:
        yield mock.return_value

def test_create_batch(mock_svc):
    mock_svc.create_batch.return_value = {
        "batchId": "b-123",
        "tenantId": "tenant-a",
        "createdAt": "2026-03-08T20:00:00Z",
        "createdBy": "test-user",
        "status": "OPEN",
        "metadata": {"source": "api"}
    }
    
    response = client.post("/api/v1/batches", json={"metadata": {"source": "api"}})
    assert response.status_code == 201
    assert response.json() == {
        "batchId": "b-123",
        "tenantId": "tenant-a",
        "createdAt": "2026-03-08T20:00:00Z",
        "createdBy": None,
        "status": "OPEN",
        "metadata": {}
    }
    mock_svc.create_batch.assert_called_once_with(
        auth=override_get_auth_context(), subject="test-user", email=None, name=None, metadata={"source": "api"}
    )

def test_get_batch(mock_svc):
    mock_svc.get_batch.return_value = {
        "batchId": "b-1234",
        "tenantId": "tenant-a",
        "createdAt": "2026-03-08T20:00:00Z",
        "createdBy": "test-user",
        "status": "OPEN",
        "metadata": {}
    }
    
    response = client.get("/api/v1/batches/b-12345678")
    assert response.status_code == 200
    assert response.json()["createdBy"] is None
    assert "test-user" not in response.text
    mock_svc.get_batch.assert_called_once_with(auth=override_get_auth_context(), batch_id="b-12345678")

def test_get_batch_not_found(mock_svc):
    mock_svc.get_batch.side_effect = AppError(code="NOT_FOUND", message="Batch not found", status_code=404, details={})
    response = client.get("/api/v1/batches/b-12345678")
    assert response.status_code == 404
    assert response.json() == {"code": "NOT_FOUND", "message": "Batch not found", "details": {}}

def test_get_batch_documents(mock_svc):
    mock_svc.get_batch_documents.return_value = [
        {"documentId": "doc-1", "status": "COMPLETED", "createdAt": "2026-03-08T20:00:00Z"}
    ]
    
    response = client.get("/api/v1/batches/b-12345678/documents")
    assert response.status_code == 200
    assert response.json() == [
        {"documentId": "doc-1", "status": "COMPLETED", "createdAt": "2026-03-08T20:00:00Z"}
    ]
    mock_svc.get_batch_documents.assert_called_once_with(auth=override_get_auth_context(), batch_id="b-12345678")

def test_export_manifest(mock_svc):
    mock_svc.export_manifest.return_value = {
        "manifestVersion": "1.0",
        "batchId": "b-12345678",
        "generatedAt": "2026-03-08T20:00:00Z",
        "summary": {"total": 1, "completed": 1, "failed": 0, "pending": 0},
        "documents": [
            {
                "batchId": "b-12345678",
                "documentId": "doc-1",
                "docType": "invoice",
                "status": "COMPLETED",
                "generatedAt": "2026-03-08T20:05:00Z",
                "artifactReferences": [],
                "errorCode": None,
                "errorMessage": None
            }
        ]
    }
    
    response = client.get("/api/v1/batches/b-12345678/manifest")
    assert response.status_code == 200
    data = response.json()
    assert data["manifestVersion"] == "1.0"
    assert data["documents"][0]["docType"] == "invoice"
    mock_svc.export_manifest.assert_called_once_with(auth=override_get_auth_context(), batch_id="b-12345678")

def test_export_json_stream(mock_svc):
    from fastapi.responses import StreamingResponse
    def dummy_generator():
        yield b'{"chunks": "true"}'
    mock_svc.export_json.return_value = StreamingResponse(dummy_generator(), media_type="application/json")
    
    response = client.get("/api/v1/batches/b-12345678/exports/json")
    assert response.status_code == 200
    assert response.headers["content-type"] == "application/json"
    assert response.content == b'{"chunks": "true"}'

def test_export_csv_stream(mock_svc):
    from fastapi.responses import StreamingResponse
    def dummy_generator():
        yield b'col1,col2\nval1,val2\n'
    mock_svc.export_csv.return_value = StreamingResponse(dummy_generator(), media_type="text/csv; charset=utf-8")
    
    response = client.get("/api/v1/batches/b-12345678/exports/csv")
    assert response.status_code == 200
    assert response.headers["content-type"] == "text/csv; charset=utf-8"
    assert response.content == b'col1,col2\nval1,val2\n'

def test_export_zip(mock_svc, tmp_path):
    from fastapi.responses import FileResponse

    archive = tmp_path / "synthetic-export.zip"
    archive.write_bytes(b"synthetic zip content")
    mock_svc.export_zip.return_value = FileResponse(archive)

    response = client.get("/api/v1/batches/b-12345678/exports/zip")
    assert response.status_code == 200
    assert response.content == b"synthetic zip content"
    mock_svc.export_zip.assert_called_once_with(auth=override_get_auth_context(), batch_id="b-12345678")
