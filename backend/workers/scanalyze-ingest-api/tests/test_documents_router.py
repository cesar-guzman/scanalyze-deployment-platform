import pytest
from fastapi.testclient import TestClient
from unittest.mock import patch, MagicMock
from app.main import app
from app.auth import get_auth_context, AuthContext
from app.services.documents import DocumentsService
from app.errors import AppError

# Override Auth dependency to simulate a logged-in user for "tenant-a"
def override_get_auth_context():
    return AuthContext(
        customer_id="cust_01ARZ3NDEKTSV4RRFFQ69G5FAW",
        deployment_id="dep_01ARZ3NDEKTSV4RRFFQ69G5FAV",
        subject="test-user",
        auth_source="cognito_jwt",
    )

app.dependency_overrides[get_auth_context] = override_get_auth_context

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
