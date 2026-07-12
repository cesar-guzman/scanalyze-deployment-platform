import pytest
from fastapi.testclient import TestClient
from unittest.mock import patch

from app.main import app
from app.auth import get_auth_context, AuthContext
from app.errors import AppError

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
        "createdBy": "test-user",
        "status": "OPEN",
        "metadata": {"source": "api"}
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
