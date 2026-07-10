import pytest
import uuid
from unittest.mock import MagicMock, patch
from datetime import datetime, timezone
from app.services.documents import DocumentsService
from app.errors import AppError

@pytest.fixture
def mock_repo():
    with patch("app.services.documents.DocumentsRepository") as mock:
        yield mock.return_value

@pytest.fixture
def mock_s3():
    with patch("app.services.documents.s3_client") as mock:
        mock_client = mock.return_value
        mock_client.generate_presigned_url.return_value = "https://s3.amazonaws.com/presigned-url"
        yield mock_client

@pytest.fixture
def mock_sqs():
    with patch("app.services.documents.sqs_client") as mock:
        yield mock.return_value

@pytest.fixture
def documents_service(mock_repo, mock_s3, mock_sqs):
    service = DocumentsService()
    # Mock settings
    service.settings = MagicMock()
    service.settings.download_url_ttl_seconds = 600
    service.settings.documents_table_name = "test-table"
    service.settings.get_bucket.side_effect = lambda x: f"bucket-{x}"
    return service

def test_list_artifacts_happy_path(documents_service, mock_repo):
    """Verifies that list_artifacts resolves strictly from the DynamoDB manifest"""
    tenant = "tenant-a"
    doc_id = "doc-123"
    
    mock_repo.get_document.return_value = {
        "tenantId": tenant,
        "documentId": doc_id,
        "artifacts": {
            "raw": {"bucket": "bucket-raw", "key": f"{tenant}/{doc_id}/raw.pdf"},
            "ocr": {"bucket": "bucket-ocr", "key": f"{tenant}/{doc_id}/ocr.json"}
        }
    }
    
    result = documents_service.list_artifacts(tenant, doc_id)
    assert result["documentId"] == doc_id
    artifacts = result["artifacts"]
    assert len(artifacts) == 2
    
    # ensure it returns the literal alias keys
    raw_artifact = next((a for a in artifacts if a["artifactId"] == "raw"), None)
    assert raw_artifact is not None
    assert raw_artifact["bucketAlias"] == "raw"
    assert "bucket-raw" in raw_artifact["uri"]

def test_list_artifacts_legacy_fallback(documents_service, mock_repo):
    """Verifies that list_artifacts falls back to legacy anchor if modern ref is missing"""
    tenant = "tenant-legacy"
    doc_id = "doc-legacy"
    
    mock_repo.get_document.return_value = {
        "tenantId": tenant,
        "documentId": doc_id,
        "artifacts": {
            "structured": {"bucket": "bucket-legacy", "key": f"{tenant}/{doc_id}/result.json"}
        }
    }
    
    result = documents_service.list_artifacts(tenant, doc_id)
    assert result["documentId"] == doc_id
    artifacts = result["artifacts"]
    assert len(artifacts) == 1
    
    struct_artifact = next((a for a in artifacts if a["artifactId"] == "structured"), None)
    assert struct_artifact is not None
    assert struct_artifact["bucketAlias"] == "structured"
    assert "bucket-legacy" in struct_artifact["uri"]

def test_list_artifacts_tenant_mismatch(documents_service, mock_repo):
    """Security negative: another tenant tries to list artifacts"""
    mock_repo.get_document.return_value = {"tenantId": "tenant-b"}
    with pytest.raises(AppError) as exc_info:
        documents_service.list_artifacts("tenant-a", "doc-123")
    assert exc_info.value.status_code == 403

def test_presign_artifact_download_happy_path(documents_service, mock_repo, mock_s3):
    """Verifies downloading an artifact directly via alias from the manifest"""
    tenant = "tenant-a"
    doc_id = "doc-123"
    mock_repo.get_document.return_value = {
        "tenantId": tenant,
        "artifacts": {
            "structured": {"bucket": "bucket-structured", "key": f"{tenant}/{doc_id}/structured.json"}
        }
    }
    
    result = documents_service.presign_artifact_download(tenant, doc_id, "structured")
    assert result["downloadUrl"] == "https://s3.amazonaws.com/presigned-url"
    assert result["artifactId"] == "structured"
    
    # Assert s3 generate_presigned_url was called correctly
    mock_s3.generate_presigned_url.assert_called_once_with(
        ClientMethod="get_object",
        Params={
            "Bucket": "bucket-structured",
            "Key": f"{tenant}/{doc_id}/structured.json",
            "ResponseContentDisposition": "attachment",
        },
        ExpiresIn=600,
    )

def test_presign_artifact_inconsistent_manifest(documents_service, mock_repo):
    """Inconsistent manifest negative: requesting an alias that doesn't exist in doc dict"""
    tenant = "tenant-a"
    doc_id = "doc-123"
    mock_repo.get_document.return_value = {
        "tenantId": tenant,
        "artifacts": {
            "raw": {"bucket": "bucket-raw", "key": "key1"}
        }
    }
    
    # Requesting 'structured' which is missing from artifacts manifest
    with pytest.raises(AppError) as exc_info:
        documents_service.presign_artifact_download(tenant, doc_id, "structured")
    assert exc_info.value.status_code == 404
    assert "not found in manifest" in exc_info.value.message.lower()

def test_get_result_happy_path(documents_service, mock_repo, mock_s3):
    """Verifies get_result returns 200 with presigned url if status is COMPLETED & has structured"""
    tenant = "tenant-a"
    doc_id = "doc-123"
    mock_repo.get_document.return_value = {
        "status": "COMPLETED",
        "tenantId": tenant,
        "artifacts": {
            "structured": {"bucket": "bucket-struct", "key": "key.json"}
        }
    }
    
    result = documents_service.get_result(tenant, doc_id)
    assert result["downloadUrl"] == "https://s3.amazonaws.com/presigned-url"
    assert result["artifactId"] == "structured"

def test_get_result_not_completed(documents_service, mock_repo):
    """Verifies get_result throws 409 if status is not COMPLETED"""
    tenant = "tenant-a"
    doc_id = "doc-123"
    mock_repo.get_document.return_value = {
        "status": "PROCESSING",
        "tenantId": tenant,
        "artifacts": {
            "structured": {"bucket": "bucket-struct", "key": "key.json"}
        }
    }
    
    with pytest.raises(AppError) as exc_info:
        documents_service.get_result(tenant, doc_id)
    assert exc_info.value.status_code == 409
    assert "Result not ready" in exc_info.value.message

def test_get_result_completed_but_no_manifest_entry(documents_service, mock_repo):
    """Inconsistent manifest negative: status is COMPLETED but artifact is missing"""
    tenant = "tenant-a"
    doc_id = "doc-123"
    mock_repo.get_document.return_value = {
        "status": "COMPLETED",
        "tenantId": tenant,
        "artifacts": {
            "raw": {"bucket": "bucket-raw", "key": "key.pdf"}
        }
    }
    
    with pytest.raises(AppError) as exc_info:
        documents_service.get_result(tenant, doc_id)
    assert exc_info.value.status_code == 404
    assert "Final result artifact not found in manifest" in exc_info.value.message
