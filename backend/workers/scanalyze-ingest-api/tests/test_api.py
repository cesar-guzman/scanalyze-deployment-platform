import pytest
import uuid
from unittest.mock import MagicMock, patch
from datetime import datetime, timezone
from app.services.documents import DocumentsService
from app.errors import AppError
from app.auth import AuthContext
from app.authorization import ObjectOwnership

CUSTOMER_ID = "cust_01ARZ3NDEKTSV4RRFFQ69G5FAW"
DEPLOYMENT_ID = "dep_01ARZ3NDEKTSV4RRFFQ69G5FAV"

def _auth(customer_id=CUSTOMER_ID, deployment_id=DEPLOYMENT_ID):
    return AuthContext(
        customer_id=customer_id,
        deployment_id=deployment_id,
        subject="synthetic-user",
        auth_source="cognito_jwt",
    )

def _record(document_id, **values):
    ownership = ObjectOwnership(CUSTOMER_ID, DEPLOYMENT_ID)
    record = {
        "documentId": document_id,
        "tenantId": CUSTOMER_ID,
        **ownership.record_fields(),
    }
    record.update(values)
    return record

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
    auth = _auth()
    ownership = ObjectOwnership.from_auth(auth)
    doc_id = "doc-123"
    
    mock_repo.get_document.return_value = _record(doc_id, artifacts={
            "raw": {"bucket": "bucket-raw", "key": f"{ownership.document_prefix(doc_id)}raw.pdf"},
            "ocr": {"bucket": "bucket-ocr", "key": f"{ownership.document_prefix(doc_id)}ocr.json"}
        })
    
    result = documents_service.list_artifacts(auth, doc_id)
    assert result["documentId"] == doc_id
    artifacts = result["artifacts"]
    assert len(artifacts) == 2
    
    # ensure it returns the literal alias keys
    raw_artifact = next((a for a in artifacts if a["artifactId"] == "raw"), None)
    assert raw_artifact is not None
    assert raw_artifact["bucketAlias"] == "raw"
    assert "bucket-raw" in raw_artifact["uri"]

def test_list_artifacts_legacy_record_fails_closed(documents_service, mock_repo):
    """Legacy customer-only records are migration-required, never inferred."""
    doc_id = "doc-legacy"
    
    mock_repo.get_document.return_value = {
        "tenantId": CUSTOMER_ID,
        "documentId": doc_id,
        "artifacts": {
            "structured": {"bucket": "bucket-structured", "key": "legacy/result.json"}
        }
    }
    
    with pytest.raises(AppError) as exc_info:
        documents_service.list_artifacts(_auth(), doc_id)
    assert exc_info.value.status_code == 404

def test_list_artifacts_tenant_mismatch(documents_service, mock_repo):
    """Security negative: another tenant tries to list artifacts"""
    mock_repo.get_document.return_value = _record("doc-123", customer_id="cust_01ARZ3NDEKTSV4RRFFQ69G5FAX")
    with pytest.raises(AppError) as exc_info:
        documents_service.list_artifacts(_auth(), "doc-123")
    assert exc_info.value.status_code == 404

def test_presign_artifact_download_happy_path(documents_service, mock_repo, mock_s3):
    """Verifies downloading an artifact directly via alias from the manifest"""
    auth = _auth()
    ownership = ObjectOwnership.from_auth(auth)
    doc_id = "doc-123"
    key = f"{ownership.document_prefix(doc_id)}structured.json"
    mock_repo.get_document.return_value = _record(
        doc_id,
        artifacts={"structured": {"bucket": "bucket-structured", "key": key}},
    )
    
    result = documents_service.presign_artifact_download(auth, doc_id, "structured")
    assert result["downloadUrl"] == "https://s3.amazonaws.com/presigned-url"
    assert result["artifactId"] == "structured"
    
    # Assert s3 generate_presigned_url was called correctly
    mock_s3.generate_presigned_url.assert_called_once_with(
        ClientMethod="get_object",
        Params={
            "Bucket": "bucket-structured",
            "Key": key,
            "ResponseContentDisposition": "attachment",
        },
        ExpiresIn=600,
    )

def test_presign_artifact_inconsistent_manifest(documents_service, mock_repo):
    """Inconsistent manifest negative: requesting an alias that doesn't exist in doc dict"""
    auth = _auth()
    doc_id = "doc-123"
    mock_repo.get_document.return_value = _record(doc_id, artifacts={
            "raw": {"bucket": "bucket-raw", "key": "key1"}
        })
    
    # Requesting 'structured' which is missing from artifacts manifest
    with pytest.raises(AppError) as exc_info:
        documents_service.presign_artifact_download(auth, doc_id, "structured")
    assert exc_info.value.status_code == 404
    assert "not found in manifest" in exc_info.value.message.lower()

def test_get_result_happy_path(documents_service, mock_repo, mock_s3):
    """Verifies get_result returns 200 with presigned url if status is COMPLETED & has structured"""
    auth = _auth()
    ownership = ObjectOwnership.from_auth(auth)
    doc_id = "doc-123"
    mock_repo.get_document.return_value = _record(
        doc_id,
        status="COMPLETED",
        artifacts={"structured": {
            "bucket": "bucket-structured",
            "key": f"{ownership.document_prefix(doc_id)}result.json",
        }},
    )
    
    result = documents_service.get_result(auth, doc_id)
    assert result["downloadUrl"] == "https://s3.amazonaws.com/presigned-url"
    assert result["artifactId"] == "structured"

def test_get_result_not_completed(documents_service, mock_repo):
    """Verifies get_result throws 409 if status is not COMPLETED"""
    auth = _auth()
    doc_id = "doc-123"
    mock_repo.get_document.return_value = _record(doc_id, status="PROCESSING", artifacts={
            "structured": {"bucket": "bucket-struct", "key": "key.json"}
        })
    
    with pytest.raises(AppError) as exc_info:
        documents_service.get_result(auth, doc_id)
    assert exc_info.value.status_code == 409
    assert "Result not ready" in exc_info.value.message

def test_get_result_completed_but_no_manifest_entry(documents_service, mock_repo):
    """Inconsistent manifest negative: status is COMPLETED but artifact is missing"""
    auth = _auth()
    doc_id = "doc-123"
    mock_repo.get_document.return_value = _record(doc_id, status="COMPLETED", artifacts={
            "raw": {"bucket": "bucket-raw", "key": "key.pdf"}
        })
    
    with pytest.raises(AppError) as exc_info:
        documents_service.get_result(auth, doc_id)
    assert exc_info.value.status_code == 404
    assert "not found in manifest" in exc_info.value.message
