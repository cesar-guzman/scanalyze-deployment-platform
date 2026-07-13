import json
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from pydantic import ValidationError

from app.auth import AuthContext
from app.authorization import ObjectOwnership
from app.config import Settings
from app.errors import AppError
from app.services.documents import DocumentsService

OCR_SRC = Path(__file__).resolve().parents[2] / "scanalyze-ocr-worker" / "src"
if str(OCR_SRC) not in sys.path:
    sys.path.insert(0, str(OCR_SRC))

from ocr_worker.boundary import authorize_document_boundary


CUSTOMER_ID = "cust_01ARZ3NDEKTSV4RRFFQ69G5FAW"
DEPLOYMENT_ID = "dep_01ARZ3NDEKTSV4RRFFQ69G5FAV"
DOCUMENT_ID = "doc-gug89-synthetic"
QUEUE_URL = "https://example.invalid/ingest-queue"


def _auth() -> AuthContext:
    return AuthContext(
        customer_id=CUSTOMER_ID,
        deployment_id=DEPLOYMENT_ID,
        subject="synthetic-user",
        auth_source="cognito_jwt",
    )


def _document(*, processing_domain=None) -> dict:
    ownership = ObjectOwnership(CUSTOMER_ID, DEPLOYMENT_ID)
    record = {
        "documentId": DOCUMENT_ID,
        "tenantId": CUSTOMER_ID,
        **ownership.record_fields(),
        "input": {
            "bucket": "synthetic-raw-bucket",
            "key": f"{ownership.document_prefix(DOCUMENT_ID)}synthetic.pdf",
            "contentType": "application/pdf",
        },
        "status": "CREATED",
    }
    if processing_domain is not None:
        record["processing_domain"] = processing_domain
    return record


def _submit_service(*, processing_domain=None, document=None) -> DocumentsService:
    service = DocumentsService.__new__(DocumentsService)
    service.settings = SimpleNamespace(
        first_stage="ingest",
        processing_domain=processing_domain,
        get_bucket=lambda alias: f"synthetic-{alias}-bucket",
        get_queue_url=lambda stage: QUEUE_URL if stage == "ingest" else None,
    )
    service.repo = MagicMock()
    service.repo.get_document.return_value = document or _document(
        processing_domain=processing_domain,
    )
    service.repo.set_stage_enqueue_pending.return_value = True
    service.sqs = MagicMock()
    service.sqs.send_message.return_value = {"MessageId": "synthetic-message-id"}
    service.s3 = MagicMock()
    service.logger = MagicMock()
    return service


def _create_service(*, processing_domain=None) -> DocumentsService:
    service = DocumentsService.__new__(DocumentsService)
    service.settings = SimpleNamespace(
        documents_table_name="synthetic-documents",
        upload_url_ttl_seconds=60,
        processing_domain=processing_domain,
        get_bucket=lambda alias: f"synthetic-{alias}-bucket",
    )
    service.repo = MagicMock()
    service.batches_repo = MagicMock()
    service.s3 = MagicMock()
    service.s3.generate_presigned_url.return_value = (
        "https://example.invalid/synthetic-upload"
    )
    service.sqs = MagicMock()
    service.logger = MagicMock()
    return service


def test_first_stage_is_closed_to_canonical_ingest(monkeypatch) -> None:
    monkeypatch.setenv("INGEST_QUEUE_URL", QUEUE_URL)
    monkeypatch.setenv("OCR_QUEUE_URL", "https://example.invalid/ocr-queue")

    settings = Settings(FIRST_STAGE="ingest", SQS_QUEUE_URLS_JSON=None)

    assert settings.get_queue_url("ingest") == QUEUE_URL
    assert settings.get_queue_url("ocr") is None
    with pytest.raises(ValidationError):
        Settings(FIRST_STAGE="ocr")
    with pytest.raises(ValidationError):
        Settings(SCANALYZE_PROCESSING_DOMAIN=CUSTOMER_ID)


def test_request_stage_can_only_confirm_the_configured_first_stage() -> None:
    service = _submit_service()

    result = service.submit_document(
        auth=_auth(),
        document_id=DOCUMENT_ID,
        stage=" INGEST ",
    )

    assert result["stage"] == "ingest"
    with pytest.raises(AppError) as exc_info:
        service.submit_document(
            auth=_auth(),
            document_id=DOCUMENT_ID,
            stage="classify",
        )
    assert exc_info.value.code == "INVALID_STAGE"
    assert exc_info.value.status_code == 400
    assert service.sqs.send_message.call_count == 1


@pytest.mark.parametrize("processing_domain", [None, "bank"])
def test_create_persists_processing_domain_only_from_trusted_config(
    processing_domain,
) -> None:
    service = _create_service(processing_domain=processing_domain)

    service.create_document(
        auth=_auth(),
        subject="synthetic-user",
        email=None,
        name=None,
        filename="synthetic.pdf",
        content_type="application/pdf",
    )

    item = service.repo.create_document.call_args.args[0]
    if processing_domain is None:
        assert "processing_domain" not in item
        assert item["documentRoute"] == "platform"
    else:
        assert item["processing_domain"] == processing_domain
        assert item["documentRoute"] == processing_domain
    assert item.get("processing_domain") != CUSTOMER_ID


@pytest.mark.parametrize("processing_domain", [None, "bank", "personal", "gov"])
def test_created_record_is_accepted_by_exact_ocr_boundary(processing_domain) -> None:
    service = _create_service(processing_domain=processing_domain)
    service.create_document(
        auth=_auth(),
        subject="synthetic-user",
        email=None,
        name=None,
        filename="synthetic.pdf",
        content_type="application/pdf",
    )
    item = service.repo.create_document.call_args.args[0]

    authorized = authorize_document_boundary(
        item=item,
        message_customer_id=CUSTOMER_ID,
        message_deployment_id=DEPLOYMENT_ID,
        message_document_id=item["documentId"],
        message_source_bucket=item["input"]["bucket"],
        message_source_key=item["input"]["key"],
        runtime_customer_id=CUSTOMER_ID,
        runtime_deployment_id=DEPLOYMENT_ID,
        trusted_source_bucket="synthetic-raw-bucket",
        trusted_artifact_bucket="synthetic-ocr-bucket",
    )

    assert authorized.document_route == (processing_domain or "platform")


def test_submit_emits_strict_owner_bound_v2_envelope() -> None:
    service = _submit_service(processing_domain="bank")

    result = service.submit_document(auth=_auth(), document_id=DOCUMENT_ID)

    assert result["enqueued"] is True
    body = json.loads(service.sqs.send_message.call_args.kwargs["MessageBody"])
    assert set(body) == {
        "schemaVersion",
        "documentId",
        "customer_id",
        "deployment_id",
        "ownership_schema_version",
        "pipeline_stage",
        "processing_domain",
        "enqueue_id",
        "raw",
        "contentType",
        "_metadata",
    }
    assert body["schemaVersion"] == "scanalyze.ingest.v2"
    assert body["customer_id"] == CUSTOMER_ID
    assert body["deployment_id"] == DEPLOYMENT_ID
    assert body["ownership_schema_version"] == 1
    assert body["pipeline_stage"] == "ingest"
    assert body["processing_domain"] == "bank"
    assert body["enqueue_id"]
    assert body["raw"] == {
        "bucket": "synthetic-raw-bucket",
        "key": service.repo.get_document.return_value["input"]["key"],
    }
    assert "tenantId" not in body
    assert "stage" not in body
    assert "route" not in body["_metadata"]
    assert "customerStack" not in body["_metadata"]
    assert "uploaderUserId" not in body["_metadata"]


def test_unclassified_envelope_does_not_infer_customer_as_domain() -> None:
    service = _submit_service()

    service.submit_document(auth=_auth(), document_id=DOCUMENT_ID)

    body = json.loads(service.sqs.send_message.call_args.kwargs["MessageBody"])
    assert body.get("processing_domain") is None
    assert CUSTOMER_ID not in {
        body.get("processing_domain"),
        body["_metadata"].get("route"),
    }


def test_stored_processing_domain_must_match_trusted_config() -> None:
    service = _submit_service(
        processing_domain=None,
        document=_document(processing_domain="bank"),
    )

    with pytest.raises(AppError) as exc_info:
        service.submit_document(auth=_auth(), document_id=DOCUMENT_ID)

    assert exc_info.value.code == "INVALID_PROCESSING_DOMAIN"
    service.repo.set_stage_enqueue_pending.assert_not_called()
    service.sqs.send_message.assert_not_called()


@pytest.mark.parametrize(
    "send_result,send_error",
    [
        ({}, None),
        (None, RuntimeError("synthetic transport failure")),
    ],
)
def test_enqueue_failure_requires_message_id_and_recovers_pending(
    send_result,
    send_error,
) -> None:
    service = _submit_service()
    if send_error is not None:
        service.sqs.send_message.side_effect = send_error
    else:
        service.sqs.send_message.return_value = send_result

    with pytest.raises(AppError) as exc_info:
        service.submit_document(auth=_auth(), document_id=DOCUMENT_ID)

    assert exc_info.value.code == "SQS_ENQUEUE_FAILED"
    service.repo.set_stage_enqueue_failed.assert_called_once()
    failure = service.repo.set_stage_enqueue_failed.call_args.kwargs
    assert failure["stage"] == "ingest"
    assert failure["error_message"] == "Failed to enqueue message"


def test_state_checkpoint_failure_recovers_pending() -> None:
    service = _submit_service()
    service.repo.set_stage_enqueued.side_effect = RuntimeError(
        "synthetic checkpoint failure"
    )

    with pytest.raises(AppError) as exc_info:
        service.submit_document(auth=_auth(), document_id=DOCUMENT_ID)

    assert exc_info.value.code == "SQS_ENQUEUE_FAILED"
    service.repo.set_stage_enqueue_failed.assert_called_once()


def test_pending_claim_exception_attempts_fail_closed_recovery() -> None:
    service = _submit_service()
    service.repo.set_stage_enqueue_pending.side_effect = RuntimeError(
        "synthetic pending checkpoint failure"
    )

    with pytest.raises(AppError) as exc_info:
        service.submit_document(auth=_auth(), document_id=DOCUMENT_ID)

    assert exc_info.value.code == "SQS_ENQUEUE_FAILED"
    service.sqs.send_message.assert_not_called()
    service.repo.set_stage_enqueue_failed.assert_called_once()
