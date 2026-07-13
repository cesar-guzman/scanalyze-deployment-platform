"""GUG-114 object-level authorization regression tests.

These tests intentionally exercise the real service and storage boundaries with
synthetic metadata only.  No AWS call is made.
"""
from __future__ import annotations

from copy import deepcopy
import json
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from app.auth import AuthContext
from app.auth import _resolve_local_mock_auth
from app.authorization import (
    ObjectAction,
    ObjectOwnership,
    authorize_batch,
    authorize_batch_membership,
    authorize_document,
)
from app.errors import AppError
from app.repositories.documents import DocumentsRepository
from app.services.batches import BatchesService
from app.services.documents import DocumentsService


CUSTOMER_A = "cust_01ARZ3NDEKTSV4RRFFQ69G5FAW"
CUSTOMER_B = "cust_01ARZ3NDEKTSV4RRFFQ69G5FAX"
DEPLOYMENT_A = "dep_01ARZ3NDEKTSV4RRFFQ69G5FAV"
DEPLOYMENT_B = "dep_01ARZ3NDEKTSV4RRFFQ69G5FAY"
DOCUMENT_ID = "doc-synthetic-0001"
BATCH_ID = "batch-synthetic-0001"


def _auth(
    *,
    customer_id: str = CUSTOMER_A,
    deployment_id: str | None = DEPLOYMENT_A,
    principal_type: str = "user",
    actions: tuple[str, ...] = (),
) -> AuthContext:
    return AuthContext(
        customer_id=customer_id,
        deployment_id=deployment_id,
        principal_type=principal_type,  # type: ignore[arg-type]
        subject="synthetic-principal",
        client_id="synthetic-client" if principal_type == "m2m" else None,
        granted_actions=actions,
        auth_source=(
            "m2m_identity_binding_v1" if principal_type == "m2m" else "cognito_jwt"
        ),
    )


def _document(
    *,
    customer_id: object = CUSTOMER_A,
    deployment_id: object = DEPLOYMENT_A,
    batch_id: object = BATCH_ID,
) -> dict:
    return {
        "documentId": DOCUMENT_ID,
        "batchId": batch_id,
        "customer_id": customer_id,
        "deployment_id": deployment_id,
        "ownership_schema_version": 1,
        "tenantId": customer_id,
        "status": "COMPLETED",
        "input": {"filename": "synthetic.pdf", "contentType": "application/pdf"},
        "stages": {},
        "artifacts": {
            "structured": {
                "bucket": "synthetic-structured-bucket",
                "key": "trusted/synthetic/result.json",
            }
        },
    }


def _batch(
    *,
    customer_id: object = CUSTOMER_A,
    deployment_id: object = DEPLOYMENT_A,
) -> dict:
    return {
        "batch_id": BATCH_ID,
        "batchId": BATCH_ID,
        "customer_id": customer_id,
        "deployment_id": deployment_id,
        "ownership_schema_version": 1,
        "tenantId": customer_id,
        "status": "OPEN",
        "createdAt": "2026-07-12T00:00:00+00:00",
        "metadata": {},
    }


def _assert_hidden(error: AppError, kind: str) -> None:
    assert error.status_code == 404
    assert error.code == "NOT_FOUND"
    assert error.message == f"{kind} not found"
    assert error.details == {}


def test_valid_user_can_access_only_exactly_owned_document_and_batch() -> None:
    auth = _auth()

    assert authorize_document(auth, _document(), ObjectAction.READ) == ObjectOwnership(
        customer_id=CUSTOMER_A,
        deployment_id=DEPLOYMENT_A,
    )
    assert authorize_batch(auth, _batch(), ObjectAction.READ) == ObjectOwnership(
        customer_id=CUSTOMER_A,
        deployment_id=DEPLOYMENT_A,
    )


@pytest.mark.parametrize(
    ("customer_id", "deployment_id"),
    [
        (CUSTOMER_B, DEPLOYMENT_A),
        (CUSTOMER_A, DEPLOYMENT_B),
        (CUSTOMER_B, DEPLOYMENT_B),
    ],
)
def test_document_cross_customer_or_deployment_is_hidden(
    customer_id: str,
    deployment_id: str,
) -> None:
    with pytest.raises(AppError) as exc_info:
        authorize_document(
            _auth(),
            _document(customer_id=customer_id, deployment_id=deployment_id),
            ObjectAction.READ,
        )

    _assert_hidden(exc_info.value, "Document")


@pytest.mark.parametrize(
    "mutation",
    [
        lambda record: record.pop("customer_id"),
        lambda record: record.pop("deployment_id"),
        lambda record: record.update(customer_id=""),
        lambda record: record.update(deployment_id=""),
        lambda record: record.update(customer_id=None),
        lambda record: record.update(deployment_id=123),
        lambda record: record.update(ownership_schema_version=0),
        lambda record: record.update(tenantId=CUSTOMER_B),
        lambda record: record.update(customerId=CUSTOMER_B),
        lambda record: record.update(deploymentId=DEPLOYMENT_B),
    ],
)
def test_missing_malformed_or_conflicting_document_ownership_is_hidden(mutation) -> None:
    record = _document()
    mutation(record)

    with pytest.raises(AppError) as exc_info:
        authorize_document(_auth(), record, ObjectAction.READ)

    _assert_hidden(exc_info.value, "Document")


def test_legacy_tenant_only_document_and_batch_fail_closed() -> None:
    legacy_document = {"documentId": DOCUMENT_ID, "tenantId": CUSTOMER_A}
    legacy_batch = {"batchId": BATCH_ID, "tenantId": CUSTOMER_A}

    with pytest.raises(AppError) as doc_error:
        authorize_document(_auth(), legacy_document, ObjectAction.READ)
    with pytest.raises(AppError) as batch_error:
        authorize_batch(_auth(), legacy_batch, ObjectAction.READ)

    _assert_hidden(doc_error.value, "Document")
    _assert_hidden(batch_error.value, "Batch")


def test_missing_and_foreign_objects_share_the_same_enumeration_safe_error() -> None:
    errors: list[tuple[str, str, int, dict]] = []
    for record in (None, _document(customer_id=CUSTOMER_B)):
        with pytest.raises(AppError) as exc_info:
            authorize_document(_auth(), record, ObjectAction.READ)
        error = exc_info.value
        errors.append((error.code, error.message, error.status_code, error.details))

    assert errors[0] == errors[1] == ("NOT_FOUND", "Document not found", 404, {})


def test_missing_auth_deployment_unknown_principal_and_missing_context_fail_closed() -> None:
    for auth in (
        _auth(deployment_id=None),
        _auth(principal_type="unknown"),
        None,
    ):
        with pytest.raises(AppError) as exc_info:
            authorize_document(auth, _document(), ObjectAction.READ)  # type: ignore[arg-type]
        assert exc_info.value.status_code == 403
        assert exc_info.value.details == {}


def test_local_mock_auth_requires_an_explicit_valid_deployment_binding() -> None:
    settings = SimpleNamespace(
        env="test",
        local_mock_tenant_id=CUSTOMER_A,
        local_mock_subject="synthetic-local-user",
        scanalyze_deployment_id=DEPLOYMENT_A,
    )

    auth = _resolve_local_mock_auth(settings)

    assert auth.customer_id == CUSTOMER_A
    assert auth.deployment_id == DEPLOYMENT_A
    authorize_document(auth, _document(), ObjectAction.READ)

    settings.scanalyze_deployment_id = None
    with pytest.raises(RuntimeError, match="SCANALYZE_DEPLOYMENT_ID"):
        _resolve_local_mock_auth(settings)


def test_m2m_actions_are_rechecked_at_the_object_boundary() -> None:
    read_only = _auth(principal_type="m2m", actions=("read",))

    authorize_document(read_only, _document(), ObjectAction.READ)
    for action in (ObjectAction.WRITE, ObjectAction.EXPORT):
        with pytest.raises(AppError) as exc_info:
            authorize_document(read_only, _document(), action)
        assert exc_info.value.status_code == 403

    exporter = _auth(principal_type="m2m", actions=("read", "admin"))
    authorize_document(exporter, _document(), ObjectAction.EXPORT)


def test_batch_membership_requires_exact_object_and_membership_binding() -> None:
    auth = _auth()
    batch = _batch()
    owned = _document()

    authorize_batch_membership(auth, batch, [owned], ObjectAction.READ)

    for invalid in (
        _document(customer_id=CUSTOMER_B),
        _document(deployment_id=DEPLOYMENT_B),
        _document(batch_id="batch-foreign-0001"),
        {**_document(), "batchId": None},
    ):
        with pytest.raises(AppError) as exc_info:
            authorize_batch_membership(auth, batch, [owned, invalid], ObjectAction.READ)
        _assert_hidden(exc_info.value, "Batch")


def _document_create_service(batch_record: dict) -> DocumentsService:
    service = DocumentsService.__new__(DocumentsService)
    service.settings = SimpleNamespace(
        documents_table_name="synthetic-documents",
        upload_url_ttl_seconds=60,
        get_bucket=lambda alias: f"synthetic-{alias}-bucket",
    )
    service.repo = MagicMock()
    service.batches_repo = MagicMock()
    service.batches_repo.get_batch.return_value = batch_record
    service.s3 = MagicMock()
    service.s3.generate_presigned_url.return_value = "https://example.invalid/presigned"
    service.sqs = MagicMock()
    service.logger = MagicMock()
    return service


def test_create_document_derives_ownership_and_membership_from_auth() -> None:
    auth = _auth()
    ownership = ObjectOwnership.from_auth(auth)
    service = _document_create_service(_batch())

    response = service.create_document(
        auth=auth,
        subject="synthetic-principal",
        email=None,
        name=None,
        filename="synthetic.pdf",
        content_type="application/pdf",
        batch_id=BATCH_ID,
    )

    item = service.repo.create_document.call_args.args[0]
    assert item["customer_id"] == CUSTOMER_A
    assert item["deployment_id"] == DEPLOYMENT_A
    assert item["ownership_schema_version"] == 1
    assert item["ownership_batch_key"] == ownership.batch_partition(BATCH_ID)
    assert item["input"]["key"].startswith(ownership.document_prefix(response["documentId"]))
    assert service.repo.create_document.call_args.kwargs["ownership"] == ownership


def test_create_document_rejects_foreign_batch_before_presign_or_write() -> None:
    foreign = _batch(customer_id=CUSTOMER_B)
    service = _document_create_service(foreign)

    with pytest.raises(AppError) as exc_info:
        service.create_document(
            auth=_auth(),
            subject="synthetic-principal",
            email=None,
            name=None,
            filename="synthetic.pdf",
            content_type="application/pdf",
            batch_id=BATCH_ID,
        )

    _assert_hidden(exc_info.value, "Batch")
    service.s3.generate_presigned_url.assert_not_called()
    service.repo.create_document.assert_not_called()


def test_create_batch_persists_canonical_immutable_ownership() -> None:
    service = BatchesService.__new__(BatchesService)
    service.repo = MagicMock()
    auth = _auth()
    ownership = ObjectOwnership.from_auth(auth)

    response = service.create_batch(
        auth=auth,
        subject="synthetic-principal",
        email=None,
        name=None,
        metadata={},
    )

    item = service.repo.create_batch.call_args.args[0]
    assert item["customer_id"] == CUSTOMER_A
    assert item["deployment_id"] == DEPLOYMENT_A
    assert item["ownership_schema_version"] == 1
    assert response["createdBy"] is None
    assert "customer_id" not in response
    assert service.repo.create_batch.call_args.kwargs["ownership"] == ownership


def _submit_service(document: dict) -> DocumentsService:
    service = DocumentsService.__new__(DocumentsService)
    service.repo = MagicMock()
    service.repo.get_document.return_value = document
    service.repo.set_stage_enqueue_pending.return_value = True
    service.settings = SimpleNamespace(
        first_stage="ingest",
        get_bucket=lambda alias: f"synthetic-{alias}-bucket",
        get_queue_url=lambda stage: "https://example.invalid/synthetic-queue",
    )
    service.sqs = MagicMock()
    service.sqs.send_message.return_value = {"MessageId": "synthetic-message"}
    service.s3 = MagicMock()
    service.logger = MagicMock()
    return service


def test_submit_document_authorizes_locator_and_emits_dual_binding() -> None:
    auth = _auth()
    ownership = ObjectOwnership.from_auth(auth)
    document = _document()
    document["input"] = {
        "bucket": "synthetic-raw-bucket",
        "key": f"{ownership.document_prefix(DOCUMENT_ID)}synthetic.pdf",
        "contentType": "application/pdf",
    }
    service = _submit_service(document)

    response = service.submit_document(auth=auth, document_id=DOCUMENT_ID)

    assert response["enqueued"] is True
    message = json.loads(service.sqs.send_message.call_args.kwargs["MessageBody"])
    assert message["customer_id"] == CUSTOMER_A
    assert message["deployment_id"] == DEPLOYMENT_A
    assert message["ownership_schema_version"] == 1
    assert service.repo.set_stage_enqueue_pending.call_args.kwargs["ownership"] == ownership
    assert service.repo.set_stage_enqueued.call_args.kwargs["ownership"] == ownership


def test_submit_document_rejects_untrusted_stored_key_before_mutation_or_sqs() -> None:
    document = _document()
    document["input"] = {
        "bucket": "synthetic-raw-bucket",
        "key": "request-controlled/foreign-prefix/synthetic.pdf",
        "contentType": "application/pdf",
    }
    service = _submit_service(document)

    with pytest.raises(AppError) as exc_info:
        service.submit_document(auth=_auth(), document_id=DOCUMENT_ID)

    assert exc_info.value.status_code == 404
    service.repo.set_stage_enqueue_pending.assert_not_called()
    service.sqs.send_message.assert_not_called()


def test_presign_rejects_unbound_document_before_s3() -> None:
    service = DocumentsService.__new__(DocumentsService)
    service.repo = MagicMock()
    service.repo.get_document.return_value = {"documentId": DOCUMENT_ID}
    service.s3 = MagicMock()
    service.settings = SimpleNamespace(download_url_ttl_seconds=60)
    service.logger = MagicMock()

    with pytest.raises(AppError) as exc_info:
        service.presign_artifact_download(
            auth=_auth(),
            document_id=DOCUMENT_ID,
            artifact_id="structured",
        )

    _assert_hidden(exc_info.value, "Document")
    service.s3.generate_presigned_url.assert_not_called()


def _artifact_service() -> DocumentsService:
    service = DocumentsService.__new__(DocumentsService)
    service.settings = SimpleNamespace(
        get_bucket=lambda alias: f"synthetic-{alias}-bucket",
    )
    service.logger = MagicMock()
    return service


@pytest.mark.parametrize(
    ("bucket_alias", "key"),
    [
        ("ocr", f"platform/{DOCUMENT_ID}/ocr.json"),
        ("ocr", f"bank/{DOCUMENT_ID}/ocr.json"),
        ("ocr", f"personal/{DOCUMENT_ID}/ocr.json"),
        ("ocr", f"gov/{DOCUMENT_ID}/ocr.json"),
        ("structured", f"bank/{DOCUMENT_ID}/result.json"),
        ("structured", f"personal/{DOCUMENT_ID}/result.json"),
        ("structured", f"gov/{DOCUMENT_ID}/result.json"),
    ],
)
def test_reviewed_worker_v1_artifact_contract_remains_available(
    bucket_alias: str,
    key: str,
) -> None:
    service = _artifact_service()
    ownership = ObjectOwnership.from_auth(_auth())
    bucket = f"synthetic-{bucket_alias}-bucket"

    assert service._validate_artifact_locator(
        ownership,
        DOCUMENT_ID,
        bucket,
        key,
    ) == (bucket, key)


def test_canonical_owner_bound_artifact_contract_is_accepted() -> None:
    service = _artifact_service()
    ownership = ObjectOwnership.from_auth(_auth())
    key = f"{ownership.document_prefix(DOCUMENT_ID)}result.json"

    assert service._validate_artifact_locator(
        ownership,
        DOCUMENT_ID,
        "synthetic-structured-bucket",
        key,
    ) == ("synthetic-structured-bucket", key)


@pytest.mark.parametrize(
    ("bucket", "key"),
    [
        ("synthetic-ocr-bucket", f"bank/foreign-document/ocr.json"),
        ("synthetic-structured-bucket", f"bank/foreign-document/result.json"),
        ("synthetic-raw-bucket", f"bank/{DOCUMENT_ID}/result.json"),
        ("synthetic-structured-bucket", f"arbitrary/{DOCUMENT_ID}/result.json"),
        ("synthetic-structured-bucket", f"bank/{DOCUMENT_ID}/other.json"),
        ("synthetic-structured-bucket", f"bank/{DOCUMENT_ID}/../result.json"),
    ],
)
def test_worker_v1_artifact_contract_rejects_arbitrary_or_cross_object_locators(
    bucket: str,
    key: str,
) -> None:
    service = _artifact_service()

    with pytest.raises(AppError) as exc_info:
        service._validate_artifact_locator(
            ObjectOwnership.from_auth(_auth()),
            DOCUMENT_ID,
            bucket,
            key,
        )

    assert exc_info.value.status_code == 404
    assert exc_info.value.message == "Artifact not found"
    service.logger.warning.assert_called_once_with(
        "artifact_authorization_failed",
        reason="untrusted_stored_locator",
    )


def test_batch_export_rejects_foreign_member_before_s3() -> None:
    service = BatchesService.__new__(BatchesService)
    service.repo = MagicMock()
    service.repo.get_batch.return_value = _batch()
    service.docs_repo = MagicMock()
    service.docs_repo.get_documents_by_batch.return_value = [
        _document(),
        _document(customer_id=CUSTOMER_B),
    ]
    service.doc_service = MagicMock()
    service.s3 = MagicMock()
    service.logger = MagicMock()

    with pytest.raises(AppError) as exc_info:
        service.export_manifest(auth=_auth(), batch_id=BATCH_ID)

    _assert_hidden(exc_info.value, "Batch")
    service.s3.get_object.assert_not_called()


def test_document_updates_bind_customer_and_deployment_in_dynamo_condition() -> None:
    repo = DocumentsRepository.__new__(DocumentsRepository)
    repo.table_name = "synthetic-documents"
    repo.table = MagicMock()
    repo.schema = SimpleNamespace(
        pk_name="documentId",
        sk_name=None,
        pk_template="{document_id}",
        sk_template=None,
    )
    ownership = ObjectOwnership(CUSTOMER_A, DEPLOYMENT_A)

    assert repo.set_stage_enqueue_pending(
        document_id=DOCUMENT_ID,
        stage="ingest",
        enqueue_id="enqueue-synthetic",
        ownership=ownership,
    )

    kwargs = repo.table.update_item.call_args.kwargs
    assert "#customer_id = :customer_id" in kwargs["ConditionExpression"]
    assert "#deployment_id = :deployment_id" in kwargs["ConditionExpression"]
    assert kwargs["ExpressionAttributeValues"][":customer_id"] == CUSTOMER_A
    assert kwargs["ExpressionAttributeValues"][":deployment_id"] == DEPLOYMENT_A


def test_batch_query_uses_exact_ownership_partition_and_paginates() -> None:
    repo = DocumentsRepository.__new__(DocumentsRepository)
    repo.table_name = "synthetic-documents"
    repo.table = MagicMock()
    repo.logger = MagicMock()
    repo.schema = SimpleNamespace(
        pk_name="documentId",
        sk_name=None,
        pk_template="{document_id}",
        sk_template=None,
    )
    repo.table.query.side_effect = [
        {"Items": [_document()], "LastEvaluatedKey": {"pk": "next"}},
        {"Items": [], "Count": 0},
    ]
    ownership = ObjectOwnership(CUSTOMER_A, DEPLOYMENT_A)

    assert repo.get_documents_by_batch(BATCH_ID, ownership=ownership) == [_document()]

    first = repo.table.query.call_args_list[0].kwargs
    second = repo.table.query.call_args_list[1].kwargs
    assert first["IndexName"] == "BatchOwnershipIndex"
    assert first["ExpressionAttributeValues"][":ownership_batch_key"] == (
        ownership.batch_partition(BATCH_ID)
    )
    assert second["ExclusiveStartKey"] == {"pk": "next"}
    assert second["ExpressionAttributeValues"] == first["ExpressionAttributeValues"]


def test_owned_record_fields_are_immutable_and_request_values_are_irrelevant() -> None:
    auth = _auth()
    ownership = ObjectOwnership.from_auth(auth)
    record = _document()
    spoofed_payload = {
        "customer_id": CUSTOMER_B,
        "deployment_id": DEPLOYMENT_B,
        "tenantId": CUSTOMER_B,
        "s3Prefix": "foreign/prefix",
    }

    assert ownership.record_fields() == {
        "customer_id": CUSTOMER_A,
        "deployment_id": DEPLOYMENT_A,
        "ownership_schema_version": 1,
        "ownership_key": ownership.partition,
    }
    assert authorize_document(auth, record, ObjectAction.READ) == ownership
    assert deepcopy(spoofed_payload) == spoofed_payload
