import json
from io import BytesIO
from unittest.mock import Mock, patch

import pytest
from botocore.exceptions import ClientError
from pydantic import ValidationError

from gov_worker import s3 as gov_s3
from gov_worker.contracts import GovExtractMessage
from gov_worker.dynamo import (
    build_artifact_binding,
    require_authorized_document,
    reserve_structured_artifact,
    update_document_status,
)
from gov_worker.processors.extract import process_gov_extract_message


CUSTOMER_ID = "cust_01ARZ3NDEKTSV4RRFFQ69G5FAW"
DEPLOYMENT_ID = "dep_01ARZ3NDEKTSV4RRFFQ69G5FAV"
FOREIGN_CUSTOMER_ID = "cust_01ARZ3NDEKTSV4RRFFQ69G5FAX"
FOREIGN_DEPLOYMENT_ID = "dep_01ARZ3NDEKTSV4RRFFQ69G5FAX"
CHECKPOINT_ID = "b" * 32
CONTENT_SHA256 = "a" * 64
ARTIFACT_WRITER = "scanalyze-gov-worker"
ARTIFACT_SCHEMA_VERSION = "1.0"


def _message(**overrides):
    payload = {
        "schemaVersion": "scanalyze.extract.v2",
        "documentId": "doc-123",
        "customer_id": CUSTOMER_ID,
        "deployment_id": DEPLOYMENT_ID,
        "ownership_schema_version": 1,
        "pipeline_stage": "gov-extract",
        "processing_domain": "gov",
        "raw": {"bucket": "raw-trusted", "key": "raw/doc-123.pdf"},
        "ocr": {"bucket": "ocr-trusted", "key": "ocr/doc-123.json"},
    }
    payload.update(overrides)
    return payload


def _structured_key():
    return (
        f"customers/{CUSTOMER_ID}/deployments/{DEPLOYMENT_ID}/"
        "documents/doc-123/structured/gov/result.json"
    )


def _authorized_record(status="GOV_EXTRACTED", *, include_structured=True):
    artifacts = {"ocr": {"bucket": "ocr-trusted", "key": "ocr/doc-123.json"}}
    if include_structured:
        artifacts["structured"] = {
            "bucket": "structured-trusted",
            "key": _structured_key(),
        }
    record = {
        "documentId": "doc-123",
        "customer_id": CUSTOMER_ID,
        "deployment_id": DEPLOYMENT_ID,
        "ownership_schema_version": 1,
        "processing_domain": "gov",
        "status": status,
        "input": {"bucket": "raw-trusted", "key": "raw/doc-123.pdf"},
        "artifacts": artifacts,
    }
    if include_structured:
        record["stages"] = {
            "gov_extract": {
                "status": "COMPLETED",
                "artifact": build_artifact_binding(
                    structured_bucket="structured-trusted",
                    structured_key=_structured_key(),
                    customer_id=CUSTOMER_ID,
                    deployment_id=DEPLOYMENT_ID,
                    document_id="doc-123",
                    tenant="gov",
                    checkpoint_id=CHECKPOINT_ID,
                    writer=ARTIFACT_WRITER,
                    artifact_schema_version=ARTIFACT_SCHEMA_VERSION,
                    content_sha256=CONTENT_SHA256,
                ),
            }
        }
    return record


def _writing_record():
    record = _authorized_record("GOV_EXTRACTING", include_structured=False)
    record["stages"] = {
        "gov_extract": {
            "status": "WRITING",
            "artifact": build_artifact_binding(
                structured_bucket="structured-trusted",
                structured_key=_structured_key(),
                customer_id=CUSTOMER_ID,
                deployment_id=DEPLOYMENT_ID,
                document_id="doc-123",
                tenant="gov",
                checkpoint_id=CHECKPOINT_ID,
                writer=ARTIFACT_WRITER,
                artifact_schema_version=ARTIFACT_SCHEMA_VERSION,
            ),
        }
    }
    return record


def _artifact_kwargs():
    return {
        "customer_id": CUSTOMER_ID,
        "deployment_id": DEPLOYMENT_ID,
        "document_id": "doc-123",
        "processing_domain": "gov",
        "ownership_schema_version": 1,
        "pipeline_stage": "gov-extract",
        "writer": ARTIFACT_WRITER,
        "artifact_schema_version": ARTIFACT_SCHEMA_VERSION,
        "checkpoint_id": CHECKPOINT_ID,
    }


def _config_value(key, default=None):
    return {
        "data-foundation/structured_bucket_name": "structured-trusted",
        "data-foundation/documents_table_name": "documents",
        "queues/validate_url": "https://sqs.test/validate",
    }.get(key, default)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("schemaVersion", "scanalyze.gov-extract.v1"),
        ("customer_id", None),
        ("deployment_id", None),
        ("ownership_schema_version", 2),
        ("pipeline_stage", "bank-extract"),
        ("processing_domain", "bank"),
    ],
)
def test_extract_contract_rejects_legacy_or_unbound_messages(field, value):
    payload = _message()
    if value is None:
        payload.pop(field)
    else:
        payload[field] = value

    with pytest.raises(ValidationError):
        GovExtractMessage(**payload)


def test_invalid_message_is_not_acknowledged_or_processed():
    with (
        patch("gov_worker.processors.extract.require_authorized_document") as authorize,
        patch("gov_worker.processors.extract.is_already_extracted") as idempotency,
        patch("gov_worker.processors.extract.get_ocr_text") as s3_read,
        patch("gov_worker.processors.extract.invoke_bedrock_gov_doc") as bedrock,
        patch("gov_worker.processors.extract.sqs_client.send_message") as send,
    ):
        assert process_gov_extract_message(json.dumps({"documentId": "legacy"}), "r", "q") is False

    authorize.assert_not_called()
    idempotency.assert_not_called()
    s3_read.assert_not_called()
    bedrock.assert_not_called()
    send.assert_not_called()


def test_foreign_document_fails_before_s3_bedrock_or_idempotency():
    with (
        patch("gov_worker.processors.extract.config.get", side_effect=_config_value),
        patch(
            "gov_worker.processors.extract.require_authorized_document",
            side_effect=ValueError("Document is unavailable"),
        ) as authorize,
        patch("gov_worker.processors.extract.is_already_extracted") as idempotency,
        patch("gov_worker.processors.extract.get_ocr_text") as s3_read,
        patch("gov_worker.processors.extract.invoke_bedrock_gov_doc") as bedrock,
        patch("gov_worker.processors.extract.sqs_client.send_message") as send,
    ):
        with pytest.raises(ValueError, match="Document is unavailable"):
            process_gov_extract_message(json.dumps(_message()), "r", "q")

    authorize.assert_called_once()
    idempotency.assert_not_called()
    s3_read.assert_not_called()
    bedrock.assert_not_called()
    send.assert_not_called()


@pytest.mark.parametrize(
    ("field", "value"),
    [("customer_id", FOREIGN_CUSTOMER_ID), ("deployment_id", FOREIGN_DEPLOYMENT_ID)],
)
def test_runtime_owner_mismatch_has_zero_protected_effects(field, value):
    payload = _message(**{field: value})
    with (
        patch("gov_worker.processors.extract.config.get") as config_get,
        patch("gov_worker.processors.extract.require_authorized_document") as authorize,
        patch("gov_worker.processors.extract.is_already_extracted") as idempotency,
        patch("gov_worker.processors.extract.get_ocr_text") as s3_read,
        patch("gov_worker.processors.extract.invoke_bedrock_gov_doc") as bedrock,
        patch("gov_worker.processors.extract.sqs_client.send_message") as send,
    ):
        with pytest.raises(ValueError, match="runtime deployment"):
            process_gov_extract_message(json.dumps(payload), "r", "q")

    config_get.assert_not_called()
    authorize.assert_not_called()
    idempotency.assert_not_called()
    s3_read.assert_not_called()
    bedrock.assert_not_called()
    send.assert_not_called()


def test_metadata_extra_field_fails_closed_before_protected_effects():
    payload = _message(_metadata={"correlationId": "corr-123", "tenantId": "spoofed"})
    with (
        patch("gov_worker.processors.extract.config.require_owner") as runtime_owner,
        patch("gov_worker.processors.extract.require_authorized_document") as authorize,
        patch("gov_worker.processors.extract.is_already_extracted") as idempotency,
        patch("gov_worker.processors.extract.get_ocr_text") as s3_read,
        patch("gov_worker.processors.extract.invoke_bedrock_gov_doc") as bedrock,
        patch("gov_worker.processors.extract.sqs_client.send_message") as send,
    ):
        assert process_gov_extract_message(json.dumps(payload), "r", "q") is False

    runtime_owner.assert_not_called()
    authorize.assert_not_called()
    idempotency.assert_not_called()
    s3_read.assert_not_called()
    bedrock.assert_not_called()
    send.assert_not_called()


@pytest.mark.parametrize("status", ["COMPLETED", "FAILED"])
def test_terminal_duplicate_is_noop(status):
    with (
        patch("gov_worker.processors.extract.config.get", side_effect=_config_value),
        patch(
            "gov_worker.processors.extract.require_authorized_document",
            return_value=_authorized_record(status),
        ),
        patch("gov_worker.processors.extract.is_already_extracted") as idempotency,
        patch("gov_worker.processors.extract.get_ocr_text") as s3_read,
        patch("gov_worker.processors.extract.invoke_bedrock_gov_doc") as bedrock,
        patch("gov_worker.processors.extract.update_document_status") as update,
        patch(
            "gov_worker.processors.extract.require_structured_artifact_proof",
            return_value=CONTENT_SHA256,
        ),
        patch("gov_worker.processors.extract.sqs_client.send_message") as send,
    ):
        assert process_gov_extract_message(json.dumps(_message()), "r", "q") is True

    idempotency.assert_not_called()
    s3_read.assert_not_called()
    bedrock.assert_not_called()
    update.assert_not_called()
    send.assert_not_called()


def test_terminal_duplicate_without_structured_checkpoint_is_denied():
    with (
        patch("gov_worker.processors.extract.config.get", side_effect=_config_value),
        patch(
            "gov_worker.processors.extract.require_authorized_document",
            return_value=_authorized_record("COMPLETED", include_structured=False),
        ),
        patch("gov_worker.processors.extract.is_already_extracted") as idempotency,
        patch("gov_worker.processors.extract.sqs_client.send_message") as send,
    ):
        with pytest.raises(RuntimeError, match="no authorized structured artifact"):
            process_gov_extract_message(json.dumps(_message()), "r", "q")

    idempotency.assert_not_called()
    send.assert_not_called()


def test_uncheckpointed_artifact_collision_is_denied():
    with (
        patch("gov_worker.processors.extract.config.get", side_effect=_config_value),
        patch(
            "gov_worker.processors.extract.require_authorized_document",
            return_value=_authorized_record("OCR_COMPLETED", include_structured=False),
        ),
        patch("gov_worker.processors.extract.is_already_extracted", return_value=True),
        patch("gov_worker.processors.extract.get_ocr_text") as s3_read,
        patch("gov_worker.processors.extract.invoke_bedrock_gov_doc") as bedrock,
        patch("gov_worker.processors.extract.update_document_status") as update,
        patch("gov_worker.processors.extract.sqs_client.send_message") as send,
    ):
        with pytest.raises(RuntimeError, match="not authorized"):
            process_gov_extract_message(json.dumps(_message()), "r", "q")

    s3_read.assert_not_called()
    bedrock.assert_not_called()
    update.assert_not_called()
    send.assert_not_called()


def test_structured_write_is_create_only_and_never_overwrites():
    with patch("gov_worker.s3.s3_client.put_object", return_value={}) as put_object:
        created, digest = gov_s3.save_structured_artifact(
            "structured-trusted",
            _structured_key(),
            {"documentId": "doc-123"},
            **_artifact_kwargs(),
        )

    assert created is True
    assert len(digest) == 64
    assert put_object.call_args.kwargs["IfNoneMatch"] == "*"
    assert put_object.call_args.kwargs["Metadata"]["customer-id"] == CUSTOMER_ID
    assert put_object.call_args.kwargs["Metadata"]["checkpoint-id"] == CHECKPOINT_ID
    assert put_object.call_args.kwargs["Metadata"]["content-sha256"] == digest


def test_oversized_structured_artifact_is_rejected_before_s3_write():
    oversized = {"payload": "x" * gov_s3.MAX_STRUCTURED_ARTIFACT_BYTES}
    with patch("gov_worker.s3.s3_client.put_object") as put_object:
        with pytest.raises(ValueError, match="unavailable"):
            gov_s3.save_structured_artifact(
                "structured-trusted",
                _structured_key(),
                oversized,
                **_artifact_kwargs(),
            )

    put_object.assert_not_called()


def test_structured_precondition_failure_reports_collision_without_overwrite():
    error = ClientError(
        {
            "Error": {"Code": "PreconditionFailed"},
            "ResponseMetadata": {"HTTPStatusCode": 412},
        },
        "PutObject",
    )
    with patch("gov_worker.s3.s3_client.put_object", side_effect=error):
        created, _ = gov_s3.save_structured_artifact(
            "structured-trusted",
            _structured_key(),
            {"documentId": "doc-123"},
            **_artifact_kwargs(),
        )

    assert created is False


@pytest.mark.parametrize(
    ("metadata_key", "metadata_value"),
    [
        ("customer-id", FOREIGN_CUSTOMER_ID),
        ("deployment-id", FOREIGN_DEPLOYMENT_ID),
        ("writer", "legacy-writer"),
        ("checkpoint-id", "c" * 32),
        ("content-sha256", "0" * 64),
    ],
)
def test_structured_artifact_proof_rejects_mismatched_metadata(
    metadata_key, metadata_value
):
    data = {"documentId": "doc-123"}
    body = gov_s3._structured_body(data)
    digest = gov_s3.hashlib.sha256(body).hexdigest()
    metadata = gov_s3._structured_metadata(
        **_artifact_kwargs(),
        content_sha256=digest,
    )
    metadata[metadata_key] = metadata_value
    with patch(
        "gov_worker.s3.s3_client.get_object",
        return_value={
            "Body": BytesIO(body),
            "ContentLength": len(body),
            "Metadata": metadata,
        },
    ):
        with pytest.raises(ValueError, match="unavailable"):
            gov_s3.require_structured_artifact_proof(
                "structured-trusted",
                _structured_key(),
                **_artifact_kwargs(),
                expected_digest=digest,
            )


def test_structured_artifact_proof_accepts_exact_metadata_and_digest():
    body = gov_s3._structured_body({"documentId": "doc-123"})
    digest = gov_s3.hashlib.sha256(body).hexdigest()
    metadata = gov_s3._structured_metadata(
        **_artifact_kwargs(),
        content_sha256=digest,
    )
    with patch(
        "gov_worker.s3.s3_client.get_object",
        return_value={
            "Body": BytesIO(body),
            "ContentLength": len(body),
            "Metadata": metadata,
        },
    ):
        assert gov_s3.require_structured_artifact_proof(
            "structured-trusted",
            _structured_key(),
            **_artifact_kwargs(),
            expected_digest=digest,
        ) == digest


def test_s3_create_then_finalize_failure_is_retryable_partial_commit():
    events = []

    def reserve(**kwargs):
        events.append("reserve")

    def save(*args, **kwargs):
        events.append("put")
        return True, CONTENT_SHA256

    def finalize(**kwargs):
        events.append("finalize")
        raise RuntimeError("synthetic finalize failure")

    with (
        patch("gov_worker.processors.extract.config.get", side_effect=_config_value),
        patch(
            "gov_worker.processors.extract.require_authorized_document",
            return_value=_authorized_record("OCR_COMPLETED", include_structured=False),
        ),
        patch("gov_worker.processors.extract.is_already_extracted", return_value=False),
        patch("gov_worker.processors.extract.reserve_structured_artifact", side_effect=reserve),
        patch(
            "gov_worker.processors.extract.get_ocr_text",
            return_value=("synthetic text", {"chars": 14, "truncated": False}),
        ),
        patch(
            "gov_worker.processors.extract.invoke_bedrock_gov_doc",
            return_value=("{}", {"inputTokens": 1}),
        ),
        patch(
            "gov_worker.processors.extract.parse_and_normalize",
            return_value={"model": {}},
        ),
        patch("gov_worker.processors.extract.save_structured_artifact", side_effect=save),
        patch("gov_worker.processors.extract.update_document_status", side_effect=finalize),
        patch("gov_worker.processors.extract.sqs_client.send_message") as send,
    ):
        with pytest.raises(RuntimeError, match="synthetic finalize failure"):
            process_gov_extract_message(json.dumps(_message()), "r", "q")

    assert events == ["reserve", "put", "finalize"]
    send.assert_not_called()


def test_oversized_structured_artifact_never_finalizes_or_enqueues():
    with (
        patch("gov_worker.processors.extract.config.get", side_effect=_config_value),
        patch(
            "gov_worker.processors.extract.require_authorized_document",
            return_value=_authorized_record("OCR_COMPLETED", include_structured=False),
        ),
        patch("gov_worker.processors.extract.is_already_extracted", return_value=False),
        patch("gov_worker.processors.extract.reserve_structured_artifact") as reserve,
        patch(
            "gov_worker.processors.extract.get_ocr_text",
            return_value=("synthetic text", {"chars": 14, "truncated": False}),
        ),
        patch(
            "gov_worker.processors.extract.invoke_bedrock_gov_doc",
            return_value=("{}", {"inputTokens": 1}),
        ),
        patch(
            "gov_worker.processors.extract.parse_and_normalize",
            return_value={"model": {}},
        ),
        patch(
            "gov_worker.processors.extract.save_structured_artifact",
            side_effect=ValueError("Structured artifact is unavailable"),
        ),
        patch("gov_worker.processors.extract.update_document_status") as update,
        patch("gov_worker.processors.extract.sqs_client.send_message") as send,
    ):
        with pytest.raises(ValueError, match="unavailable"):
            process_gov_extract_message(json.dumps(_message()), "r", "q")

    reserve.assert_called_once()
    update.assert_not_called()
    send.assert_not_called()


def test_retry_recovers_owner_bound_partial_commit_without_bedrock():
    with (
        patch("gov_worker.processors.extract.config.get", side_effect=_config_value),
        patch(
            "gov_worker.processors.extract.require_authorized_document",
            return_value=_writing_record(),
        ) as authorize,
        patch("gov_worker.processors.extract.is_already_extracted", return_value=True),
        patch("gov_worker.processors.extract.get_ocr_text") as s3_read,
        patch("gov_worker.processors.extract.invoke_bedrock_gov_doc") as bedrock,
        patch(
            "gov_worker.processors.extract.require_structured_artifact_proof",
            return_value=CONTENT_SHA256,
        ) as verify,
        patch("gov_worker.processors.extract.save_structured_artifact") as save,
        patch("gov_worker.processors.extract.update_document_status") as update,
        patch(
            "gov_worker.processors.extract.sqs_client.send_message",
            return_value={"MessageId": "validate-message"},
        ) as send,
    ):
        assert process_gov_extract_message(json.dumps(_message()), "r", "q") is True

    authorize.assert_called_once()
    verify.assert_called_once()
    s3_read.assert_not_called()
    bedrock.assert_not_called()
    save.assert_not_called()
    assert update.call_args.kwargs["checkpoint_id"] == CHECKPOINT_ID
    assert update.call_args.kwargs["content_sha256"] == CONTENT_SHA256
    send.assert_called_once()


def test_retry_rejects_partial_commit_when_s3_proof_mismatches():
    with (
        patch("gov_worker.processors.extract.config.get", side_effect=_config_value),
        patch(
            "gov_worker.processors.extract.require_authorized_document",
            return_value=_writing_record(),
        ),
        patch("gov_worker.processors.extract.is_already_extracted", return_value=True),
        patch("gov_worker.processors.extract.get_ocr_text") as s3_read,
        patch("gov_worker.processors.extract.invoke_bedrock_gov_doc") as bedrock,
        patch(
            "gov_worker.processors.extract.require_structured_artifact_proof",
            side_effect=ValueError("Structured artifact is unavailable"),
        ),
        patch("gov_worker.processors.extract.update_document_status") as update,
        patch("gov_worker.processors.extract.sqs_client.send_message") as send,
    ):
        with pytest.raises(ValueError, match="unavailable"):
            process_gov_extract_message(json.dumps(_message()), "r", "q")

    s3_read.assert_not_called()
    bedrock.assert_not_called()
    update.assert_not_called()
    send.assert_not_called()


def test_authorized_idempotent_message_propagates_owner_and_safe_metadata():
    payload = _message(
        _metadata={
            "correlationId": "corr-123",
            "traceId": "trace-123",
        }
    )
    with (
        patch("gov_worker.processors.extract.config.get", side_effect=_config_value),
        patch(
            "gov_worker.processors.extract.require_authorized_document",
            return_value=_authorized_record(),
        ) as authorize,
        patch("gov_worker.processors.extract.is_already_extracted", return_value=True),
        patch(
            "gov_worker.processors.extract.require_structured_artifact_proof",
            return_value=CONTENT_SHA256,
        ),
        patch("gov_worker.processors.extract.update_document_status") as update,
        patch(
            "gov_worker.processors.extract.sqs_client.send_message",
            return_value={"MessageId": "msg-123"},
        ) as send,
    ):
        assert process_gov_extract_message(json.dumps(payload), "r", "q") is True

    authorize.assert_called_once_with(
        table_name="documents",
        document_id="doc-123",
        tenant="gov",
        customer_id=CUSTOMER_ID,
        deployment_id=DEPLOYMENT_ID,
        raw_bucket="raw-trusted",
        raw_key="raw/doc-123.pdf",
        ocr_bucket="ocr-trusted",
        ocr_key="ocr/doc-123.json",
    )
    update.assert_not_called()
    outbound = json.loads(send.call_args.kwargs["MessageBody"])
    assert outbound["schemaVersion"] == "scanalyze.validate.v2"
    assert outbound["customer_id"] == CUSTOMER_ID
    assert outbound["deployment_id"] == DEPLOYMENT_ID
    assert outbound["ownership_schema_version"] == 1
    assert outbound["pipeline_stage"] == "validate"
    assert outbound["processing_domain"] == "gov"
    assert outbound["_metadata"] == {"correlationId": "corr-123", "traceId": "trace-123"}


def test_missing_sqs_message_id_does_not_acknowledge_message():
    with (
        patch("gov_worker.processors.extract.config.get", side_effect=_config_value),
        patch(
            "gov_worker.processors.extract.require_authorized_document",
            return_value=_authorized_record(),
        ),
        patch("gov_worker.processors.extract.is_already_extracted", return_value=True),
        patch(
            "gov_worker.processors.extract.require_structured_artifact_proof",
            return_value=CONTENT_SHA256,
        ),
        patch("gov_worker.processors.extract.update_document_status"),
        patch("gov_worker.processors.extract.sqs_client.send_message", return_value={}),
    ):
        with pytest.raises(RuntimeError, match="did not acknowledge"):
            process_gov_extract_message(json.dumps(_message()), "r", "q")


def test_dynamo_authorization_requires_exact_owner_domain_and_locators():
    table = Mock()
    table.get_item.return_value = {
        "Item": {
            "customer_id": CUSTOMER_ID,
            "deployment_id": DEPLOYMENT_ID,
            "ownership_schema_version": 1,
            "processing_domain": "gov",
            "input": {"bucket": "raw-trusted", "key": "raw/doc-123.pdf"},
            "artifacts": {"ocr": {"bucket": "ocr-trusted", "key": "ocr/doc-123.json"}},
        }
    }
    with patch("gov_worker.dynamo.dynamodb_resource.Table", return_value=table):
        item = require_authorized_document(
            "documents", "doc-123", "gov", CUSTOMER_ID, DEPLOYMENT_ID,
            "raw-trusted", "raw/doc-123.pdf", "ocr-trusted", "ocr/doc-123.json",
        )
        with pytest.raises(ValueError, match="Document is unavailable"):
            require_authorized_document(
                "documents", "doc-123", "gov", CUSTOMER_ID, DEPLOYMENT_ID,
                "raw-trusted", "raw/doc-123.pdf", "ocr-foreign", "ocr/doc-123.json",
            )

    assert item["processing_domain"] == "gov"
    table.get_item.assert_called_with(Key={"documentId": "doc-123"}, ConsistentRead=True)


def test_dynamo_update_is_conditioned_on_owner_and_domain():
    table = Mock()
    table.update_item.return_value = {"Attributes": {}}
    with patch("gov_worker.dynamo.dynamodb_resource.Table", return_value=table):
        reserve_structured_artifact(
            "documents", "doc-123", "gov", "structured-key", "structured",
            CUSTOMER_ID, DEPLOYMENT_ID, CHECKPOINT_ID, ARTIFACT_WRITER,
            ARTIFACT_SCHEMA_VERSION,
        )
        update_document_status(
            "documents", "doc-123", "GOV_EXTRACTED", "gov", "structured-key",
            "structured", CUSTOMER_ID, DEPLOYMENT_ID, {}, CHECKPOINT_ID,
            CONTENT_SHA256, ARTIFACT_WRITER, ARTIFACT_SCHEMA_VERSION,
        )

    reserve_call, finalize_call = [item.kwargs for item in table.update_item.call_args_list]
    for call in (reserve_call, finalize_call):
        assert "#customer_id = :customer_id" in call["ConditionExpression"]
        assert "#deployment_id = :deployment_id" in call["ConditionExpression"]
        assert "#ownership_version = :ownership_version" in call["ConditionExpression"]
        assert "#processing_domain = :processing_domain" in call["ConditionExpression"]
        assert call["ExpressionAttributeValues"][":customer_id"] == CUSTOMER_ID
        assert call["ExpressionAttributeValues"][":deployment_id"] == DEPLOYMENT_ID

    assert "#m_status IN (:classify_completed, :ocr_completed)" in reserve_call["ConditionExpression"]
    assert "attribute_not_exists(#artifacts.#structured)" in reserve_call["ConditionExpression"]
    assert "attribute_not_exists(#stages.#stage_name)" in reserve_call["ConditionExpression"]
    assert "#m_status = :writing_status" in finalize_call["ConditionExpression"]
    assert "#stages.#stage_name = :reservation" in finalize_call["ConditionExpression"]
    assert finalize_call["ExpressionAttributeValues"][":reservation"]["artifact"]["checkpoint_id"] == CHECKPOINT_ID
