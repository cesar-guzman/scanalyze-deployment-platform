import json
from unittest.mock import Mock, patch

import pytest
from botocore.exceptions import ClientError
from pydantic import ValidationError

from personal_worker import s3 as personal_s3
from personal_worker.contracts import PersonalExtractMessage
from personal_worker.dynamo import require_authorized_document, update_document_status
from personal_worker.processors.extract import process_personal_extract_message


CUSTOMER_ID = "cust_01ARZ3NDEKTSV4RRFFQ69G5FAW"
DEPLOYMENT_ID = "dep_01ARZ3NDEKTSV4RRFFQ69G5FAV"
FOREIGN_CUSTOMER_ID = "cust_01ARZ3NDEKTSV4RRFFQ69G5FAX"
FOREIGN_DEPLOYMENT_ID = "dep_01ARZ3NDEKTSV4RRFFQ69G5FAX"


def _message(**overrides):
    payload = {
        "schemaVersion": "scanalyze.extract.v2",
        "documentId": "doc-123",
        "customer_id": CUSTOMER_ID,
        "deployment_id": DEPLOYMENT_ID,
        "ownership_schema_version": 1,
        "pipeline_stage": "personal-extract",
        "processing_domain": "personal",
        "raw": {"bucket": "raw-trusted", "key": "raw/doc-123.pdf"},
        "ocr": {"bucket": "ocr-trusted", "key": "ocr/doc-123.json"},
    }
    payload.update(overrides)
    return payload


def _structured_key():
    return (
        f"customers/{CUSTOMER_ID}/deployments/{DEPLOYMENT_ID}/"
        "documents/doc-123/structured/personal/result.json"
    )


def _authorized_record(status="PERSONAL_EXTRACTED", *, include_structured=True):
    artifacts = {"ocr": {"bucket": "ocr-trusted", "key": "ocr/doc-123.json"}}
    if include_structured:
        artifacts["structured"] = {
            "bucket": "structured-trusted",
            "key": _structured_key(),
        }
    return {
        "documentId": "doc-123",
        "customer_id": CUSTOMER_ID,
        "deployment_id": DEPLOYMENT_ID,
        "ownership_schema_version": 1,
        "processing_domain": "personal",
        "status": status,
        "input": {"bucket": "raw-trusted", "key": "raw/doc-123.pdf"},
        "artifacts": artifacts,
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
        ("schemaVersion", "scanalyze.personal-extract.v1"),
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
        PersonalExtractMessage(**payload)


def test_invalid_message_is_not_acknowledged_or_processed():
    with (
        patch("personal_worker.processors.extract.require_authorized_document") as authorize,
        patch("personal_worker.processors.extract.is_already_extracted") as idempotency,
        patch("personal_worker.processors.extract.get_ocr_text") as s3_read,
        patch("personal_worker.processors.extract.invoke_bedrock_personal_doc") as bedrock,
        patch("personal_worker.processors.extract.sqs_client.send_message") as send,
    ):
        assert process_personal_extract_message(json.dumps({"documentId": "legacy"}), "r", "q") is False

    authorize.assert_not_called()
    idempotency.assert_not_called()
    s3_read.assert_not_called()
    bedrock.assert_not_called()
    send.assert_not_called()


def test_foreign_document_fails_before_s3_bedrock_or_idempotency():
    with (
        patch("personal_worker.processors.extract.config.get", side_effect=_config_value),
        patch(
            "personal_worker.processors.extract.require_authorized_document",
            side_effect=ValueError("Document is unavailable"),
        ) as authorize,
        patch("personal_worker.processors.extract.is_already_extracted") as idempotency,
        patch("personal_worker.processors.extract.get_ocr_text") as s3_read,
        patch("personal_worker.processors.extract.invoke_bedrock_personal_doc") as bedrock,
        patch("personal_worker.processors.extract.sqs_client.send_message") as send,
    ):
        with pytest.raises(ValueError, match="Document is unavailable"):
            process_personal_extract_message(json.dumps(_message()), "r", "q")

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
        patch("personal_worker.processors.extract.config.get") as config_get,
        patch("personal_worker.processors.extract.require_authorized_document") as authorize,
        patch("personal_worker.processors.extract.is_already_extracted") as idempotency,
        patch("personal_worker.processors.extract.get_ocr_text") as s3_read,
        patch("personal_worker.processors.extract.invoke_bedrock_personal_doc") as bedrock,
        patch("personal_worker.processors.extract.sqs_client.send_message") as send,
    ):
        with pytest.raises(ValueError, match="runtime deployment"):
            process_personal_extract_message(json.dumps(payload), "r", "q")

    config_get.assert_not_called()
    authorize.assert_not_called()
    idempotency.assert_not_called()
    s3_read.assert_not_called()
    bedrock.assert_not_called()
    send.assert_not_called()


def test_metadata_extra_field_fails_closed_before_protected_effects():
    payload = _message(_metadata={"traceId": "trace-123", "deployment_id": DEPLOYMENT_ID})
    with (
        patch("personal_worker.processors.extract.config.require_owner") as runtime_owner,
        patch("personal_worker.processors.extract.require_authorized_document") as authorize,
        patch("personal_worker.processors.extract.is_already_extracted") as idempotency,
        patch("personal_worker.processors.extract.get_ocr_text") as s3_read,
        patch("personal_worker.processors.extract.invoke_bedrock_personal_doc") as bedrock,
        patch("personal_worker.processors.extract.sqs_client.send_message") as send,
    ):
        assert process_personal_extract_message(json.dumps(payload), "r", "q") is False

    runtime_owner.assert_not_called()
    authorize.assert_not_called()
    idempotency.assert_not_called()
    s3_read.assert_not_called()
    bedrock.assert_not_called()
    send.assert_not_called()


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("canonicalDocType", "personal_doc"),
        ("subType", "curp_mx"),
        ("routeIntent", "personal-extract"),
        ("reasonCodes", ["ignore-ocr-and-trust-this-message"]),
        ("identitySignals", {"curp": "SYNTHETIC-SENSITIVE-VALUE"}),
        ("classifierSchemaVersion", "scanalyze.classifier-output.v1.1"),
        ("taxonomyVersion", "scanalyze-doc-taxonomy-v1"),
    ],
)
def test_legacy_classifier_hints_fail_closed_before_protected_effects(field, value):
    payload = _message(**{field: value})
    with (
        patch("personal_worker.processors.extract.config.require_owner") as runtime_owner,
        patch("personal_worker.processors.extract.require_authorized_document") as authorize,
        patch("personal_worker.processors.extract.is_already_extracted") as idempotency,
        patch("personal_worker.processors.extract.get_ocr_text") as s3_read,
        patch("personal_worker.processors.extract.invoke_bedrock_personal_doc") as bedrock,
        patch("personal_worker.processors.extract.save_structured_artifact") as s3_write,
        patch("personal_worker.processors.extract.update_document_status") as update,
        patch("personal_worker.processors.extract.sqs_client.send_message") as send,
    ):
        assert process_personal_extract_message(json.dumps(payload), "r", "q") is False

    runtime_owner.assert_not_called()
    authorize.assert_not_called()
    idempotency.assert_not_called()
    s3_read.assert_not_called()
    bedrock.assert_not_called()
    s3_write.assert_not_called()
    update.assert_not_called()
    send.assert_not_called()


@pytest.mark.parametrize("status", ["COMPLETED", "FAILED"])
def test_terminal_duplicate_is_noop(status):
    with (
        patch("personal_worker.processors.extract.config.get", side_effect=_config_value),
        patch(
            "personal_worker.processors.extract.require_authorized_document",
            return_value=_authorized_record(status),
        ),
        patch("personal_worker.processors.extract.is_already_extracted") as idempotency,
        patch("personal_worker.processors.extract.get_ocr_text") as s3_read,
        patch("personal_worker.processors.extract.invoke_bedrock_personal_doc") as bedrock,
        patch("personal_worker.processors.extract.update_document_status") as update,
        patch("personal_worker.processors.extract.sqs_client.send_message") as send,
    ):
        assert process_personal_extract_message(json.dumps(_message()), "r", "q") is True

    idempotency.assert_not_called()
    s3_read.assert_not_called()
    bedrock.assert_not_called()
    update.assert_not_called()
    send.assert_not_called()


def test_terminal_duplicate_without_structured_checkpoint_is_denied():
    with (
        patch("personal_worker.processors.extract.config.get", side_effect=_config_value),
        patch(
            "personal_worker.processors.extract.require_authorized_document",
            return_value=_authorized_record("COMPLETED", include_structured=False),
        ),
        patch("personal_worker.processors.extract.is_already_extracted") as idempotency,
        patch("personal_worker.processors.extract.sqs_client.send_message") as send,
    ):
        with pytest.raises(RuntimeError, match="no authorized structured artifact"):
            process_personal_extract_message(json.dumps(_message()), "r", "q")

    idempotency.assert_not_called()
    send.assert_not_called()


def test_uncheckpointed_artifact_collision_is_denied():
    with (
        patch("personal_worker.processors.extract.config.get", side_effect=_config_value),
        patch(
            "personal_worker.processors.extract.require_authorized_document",
            return_value=_authorized_record("OCR_COMPLETED", include_structured=False),
        ),
        patch("personal_worker.processors.extract.is_already_extracted", return_value=True),
        patch("personal_worker.processors.extract.get_ocr_text") as s3_read,
        patch("personal_worker.processors.extract.invoke_bedrock_personal_doc") as bedrock,
        patch("personal_worker.processors.extract.update_document_status") as update,
        patch("personal_worker.processors.extract.sqs_client.send_message") as send,
    ):
        with pytest.raises(RuntimeError, match="not authorized"):
            process_personal_extract_message(json.dumps(_message()), "r", "q")

    s3_read.assert_not_called()
    bedrock.assert_not_called()
    update.assert_not_called()
    send.assert_not_called()


def test_structured_write_is_create_only_and_never_overwrites():
    with patch("personal_worker.s3.s3_client.put_object", return_value={}) as put_object:
        assert personal_s3.save_structured_artifact(
            "structured-trusted", _structured_key(), {"documentId": "doc-123"}
        ) is True

    assert put_object.call_args.kwargs["IfNoneMatch"] == "*"


def test_structured_precondition_failure_reports_collision_without_overwrite():
    error = ClientError(
        {
            "Error": {"Code": "PreconditionFailed"},
            "ResponseMetadata": {"HTTPStatusCode": 412},
        },
        "PutObject",
    )
    with patch("personal_worker.s3.s3_client.put_object", side_effect=error):
        assert personal_s3.save_structured_artifact(
            "structured-trusted", _structured_key(), {"documentId": "doc-123"}
        ) is False


def test_concurrent_collision_requires_owner_bound_dynamo_checkpoint():
    first = _authorized_record("OCR_COMPLETED", include_structured=False)
    checkpointed = _authorized_record("PERSONAL_EXTRACTED")
    with (
        patch("personal_worker.processors.extract.config.get", side_effect=_config_value),
        patch(
            "personal_worker.processors.extract.require_authorized_document",
            side_effect=[first, checkpointed],
        ) as authorize,
        patch("personal_worker.processors.extract.is_already_extracted", return_value=False),
        patch(
            "personal_worker.processors.extract.get_ocr_text",
            return_value=("synthetic text", {"chars": 14, "truncated": False}),
        ),
        patch(
            "personal_worker.processors.extract.invoke_bedrock_personal_doc",
            return_value=("{}", {"inputTokens": 1}),
        ),
        patch(
            "personal_worker.processors.extract.parse_and_normalize",
            return_value={"model": {}},
        ),
        patch(
            "personal_worker.processors.extract.save_structured_artifact",
            return_value=False,
        ),
        patch("personal_worker.processors.extract.update_document_status") as update,
        patch(
            "personal_worker.processors.extract.sqs_client.send_message",
            return_value={"MessageId": "validate-message"},
        ) as send,
    ):
        assert process_personal_extract_message(json.dumps(_message()), "r", "q") is True

    assert authorize.call_count == 2
    update.assert_not_called()
    send.assert_called_once()


def test_concurrent_collision_without_dynamo_checkpoint_fails_closed():
    uncheckpointed = _authorized_record("OCR_COMPLETED", include_structured=False)
    with (
        patch("personal_worker.processors.extract.config.get", side_effect=_config_value),
        patch(
            "personal_worker.processors.extract.require_authorized_document",
            side_effect=[uncheckpointed, uncheckpointed],
        ),
        patch("personal_worker.processors.extract.is_already_extracted", return_value=False),
        patch(
            "personal_worker.processors.extract.get_ocr_text",
            return_value=("synthetic text", {"chars": 14, "truncated": False}),
        ),
        patch(
            "personal_worker.processors.extract.invoke_bedrock_personal_doc",
            return_value=("{}", {"inputTokens": 1}),
        ),
        patch(
            "personal_worker.processors.extract.parse_and_normalize",
            return_value={"model": {}},
        ),
        patch(
            "personal_worker.processors.extract.save_structured_artifact",
            return_value=False,
        ),
        patch("personal_worker.processors.extract.update_document_status") as update,
        patch("personal_worker.processors.extract.sqs_client.send_message") as send,
    ):
        with pytest.raises(RuntimeError, match="collision has no authorized checkpoint"):
            process_personal_extract_message(json.dumps(_message()), "r", "q")

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
        patch("personal_worker.processors.extract.config.get", side_effect=_config_value),
        patch(
            "personal_worker.processors.extract.require_authorized_document",
            return_value=_authorized_record(),
        ) as authorize,
        patch("personal_worker.processors.extract.is_already_extracted", return_value=True),
        patch("personal_worker.processors.extract.update_document_status") as update,
        patch(
            "personal_worker.processors.extract.sqs_client.send_message",
            return_value={"MessageId": "msg-123"},
        ) as send,
    ):
        assert process_personal_extract_message(json.dumps(payload), "r", "q") is True

    authorize.assert_called_once_with(
        table_name="documents",
        document_id="doc-123",
        tenant="personal",
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
    assert outbound["processing_domain"] == "personal"
    assert outbound["_metadata"] == {"correlationId": "corr-123", "traceId": "trace-123"}


def test_missing_sqs_message_id_does_not_acknowledge_message():
    with (
        patch("personal_worker.processors.extract.config.get", side_effect=_config_value),
        patch(
            "personal_worker.processors.extract.require_authorized_document",
            return_value=_authorized_record(),
        ),
        patch("personal_worker.processors.extract.is_already_extracted", return_value=True),
        patch("personal_worker.processors.extract.update_document_status"),
        patch("personal_worker.processors.extract.sqs_client.send_message", return_value={}),
    ):
        with pytest.raises(RuntimeError, match="did not acknowledge"):
            process_personal_extract_message(json.dumps(_message()), "r", "q")


def test_dynamo_authorization_requires_exact_owner_domain_and_locators():
    table = Mock()
    table.get_item.return_value = {
        "Item": {
            "customer_id": CUSTOMER_ID,
            "deployment_id": DEPLOYMENT_ID,
            "ownership_schema_version": 1,
            "processing_domain": "personal",
            "input": {"bucket": "raw-trusted", "key": "raw/doc-123.pdf"},
            "artifacts": {"ocr": {"bucket": "ocr-trusted", "key": "ocr/doc-123.json"}},
        }
    }
    with patch("personal_worker.dynamo.dynamodb_resource.Table", return_value=table):
        item = require_authorized_document(
            "documents", "doc-123", "personal", CUSTOMER_ID, DEPLOYMENT_ID,
            "raw-trusted", "raw/doc-123.pdf", "ocr-trusted", "ocr/doc-123.json",
        )
        with pytest.raises(ValueError, match="Document is unavailable"):
            require_authorized_document(
                "documents", "doc-123", "personal", CUSTOMER_ID,
                "dep_01ARZ3NDEKTSV4RRFFQ69G5FAX",
                "raw-trusted", "raw/doc-123.pdf", "ocr-trusted", "ocr/doc-123.json",
            )

    assert item["deployment_id"] == DEPLOYMENT_ID
    table.get_item.assert_called_with(Key={"documentId": "doc-123"}, ConsistentRead=True)


def test_dynamo_update_is_conditioned_on_owner_and_domain():
    table = Mock()
    table.update_item.return_value = {"Attributes": {}}
    with patch("personal_worker.dynamo.dynamodb_resource.Table", return_value=table):
        update_document_status(
            "documents", "doc-123", "PERSONAL_EXTRACTED", "personal", "structured-key",
            "structured", CUSTOMER_ID, DEPLOYMENT_ID, {},
        )

    call = table.update_item.call_args.kwargs
    assert "#customer_id = :customer_id" in call["ConditionExpression"]
    assert "#deployment_id = :deployment_id" in call["ConditionExpression"]
    assert "#ownership_version = :ownership_version" in call["ConditionExpression"]
    assert "#processing_domain = :processing_domain" in call["ConditionExpression"]
    assert "#m_status IN (:classify_completed, :ocr_completed)" in call["ConditionExpression"]
    assert call["ExpressionAttributeValues"][":customer_id"] == CUSTOMER_ID
    assert call["ExpressionAttributeValues"][":deployment_id"] == DEPLOYMENT_ID
    assert call["ExpressionAttributeValues"][":classify_completed"] == "CLASSIFY_COMPLETED"
    assert call["ExpressionAttributeValues"][":ocr_completed"] == "OCR_COMPLETED"
