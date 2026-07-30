import json
from unittest.mock import MagicMock, patch

import pytest
from pydantic import ValidationError

from classifier_worker import aws
from classifier_worker.contracts import ClassifyMessage, ExtractMessage
from classifier_worker.main import _classification_handoff_confirmed, process_message


CUSTOMER_ID = "cust_01ARZ3NDEKTSV4RRFFQ69G5FAW"
DEPLOYMENT_ID = "dep_01ARZ3NDEKTSV4RRFFQ69G5FAV"


def _body(**overrides):
    payload = {
        "schemaVersion": "scanalyze.classify.v2",
        "documentId": "doc-123",
        "customer_id": CUSTOMER_ID,
        "deployment_id": DEPLOYMENT_ID,
        "ownership_schema_version": 1,
        "pipeline_stage": "classify",
        "processing_domain": None,
        "ocr": {"bucket": "ocr-bucket", "key": "ocr/doc-123/ocr.json"},
        "raw": {"bucket": "raw-bucket", "key": "raw/doc-123/input.pdf"},
        "meta": {"env": "test", "tenant": "platform"},
    }
    payload.update(overrides)
    return payload


def _owned_document(**overrides):
    item = {
        "documentId": "doc-123",
        "customer_id": CUSTOMER_ID,
        "deployment_id": DEPLOYMENT_ID,
        "ownership_schema_version": 1,
        "status": "OCR_COMPLETED",
        "documentRoute": "platform",
        "input": {"bucket": "raw-bucket", "key": "raw/doc-123/input.pdf"},
        "artifacts": {
            "ocr": {"bucket": "ocr-bucket", "key": "ocr/doc-123/ocr.json"}
        },
    }
    item.update(overrides)
    return item


def _config_values(key, **kwargs):
    return {
        "data-foundation/documents_table_name": "documents",
        "queues/classify_url": "https://sqs.invalid/classify",
        "queues/bank-extract_url": "https://sqs.invalid/bank-extract",
        "features/bedrock_classification_enabled": "false",
    }.get(key, kwargs.get("default"))


def test_classifier_v2_requires_exact_owner_tuple_and_forbids_spoof_fields():
    message = ClassifyMessage(**_body())
    assert message.customer_id == CUSTOMER_ID
    assert message.deployment_id == DEPLOYMENT_ID

    for missing in ("customer_id", "deployment_id", "ownership_schema_version"):
        payload = _body()
        payload.pop(missing)
        with pytest.raises(ValidationError):
            ClassifyMessage(**payload)

    with pytest.raises(ValidationError):
        ClassifyMessage(**_body(tenantId="spoofed"))


@pytest.mark.parametrize(
    ("override", "value"),
    [
        ("documentId", "invalid document id"),
        ("meta", {"env": "test", "tenant": "customer-controlled"}),
        (
            "textract",
            {"jobId": "textract-synthetic", "api": "GetDocumentTextDetection"},
        ),
    ],
)
def test_classifier_runtime_contract_matches_canonical_v2_constraints(
    override, value
):
    with pytest.raises(ValidationError):
        ClassifyMessage(**_body(**{override: value}))


def test_extract_runtime_contract_rejects_stage_domain_conflicts():
    with pytest.raises(ValidationError, match="pipeline stage"):
        ExtractMessage(
            schemaVersion="scanalyze.extract.v2",
            documentId="doc-123",
            customer_id=CUSTOMER_ID,
            deployment_id=DEPLOYMENT_ID,
            ownership_schema_version=1,
            pipeline_stage="bank-extract",
            processing_domain="personal",
            ocr={"bucket": "ocr-bucket", "key": "ocr/doc-123/ocr.json"},
            raw={"bucket": "raw-bucket", "key": "raw/doc-123/input.pdf"},
        )


def test_dynamo_lookup_errors_fail_closed(monkeypatch):
    table = type(
        "Table",
        (),
        {"get_item": lambda self, **kwargs: (_ for _ in ()).throw(RuntimeError("down"))},
    )()
    monkeypatch.setattr(aws.dynamodb, "Table", lambda _name: table)

    with pytest.raises(RuntimeError):
        aws.get_document_item("documents", "doc-123")


def test_foreign_document_stops_before_s3_bedrock_or_enqueue():
    sqs_message = {"ReceiptHandle": "receipt", "Body": json.dumps(_body())}
    foreign = {
        "documentId": "doc-123",
        "customer_id": "cust_01ARZ3NDEKTSV4RRFFQ69G5FAX",
        "deployment_id": DEPLOYMENT_ID,
        "ownership_schema_version": 1,
        "input": {"bucket": "raw-bucket", "key": "raw/doc-123/input.pdf"},
        "artifacts": {
            "ocr": {"bucket": "ocr-bucket", "key": "ocr/doc-123/ocr.json"}
        },
    }

    with (
        patch("classifier_worker.main.get_document_item", return_value=foreign),
        patch("classifier_worker.main.get_ocr_text") as get_ocr_text,
        patch("classifier_worker.main.classify_document") as classify,
        patch("classifier_worker.main.enqueue_message") as enqueue,
        patch("classifier_worker.main.delete_message") as delete,
        patch("classifier_worker.main.config") as config,
    ):
        config.env = "test"
        config.get.side_effect = lambda key, **kwargs: {
            "data-foundation/documents_table_name": "documents",
            "queues/classify_url": "https://sqs.invalid/classify",
        }.get(key, kwargs.get("default"))
        assert process_message(sqs_message) is False

    get_ocr_text.assert_not_called()
    classify.assert_not_called()
    enqueue.assert_not_called()
    delete.assert_not_called()


@pytest.mark.parametrize(
    ("record_change", "message_change"),
    [
        ({"documentRoute": "bank", "processing_domain": "bank"}, {}),
        ({"documentRoute": "personal", "processing_domain": "personal"}, {}),
        ({"documentRoute": "gov", "processing_domain": "gov"}, {}),
        ({"documentRoute": "platform"}, {"meta": {"env": "prod", "tenant": "platform"}}),
        ({"documentRoute": "default"}, {}),
    ],
)
def test_classifier_rejects_direct_domain_or_route_environment_mismatch(
    record_change,
    message_change,
):
    item = _owned_document(**record_change)
    sqs_message = {
        "ReceiptHandle": "receipt",
        "Body": json.dumps(_body(**message_change)),
    }

    with (
        patch("classifier_worker.main.get_document_item", return_value=item),
        patch("classifier_worker.main.get_ocr_text") as get_ocr_text,
        patch("classifier_worker.main.classify_document") as classify,
        patch("classifier_worker.main.save_classification_evidence") as save,
        patch("classifier_worker.main.enqueue_message") as enqueue,
        patch("classifier_worker.main.delete_message") as delete,
        patch("classifier_worker.main.config") as config,
    ):
        config.env = "test"
        config.get.side_effect = _config_values
        assert process_message(sqs_message) is False

    get_ocr_text.assert_not_called()
    classify.assert_not_called()
    save.assert_not_called()
    enqueue.assert_not_called()
    delete.assert_not_called()


@pytest.mark.parametrize(
    "record_change",
    [
        {"input": {"bucket": "foreign", "key": "raw/doc-123/input.pdf"}},
        {"input": {"bucket": "raw-bucket", "key": "foreign/input.pdf"}},
        {"artifacts": {"ocr": {"bucket": "foreign", "key": "ocr/doc-123/ocr.json"}}},
        {"artifacts": {"ocr": {"bucket": "ocr-bucket", "key": "foreign/ocr.json"}}},
    ],
)
def test_authorized_owner_with_foreign_locator_stops_before_side_effects(record_change):
    item = _owned_document(**record_change)
    sqs_message = {"ReceiptHandle": "receipt", "Body": json.dumps(_body())}

    with (
        patch("classifier_worker.main.get_document_item", return_value=item),
        patch("classifier_worker.main.get_ocr_text") as get_ocr_text,
        patch("classifier_worker.main.classify_document") as classify,
        patch("classifier_worker.main.save_classification_evidence") as save,
        patch("classifier_worker.main.enqueue_message") as enqueue,
        patch("classifier_worker.main.delete_message") as delete,
        patch("classifier_worker.main.config") as config,
    ):
        config.get.side_effect = _config_values
        assert process_message(sqs_message) is False

    get_ocr_text.assert_not_called()
    classify.assert_not_called()
    save.assert_not_called()
    enqueue.assert_not_called()
    delete.assert_not_called()


@pytest.mark.parametrize(
    ("runtime_customer", "runtime_deployment"),
    [
        ("cust_01BX5ZZKBKACTAV9WEVGEMMVS1", DEPLOYMENT_ID),
        (CUSTOMER_ID, "dep_01BX5ZZKBKACTAV9WEVGEMMVS0"),
    ],
)
def test_runtime_owner_mismatch_stops_before_authoritative_read(
    runtime_customer,
    runtime_deployment,
):
    sqs_message = {"ReceiptHandle": "receipt", "Body": json.dumps(_body())}
    with (
        patch("classifier_worker.main.get_document_item") as get_item,
        patch("classifier_worker.main.get_ocr_text") as get_ocr_text,
        patch("classifier_worker.main.enqueue_message") as enqueue,
        patch("classifier_worker.main.delete_message") as delete,
        patch("classifier_worker.main.config") as config,
    ):
        config.require_owner.side_effect = lambda customer, deployment: (
            None
            if (customer, deployment) == (runtime_customer, runtime_deployment)
            else (_ for _ in ()).throw(ValueError("runtime owner mismatch"))
        )
        assert process_message(sqs_message) is False

    get_item.assert_not_called()
    get_ocr_text.assert_not_called()
    enqueue.assert_not_called()
    delete.assert_not_called()


def test_pending_checkpoint_retries_handoff_without_reclassification():
    pending = _owned_document(
        status="CLASSIFY_PENDING",
        routingTarget="bank-extract",
        processing_domain="bank",
        classification={
            "classifierVersion": "v2",
            "route": "bank-extract",
            "docType": "bank_statement",
        },
    )
    sqs_message = {"ReceiptHandle": "receipt", "Body": json.dumps(_body())}

    with (
        patch("classifier_worker.main.get_document_item", return_value=pending),
        patch("classifier_worker.main.get_ocr_text") as get_ocr_text,
        patch("classifier_worker.main.classify_document") as classify,
        patch("classifier_worker.main.save_classification_evidence") as save,
        patch("classifier_worker.main.enqueue_message", return_value="downstream-1") as enqueue,
        patch("classifier_worker.main.mark_classification_enqueued") as mark,
        patch("classifier_worker.main.delete_message") as delete,
        patch("classifier_worker.main.config") as config,
    ):
        config.env = "test"
        config.get.side_effect = _config_values
        assert process_message(sqs_message) is True

    get_ocr_text.assert_not_called()
    classify.assert_not_called()
    save.assert_not_called()
    enqueue.assert_called_once()
    mark.assert_called_once_with(
        "documents",
        "doc-123",
        CUSTOMER_ID,
        DEPLOYMENT_ID,
        "bank-extract",
        "bank",
        "downstream-1",
    )
    delete.assert_called_once()


def test_failed_send_after_checkpoint_is_resumable_on_retry():
    fresh = _owned_document()
    pending = _owned_document(
        status="CLASSIFY_PENDING",
        routingTarget="bank-extract",
        processing_domain="bank",
        classification={"classifierVersion": "v2", "route": "bank-extract"},
    )
    sqs_message = {"ReceiptHandle": "receipt", "Body": json.dumps(_body())}
    enqueue = MagicMock(side_effect=[RuntimeError("synthetic outage"), "downstream-2"])

    with (
        patch("classifier_worker.main.get_document_item", side_effect=[fresh, pending]),
        patch("classifier_worker.main.get_ocr_text", return_value="bank statement") as get_text,
        patch(
            "classifier_worker.main.classify_document",
            return_value=("bank_statement", 0.9, "bank-extract", "heuristic"),
        ) as classify,
        patch("classifier_worker.main.save_classification_evidence") as save,
        patch("classifier_worker.main.enqueue_message", enqueue),
        patch("classifier_worker.main.mark_classification_enqueued") as mark,
        patch("classifier_worker.main.delete_message") as delete,
        patch("classifier_worker.main.config") as config,
    ):
        config.env = "test"
        config.get.side_effect = _config_values
        assert process_message(sqs_message) is False
        assert process_message(sqs_message) is True

    get_text.assert_called_once()
    classify.assert_called_once()
    save.assert_called_once()
    assert enqueue.call_count == 2
    mark.assert_called_once()
    delete.assert_called_once()


def test_failed_enqueue_mark_retries_from_checkpoint_without_reclassification():
    fresh = _owned_document()
    pending = _owned_document(
        status="CLASSIFY_PENDING",
        routingTarget="bank-extract",
        processing_domain="bank",
        classification={"classifierVersion": "v2", "route": "bank-extract"},
    )
    sqs_message = {"ReceiptHandle": "receipt", "Body": json.dumps(_body())}
    mark = MagicMock(side_effect=[RuntimeError("synthetic mark outage"), None])

    with (
        patch("classifier_worker.main.get_document_item", side_effect=[fresh, pending]),
        patch("classifier_worker.main.get_ocr_text", return_value="bank statement") as get_text,
        patch(
            "classifier_worker.main.classify_document",
            return_value=("bank_statement", 0.9, "bank-extract", "heuristic"),
        ) as classify,
        patch("classifier_worker.main.save_classification_evidence") as save,
        patch(
            "classifier_worker.main.enqueue_message",
            side_effect=["downstream-1", "downstream-2"],
        ) as enqueue,
        patch("classifier_worker.main.mark_classification_enqueued", mark),
        patch("classifier_worker.main.delete_message") as delete,
        patch("classifier_worker.main.config") as config,
    ):
        config.env = "test"
        config.get.side_effect = _config_values
        assert process_message(sqs_message) is False
        assert process_message(sqs_message) is True

    get_text.assert_called_once()
    classify.assert_called_once()
    save.assert_called_once()
    assert enqueue.call_count == 2
    assert mark.call_count == 2
    delete.assert_called_once()


def test_metadata_authority_field_is_rejected_before_read():
    payload = _body()
    payload["_metadata"] = {"customer_id": CUSTOMER_ID}
    with (
        patch("classifier_worker.main.get_document_item") as get_item,
        patch("classifier_worker.main.delete_message") as delete,
        patch("classifier_worker.main.config") as config,
    ):
        assert process_message(
            {"ReceiptHandle": "receipt", "Body": json.dumps(payload)}
        ) is False

    get_item.assert_not_called()
    delete.assert_not_called()


@pytest.mark.parametrize("metadata", ({"traceId": 7}, {"correlationId": ""}))
def test_malformed_trace_metadata_is_rejected_before_read(metadata):
    payload = _body()
    payload["_metadata"] = metadata
    with (
        patch("classifier_worker.main.get_document_item") as get_item,
        patch("classifier_worker.main.delete_message") as delete,
    ):
        assert process_message(
            {"ReceiptHandle": "receipt", "Body": json.dumps(payload)}
        ) is False

    get_item.assert_not_called()
    delete.assert_not_called()


def test_dynamo_transitions_are_owner_and_state_conditioned(monkeypatch):
    table = MagicMock()
    monkeypatch.setattr(aws.dynamodb, "Table", lambda _name: table)
    monkeypatch.setattr(aws, "build_key", lambda *_args: {"documentId": "doc-123"})

    aws.save_classification_evidence(
        "documents",
        "doc-123",
        CUSTOMER_ID,
        DEPLOYMENT_ID,
        "bank_statement",
        0.9,
        "bank-extract",
        "bank",
        "heuristic",
    )
    save = table.update_item.call_args.kwargs
    assert "#status = :expected_status" in save["ConditionExpression"]
    assert save["ExpressionAttributeValues"][":expected_status"] == "OCR_COMPLETED"
    assert save["ExpressionAttributeValues"][":s"] == "CLASSIFY_PENDING"

    table.reset_mock()
    aws.mark_classification_enqueued(
        "documents",
        "doc-123",
        CUSTOMER_ID,
        DEPLOYMENT_ID,
        "bank-extract",
        "bank",
        "downstream-1",
    )
    mark = table.update_item.call_args.kwargs
    assert "#status = :expected_status" in mark["ConditionExpression"]
    assert mark["ExpressionAttributeValues"][":expected_status"] == "CLASSIFY_PENDING"
    assert mark["ExpressionAttributeValues"][":completed"] == "CLASSIFY_COMPLETED"


def test_poison_message_is_not_deleted_before_native_redrive():
    message = {"ReceiptHandle": "receipt", "Body": "{"}
    with (
        patch("classifier_worker.main.delete_message") as delete,
        patch("classifier_worker.main.config") as config,
    ):
        config.get.return_value = "https://sqs.invalid/classify"
        assert process_message(message) is False
    delete.assert_not_called()


def test_only_complete_v2_handoff_is_idempotent_success():
    complete = {
        "status": "CLASSIFY_COMPLETED",
        "routingTarget": "bank-extract",
        "processing_domain": "bank",
        "classification": {
            "classifierVersion": "v2",
            "enqueuedTo": "bank-extract",
            "messageId": "downstream-message-1",
        },
    }
    assert _classification_handoff_confirmed(complete) is True

    for path, value in (
        (("status",), "OCR_COMPLETED"),
        (("routingTarget",), "personal-extract"),
        (("processing_domain",), "personal"),
        (("classification", "classifierVersion"), "v1"),
        (("classification", "messageId"), ""),
    ):
        candidate = json.loads(json.dumps(complete))
        target = candidate
        for key in path[:-1]:
            target = target[key]
        target[path[-1]] = value
        assert _classification_handoff_confirmed(candidate) is False
