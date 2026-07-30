import json
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import MagicMock

import boto3
import pytest
from botocore.exceptions import ClientError

from ocr_worker.processors import ocr_poll


CUSTOMER_ID = "cust_01ARZ3NDEKTSV4RRFFQ69G5FAW"
DEPLOYMENT_ID = "dep_01ARZ3NDEKTSV4RRFFQ69G5FAV"
DOCUMENT_ID = "doc-ocr-handoff"
RAW_BUCKET = "raw-bucket"
OCR_BUCKET = "artifact-bucket"
RAW_KEY = (
    f"customers/{CUSTOMER_ID}/deployments/{DEPLOYMENT_ID}/"
    f"documents/{DOCUMENT_ID}/source.pdf"
)
OCR_KEY = (
    f"customers/{CUSTOMER_ID}/deployments/{DEPLOYMENT_ID}/"
    f"documents/{DOCUMENT_ID}/ocr.json"
)


def _poll_message() -> str:
    return json.dumps(
        {
            "schemaVersion": "scanalyze.ocr-poll.v2",
            "customer_id": CUSTOMER_ID,
            "deployment_id": DEPLOYMENT_ID,
            "ownership_schema_version": 1,
            "pipeline_stage": "ocr",
            "documentId": DOCUMENT_ID,
            "textractJobId": "textract-job-1",
            "sourceBucket": RAW_BUCKET,
            "sourceKey": RAW_KEY,
            "documentRoute": "platform",
            "artifactBucket": OCR_BUCKET,
            "artifactKey": OCR_KEY,
            "submittedAt": datetime.now(timezone.utc).isoformat(),
            "_metadata": {
                "correlationId": "correlation-1",
                "traceId": "trace-1",
            },
        }
    )


@pytest.fixture
def handoff_dependencies(monkeypatch):
    table = MagicMock()
    table.get_item.return_value = {
        "Item": {
            "documentId": DOCUMENT_ID,
            "customer_id": CUSTOMER_ID,
            "deployment_id": DEPLOYMENT_ID,
            "ownership_schema_version": 1,
            "status": "OCR",
            "batchId": "batch-1",
            "textractJobId": "textract-job-1",
            "documentRoute": "platform",
            "input": {"bucket": RAW_BUCKET, "key": RAW_KEY},
            "ocrPollHandoff": {
                "status": "ENQUEUED",
                "messageId": "source-message-1",
                "textractJobId": "textract-job-1",
                "source": {"bucket": RAW_BUCKET, "key": RAW_KEY},
                "artifact": {"bucket": OCR_BUCKET, "key": OCR_KEY},
                "documentRoute": "platform",
                "submittedAt": datetime.now(timezone.utc).isoformat(),
            },
        }
    }
    dynamodb = MagicMock()
    dynamodb.Table.return_value = table

    textract = MagicMock()
    textract.get_document_text_detection.return_value = {
        "JobStatus": "SUCCEEDED",
        "DocumentMetadata": {"Pages": 1},
        "Blocks": [{"BlockType": "PAGE"}],
    }

    sqs = MagicMock()
    s3 = MagicMock()
    config = SimpleNamespace(
        env="test",
        tenant="test-tenant",
        customer_id=CUSTOMER_ID,
        deployment_id=DEPLOYMENT_ID,
        get=lambda key: {
            "data-foundation/documents_table_name": "documents-table",
            "data-foundation/raw_bucket_name": RAW_BUCKET,
            "data-foundation/ocr_bucket_name": OCR_BUCKET,
            "queues/classify_url": "https://sqs.test/classify",
            "queues/bank-extract_url": "https://sqs.test/bank-extract",
            "queues/personal-extract_url": "https://sqs.test/personal-extract",
            "queues/gov-extract_url": "https://sqs.test/gov-extract",
        }[key],
    )

    monkeypatch.setattr(ocr_poll, "config", config)
    monkeypatch.setattr(ocr_poll, "dynamodb_resource", dynamodb)
    monkeypatch.setattr(ocr_poll, "textract_client", textract)
    monkeypatch.setattr(ocr_poll, "sqs_client", sqs)
    monkeypatch.setattr(ocr_poll, "s3_client", s3)
    monkeypatch.setattr(ocr_poll, "extend_visibility", MagicMock())
    monkeypatch.setattr(
        ocr_poll,
        "build_key",
        MagicMock(return_value={"document_id": "doc-ocr-handoff"}),
    )
    monkeypatch.setattr(
        ocr_poll,
        "record_usage_metering_with_idempotency",
        MagicMock(),
    )
    monkeypatch.setattr(boto3, "client", MagicMock(return_value=MagicMock()))

    return SimpleNamespace(table=table, sqs=sqs)


def _process() -> bool:
    return ocr_poll.process_ocr_poll_message(
        _poll_message(),
        "receipt-handle",
        "https://sqs.test/ocr",
        "source-message-1",
        1,
    )


def test_handoff_send_failure_leaves_document_retryable_and_retry_succeeds(
    handoff_dependencies,
):
    table = handoff_dependencies.table
    sqs = handoff_dependencies.sqs

    sqs.send_message.side_effect = RuntimeError("synthetic downstream outage")

    with pytest.raises(RuntimeError, match="synthetic downstream outage"):
        _process()

    table.update_item.assert_not_called()

    sqs.send_message.side_effect = None
    sqs.send_message.return_value = {"MessageId": "downstream-message-1"}

    assert _process() is True

    table.update_item.assert_called_once()
    values = table.update_item.call_args.kwargs["ExpressionAttributeValues"]
    assert values[":s"] == "OCR_COMPLETED"
    assert values[":stageData"]["messageId"] == "downstream-message-1"
    assert table.update_item.call_args.kwargs["ConditionExpression"] == (
        "#s = :old AND #textract_job_id = :job_id AND "
        "#customer_id = :customer_id AND #deployment_id = :deployment_id AND "
        "#ownership_schema_version = :ownership_schema_version"
    )
    assert sqs.send_message.call_count == 2
    sent = json.loads(sqs.send_message.call_args.kwargs["MessageBody"])
    assert sent["schemaVersion"] == "scanalyze.classify.v2"
    assert sent["customer_id"] == CUSTOMER_ID
    assert sent["deployment_id"] == DEPLOYMENT_ID
    assert sent["ownership_schema_version"] == 1
    assert sent["pipeline_stage"] == "classify"


def test_handoff_without_message_id_does_not_complete_document(
    handoff_dependencies,
):
    table = handoff_dependencies.table
    sqs = handoff_dependencies.sqs
    sqs.send_message.return_value = {}

    with pytest.raises(RuntimeError, match="not acknowledged"):
        _process()

    table.update_item.assert_not_called()


def test_missing_authoritative_document_fails_before_handoff(handoff_dependencies):
    table = handoff_dependencies.table
    sqs = handoff_dependencies.sqs
    table.get_item.return_value = {}

    with pytest.raises(RuntimeError, match="Authoritative document was not found"):
        _process()

    table.get_item.assert_called_once_with(
        Key={"document_id": "doc-ocr-handoff"},
        ConsistentRead=True,
    )
    sqs.send_message.assert_not_called()
    table.update_item.assert_not_called()


def test_authoritative_read_failure_fails_before_handoff(handoff_dependencies):
    table = handoff_dependencies.table
    sqs = handoff_dependencies.sqs
    table.get_item.side_effect = RuntimeError("synthetic read outage")

    with pytest.raises(RuntimeError, match="synthetic read outage"):
        _process()

    sqs.send_message.assert_not_called()
    table.update_item.assert_not_called()


def test_downstream_advanced_after_send_is_treated_as_confirmed(
    handoff_dependencies,
):
    table = handoff_dependencies.table
    sqs = handoff_dependencies.sqs
    initial_item = table.get_item.return_value
    table.get_item.side_effect = [
        initial_item,
        {
            "Item": {
                **initial_item["Item"],
                "status": "CLASSIFY_COMPLETED",
            }
        },
    ]
    table.update_item.side_effect = ClientError(
        {
            "Error": {
                "Code": "ConditionalCheckFailedException",
                "Message": "synthetic transition race",
            }
        },
        "UpdateItem",
    )
    sqs.send_message.return_value = {"MessageId": "downstream-message-1"}

    assert _process() is True

    assert table.get_item.call_count == 2
    sqs.send_message.assert_called_once()
    table.update_item.assert_called_once()


def test_retry_after_downstream_progress_does_not_resend(handoff_dependencies):
    table = handoff_dependencies.table
    sqs = handoff_dependencies.sqs
    table.get_item.return_value["Item"]["status"] = "BANK_EXTRACTED"

    assert _process() is True

    sqs.send_message.assert_not_called()
    table.update_item.assert_not_called()


def test_downstream_progress_with_mismatched_job_fails_closed(
    handoff_dependencies,
):
    table = handoff_dependencies.table
    sqs = handoff_dependencies.sqs
    table.get_item.return_value["Item"].update(
        status="CLASSIFY_COMPLETED",
        textractJobId="different-job",
    )

    with pytest.raises(RuntimeError, match="job does not match"):
        _process()

    sqs.send_message.assert_not_called()
    table.update_item.assert_not_called()


def test_missing_authoritative_customer_fails_closed(handoff_dependencies):
    table = handoff_dependencies.table
    sqs = handoff_dependencies.sqs
    table.get_item.return_value["Item"].pop("customer_id")

    with pytest.raises(RuntimeError, match="ownership"):
        _process()

    sqs.send_message.assert_not_called()
    table.update_item.assert_not_called()


def test_missing_route_does_not_fall_back_to_customer(
    handoff_dependencies,
):
    table = handoff_dependencies.table
    sqs = handoff_dependencies.sqs
    table.get_item.return_value["Item"].pop("documentRoute")

    with pytest.raises(RuntimeError, match="route"):
        _process()

    sqs.send_message.assert_not_called()
    table.update_item.assert_not_called()


@pytest.mark.parametrize(
    "record_change",
    [
        {"customer_id": "cust_01BX5ZZKBKACTAV9WEVGEMMVS1"},
        {"deployment_id": "dep_01BX5ZZKBKACTAV9WEVGEMMVS0"},
        {"ownership_schema_version": 2},
    ],
)
def test_poll_owner_mismatch_fails_before_textract_or_side_effects(
    handoff_dependencies,
    record_change,
):
    table = handoff_dependencies.table
    item = table.get_item.return_value["Item"]
    item.update(record_change)

    with pytest.raises(RuntimeError, match="ownership"):
        _process()

    ocr_poll.textract_client.get_document_text_detection.assert_not_called()
    ocr_poll.s3_client.put_object.assert_not_called()
    handoff_dependencies.sqs.send_message.assert_not_called()
    table.update_item.assert_not_called()


@pytest.mark.parametrize(
    ("message_field", "value"),
    [
        ("sourceKey", "foreign-prefix/source.pdf"),
        ("sourceBucket", "foreign-bucket"),
        ("artifactKey", "foreign-prefix/ocr.json"),
        ("artifactBucket", "foreign-bucket"),
    ],
)
def test_poll_message_locator_mismatch_fails_before_side_effects(
    handoff_dependencies,
    message_field,
    value,
):
    payload = json.loads(_poll_message())
    payload[message_field] = value

    with pytest.raises(RuntimeError, match="locator"):
        ocr_poll.process_ocr_poll_message(
            json.dumps(payload),
            "receipt-handle",
            "https://sqs.test/ocr",
            "source-message-1",
            1,
        )

    ocr_poll.textract_client.get_document_text_detection.assert_not_called()
    ocr_poll.s3_client.put_object.assert_not_called()
    handoff_dependencies.sqs.send_message.assert_not_called()
    handoff_dependencies.table.update_item.assert_not_called()


def test_poll_missing_checkpoint_fails_before_side_effects(handoff_dependencies):
    handoff_dependencies.table.get_item.return_value["Item"].pop("ocrPollHandoff")

    with pytest.raises(RuntimeError, match="checkpoint"):
        _process()

    ocr_poll.textract_client.get_document_text_detection.assert_not_called()
    ocr_poll.s3_client.put_object.assert_not_called()
    handoff_dependencies.sqs.send_message.assert_not_called()
    handoff_dependencies.table.update_item.assert_not_called()


def test_poll_deadline_raises_for_native_retry_and_dlq_without_side_effects(
    handoff_dependencies,
):
    payload = json.loads(_poll_message())
    stale_time = (datetime.now(timezone.utc) - timedelta(hours=2)).isoformat()
    payload["submittedAt"] = stale_time
    handoff_dependencies.table.get_item.return_value["Item"]["ocrPollHandoff"][
        "submittedAt"
    ] = stale_time
    ocr_poll.textract_client.get_document_text_detection.return_value = {
        "JobStatus": "IN_PROGRESS"
    }

    with pytest.raises(ValueError, match="polling deadline exceeded"):
        ocr_poll.process_ocr_poll_message(
            json.dumps(payload),
            "receipt-handle",
            "https://sqs.test/ocr",
            "source-message-1",
            3,
        )

    ocr_poll.s3_client.put_object.assert_not_called()
    handoff_dependencies.sqs.send_message.assert_not_called()
    handoff_dependencies.table.update_item.assert_not_called()


def test_in_progress_republishes_before_ack_without_spending_error_budget(
    handoff_dependencies,
):
    handoff_dependencies.sqs.send_message.return_value = {
        "MessageId": "next-poll-message-1"
    }
    ocr_poll.textract_client.get_document_text_detection.return_value = {
        "JobStatus": "IN_PROGRESS"
    }

    assert _process() is True

    handoff_dependencies.sqs.send_message.assert_called_once()
    send = handoff_dependencies.sqs.send_message.call_args.kwargs
    assert send["QueueUrl"] == "https://sqs.test/ocr"
    assert 0 < send["DelaySeconds"] <= 900
    replacement = json.loads(send["MessageBody"])
    assert replacement["attempt"] == 1
    assert isinstance(replacement["submittedAt"], str)

    update = handoff_dependencies.table.update_item.call_args.kwargs
    assert "ocrPollHandoff.messageId = :source_message_id" in update["ConditionExpression"]
    assert update["ExpressionAttributeValues"][":source_message_id"] == "source-message-1"
    assert update["ExpressionAttributeValues"][":next_message_id"] == "next-poll-message-1"
    assert update["ExpressionAttributeValues"][":attempt"] == 1


def test_stale_duplicate_poll_message_fails_before_textract(
    handoff_dependencies,
):
    handoff_dependencies.table.get_item.return_value["Item"]["ocrPollHandoff"][
        "messageId"
    ] = "newer-poll-message"

    with pytest.raises(RuntimeError, match="authoritative checkpoint"):
        _process()

    ocr_poll.textract_client.get_document_text_detection.assert_not_called()
    handoff_dependencies.sqs.send_message.assert_not_called()
    handoff_dependencies.table.update_item.assert_not_called()


def test_direct_extract_handoff_v2_keeps_owner_separate_from_route(
    handoff_dependencies,
):
    payload = json.loads(_poll_message())
    payload["documentRoute"] = "bank"
    item = handoff_dependencies.table.get_item.return_value["Item"]
    item["documentRoute"] = "bank"
    item["ocrPollHandoff"]["documentRoute"] = "bank"
    handoff_dependencies.sqs.send_message.return_value = {
        "MessageId": "bank-message-1"
    }

    assert ocr_poll.process_ocr_poll_message(
        json.dumps(payload),
        "receipt-handle",
        "https://sqs.test/ocr",
        "source-message-1",
        1,
    ) is True

    sent = json.loads(
        handoff_dependencies.sqs.send_message.call_args.kwargs["MessageBody"]
    )
    assert sent["schemaVersion"] == "scanalyze.extract.v2"
    assert sent["customer_id"] == CUSTOMER_ID
    assert sent["deployment_id"] == DEPLOYMENT_ID
    assert sent["pipeline_stage"] == "bank-extract"
    assert sent["processing_domain"] == "bank"
    assert "tenantId" not in sent
