import json
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import MagicMock

import boto3
import pytest
from botocore.exceptions import ClientError

from ocr_worker.processors import ocr_poll


def _poll_message() -> str:
    return json.dumps(
        {
            "schemaVersion": "scanalyze.ocr-poll.v1",
            "documentId": "doc-ocr-handoff",
            "textractJobId": "textract-job-1",
            "sourceBucket": "raw-bucket",
            "sourceKey": "raw/document.pdf",
            "serviceTenant": "test-tenant",
            "documentRoute": "platform",
            "artifactBucket": "artifact-bucket",
            "artifactKey": "ocr/doc-ocr-handoff.json",
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
            "status": "OCR",
            "batchId": "batch-1",
            "textractJobId": "textract-job-1",
            "tenantId": "test-tenant",
            "documentRoute": "platform",
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
        get=lambda key: {
            "data-foundation/documents_table_name": "documents-table",
            "queues/classify_url": "https://sqs.test/classify",
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
        "#s = :old AND #textract_job_id = :job_id"
    )
    assert sqs.send_message.call_count == 2


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


def test_missing_authoritative_tenant_fails_closed(handoff_dependencies):
    table = handoff_dependencies.table
    sqs = handoff_dependencies.sqs
    table.get_item.return_value["Item"].pop("tenantId")

    with pytest.raises(RuntimeError, match="missing its tenant binding"):
        _process()

    sqs.send_message.assert_not_called()
    table.update_item.assert_not_called()


def test_route_falls_back_to_authoritative_tenant_and_must_match(
    handoff_dependencies,
):
    table = handoff_dependencies.table
    sqs = handoff_dependencies.sqs
    table.get_item.return_value["Item"].pop("documentRoute")

    with pytest.raises(RuntimeError, match="route does not match"):
        _process()

    sqs.send_message.assert_not_called()
    table.update_item.assert_not_called()
