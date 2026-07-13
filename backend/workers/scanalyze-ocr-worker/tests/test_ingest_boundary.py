import json
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from ocr_worker.processors import ingest


CUSTOMER_ID = "cust_01ARZ3NDEKTSV4RRFFQ69G5FAW"
OTHER_CUSTOMER_ID = "cust_01BX5ZZKBKACTAV9WEVGEMMVS1"
DEPLOYMENT_ID = "dep_01ARZ3NDEKTSV4RRFFQ69G5FAV"
OTHER_DEPLOYMENT_ID = "dep_01BX5ZZKBKACTAV9WEVGEMMVS0"
DOCUMENT_ID = "doc-ingest-1"
RAW_BUCKET = "raw-bucket"
OCR_BUCKET = "ocr-bucket"
RAW_KEY = (
    f"customers/{CUSTOMER_ID}/deployments/{DEPLOYMENT_ID}/"
    f"documents/{DOCUMENT_ID}/source.pdf"
)
OCR_KEY = (
    f"customers/{CUSTOMER_ID}/deployments/{DEPLOYMENT_ID}/"
    f"documents/{DOCUMENT_ID}/ocr.json"
)


def _message(**overrides) -> str:
    payload = {
        "schemaVersion": "scanalyze.ingest.v2",
        "customer_id": CUSTOMER_ID,
        "deployment_id": DEPLOYMENT_ID,
        "ownership_schema_version": 1,
        "pipeline_stage": "ingest",
        "enqueue_id": "enqueue-1",
        "documentId": DOCUMENT_ID,
        "raw": {"bucket": RAW_BUCKET, "key": RAW_KEY},
        "contentType": "application/pdf",
        "uploadedAt": "2026-07-12T00:00:00+00:00",
        "_metadata": {"correlationId": "correlation-1", "traceId": "trace-1"},
    }
    payload.update(overrides)
    return json.dumps(payload)


def _document(**overrides) -> dict:
    item = {
        "documentId": DOCUMENT_ID,
        "customer_id": CUSTOMER_ID,
        "deployment_id": DEPLOYMENT_ID,
        "ownership_schema_version": 1,
        "status": "SUBMITTED",
        "stages": {
            "ingest": {
                "status": "ENQUEUED",
                "enqueueId": "enqueue-1",
                "sqsMessageId": "source-message",
            }
        },
        "documentRoute": "bank",
        "input": {"bucket": RAW_BUCKET, "key": RAW_KEY},
    }
    item.update(overrides)
    return item


@pytest.fixture
def dependencies(monkeypatch):
    table = MagicMock()
    table.get_item.return_value = {"Item": _document()}
    dynamodb = MagicMock()
    dynamodb.Table.return_value = table

    textract = MagicMock()
    textract.start_document_text_detection.return_value = {"JobId": "job-1"}
    sqs = MagicMock()
    sqs.send_message.return_value = {"MessageId": "poll-message-1"}
    config = SimpleNamespace(
        env="test",
        tenant="platform",
        customer_id=CUSTOMER_ID,
        deployment_id=DEPLOYMENT_ID,
        get=lambda key: {
            "data-foundation/documents_table_name": "documents-table",
            "data-foundation/raw_bucket_name": RAW_BUCKET,
            "data-foundation/ocr_bucket_name": OCR_BUCKET,
            "queues/ocr_url": "https://sqs.test/ocr.fifo",
        }[key],
    )

    monkeypatch.setattr(ingest, "config", config)
    monkeypatch.setattr(ingest, "dynamodb_resource", dynamodb)
    monkeypatch.setattr(ingest, "textract_client", textract)
    monkeypatch.setattr(ingest, "sqs_client", sqs)
    monkeypatch.setattr(
        ingest,
        "build_key",
        MagicMock(return_value={"document_id": DOCUMENT_ID}),
    )
    return SimpleNamespace(table=table, textract=textract, sqs=sqs)


def _process() -> bool:
    return ingest.process_ingest_message(_message(), "receipt", "source-message", 1)


def test_ingest_reconciles_authoritative_owner_and_locators_before_side_effects(dependencies):
    assert _process() is True

    dependencies.table.get_item.assert_called_once_with(
        Key={"document_id": DOCUMENT_ID},
        ConsistentRead=True,
    )
    dependencies.textract.start_document_text_detection.assert_called_once_with(
        DocumentLocation={"S3Object": {"Bucket": RAW_BUCKET, "Name": RAW_KEY}},
        ClientRequestToken=DOCUMENT_ID[:64],
    )
    assert dependencies.table.update_item.call_count == 2
    pending = dependencies.table.update_item.call_args_list[0].kwargs
    assert "#customer_id = :customer_id" in pending["ConditionExpression"]
    assert "#deployment_id = :deployment_id" in pending["ConditionExpression"]
    assert pending["ExpressionAttributeValues"][":handoff"]["status"] == "PENDING"
    assert pending["ExpressionAttributeValues"][":handoff"]["artifact"] == {
        "bucket": OCR_BUCKET,
        "key": OCR_KEY,
    }
    checkpoint = dependencies.table.update_item.call_args_list[1].kwargs
    assert checkpoint["ExpressionAttributeValues"][":message_id"] == "poll-message-1"
    assert checkpoint["ExpressionAttributeValues"][":enqueued"] == "ENQUEUED"

    sent = json.loads(dependencies.sqs.send_message.call_args.kwargs["MessageBody"])
    assert sent["schemaVersion"] == "scanalyze.ocr-poll.v2"
    assert sent["customer_id"] == CUSTOMER_ID
    assert sent["deployment_id"] == DEPLOYMENT_ID
    assert sent["ownership_schema_version"] == 1
    assert sent["pipeline_stage"] == "ocr"
    assert sent["documentRoute"] == "bank"
    assert sent["artifactKey"] == OCR_KEY


@pytest.mark.parametrize(
    "ddb_result",
    [{}, {"Item": {}}],
)
def test_ingest_missing_authoritative_document_has_no_side_effects(dependencies, ddb_result):
    dependencies.table.get_item.return_value = ddb_result
    with pytest.raises(RuntimeError, match="not found"):
        _process()
    dependencies.textract.start_document_text_detection.assert_not_called()
    dependencies.sqs.send_message.assert_not_called()
    dependencies.table.update_item.assert_not_called()


def test_ingest_authoritative_read_error_has_no_side_effects(dependencies):
    dependencies.table.get_item.side_effect = RuntimeError("synthetic read outage")
    with pytest.raises(RuntimeError, match="synthetic read outage"):
        _process()
    dependencies.textract.start_document_text_detection.assert_not_called()
    dependencies.sqs.send_message.assert_not_called()
    dependencies.table.update_item.assert_not_called()


@pytest.mark.parametrize(
    "ingest_stage",
    [
        {},
        {"status": "ENQUEUE_PENDING", "enqueueId": "enqueue-1"},
        {
            "status": "ENQUEUED",
            "enqueueId": "foreign-enqueue",
            "sqsMessageId": "source-message",
        },
        {
            "status": "ENQUEUED",
            "enqueueId": "enqueue-1",
            "sqsMessageId": "foreign-message",
        },
    ],
)
def test_ingest_requires_exact_durable_producer_checkpoint_before_textract(
    dependencies, ingest_stage
):
    dependencies.table.get_item.return_value = {
        "Item": _document(stages={"ingest": ingest_stage})
    }
    with pytest.raises(RuntimeError, match="checkpoint"):
        _process()
    dependencies.textract.start_document_text_detection.assert_not_called()
    dependencies.sqs.send_message.assert_not_called()
    dependencies.table.update_item.assert_not_called()


def test_ingest_processing_domain_mismatch_has_no_side_effects(dependencies):
    with pytest.raises(RuntimeError, match="processing domain"):
        ingest.process_ingest_message(
            _message(processing_domain="personal"),
            "receipt",
            "source-message",
            1,
        )
    dependencies.textract.start_document_text_detection.assert_not_called()
    dependencies.sqs.send_message.assert_not_called()
    dependencies.table.update_item.assert_not_called()


@pytest.mark.parametrize(
    "record_change",
    [
        {"customer_id": OTHER_CUSTOMER_ID},
        {"deployment_id": OTHER_DEPLOYMENT_ID},
        {"ownership_schema_version": 2},
        {"customer_id": None},
        {"deployment_id": None},
    ],
)
def test_ingest_owner_mismatch_has_no_side_effects(dependencies, record_change):
    dependencies.table.get_item.return_value = {"Item": _document(**record_change)}
    with pytest.raises(RuntimeError, match="ownership"):
        _process()
    dependencies.textract.start_document_text_detection.assert_not_called()
    dependencies.sqs.send_message.assert_not_called()
    dependencies.table.update_item.assert_not_called()


@pytest.mark.parametrize(
    "message_change",
    [
        {"customer_id": OTHER_CUSTOMER_ID},
        {"deployment_id": OTHER_DEPLOYMENT_ID},
    ],
)
def test_ingest_message_owner_cannot_select_another_runtime_boundary(
    dependencies,
    message_change,
):
    with pytest.raises(RuntimeError, match="ownership"):
        ingest.process_ingest_message(
            _message(**message_change),
            "receipt",
            "source-message",
            1,
        )
    dependencies.textract.start_document_text_detection.assert_not_called()
    dependencies.sqs.send_message.assert_not_called()
    dependencies.table.update_item.assert_not_called()


@pytest.mark.parametrize(
    "stored_input",
    [
        {"bucket": "foreign-bucket", "key": RAW_KEY},
        {"bucket": RAW_BUCKET, "key": "foreign-prefix/source.pdf"},
        {"bucket": RAW_BUCKET, "key": RAW_KEY + ".different"},
        {},
    ],
)
def test_ingest_untrusted_or_mismatched_locator_has_no_side_effects(dependencies, stored_input):
    dependencies.table.get_item.return_value = {"Item": _document(input=stored_input)}
    with pytest.raises(RuntimeError, match="locator"):
        _process()
    dependencies.textract.start_document_text_detection.assert_not_called()
    dependencies.sqs.send_message.assert_not_called()
    dependencies.table.update_item.assert_not_called()


def test_ingest_requires_explicit_document_route_and_never_uses_customer_as_route(dependencies):
    dependencies.table.get_item.return_value = {"Item": _document(documentRoute=None)}
    with pytest.raises(RuntimeError, match="route"):
        _process()
    dependencies.textract.start_document_text_detection.assert_not_called()
    dependencies.sqs.send_message.assert_not_called()


def test_ingest_retry_resends_pending_poll_without_restarting_textract(dependencies):
    dependencies.sqs.send_message.side_effect = RuntimeError("synthetic poll outage")
    with pytest.raises(RuntimeError, match="synthetic poll outage"):
        _process()

    pending_handoff = dependencies.table.update_item.call_args_list[0].kwargs[
        "ExpressionAttributeValues"
    ][":handoff"]
    dependencies.table.get_item.return_value = {
        "Item": _document(
            status="OCR",
            textractJobId="job-1",
            ocrPollHandoff=pending_handoff,
        )
    }
    dependencies.sqs.send_message.side_effect = None
    dependencies.sqs.send_message.return_value = {"MessageId": "poll-message-2"}

    assert _process() is True
    dependencies.textract.start_document_text_detection.assert_called_once()
    assert dependencies.sqs.send_message.call_count == 2
    checkpoint = dependencies.table.update_item.call_args_list[-1].kwargs
    assert checkpoint["ExpressionAttributeValues"][":message_id"] == "poll-message-2"


def test_ingest_retry_acks_only_durable_enqueued_checkpoint(dependencies):
    dependencies.table.get_item.return_value = {
        "Item": _document(
            status="OCR",
            textractJobId="job-1",
            ocrPollHandoff={
                "status": "ENQUEUED",
                "messageId": "poll-message-existing",
                "textractJobId": "job-1",
                "source": {"bucket": RAW_BUCKET, "key": RAW_KEY},
                "artifact": {"bucket": OCR_BUCKET, "key": OCR_KEY},
                "documentRoute": "bank",
                "submittedAt": "2026-07-12T00:00:00+00:00",
            },
        )
    }
    assert _process() is True
    dependencies.textract.start_document_text_detection.assert_not_called()
    dependencies.sqs.send_message.assert_not_called()
    dependencies.table.update_item.assert_not_called()


def test_ingest_retry_after_downstream_progress_acks_durable_checkpoint(
    dependencies,
):
    dependencies.table.get_item.return_value = {
        "Item": _document(
            status="BANK_EXTRACTED",
            textractJobId="job-1",
            ocrPollHandoff={
                "status": "ENQUEUED",
                "messageId": "poll-message-existing",
                "textractJobId": "job-1",
                "source": {"bucket": RAW_BUCKET, "key": RAW_KEY},
                "artifact": {"bucket": OCR_BUCKET, "key": OCR_KEY},
                "documentRoute": "bank",
                "submittedAt": "2026-07-12T00:00:00+00:00",
            },
        )
    }
    assert _process() is True
    dependencies.textract.start_document_text_detection.assert_not_called()
    dependencies.sqs.send_message.assert_not_called()
    dependencies.table.update_item.assert_not_called()
