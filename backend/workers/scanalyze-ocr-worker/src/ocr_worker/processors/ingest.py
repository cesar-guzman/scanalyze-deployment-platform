import json
import logging
from datetime import datetime, timezone
from typing import Mapping

from ..aws import build_key, dynamodb_resource, sqs_client, textract_client
from ..boundary import authorize_document_boundary, require_poll_checkpoint
from ..config import config
from ..contracts import IngestMessage, MessageMetadata, OcrPollMessage
from ..logger import bind_context, clear_context, log_event, safe_error_details


logger = logging.getLogger(__name__)

HANDOFF_CONFIRMED_STATUSES = frozenset(
    {
        "OCR_COMPLETED",
        "CLASSIFY_COMPLETED",
        "BANK_EXTRACTED",
        "PERSONAL_EXTRACTED",
        "GOV_EXTRACTED",
        "COMPLETED",
        "FAILED",
    }
)


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _checkpoint_is_durable(checkpoint: Mapping[str, object], job_id: str) -> bool:
    message_id = checkpoint.get("messageId")
    return (
        checkpoint.get("status") == "ENQUEUED"
        and checkpoint.get("textractJobId") == job_id
        and isinstance(message_id, str)
        and bool(message_id.strip())
    )


def _send_poll_message(
    *,
    poll_message: OcrPollMessage,
    queue_url: str,
) -> str:
    send_kwargs = {
        "QueueUrl": queue_url,
        "MessageBody": json.dumps(
            poll_message.model_dump(by_alias=True, exclude_none=True)
        ),
    }
    if queue_url.endswith(".fifo"):
        send_kwargs["MessageGroupId"] = poll_message.documentId
        send_kwargs["MessageDeduplicationId"] = (
            f"{poll_message.documentId}-{poll_message.textractJobId}-ocr-poll-v2"
        )

    response = sqs_client.send_message(**send_kwargs)
    message_id = response.get("MessageId") if isinstance(response, dict) else None
    if not isinstance(message_id, str) or not message_id.strip():
        raise RuntimeError("OCR poll handoff was not acknowledged by SQS")
    return message_id


def process_ingest_message(
    message_body: str,
    receipt_handle: str,
    message_id: str,
    receive_count: int,
) -> bool:
    """Authorize and advance one strict ingest-v2 message to OCR polling."""

    del receipt_handle
    clear_context()
    logger.info("Processing ingest message")
    log_event("processing_ingest", message_id=message_id, receive_count=receive_count)

    try:
        msg_dict = json.loads(message_body)
        ingest_msg = IngestMessage(**msg_dict)
    except Exception as error:
        log_event("schema_validation_failed", **safe_error_details(error))
        raise ValueError("Invalid message schema") from error

    metadata = ingest_msg.metadata.model_dump(exclude_none=True)
    bind_context(
        documentId=ingest_msg.documentId,
        correlationId=metadata.get("correlationId"),
        traceId=metadata.get("traceId"),
        tenant=config.tenant,
        stage="ocr_ingest",
    )

    table_name = config.get("data-foundation/documents_table_name")
    trusted_raw_bucket = config.get("data-foundation/raw_bucket_name")
    trusted_ocr_bucket = config.get("data-foundation/ocr_bucket_name")
    ocr_queue_url = config.get("queues/ocr_url")
    table = dynamodb_resource.Table(table_name)
    key = build_key(table_name, ingest_msg.documentId, config.tenant)

    # This read is the security boundary. Missing data and read failures retry/DLQ.
    response = table.get_item(Key=key, ConsistentRead=True)
    item = response.get("Item")
    authorized = authorize_document_boundary(
        item=item,
        message_customer_id=ingest_msg.customer_id,
        message_deployment_id=ingest_msg.deployment_id,
        message_document_id=ingest_msg.documentId,
        message_source_bucket=ingest_msg.raw.bucket,
        message_source_key=ingest_msg.raw.key,
        runtime_customer_id=config.customer_id,
        runtime_deployment_id=config.deployment_id,
        trusted_source_bucket=trusted_raw_bucket,
        trusted_artifact_bucket=trusted_ocr_bucket,
    )
    if (
        ingest_msg.processing_domain is not None
        and ingest_msg.processing_domain != authorized.document_route
    ):
        raise RuntimeError("Message processing domain does not match the document")

    ingest_checkpoint = (item.get("stages") or {}).get("ingest") or {}
    if (
        ingest_checkpoint.get("status") != "ENQUEUED"
        or ingest_checkpoint.get("enqueueId") != ingest_msg.enqueue_id
        or ingest_checkpoint.get("sqsMessageId") != message_id
    ):
        raise RuntimeError("Ingest handoff checkpoint is unavailable")

    current_status = item.get("status")
    checkpoint = item.get("ocrPollHandoff")
    job_id = item.get("textractJobId")
    submitted_at = ingest_msg.uploadedAt or _utc_now()

    if current_status == "OCR" or current_status in HANDOFF_CONFIRMED_STATUSES:
        if not isinstance(job_id, str) or not job_id:
            raise RuntimeError("Authoritative OCR state is missing its Textract job")
        checkpoint = require_poll_checkpoint(
            authorized,
            textract_job_id=job_id,
            source_bucket=authorized.source_bucket,
            source_key=authorized.source_key,
            artifact_bucket=authorized.artifact_bucket,
            artifact_key=authorized.artifact_key,
        )
        if _checkpoint_is_durable(checkpoint, job_id):
            log_event("ocr_poll_handoff_already_enqueued", message_id=message_id)
            return True
        if current_status in HANDOFF_CONFIRMED_STATUSES:
            raise RuntimeError("Downstream progress is missing a durable OCR handoff checkpoint")
        submitted_at = checkpoint.get("submittedAt")
        if not isinstance(submitted_at, str) or not submitted_at:
            raise RuntimeError("Authoritative OCR poll checkpoint is missing submittedAt")
    elif current_status == "SUBMITTED":
        try:
            textract_response = textract_client.start_document_text_detection(
                DocumentLocation={
                    "S3Object": {
                        "Bucket": authorized.source_bucket,
                        "Name": authorized.source_key,
                    }
                },
                ClientRequestToken=ingest_msg.documentId[:64],
            )
            job_id = textract_response["JobId"]
        except textract_client.exceptions.InvalidS3ObjectException as error:
            logger.error(
                "Textract cannot access authoritative object",
                extra={"errorType": type(error).__name__},
            )
            raise
        except Exception as error:
            logger.error("Failed to start Textract", extra={"errorType": type(error).__name__})
            raise

        if not isinstance(job_id, str) or not job_id:
            raise RuntimeError("Textract did not return a job identifier")

        checkpoint = {
            "status": "PENDING",
            "textractJobId": job_id,
            "source": {
                "bucket": authorized.source_bucket,
                "key": authorized.source_key,
            },
            "artifact": {
                "bucket": authorized.artifact_bucket,
                "key": authorized.artifact_key,
            },
            "documentRoute": authorized.document_route,
            "submittedAt": submitted_at,
        }
        now_iso = _utc_now()
        table.update_item(
            Key=key,
            UpdateExpression=(
                "SET #s = :new_status, textractJobId = :textract_job_id, "
                "updatedAt = :now, ocrPollHandoff = :handoff, "
                "#stages.#ocr = :ocr_stage"
            ),
            ConditionExpression=(
                "attribute_exists(#document_id) AND #s = :old_status AND "
                "#customer_id = :customer_id AND #deployment_id = :deployment_id AND "
                "#ownership_schema_version = :ownership_schema_version"
            ),
            ExpressionAttributeNames={
                "#s": "status",
                "#document_id": "documentId",
                "#customer_id": "customer_id",
                "#deployment_id": "deployment_id",
                "#ownership_schema_version": "ownership_schema_version",
                "#stages": "stages",
                "#ocr": "ocr",
            },
            ExpressionAttributeValues={
                ":new_status": "OCR",
                ":old_status": "SUBMITTED",
                ":textract_job_id": job_id,
                ":now": now_iso,
                ":handoff": checkpoint,
                ":customer_id": authorized.customer_id,
                ":deployment_id": authorized.deployment_id,
                ":ownership_schema_version": 1,
                ":ocr_stage": {
                    "status": "IN_PROGRESS",
                    "startedAt": now_iso,
                    "message": "Textract processing started",
                },
            },
        )
    else:
        raise RuntimeError("Document is not in a retryable ingest state")

    poll_msg = OcrPollMessage(
        schemaVersion="scanalyze.ocr-poll.v2",
        customer_id=authorized.customer_id,
        deployment_id=authorized.deployment_id,
        ownership_schema_version=1,
        pipeline_stage="ocr",
        documentId=authorized.document_id,
        textractJobId=job_id,
        sourceBucket=authorized.source_bucket,
        sourceKey=authorized.source_key,
        documentRoute=authorized.document_route,
        artifactBucket=authorized.artifact_bucket,
        artifactKey=authorized.artifact_key,
        submittedAt=submitted_at,
        attempt=0,
        metadata=MessageMetadata(**metadata),
    )
    downstream_message_id = _send_poll_message(
        poll_message=poll_msg,
        queue_url=ocr_queue_url,
    )

    now_iso = _utc_now()
    table.update_item(
        Key=key,
        UpdateExpression=(
            "SET ocrPollHandoff.#handoff_status = :enqueued, "
            "ocrPollHandoff.messageId = :message_id, "
            "ocrPollHandoff.enqueuedAt = :now, updatedAt = :now"
        ),
        ConditionExpression=(
            "#s = :ocr_status AND textractJobId = :textract_job_id AND "
            "ocrPollHandoff.#handoff_status = :pending AND "
            "#customer_id = :customer_id AND #deployment_id = :deployment_id AND "
            "#ownership_schema_version = :ownership_schema_version"
        ),
        ExpressionAttributeNames={
            "#s": "status",
            "#handoff_status": "status",
            "#customer_id": "customer_id",
            "#deployment_id": "deployment_id",
            "#ownership_schema_version": "ownership_schema_version",
        },
        ExpressionAttributeValues={
            ":enqueued": "ENQUEUED",
            ":pending": "PENDING",
            ":ocr_status": "OCR",
            ":message_id": downstream_message_id,
            ":textract_job_id": job_id,
            ":now": now_iso,
            ":customer_id": authorized.customer_id,
            ":deployment_id": authorized.deployment_id,
            ":ownership_schema_version": 1,
        },
    )
    log_event(
        "enqueued_ocr_poll",
        message_id=message_id,
        downstream_message_id=downstream_message_id,
        receive_count=receive_count,
    )
    return True
