import datetime
import json

from pydantic import ValidationError as PydanticValidationError

from ..aws import sqs_client
from ..config import config
from ..contracts import NotifyMessage, NotifyMeta, NotifyResult, PersistMessage
from ..dynamo import update_persist_stage
from ..logger import bind_context, log_event, logger, safe_error_details
from ..routing import route_is_allowed, structured_key_for


def process_persist_message(body: str, receipt_handle: str, queue_url: str, tenant: str) -> bool:
    del receipt_handle, queue_url

    try:
        msg_data = json.loads(body)
        if not isinstance(msg_data, dict):
            raise ValueError("Message body must be a JSON object")

        meta_env = msg_data.get("_metadata", {})
        if not isinstance(meta_env, dict):
            raise ValueError("Message metadata must be a JSON object")

        msg = PersistMessage(**msg_data)
    except (json.JSONDecodeError, PydanticValidationError, TypeError, ValueError) as error:
        log_event("poison_message", stage="persist", **safe_error_details(error))
        return False

    doc_id = msg.documentId
    route = msg.meta.tenant
    if msg.meta.env != config.env or not route_is_allowed(tenant, route):
        log_event("message_route_mismatch", stage="persist", document_id=doc_id)
        return False

    bind_context(
        documentId=doc_id,
        correlationId=meta_env.get("correlationId"),
        traceId=meta_env.get("traceId"),
        uploaderUserId=meta_env.get("uploaderUserId"),
        customerStack=meta_env.get("customerStack"),
        route=route,
        tenant=route,
        stage="persist",
    )

    expected_bucket = config.get(tenant, "data-foundation/structured_bucket_name")
    expected_key = structured_key_for(route, doc_id)
    if msg.validation.status == "PASS" and (
        msg.structured.bucket != expected_bucket or msg.structured.key != expected_key
    ):
        log_event("artifact_route_mismatch", stage="persist", document_id=doc_id)
        return False

    log_event(
        "processing_persist",
        stage="persist",
        document_id=doc_id,
        correlationId=msg.correlationId,
        tenant=route,
    )

    final_status = "COMPLETED" if msg.validation.status == "PASS" else "FAILED"
    now = datetime.datetime.now(datetime.timezone.utc).isoformat()
    table_name = config.get(tenant, "data-foundation/documents_table_name")

    payload = {
        "status": final_status,
        "completedAt": now,
        "validationStatus": msg.validation.status,
        "stages_persist": {
            "status": "DONE",
            "finalStatus": final_status,
            "completedAt": now,
        },
        "updatedAt": now,
    }
    if msg.validation.status == "PASS":
        payload["structured"] = msg.structured.model_dump()

    try:
        completed_at = update_persist_stage(table_name, route, doc_id, payload)
    except Exception as error:
        logger.warning(
            "Transient or rejected DynamoDB persist transition",
            extra={"errorType": type(error).__name__},
        )
        return False

    notify_msg = NotifyMessage(
        documentId=doc_id,
        result=NotifyResult(
            finalStatus=final_status,
            completedAt=completed_at,
            validationStatus=msg.validation.status,
        ),
        meta=NotifyMeta(env=msg.meta.env, tenant=msg.meta.tenant),
        correlationId=msg.correlationId,
        attempt=msg.attempt + 1,
    )

    notify_queue_url = config.get(tenant, "queues/notify_url")
    out_dict = notify_msg.model_dump()
    out_dict["_metadata"] = meta_env

    send_kwargs = {
        "QueueUrl": notify_queue_url,
        "MessageBody": json.dumps(out_dict),
    }
    if notify_queue_url.endswith(".fifo"):
        send_kwargs["MessageGroupId"] = doc_id
        send_kwargs["MessageDeduplicationId"] = f"{doc_id}-notify-v1"

    try:
        sqs_client.send_message(**send_kwargs)
        logger.info("Enqueued notify message")
    except Exception as error:
        logger.warning(
            "Transient SQS error enqueueing notify",
            extra={"errorType": type(error).__name__},
        )
        return False

    log_event(
        "persist_completed",
        stage="persist",
        document_id=doc_id,
        finalStatus=final_status,
        tenant=route,
    )
    return True
