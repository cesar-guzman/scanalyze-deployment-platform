import datetime
import json

from pydantic import ValidationError as PydanticValidationError

from ..config import config
from ..contracts import NotifyMessage
from ..dynamo import update_notify_stage
from ..logger import bind_context, log_event, logger, safe_error_details
from ..routing import route_is_allowed


def process_notify_message(body: str, receipt_handle: str, queue_url: str, tenant: str) -> bool:
    del receipt_handle, queue_url

    try:
        msg_data = json.loads(body)
        if not isinstance(msg_data, dict):
            raise ValueError("Message body must be a JSON object")

        meta_env = msg_data.get("_metadata", {})
        if not isinstance(meta_env, dict):
            raise ValueError("Message metadata must be a JSON object")

        msg = NotifyMessage(**msg_data)
    except (json.JSONDecodeError, PydanticValidationError, TypeError, ValueError) as error:
        log_event("poison_message", stage="notify", **safe_error_details(error))
        return False

    doc_id = msg.documentId
    route = msg.meta.tenant
    if msg.meta.env != config.env or not route_is_allowed(tenant, route):
        log_event("message_route_mismatch", stage="notify", document_id=doc_id)
        return False

    bind_context(
        documentId=doc_id,
        correlationId=meta_env.get("correlationId"),
        traceId=meta_env.get("traceId"),
        uploaderUserId=meta_env.get("uploaderUserId"),
        customerStack=meta_env.get("customerStack"),
        route=route,
        tenant=route,
        stage="notify",
    )

    log_event(
        "notify_minimal",
        stage="notify",
        document_id=doc_id,
        finalStatus=msg.result.finalStatus,
        tenant=route,
    )

    now = datetime.datetime.now(datetime.timezone.utc).isoformat()
    table_name = config.get(tenant, "data-foundation/documents_table_name")
    payload = {
        "notifiedAt": now,
        "completedAt": msg.result.completedAt,
        "finalStatus": msg.result.finalStatus,
        "validationStatus": msg.result.validationStatus,
        "stages_notify": {
            "status": "DONE",
            "notifiedAt": now,
        },
        "updatedAt": now,
    }

    try:
        update_notify_stage(table_name, route, doc_id, payload)
    except Exception as error:
        logger.warning(
            "Transient or rejected DynamoDB notify transition",
            extra={"errorType": type(error).__name__},
        )
        return False

    try:
        webhooks_enabled = (
            config.get(tenant, "features/webhooks_enabled", "false").lower() == "true"
        )
        if webhooks_enabled:
            logger.info("Webhooks are enabled but not fully implemented")
            log_event(
                "webhook_dispatch_skipped",
                stage="notify",
                document_id=doc_id,
                reason="Not Implemented",
                tenant=route,
            )
    except Exception as error:
        logger.error(
            "Error checking webhook feature",
            extra={"errorType": type(error).__name__},
        )

    log_event("notify_completed", stage="notify", document_id=doc_id, tenant=route)
    return True
