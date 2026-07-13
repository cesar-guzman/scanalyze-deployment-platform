import os
import signal
import sys
import time
import json
from pydantic import ValidationError

from .logger import setup_logging, get_logger, bind_context, safe_error_details
from .config import config
from .contracts import ClassifyMessage, ExtractMessage
from .aws import (
    receive_messages,
    delete_message,
    enqueue_message,
    get_document_item,
    get_ocr_text,
    mark_classification_enqueued,
    save_classification_evidence,
)
from .classifier import classify_document

setup_logging()
log = get_logger(__name__)

running = True
ROUTE_TO_DOMAIN = {
    "bank-extract": "bank",
    "personal-extract": "personal",
    "gov-extract": "gov",
}


def _safe_metadata(value):
    if not isinstance(value, dict):
        raise ValueError("Message metadata must be an object")
    allowed = {"correlationId", "traceId"}
    if set(value) - allowed:
        raise ValueError("Message metadata contains unsupported fields")
    result = {}
    for key in ("correlationId", "traceId"):
        item = value.get(key)
        if item is None:
            continue
        if not isinstance(item, str) or not 0 < len(item) <= 128:
            raise ValueError("Message metadata contains an invalid trace field")
        result[key] = item
    return result


def _require_owned_document(message, item, runtime_env):
    if (
        item.get("customer_id") != message.customer_id
        or item.get("deployment_id") != message.deployment_id
        or item.get("ownership_schema_version") != 1
    ):
        raise ValueError("Document is unavailable")
    stored_raw = item.get("input") or {}
    stored_ocr = (item.get("artifacts") or {}).get("ocr") or {}
    if (
        stored_raw.get("bucket") != message.raw.bucket
        or stored_raw.get("key") != message.raw.key
        or stored_ocr.get("bucket") != message.ocr.bucket
        or stored_ocr.get("key") != message.ocr.key
    ):
        raise ValueError("Document is unavailable")
    stored_route = item.get("documentRoute")
    if (
        stored_route not in {"platform", "default"}
        or message.meta.tenant != stored_route
        or message.meta.env != runtime_env
        or (
            item.get("status") == "OCR_COMPLETED"
            and item.get("processing_domain") is not None
        )
    ):
        raise ValueError("Document is unavailable")


def _classification_handoff_confirmed(item):
    classification = item.get("classification")
    if not isinstance(classification, dict):
        return False
    route = classification.get("enqueuedTo")
    processing_domain = ROUTE_TO_DOMAIN.get(route)
    message_id = classification.get("messageId")
    return (
        classification.get("classifierVersion") == "v2"
        and processing_domain is not None
        and item.get("routingTarget") == route
        and item.get("processing_domain") == processing_domain
        and item.get("status") == "CLASSIFY_COMPLETED"
        and isinstance(message_id, str)
        and bool(message_id.strip())
    )


def _pending_classification_route(item):
    classification = item.get("classification")
    if not isinstance(classification, dict):
        return None
    route = classification.get("route")
    processing_domain = ROUTE_TO_DOMAIN.get(route)
    if (
        item.get("status") == "CLASSIFY_PENDING"
        and classification.get("classifierVersion") == "v2"
        and processing_domain is not None
        and item.get("routingTarget") == route
        and item.get("processing_domain") == processing_domain
        and not classification.get("enqueuedTo")
        and not classification.get("messageId")
    ):
        return route
    return None

def handle_sigterm(*args):
    global running
    log.info("Received SIGTERM/SIGINT, initiating graceful shutdown")
    running = False

signal.signal(signal.SIGTERM, handle_sigterm)
signal.signal(signal.SIGINT, handle_sigterm)

def process_message(msg: dict):
    receipt_handle = msg['ReceiptHandle']
    body_str = msg.get('Body', '{}')
    
    try:
        body_dict = json.loads(body_str)
        
        meta_env = _safe_metadata(body_dict.pop("_metadata", {}))
        bind_context(
            documentId=body_dict.get("documentId"),
            correlationId=meta_env.get("correlationId"),
            traceId=meta_env.get("traceId"),
            tenant="classifier",
            stage="classify"
        )
        
        # Parse against Pydantic model
        classify_msg = ClassifyMessage(**body_dict)
        config.require_owner(classify_msg.customer_id, classify_msg.deployment_id)
    except (json.JSONDecodeError, ValidationError, ValueError, AttributeError) as e:
        log.error("poison_message", **safe_error_details(e))
        return False

    doc_id = classify_msg.documentId
    log_bound = log.bind(documentId=doc_id, tenant=classify_msg.meta.tenant, env=classify_msg.meta.env)
    
    try:
        bucket = classify_msg.ocr.bucket
        table_name = config.get("data-foundation/documents_table_name")
        doc_item = get_document_item(table_name, doc_id)
        _require_owned_document(classify_msg, doc_item, config.env)
        if _classification_handoff_confirmed(doc_item):
            log_bound.info("message_already_processed", info="Classification evidence and enqueue mark found")
            delete_message(config.get("queues/classify_url"), receipt_handle)
            return True

        route = _pending_classification_route(doc_item)
        if route is None:
            if doc_item.get("status") != "OCR_COMPLETED":
                raise ValueError("Document classification state is unavailable")

            # 1. Read S3 text
            text_content = get_ocr_text(bucket, classify_msg.ocr.key)

            # 2. Classify
            bedrock_flag = config.get("features/bedrock_classification_enabled", default="false").lower() == "true"
            doc_type, confidence, route, strategy = classify_document(text_content, bedrock_flag)
            processing_domain = ROUTE_TO_DOMAIN.get(route)
            if not processing_domain:
                raise ValueError("Classification route is not supported")

            log_bound.info("classification_result", docType=doc_type, confidence=confidence, route=route, strategy=strategy)

            # 3. Persist a resumable pre-handoff checkpoint.
            save_classification_evidence(
                table_name=table_name,
                document_id=doc_id,
                customer_id=classify_msg.customer_id,
                deployment_id=classify_msg.deployment_id,
                doc_type=doc_type,
                confidence=confidence,
                route=route,
                processing_domain=processing_domain,
                strategy=strategy,
                classifier_version="v2"
            )
        else:
            processing_domain = ROUTE_TO_DOMAIN[route]

        # 4. Enqueue to route queue (tenant-specific queue)
        target_queue_url = config.get(f"queues/{route}_url")
            
        extract_msg = ExtractMessage(
            documentId=doc_id,
            customer_id=classify_msg.customer_id,
            deployment_id=classify_msg.deployment_id,
            ownership_schema_version=classify_msg.ownership_schema_version,
            pipeline_stage=route,
            processing_domain=processing_domain,
            ocr=classify_msg.ocr,
            raw=classify_msg.raw,
            correlationId=meta_env.get("correlationId"),
            attempt=0,
        )
        
        # message deduplication id
        dedup_id = f"{classify_msg.deployment_id}-{doc_id}-classify-v2"
        
        out_dict = extract_msg.model_dump()
        out_dict["_metadata"] = meta_env
        
        downstream_message_id = enqueue_message(
            queue_url=target_queue_url,
            message_body=json.dumps(out_dict),
            message_group_id=doc_id,
            deduplication_id=dedup_id
        )
        mark_classification_enqueued(
            table_name,
            doc_id,
            classify_msg.customer_id,
            classify_msg.deployment_id,
            route,
            processing_domain,
            downstream_message_id,
        )

        # 5. Delete original message
        classify_url = config.get("queues/classify_url")
        delete_message(classify_url, receipt_handle)
        return True

    except Exception as e:
        log_bound.error("transient_error", **safe_error_details(e))
        # Do not delete message to allow SQS retry
        return False

def main_loop():
    log.info("Starting classifier worker")
    try:
        classify_queue = config.get("queues/classify_url")
    except KeyError as e:
        log.error("boot_failed", errorType=type(e).__name__)
        sys.exit(1)

    while running:
        # Long polling SQS
        messages = receive_messages(classify_queue, max_messages=10, wait_time=20)
        for msg in messages:
            if not running:
                break
            process_message(msg)

if __name__ == "__main__":
    main_loop()
    log.info("Worker shutdown complete")
