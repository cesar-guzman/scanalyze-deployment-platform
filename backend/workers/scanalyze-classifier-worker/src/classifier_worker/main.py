import os
import signal
import sys
import time
import json
from pydantic import ValidationError

from .logger import setup_logging, get_logger, bind_context, safe_error_details
from .config import config
from .contracts import ClassifyMessage, ExtractMessage, ExtractMeta
from .aws import receive_messages, delete_message, get_ocr_text, save_classification_evidence, enqueue_message, get_document_item
from .classifier import classify_document

setup_logging()
log = get_logger(__name__)

running = True

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
        
        meta_env = body_dict.get("_metadata", {})
        bind_context(
            documentId=body_dict.get("documentId"),
            correlationId=meta_env.get("correlationId"),
            traceId=meta_env.get("traceId"),
            uploaderUserId=meta_env.get("uploaderUserId"),
            customerStack=meta_env.get("customerStack"),
            route=meta_env.get("route"),
            tenant="classifier",
            stage="classify"
        )
        
        # Parse against Pydantic model
        classify_msg = ClassifyMessage(**body_dict)
    except (json.JSONDecodeError, ValidationError) as e:
        log.error("poison_message", **safe_error_details(e))
        # Delete poison message
        classify_url = config.get("queues/classify_url")
        delete_message(classify_url, receipt_handle)
        return

    doc_id = classify_msg.documentId
    log_bound = log.bind(documentId=doc_id, tenant=classify_msg.meta.tenant, env=classify_msg.meta.env)
    
    try:
        if classify_msg.schemaVersion != "scanalyze.classify.v1":
            raise ValueError(f"Invalid schemaVersion: {classify_msg.schemaVersion}")
            
        bucket = classify_msg.ocr.bucket or config.get("data-foundation/ocr_bucket_name")
        if not bucket or not classify_msg.ocr.key:
            raise ValueError("OCR bucket or key missing in message")

        # Idempotency check: see if we already routed it
        table_name = config.get("data-foundation/documents_table_name")
        doc_item = get_document_item(table_name, doc_id)
        if doc_item and 'classification' in doc_item and 'enqueuedTo' in doc_item['classification']:
            log_bound.info("message_already_processed", info="Classification evidence and enqueue mark found")
            delete_message(config.get("queues/classify_url"), receipt_handle)
            return

        # 1. Read S3 text
        text_content = get_ocr_text(bucket, classify_msg.ocr.key)

        # 2. Classify
        bedrock_flag = config.get("features/bedrock_classification_enabled", default="false").lower() == "true"
        doc_type, confidence, route, strategy = classify_document(text_content, bedrock_flag)
        
        log_bound.info("classification_result", docType=doc_type, confidence=confidence, route=route, strategy=strategy)

        # 3. Save Evidence to Dynamo
        save_classification_evidence(
            table_name=table_name,
            document_id=doc_id,
            doc_type=doc_type,
            confidence=confidence,
            route=route,
            strategy=strategy,
            classifier_version="v1"
        )

        # 4. Enqueue to route queue (tenant-specific queue)
        env = config.env
        target_tenant = route.split('-')[0]
        param_name = f"/scanalyze/{env}/tenants/{target_tenant}/queues/{route}_url"
        try:
            ssm_resp = config.ssm_client.get_parameter(Name=param_name, WithDecryption=True)
            target_queue_url = ssm_resp['Parameter']['Value']
        except Exception as e:
            log_bound.error("queue_resolution_failed", errorType=type(e).__name__)
            raise
            
        extract_msg = ExtractMessage(
            documentId=doc_id,
            docType=doc_type,
            confidence=confidence,
            ocr=classify_msg.ocr,
            raw=classify_msg.raw,
            textract=classify_msg.textract,
            meta=ExtractMeta(
                pages=classify_msg.meta.pages,
                env=classify_msg.meta.env,
                tenant=classify_msg.meta.tenant,
                classifierStrategy=strategy
            )
        )
        
        # message deduplication id
        dedup_id = f"{doc_id}-classify-v1"
        
        out_dict = extract_msg.model_dump()
        out_dict["_metadata"] = meta_env
        
        enqueue_message(
            queue_url=target_queue_url,
            message_body=json.dumps(out_dict),
            message_group_id=doc_id,
            deduplication_id=dedup_id
        )
        
        # Optimization: Ideally update Dynamo to set 'enqueuedTo', but we already have idempotency via SQS MessageDeduplicationId in FIFOs.
        # We will keep it robust as is.

        # 5. Delete original message
        classify_url = config.get("queues/classify_url")
        delete_message(classify_url, receipt_handle)

    except Exception as e:
        log_bound.error("transient_error", **safe_error_details(e))
        # Do not delete message to allow SQS retry

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
