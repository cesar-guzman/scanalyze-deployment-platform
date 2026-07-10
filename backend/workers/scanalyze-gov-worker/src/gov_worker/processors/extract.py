import json
import logging
from botocore.exceptions import ClientError
from pydantic import ValidationError

from ..logger import log_event, bind_context, safe_error_details
from ..config import config
from ..contracts import GovExtractMessage, ValidateMessage, S3Location, ValidateMeta
from ..aws import sqs_client
from ..s3 import get_ocr_text, save_structured_artifact
from ..dynamo import update_document_status
from ..bedrock import invoke_bedrock_gov_doc, PROMPT_VERSION
from ..normalize import parse_and_normalize

logger = logging.getLogger(__name__)

def is_already_extracted(bucket: str, key: str) -> bool:
    from ..aws import s3_client
    try:
        s3_client.head_object(Bucket=bucket, Key=key)
        return True
    except ClientError as e:
        if e.response['Error']['Code'] in ('404', 'NoSuchKey'):
            return False
        raise

def process_gov_extract_message(body: str, receipt_handle: str, queue_url: str) -> bool:
    """
    Main orchestrator for mapping OCR to Bedrock and uploading Structured output for gov documents.
    Returns True if the message should be deleted (success or permanent non-retryable error).
    Raises exception or returns False if SQS should retry.
    """
    message_id = "unknown"
    try:
        payload = json.loads(body)
        document_id = payload.get("documentId", "unknown")
        
        meta_env = payload.get("_metadata", {})
        bind_context(
            documentId=document_id,
            correlationId=meta_env.get("correlationId"),
            traceId=meta_env.get("traceId"),
            uploaderUserId=meta_env.get("uploaderUserId"),
            customerStack=meta_env.get("customerStack"),
            route=meta_env.get("route", payload.get("tenantId")),
            tenant="gov",
            stage="gov_extract"
        )
        log_event("extract_started", documentId=document_id)
        
        # Parse against Pydantic model with extra=ignore
        msg = GovExtractMessage(**payload)
        
        # Dependencies from config
        if msg.ocr and msg.ocr.bucket:
            ocr_bucket = msg.ocr.bucket
        else:
            ocr_bucket = config.get("data-foundation/ocr_bucket_name")
        structured_bucket = config.get("data-foundation/structured_bucket_name")
        dynamo_table = config.get("data-foundation/documents_table_name")
        validate_queue_url = config.get("queues/validate_url")
        model_id = config.get("BEDROCK_MODEL_ID", default="anthropic.claude-3-haiku-20240307-v1:0")
        
        # Identify OCR Key location
        if msg.ocr and msg.ocr.key:
            ocr_key = msg.ocr.key
        else:
            # Fallback pattern if contract just gave us DocumentID
            ocr_key = f"gov/{msg.documentId}/ocr.json"
            
        structured_key = f"gov/{msg.documentId}/result.json"
        
        # Idempotency check 
        if is_already_extracted(structured_bucket, structured_key):
            logger.info("Document already extracted; skipping Bedrock")
            log_event("extract_skipped_idempotent", documentId=msg.documentId)
            # Fast-forward to validate queue in case it got dropped there
            # Safely touch the DB status again just in case it wasn't saved last time
            update_document_status(
                table_name=dynamo_table,
                document_id=msg.documentId,
                status="GOV_EXTRACTED",
                tenant="gov",
                structured_key=structured_key,
                structured_bucket=structured_bucket,
                metadata={
                    "cached": True,
                    "attempt": getattr(msg, 'attempt', 0)
                }
            )
        else:
            # 1. Read S3
            try:
                ocr_text, text_stats = get_ocr_text(ocr_bucket, ocr_key)
            except ClientError as e:
                if e.response['Error']['Code'] in ('NoSuchKey', '404'):
                    if msg.attempt < 3:
                        logger.warning(f"OCR artifact missing; retrying attempt {msg.attempt}")
                        raise # Bubble up for SQS retry
                    
                    logger.error("OCR artifact missing after retry limit; non-retryable")
                    log_event("ocr_artifact_missing", documentId=msg.documentId)
                    # Mark document as failed
                    update_document_status(
                        table_name=dynamo_table,
                        document_id=msg.documentId,
                        status="GOV_EXTRACT_FAILED",
                        tenant="gov",
                        structured_key="N/A",
                        structured_bucket="N/A",
                        metadata={"error": "NoSuchKey"}
                    )
                    return True # Delete poison message
                raise # Bubble up for retry
                
            # 2. Invoke Bedrock
            logger.info("Invoking Bedrock")
            raw_json, metrics = invoke_bedrock_gov_doc(msg.documentId, ocr_text, model_id)
            
            # 3. Normalize & Validate
            logger.info("Validating schemas")
            try:
                final_dict = parse_and_normalize(raw_json, msg.documentId, PROMPT_VERSION, model_id)
            except ValueError as ve:
                log_event(
                    "bedrock_schema_violation",
                    documentId=msg.documentId,
                    **safe_error_details(ve),
                )
                # Consider non-retryable since exact same prompt will likely fail again on same OCR.
                update_document_status(
                    table_name=dynamo_table,
                    document_id=msg.documentId,
                    status="GOV_EXTRACT_FAILED",
                    tenant="gov",
                    structured_key="N/A",
                    structured_bucket="N/A",
                    metadata={"error": "Bedrock Schema Violation"}
                )
                return True
                
            # Update metric models dynamically
            final_dict["model"]["usage"] = metrics
            
            # 4. Save Structured Artifact
            save_structured_artifact(structured_bucket, structured_key, final_dict)
            
            # 5. Update DynamoDB
            update_document_status(
                table_name=dynamo_table,
                document_id=msg.documentId,
                status="GOV_EXTRACTED",
                tenant="gov",
                structured_key=structured_key,
                structured_bucket=structured_bucket,
                metadata={
                    "prompt_version": PROMPT_VERSION,
                    "schema_version": "1.0",
                    "modelId": model_id,
                    "metrics": metrics,
                    "attempt": msg.attempt,
                    "textStats": text_stats
                }
            )

        # 6. Forward to Validate Queue
        val_msg = ValidateMessage(
            documentId=msg.documentId,
            structured=S3Location(bucket=structured_bucket, key=structured_key),
            meta=ValidateMeta(
                env=config.env,
                tenant="gov",
                schema_version="1.0",
                prompt_version=PROMPT_VERSION
            ),
            correlationId=meta_env.get("correlationId", msg.correlationId)
        )
        
        out_payload = val_msg.model_dump()
        out_payload["_metadata"] = meta_env
        
        # FIFO queues support
        send_kwargs = {
            "QueueUrl": validate_queue_url,
            "MessageBody": json.dumps(out_payload)
        }
        
        if validate_queue_url.endswith(".fifo"):
            send_kwargs["MessageGroupId"] = msg.documentId
            send_kwargs["MessageDeduplicationId"] = f"{msg.documentId}-gov-extract-v1"
            
        sqs_client.send_message(**send_kwargs)
        
        logger.info("Successfully finished extraction and handed off to validation")
        log_event("enqueued_next_step", documentId=msg.documentId)
        log_event("extract_success", documentId=msg.documentId)
        return True

    except ValidationError as ve:
        # Invalid payload schema, non-retryable
        log_event(
            "poison_message",
            messageId=message_id,
            **safe_error_details(ve),
        )
        return True # Delete poison message
    except json.JSONDecodeError as je:
        log_event(
            "poison_message",
            messageId=message_id,
            **safe_error_details(je),
        )
        return True 
    except Exception as e:
        logger.error("Transient error processing document", extra={"errorType": type(e).__name__})
        # Allow SQS visibility timeout to throw it back
        raise 
