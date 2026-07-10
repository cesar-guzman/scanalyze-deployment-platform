import json
import logging
from botocore.exceptions import ClientError
from pydantic import ValidationError

from ..logger import log_event, bind_context, safe_error_details
from ..config import config
from ..contracts import BankExtractMessage, ValidateMessage, S3Location, ValidateMeta
from ..aws import sqs_client
from ..s3 import get_ocr_text, save_structured_artifact
from ..dynamo import update_document_status
from ..bedrock import invoke_bedrock_bank_statement, PROMPT_VERSION
from ..normalize import parse_and_normalize

def chunk_text(text: str, chunk_size: int = 120000):
    """
    Splits text into chunks of at most `chunk_size` characters,
    attempting to break cleanly at newlines if possible.
    """
    if not text:
        return []
        
    chunks = []
    current_chunk = []
    current_length = 0
    
    for line in text.split("\n"):
        line_len = len(line)
        
        # If adding this line exceeds chunk size (accounting for the \n if not first line)
        if current_length + line_len + (1 if current_chunk else 0) > chunk_size:
            if current_chunk:
                chunks.append("\n".join(current_chunk))
                current_chunk = []
                current_length = 0
            
            # If the single line is STILL bigger than chunk_size, hard split it
            if line_len > chunk_size:
                for i in range(0, line_len, chunk_size):
                    part = line[i:i+chunk_size]
                    if i + chunk_size >= line_len:
                        current_chunk = [part]
                        current_length = len(part)
                    else:
                        chunks.append(part)
                continue
                
        current_chunk.append(line)
        current_length += line_len + (1 if len(current_chunk) > 1 else 0)
        
    if current_chunk:
        chunks.append("\n".join(current_chunk))
        
    return chunks

logger = logging.getLogger(__name__)

def is_already_extracted(bucket: str, key: str) -> bool:
    from ..aws import s3_client
    try:
        s3_client.head_object(Bucket=bucket, Key=key)
        return True
    except ClientError as e:
        if e.response['Error']['Code'] == '404':
            return False
        raise

def process_bank_extract_message(body: str, receipt_handle: str, queue_url: str) -> bool:
    """
    Main orchestrator for mapping OCR to Bedrock and uploading Structured output.
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
            tenant="bank",
            stage="bank_extract"
        )
        log_event("extract_started", documentId=document_id)
        
        # Parse against Pydantic model
        msg = BankExtractMessage(**payload)
        
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
            ocr_key = f"bank/{msg.documentId}/ocr.json"
            
        structured_key = f"bank/{msg.documentId}/result.json"
        
        # Idempotency check 
        if is_already_extracted(structured_bucket, structured_key):
            logger.info("Document already extracted; skipping Bedrock")
            log_event("extract_skipped_idempotent", documentId=msg.documentId)
            # Fast-forward to validate queue in case it got dropped there
            # Safely touch the DB status again just in case it wasn't saved last time
            update_document_status(
                table_name=dynamo_table,
                document_id=msg.documentId,
                status="BANK_EXTRACTED",
                tenant="bank",
                structured_key=structured_key,
                structured_bucket=structured_bucket,
                metadata={
                    "cached": True,
                    "attempt": msg.attempt
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
                        status="BANK_EXTRACT_FAILED",
                        tenant="bank",
                        structured_key="N/A",
                        structured_bucket="N/A",
                        metadata={"error": "NoSuchKey"}
                    )
                    return True # Delete poison message
                raise # Bubble up for retry
                
            # 2. Chunk OCR Text & Invoke Bedrock
            # Split OCR text into chunks to respect Bedrock maxTokens limits
            chunk_size = 120000
            chunks = chunk_text(ocr_text, chunk_size)
            if not chunks:
                chunks = [""]
            
            logger.info(f"Splitting OCR text into {len(chunks)} chunks")
            log_event("ocr_chunked", documentId=msg.documentId, chunkCount=len(chunks), charCount=len(ocr_text))

            final_dict = None
            total_metrics = {"inputTokens": 0, "outputTokens": 0, "totalTokens": 0, "latencyMs": 0}
            
            for i, chunk in enumerate(chunks):
                logger.info(f"Invoking Bedrock for chunk {i+1}/{len(chunks)}")
                try:
                    raw_json, metrics = invoke_bedrock_bank_statement(msg.documentId, chunk, model_id)
                except Exception as e:
                    logger.error(
                        "Bedrock invocation failed for chunk",
                        extra={"chunk": i + 1, "errorType": type(e).__name__},
                    )
                    # Allow transient failures on individual chunks if we have others, but for simplicity we bubble up
                    raise
                
                for k in total_metrics:
                    total_metrics[k] += metrics.get(k, 0)
                
                logger.info(f"Validating schemas for chunk {i+1}/{len(chunks)}")
                try:
                    chunk_dict = parse_and_normalize(raw_json, msg.documentId, PROMPT_VERSION, model_id, ocr_char_count=len(ocr_text))
                except ValueError as ve:
                    log_event(
                        "bedrock_schema_violation",
                        documentId=msg.documentId,
                        chunk=i + 1,
                        **safe_error_details(ve),
                    )
                    # Instead of deleting poison message, we just skip the broken chunk to ensure robustness
                    continue
                
                logger.info(f"Chunk {i+1} extracted {len(chunk_dict.get('transactions', []))} transactions")
                log_event("chunk_extracted", documentId=msg.documentId, chunk=i+1, txnCount=len(chunk_dict.get('transactions', [])))

                if final_dict is None:
                    final_dict = chunk_dict
                else:
                    # Merge logic
                    # 1. Transactions — append from subsequent chunks
                    final_dict.setdefault("transactions", []).extend(chunk_dict.get("transactions", []))
                    
                    # 2. Top-level dict objects — fill nulls from later chunks
                    for key in ["bank", "account", "statement", "balances"]:
                        if key in chunk_dict and isinstance(chunk_dict[key], dict):
                            final_dict.setdefault(key, {})
                            for sub_k, sub_v in chunk_dict[key].items():
                                if final_dict[key].get(sub_k) is None and sub_v is not None:
                                    final_dict[key][sub_k] = sub_v

                    # 3. Scalar fields — take first non-null
                    for scalar_key in ["accountType", "bankCountry", "summaryText"]:
                        if final_dict.get(scalar_key) is None and chunk_dict.get(scalar_key) is not None:
                            final_dict[scalar_key] = chunk_dict[scalar_key]

                    # 4. Numeric fields — sum across chunks
                    for num_key in ["interestEarned", "interestCharged"]:
                        chunk_val = chunk_dict.get(num_key)
                        if chunk_val is not None:
                            final_dict[num_key] = (final_dict.get(num_key) or 0) + chunk_val

                    # 5. Fees object — sum sub-fields
                    chunk_fees = chunk_dict.get("fees")
                    if chunk_fees and isinstance(chunk_fees, dict):
                        final_dict.setdefault("fees", {})
                        for fee_key in ["totalFees", "ivaOnFees"]:
                            if chunk_fees.get(fee_key) is not None:
                                final_dict["fees"][fee_key] = (final_dict["fees"].get(fee_key) or 0) + chunk_fees[fee_key]
            
            if final_dict is None:
                logger.error("All chunks failed schema validation")
                log_event("extract_failed_all_chunks", documentId=msg.documentId)
                update_document_status(
                    table_name=dynamo_table,
                    document_id=msg.documentId,
                    status="BANK_EXTRACT_FAILED",
                    tenant="bank",
                    structured_key="N/A",
                    structured_bucket="N/A",
                    metadata={"error": "All chunks failed Bedrock Schema Violation"}
                )
                return True

            # Update metric models dynamically
            final_dict["model"]["usage"] = total_metrics

            # Sort all transactions by date for consistent ordering
            txns = final_dict.get("transactions", [])
            txns.sort(key=lambda t: t.get("date") or "")
            final_dict["transactions"] = txns
            logger.info(f"Total transactions extracted: {len(txns)}")
            log_event("extract_total_transactions", documentId=msg.documentId, txnCount=len(txns))
            
            # 4. Save Structured Artifact
            save_structured_artifact(structured_bucket, structured_key, final_dict)

            conf_val = final_dict.get("overallConfidence")
            if conf_val is not None:
                log_event("bank_confidence_extracted", documentId=msg.documentId, confidence=conf_val)
            
            # 5. Update DynamoDB
            update_document_status(
                table_name=dynamo_table,
                document_id=msg.documentId,
                status="BANK_EXTRACTED",
                tenant="bank",
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
                tenant="bank",
                schema_version="1.0",
                prompt_version=PROMPT_VERSION
            ),
            correlationId=meta_env.get("correlationId", msg.correlationId)
        )
        
        out_payload = val_msg.model_dump()
        out_payload["_metadata"] = meta_env
        
        # Soporte para colas FIFO según mejores prácticas (sin romper)
        send_kwargs = {
            "QueueUrl": validate_queue_url,
            "MessageBody": json.dumps(out_payload)
        }
        
        if validate_queue_url.endswith(".fifo"):
            send_kwargs["MessageGroupId"] = msg.documentId
            # Deduplication id needs to be deterministic to avoid multiple validate events for the same extract result.
            send_kwargs["MessageDeduplicationId"] = f"val-{msg.documentId}-{msg.attempt}"
            
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
