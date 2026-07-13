import json
import logging
from botocore.exceptions import ClientError
from pydantic import ValidationError

from ..logger import log_event, bind_context, safe_error_details
from ..config import config
from ..contracts import BankExtractMessage, ValidateMessage, S3Location, ValidateMeta
from ..aws import sqs_client
from ..s3 import get_ocr_text, save_structured_artifact
from ..dynamo import require_authorized_document, update_document_status
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


class MetadataValidationError(ValueError):
    """Raised when non-authoritative message metadata violates its closed contract."""

def is_already_extracted(bucket: str, key: str) -> bool:
    from ..aws import s3_client
    try:
        s3_client.head_object(Bucket=bucket, Key=key)
        return True
    except ClientError as e:
        if e.response['Error']['Code'] == '404':
            return False
        raise


def _safe_metadata(value: object) -> dict[str, str]:
    if not isinstance(value, dict):
        raise MetadataValidationError("Message metadata must be an object")
    allowed = {"correlationId", "traceId"}
    if set(value) - allowed:
        raise MetadataValidationError("Message metadata contains unsupported fields")
    result = {}
    for key, item in value.items():
        if not isinstance(item, str) or not 0 < len(item) <= 128:
            raise MetadataValidationError("Message metadata is invalid")
        result[key] = item
    return result

def process_bank_extract_message(body: str, receipt_handle: str, queue_url: str) -> bool:
    """
    Main orchestrator for mapping OCR to Bedrock and uploading Structured output.
    Return True only after the ownership-bound validate handoff is acknowledged.
    Invalid messages return False; transient and authorization errors raise for retry/DLQ.
    """
    try:
        payload = json.loads(body)
        if not isinstance(payload, dict):
            return False
        meta_env = _safe_metadata(payload.pop("_metadata", {}))
        msg = BankExtractMessage(**payload)
        config.require_owner(msg.customer_id, msg.deployment_id)

        bind_context(
            documentId=msg.documentId,
            correlationId=meta_env.get("correlationId"),
            traceId=meta_env.get("traceId"),
            tenant="bank",
            stage="bank_extract"
        )
        log_event("extract_started", documentId=msg.documentId)

        ocr_bucket = msg.ocr.bucket
        ocr_key = msg.ocr.key
        structured_bucket = config.get("data-foundation/structured_bucket_name")
        dynamo_table = config.get("data-foundation/documents_table_name")
        validate_queue_url = config.get("queues/validate_url")
        model_id = config.get("BEDROCK_MODEL_ID", default="anthropic.claude-3-haiku-20240307-v1:0")

        structured_key = (
            f"customers/{msg.customer_id}/deployments/{msg.deployment_id}/"
            f"documents/{msg.documentId}/structured/bank/result.json"
        )

        document_item = require_authorized_document(
            table_name=dynamo_table,
            document_id=msg.documentId,
            tenant="bank",
            customer_id=msg.customer_id,
            deployment_id=msg.deployment_id,
            raw_bucket=msg.raw.bucket,
            raw_key=msg.raw.key,
            ocr_bucket=ocr_bucket,
            ocr_key=ocr_key,
        )

        stored_structured = (document_item.get("artifacts") or {}).get("structured") or {}
        document_status = document_item.get("status")
        if document_status in {"COMPLETED", "FAILED"}:
            if stored_structured != {"bucket": structured_bucket, "key": structured_key}:
                raise RuntimeError("Terminal document has no authorized structured artifact")
            return True

        artifact_exists = is_already_extracted(structured_bucket, structured_key)
        if artifact_exists:
            if stored_structured != {"bucket": structured_bucket, "key": structured_key}:
                raise RuntimeError("Existing structured artifact is not authorized")
            if document_status != "BANK_EXTRACTED":
                raise RuntimeError("Existing structured artifact has no durable stage checkpoint")
            logger.info("Document already extracted; skipping Bedrock")
            log_event("extract_skipped_idempotent", documentId=msg.documentId)
        else:
            if document_status not in {"CLASSIFY_COMPLETED", "OCR_COMPLETED"}:
                raise RuntimeError("Document is not ready for bank extraction")
            ocr_text, text_stats = get_ocr_text(ocr_bucket, ocr_key)
            chunks = chunk_text(ocr_text, 120000) or [""]
            
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
                log_event("extract_failed_all_chunks", documentId=msg.documentId)
                raise ValueError("Bank extraction result failed schema validation")

            # Update metric models dynamically
            final_dict["model"]["usage"] = total_metrics

            # Sort all transactions by date for consistent ordering
            txns = final_dict.get("transactions", [])
            txns.sort(key=lambda t: t.get("date") or "")
            final_dict["transactions"] = txns
            logger.info(f"Total transactions extracted: {len(txns)}")
            log_event("extract_total_transactions", documentId=msg.documentId, txnCount=len(txns))
            
            # 4. Save Structured Artifact
            artifact_created = save_structured_artifact(
                structured_bucket, structured_key, final_dict
            )

            conf_val = final_dict.get("overallConfidence")
            if conf_val is not None:
                log_event("bank_confidence_extracted", documentId=msg.documentId, confidence=conf_val)
            
            # 5. Update DynamoDB only for the writer that created the artifact.
            if artifact_created:
                update_document_status(
                    table_name=dynamo_table,
                    document_id=msg.documentId,
                    status="BANK_EXTRACTED",
                    tenant="bank",
                    structured_key=structured_key,
                    structured_bucket=structured_bucket,
                    customer_id=msg.customer_id,
                    deployment_id=msg.deployment_id,
                    metadata={
                        "prompt_version": PROMPT_VERSION,
                        "schema_version": "1.0",
                        "modelId": model_id,
                        "metrics": total_metrics,
                        "attempt": msg.attempt,
                        "textStats": text_stats
                    }
                )
            else:
                latest = require_authorized_document(
                    table_name=dynamo_table,
                    document_id=msg.documentId,
                    tenant="bank",
                    customer_id=msg.customer_id,
                    deployment_id=msg.deployment_id,
                    raw_bucket=msg.raw.bucket,
                    raw_key=msg.raw.key,
                    ocr_bucket=ocr_bucket,
                    ocr_key=ocr_key,
                )
                latest_structured = (
                    (latest.get("artifacts") or {}).get("structured") or {}
                )
                latest_status = latest.get("status")
                if latest_structured != {
                    "bucket": structured_bucket,
                    "key": structured_key,
                } or latest_status not in {"BANK_EXTRACTED", "COMPLETED", "FAILED"}:
                    raise RuntimeError(
                        "Structured artifact collision has no authorized checkpoint"
                    )
                if latest_status in {"COMPLETED", "FAILED"}:
                    return True
                log_event(
                    "extract_collision_reconciled",
                    documentId=msg.documentId,
                )

        # 6. Forward to Validate Queue
        val_msg = ValidateMessage(
            documentId=msg.documentId,
            customer_id=msg.customer_id,
            deployment_id=msg.deployment_id,
            ownership_schema_version=msg.ownership_schema_version,
            pipeline_stage="validate",
            processing_domain="bank",
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
        if meta_env:
            out_payload["_metadata"] = meta_env
        
        # Soporte para colas FIFO según mejores prácticas (sin romper)
        send_kwargs = {
            "QueueUrl": validate_queue_url,
            "MessageBody": json.dumps(out_payload)
        }
        
        if validate_queue_url.endswith(".fifo"):
            send_kwargs["MessageGroupId"] = f"{msg.deployment_id}:{msg.documentId}"
            send_kwargs["MessageDeduplicationId"] = (
                f"val-v2-{msg.deployment_id}-{msg.documentId}-{msg.attempt}"
            )
            
        response = sqs_client.send_message(**send_kwargs)
        if not isinstance(response.get("MessageId"), str) or not response["MessageId"].strip():
            raise RuntimeError("Validate queue did not acknowledge the handoff")
        
        logger.info("Successfully finished extraction and handed off to validation")
        log_event("enqueued_next_step", documentId=msg.documentId)
        log_event("extract_success", documentId=msg.documentId)
        return True

    except (ValidationError, MetadataValidationError) as ve:
        log_event(
            "poison_message",
            **safe_error_details(ve),
        )
        return False
    except json.JSONDecodeError as je:
        log_event(
            "poison_message",
            **safe_error_details(je),
        )
        return False
    except Exception as e:
        logger.error("Transient error processing document", extra={"errorType": type(e).__name__})
        # Allow SQS visibility timeout to throw it back
        raise 
