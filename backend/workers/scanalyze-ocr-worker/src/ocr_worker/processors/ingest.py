import logging
import json
from datetime import datetime, timezone

from ..contracts import IngestMessage, OcrPollMessage
from ..config import config
from ..aws import textract_client, dynamodb_resource, sqs_client, build_key
from ..logger import log_event, bind_context, safe_error_details
from ..storage import build_ocr_artifact_key

logger = logging.getLogger(__name__)

def process_ingest_message(message_body: str, receipt_handle: str, message_id: str, receive_count: int) -> bool:
    """
    Procesa mensaje de INGEST.
    Retorna True si procesado correctamente (para borrar mensaje), False en caso de error transitorio.
    Lanza ValueError si el mensaje es poison (no debe ser re-encolado).
    """
    logger.info("Processing ingest message")
    log_event("processing_ingest", message_id=message_id, receive_count=receive_count)
    try:
        msg_dict = json.loads(message_body)
        
        meta_env = msg_dict.get("_metadata", {})
        bind_context(
            documentId=msg_dict.get("documentId"),
            correlationId=meta_env.get("correlationId"),
            traceId=meta_env.get("traceId"),
            uploaderUserId=meta_env.get("uploaderUserId"),
            customerStack=meta_env.get("customerStack"),
            route=meta_env.get("route"),
            tenant="ocr",
            stage="ocr_ingest"
        )
        
        ingest_msg = IngestMessage(**msg_dict)
    except Exception as e:
        log_event("schema_validation_failed", **safe_error_details(e))
        raise ValueError("Invalid message schema")

    # Resolver bucket y key (fallback a SSM si no viene)
    raw_info = ingest_msg.raw or ingest_msg.s3
    if not raw_info or not raw_info.key:
        logger.error("Missing raw key in message")
        raise ValueError("Raw object key is mandatory")
        
    raw_bucket = raw_info.bucket or config.get("data-foundation/raw_bucket_name")
    raw_key = raw_info.key
    doc_id = ingest_msg.documentId

    # 1. Idempotency Check en DynamoDB
    table_name = config.get("data-foundation/documents_table_name")
    table = dynamodb_resource.Table(table_name)
    
    try:
        key = build_key(table_name, doc_id, config.tenant)
        response = table.get_item(Key=key)
        item = response.get('Item', {})
        current_status = item.get('status')
        service_tenant = item.get('tenantId', config.tenant)
        document_route = item.get('documentRoute') or service_tenant

        if current_status in ['OCR', 'OCR_COMPLETED']:
            logger.info(f"Document is already in state {current_status}; skipping Textract start")
            log_event("textract_skipped_already_exists", documentId=doc_id, status=current_status, message_id=message_id)
            return True
    except Exception as e:
        logger.warning(
            "Could not fetch item from DDB; proceeding",
            extra={"errorType": type(e).__name__},
        )
        service_tenant = config.tenant
        document_route = config.tenant

    # Fetch targeted artifact bucket & key early
    env = config.env
    if service_tenant == config.tenant:
        artifact_bucket = config.get("data-foundation/ocr_bucket_name")
    else:
        param_name = f"/scanalyze/{env}/tenants/{service_tenant}/data-foundation/ocr_bucket_name"
        try:
            ssm_resp = config.ssm_client.get_parameter(Name=param_name, WithDecryption=True)
            artifact_bucket = ssm_resp['Parameter']['Value']
        except Exception as e:
            logger.error("Failed to resolve OCR bucket", extra={"errorType": type(e).__name__})
            raise

    artifact_key = build_ocr_artifact_key(document_route, doc_id)

    # 2. Start Textract Job Async
    # ClientRequestToken se usa para hacer la llamada idempotente a Textract
    log_event("starting_textract", documentId=doc_id, service_tenant=service_tenant, document_route=document_route, message_id=message_id, receive_count=receive_count)
    try:
        response = textract_client.start_document_text_detection(
            DocumentLocation={
                'S3Object': {
                    'Bucket': raw_bucket,
                    'Name': raw_key
                }
            },
            ClientRequestToken=doc_id[:64] # Máximo 64 caracteres
        )
        job_id = response['JobId']
    except textract_client.exceptions.InvalidS3ObjectException as e:
        logger.error("Textract cannot access object", extra={"errorType": type(e).__name__})
        # Could be transient S3 eventual consistency or permanent error.
        # Bubble up to SQS re-queue. SQS will retry later.
        raise
    except Exception as e:
        logger.error("Failed to start Textract", extra={"errorType": type(e).__name__})
        raise

    log_event("textract_started", documentId=doc_id, jobId=job_id, service_tenant=service_tenant, document_route=document_route, message_id=message_id)

    # 3. Guardar estado transicional en DynamoDB UPLOADED -> OCR
    try:
        key = build_key(table_name, doc_id, config.tenant)
        now_iso = datetime.now(timezone.utc).isoformat()
        table.update_item(
            Key=key,
            UpdateExpression="SET #s = :new_status, textractJobId = :tj, updatedAt = :now, #input.#bucket = :rb, #input.#key = :rk, #stages.#ocr = :ocrStage",
            ConditionExpression="attribute_not_exists(#s) OR #s = :old_status",
            ExpressionAttributeNames={
                '#s': 'status',
                '#stages': 'stages',
                '#ocr': 'ocr',
                '#key': 'key',
                '#input': 'input',
                '#bucket': 'bucket'
            },
            ExpressionAttributeValues={
                ':new_status': 'OCR',
                ':old_status': 'SUBMITTED',
                ':rb': raw_bucket,
                ':rk': raw_key,
                ':tj': job_id,
                ':now': now_iso,
                ':ocrStage': {
                    'status': 'IN_PROGRESS',
                    'startedAt': now_iso,
                    'message': 'Textract processing started'
                }
            }
        )
        log_event("ddb_state_updated", documentId=doc_id, state="OCR", service_tenant=service_tenant, document_route=document_route, message_id=message_id)
    except dynamodb_resource.meta.client.exceptions.ConditionalCheckFailedException:
        logger.warning("Conditional check failed; another processor might be handling this document")
        # Se ignora, porque lo más probable es que alguien más lo esté procesando o ya lo procesó.
        # Acusamos recibo del mensaje SQS para borrarlo.
    except Exception as e:
        logger.error(
            "DynamoDB update failed after Textract started",
            extra={"errorType": type(e).__name__},
        )
        # Bubble up to SQS re-queue. The Textract job will continue safely because we used ClientRequestToken
        raise

    # 4. Encolar en la cola de OCR Poll
    ocr_queue_url = config.get("queues/ocr_url")
    now_iso = datetime.now(timezone.utc).isoformat()
    
    poll_msg = OcrPollMessage(
        documentId=doc_id,
        textractJobId=job_id,
        sourceBucket=raw_bucket,
        sourceKey=raw_key,
        serviceTenant=service_tenant,
        documentRoute=document_route,
        artifactBucket=artifact_bucket,
        artifactKey=artifact_key,
        submittedAt=ingest_msg.uploadedAt or now_iso,
        attempt=0
    )
    
    poll_msg_dict = poll_msg.model_dump()
    poll_msg_dict["_metadata"] = meta_env

    # Podríamos usar MessageGroupId si es FIFO.
    # Dado que "termina en .fifo" es una convención, lo manejamos:
    send_kwargs = {
        'QueueUrl': ocr_queue_url,
        'MessageBody': json.dumps(poll_msg_dict)
    }
    if ocr_queue_url.endswith('.fifo'):
        send_kwargs['MessageGroupId'] = doc_id
        send_kwargs['MessageDeduplicationId'] = f"{doc_id}-{job_id}" # Simple dedup

    sqs_client.send_message(**send_kwargs)
    
    log_event("enqueued_ocr_poll", 
              documentId=doc_id, 
              jobId=job_id, 
              service_tenant=service_tenant, 
              document_route=document_route, 
              queue_name="OCR",
              message_id=message_id,
              receive_count=receive_count)
    return True
