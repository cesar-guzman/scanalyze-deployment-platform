import logging
import json
import time
from datetime import datetime, timezone

from botocore.exceptions import ClientError

from ..contracts import (
    ClassifyMessage,
    ClassifyMeta,
    ExtractMessage,
    MessageMetadata,
    OcrPollMessage,
    S3Location,
    TextractInfo,
)
from ..config import config
from ..aws import (
    build_key,
    dynamodb_resource,
    extend_visibility,
    s3_client,
    sqs_client,
    textract_client,
)
from ..logger import bind_context, clear_context, log_event, safe_error_details
from ..boundary import authorize_document_boundary, require_poll_checkpoint
from ..routing import get_next_stage
from ..usage import record_usage_metering_with_idempotency

logger = logging.getLogger(__name__)

HANDOFF_CONFIRMED_STATUSES = frozenset({
    "OCR_COMPLETED",
    "CLASSIFY_COMPLETED",
    "BANK_EXTRACTED",
    "PERSONAL_EXTRACTED",
    "GOV_EXTRACTED",
    "COMPLETED",
    "FAILED",
})


def _handoff_is_confirmed(item: dict) -> bool:
    return isinstance(item, dict) and item.get("status") in HANDOFF_CONFIRMED_STATUSES

def process_ocr_poll_message(
    message_body: str,
    receipt_handle: str,
    queue_url: str,
    message_id: str,
    receive_count: int,
) -> bool:
    clear_context()
    logger.info("Processing OCR poll message")
    log_event("processing_ocr_poll")
    try:
        msg_dict = json.loads(message_body)
        poll_msg = OcrPollMessage(**msg_dict)
    except Exception as e:
        log_event("schema_validation_failed", **safe_error_details(e))
        raise ValueError("Invalid message schema")

    meta_env = poll_msg.metadata.model_dump(exclude_none=True)
    bind_context(
        documentId=poll_msg.documentId,
        correlationId=meta_env.get("correlationId"),
        traceId=meta_env.get("traceId"),
        tenant=config.tenant,
        stage="ocr",
    )

    doc_id = poll_msg.documentId
    job_id = poll_msg.textractJobId
    artifact_bucket = poll_msg.artifactBucket
    artifact_key = poll_msg.artifactKey
    raw_bucket = poll_msg.sourceBucket
    raw_key = poll_msg.sourceKey
    submitted_at = poll_msg.submittedAt

    table_name = config.get("data-foundation/documents_table_name")
    table = dynamodb_resource.Table(table_name)
    
    # 1. Verify the authoritative document and OCR job before side effects.
    batch_id = None
    key = build_key(table_name, doc_id, config.tenant)
    try:
        response_ddb = table.get_item(Key=key, ConsistentRead=True)
    except Exception as e:
        logger.warning(
            "Could not verify document before OCR poll",
            extra={"errorType": type(e).__name__},
        )
        raise

    item = response_ddb.get("Item")
    if not isinstance(item, dict) or not item:
        raise RuntimeError("Authoritative document was not found for OCR poll")

    authorized = authorize_document_boundary(
        item=item,
        message_customer_id=poll_msg.customer_id,
        message_deployment_id=poll_msg.deployment_id,
        message_document_id=doc_id,
        message_source_bucket=raw_bucket,
        message_source_key=raw_key,
        runtime_customer_id=config.customer_id,
        runtime_deployment_id=config.deployment_id,
        trusted_source_bucket=config.get("data-foundation/raw_bucket_name"),
        trusted_artifact_bucket=config.get("data-foundation/ocr_bucket_name"),
    )
    if artifact_bucket != authorized.artifact_bucket or artifact_key != authorized.artifact_key:
        raise RuntimeError("OCR poll artifact locator does not match trusted document metadata")
    require_poll_checkpoint(
        authorized,
        textract_job_id=job_id,
        source_bucket=raw_bucket,
        source_key=raw_key,
        artifact_bucket=artifact_bucket,
        artifact_key=artifact_key,
        source_message_id=message_id,
    )

    current_status = item.get("status")
    batch_id = item.get("batchId")
    if item.get("textractJobId") != job_id:
        raise RuntimeError("OCR poll job does not match the authoritative document")

    document_route = authorized.document_route
    if poll_msg.documentRoute != document_route:
        raise RuntimeError("OCR poll route does not match the authoritative document")

    if _handoff_is_confirmed(item):
        logger.info("OCR handoff already confirmed or consumed downstream")
        log_event("ocr_poll_skipped_already_done", documentId=doc_id, message_id=message_id)
        return True

    if current_status != "OCR":
        raise RuntimeError("Document is not in the retryable OCR state")

    # 2. Consultar Textract
    log_event(
        "polling_textract",
        documentId=doc_id,
        jobId=job_id,
        document_route=document_route,
        message_id=message_id,
        receive_count=receive_count,
    )
    try:
        # Obtenemos solo 1 max results para ser rápidos solo preguntando status
        response = textract_client.get_document_text_detection(JobId=job_id, MaxResults=1)
        status = response['JobStatus']
    except Exception as e:
        logger.error("Textract API error", extra={"errorType": type(e).__name__})
        # Si The job is not found or expired, loggear robustamente o mandar a DLQ
        raise

    if status == 'IN_PROGRESS':
        log_event(
            "textract_in_progress",
            documentId=doc_id,
            jobId=job_id,
            document_route=document_route,
            message_id=message_id,
        )
        
        first_enqueued = datetime.fromisoformat(submitted_at) if submitted_at else datetime.now(timezone.utc)
        elapsed_seconds = (datetime.now(timezone.utc) - first_enqueued).total_seconds()
        
        # Deadline de 1 hora
        if elapsed_seconds > 3600:
            logger.error("Polling deadline exceeded; rejecting message for DLQ handling")
            raise ValueError(f"Textract polling deadline exceeded (elapsed {elapsed_seconds}s for {doc_id})")

        # Backoff suave determinístico
        delay_seconds = min(120 + int(elapsed_seconds / 2.0), 900)
        
        next_poll = poll_msg.model_copy(update={"attempt": poll_msg.attempt + 1})
        response = sqs_client.send_message(
            QueueUrl=queue_url,
            MessageBody=next_poll.model_dump_json(by_alias=True, exclude_none=True),
            DelaySeconds=delay_seconds,
        )
        next_message_id = response.get("MessageId")
        if not isinstance(next_message_id, str) or not next_message_id.strip():
            raise RuntimeError("SQS did not acknowledge the next OCR poll message")

        table.update_item(
            Key=key,
            UpdateExpression=(
                "SET ocrPollHandoff.messageId = :next_message_id, "
                "ocrPollHandoff.requeuedAt = :now, "
                "ocrPollHandoff.attempt = :attempt, updatedAt = :now"
            ),
            ConditionExpression=(
                "#status = :ocr AND #textract_job_id = :job_id AND "
                "#customer_id = :customer_id AND #deployment_id = :deployment_id AND "
                "#ownership_schema_version = :ownership_schema_version AND "
                "ocrPollHandoff.messageId = :source_message_id"
            ),
            ExpressionAttributeNames={
                "#status": "status",
                "#textract_job_id": "textractJobId",
                "#customer_id": "customer_id",
                "#deployment_id": "deployment_id",
                "#ownership_schema_version": "ownership_schema_version",
            },
            ExpressionAttributeValues={
                ":ocr": "OCR",
                ":job_id": job_id,
                ":customer_id": authorized.customer_id,
                ":deployment_id": authorized.deployment_id,
                ":ownership_schema_version": 1,
                ":source_message_id": message_id,
                ":next_message_id": next_message_id,
                ":attempt": next_poll.attempt,
                ":now": datetime.now(timezone.utc).isoformat(),
            },
        )
        log_event(
            "ocr_poll_requeued",
            documentId=doc_id,
            delay=delay_seconds,
            document_route=document_route,
            message_id=message_id,
            receive_count=receive_count,
            attempt=next_poll.attempt,
        )

        # Acknowledge the current message only after the replacement and checkpoint
        # are both durable. Each poll therefore receives a fresh native redrive budget.
        return True

    elif status in ['FAILED', 'PARTIAL_SUCCESS']:
        log_event(
            "textract_failed",
            documentId=doc_id,
            jobId=job_id,
            status=status,
            document_route=document_route,
            message_id=message_id,
        )
        key = build_key(table_name, doc_id, config.tenant)
        table.update_item(
            Key=key,
            UpdateExpression="SET #s = :s, updatedAt = :now",
            ConditionExpression=(
                "#s = :old_status AND #customer_id = :customer_id AND "
                "#deployment_id = :deployment_id AND "
                "#ownership_schema_version = :ownership_schema_version"
            ),
            ExpressionAttributeNames={
                '#s': 'status',
                '#customer_id': 'customer_id',
                '#deployment_id': 'deployment_id',
                '#ownership_schema_version': 'ownership_schema_version',
            },
            ExpressionAttributeValues={
                ':s': 'OCR_FAILED',
                ':old_status': 'OCR',
                ':now': datetime.now(timezone.utc).isoformat(),
                ':customer_id': authorized.customer_id,
                ':deployment_id': authorized.deployment_id,
                ':ownership_schema_version': 1,
            }
        )
        return True # Marcar estado y matar mensaje. Alternativa: Encolar classify con error.

    elif status == 'SUCCEEDED':
        log_event(
            "textract_succeeded",
            documentId=doc_id,
            jobId=job_id,
            document_route=document_route,
            message_id=message_id,
        )
        
        # 3. Descargar OCR paginadamente
        pages = response.get('DocumentMetadata', {}).get('Pages', 1)
        all_blocks = []
        
        next_token = response.get('NextToken')
        all_blocks.extend(response.get('Blocks', []))
        
        # Si la paginación es muy larga, el mensaje podría volver a ser visible
        # Por seguridad extendemos la visibilidad inicial
        extend_visibility(queue_url, receipt_handle, 120)

        while next_token:
            # heartbeat
            extend_visibility(queue_url, receipt_handle, 60)
            
            resp = textract_client.get_document_text_detection(JobId=job_id, NextToken=next_token)
            all_blocks.extend(resp.get('Blocks', []))
            next_token = resp.get('NextToken')
            time.sleep(0.1) 

        # 4. Guardar Artifact en S3
        log_event(
            "writing_s3_artifact",
            documentId=doc_id,
            document_route=document_route,
            message_id=message_id,
        )
        
        full_result = {
            "documentId": doc_id,
            "jobId": job_id,
            "blocks": all_blocks
        }
        
        s3_client.put_object(
            Bucket=artifact_bucket,
            Key=artifact_key,
            Body=json.dumps(full_result),
            ContentType="application/json"
        )
        log_event(
            "s3_artifact_written",
            documentId=doc_id,
            document_route=document_route,
            state="OCR_COMPLETED",
            textractJobId=job_id,
        )

        # Determine targeting using the central router
        next_stage = get_next_stage(document_route)
        env = config.env
        
        # Get queue URL dynamically
        target_queue_url = config.get(f"queues/{next_stage}_url")
                
        now_iso = datetime.now(timezone.utc).isoformat()

        import boto3
        s_dynamo_client = boto3.client("dynamodb")
        record_usage_metering_with_idempotency(
            dynamodb_client=s_dynamo_client,
            tenant=config.tenant,
            doc_id=doc_id,
            pages=pages,
            uploader_user_id="",
            batch_id=batch_id,
            doc_type=""
        )

        # 5. Construir el mensaje para la cola correcta
        if next_stage == "classify":
            out_msg_obj = ClassifyMessage(
                schemaVersion="scanalyze.classify.v2",
                customer_id=authorized.customer_id,
                deployment_id=authorized.deployment_id,
                ownership_schema_version=1,
                pipeline_stage="classify",
                documentId=doc_id,
                ocr=S3Location(bucket=artifact_bucket, key=artifact_key),
                raw=S3Location(bucket=raw_bucket, key=raw_key),
                textract=TextractInfo(jobId=job_id),
                meta=ClassifyMeta(
                    pages=pages,
                    env=env,
                    tenant=document_route
                ),
                metadata=MessageMetadata(**meta_env),
            )
            out_dict = out_msg_obj.model_dump(by_alias=True, exclude_none=True)
            out_msg = json.dumps(out_dict)
        else:
            processing_domain = next_stage.removesuffix("-extract")
            out_msg_obj = ExtractMessage(
                customer_id=authorized.customer_id,
                deployment_id=authorized.deployment_id,
                ownership_schema_version=1,
                pipeline_stage=next_stage,
                processing_domain=processing_domain,
                documentId=doc_id,
                ocr=S3Location(bucket=artifact_bucket, key=artifact_key),
                raw=S3Location(bucket=raw_bucket, key=raw_key),
                correlationId=meta_env.get("correlationId"),
                attempt=0,
                metadata=MessageMetadata(**meta_env),
            )
            out_msg = out_msg_obj.model_dump_json(by_alias=True, exclude_none=True)

        send_kwargs = {
            'QueueUrl': target_queue_url,
            'MessageBody': out_msg
        }
        if target_queue_url.endswith('.fifo'):
            send_kwargs['MessageGroupId'] = doc_id
            send_kwargs['MessageDeduplicationId'] = f"{doc_id}-{next_stage}"

        # 6. Publicar y verificar el handoff antes de marcar OCR como completado.
        # Si SQS falla o no confirma MessageId, la excepción deja el mensaje
        # original sin borrar y el estado OCR permanece disponible para retry.
        try:
            handoff_response = sqs_client.send_message(**send_kwargs)
        except Exception as e:
            logger.error("Failed to enqueue OCR handoff", extra={"errorType": type(e).__name__})
            log_event(
                "ocr_handoff_failed",
                documentId=doc_id,
                next_stage=next_stage,
                document_route=document_route,
                message_id=message_id,
                errorType=type(e).__name__,
            )
            raise

        downstream_message_id = (
            handoff_response.get("MessageId")
            if isinstance(handoff_response, dict)
            else None
        )
        if not downstream_message_id:
            log_event(
                "ocr_handoff_failed",
                documentId=doc_id,
                next_stage=next_stage,
                document_route=document_route,
                message_id=message_id,
                reason="missing_message_id",
            )
            raise RuntimeError("Downstream OCR handoff was not acknowledged by SQS")

        log_event("ocr_handoff_enqueued", 
                  documentId=doc_id, 
                  textractJobId=job_id,
                  document_route=document_route,
                  next_stage=next_stage,
                  queue_name=next_stage,
                  state="HANDOFF_ENQUEUED",
                  downstream_message_id=downstream_message_id,
                  message_id=message_id,
                  receive_count=receive_count)

        # 7. Persistir estado final sólo después del handoff confirmado.
        try:
            table.update_item(
                Key=key,
                UpdateExpression="""SET #s = :s, 
                                        ocrArtifactKey = :ok, 
                                        ocrSucceededAt = :now, 
                                        pagesScanned = :pages,
                                        pagesScannedSource = :pagesSource,
                                        updatedAt = :now, 
                                        #artifacts.#ocrStr = :ocrArtifact,
                                        #stages.#ns = :stageData,
                                        #stages.#ocrStr = :ocrStageDict""",
                ConditionExpression=(
                    "#s = :old AND #textract_job_id = :job_id AND "
                    "#customer_id = :customer_id AND #deployment_id = :deployment_id AND "
                    "#ownership_schema_version = :ownership_schema_version"
                ),
                ExpressionAttributeNames={
                    '#s': 'status',
                    '#textract_job_id': 'textractJobId',
                    '#stages': 'stages',
                    '#ns': next_stage,
                    '#artifacts': 'artifacts',
                    '#ocrStr': 'ocr',
                    '#customer_id': 'customer_id',
                    '#deployment_id': 'deployment_id',
                    '#ownership_schema_version': 'ownership_schema_version',
                },
                ExpressionAttributeValues={
                    ':s': 'OCR_COMPLETED',
                    ':old': 'OCR',
                    ':job_id': job_id,
                    ':customer_id': authorized.customer_id,
                    ':deployment_id': authorized.deployment_id,
                    ':ownership_schema_version': 1,
                    ':ok': artifact_key,
                    ':now': now_iso,
                    ':pages': pages,
                    ':pagesSource': 'textract',
                    ':ocrArtifact': {
                        'bucket': artifact_bucket,
                        'key': artifact_key
                    },
                    ':stageData': {
                        'status': 'ENQUEUED',
                        'queueUrl': target_queue_url,
                        'messageId': downstream_message_id,
                        'enqueuedAt': now_iso
                    },
                    ':ocrStageDict': {
                        'status': 'COMPLETED',
                        'startedAt': poll_msg.submittedAt,
                        'endedAt': now_iso,
                        'message': 'Textract extracted text successfully'
                    }
                }
            )
        except ClientError as e:
            if e.response.get("Error", {}).get("Code") == "ConditionalCheckFailedException":
                latest = table.get_item(Key=key, ConsistentRead=True).get("Item")
                if _handoff_is_confirmed(latest):
                    log_event(
                        "ocr_handoff_already_consumed",
                        documentId=doc_id,
                        next_stage=next_stage,
                        message_id=message_id,
                    )
                    return True
            logger.error("Failed to update DDB status and stages", extra={"errorType": type(e).__name__})
            raise
        except Exception as e:
            logger.error("Failed to update DDB status and stages", extra={"errorType": type(e).__name__})
            raise
        log_event(
            "ddb_state_updated",
            documentId=doc_id,
            state="OCR_COMPLETED",
            next_stage=next_stage,
            document_route=document_route,
            message_id=message_id,
        )

        return True
    
    return False
