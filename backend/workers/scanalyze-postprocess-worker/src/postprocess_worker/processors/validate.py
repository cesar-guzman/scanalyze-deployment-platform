import datetime
import json

from pydantic import ValidationError as PydanticValidationError

from ..aws import s3_client, sqs_client
from ..config import config
from ..contracts import (
    PersistMessage,
    PersistMeta,
    MessageMetadata,
    ValidateMessage,
    ValidationError,
    ValidationResult,
)
from ..dynamo import require_authorized_document, update_validate_stage
from ..logger import bind_context, log_event, logger, safe_error_details
from ..routing import route_is_allowed, structured_key_for
from ..validators.bank_statement import BankStatementValidator
from ..validators.generic import GenericValidator


EXPECTED_DOC_TYPES = {
    "bank": "bank_statement",
    "personal": "personal_doc",
    "gov": "gov_document",
}


def get_validator(doc_type: str):
    if doc_type == "bank_statement":
        return BankStatementValidator()
    return GenericValidator()


def process_validate_message(body: str, receipt_handle: str, queue_url: str, tenant: str) -> bool:
    del receipt_handle, queue_url

    try:
        msg_data = json.loads(body)
        if not isinstance(msg_data, dict):
            raise ValueError("Message body must be a JSON object")

        meta_env = MessageMetadata.model_validate(
            msg_data.pop("_metadata", {})
        ).model_dump(exclude_none=True)

        msg = ValidateMessage(**msg_data)
        config.require_owner(msg.customer_id, msg.deployment_id)
    except (json.JSONDecodeError, PydanticValidationError, TypeError, ValueError) as error:
        log_event("poison_message", stage="validate", **safe_error_details(error))
        return False

    doc_id = msg.documentId
    route = msg.meta.tenant
    if (
        msg.meta.env != config.env
        or route != msg.processing_domain
        or not route_is_allowed(tenant, route)
    ):
        log_event("message_route_mismatch", stage="validate", document_id=doc_id)
        return False

    bind_context(
        documentId=doc_id,
        correlationId=meta_env.get("correlationId"),
        traceId=meta_env.get("traceId"),
        route=route,
        tenant=route,
        stage="validate",
    )

    log_event(
        "processing_validate",
        stage="validate",
        document_id=doc_id,
        message_id=msg.correlationId,
        tenant=route,
    )

    table_name = config.get(tenant, "data-foundation/documents_table_name")
    expected_bucket = config.get(tenant, "data-foundation/structured_bucket_name")
    expected_key = structured_key_for(
        msg.customer_id, msg.deployment_id, route, doc_id
    )
    bucket = msg.structured.bucket
    key = msg.structured.key

    if not bucket or not key:
        return False
    if bucket != expected_bucket or key != expected_key:
        return False

    try:
        require_authorized_document(
            table_name,
            route,
            doc_id,
            msg.customer_id,
            msg.deployment_id,
            structured_bucket=bucket,
            structured_key=key,
        )
    except Exception as error:
        logger.warning(
            "Rejected document authorization before validation",
            extra={"errorType": type(error).__name__},
        )
        return False

    try:
        response = s3_client.get_object(Bucket=bucket, Key=key)
        payload_bytes = response["Body"].read()
        payload = json.loads(payload_bytes.decode("utf-8"))
    except s3_client.exceptions.NoSuchKey:
        return False
    except (json.JSONDecodeError, UnicodeDecodeError):
        return handle_validation_failure(
            doc_id,
            msg,
            tenant,
            route,
            "INVALID_ARTIFACT",
            "Structured artifact is not valid JSON",
            meta_env,
        )
    except Exception as error:
        logger.warning(
            "Transient error fetching S3",
            extra={"errorType": type(error).__name__},
        )
        return False

    if not isinstance(payload, dict):
        return handle_validation_failure(
            doc_id,
            msg,
            tenant,
            route,
            "INVALID_ARTIFACT",
            "Structured artifact must be a JSON object",
            meta_env,
        )

    if payload.get("schema_version") != msg.meta.schema_version:
        return handle_validation_failure(
            doc_id,
            msg,
            tenant,
            route,
            "SCHEMA_MISMATCH",
            "Structured artifact schema does not match the message contract",
            meta_env,
        )

    expected_doc_type = EXPECTED_DOC_TYPES.get(route)
    if not expected_doc_type or payload.get("docType") != expected_doc_type:
        return handle_validation_failure(
            doc_id,
            msg,
            tenant,
            route,
            "ROUTE_MISMATCH",
            "Structured artifact type does not match the configured route",
            meta_env,
        )

    validator = get_validator(payload["docType"])
    try:
        val_result = validator.validate(doc_id, payload, tenant)
    except Exception as error:
        log_event(
            "validation_exception",
            stage="validate",
            document_id=doc_id,
            tenant=route,
            **safe_error_details(error),
        )
        val_result = ValidationResult(
            status="FAIL",
            errors=[
                ValidationError(
                    code="INTERNAL_VALIDATION_ERROR",
                    message="Internal validation error",
                )
            ],
            validatedAt=datetime.datetime.now(datetime.timezone.utc).isoformat(),
        )

    return finalize_validation(doc_id, tenant, route, msg, val_result, meta_env)


def handle_validation_failure(
    doc_id: str,
    msg: ValidateMessage,
    config_tenant: str,
    route: str,
    code: str,
    reason: str,
    meta_env: dict = None,
) -> bool:
    logger.error("Validation failed closed")
    val_result = ValidationResult(
        status="FAIL",
        errors=[ValidationError(code=code, message=reason)],
        validatedAt=datetime.datetime.now(datetime.timezone.utc).isoformat(),
    )
    return finalize_validation(doc_id, config_tenant, route, msg, val_result, meta_env)


def finalize_validation(
    doc_id: str,
    config_tenant: str,
    route: str,
    msg: ValidateMessage,
    val_result: ValidationResult,
    meta_env: dict = None,
) -> bool:
    meta_env = meta_env or {}
    now = datetime.datetime.now(datetime.timezone.utc).isoformat()
    table_name = config.get(config_tenant, "data-foundation/documents_table_name")

    payload = {
        "validation": val_result.model_dump(),
        "stages_validate": {
            "status": "DONE",
            "validatedAt": val_result.validatedAt,
            "errorsCount": len(val_result.errors),
        },
        "updatedAt": now,
    }

    try:
        stored_validation = update_validate_stage(
            table_name,
            route,
            doc_id,
            msg.customer_id,
            msg.deployment_id,
            payload,
        )
        val_result = ValidationResult(**stored_validation)
    except Exception as error:
        logger.warning(
            "Transient or rejected DynamoDB validate transition",
            extra={"errorType": type(error).__name__},
        )
        return False

    persist_msg = PersistMessage(
        documentId=doc_id,
        customer_id=msg.customer_id,
        deployment_id=msg.deployment_id,
        ownership_schema_version=msg.ownership_schema_version,
        pipeline_stage="persist",
        processing_domain=msg.processing_domain,
        structured=msg.structured,
        validation=val_result,
        meta=PersistMeta(
            env=msg.meta.env,
            tenant=msg.meta.tenant,
            schema_version=msg.meta.schema_version,
            prompt_version=msg.meta.prompt_version,
        ),
        correlationId=msg.correlationId,
        attempt=msg.attempt + 1,
    )

    persist_queue_url = config.get(config_tenant, "queues/persist_url")
    out_dict = persist_msg.model_dump()
    out_dict["_metadata"] = meta_env

    send_kwargs = {
        "QueueUrl": persist_queue_url,
        "MessageBody": json.dumps(out_dict),
    }
    if persist_queue_url.endswith(".fifo"):
        send_kwargs["MessageGroupId"] = doc_id
        send_kwargs["MessageDeduplicationId"] = f"{doc_id}-persist-v1"

    try:
        response = sqs_client.send_message(**send_kwargs)
        if not response.get("MessageId"):
            raise RuntimeError("SQS did not return a message id")
        logger.info("Enqueued persist message")
    except Exception as error:
        logger.warning(
            "Transient SQS error enqueueing persist",
            extra={"errorType": type(error).__name__},
        )
        return False

    log_event(
        "validation_completed",
        stage="validate",
        document_id=doc_id,
        status=val_result.status,
        tenant=route,
    )
    return True
