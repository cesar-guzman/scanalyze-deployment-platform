import datetime
import logging
from botocore.exceptions import ClientError
from typing import Dict, Any, Optional
from .aws import dynamodb_resource, build_key

logger = logging.getLogger(__name__)


def require_authorized_document(
    table_name: str,
    document_id: str,
    tenant: str,
    customer_id: str,
    deployment_id: str,
    raw_bucket: str,
    raw_key: str,
    ocr_bucket: str,
    ocr_key: str,
):
    table = dynamodb_resource.Table(table_name)
    key = build_key(table_name, document_id, tenant)
    response = table.get_item(Key=key, ConsistentRead=True)
    item = response.get("Item")
    if not isinstance(item, dict):
        raise ValueError("Document is unavailable")
    stored_raw = item.get("input") or {}
    stored_ocr = (item.get("artifacts") or {}).get("ocr") or {}
    if (
        item.get("customer_id") != customer_id
        or item.get("deployment_id") != deployment_id
        or item.get("ownership_schema_version") != 1
        or item.get("processing_domain") != tenant
        or stored_raw.get("bucket") != raw_bucket
        or stored_raw.get("key") != raw_key
        or stored_ocr.get("bucket") != ocr_bucket
        or stored_ocr.get("key") != ocr_key
    ):
        raise ValueError("Document is unavailable")
    return item


def build_artifact_binding(
    *,
    structured_bucket: str,
    structured_key: str,
    customer_id: str,
    deployment_id: str,
    document_id: str,
    tenant: str,
    checkpoint_id: str,
    writer: str,
    artifact_schema_version: str,
    content_sha256: str | None = None,
) -> Dict[str, Any]:
    binding = {
        "bucket": structured_bucket,
        "key": structured_key,
        "customer_id": customer_id,
        "deployment_id": deployment_id,
        "document_id": document_id,
        "processing_domain": tenant,
        "ownership_schema_version": 1,
        "pipeline_stage": f"{tenant}-extract",
        "writer": writer,
        "artifact_schema_version": artifact_schema_version,
        "checkpoint_id": checkpoint_id,
    }
    if content_sha256 is not None:
        binding["content_sha256"] = content_sha256
    return binding


def reserve_structured_artifact(
    table_name: str,
    document_id: str,
    tenant: str,
    structured_key: str,
    structured_bucket: str,
    customer_id: str,
    deployment_id: str,
    checkpoint_id: str,
    writer: str,
    artifact_schema_version: str,
):
    """Create the owner-bound write intent that must precede an S3 put."""
    table = dynamodb_resource.Table(table_name)
    now = datetime.datetime.now(datetime.timezone.utc).isoformat()
    key = build_key(table_name, document_id, tenant)
    reservation = {
        "status": "WRITING",
        "artifact": build_artifact_binding(
            structured_bucket=structured_bucket,
            structured_key=structured_key,
            customer_id=customer_id,
            deployment_id=deployment_id,
            document_id=document_id,
            tenant=tenant,
            checkpoint_id=checkpoint_id,
            writer=writer,
            artifact_schema_version=artifact_schema_version,
        ),
    }
    return table.update_item(
        Key=key,
        UpdateExpression=(
            "SET #m_status = :writing_status, updatedAt = :now, "
            "#stages.#stage_name = :reservation"
        ),
        ConditionExpression=(
            "attribute_exists(#pk) AND #customer_id = :customer_id AND "
            "#deployment_id = :deployment_id AND #ownership_version = :ownership_version AND "
            "#processing_domain = :processing_domain AND "
            "#m_status IN (:classify_completed, :ocr_completed) AND "
            "attribute_not_exists(#artifacts.#structured) AND "
            "attribute_not_exists(#stages.#stage_name)"
        ),
        ExpressionAttributeNames={
            "#m_status": "status",
            "#artifacts": "artifacts",
            "#structured": "structured",
            "#stages": "stages",
            "#stage_name": f"{tenant}_extract",
            "#pk": next(iter(key)),
            "#customer_id": "customer_id",
            "#deployment_id": "deployment_id",
            "#ownership_version": "ownership_schema_version",
            "#processing_domain": "processing_domain",
        },
        ExpressionAttributeValues={
            ":writing_status": f"{tenant.upper()}_EXTRACTING",
            ":now": now,
            ":reservation": reservation,
            ":customer_id": customer_id,
            ":deployment_id": deployment_id,
            ":ownership_version": 1,
            ":processing_domain": tenant,
            ":classify_completed": "CLASSIFY_COMPLETED",
            ":ocr_completed": "OCR_COMPLETED",
        },
        ReturnValues="UPDATED_NEW",
    )


def update_document_status(
    table_name: str, 
    document_id: str, 
    status: str, 
    tenant: str, 
    structured_key: str, 
    structured_bucket: str,
    customer_id: str,
    deployment_id: str,
    metadata: Dict[str, Any],
    checkpoint_id: str,
    content_sha256: str,
    writer: str,
    artifact_schema_version: str,
):
    """
    Performs a resilient UpdateExpression on the document item.
    Updates status, adds S3 pointers, and saves stage metadata.
    """
    table = dynamodb_resource.Table(table_name)
    now = datetime.datetime.now(datetime.timezone.utc).isoformat()
    key = build_key(table_name, document_id, tenant)
    
    expected_status = f"{tenant.upper()}_EXTRACTED"
    if status != expected_status:
        raise ValueError("Invalid extraction status transition")

    update_expression = "SET #m_status = :status, " \
                        "updatedAt = :now, " \
                        "#artifacts.#structured = :structured_map, " \
                        "#stages.#stage_name = :extract_metadata"
                        
    expression_attribute_names = {
        "#m_status": "status",
        "#artifacts": "artifacts",
        "#structured": "structured",
        "#stages": "stages",
        "#stage_name": f"{tenant}_extract",
        "#pk": next(iter(key)),
        "#customer_id": "customer_id",
        "#deployment_id": "deployment_id",
        "#ownership_version": "ownership_schema_version",
        "#processing_domain": "processing_domain",
    }
    
    reservation = {
        "status": "WRITING",
        "artifact": build_artifact_binding(
            structured_bucket=structured_bucket,
            structured_key=structured_key,
            customer_id=customer_id,
            deployment_id=deployment_id,
            document_id=document_id,
            tenant=tenant,
            checkpoint_id=checkpoint_id,
            writer=writer,
            artifact_schema_version=artifact_schema_version,
        ),
    }
    artifact_binding = build_artifact_binding(
        structured_bucket=structured_bucket,
        structured_key=structured_key,
        customer_id=customer_id,
        deployment_id=deployment_id,
        document_id=document_id,
        tenant=tenant,
        checkpoint_id=checkpoint_id,
        writer=writer,
        artifact_schema_version=artifact_schema_version,
        content_sha256=content_sha256,
    )
    metadata = {
        **metadata,
        "status": "COMPLETED",
        "artifact": artifact_binding,
        "updatedAt": now,
    }
    
    expression_attribute_values = {
        ":status": status,
        ":now": now,
        ":structured_map": {
            "bucket": structured_bucket,
            "key": structured_key
        },
        ":extract_metadata": metadata
    }
    
    try:
        response = table.update_item(
            Key=key,
            UpdateExpression=update_expression,
            ConditionExpression=(
                "attribute_exists(#pk) AND #customer_id = :customer_id AND "
                "#deployment_id = :deployment_id AND #ownership_version = :ownership_version AND "
                "#processing_domain = :processing_domain AND "
                "#m_status = :writing_status AND #stages.#stage_name = :reservation"
            ),
            ExpressionAttributeNames=expression_attribute_names,
            ExpressionAttributeValues=expression_attribute_values | {
                ":customer_id": customer_id,
                ":deployment_id": deployment_id,
                ":ownership_version": 1,
                ":processing_domain": tenant,
                ":writing_status": f"{tenant.upper()}_EXTRACTING",
                ":reservation": reservation,
            },
            ReturnValues="UPDATED_NEW"
        )
        logger.info("DynamoDB item updated successfully")
        return response
    except ClientError as e:
        logger.error("Failed to update DynamoDB", extra={"errorType": type(e).__name__})
        raise
