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

def update_document_status(
    table_name: str, 
    document_id: str, 
    status: str, 
    tenant: str, 
    structured_key: str, 
    structured_bucket: str,
    customer_id: str,
    deployment_id: str,
    metadata: Dict[str, Any]
):
    """
    Performs a resilient UpdateExpression on the document item.
    Updates status, adds S3 pointers, and saves stage metadata.
    """
    table = dynamodb_resource.Table(table_name)
    now = datetime.datetime.now(datetime.timezone.utc).isoformat()
    key = build_key(table_name, document_id, tenant)
    
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
    
    metadata = {**metadata, "updatedAt": now}
    
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
                "#m_status IN (:classify_completed, :ocr_completed)"
            ),
            ExpressionAttributeNames=expression_attribute_names,
            ExpressionAttributeValues=expression_attribute_values | {
                ":customer_id": customer_id,
                ":deployment_id": deployment_id,
                ":ownership_version": 1,
                ":processing_domain": tenant,
                ":classify_completed": "CLASSIFY_COMPLETED",
                ":ocr_completed": "OCR_COMPLETED",
            },
            ReturnValues="UPDATED_NEW"
        )
        logger.info("DynamoDB item updated successfully")
        return response
    except ClientError as e:
        logger.error("Failed to update DynamoDB", extra={"errorType": type(e).__name__})
        raise
