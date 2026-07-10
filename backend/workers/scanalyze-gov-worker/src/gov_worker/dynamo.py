import datetime
import logging
from botocore.exceptions import ClientError
from typing import Dict, Any, Optional
from .aws import dynamodb_resource, build_key

logger = logging.getLogger(__name__)

def update_document_status(
    table_name: str, 
    document_id: str, 
    status: str, 
    tenant: str, 
    structured_key: str, 
    structured_bucket: str,
    metadata: Dict[str, Any]
):
    """
    Performs a resilient UpdateExpression on the document item.
    Updates status, adds S3 pointers, and saves stage metadata.
    """
    table = dynamodb_resource.Table(table_name)
    now = datetime.datetime.now(datetime.timezone.utc).isoformat()
    
    update_expression = "SET #m_status = :status, " \
                        "updatedAt = :now, " \
                        "#artifacts.#structured = :structured_map, " \
                        "#stages.#stage_name = :extract_metadata"
                        
    expression_attribute_names = {
        "#m_status": "status",
        "#artifacts": "artifacts",
        "#structured": "structured",
        "#stages": "stages",
        "#stage_name": f"{tenant}_extract"
    }
    
    metadata["updatedAt"] = now
    
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
        key = build_key(table_name, document_id, tenant)
        response = table.update_item(
            Key=key,
            UpdateExpression=update_expression,
            ExpressionAttributeNames=expression_attribute_names,
            ExpressionAttributeValues=expression_attribute_values,
            ReturnValues="UPDATED_NEW"
        )
        logger.info("DynamoDB item updated successfully")
        return response
    except ClientError as e:
        if e.response.get('Error', {}).get('Code') == 'ValidationException':
            logger.warning("DynamoDB maps might be missing; initializing them")
            try:
                table.update_item(
                    Key=key,
                    UpdateExpression="SET artifacts = if_not_exists(artifacts, :empty), stages = if_not_exists(stages, :empty)",
                    ExpressionAttributeValues={":empty": {}}
                )
                logger.info("Initialized DynamoDB maps; retrying update")
                response = table.update_item(
                    Key=key,
                    UpdateExpression=update_expression,
                    ExpressionAttributeNames=expression_attribute_names,
                    ExpressionAttributeValues=expression_attribute_values,
                    ReturnValues="UPDATED_NEW"
                )
                logger.info("DynamoDB item updated successfully on retry")
                return response
            except Exception as inner_e:
                logger.error(
                    "Failed to retry DynamoDB update",
                    extra={"errorType": type(inner_e).__name__},
                )
                raise
            
        logger.error("Failed to update DynamoDB", extra={"errorType": type(e).__name__})
        raise
