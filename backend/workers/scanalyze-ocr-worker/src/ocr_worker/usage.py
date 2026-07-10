import uuid
import datetime
from botocore.exceptions import ClientError
from .config import config
from .logger import get_logger

logger = get_logger(__name__)

def resolve_usage_tables(tenant: str):
    env = config.env
    
    events_param = f"/scanalyze/{env}/tenants/{tenant}/usage_events_table_name"
    rollups_param = f"/scanalyze/{env}/tenants/{tenant}/usage_rollups_table_name"
    
    events_table = None
    rollups_table = None
    try:
        ssm = config.ssm_client
        resp_events = ssm.get_parameter(Name=events_param)
        events_table = resp_events["Parameter"]["Value"]
        
        resp_rollups = ssm.get_parameter(Name=rollups_param)
        rollups_table = resp_rollups["Parameter"]["Value"]
        return events_table, rollups_table
    except Exception as e:
        logger.error("Failed to resolve usage tables", extra={"errorType": type(e).__name__})
        return None, None

def record_usage_metering_with_idempotency(dynamodb_client, tenant: str, doc_id: str, pages: int, uploader_user_id: str, batch_id: str, doc_type: str):
    events_table, rollups_table = resolve_usage_tables(tenant)
    if not events_table or not rollups_table:
        logger.error("Skipping usage metering because tables could not be resolved.")
        return False
        
    idempotency_key = f"{doc_id}#PAGES_SCANNED"
    now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
    day_iso = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d")

    # The TransactWriteItems guarantees we only add to rollups IF this specific event hasn't been written yet.
    # It requires dynamodb client, not resource.
    
    items_to_update = [
        {"pk": {"S": "OVERALL"}, "sk": {"S": "TOTAL"}},
        {"pk": {"S": "DAYS"}, "sk": {"S": day_iso}}
    ]
    if uploader_user_id:
        items_to_update.append({"pk": {"S": "USERS"}, "sk": {"S": uploader_user_id}})
    if batch_id:
        items_to_update.append({"pk": {"S": "BATCHES"}, "sk": {"S": batch_id}})
    if doc_type:
        items_to_update.append({"pk": {"S": "DOCTYPES"}, "sk": {"S": doc_type}})

    transact_items = []
    
    # 1. Append-only events item
    event_item = {
        "id": {"S": idempotency_key},
        "tenantId": {"S": tenant},
        "createdAt": {"S": now_iso},
        "metric": {"S": "PAGES_SCANNED"},
        "value": {"N": str(pages)},
        "documentId": {"S": doc_id}
    }
    if uploader_user_id:
        event_item["uploaderUserId"] = {"S": uploader_user_id}
    if batch_id:
        event_item["batchId"] = {"S": batch_id}
    if doc_type:
        event_item["documentType"] = {"S": doc_type}

    transact_items.append({
        "Put": {
            "TableName": events_table,
            "Item": event_item,
            "ConditionExpression": "attribute_not_exists(id)"
        }
    })
    
    # 2. Rollups Update items
    for rollup_key in items_to_update:
        transact_items.append({
            "Update": {
                "TableName": rollups_table,
                "Key": rollup_key,
                "UpdateExpression": "ADD pagesScanned :pages, documentsCompleted :doc",
                "ExpressionAttributeValues": {
                    ":pages": {"N": str(pages)},
                    ":doc": {"N": "1"}
                }
            }
        })
        
    try:
        dynamodb_client.transact_write_items(TransactItems=transact_items)
        logger.info(f"Successfully metered {pages} pages")
        return True
    except ClientError as e:
        error_code = e.response['Error']['Code']
        if error_code == 'TransactionCanceledException':
            reasons = e.response.get('CancellationReasons', [])
            # Reason 0 is for the events table condition check
            if reasons and reasons[0].get('Code') == 'ConditionalCheckFailed':
                logger.warning("Idempotency check met; document already metered")
                return True # Not an error, just idempotency doing its job
        logger.error("Failed to transact usage metering", extra={"errorType": type(e).__name__})
        return False
