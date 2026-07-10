import os
import json
from typing import Optional, Dict, Any, List
import boto3
from botocore.config import Config
from .logger import get_logger

log = get_logger(__name__)

# Standard retry configuration for robust AWS calls
boto_config = Config(
    retries=dict(max_attempts=5, mode='standard')
)

s3_client = boto3.client('s3', config=boto_config)
dynamodb = boto3.resource('dynamodb', config=boto_config)
sqs_client = boto3.client('sqs', config=boto_config)
bedrock_client = boto3.client('bedrock-runtime', config=boto_config)

def get_ocr_text(bucket: str, key: str) -> str:
    """Reads the OCR artifact from S3 and extracts the text blocks."""
    try:
        response = s3_client.get_object(Bucket=bucket, Key=key)
        content = response['Body'].read().decode('utf-8')
        data = json.loads(content)
        
        # Determine format (Textract format typically has 'Blocks')
        lines = []
        if 'Blocks' in data:
            for block in data['Blocks']:
                if block.get('BlockType') == 'LINE':
                    lines.append(block.get('Text', ''))
            return "\n".join(lines)
        elif isinstance(data, list):
            # Fallback if structure is a flat list of lines or dicts
            for item in data:
                if isinstance(item, str):
                    lines.append(item)
                elif isinstance(item, dict) and 'Text' in item:
                    lines.append(item['Text'])
            return "\n".join(lines)
        else:
            return str(data)
    except Exception as e:
        log.error("s3_read_error", errorType=type(e).__name__)
        raise

def enqueue_message(queue_url: str, message_body: str, message_group_id: str, deduplication_id: Optional[str] = None):
    """Enqueues a message to SQS (FIFO support included if queue is .fifo)."""
    kwargs = {
        'QueueUrl': queue_url,
        'MessageBody': message_body
    }
    
    if queue_url.endswith('.fifo'):
        kwargs['MessageGroupId'] = message_group_id
        if deduplication_id:
            kwargs['MessageDeduplicationId'] = deduplication_id
            
    try:
        sqs_client.send_message(**kwargs)
    except Exception as e:
        log.error("sqs_enqueue_error", errorType=type(e).__name__)
        raise

def delete_message(queue_url: str, receipt_handle: str):
    try:
        sqs_client.delete_message(QueueUrl=queue_url, ReceiptHandle=receipt_handle)
    except Exception as e:
        log.error("sqs_delete_error", errorType=type(e).__name__)
        # Don't fail the worker if delete fails, let visibility timeout handle it

def receive_messages(queue_url: str, max_messages: int = 10, wait_time: int = 20) -> List[Dict[str, Any]]:
    try:
        response = sqs_client.receive_message(
            QueueUrl=queue_url,
            MaxNumberOfMessages=max_messages,
            WaitTimeSeconds=wait_time,
            AttributeNames=['All'],
            MessageAttributeNames=['All']
        )
        return response.get('Messages', [])
    except Exception as e:
        log.error("sqs_receive_error", errorType=type(e).__name__)
        return []

def save_classification_evidence(table_name: str, document_id: str, doc_type: str, confidence: float, route: str, strategy: str, classifier_version: str = "v1"):
    """
    Saves the classification result to DynamoDB using a subdocument or specific fields.
    Does an UpdateItem so it doesn't overwrite existant critical fields like 'status'.
    """
    table = dynamodb.Table(table_name)
    import datetime
    now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
    
    try:
        key = build_key(table_name, document_id)
        table.update_item(
            Key=key,
            UpdateExpression="SET classification = :c, routingTarget = :r, #stages.#classify = :stageData, #status = :s",
            ExpressionAttributeNames={
                '#stages': 'stages',
                '#classify': 'classify',
                '#status': 'status'
            },
            ExpressionAttributeValues={
                ':s': 'CLASSIFY_COMPLETED',
                ':c': {
                    'docType': doc_type,
                    'confidence': str(confidence), # DDB decimals or str
                    'route': route,
                    'strategy': strategy,
                    'classifiedAt': now_iso,
                    'classifierVersion': classifier_version
                },
                ':r': route,
                ':stageData': {
                    'status': 'COMPLETED',
                    'endedAt': now_iso,
                    'route': route,
                    'docType': doc_type,
                    'confidence': str(confidence)
                }
            }
        )
    except Exception as e:
        log.error("dynamo_update_error", errorType=type(e).__name__)
        raise

def get_document_item(table_name: str, document_id: str) -> Optional[Dict[str, Any]]:
    try:
        table = dynamodb.Table(table_name)
        key = build_key(table_name, document_id)
        res = table.get_item(Key=key, ConsistentRead=True)
        return res.get('Item')
    except Exception as e:
        log.error("dynamo_get_error", errorType=type(e).__name__)
        return None

def build_key(table_name: str, document_id: str, tenant: str = None) -> dict:
    pk_name = os.environ.get("DOCUMENTS_TABLE_PK_NAME", "documentId")
    sk_name = os.environ.get("DOCUMENTS_TABLE_SK_NAME")
    pk_template = os.environ.get("DOCUMENTS_TABLE_PK_TEMPLATE", "{document_id}")
    sk_template = os.environ.get("DOCUMENTS_TABLE_SK_TEMPLATE")
    
    key = {pk_name: pk_template.format(document_id=document_id)}
    if sk_name:
        key[sk_name] = (sk_template or "METADATA").format(document_id=document_id)
    return key
