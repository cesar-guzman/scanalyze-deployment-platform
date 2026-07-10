import boto3
import os
from botocore.config import Config

# Standard retry mode is recommended by AWS for robust throttling handling
boto_config = Config(
    retries={
        'mode': 'standard',
        'max_attempts': 5
    }
)

sqs_client = boto3.client('sqs', config=boto_config)
s3_client = boto3.client('s3', config=boto_config)
dynamodb_resource = boto3.resource('dynamodb', config=boto_config)
bedrock_config = Config(
    retries={
        'mode': 'adaptive',
        'max_attempts': 10
    }
)
bedrock_client = boto3.client('bedrock-runtime', config=bedrock_config)

def extend_visibility(queue_url: str, receipt_handle: str, timeout: int):
    try:
        sqs_client.change_message_visibility(
            QueueUrl=queue_url,
            ReceiptHandle=receipt_handle,
            VisibilityTimeout=timeout
        )
    except Exception as e:
        import logging
        logging.getLogger(__name__).warning(
            "Failed to extend visibility",
            extra={"errorType": type(e).__name__},
        )

def build_key(table_name: str, document_id: str, tenant: str = None) -> dict:
    pk_name = os.environ.get("DOCUMENTS_TABLE_PK_NAME", "documentId")
    sk_name = os.environ.get("DOCUMENTS_TABLE_SK_NAME")
    pk_template = os.environ.get("DOCUMENTS_TABLE_PK_TEMPLATE", "{document_id}")
    sk_template = os.environ.get("DOCUMENTS_TABLE_SK_TEMPLATE")
    
    key = {pk_name: pk_template.format(document_id=document_id)}
    if sk_name:
        key[sk_name] = (sk_template or "METADATA").format(document_id=document_id)
    return key
