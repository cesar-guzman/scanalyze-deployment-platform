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
bedrock_client = boto3.client('bedrock-runtime', config=boto_config)

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
    
    # We provide both to avoid KeyError in format string
    fmt_args = {"document_id": document_id, "tenant": tenant or "unknown"}
    
    try:
        pk_value = pk_template.format(**fmt_args)
    except KeyError:
        # Fallback if the template has variables we didn't provide
        pk_value = document_id
        
    key = {pk_name: pk_value}
    
    if sk_name:
        try:
            sk_value = (sk_template or "METADATA").format(**fmt_args)
        except KeyError:
            sk_value = "METADATA"
        key[sk_name] = sk_value
        
    return key
