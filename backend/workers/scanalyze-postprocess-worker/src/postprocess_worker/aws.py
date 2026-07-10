import boto3
import os
from botocore.config import Config

boto_config = Config(
    retries={
        'mode': 'standard',
        'max_attempts': 5
    }
)

sqs_client = boto3.client('sqs', config=boto_config)
s3_client = boto3.client('s3', config=boto_config)
dynamodb_resource = boto3.resource('dynamodb', config=boto_config)

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
