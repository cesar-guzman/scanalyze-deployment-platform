import boto3
import os

# Configuración centralizada de clientes de AWS para reuso de la sesión e hilos.
# botocore por defecto maneja un pool de conexiones HTTP y retry con adaptive o standard 
# si se configura mediante botocore.config.Config. Usaremos el modelo standard.
from botocore.config import Config

# Standard retry mode es recomendado por AWS para manejar throttling de forma robusta
boto_config = Config(
    retries={
        'mode': 'standard',
        'max_attempts': 5
    }
)

# Sesión global
aws_session = boto3.Session()

# Clientes y recursos a usar en toda la app
sqs_client = aws_session.client('sqs', config=boto_config)
s3_client = aws_session.client('s3', config=boto_config)
textract_client = aws_session.client('textract', config=boto_config)
dynamodb_resource = aws_session.resource('dynamodb', config=boto_config)

def extend_visibility(queue_url: str, receipt_handle: str, timeout: int):
    """
    Extiende el Visibility Timeout del mensaje en SQS
    para evitar que otro worker lo tome mientras se procesa.
    """
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
