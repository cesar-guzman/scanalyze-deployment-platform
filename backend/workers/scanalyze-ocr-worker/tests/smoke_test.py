import os
from unittest.mock import patch, MagicMock

# Ajustar variables de entorno para que el worker no falle
os.environ['SCANALYZE_ENV'] = 'demo'
os.environ['SCANALYZE_TENANT'] = 'test-tenant'
os.environ['AWS_REGION'] = 'us-east-1'

# Prevenimos llamadas reales a Boto3 mockeando a nivel global para el test
@patch('boto3.Session')
@patch('boto3.client')
@patch('boto3.resource')
def test_full_pipeline(mock_resource, mock_client, mock_session):
    # Mock SSM -> config fetch
    mock_ssm = MagicMock()
    mock_client.return_value = mock_ssm
    
    # Simular paginator de SSM
    mock_paginator = MagicMock()
    mock_ssm.get_paginator.return_value = mock_paginator
    mock_paginator.paginate.return_value = [{
        'Parameters': [
            {'Name': '/scanalyze/demo/tenants/test-tenant/data-foundation/raw_bucket_name', 'Value': 'raw-bucket-test'},
            {'Name': '/scanalyze/demo/tenants/test-tenant/data-foundation/ocr_bucket_name', 'Value': 'ocr-bucket-test'},
            {'Name': '/scanalyze/demo/tenants/test-tenant/data-foundation/documents_table_name', 'Value': 'docs-table'},
            {'Name': '/scanalyze/demo/tenants/test-tenant/queues/ingest_url', 'Value': 'https://sqs/ingest'},
            {'Name': '/scanalyze/demo/tenants/test-tenant/queues/ocr_url', 'Value': 'https://sqs/ocr'},
            {'Name': '/scanalyze/demo/tenants/test-tenant/queues/classify_url', 'Value': 'https://sqs/classify'},
        ]
    }]

    # Import dependencies ONLY after patching environment and globals
    from src.ocr_worker import aws
    from src.ocr_worker.config import config
    from src.ocr_worker.processors import ingest, ocr_poll
    from src.ocr_worker.processors.ingest import process_ingest_message
    from src.ocr_worker.processors.ocr_poll import process_ocr_poll_message

    # Inject mock clients instead of real ones into aws bindings
    mock_sqs = MagicMock()
    mock_textract = MagicMock()
    mock_s3 = MagicMock()
    
    aws.sqs_client = ingest.sqs_client = ocr_poll.sqs_client = mock_sqs
    aws.textract_client = ingest.textract_client = ocr_poll.textract_client = mock_textract
    aws.s3_client = ocr_poll.s3_client = mock_s3
    
    mock_dynamodb = MagicMock()
    mock_table = MagicMock()
    # Ensure key_schema evaluates correctly
    mock_table.key_schema = [{'AttributeName': 'document_id', 'KeyType': 'HASH'}]
    mock_dynamodb.Table.return_value = mock_table
    aws.dynamodb_resource = ingest.dynamodb_resource = ocr_poll.dynamodb_resource = mock_dynamodb

    # 1. Simular mensaje SQS en INGEST
    print("--- EMULANDO INGEST ---")
    ingest_msg_body = """{
        "schemaVersion": "scanalyze.ingest.v1",
        "documentId": "doc-uuid-123",
        "raw": {"bucket": "raw-bucket-test", "key": "inbound/doc.pdf"}
    }"""
    
    # Simular Textract
    mock_textract.start_document_text_detection.return_value = {'JobId': 'job-456'}
    
    # Procesar ingest
    success = process_ingest_message(ingest_msg_body, "receipt-HANDLE-1")
    assert success is True
    print("INGEST OK: Textract iniciado.")

    # Validaciones Ingest
    mock_textract.start_document_text_detection.assert_called_once()
    mock_table.update_item.assert_called_once()
    mock_sqs.send_message.assert_called_once()
    
    enqueued_ocr_msg = mock_sqs.send_message.call_args[1]['MessageBody']
    print(f"Mensaje encolado a ocr_queue:\n{enqueued_ocr_msg}")

    # 2. Simular mensaje SQS en OCR POLL (Primero: IN_PROGRESS)
    print("\n--- EMULANDO OCR POLL (IN PROGRESS) ---")
    mock_sqs.reset_mock()
    mock_textract.get_document_text_detection.return_value = {
        'JobStatus': 'IN_PROGRESS'
    }
    
    success = process_ocr_poll_message(enqueued_ocr_msg, "receipt-HANDLE-2", "https://sqs/ocr")
    assert success is True
    print("OCR POLL OK: Re-encolado con backoff.")
    
    mock_sqs.send_message.assert_called_once()
    re_enqueued_msg = mock_sqs.send_message.call_args[1]['MessageBody']
    delay_sec = mock_sqs.send_message.call_args[1]['DelaySeconds']
    print(f"Re-encolado SQS (delay {delay_sec}s):\n{re_enqueued_msg}")

    # 3. Simular mensaje SQS en OCR POLL (Segundo intento: SUCCEEDED)
    print("\n--- EMULANDO OCR POLL (SUCCEEDED) ---")
    mock_sqs.reset_mock()
    mock_textract.get_document_text_detection.return_value = {
        'JobStatus': 'SUCCEEDED',
        'DocumentMetadata': {'Pages': 2},
        'Blocks': [{'BlockType': 'PAGE'}]
    }
    
    success = process_ocr_poll_message(re_enqueued_msg, "receipt-HANDLE-3", "https://sqs/ocr")
    assert success is True
    print("OCR POLL OK: Artifact S3 guardado y mensaje classify enviado.")

    # Validaciones Finales
    mock_s3.put_object.assert_called_once()
    s3_call = mock_s3.put_object.call_args[1]
    print(f"Artifact S3 put_object (Bucket: {s3_call['Bucket']}, Key: {s3_call['Key']})")

    mock_sqs.send_message.assert_called_once()
    final_classify_msg = mock_sqs.send_message.call_args[1]['MessageBody']
    print(f"Mensaje final encolado a classify_url:\n{final_classify_msg}")
    
    print("\n¡Smoke Test Pasó Correctamente!")

if __name__ == "__main__":
    test_full_pipeline()
