import os
import pytest
from src.ocr_worker.contracts import IngestMessage, MessageMetadata, S3Location
import json
import io
import logging
import asyncio

def _mock_s3_read(bucket, key):
    return b"dummy_data"

def _mock_boto_client(*args, **kwargs):
    class MockPaginator:
        def paginate(self, *args, **kwargs):
            return [{"Parameters": [
                {"Name": "/scanalyze/test/tenants/test_tenant/data-foundation/documents_table_name", "Value": "table"},
                {"Name": "/scanalyze/test/tenants/test_tenant/ocr_jobs_table_name", "Value": "jobs"},
                {"Name": "/scanalyze/test/tenants/test_tenant/data-foundation/raw_bucket_name", "Value": "b"},
                {"Name": "/scanalyze/test/tenants/test_tenant/data-foundation/ocr_bucket_name", "Value": "b2"},
                {"Name": "/scanalyze/test/tenants/test_tenant/queues/ocr_url", "Value": "queue_url"},
                {"Name": "/scanalyze/test/tenants/test_tenant/ocr_poll_queue_url", "Value": "queue"},
                {"Name": "/scanalyze/test/tenants/test_tenant/ocr_sns_topic_arn", "Value": "arn:aws:sns:us-east-1:123456789012:topic"}
            ]}]
            
    class MockClient:
        def __init__(self):
            class MockExceptions:
                class InvalidS3ObjectException(Exception):
                    pass
            self.exceptions = MockExceptions()
        def start_document_analysis(self, *args, **kwargs):
            return {"JobId": "dummy_job"}
        def start_document_text_detection(self, *args, **kwargs):
            return {"JobId": "dummy_job"}
        def get_parameter(self, *args, **kwargs):
            return {"Parameter": {"Value": '{"IngestS3Bucket": "bucket"}'}}
        def send_message(self, *args, **kwargs):
            return {"MessageId": "dummy_sqs_message_id"}
        def delete_message(self, *args, **kwargs):
            pass
        def get_paginator(self, name):
            return MockPaginator()
    return MockClient()

def _mock_boto_resource(*args, **kwargs):
    class MockTable:
        def get_item(self, *args, **kwargs):
            key = kwargs.get("Key", {})
            doc_id = key.get("documentId", "d1")
            return {"Item": {
                "documentId": doc_id,
                "customer_id": "cust_0123456789ABCDEFGHJKMNP123",
                "deployment_id": "dep_0123456789ABCDEFGHJKMNP123",
                "ownership_schema_version": 1,
                "documentRoute": "default",
                "objectLocation": {"bucket": "b", "key": f"customers/cust_0123456789ABCDEFGHJKMNP123/deployments/dep_0123456789ABCDEFGHJKMNP123/documents/{doc_id}/original.pdf"},
                "input": {"bucket": "b", "key": f"customers/cust_0123456789ABCDEFGHJKMNP123/deployments/dep_0123456789ABCDEFGHJKMNP123/documents/{doc_id}/original.pdf"},
                "status": "SUBMITTED",
                "stages": {
                    "ingest": {
                        "status": "ENQUEUED",
                        "enqueueId": "q1" if doc_id == "d1" else "q2",
                        "sqsMessageId": "msg1" if doc_id == "d1" else "msg2"
                    }
                }
            }}
        def update_item(self, *args, **kwargs):
            return {}
    class MockResource:
        def Table(self, name):
            return MockTable()
    return MockResource()

@pytest.fixture
def hermetic_aws(monkeypatch):
    monkeypatch.setenv("SCANALYZE_ENV", "test")
    monkeypatch.setenv("SCANALYZE_TENANT", "test_tenant")
    monkeypatch.setenv("SCANALYZE_DEPLOYMENT_CUSTOMER_ID", "cust_0123456789ABCDEFGHJKMNP123")
    monkeypatch.setenv("SCANALYZE_DEPLOYMENT_ID", "dep_0123456789ABCDEFGHJKMNP123")
    monkeypatch.setenv("SSM_PREFIX", "/test")
    monkeypatch.setenv("AWS_REGION", "us-east-1")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")
    monkeypatch.setenv("AWS_EC2_METADATA_DISABLED", "true")
    monkeypatch.delenv("AWS_ACCESS_KEY_ID", raising=False)
    monkeypatch.delenv("AWS_SECRET_ACCESS_KEY", raising=False)
    monkeypatch.delenv("AWS_SESSION_TOKEN", raising=False)

    import socket
    def guard(*args, **kwargs):
        raise RuntimeError("Network blocked in causal test")
    monkeypatch.setattr(socket, "socket", guard)
    

    import boto3
    monkeypatch.setattr(boto3, "client", _mock_boto_client)
    monkeypatch.setattr(boto3, "resource", _mock_boto_resource)
    
    from src.ocr_worker import aws
    monkeypatch.setattr(aws, "sqs_client", _mock_boto_client())
    monkeypatch.setattr(aws, "s3_client", _mock_boto_client())
    monkeypatch.setattr(aws, "textract_client", _mock_boto_client())
    monkeypatch.setattr(aws, "dynamodb_resource", _mock_boto_resource())
    
    from src.ocr_worker import config
    monkeypatch.setattr(config.config, "ssm_client", _mock_boto_client())

def test_causal_ingest_log(hermetic_aws, monkeypatch):
    from src.ocr_worker.logger import setup_logging, clear_context
    setup_logging()
    
    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    handler.setFormatter(logging.getLogger().handlers[0].formatter)
    logging.getLogger().addHandler(handler)
    
    # Valid
    msg_valid = IngestMessage(
        schemaVersion="scanalyze.ingest.v2",
        customer_id="cust_0123456789ABCDEFGHJKMNP123",
        deployment_id="dep_0123456789ABCDEFGHJKMNP123",
        ownership_schema_version=1,
        pipeline_stage="ingest",
        enqueue_id="q1",
        documentId="d1",
        raw=S3Location(bucket="b", key="customers/cust_0123456789ABCDEFGHJKMNP123/deployments/dep_0123456789ABCDEFGHJKMNP123/documents/d1/original.pdf"),
        _metadata=MessageMetadata(correlationId="550e8400-e29b-41d4-a716-446655440000", traceId="1-67891233-defdefdefdefdefdefdefdef")
    )
    
    # Invalid (sentinel)
    msg_invalid = IngestMessage(
        schemaVersion="scanalyze.ingest.v2",
        customer_id="cust_0123456789ABCDEFGHJKMNP123",
        deployment_id="dep_0123456789ABCDEFGHJKMNP123",
        ownership_schema_version=1,
        pipeline_stage="ingest",
        enqueue_id="q2",
        documentId="d2",
        raw=S3Location(bucket="b", key="customers/cust_0123456789ABCDEFGHJKMNP123/deployments/dep_0123456789ABCDEFGHJKMNP123/documents/d2/original.pdf"),
        _metadata=MessageMetadata(correlationId="<SENTINEL_CORR>", traceId="<SENTINEL_TRACE>")
    )
    
    # Must import *after* hermetic_aws mocks are in place
    from src.ocr_worker.processors.ingest import process_ingest_message
    
    # These must NOT throw an exception. We removed try/except.
    process_ingest_message(msg_valid.model_dump_json(), "receipt", "msg1", 1)
    process_ingest_message(msg_invalid.model_dump_json(), "receipt", "msg2", 1)
        
    logs = stream.getvalue()
    assert "550e8400-e29b-41d4-a716-446655440000" in logs
    assert "1-67891233-defdefdefdefdefdefdefdef" in logs
    assert "<SENTINEL_CORR>" not in logs
    assert "<SENTINEL_TRACE>" not in logs
