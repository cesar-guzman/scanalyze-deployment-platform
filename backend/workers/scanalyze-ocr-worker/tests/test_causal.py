import os
import sys
import subprocess
import pytest
import tempfile

def test_causal_ingest_log_isolated():
    script = """
import os
import json
import io
import logging
import socket
import boto3

# --- Mocks ---
call_tracker = {"client": 0, "resource": 0, "Session": 0}

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
        def __getattr__(self, name):
            if name in ["exceptions"]: raise AttributeError()
            raise RuntimeError(f"Unexpected client method called: {name}")
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
                        "sqsMessageId": "11111111-2222-3333-4444-555555555555" if doc_id == "d1" else "22222222-3333-4444-5555-666666666666"
                    }
                }
            }}
        def update_item(self, *args, **kwargs):
            return {}
        def __getattr__(self, name):
            raise RuntimeError(f"Unexpected table method called: {name}")
    class MockResource:
        def Table(self, name):
            return MockTable()
        def __getattr__(self, name):
            raise RuntimeError(f"Unexpected resource method called: {name}")
    return MockResource()

def _mock_boto_client_tracked(*args, **kwargs):
    call_tracker["client"] += 1
    return _mock_boto_client(*args, **kwargs)

def _mock_boto_resource_tracked(*args, **kwargs):
    call_tracker["resource"] += 1
    return _mock_boto_resource(*args, **kwargs)

class _MockSession:
    def __init__(self, *args, **kwargs):
        call_tracker["Session"] += 1
    def client(self, *args, **kwargs):
        call_tracker["client"] += 1
        return _mock_boto_client(*args, **kwargs)
    def resource(self, *args, **kwargs):
        call_tracker["resource"] += 1
        return _mock_boto_resource(*args, **kwargs)

# Kill network
def guard(*args, **kwargs):
    raise RuntimeError("Network blocked in causal test")
socket.socket = guard

# Mock Boto3
boto3.client = _mock_boto_client_tracked
boto3.resource = _mock_boto_resource_tracked
boto3.Session = _MockSession

# Setup Envs
os.environ["SCANALYZE_ENV"] = "test"
os.environ["SCANALYZE_TENANT"] = "test_tenant"
os.environ["SCANALYZE_DEPLOYMENT_CUSTOMER_ID"] = "cust_0123456789ABCDEFGHJKMNP123"
os.environ["SCANALYZE_DEPLOYMENT_ID"] = "dep_0123456789ABCDEFGHJKMNP123"
os.environ["SSM_PREFIX"] = "/test"
os.environ["AWS_REGION"] = "us-east-1"
os.environ["AWS_DEFAULT_REGION"] = "us-east-1"
os.environ["AWS_EC2_METADATA_DISABLED"] = "true"
os.environ.pop("AWS_ACCESS_KEY_ID", None)
os.environ.pop("AWS_SECRET_ACCESS_KEY", None)
os.environ.pop("AWS_SESSION_TOKEN", None)

# Import app AFTER mocks
from src.ocr_worker.logger import setup_logging, clear_context
from src.ocr_worker.contracts import IngestMessage, MessageMetadata, S3Location
from src.ocr_worker.processors.ingest import process_ingest_message

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

process_ingest_message(msg_valid.model_dump_json(), "receipt", "11111111-2222-3333-4444-555555555555", 1)
process_ingest_message(msg_invalid.model_dump_json(), "receipt", "22222222-3333-4444-5555-666666666666", 1)

logs = stream.getvalue()
assert "550e8400-e29b-41d4-a716-446655440000" in logs
assert "1-67891233-defdefdefdefdefdefdefdef" in logs
assert "<SENTINEL_CORR>" not in logs
assert "<SENTINEL_TRACE>" not in logs

assert call_tracker["Session"] > 0
assert call_tracker["client"] > 0
assert call_tracker["resource"] > 0

print("SUCCESS")
"""

    with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False) as f:
        f.write(script)
        test_path = f.name
    
    try:
        env = os.environ.copy()
        env["PYTHONPATH"] = "backend/workers/scanalyze-ocr-worker/src:backend/workers/scanalyze-ocr-worker"
        out = subprocess.check_output([sys.executable, test_path], env=env, stderr=subprocess.STDOUT, text=True)
        assert "SUCCESS" in out
    finally:
        os.unlink(test_path)

def test_causal_enums():
    # Enums are mostly pure logic on the logger, but to be hermetic we isolate as well.
    script = """
import os
import io
import logging
from src.ocr_worker.logger import setup_logging, log_event

os.environ["SCANALYZE_ENV"] = "test"
os.environ["SCANALYZE_TENANT"] = "test_tenant"
setup_logging()

stream = io.StringIO()
handler = logging.StreamHandler(stream)
handler.setFormatter(logging.getLogger().handlers[0].formatter)
logging.getLogger().addHandler(handler)

valid_routes = ["platform", "default", "bank", "personal", "gov"]
valid_next_stages = ["classify", "bank-extract", "personal-extract", "gov-extract"]

for route in valid_routes:
    log_event("test", document_route=route)

for stage in valid_next_stages:
    log_event("test", next_stage=stage)

logs = stream.getvalue()
for route in valid_routes:
    assert f'"document_route": "{route}"' in logs
for stage in valid_next_stages:
    assert f'"next_stage": "{stage}"' in logs

print("SUCCESS")
"""
    with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False) as f:
        f.write(script)
        test_path = f.name
    
    try:
        env = os.environ.copy()
        env["PYTHONPATH"] = "backend/workers/scanalyze-ocr-worker/src:backend/workers/scanalyze-ocr-worker"
        out = subprocess.check_output([sys.executable, test_path], env=env, stderr=subprocess.STDOUT, text=True)
        assert "SUCCESS" in out
    finally:
        os.unlink(test_path)
