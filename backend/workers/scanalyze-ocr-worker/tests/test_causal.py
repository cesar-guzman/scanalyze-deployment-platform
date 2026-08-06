import os
os.environ["SCANALYZE_ENV"] = "test"
os.environ["SCANALYZE_TENANT"] = "test_tenant"
os.environ["SCANALYZE_DEPLOYMENT_CUSTOMER_ID"] = "cust_0123456789ABCDEFGHJKMNP123"
os.environ["SCANALYZE_DEPLOYMENT_ID"] = "dep_0123456789ABCDEFGHJKMNP123"
os.environ["SSM_PREFIX"] = "/test"
os.environ["AWS_REGION"] = "us-east-1"
os.environ["AWS_DEFAULT_REGION"] = "us-east-1"
import pytest
from ocr_worker.processors.ingest import process_ingest_message
from ocr_worker.contracts import IngestMessage, MessageMetadata, S3Location
from ocr_worker.logger import setup_logging, clear_context
import json
import io
import logging
import asyncio

def test_causal_ingest_log(monkeypatch):
    _test_causal_ingest_log_impl(monkeypatch)

def _test_causal_ingest_log_impl(monkeypatch):
    monkeypatch.setenv("SCANALYZE_ENV", "test")
    monkeypatch.setenv("SCANALYZE_TENANT", "test_tenant")
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
        raw=S3Location(bucket="b", key="k"),
        _metadata=MessageMetadata(correlationId="corr-valid-123", traceId="trace-valid-456")
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
        raw=S3Location(bucket="b", key="k"),
        _metadata=MessageMetadata(correlationId="<SENTINEL_CORR>", traceId="<SENTINEL_TRACE>")
    )
    
    try:
        process_ingest_message(msg_valid.model_dump_json(), "receipt", "msg1", 1)
    except Exception:
        pass
        
    try:
        process_ingest_message(msg_invalid.model_dump_json(), "receipt", "msg2", 1)
    except Exception:
        pass
        
    logs = stream.getvalue()
    assert "corr-valid-123" in logs
    assert "trace-valid-456" in logs
    assert "<SENTINEL_CORR>" not in logs
    assert "<SENTINEL_TRACE>" not in logs
