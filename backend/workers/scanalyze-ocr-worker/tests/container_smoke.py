"""Offline causal smoke executed inside the built OCR worker image.

This file intentionally has no pytest dependency. The container verifier pipes
it to ``python -`` while Docker networking is disabled.
"""

from __future__ import annotations

import io
import logging
import os
import socket

import boto3


CUSTOMER_ID = "cust_0123456789ABCDEFGHJKMNP123"
DEPLOYMENT_ID = "dep_0123456789ABCDEFGHJKMNP123"
VALID_CORRELATION_ID = "550e8400-e29b-41d4-a716-446655440000"
VALID_TRACE_ID = "1-67891233-defdefdefdefdefdefdefdef"
SENTINELS = (
    "SYNTHETIC_RAW_DOCUMENT_CONTENT",
    "SYNTHETIC_PII_ISH_CONTENT",
    "SYNTHETIC_EXCEPTION_CONTENT",
    "<SENTINEL_CORR>",
    "<SENTINEL_TRACE>",
)

for key in (
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",
    "AWS_SECURITY_TOKEN",
    "AWS_PROFILE",
    "AWS_DEFAULT_PROFILE",
    "AWS_ROLE_ARN",
    "AWS_WEB_IDENTITY_TOKEN_FILE",
    "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI",
    "AWS_CONTAINER_CREDENTIALS_FULL_URI",
    "AWS_CONTAINER_AUTHORIZATION_TOKEN",
    "AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE",
):
    os.environ.pop(key, None)

os.environ.update(
    {
        "SCANALYZE_ENV": "ci",
        "SCANALYZE_TENANT": "test_tenant",
        "SCANALYZE_DEPLOYMENT_CUSTOMER_ID": CUSTOMER_ID,
        "SCANALYZE_DEPLOYMENT_ID": DEPLOYMENT_ID,
        "SCANALYZE_PARAM_ROOT": "/scanalyze/ci/tenants",
        "AWS_EC2_METADATA_DISABLED": "true",
        "AWS_REGION": "us-east-1",
        "AWS_DEFAULT_REGION": "us-east-1",
        "AWS_CONFIG_FILE": os.devnull,
        "AWS_SHARED_CREDENTIALS_FILE": os.devnull,
        "BOTO_CONFIG": os.devnull,
    }
)


class _BlockedSocket(socket.socket):
    def connect(self, *args, **kwargs):
        raise AssertionError("network access attempted during container smoke")

    def connect_ex(self, *args, **kwargs):
        raise AssertionError("network access attempted during container smoke")


def _blocked_create_connection(*args, **kwargs):
    raise AssertionError("network access attempted during container smoke")


socket.socket = _BlockedSocket
socket.create_connection = _blocked_create_connection

call_tracker = {"client": 0, "resource": 0, "session": 0}


class ContainerSmokeFailure(RuntimeError):
    """Raised when the causal smoke detects a contract violation."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ContainerSmokeFailure(message)


class _MockPaginator:
    def paginate(self, *args, **kwargs):
        return [
            {
                "Parameters": [
                    {
                        "Name": "/scanalyze/ci/tenants/test_tenant/data-foundation/documents_table_name",
                        "Value": "documents-table",
                    },
                    {
                        "Name": "/scanalyze/ci/tenants/test_tenant/data-foundation/raw_bucket_name",
                        "Value": "raw-bucket",
                    },
                    {
                        "Name": "/scanalyze/ci/tenants/test_tenant/data-foundation/ocr_bucket_name",
                        "Value": "ocr-bucket",
                    },
                    {
                        "Name": "/scanalyze/ci/tenants/test_tenant/queues/ocr_url",
                        "Value": "https://sqs.invalid/ocr",
                    },
                ]
            }
        ]


class _MockClient:
    class exceptions:
        class InvalidS3ObjectException(Exception):
            pass

    def get_paginator(self, name):
        _require(
            name == "get_parameters_by_path",
            f"unexpected paginator requested: {name}",
        )
        return _MockPaginator()

    def start_document_text_detection(self, *args, **kwargs):
        return {"JobId": "job-container-smoke"}

    def send_message(self, *args, **kwargs):
        return {"MessageId": "33333333-4444-5555-6666-777777777777"}

    def __getattr__(self, name):
        raise AssertionError(f"unexpected fake AWS client method: {name}")


class _MockTable:
    def get_item(self, *, Key, ConsistentRead):
        _require(ConsistentRead is True, "document read must be strongly consistent")
        document_id = Key["documentId"]
        enqueue_id = "enqueue-one" if document_id == "doc-one" else "enqueue-two"
        sqs_message_id = (
            "11111111-2222-3333-4444-555555555555"
            if document_id == "doc-one"
            else "22222222-3333-4444-5555-666666666666"
        )
        source_key = (
            f"customers/{CUSTOMER_ID}/deployments/{DEPLOYMENT_ID}/"
            f"documents/{document_id}/source.pdf"
        )
        return {
            "Item": {
                "documentId": document_id,
                "customer_id": CUSTOMER_ID,
                "deployment_id": DEPLOYMENT_ID,
                "ownership_schema_version": 1,
                "documentRoute": "default",
                "objectLocation": {"bucket": "raw-bucket", "key": source_key},
                "input": {"bucket": "raw-bucket", "key": source_key},
                "status": "SUBMITTED",
                "stages": {
                    "ingest": {
                        "status": "ENQUEUED",
                        "enqueueId": enqueue_id,
                        "sqsMessageId": sqs_message_id,
                    }
                },
            }
        }

    def update_item(self, *args, **kwargs):
        return {}


class _MockResource:
    def Table(self, name):
        _require(name == "documents-table", f"unexpected table requested: {name}")
        return _MockTable()


def _mock_client(*args, **kwargs):
    call_tracker["client"] += 1
    return _MockClient()


def _mock_resource(*args, **kwargs):
    call_tracker["resource"] += 1
    return _MockResource()


class _MockSession:
    def __init__(self, *args, **kwargs):
        call_tracker["session"] += 1

    def client(self, *args, **kwargs):
        return _mock_client(*args, **kwargs)

    def resource(self, *args, **kwargs):
        return _mock_resource(*args, **kwargs)


boto3.client = _mock_client
boto3.resource = _mock_resource
boto3.Session = _MockSession

# The worker must only be imported after AWS and network isolation is installed.
from src.ocr_worker.contracts import IngestMessage, MessageMetadata, S3Location
from src.ocr_worker.logger import bind_context, clear_context, log_event, setup_logging
from src.ocr_worker.processors.ingest import process_ingest_message


setup_logging()
root_logger = logging.getLogger()
stream = io.StringIO()
handler = logging.StreamHandler(stream)
handler.setFormatter(root_logger.handlers[0].formatter)
root_logger.addHandler(handler)


def _message(*, document_id: str, enqueue_id: str, correlation_id: str, trace_id: str):
    source_key = (
        f"customers/{CUSTOMER_ID}/deployments/{DEPLOYMENT_ID}/"
        f"documents/{document_id}/source.pdf"
    )
    return IngestMessage(
        schemaVersion="scanalyze.ingest.v2",
        customer_id=CUSTOMER_ID,
        deployment_id=DEPLOYMENT_ID,
        ownership_schema_version=1,
        pipeline_stage="ingest",
        enqueue_id=enqueue_id,
        documentId=document_id,
        raw=S3Location(bucket="raw-bucket", key=source_key),
        _metadata=MessageMetadata(
            correlationId=correlation_id,
            traceId=trace_id,
        ),
    )


valid = _message(
    document_id="doc-one",
    enqueue_id="enqueue-one",
    correlation_id=VALID_CORRELATION_ID,
    trace_id=VALID_TRACE_ID,
)
unsafe = _message(
    document_id="doc-two",
    enqueue_id="enqueue-two",
    correlation_id="<SENTINEL_CORR>",
    trace_id="<SENTINEL_TRACE>",
)

_require(
    process_ingest_message(
        valid.model_dump_json(),
        "receipt-one",
        "11111111-2222-3333-4444-555555555555",
        1,
    ),
    "valid ingest fixture was not processed",
)
_require(
    process_ingest_message(
        unsafe.model_dump_json(),
        "receipt-two",
        "22222222-3333-4444-5555-666666666666",
        1,
    ),
    "redaction ingest fixture was not processed",
)

clear_context()
bind_context(
    correlationId=VALID_CORRELATION_ID,
    rawBody="SYNTHETIC_RAW_DOCUMENT_CONTENT",
    payload="SYNTHETIC_PII_ISH_CONTENT",
)
log_event(
    "container_smoke",
    rawBody="SYNTHETIC_RAW_DOCUMENT_CONTENT",
    content="SYNTHETIC_PII_ISH_CONTENT",
)
try:
    raise ValueError("SYNTHETIC_EXCEPTION_CONTENT")
except ValueError:
    logging.getLogger("ocr.container-smoke").exception("Container smoke exception")

logs = stream.getvalue()
_require(VALID_CORRELATION_ID in logs, "valid correlation ID was not logged")
_require(VALID_TRACE_ID in logs, "valid trace ID was not logged")
for sentinel in SENTINELS:
    _require(sentinel not in logs, "a synthetic sensitive sentinel reached logs")
_require(call_tracker["session"] > 0, "boto3 Session fake was not exercised")
_require(call_tracker["client"] > 0, "boto3 client fake was not exercised")
_require(call_tracker["resource"] > 0, "boto3 resource fake was not exercised")

print("OCR_CONTAINER_SMOKE_OK")
