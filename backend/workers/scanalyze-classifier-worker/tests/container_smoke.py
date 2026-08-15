"""Deterministic causal smoke executed inside the classifier worker image.

The verifier pipes this dependency-free script to ``python -`` with Docker
networking disabled. Every AWS boundary is replaced before worker imports.
"""

from __future__ import annotations

import io
import json
import logging
import os
import socket

import boto3


CUSTOMER_ID = "cust_01ARZ3NDEKTSV4RRFFQ69G5FAW"
DEPLOYMENT_ID = "dep_01ARZ3NDEKTSV4RRFFQ69G5FAV"
DOCUMENT_ID = "doc-classifier-container-smoke"
CORRELATION_ID = "ref_f07165b64216ae9a4988fc779b08f0db"
TRACE_ID = "ref_8d49ce52b2f423b5306c54091fa2fb54"
SENTINELS = (
    "SYNTHETIC_DOCUMENT_CONTENT_DO_NOT_LOG",
    "SYNTHETIC_TOKEN_DO_NOT_LOG",
    "SYNTHETIC_CREDENTIAL_DO_NOT_LOG",
    "000011112222",
    "SYNTHETIC_PROVIDER_PAYLOAD_DO_NOT_LOG",
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
        "SCANALYZE_TENANT": "platform",
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


class ContainerSmokeFailure(RuntimeError):
    """Raised when the container contract is not satisfied."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ContainerSmokeFailure(message)


class _BlockedSocket(socket.socket):
    def connect(self, *args, **kwargs):
        raise ContainerSmokeFailure("network access attempted during container smoke")

    def connect_ex(self, *args, **kwargs):
        raise ContainerSmokeFailure("network access attempted during container smoke")


def _blocked_create_connection(*args, **kwargs):
    raise ContainerSmokeFailure("network access attempted during container smoke")


socket.socket = _BlockedSocket
socket.create_connection = _blocked_create_connection

constructed = {"clients": [], "resources": []}
provider_calls: list[str] = []
sent_messages: list[dict[str, object]] = []
deleted_messages: list[dict[str, object]] = []
table_updates: list[dict[str, object]] = []


class _MockPaginator:
    def paginate(self, *args, **kwargs):
        provider_calls.append("ssm.get_parameters_by_path")
        return [
            {
                "Parameters": [
                    {
                        "Name": "/scanalyze/ci/tenants/platform/data-foundation/documents_table_name",
                        "Value": "documents-table",
                    },
                    {
                        "Name": "/scanalyze/ci/tenants/platform/queues/classify_url",
                        "Value": "https://sqs.invalid/classify.fifo",
                    },
                    {
                        "Name": "/scanalyze/ci/tenants/platform/queues/bank-extract_url",
                        "Value": "https://sqs.invalid/bank-extract.fifo",
                    },
                    {
                        "Name": "/scanalyze/ci/tenants/platform/features/bedrock_classification_enabled",
                        "Value": "false",
                    },
                ]
            }
        ]


class _MockSsmClient:
    def get_paginator(self, name):
        _require(name == "get_parameters_by_path", "unexpected SSM paginator")
        return _MockPaginator()


class _MockS3Client:
    def get_object(self, *, Bucket, Key):
        _require(Bucket == "ocr-bucket", "unexpected OCR bucket")
        _require(Key == "synthetic/ocr.json", "unexpected OCR key")
        provider_calls.append("s3.get_object")
        text = " ".join(
            (
                "bank statement balance deposit withdrawal",
                SENTINELS[0],
                SENTINELS[1],
                SENTINELS[2],
            )
        )
        body = json.dumps({"Blocks": [{"BlockType": "LINE", "Text": text}]})
        return {"Body": io.BytesIO(body.encode("utf-8"))}


class _MockSqsClient:
    def send_message(self, **kwargs):
        provider_calls.append("sqs.send_message")
        sent_messages.append(kwargs)
        return {"MessageId": "33333333-4444-5555-6666-777777777777"}

    def delete_message(self, **kwargs):
        provider_calls.append("sqs.delete_message")
        deleted_messages.append(kwargs)
        return {}


class _ForbiddenBedrockClient:
    def __getattr__(self, name):
        raise ContainerSmokeFailure(f"Bedrock provider method was reached: {name}")


class _MockTable:
    def get_item(self, *, Key, ConsistentRead):
        _require(Key == {"documentId": DOCUMENT_ID}, "unexpected document key")
        _require(ConsistentRead is True, "document read must be consistent")
        provider_calls.append("dynamodb.get_item")
        return {
            "Item": {
                "documentId": DOCUMENT_ID,
                "customer_id": CUSTOMER_ID,
                "deployment_id": DEPLOYMENT_ID,
                "ownership_schema_version": 1,
                "status": "OCR_COMPLETED",
                "documentRoute": "platform",
                "input": {"bucket": "raw-bucket", "key": "synthetic/source.pdf"},
                "artifacts": {
                    "ocr": {"bucket": "ocr-bucket", "key": "synthetic/ocr.json"}
                },
                "accountId": SENTINELS[3],
                "providerPayload": SENTINELS[4],
            }
        }

    def update_item(self, **kwargs):
        provider_calls.append("dynamodb.update_item")
        table_updates.append(kwargs)
        return {}


class _MockDynamoResource:
    def Table(self, name):
        _require(name == "documents-table", "unexpected DynamoDB table")
        return _MockTable()


def _mock_client(service_name, *args, **kwargs):
    constructed["clients"].append(service_name)
    clients = {
        "ssm": _MockSsmClient(),
        "s3": _MockS3Client(),
        "sqs": _MockSqsClient(),
        "bedrock-runtime": _ForbiddenBedrockClient(),
    }
    _require(service_name in clients, f"unexpected boto3 client: {service_name}")
    return clients[service_name]


def _mock_resource(service_name, *args, **kwargs):
    constructed["resources"].append(service_name)
    _require(service_name == "dynamodb", "unexpected boto3 resource")
    return _MockDynamoResource()


boto3.client = _mock_client
boto3.resource = _mock_resource

# Worker imports are intentionally delayed until network and provider fakes exist.
from classifier_worker.contracts import ClassifyMessage, ExtractMessage
from classifier_worker.main import process_message


stream = io.StringIO()
handler = logging.StreamHandler(stream)
handler.setFormatter(logging.Formatter("%(message)s"))
logging.getLogger().addHandler(handler)

message_body = {
    "schemaVersion": "scanalyze.classify.v2",
    "documentId": DOCUMENT_ID,
    "customer_id": CUSTOMER_ID,
    "deployment_id": DEPLOYMENT_ID,
    "ownership_schema_version": 1,
    "pipeline_stage": "classify",
    "processing_domain": None,
    "ocr": {"bucket": "ocr-bucket", "key": "synthetic/ocr.json"},
    "raw": {"bucket": "raw-bucket", "key": "synthetic/source.pdf"},
    "meta": {"env": "ci", "tenant": "platform"},
    "_metadata": {"correlationId": CORRELATION_ID, "traceId": TRACE_ID},
}
contract_input = dict(message_body)
contract_input.pop("_metadata")
parsed_input = ClassifyMessage(**contract_input)
_require(parsed_input.schemaVersion == "scanalyze.classify.v2", "input contract drift")

processed = process_message(
    {"ReceiptHandle": "synthetic-receipt", "Body": json.dumps(message_body)}
)
_require(processed is True, "synthetic classification did not complete")
_require(len(sent_messages) == 1, "synthetic handoff was not emitted exactly once")
_require(len(deleted_messages) == 1, "input message was not deleted exactly once")
_require(len(table_updates) == 2, "classification checkpoints were not persisted")

sent = sent_messages[0]
_require(
    sent.get("QueueUrl") == "https://sqs.invalid/bank-extract.fifo",
    "classification route drifted",
)
_require(sent.get("MessageGroupId") == DOCUMENT_ID, "FIFO group binding drifted")
_require(
    sent.get("MessageDeduplicationId")
    == f"{DEPLOYMENT_ID}-{DOCUMENT_ID}-classify-v2",
    "FIFO deduplication binding drifted",
)
outbound = json.loads(str(sent["MessageBody"]))
metadata = outbound.pop("_metadata")
parsed_output = ExtractMessage(**outbound)
_require(parsed_output.schemaVersion == "scanalyze.extract.v2", "output contract drift")
_require(parsed_output.pipeline_stage == "bank-extract", "classification changed")
_require(parsed_output.processing_domain == "bank", "processing domain changed")
_require(parsed_output.attempt == 0, "attempt contract changed")
_require(
    metadata == {"correlationId": CORRELATION_ID, "traceId": TRACE_ID},
    "trace metadata contract drifted",
)

first_update = table_updates[0]["ExpressionAttributeValues"]
_require(first_update[":c"]["docType"] == "bank_statement", "docType drifted")
_require(first_update[":c"]["confidence"] == "1.0", "confidence drifted")
_require(first_update[":c"]["strategy"] == "heuristic", "provider was used")

_require(
    constructed["clients"] == ["ssm", "s3", "sqs", "bedrock-runtime"],
    "unexpected boto3 client construction",
)
_require(constructed["resources"] == ["dynamodb"], "unexpected boto3 resource")
_require(
    provider_calls
    == [
        "ssm.get_parameters_by_path",
        "dynamodb.get_item",
        "s3.get_object",
        "dynamodb.update_item",
        "sqs.send_message",
        "dynamodb.update_item",
        "sqs.delete_message",
    ],
    "synthetic provider call sequence drifted",
)

logs = stream.getvalue()
_require("classification_result" in logs, "classification evidence was not logged")
for sentinel in SENTINELS:
    _require(sentinel not in logs, "a synthetic sensitive sentinel reached logs")

print("CLASSIFIER_CONTAINER_SMOKE_OK")
