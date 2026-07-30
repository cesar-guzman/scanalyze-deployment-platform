import pytest
from pydantic import ValidationError

from src.postprocess_worker import dynamo
from src.postprocess_worker.contracts import (
    NotifyMessage,
    PersistMessage,
    ValidateMessage,
)


CUSTOMER_ID = "cust_01ARZ3NDEKTSV4RRFFQ69G5FAW"
DEPLOYMENT_ID = "dep_01ARZ3NDEKTSV4RRFFQ69G5FAV"


def _ownership(stage: str, domain: str = "bank") -> dict:
    return {
        "customer_id": CUSTOMER_ID,
        "deployment_id": DEPLOYMENT_ID,
        "ownership_schema_version": 1,
        "pipeline_stage": stage,
        "processing_domain": domain,
    }


@pytest.mark.parametrize(
    ("message_type", "payload"),
    (
        (
            ValidateMessage,
            {
                "schemaVersion": "scanalyze.validate.v2",
                "documentId": "doc-123",
                "structured": {
                    "bucket": "structured-bucket",
                    "key": "customers/cust_01ARZ3NDEKTSV4RRFFQ69G5FAW/deployments/dep_01ARZ3NDEKTSV4RRFFQ69G5FAV/documents/doc-123/structured/bank/result.json",
                },
                "meta": {
                    "env": "test",
                    "tenant": "bank",
                    "schema_version": "1.0",
                    "prompt_version": "1.0",
                },
            },
        ),
        (
            PersistMessage,
            {
                "schemaVersion": "scanalyze.persist.v2",
                "documentId": "doc-123",
                "structured": {
                    "bucket": "structured-bucket",
                    "key": "customers/cust_01ARZ3NDEKTSV4RRFFQ69G5FAW/deployments/dep_01ARZ3NDEKTSV4RRFFQ69G5FAV/documents/doc-123/structured/bank/result.json",
                },
                "validation": {
                    "status": "PASS",
                    "errors": [],
                    "validatedAt": "2026-01-01T00:00:00Z",
                },
                "meta": {
                    "env": "test",
                    "tenant": "bank",
                    "schema_version": "1.0",
                    "prompt_version": "1.0",
                },
            },
        ),
        (
            NotifyMessage,
            {
                "schemaVersion": "scanalyze.notify.v2",
                "documentId": "doc-123",
                "result": {
                    "finalStatus": "COMPLETED",
                    "completedAt": "2026-01-01T00:00:00Z",
                    "validationStatus": "PASS",
                },
                "meta": {"env": "test", "tenant": "bank"},
            },
        ),
    ),
)
def test_async_contracts_require_exact_ownership_tuple(message_type, payload):
    with pytest.raises(ValidationError):
        message_type(**payload)


def test_validate_v2_accepts_canonical_ownership_and_rejects_spoof_fields():
    payload = {
        "schemaVersion": "scanalyze.validate.v2",
        "documentId": "doc-123",
        **_ownership("validate"),
        "structured": {
            "bucket": "structured-bucket",
            "key": "customers/cust_01ARZ3NDEKTSV4RRFFQ69G5FAW/deployments/dep_01ARZ3NDEKTSV4RRFFQ69G5FAV/documents/doc-123/structured/bank/result.json",
        },
        "meta": {
            "env": "test",
            "tenant": "bank",
            "schema_version": "1.0",
            "prompt_version": "1.0",
        },
    }

    message = ValidateMessage(**payload)
    assert message.customer_id == CUSTOMER_ID
    assert message.deployment_id == DEPLOYMENT_ID

    with pytest.raises(ValidationError):
        ValidateMessage(**payload, tenantId="spoofed")


def test_validate_update_condition_binds_customer_and_deployment(monkeypatch):
    monkeypatch.setenv("DOCUMENTS_TABLE_PK_NAME", "PK")
    monkeypatch.setenv("DOCUMENTS_TABLE_PK_TEMPLATE", "DOC#{document_id}")
    monkeypatch.delenv("DOCUMENTS_TABLE_SK_NAME", raising=False)
    monkeypatch.delenv("DOCUMENTS_TABLE_SK_TEMPLATE", raising=False)

    class Table:
        request = None

        def update_item(self, **kwargs):
            self.request = kwargs

    table = Table()
    monkeypatch.setattr(dynamo.dynamodb_resource, "Table", lambda _name: table)
    payload = {
        "validation": {
            "status": "PASS",
            "errors": [],
            "validatedAt": "2026-01-01T00:00:00Z",
        },
        "stages_validate": {
            "status": "DONE",
            "validatedAt": "2026-01-01T00:00:00Z",
            "errorsCount": 0,
        },
        "updatedAt": "2026-01-01T00:00:00Z",
    }

    dynamo.update_validate_stage(
        "documents",
        "bank",
        "doc-123",
        CUSTOMER_ID,
        DEPLOYMENT_ID,
        payload,
    )

    assert "#customer_id = :customer_id" in table.request["ConditionExpression"]
    assert "#deployment_id = :deployment_id" in table.request["ConditionExpression"]
    assert "#processing_domain = :processing_domain" in table.request["ConditionExpression"]
    assert table.request["ExpressionAttributeValues"][":customer_id"] == CUSTOMER_ID
    assert table.request["ExpressionAttributeValues"][":deployment_id"] == DEPLOYMENT_ID
    assert table.request["ExpressionAttributeValues"][":processing_domain"] == "bank"


@pytest.mark.parametrize(
    "record_change",
    [
        {"customer_id": "cust_01BX5ZZKBKACTAV9WEVGEMMVS1"},
        {"deployment_id": "dep_01BX5ZZKBKACTAV9WEVGEMMVS0"},
        {"ownership_schema_version": 2},
        {"processing_domain": "personal"},
        {"artifacts": {"structured": {"bucket": "foreign", "key": "foreign"}}},
    ],
)
def test_postprocess_authorization_rejects_foreign_record_or_locator(
    monkeypatch, record_change
):
    monkeypatch.setenv("DOCUMENTS_TABLE_PK_NAME", "PK")
    monkeypatch.setenv("DOCUMENTS_TABLE_PK_TEMPLATE", "DOC#{document_id}")
    monkeypatch.delenv("DOCUMENTS_TABLE_SK_NAME", raising=False)
    monkeypatch.delenv("DOCUMENTS_TABLE_SK_TEMPLATE", raising=False)
    key = (
        "customers/cust_01ARZ3NDEKTSV4RRFFQ69G5FAW/"
        "deployments/dep_01ARZ3NDEKTSV4RRFFQ69G5FAV/"
        "documents/doc-123/structured/bank/result.json"
    )
    item = {
        "customer_id": CUSTOMER_ID,
        "deployment_id": DEPLOYMENT_ID,
        "ownership_schema_version": 1,
        "processing_domain": "bank",
        "artifacts": {
            "structured": {"bucket": "structured-bucket", "key": key}
        },
    }
    item.update(record_change)

    class Table:
        def get_item(self, **kwargs):
            return {"Item": item}

    monkeypatch.setattr(dynamo.dynamodb_resource, "Table", lambda _name: Table())

    with pytest.raises(ValueError, match="unavailable"):
        dynamo.require_authorized_document(
            "documents",
            "bank",
            "doc-123",
            CUSTOMER_ID,
            DEPLOYMENT_ID,
            structured_bucket="structured-bucket",
            structured_key=key,
        )
