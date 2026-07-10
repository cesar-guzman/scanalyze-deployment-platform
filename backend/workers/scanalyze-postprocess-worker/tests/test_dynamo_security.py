from unittest.mock import patch

import pytest
from botocore.exceptions import ClientError

from src.postprocess_worker import dynamo


class _FakeTable:
    def __init__(self, *, item=None, update_error=None):
        self.item = item
        self.update_error = update_error
        self.update_calls = []
        self.get_calls = []

    def update_item(self, **kwargs):
        self.update_calls.append(kwargs)
        if self.update_error:
            raise self.update_error
        return {"Attributes": {}}

    def get_item(self, **kwargs):
        self.get_calls.append(kwargs)
        return {"Item": self.item} if self.item is not None else {}


def _set_key_config(monkeypatch):
    monkeypatch.setenv("DOCUMENTS_TABLE_PK_NAME", "PK")
    monkeypatch.setenv("DOCUMENTS_TABLE_PK_TEMPLATE", "TENANT#{tenant}#DOC#{document_id}")
    monkeypatch.setenv("DOCUMENTS_TABLE_SK_NAME", "SK")
    monkeypatch.setenv("DOCUMENTS_TABLE_SK_TEMPLATE", "METADATA")


def _conditional_failure():
    return ClientError(
        {
            "Error": {
                "Code": "ConditionalCheckFailedException",
                "Message": "condition failed",
            }
        },
        "UpdateItem",
    )


def test_document_key_is_rendered_only_from_explicit_templates(monkeypatch):
    _set_key_config(monkeypatch)

    assert dynamo.get_key_dict("documents", "bank", "doc-123") == {
        "PK": "TENANT#bank#DOC#doc-123",
        "SK": "METADATA",
    }


def test_document_key_rejects_missing_or_partial_configuration(monkeypatch):
    for name in (
        "DOCUMENTS_TABLE_PK_NAME",
        "DOCUMENTS_TABLE_PK_TEMPLATE",
        "DOCUMENTS_TABLE_SK_NAME",
        "DOCUMENTS_TABLE_SK_TEMPLATE",
    ):
        monkeypatch.delenv(name, raising=False)

    with pytest.raises(RuntimeError, match="DOCUMENTS_TABLE_PK_NAME"):
        dynamo.get_key_dict("documents", "bank", "doc-123")

    monkeypatch.setenv("DOCUMENTS_TABLE_PK_NAME", "PK")
    monkeypatch.setenv("DOCUMENTS_TABLE_PK_TEMPLATE", "DOC#{document_id}")
    monkeypatch.setenv("DOCUMENTS_TABLE_SK_NAME", "SK")
    with pytest.raises(RuntimeError, match="DOCUMENTS_TABLE_SK_NAME.*DOCUMENTS_TABLE_SK_TEMPLATE"):
        dynamo.get_key_dict("documents", "bank", "doc-123")


def test_validate_update_requires_existing_document_and_extracted_transition(monkeypatch):
    _set_key_config(monkeypatch)
    table = _FakeTable()
    payload = {
        "validation": {"status": "PASS", "errors": [], "validatedAt": "2026-01-01T00:00:00Z"},
        "stages_validate": {"status": "DONE", "validatedAt": "2026-01-01T00:00:00Z", "errorsCount": 0},
        "updatedAt": "2026-01-01T00:00:00Z",
    }

    with patch.object(dynamo.dynamodb_resource, "Table", return_value=table):
        assert dynamo.update_validate_stage("documents", "bank", "doc-123", payload) == payload["validation"]

    request = table.update_calls[0]
    assert "attribute_exists(#pk)" in request["ConditionExpression"]
    assert "#status = :expected_status" in request["ConditionExpression"]
    assert request["ExpressionAttributeNames"]["#pk"] == "PK"
    assert request["ExpressionAttributeValues"][":expected_status"] == "BANK_EXTRACTED"


def test_persist_update_requires_matching_stored_validation(monkeypatch):
    _set_key_config(monkeypatch)
    table = _FakeTable()
    payload = {
        "status": "COMPLETED",
        "completedAt": "2026-01-01T00:00:00Z",
        "validationStatus": "PASS",
        "stages_persist": {
            "status": "DONE",
            "finalStatus": "COMPLETED",
            "completedAt": "2026-01-01T00:00:00Z",
        },
        "updatedAt": "2026-01-01T00:00:00Z",
        "structured": {"bucket": "structured", "key": "bank/doc-123/result.json"},
    }

    with patch.object(dynamo.dynamodb_resource, "Table", return_value=table):
        assert dynamo.update_persist_stage("documents", "bank", "doc-123", payload) == payload["completedAt"]

    request = table.update_calls[0]
    condition = request["ConditionExpression"]
    assert "attribute_exists(#pk)" in condition
    assert "#stages.#validate.#stage_status = :done" in condition
    assert "#validation.#validation_status = :validation_status" in condition
    assert request["ExpressionAttributeValues"][":validation_status"] == "PASS"


def test_conditional_failure_without_matching_existing_state_is_not_success(monkeypatch):
    _set_key_config(monkeypatch)
    table = _FakeTable(update_error=_conditional_failure())
    payload = {
        "validation": {"status": "PASS", "errors": [], "validatedAt": "2026-01-01T00:00:00Z"},
        "stages_validate": {"status": "DONE", "validatedAt": "2026-01-01T00:00:00Z", "errorsCount": 0},
        "updatedAt": "2026-01-01T00:00:00Z",
    }

    with patch.object(dynamo.dynamodb_resource, "Table", return_value=table):
        with pytest.raises(ClientError):
            dynamo.update_validate_stage("documents", "bank", "doc-123", payload)

    assert table.get_calls


def test_matching_existing_validation_is_the_only_idempotent_success(monkeypatch):
    _set_key_config(monkeypatch)
    table = _FakeTable(
        update_error=_conditional_failure(),
        item={
            "validation": {"status": "PASS"},
            "stages": {"validate": {"status": "DONE"}},
        },
    )
    payload = {
        "validation": {"status": "PASS", "errors": [], "validatedAt": "2026-01-01T00:00:00Z"},
        "stages_validate": {"status": "DONE", "validatedAt": "2026-01-01T00:00:00Z", "errorsCount": 0},
        "updatedAt": "2026-01-01T00:00:00Z",
    }

    with patch.object(dynamo.dynamodb_resource, "Table", return_value=table):
        assert dynamo.update_validate_stage("documents", "bank", "doc-123", payload) == table.item["validation"]

    assert table.get_calls


def test_matching_existing_persist_returns_authoritative_completion_time(monkeypatch):
    _set_key_config(monkeypatch)
    stored_completed_at = "2026-01-01T00:00:00Z"
    table = _FakeTable(
        update_error=_conditional_failure(),
        item={
            "status": "COMPLETED",
            "completedAt": stored_completed_at,
            "validation": {"status": "PASS"},
            "stages": {
                "persist": {"status": "DONE", "finalStatus": "COMPLETED"}
            },
        },
    )
    payload = {
        "status": "COMPLETED",
        "completedAt": "2026-01-01T00:02:00Z",
        "validationStatus": "PASS",
        "stages_persist": {
            "status": "DONE",
            "finalStatus": "COMPLETED",
            "completedAt": "2026-01-01T00:02:00Z",
        },
        "updatedAt": "2026-01-01T00:02:00Z",
        "structured": {"bucket": "structured", "key": "bank/doc-123/result.json"},
    }

    with patch.object(dynamo.dynamodb_resource, "Table", return_value=table):
        assert (
            dynamo.update_persist_stage("documents", "bank", "doc-123", payload)
            == stored_completed_at
        )

    assert table.get_calls


def test_notify_update_requires_matching_completed_persist_transition(monkeypatch):
    _set_key_config(monkeypatch)
    table = _FakeTable()
    payload = {
        "notifiedAt": "2026-01-01T00:01:00Z",
        "completedAt": "2026-01-01T00:00:00Z",
        "finalStatus": "COMPLETED",
        "validationStatus": "PASS",
        "stages_notify": {"status": "DONE", "notifiedAt": "2026-01-01T00:01:00Z"},
        "updatedAt": "2026-01-01T00:01:00Z",
    }

    with patch.object(dynamo.dynamodb_resource, "Table", return_value=table):
        assert dynamo.update_notify_stage("documents", "bank", "doc-123", payload) is True

    request = table.update_calls[0]
    condition = request["ConditionExpression"]
    assert "attribute_exists(#pk)" in condition
    assert "#status = :final_status" in condition
    assert "#stages.#persist.#stage_status = :done" in condition
    assert "#validation.#validation_status = :validation_status" in condition
