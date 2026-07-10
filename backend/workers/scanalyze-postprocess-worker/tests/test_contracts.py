import pytest
from pydantic import ValidationError
from src.postprocess_worker.contracts import (
    NotifyMessage,
    PersistMessage,
    ValidateMessage,
    ValidationResult,
)

def test_validate_message_valid():
    msg = ValidateMessage(
        documentId="doc-123",
        structured={"bucket": "my-bucket", "key": "docs/123.json"},
        meta={
            "env": "demo",
            "tenant": "test-tenant",
            "schema_version": "1.0",
            "prompt_version": "1.0"
        }
    )
    assert msg.schemaVersion == "scanalyze.validate.v1"
    assert msg.documentId == "doc-123"
    assert msg.structured.bucket == "my-bucket"

def test_validate_message_missing_fields():
    with pytest.raises(ValidationError):
        ValidateMessage(
            documentId="doc-123",
            structured={"bucket": "my-bucket"},
            # missing meta
        )

def test_persist_message_valid():
    msg = PersistMessage(
        documentId="doc-123",
        structured={"bucket": "my-bucket", "key": "docs/123.json"},
        validation={
            "status": "PASS",
            "errors": [],
            "validatedAt": "2023-01-01T00:00:00Z"
        },
        meta={
            "env": "demo",
            "tenant": "test-tenant",
            "schema_version": "1.0",
            "prompt_version": "1.0"
        }
    )
    assert msg.schemaVersion == "scanalyze.persist.v1"
    assert msg.validation.status == "PASS"

def test_notify_message_valid():
    msg = NotifyMessage(
        documentId="doc-123",
        result={
            "finalStatus": "COMPLETED",
            "completedAt": "2023-01-01T00:00:00Z",
            "validationStatus": "PASS"
        },
        meta={
            "env": "demo",
            "tenant": "test-tenant"
        }
    )
    assert msg.schemaVersion == "scanalyze.notify.v1"
    assert msg.result.finalStatus == "COMPLETED"


def test_message_contracts_reject_incompatible_schema_versions():
    with pytest.raises(ValidationError):
        ValidateMessage(
            schemaVersion="scanalyze.persist.v1",
            documentId="doc-123",
            structured={"bucket": "my-bucket", "key": "bank/doc-123/result.json"},
            meta={
                "env": "demo",
                "tenant": "bank",
                "schema_version": "1.0",
                "prompt_version": "1.0",
            },
        )


def test_pass_result_cannot_contain_error_severity():
    with pytest.raises(ValidationError):
        ValidationResult(
            status="PASS",
            errors=[{"code": "INVALID", "message": "invalid", "severity": "ERROR"}],
            validatedAt="2026-01-01T00:00:00Z",
        )


def test_persist_pass_requires_complete_structured_pointer():
    with pytest.raises(ValidationError):
        PersistMessage(
            documentId="doc-123",
            structured={"bucket": None, "key": "bank/doc-123/result.json"},
            validation={
                "status": "PASS",
                "errors": [],
                "validatedAt": "2026-01-01T00:00:00Z",
            },
            meta={
                "env": "demo",
                "tenant": "bank",
                "schema_version": "1.0",
                "prompt_version": "1.0",
            },
        )


def test_notify_completion_must_match_validation_result():
    with pytest.raises(ValidationError):
        NotifyMessage(
            documentId="doc-123",
            result={
                "finalStatus": "COMPLETED",
                "completedAt": "2026-01-01T00:00:00Z",
                "validationStatus": "FAIL",
            },
            meta={"env": "demo", "tenant": "bank"},
        )
