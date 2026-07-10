import json
from unittest.mock import Mock

from src.postprocess_worker.contracts import (
    NOTIFY_SCHEMA_VERSION,
    PERSIST_SCHEMA_VERSION,
    VALIDATE_SCHEMA_VERSION,
)
from src.postprocess_worker.config import config
from src.postprocess_worker.main import build_queue_bindings, dispatch_message


def _message(schema_version: str, *, tenant: str = "bank") -> str:
    return json.dumps(
        {
            "schemaVersion": schema_version,
            "documentId": "doc-123",
            "meta": {"env": config.env, "tenant": tenant},
        }
    )


def test_shared_queue_has_one_binding_with_schema_dispatchers():
    bindings = build_queue_bindings(
        "https://sqs.invalid/shared",
        "https://sqs.invalid/shared",
        "https://sqs.invalid/shared",
        "POSTPROCESS",
    )

    assert list(bindings) == ["https://sqs.invalid/shared"]
    assert set(bindings["https://sqs.invalid/shared"]) == {
        VALIDATE_SCHEMA_VERSION,
        PERSIST_SCHEMA_VERSION,
        NOTIFY_SCHEMA_VERSION,
    }


def test_dispatcher_selects_only_the_matching_schema_processor():
    validate_processor = Mock(return_value=True)
    persist_processor = Mock(return_value=True)

    result = dispatch_message(
        _message(PERSIST_SCHEMA_VERSION),
        "receipt",
        "https://sqs.invalid/shared",
        "platform",
        {
            VALIDATE_SCHEMA_VERSION: validate_processor,
            PERSIST_SCHEMA_VERSION: persist_processor,
        },
    )

    assert result is True
    persist_processor.assert_called_once()
    validate_processor.assert_not_called()


def test_dispatcher_fails_closed_for_missing_or_incompatible_schema():
    validate_processor = Mock(return_value=True)
    processors = {VALIDATE_SCHEMA_VERSION: validate_processor}

    missing_schema = json.dumps(
        {
            "documentId": "doc-123",
            "meta": {"env": config.env, "tenant": "bank"},
        }
    )
    assert dispatch_message(
        missing_schema,
        "receipt",
        "https://sqs.invalid/validate",
        "bank",
        processors,
    ) is False
    assert dispatch_message(
        _message(PERSIST_SCHEMA_VERSION),
        "receipt",
        "https://sqs.invalid/validate",
        "bank",
        processors,
    ) is False
    validate_processor.assert_not_called()


def test_dispatcher_does_not_process_a_different_tenant_route():
    validate_processor = Mock(return_value=True)

    assert dispatch_message(
        _message(VALIDATE_SCHEMA_VERSION, tenant="personal"),
        "receipt",
        "https://sqs.invalid/shared",
        "bank",
        {VALIDATE_SCHEMA_VERSION: validate_processor},
    ) is False
    validate_processor.assert_not_called()
