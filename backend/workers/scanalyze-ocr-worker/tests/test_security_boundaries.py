import json
import logging
import sys
from unittest.mock import MagicMock, patch

import pytest
from pydantic import BaseModel, ConfigDict, ValidationError

from ocr_worker.config import ConfigCache
from ocr_worker.logger import (
    JSONFormatter,
    bind_context,
    clear_context,
    log_event,
    safe_error_details,
)
from ocr_worker import main as worker_main


class _StrictPayload(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    pages: int


class _StrictMetadata(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    correlationId: str


class _StrictMetadataListPayload(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    metadata: list[_StrictMetadata]


def test_config_rejects_missing_deployment_environment(monkeypatch):
    monkeypatch.delenv("SCANALYZE_ENV", raising=False)
    with patch("ocr_worker.config.boto3.client") as boto_client:
        with pytest.raises(RuntimeError, match="SCANALYZE_ENV is required"):
            ConfigCache()
    boto_client.assert_not_called()


@pytest.mark.parametrize("valid_env", ["local", "test", "ci", "demo", "sandbox", "dev", "staging", "production"])
def test_environment_positive_cases(monkeypatch, valid_env):
    monkeypatch.setenv("SCANALYZE_ENV", valid_env)
    formatter = JSONFormatter(tenant="platform", stage="ocr")
    import json
    import logging
    record = logging.LogRecord("test", logging.INFO, "path", 1, "msg", (), None)
    out = json.loads(formatter.format(record))
    assert out["env"] == valid_env


@pytest.mark.parametrize("invalid_env", [
    " ",
    " test ",
    "dev\n",
    "x" * 100,
    "unknown-free-text",
    "SYNTHETIC-SENTINEL-123",
    '{"env": "test"}',
])
def test_environment_negative_cases(monkeypatch, invalid_env):
    monkeypatch.setenv("SCANALYZE_ENV", invalid_env)
    formatter = JSONFormatter(tenant="platform", stage="ocr")
    import json
    import logging
    record = logging.LogRecord("test", logging.INFO, "path", 1, "msg", (), None)
    out = json.loads(formatter.format(record))
    assert out["env"] == "unknown"
    if invalid_env.strip():
        assert invalid_env not in repr(out)


def test_config_rejects_missing_tenant(monkeypatch):
    monkeypatch.setenv("SCANALYZE_ENV", "test")
    monkeypatch.delenv("SCANALYZE_TENANT", raising=False)
    with patch("ocr_worker.config.boto3.client") as boto_client:
        with pytest.raises(RuntimeError, match="SCANALYZE_TENANT is required"):
            ConfigCache()
    boto_client.assert_not_called()


@pytest.mark.parametrize(
    "name",
    ["SCANALYZE_DEPLOYMENT_CUSTOMER_ID", "SCANALYZE_DEPLOYMENT_ID"],
)
def test_config_rejects_missing_runtime_ownership_binding(monkeypatch, name):
    monkeypatch.setenv("SCANALYZE_ENV", "test")
    monkeypatch.setenv("SCANALYZE_TENANT", "platform")
    monkeypatch.setenv("SCANALYZE_DEPLOYMENT_CUSTOMER_ID", "cust_01ARZ3NDEKTSV4RRFFQ69G5FAW")
    monkeypatch.setenv("SCANALYZE_DEPLOYMENT_ID", "dep_01ARZ3NDEKTSV4RRFFQ69G5FAV")
    monkeypatch.delenv(name, raising=False)
    with patch("ocr_worker.config.boto3.client") as boto_client:
        with pytest.raises(RuntimeError, match=f"{name} is required"):
            ConfigCache()
    boto_client.assert_not_called()


def test_validation_summary_omits_input_value():
    sensitive_value = "SYNTHETIC-SENSITIVE-VALUE"
    with pytest.raises(ValidationError) as captured:
        _StrictPayload(pages=sensitive_value)

    details = safe_error_details(captured.value)

    assert details["errorCount"] == 1
    assert details["invalidFields"] == ["pages"]
    assert sensitive_value not in repr(details)


def test_validation_summary_redacts_unknown_extra_key():
    hostile_field = "HOSTILE_FIELD_SENTINEL_123"
    with pytest.raises(ValidationError) as captured:
        _StrictPayload.model_validate({"pages": 1, hostile_field: "SYNTHETIC-SENSITIVE-VALUE"})

    details = safe_error_details(captured.value)

    assert details["errorCount"] == 1
    assert details["invalidFields"] == ["<field>"]
    assert hostile_field not in repr(details)


def test_validation_summary_redacts_nested_unknown_key_and_preserves_index_shape():
    hostile_field = "HOSTILE_NESTED_KEY_123456"
    with pytest.raises(ValidationError) as captured:
        _StrictMetadataListPayload.model_validate(
            {
                "metadata": [
                    {
                        "correlationId": "ref_" + "a" * 32,
                        hostile_field: "SYNTHETIC-SENSITIVE-VALUE",
                    }
                ]
            }
        )

    details = safe_error_details(captured.value)

    assert details["invalidFields"] == ["metadata.<index>.<field>"]
    assert hostile_field not in repr(details)


def test_validation_summary_preserves_known_nested_schema_path():
    with pytest.raises(ValidationError) as captured:
        _StrictMetadataListPayload.model_validate({"metadata": [{"correlationId": 123}]})

    details = safe_error_details(captured.value)

    assert details["invalidFields"] == ["metadata.<index>.correlationId"]


@pytest.mark.parametrize("opaque_length", [24, 32, 64])
def test_context_preserves_producer_opaque_references(opaque_length):
    opaque_reference = "ref_" + "a" * opaque_length
    clear_context()
    try:
        bind_context(correlationId=opaque_reference, traceId=opaque_reference)
        formatter = JSONFormatter(tenant="platform", stage="ocr")
        record = logging.LogRecord("test", logging.INFO, "path", 1, "processing", (), None)
        rendered = json.loads(formatter.format(record))
    finally:
        clear_context()

    assert rendered["correlationId"] == opaque_reference
    assert rendered["traceId"] == opaque_reference


@pytest.mark.parametrize(
    ("correlation_id", "trace_id"),
    [
        (
            "550e8400-e29b-41d4-a716-446655440000",
            "1-67891233-defdefdefdefdefdefdefdef",
        ),
        (
            "01ARZ3NDEKTSV4RRFFQ69G5FAV",
            "0123456789abcdef0123456789abcdef",
        ),
    ],
)
def test_context_preserves_existing_correlation_and_trace_formats(correlation_id, trace_id):
    clear_context()
    try:
        bind_context(correlationId=correlation_id, traceId=trace_id)
        formatter = JSONFormatter(tenant="platform", stage="ocr")
        record = logging.LogRecord("test", logging.INFO, "path", 1, "processing", (), None)
        rendered = json.loads(formatter.format(record))
    finally:
        clear_context()

    assert rendered["correlationId"] == correlation_id
    assert rendered["traceId"] == trace_id


def test_context_drops_unsafe_opaque_reference_payloads():
    unsafe_reference = "ref_SYNTHETIC-SENSITIVE-PAYLOAD"
    clear_context()
    try:
        bind_context(correlationId=unsafe_reference, traceId=unsafe_reference)
        formatter = JSONFormatter(tenant="platform", stage="ocr")
        record = logging.LogRecord("test", logging.INFO, "path", 1, "processing", (), None)
        rendered = json.loads(formatter.format(record))
    finally:
        clear_context()

    assert "correlationId" not in rendered
    assert "traceId" not in rendered
    assert unsafe_reference not in repr(rendered)


def test_actual_exception_type_with_underscore_overrides_caller_value():
    class Custom_Error(RuntimeError):
        pass

    try:
        raise Custom_Error("SYNTHETIC-SENSITIVE-VALUE")
    except Custom_Error:
        record = logging.LogRecord(
            "test",
            logging.ERROR,
            "path",
            1,
            "processing failed",
            (),
            sys.exc_info(),
        )
    record.errorType = "CallerSpoof"

    rendered = json.loads(JSONFormatter(tenant="platform", stage="ocr").format(record))

    assert rendered["errorType"] == "Custom_Error"
    assert "SYNTHETIC-SENSITIVE-VALUE" not in repr(rendered)


def test_log_event_uses_constant_message_and_validated_event_field(caplog):
    with caplog.at_level(logging.INFO, logger="ocr_worker.structured"):
        log_event("worker_started")

    record = caplog.records[-1]
    rendered = json.loads(JSONFormatter(tenant="platform", stage="ocr").format(record))

    assert rendered["message"] == "OCR worker event"
    assert rendered["event"] == "worker_started"


def test_log_event_does_not_reflect_invalid_event_name(caplog):
    hostile_event = "worker_started\nSYNTHETIC-SENSITIVE-VALUE"
    with caplog.at_level(logging.INFO, logger="ocr_worker.structured"):
        log_event(hostile_event)

    record = caplog.records[-1]
    rendered = json.loads(JSONFormatter(tenant="platform", stage="ocr").format(record))

    assert rendered["message"] == "OCR worker event"
    assert "event" not in rendered
    assert hostile_event not in repr(rendered)


def test_schema_or_deadline_value_error_is_not_deleted_before_native_dlq(monkeypatch):
    sqs = MagicMock()
    sqs.receive_message.return_value = {
        "Messages": [
            {
                "ReceiptHandle": "receipt-1",
                "Body": "{synthetic-invalid-json",
                "MessageId": "message-1",
                "Attributes": {"ApproximateReceiveCount": "3"},
            }
        ]
    }

    def reject_for_dlq(*args):
        worker_main.shutdown_requested = True
        raise ValueError("synthetic payload content must never be logged")

    monkeypatch.setattr(worker_main, "sqs_client", sqs)
    worker_main.shutdown_requested = False
    try:
        worker_main.poll_queue(
            "https://sqs.test/ingest",
            reject_for_dlq,
            "INGEST",
        )
    finally:
        worker_main.shutdown_requested = False

    sqs.delete_message.assert_not_called()


def test_log_context_is_cleared_between_messages():
    import logging

    bind_context(documentId="previous-document", correlationId="550e8400-e29b-41d4-a716-446655440000")
    clear_context()
    formatter = JSONFormatter(tenant="platform", stage="ocr")
    record = logging.LogRecord(
        name="ocr-test",
        level=logging.INFO,
        pathname=__file__,
        lineno=1,
        msg="processing",
        args=(),
        exc_info=None,
    )
    rendered = formatter.format(record)
    assert "previous-document" not in rendered
    assert "previous-correlation" not in rendered
