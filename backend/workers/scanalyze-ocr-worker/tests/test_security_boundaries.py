from unittest.mock import MagicMock, patch

import pytest
from pydantic import BaseModel, ValidationError

from ocr_worker.config import ConfigCache
from ocr_worker.logger import JSONFormatter, bind_context, clear_context, safe_error_details
from ocr_worker import main as worker_main


class _StrictPayload(BaseModel):
    pages: int


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
