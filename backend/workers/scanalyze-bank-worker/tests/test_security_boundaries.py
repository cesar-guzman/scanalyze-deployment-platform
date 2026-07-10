import json
import logging
import sys
from unittest.mock import patch

import pytest
from pydantic import BaseModel, ValidationError

from bank_worker.config import ConfigCache
from bank_worker.logger import JSONFormatter, safe_error_details


class _StrictPayload(BaseModel):
    amount: int


def test_config_rejects_missing_deployment_environment(monkeypatch):
    monkeypatch.delenv("SCANALYZE_ENV", raising=False)
    with patch("bank_worker.config.boto3.client") as boto_client:
        with pytest.raises(RuntimeError, match="SCANALYZE_ENV is required"):
            ConfigCache()
    boto_client.assert_not_called()


def test_config_rejects_missing_tenant(monkeypatch):
    monkeypatch.setenv("SCANALYZE_ENV", "test")
    monkeypatch.delenv("SCANALYZE_TENANT", raising=False)
    with patch("bank_worker.config.boto3.client") as boto_client:
        with pytest.raises(RuntimeError, match="SCANALYZE_TENANT is required"):
            ConfigCache()
    boto_client.assert_not_called()


def test_validation_summary_omits_input_value():
    sensitive_value = "SYNTHETIC-SENSITIVE-VALUE"
    with pytest.raises(ValidationError) as captured:
        _StrictPayload(amount=sensitive_value)

    details = safe_error_details(captured.value)

    assert details["errorCount"] == 1
    assert details["invalidFields"] == ["amount"]
    assert sensitive_value not in repr(details)


def test_json_formatter_omits_exception_message_and_traceback(monkeypatch):
    sensitive_value = "SYNTHETIC-PII-IN-EXCEPTION"
    monkeypatch.setenv("SCANALYZE_ENV", "test")
    formatter = JSONFormatter(tenant="bank", stage="bank_extract")

    try:
        raise RuntimeError(sensitive_value)
    except RuntimeError:
        record = logging.LogRecord(
            name="test",
            level=logging.ERROR,
            pathname=__file__,
            lineno=1,
            msg="operation_failed",
            args=(),
            exc_info=sys.exc_info(),
        )

    rendered = formatter.format(record)
    payload = json.loads(rendered)

    assert payload["errorType"] == "RuntimeError"
    assert "exception" not in payload
    assert sensitive_value not in rendered
