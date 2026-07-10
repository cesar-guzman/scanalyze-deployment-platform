import sys
from unittest.mock import patch

import pytest
from pydantic import BaseModel, ValidationError

from classifier_worker.config import ConfigCache
from classifier_worker.logger import safe_error_details, sanitize_exception_info


class _StrictPayload(BaseModel):
    confidence: float


def test_config_rejects_missing_deployment_environment(monkeypatch):
    monkeypatch.delenv("SCANALYZE_ENV", raising=False)
    with patch("classifier_worker.config.boto3.client") as boto_client:
        with pytest.raises(RuntimeError, match="SCANALYZE_ENV is required"):
            ConfigCache()
    boto_client.assert_not_called()


def test_config_rejects_missing_tenant(monkeypatch):
    monkeypatch.setenv("SCANALYZE_ENV", "test")
    monkeypatch.delenv("SCANALYZE_TENANT", raising=False)
    with patch("classifier_worker.config.boto3.client") as boto_client:
        with pytest.raises(RuntimeError, match="SCANALYZE_TENANT is required"):
            ConfigCache()
    boto_client.assert_not_called()


def test_validation_summary_omits_input_value():
    sensitive_value = "SYNTHETIC-SENSITIVE-VALUE"
    with pytest.raises(ValidationError) as captured:
        _StrictPayload(confidence=sensitive_value)

    details = safe_error_details(captured.value)

    assert details["errorCount"] == 1
    assert details["invalidFields"] == ["confidence"]
    assert sensitive_value not in repr(details)


def test_structlog_processor_omits_exception_message_and_traceback():
    sensitive_value = "SYNTHETIC-PII-IN-EXCEPTION"

    try:
        raise RuntimeError(sensitive_value)
    except RuntimeError:
        event = sanitize_exception_info(
            None,
            "error",
            {"event": "operation_failed", "exc_info": sys.exc_info()},
        )

    assert event == {"event": "operation_failed", "errorType": "RuntimeError"}
    assert sensitive_value not in repr(event)
