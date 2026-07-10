from unittest.mock import patch

import pytest
from pydantic import BaseModel, ValidationError

from personal_worker.config import ConfigCache
from personal_worker.logger import safe_error_details
from personal_worker.processors.extract import _terminal_failure_metadata


class _StrictPayload(BaseModel):
    date_of_birth: int


def test_config_rejects_missing_deployment_environment(monkeypatch):
    monkeypatch.delenv("SCANALYZE_ENV", raising=False)
    with patch("personal_worker.config.boto3.client") as boto_client:
        with pytest.raises(RuntimeError, match="SCANALYZE_ENV is required"):
            ConfigCache()
    boto_client.assert_not_called()


def test_validation_summary_omits_input_value():
    sensitive_value = "SYNTHETIC-SENSITIVE-VALUE"
    with pytest.raises(ValidationError) as captured:
        _StrictPayload(date_of_birth=sensitive_value)

    details = safe_error_details(captured.value)

    assert details["errorCount"] == 1
    assert details["invalidFields"] == ["date_of_birth"]
    assert sensitive_value not in repr(details)


def test_terminal_failure_metadata_omits_exception_message():
    sensitive_value = "SYNTHETIC-PII-IN-EXCEPTION"

    metadata = _terminal_failure_metadata(RuntimeError(sensitive_value))

    assert metadata == {
        "status": "FAILED",
        "errorCode": "MAX_RETRIES_REACHED",
        "errorType": "RuntimeError",
    }
    assert sensitive_value not in repr(metadata)
