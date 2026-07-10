import json
from unittest.mock import Mock, patch

import pytest
from pydantic import BaseModel, ValidationError

from src.postprocess_worker.config import ConfigCache, config
from src.postprocess_worker.logger import safe_error_details
from src.postprocess_worker.processors.notify import process_notify_message
from src.postprocess_worker.processors.persist import process_persist_message
from src.postprocess_worker.processors.validate import process_validate_message


class _StrictPayload(BaseModel):
    status_code: int


def test_config_rejects_missing_deployment_environment(monkeypatch):
    monkeypatch.delenv("SCANALYZE_ENV", raising=False)
    with patch("src.postprocess_worker.config.boto3.client") as boto_client:
        with pytest.raises(RuntimeError, match="SCANALYZE_ENV is required"):
            ConfigCache()
    boto_client.assert_not_called()


def test_config_rejects_missing_tenant_configuration(monkeypatch):
    monkeypatch.setenv("SCANALYZE_ENV", "test")
    monkeypatch.delenv("SCANALYZE_TENANT", raising=False)
    monkeypatch.delenv("SCANALYZE_TENANTS", raising=False)
    with patch("src.postprocess_worker.config.boto3.client") as boto_client:
        with pytest.raises(RuntimeError, match="SCANALYZE_TENANT is required"):
            ConfigCache()
    boto_client.assert_not_called()


def test_validation_summary_omits_input_value():
    sensitive_value = "SYNTHETIC-SENSITIVE-VALUE"
    with pytest.raises(ValidationError) as captured:
        _StrictPayload(status_code=sensitive_value)

    details = safe_error_details(captured.value)

    assert details["errorCount"] == 1
    assert details["invalidFields"] == ["status_code"]
    assert sensitive_value not in repr(details)


def test_poison_message_log_omits_body():
    sensitive_value = "SYNTHETIC-SENSITIVE-VALUE"
    malformed_body = '{"documentId":"' + sensitive_value + '"'

    with patch("src.postprocess_worker.processors.validate.log_event") as log_event:
        assert process_validate_message(
            malformed_body,
            "receipt",
            "https://sqs.invalid/validate",
            "platform",
        ) is False

    logged = log_event.call_args
    assert "body" not in logged.kwargs
    assert "body_snippet" not in logged.kwargs
    assert "error" not in logged.kwargs
    assert sensitive_value not in repr(logged)


@pytest.mark.parametrize(
    "processor",
    (process_validate_message, process_persist_message, process_notify_message),
)
def test_invalid_stage_contract_is_left_for_redrive(processor):
    assert processor(
        "{}",
        "receipt",
        "https://sqs.invalid/postprocess",
        "platform",
    ) is False


def _validate_message(*, tenant="bank", bucket="structured-bucket", key="bank/doc-123/result.json"):
    return json.dumps(
        {
            "schemaVersion": "scanalyze.validate.v1",
            "documentId": "doc-123",
            "structured": {"bucket": bucket, "key": key},
            "meta": {
                "env": config.env,
                "tenant": tenant,
                "schema_version": "1.0",
                "prompt_version": "1.0",
            },
        }
    )


def _config_value(_tenant, key, default=None):
    values = {
        "data-foundation/structured_bucket_name": "structured-bucket",
        "data-foundation/documents_table_name": "documents",
        "queues/persist_url": "https://sqs.invalid/persist",
        "queues/notify_url": "https://sqs.invalid/notify",
    }
    return values.get(key, default)


def _stored_validation(_table_name, _route, _document_id, payload):
    return payload["validation"]


def _persist_message():
    return json.dumps(
        {
            "schemaVersion": "scanalyze.persist.v1",
            "documentId": "doc-123",
            "structured": {
                "bucket": "structured-bucket",
                "key": "bank/doc-123/result.json",
            },
            "validation": {
                "status": "PASS",
                "errors": [],
                "validatedAt": "2026-01-01T00:00:00Z",
            },
            "meta": {
                "env": config.env,
                "tenant": "bank",
                "schema_version": "1.0",
                "prompt_version": "1.0",
            },
        }
    )


def test_validate_route_mismatch_has_no_s3_or_dynamo_side_effect():
    with (
        patch("src.postprocess_worker.processors.validate.s3_client.get_object") as get_object,
        patch("src.postprocess_worker.processors.validate.update_validate_stage") as update_stage,
    ):
        result = process_validate_message(
            _validate_message(tenant="personal"),
            "receipt",
            "https://sqs.invalid/validate",
            "bank",
        )

    assert result is False
    get_object.assert_not_called()
    update_stage.assert_not_called()


def test_validate_missing_bucket_records_fail_without_s3_fallback():
    body = _validate_message(bucket=None)
    with (
        patch(
            "src.postprocess_worker.processors.validate.config.get",
            side_effect=_config_value,
        ),
        patch("src.postprocess_worker.processors.validate.s3_client.get_object") as get_object,
        patch(
            "src.postprocess_worker.processors.validate.update_validate_stage",
            side_effect=_stored_validation,
        ) as update_stage,
        patch(
            "src.postprocess_worker.processors.validate.sqs_client.send_message",
            return_value={"MessageId": "synthetic"},
        ),
    ):
        result = process_validate_message(
            body,
            "receipt",
            "https://sqs.invalid/validate",
            "bank",
        )

    assert result is True
    get_object.assert_not_called()
    validation_payload = update_stage.call_args.args[3]
    assert validation_payload["validation"]["status"] == "FAIL"
    assert validation_payload["validation"]["errors"][0]["code"] == "MISSING_ARTIFACT"


def test_validate_non_object_artifact_records_fail():
    response_body = Mock()
    response_body.read.return_value = b"[]"
    with (
        patch(
            "src.postprocess_worker.processors.validate.config.get",
            side_effect=_config_value,
        ),
        patch(
            "src.postprocess_worker.processors.validate.s3_client.get_object",
            return_value={"Body": response_body},
        ),
        patch(
            "src.postprocess_worker.processors.validate.update_validate_stage",
            side_effect=_stored_validation,
        ) as update_stage,
        patch(
            "src.postprocess_worker.processors.validate.sqs_client.send_message",
            return_value={"MessageId": "synthetic"},
        ),
    ):
        result = process_validate_message(
            _validate_message(),
            "receipt",
            "https://sqs.invalid/validate",
            "bank",
        )

    assert result is True
    validation_payload = update_stage.call_args.args[3]
    assert validation_payload["validation"]["status"] == "FAIL"
    assert validation_payload["validation"]["errors"][0]["code"] == "INVALID_ARTIFACT"


def test_platform_worker_accepts_valid_bank_route_and_records_pass():
    response_body = Mock()
    response_body.read.return_value = json.dumps(
        {
            "documentId": "doc-123",
            "docType": "bank_statement",
            "schema_version": "1.0",
            "balances": {},
            "transactions": [],
        }
    ).encode("utf-8")
    with (
        patch(
            "src.postprocess_worker.processors.validate.config.get",
            side_effect=_config_value,
        ),
        patch(
            "src.postprocess_worker.processors.validate.s3_client.get_object",
            return_value={"Body": response_body},
        ),
        patch(
            "src.postprocess_worker.processors.validate.update_validate_stage",
            side_effect=_stored_validation,
        ) as update_stage,
        patch(
            "src.postprocess_worker.processors.validate.sqs_client.send_message",
            return_value={"MessageId": "synthetic"},
        ),
    ):
        result = process_validate_message(
            _validate_message(),
            "receipt",
            "https://sqs.invalid/shared",
            "platform",
        )

    assert result is True
    assert update_stage.call_args.args[1] == "bank"
    assert update_stage.call_args.args[3]["validation"]["status"] == "PASS"


def test_rejected_persist_transition_cannot_enqueue_notify():
    with (
        patch(
            "src.postprocess_worker.processors.persist.config.get",
            side_effect=_config_value,
        ),
        patch(
            "src.postprocess_worker.processors.persist.update_persist_stage",
            side_effect=RuntimeError("transition rejected"),
        ),
        patch("src.postprocess_worker.processors.persist.sqs_client.send_message") as send_message,
    ):
        result = process_persist_message(
            _persist_message(),
            "receipt",
            "https://sqs.invalid/shared",
            "platform",
        )

    assert result is False
    send_message.assert_not_called()


def test_valid_persist_uses_authoritative_completion_time_for_notify():
    stored_completed_at = "2026-01-01T00:00:00Z"
    with (
        patch(
            "src.postprocess_worker.processors.persist.config.get",
            side_effect=_config_value,
        ),
        patch(
            "src.postprocess_worker.processors.persist.update_persist_stage",
            return_value=stored_completed_at,
        ) as update_stage,
        patch(
            "src.postprocess_worker.processors.persist.sqs_client.send_message",
            return_value={"MessageId": "synthetic"},
        ) as send_message,
    ):
        result = process_persist_message(
            _persist_message(),
            "receipt",
            "https://sqs.invalid/shared",
            "platform",
        )

    assert result is True
    assert update_stage.call_args.args[1] == "bank"
    assert update_stage.call_args.args[3]["status"] == "COMPLETED"
    notify_body = json.loads(send_message.call_args.kwargs["MessageBody"])
    assert notify_body["result"]["completedAt"] == stored_completed_at
