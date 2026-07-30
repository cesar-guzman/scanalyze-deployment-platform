import json
from unittest.mock import Mock, patch

import pytest
from pydantic import BaseModel, ValidationError

from src.postprocess_worker.config import ConfigCache, config
from src.postprocess_worker.logger import safe_error_details
from src.postprocess_worker.processors import notify as notify_processor
from src.postprocess_worker.processors import persist as persist_processor
from src.postprocess_worker.processors import validate as validate_processor
from src.postprocess_worker.processors.notify import process_notify_message
from src.postprocess_worker.processors.persist import process_persist_message
from src.postprocess_worker.processors.validate import process_validate_message

CUSTOMER_ID = "cust_01ARZ3NDEKTSV4RRFFQ69G5FAW"
DEPLOYMENT_ID = "dep_01ARZ3NDEKTSV4RRFFQ69G5FAV"


@pytest.fixture(autouse=True)
def _authorized_document_boundary(monkeypatch):
    authorized = lambda *args, **kwargs: {  # noqa: E731
        "customer_id": CUSTOMER_ID,
        "deployment_id": DEPLOYMENT_ID,
        "ownership_schema_version": 1,
        "processing_domain": "bank",
    }
    monkeypatch.setattr(validate_processor, "require_authorized_document", authorized)
    monkeypatch.setattr(persist_processor, "require_authorized_document", authorized)
    monkeypatch.setattr(notify_processor, "require_authorized_document", authorized)


def _ownership(stage, domain="bank"):
    return {
        "customer_id": CUSTOMER_ID,
        "deployment_id": DEPLOYMENT_ID,
        "ownership_schema_version": 1,
        "pipeline_stage": stage,
        "processing_domain": domain,
    }


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


def _validate_message(*, tenant="bank", bucket="structured-bucket", key="customers/cust_01ARZ3NDEKTSV4RRFFQ69G5FAW/deployments/dep_01ARZ3NDEKTSV4RRFFQ69G5FAV/documents/doc-123/structured/bank/result.json"):
    return json.dumps(
        {
            "schemaVersion": "scanalyze.validate.v2",
            "documentId": "doc-123",
            **_ownership("validate", tenant),
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


def _stored_validation(
    _table_name,
    _route,
    _document_id,
    _customer_id,
    _deployment_id,
    payload,
):
    return payload["validation"]


def _persist_message():
    return json.dumps(
        {
            "schemaVersion": "scanalyze.persist.v2",
            "documentId": "doc-123",
            **_ownership("persist"),
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
                "env": config.env,
                "tenant": "bank",
                "schema_version": "1.0",
                "prompt_version": "1.0",
            },
        }
    )


def _notify_message():
    return json.dumps(
        {
            "schemaVersion": "scanalyze.notify.v2",
            "documentId": "doc-123",
            **_ownership("notify"),
            "result": {
                "finalStatus": "COMPLETED",
                "completedAt": "2026-01-01T00:00:00Z",
                "validationStatus": "PASS",
            },
            "meta": {"env": config.env, "tenant": "bank"},
        }
    )


@pytest.mark.parametrize(
    ("module", "processor", "body"),
    (
        (validate_processor, process_validate_message, _validate_message),
        (persist_processor, process_persist_message, _persist_message),
        (notify_processor, process_notify_message, _notify_message),
    ),
)
def test_runtime_deployment_mismatch_has_zero_side_effects(module, processor, body):
    with (
        patch.object(
            module.config,
            "require_owner",
            side_effect=ValueError("runtime owner mismatch"),
        ),
        patch.object(module.config, "get") as config_get,
        patch.object(module, "require_authorized_document") as authorize,
    ):
        assert processor(
            body(),
            "receipt",
            "https://sqs.invalid/postprocess",
            "platform",
        ) is False

    config_get.assert_not_called()
    authorize.assert_not_called()


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


def test_validate_rejects_authority_in_trace_metadata_before_side_effects():
    payload = json.loads(_validate_message())
    payload["_metadata"] = {"customer_id": CUSTOMER_ID}
    with (
        patch("src.postprocess_worker.processors.validate.s3_client.get_object") as get_object,
        patch("src.postprocess_worker.processors.validate.update_validate_stage") as update_stage,
    ):
        result = process_validate_message(
            json.dumps(payload),
            "receipt",
            "https://sqs.invalid/validate",
            "bank",
        )

    assert result is False
    get_object.assert_not_called()
    update_stage.assert_not_called()


def test_validate_foreign_document_stops_before_s3_or_state_transition():
    with (
        patch(
            "src.postprocess_worker.processors.validate.config.get",
            side_effect=_config_value,
        ),
        patch(
            "src.postprocess_worker.processors.validate.require_authorized_document",
            side_effect=ValueError("Document is unavailable"),
        ),
        patch("src.postprocess_worker.processors.validate.s3_client.get_object") as get_object,
        patch("src.postprocess_worker.processors.validate.update_validate_stage") as update_stage,
    ):
        result = process_validate_message(
            _validate_message(),
            "receipt",
            "https://sqs.invalid/validate",
            "bank",
        )

    assert result is False
    get_object.assert_not_called()
    update_stage.assert_not_called()


def test_validate_missing_bucket_is_rejected_without_side_effects():
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

    assert result is False
    get_object.assert_not_called()
    update_stage.assert_not_called()


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
    validation_payload = update_stage.call_args.args[5]
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
    assert update_stage.call_args.args[5]["validation"]["status"] == "PASS"


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
    assert update_stage.call_args.args[5]["status"] == "COMPLETED"
    notify_body = json.loads(send_message.call_args.kwargs["MessageBody"])
    assert notify_body["result"]["completedAt"] == stored_completed_at
