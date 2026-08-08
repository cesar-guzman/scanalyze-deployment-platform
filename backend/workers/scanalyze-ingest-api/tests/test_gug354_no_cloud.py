from __future__ import annotations

import socket
import urllib.request

import pytest
from pydantic import ValidationError

from app import aws_clients
from app.config import Settings
from app.errors import AppError
from app.services.journey import JourneyService


class SyntheticSettings:
    documents_table_name = "synthetic-documents"
    operation_ledger_table_name = "synthetic-documents"

    @staticmethod
    def get_bucket(alias: str) -> str | None:
        return {
            "raw": "synthetic-raw",
            "structured": "synthetic-structured",
        }.get(alias)


def _forbidden_cloud(*_args: object, **_kwargs: object) -> object:
    raise AssertionError("a real cloud or network constructor was invoked")


def test_fully_injected_journey_service_constructs_no_aws_or_network_client(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for name in (
        "AWS_PROFILE",
        "AWS_DEFAULT_PROFILE",
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "AWS_SESSION_TOKEN",
    ):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("AWS_EC2_METADATA_DISABLED", "true")
    monkeypatch.setattr(aws_clients, "s3_client", _forbidden_cloud)
    monkeypatch.setattr(aws_clients, "dynamodb_resource", _forbidden_cloud)
    monkeypatch.setattr(aws_clients.boto3, "client", _forbidden_cloud)
    monkeypatch.setattr(aws_clients.boto3, "resource", _forbidden_cloud)
    monkeypatch.setattr(socket.socket, "connect", _forbidden_cloud)
    monkeypatch.setattr(urllib.request, "urlopen", _forbidden_cloud)

    operations = object()
    batches = object()
    documents = object()
    s3 = object()
    legacy = object()
    service = JourneyService(
        settings=SyntheticSettings(),
        operations=operations,
        batches_repo=batches,
        documents_repo=documents,
        s3=s3,
        legacy_documents_service=legacy,
    )

    assert service.operations is operations
    assert service.batches_repo is batches
    assert service.documents_repo is documents
    assert service.s3 is s3
    assert service._legacy_documents_service is legacy


def test_missing_or_separate_ledger_configuration_fails_before_aws_construction(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(aws_clients, "dynamodb_resource", _forbidden_cloud)
    monkeypatch.setattr(aws_clients.boto3, "resource", _forbidden_cloud)

    class MisconfiguredSettings(SyntheticSettings):
        operation_ledger_table_name = "synthetic-other-table"

    with pytest.raises(AppError) as captured:
        JourneyService(
            settings=MisconfiguredSettings(),
            batches_repo=object(),
            documents_repo=object(),
            s3=object(),
        )

    assert captured.value.code == "SERVICE_UNAVAILABLE"
    assert captured.value.status_code == 503


def test_real_settings_parse_structured_bucket_and_bounded_journey_controls() -> None:
    settings = Settings(
        STRUCTURED_BUCKET="synthetic-structured-direct",
        BUCKETS_JSON={},
        JOURNEY_OPERATION_RETENTION_SECONDS=2_592_000,
        JOURNEY_PENDING_RECONCILIATION_GRACE_SECONDS=30,
    )
    json_settings = Settings(
        STRUCTURED_BUCKET="synthetic-structured-direct",
        BUCKETS_JSON='{"structured":"synthetic-structured-json"}',
    )

    assert settings.get_bucket("structured") == "synthetic-structured-direct"
    assert json_settings.get_bucket("structured") == "synthetic-structured-json"
    assert settings.journey_operation_retention_seconds == 2_592_000
    assert settings.journey_pending_reconciliation_grace_seconds == 30


@pytest.mark.parametrize(
    "overrides",
    [
        {"JOURNEY_OPERATION_RETENTION_SECONDS": 2_591_999},
        {"JOURNEY_PENDING_RECONCILIATION_GRACE_SECONDS": 4},
        {"JOURNEY_PENDING_RECONCILIATION_GRACE_SECONDS": 301},
    ],
)
def test_real_settings_reject_journey_controls_outside_reviewed_bounds(
    overrides: dict[str, int],
) -> None:
    with pytest.raises(ValidationError):
        Settings(**overrides)
