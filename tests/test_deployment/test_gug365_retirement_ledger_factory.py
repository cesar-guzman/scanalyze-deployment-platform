"""Fail-closed tests for the dedicated one-shot GUG-365 ledger factory."""

from __future__ import annotations

import json
from pathlib import Path
import sys
from typing import Any

import pytest


ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tooling import platform_authority_retirement_ledger_factory as factory  # noqa: E402


REVISION = "revision-1"
KMS_KEY_ID = "11111111-2222-3333-4444-555555555555"
KMS_KEY_ARN = (
    f"arn:aws:kms:{factory.REGION}:{factory.AUTHORITY_ACCOUNT_ID}:"
    f"key/{KMS_KEY_ID}"
)


class Context:
    function_version = "7"
    invoked_function_arn = factory._factory_function_arn(version="7")


class ProviderError(Exception):
    def __init__(self, code: str) -> None:
        self.response = {"Error": {"Code": code}}
        super().__init__("sensitive provider error must not escape")


def table(
    status: str = "ACTIVE", *, kms_key_arn: str = KMS_KEY_ARN
) -> dict[str, Any]:
    return {
        "TableName": factory.LEDGER_TABLE_NAME,
        "TableArn": factory._table_arn(),
        "TableStatus": status,
        "KeySchema": [{"AttributeName": "retirement_id", "KeyType": "HASH"}],
        "AttributeDefinitions": [
            {"AttributeName": "retirement_id", "AttributeType": "S"}
        ],
        "DeletionProtectionEnabled": True,
        "BillingModeSummary": {"BillingMode": "PAY_PER_REQUEST"},
        "SSEDescription": {
            "Status": "ENABLED",
            "SSEType": "KMS",
            "KMSMasterKeyArn": kms_key_arn,
        },
        "TableClassSummary": {"TableClass": "STANDARD"},
    }


def pitr(enabled: bool) -> dict[str, Any]:
    return {
        "ContinuousBackupsDescription": {
            "ContinuousBackupsStatus": "ENABLED",
            "PointInTimeRecoveryDescription": {
                "PointInTimeRecoveryStatus": "ENABLED" if enabled else "DISABLED",
                **({"RecoveryPeriodInDays": 35} if enabled else {}),
            },
        }
    }


def tags() -> list[dict[str, str]]:
    return [
        {"Key": key, "Value": value}
        for key, value in factory.EXPECTED_LEDGER_TAGS.items()
    ]


class FakeSts:
    def __init__(self, calls: list[str], *, wrong: bool = False) -> None:
        self.calls = calls
        self.wrong = wrong

    def get_caller_identity(self) -> dict[str, str]:
        self.calls.append("sts:GetCallerIdentity")
        account = "999988887777" if self.wrong else factory.AUTHORITY_ACCOUNT_ID
        return {
            "Account": account,
            "Arn": (
                f"arn:aws:sts::{account}:assumed-role/"
                f"{factory.FACTORY_ROLE_NAME}/one-shot"
            ),
        }


def kms_metadata(**changes: Any) -> dict[str, Any]:
    value: dict[str, Any] = {
        "AWSAccountId": factory.AUTHORITY_ACCOUNT_ID,
        "KeyId": KMS_KEY_ID,
        "Arn": KMS_KEY_ARN,
        "Enabled": True,
        "KeyUsage": "ENCRYPT_DECRYPT",
        "KeyState": "Enabled",
        "Origin": "AWS_KMS",
        "KeyManager": "AWS",
        "KeySpec": "SYMMETRIC_DEFAULT",
        "MultiRegion": False,
        "EncryptionAlgorithms": ["SYMMETRIC_DEFAULT"],
    }
    value.update(changes)
    return value


class FakeKms:
    def __init__(
        self,
        calls: list[str],
        *,
        metadata_values: list[dict[str, Any]] | None = None,
        raises: bool = False,
    ) -> None:
        self.calls = calls
        self.metadata_values = list(metadata_values or [kms_metadata()] * 10)
        self.raises = raises

    def describe_key(self, **kwargs: Any) -> dict[str, Any]:
        self.calls.append("kms:DescribeKey")
        assert kwargs == {"KeyId": factory.KMS_KEY_ALIAS}
        if self.raises:
            raise ProviderError("InternalException")
        return {"KeyMetadata": self.metadata_values.pop(0)}


class FakeDynamo:
    def __init__(
        self,
        calls: list[str],
        *,
        describe_states: list[str],
        policy_states: list[str] | None = None,
        pitr_states: list[bool] | None = None,
        create_raises: bool = False,
        update_raises: bool = False,
        create_response: object | None = None,
        tag_values: list[dict[str, str]] | None = None,
        scan_values: list[dict[str, Any]] | None = None,
        ttl_values: list[dict[str, Any]] | None = None,
        table_kms_key_arn: str = KMS_KEY_ARN,
    ) -> None:
        self.calls = calls
        self.describe_states = list(describe_states)
        self.policy_states = list(policy_states or ["EXACT"] * 10)
        self.pitr_states = list(pitr_states or [True] * 20)
        self.create_raises = create_raises
        self.update_raises = update_raises
        self.create_response = (
            {"TableDescription": table("CREATING")}
            if create_response is None
            else create_response
        )
        self.tag_values = tag_values or tags()
        self.scan_values = list(
            scan_values or [{"Count": 0, "ScannedCount": 0}] * 10
        )
        self.ttl_values = list(
            ttl_values or [{"TimeToLiveStatus": "DISABLED"}] * 10
        )
        self.table_kms_key_arn = table_kms_key_arn
        self.create_requests: list[dict[str, Any]] = []
        self.update_requests: list[dict[str, Any]] = []

    def describe_table(self, **kwargs: Any) -> dict[str, Any]:
        self.calls.append("dynamodb:DescribeTable")
        assert kwargs == {"TableName": factory.LEDGER_TABLE_NAME}
        state = self.describe_states.pop(0)
        if state == "ABSENT":
            raise ProviderError("ResourceNotFoundException")
        if state == "UNAVAILABLE":
            raise ProviderError("InternalServerError")
        return {"Table": table(state, kms_key_arn=self.table_kms_key_arn)}

    def create_table(self, **kwargs: Any) -> object:
        self.calls.append("dynamodb:CreateTable")
        self.create_requests.append(kwargs)
        if self.create_raises:
            raise ProviderError("InternalServerError")
        return self.create_response

    def get_resource_policy(self, **kwargs: Any) -> dict[str, Any]:
        self.calls.append("dynamodb:GetResourcePolicy")
        assert kwargs == {"ResourceArn": factory._table_arn()}
        state = self.policy_states.pop(0)
        if state == "ABSENT":
            raise ProviderError("PolicyNotFoundException")
        if state == "DRIFTED":
            policy = {"Version": "2012-10-17", "Statement": []}
        else:
            policy = factory.canonical_resource_policy()
        revision = "other-revision" if state == "EXACT_OTHER" else REVISION
        return {"Policy": json.dumps(policy), "RevisionId": revision}

    def list_tags_of_resource(self, **kwargs: Any) -> dict[str, Any]:
        self.calls.append("dynamodb:ListTagsOfResource")
        assert kwargs == {"ResourceArn": factory._table_arn()}
        return {"Tags": self.tag_values}

    def scan(self, **kwargs: Any) -> dict[str, Any]:
        self.calls.append("dynamodb:Scan")
        assert kwargs == {
            "TableName": factory.LEDGER_TABLE_NAME,
            "ConsistentRead": True,
            "Select": "COUNT",
            "Limit": 1,
        }
        return self.scan_values.pop(0)

    def update_continuous_backups(self, **kwargs: Any) -> dict[str, Any]:
        self.calls.append("dynamodb:UpdateContinuousBackups")
        self.update_requests.append(kwargs)
        if self.update_raises:
            raise ProviderError("InternalServerError")
        return pitr(True)

    def describe_continuous_backups(self, **kwargs: Any) -> dict[str, Any]:
        self.calls.append("dynamodb:DescribeContinuousBackups")
        assert kwargs == {"TableName": factory.LEDGER_TABLE_NAME}
        return pitr(self.pitr_states.pop(0))

    def describe_time_to_live(self, **kwargs: Any) -> dict[str, Any]:
        self.calls.append("dynamodb:DescribeTimeToLive")
        assert kwargs == {"TableName": factory.LEDGER_TABLE_NAME}
        return {"TimeToLiveDescription": self.ttl_values.pop(0)}


def clients(
    *,
    describe_states: list[str],
    wrong_identity: bool = False,
    kms_metadata_values: list[dict[str, Any]] | None = None,
    kms_raises: bool = False,
    **kwargs: Any,
) -> tuple[factory.BotoClients, list[str], FakeDynamo]:
    calls: list[str] = []
    dynamodb = FakeDynamo(calls, describe_states=describe_states, **kwargs)
    return (
        factory.BotoClients(
            sts=FakeSts(calls, wrong=wrong_identity),
            dynamodb=dynamodb,
            kms=FakeKms(
                calls,
                metadata_values=kms_metadata_values,
                raises=kms_raises,
            ),
        ),
        calls,
        dynamodb,
    )


def run(boto_clients: factory.BotoClients) -> dict[str, Any]:
    return factory.execute(
        event={}, context=Context(), clients=boto_clients, sleeper=lambda _: None
    )


def assert_sanitized(receipt: dict[str, Any]) -> None:
    encoded = factory.canonical_json(receipt)
    for secret in (
        factory.AUTHORITY_ACCOUNT_ID,
        factory.LEDGER_TABLE_NAME,
        factory._table_arn(),
        factory.FACTORY_ROLE_NAME,
        factory.RETIREMENT_BROKER_ROLE_NAME,
        factory.FACTORY_FUNCTION_NAME,
        "DenyWritesOutsideRetirementBroker",
        REVISION,
        KMS_KEY_ID,
        KMS_KEY_ARN,
        factory.KMS_KEY_ALIAS,
    ):
        assert secret not in encoded
    assert receipt["receipt_sha256"] == factory.canonical_digest(
        {key: value for key, value in receipt.items() if key != "receipt_sha256"}
    )


def test_factory_is_dedicated_and_policy_matches_materializer_contract() -> None:
    assert factory.EXPECTED_LEDGER_TAGS["managed_by"] == (
        "reviewed-direct-dynamodb"
    )
    from tooling import (
        platform_authority_retirement_entrypoint_service_role_materializer as materializer,
    )

    assert factory.FACTORY_FUNCTION_NAME != materializer.BROKER_FUNCTION_NAME
    assert factory.FACTORY_ROLE_NAME != materializer.BROKER_ROLE_NAME
    assert factory.canonical_resource_policy() == materializer._ledger_resource_policy()
    assert factory.CONTRACT_SHA256 == factory.canonical_digest(
        factory._contract_projection()
    )


def test_absence_twice_create_with_atomic_policy_pitr_and_full_readback() -> None:
    boto_clients, calls, dynamodb = clients(
        describe_states=["ABSENT", "ABSENT", "CREATING", "ACTIVE", "ACTIVE"]
    )

    receipt = run(boto_clients)

    assert receipt["status"] == "CREATED"
    assert receipt["create_table_call_count"] == 1
    assert receipt["update_pitr_call_count"] == 1
    assert receipt["retry_permitted"] is False
    assert dynamodb.create_requests == [factory.create_table_request()]
    assert dynamodb.create_requests[0]["ResourcePolicy"] == (
        factory.canonical_json(factory.canonical_resource_policy())
    )
    assert dynamodb.create_requests[0]["SSESpecification"] == {
        "Enabled": True,
        "SSEType": "KMS",
        "KMSMasterKeyId": factory.KMS_KEY_ALIAS,
    }
    assert dynamodb.update_requests == [factory.update_pitr_request()]
    assert calls[0] == "sts:GetCallerIdentity"
    assert calls.count("dynamodb:CreateTable") == 1
    assert calls.count("dynamodb:UpdateContinuousBackups") == 1
    assert calls.count("kms:DescribeKey") == 2
    assert calls.index("kms:DescribeKey") < calls.index("dynamodb:CreateTable")
    assert calls.count("dynamodb:DescribeTimeToLive") == 2
    assert calls.index("dynamodb:CreateTable") > 2
    assert calls.index("dynamodb:UpdateContinuousBackups") > calls.index(
        "dynamodb:Scan"
    )
    assert_sanitized(receipt)
    assert receipt["kms_key_arn_sha256"] == factory._secret_digest(
        "kms_key_arn", KMS_KEY_ARN
    )
    assert receipt["kms_key_metadata_sha256"] == factory.canonical_digest(
        factory._kms_key_projection(kms_metadata())
    )


def test_existing_exact_table_is_read_only_already_exact() -> None:
    boto_clients, calls, dynamodb = clients(describe_states=["ACTIVE", "ACTIVE"])

    receipt = run(boto_clients)

    assert receipt["status"] == "ALREADY_EXACT"
    assert receipt["create_table_call_count"] == 0
    assert receipt["update_pitr_call_count"] == 0
    assert dynamodb.create_requests == []
    assert dynamodb.update_requests == []
    assert "dynamodb:Scan" in calls
    assert_sanitized(receipt)


@pytest.mark.parametrize(
    "change",
    [
        {"policy_states": ["DRIFTED"]},
        {"pitr_states": [False]},
        {"tag_values": [{"Key": "managed_by", "Value": "manual"}]},
        {"scan_values": [{"Count": 1, "ScannedCount": 1}]},
        {"ttl_values": [{"TimeToLiveStatus": "ENABLED", "AttributeName": "ttl"}]},
        {"ttl_values": [{"TimeToLiveStatus": "DISABLED", "AttributeName": "ttl"}]},
    ],
)
def test_existing_incomplete_or_drifted_table_never_mutates(change: dict[str, Any]) -> None:
    boto_clients, _, dynamodb = clients(
        describe_states=["ACTIVE", "ACTIVE"], **change
    )
    receipt = run(boto_clients)
    assert receipt["status"] == "EXISTING_DRIFT_DENIED"
    assert receipt["next_required_action"] == "HUMAN_REVIEW_REQUIRED"
    assert dynamodb.create_requests == []
    assert dynamodb.update_requests == []


def test_absence_race_stops_before_create() -> None:
    boto_clients, calls, dynamodb = clients(
        describe_states=["ABSENT", "ACTIVE", "ACTIVE"]
    )
    receipt = run(boto_clients)
    assert receipt["status"] == "ALREADY_EXACT"
    assert dynamodb.create_requests == []
    assert calls.count("dynamodb:DescribeTable") == 3


@pytest.mark.parametrize(
    "metadata_change",
    [
        {"AWSAccountId": "999988887777"},
        {"KeyId": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"},
        {
            "Arn": (
                "arn:aws:kms:us-west-2:042360977644:key/"
                f"{KMS_KEY_ID}"
            )
        },
        {"Enabled": False},
        {"KeyUsage": "SIGN_VERIFY"},
        {"KeyState": "PendingDeletion"},
        {"Origin": "EXTERNAL"},
        {"KeyManager": "CUSTOMER"},
        {"KeySpec": "RSA_2048"},
        {"CustomerMasterKeySpec": "RSA_2048"},
        {"MultiRegion": True},
        {"EncryptionAlgorithms": ["RSAES_OAEP_SHA_256"]},
        {"CustomKeyStoreId": "cks-sensitive"},
        {"SigningAlgorithms": []},
    ],
)
def test_kms_metadata_drift_stops_before_create(
    metadata_change: dict[str, Any],
) -> None:
    boto_clients, calls, dynamodb = clients(
        describe_states=["ABSENT", "ABSENT"],
        kms_metadata_values=[kms_metadata(**metadata_change)],
    )
    receipt = run(boto_clients)
    assert receipt["status"] == "DENY"
    assert receipt["reason_code"] == "KMS_KEY_CONTROLS_CHANGED"
    assert receipt["create_table_call_count"] == 0
    assert calls.count("kms:DescribeKey") == 1
    assert "dynamodb:CreateTable" not in calls
    assert dynamodb.create_requests == []
    assert_sanitized(receipt)


def test_kms_read_unavailable_stops_before_create() -> None:
    boto_clients, calls, dynamodb = clients(
        describe_states=["ABSENT", "ABSENT"], kms_raises=True
    )
    receipt = run(boto_clients)
    assert receipt["status"] == "DENY"
    assert receipt["reason_code"] == "KMS_KEY_READ_UNAVAILABLE"
    assert receipt["create_table_call_count"] == 0
    assert calls[-1] == "kms:DescribeKey"
    assert dynamodb.create_requests == []


def test_final_kms_binding_change_is_uncertain() -> None:
    other_key_id = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
    other_key_arn = (
        f"arn:aws:kms:{factory.REGION}:{factory.AUTHORITY_ACCOUNT_ID}:"
        f"key/{other_key_id}"
    )
    boto_clients, _, _ = clients(
        describe_states=["ABSENT", "ABSENT", "ACTIVE", "ACTIVE"],
        kms_metadata_values=[
            kms_metadata(),
            kms_metadata(KeyId=other_key_id, Arn=other_key_arn),
        ],
    )
    receipt = run(boto_clients)
    assert receipt["status"] == "UNCERTAIN_RECONCILE_ONLY"
    assert receipt["reason_code"] == "FINAL_CERTIFICATION_NOT_PROVEN"
    assert receipt["kms_key_arn_sha256"] == factory._secret_digest(
        "kms_key_arn", KMS_KEY_ARN
    )
    assert_sanitized(receipt)


def test_table_kms_key_must_equal_resolved_aws_managed_alias() -> None:
    other_key_arn = (
        f"arn:aws:kms:{factory.REGION}:{factory.AUTHORITY_ACCOUNT_ID}:"
        "key/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
    )
    boto_clients, calls, dynamodb = clients(
        describe_states=["ABSENT", "ABSENT", "ACTIVE"],
        table_kms_key_arn=other_key_arn,
    )
    receipt = run(boto_clients)
    assert receipt["status"] == "UNCERTAIN_RECONCILE_ONLY"
    assert receipt["reason_code"] == "CREATE_TABLE_ACTIVE_NOT_PROVEN"
    assert calls.count("dynamodb:CreateTable") == 1
    assert "dynamodb:UpdateContinuousBackups" not in calls
    assert dynamodb.update_requests == []
    assert_sanitized(receipt)


@pytest.mark.parametrize(
    ("create_raises", "create_response"),
    [(True, None), (False, {}), (False, {"TableDescription": {"TableName": "wrong"}})],
)
def test_ambiguous_create_is_read_only_reconcile_without_pitr(
    create_raises: bool, create_response: object | None
) -> None:
    kwargs: dict[str, Any] = {"create_raises": create_raises}
    if create_response is not None:
        kwargs["create_response"] = create_response
    boto_clients, calls, dynamodb = clients(
        describe_states=["ABSENT", "ABSENT", "ACTIVE"], **kwargs
    )

    receipt = run(boto_clients)

    assert receipt["status"] == "UNCERTAIN_RECONCILE_ONLY"
    assert receipt["create_table_call_count"] == 1
    assert receipt["update_pitr_call_count"] == 0
    assert calls.count("dynamodb:CreateTable") == 1
    assert "dynamodb:UpdateContinuousBackups" not in calls
    assert dynamodb.update_requests == []


def test_create_convergence_exhaustion_never_retries_or_updates() -> None:
    boto_clients, calls, dynamodb = clients(
        describe_states=["ABSENT", "ABSENT"]
        + ["CREATING"] * factory.ACTIVE_READBACK_MAX_ATTEMPTS
    )

    receipt = run(boto_clients)

    assert receipt["status"] == "UNCERTAIN_RECONCILE_ONLY"
    assert calls.count("dynamodb:CreateTable") == 1
    assert "dynamodb:UpdateContinuousBackups" not in calls
    assert len(dynamodb.create_requests) == 1


def test_policy_eventual_consistency_polls_read_only_before_pitr() -> None:
    boto_clients, calls, dynamodb = clients(
        describe_states=["ABSENT", "ABSENT", "ACTIVE", "ACTIVE"],
        policy_states=["ABSENT", "ABSENT", "EXACT", "EXACT"],
    )

    receipt = run(boto_clients)

    assert receipt["status"] == "CREATED"
    assert receipt["policy_readback_attempt_count"] == 4
    assert calls.count("dynamodb:CreateTable") == 1
    assert calls.count("dynamodb:UpdateContinuousBackups") == 1
    assert calls.count("dynamodb:GetResourcePolicy") == 4


def test_update_exception_can_only_succeed_after_full_readback() -> None:
    boto_clients, calls, dynamodb = clients(
        describe_states=["ABSENT", "ABSENT", "ACTIVE", "ACTIVE"],
        update_raises=True,
        pitr_states=[False, True, True],
    )

    receipt = run(boto_clients)

    assert receipt["status"] == "CREATED_RECONCILED"
    assert receipt["update_pitr_call_count"] == 1
    assert calls.count("dynamodb:UpdateContinuousBackups") == 1
    assert len(dynamodb.update_requests) == 1


def test_pitr_exhaustion_is_terminal_and_never_retries_update() -> None:
    boto_clients, calls, dynamodb = clients(
        describe_states=["ABSENT", "ABSENT", "ACTIVE"],
        pitr_states=[False] * factory.PITR_READBACK_MAX_ATTEMPTS,
        update_raises=True,
    )

    receipt = run(boto_clients)

    assert receipt["status"] == "UNCERTAIN_RECONCILE_ONLY"
    assert receipt["pitr_readback_attempt_count"] == (
        factory.PITR_READBACK_MAX_ATTEMPTS
    )
    assert calls.count("dynamodb:UpdateContinuousBackups") == 1
    assert len(dynamodb.update_requests) == 1


def test_final_policy_revision_drift_is_uncertain() -> None:
    boto_clients, _, _ = clients(
        describe_states=["ABSENT", "ABSENT", "ACTIVE", "ACTIVE"],
        policy_states=["EXACT", "EXACT_OTHER"],
    )

    receipt = run(boto_clients)

    assert receipt["status"] == "UNCERTAIN_RECONCILE_ONLY"
    assert receipt["reason_code"] == "FINAL_CERTIFICATION_NOT_PROVEN"


def test_wrong_identity_event_or_unqualified_context_stops_before_dynamodb() -> None:
    boto_clients, calls, dynamodb = clients(
        describe_states=["ABSENT"], wrong_identity=True
    )
    with pytest.raises(
        factory.LedgerFactoryError, match="CALLER_IDENTITY_BINDING_MISMATCH"
    ):
        run(boto_clients)
    assert calls == ["sts:GetCallerIdentity"]
    assert dynamodb.create_requests == []

    boto_clients, calls, _ = clients(describe_states=["ABSENT"])
    with pytest.raises(factory.LedgerFactoryError, match="EMPTY_EVENT_REQUIRED"):
        factory.execute(
            event={"operation": "CREATE"},
            context=Context(),
            clients=boto_clients,
            sleeper=lambda _: None,
        )
    assert calls == []

    context = Context()
    context.invoked_function_arn = context.invoked_function_arn.rsplit(":", 1)[0]
    with pytest.raises(
        factory.LedgerFactoryError, match="DEDICATED_FUNCTION_VERSION_REQUIRED"
    ):
        factory.execute(
            event={}, context=context, clients=boto_clients, sleeper=lambda _: None
        )
    assert calls == []


def test_handler_sanitizes_internal_exceptions(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        factory.BotoClients,
        "create",
        classmethod(
            lambda cls: (_ for _ in ()).throw(
                RuntimeError(f"secret {factory._table_arn()}")
            )
        ),
    )
    receipt = factory.handler({}, Context())
    assert receipt["status"] == "DENY"
    assert receipt["reason_code"] == "LEDGER_FACTORY_INTERNAL_ERROR"
    assert_sanitized(receipt)


def test_source_has_two_bounded_writes_no_environment_and_zero_sdk_retries() -> None:
    source = (
        ROOT / "tooling/platform_authority_retirement_ledger_factory.py"
    ).read_text(encoding="utf-8")

    assert source.count(".create_table(") == 1
    assert source.count(".update_continuous_backups(") == 1
    assert ".put_resource_policy(" not in source
    assert 'retries={"max_attempts": 0, "mode": "standard"}' in source
    assert "os.environ" not in source
    assert "GUG365_PLAN_SHA256" not in source
    assert ".delete_" not in source
    assert ".put_item(" not in source
    assert ".update_item(" not in source
    assert ".delete_item(" not in source
    assert ".query(" not in source
    assert "print(" not in source
    assert "logging." not in source
