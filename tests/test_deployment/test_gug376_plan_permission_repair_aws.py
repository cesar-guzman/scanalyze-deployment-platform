from __future__ import annotations

from datetime import UTC, datetime
import json
from pathlib import Path
from typing import Any, Mapping

import pytest

from tooling.platform_authority_plan_permission_repair import (
    PlanPermissionRepairError,
    RepairBinding,
    build_plan_ledger,
    build_private_intent,
    build_reconcile_attempt,
    build_reconcile_attestation,
    immutable_configuration_digest_from_environment,
    transition_ledger,
)
from tooling import platform_authority_plan_permission_repair_aws as runtime


REPO_ROOT = Path(__file__).resolve().parents[2]
NOW = datetime(2026, 8, 30, 1, 3, tzinfo=UTC)


def _binding(
    *, identity_center_kms_key_arn: str | None = None
) -> RepairBinding:
    return RepairBinding.from_mapping(
        {
            "source_commit": "a" * 40,
            "repair_id": "gug376-plan-permission-repair-" + "b" * 64,
            "source_bundle_digest": "sha256:" + "c" * 64,
            "instance_arn": (
                "arn:aws:sso:::instance/ssoins-0123456789ABCDEF"
            ),
            "identity_store_id": "d-0123456789",
            "permission_set_arn": (
                "arn:aws:sso:::permissionSet/ssoins-0123456789ABCDEF/"
                "ps-0123456789ABCDEF"
            ),
            "repair_invoker_permission_set_arn": (
                "arn:aws:sso:::permissionSet/ssoins-0123456789ABCDEF/"
                "ps-fedcba9876543210"
            ),
            "permission_set_description": "Synthetic reviewed Plan policy",
            "permission_set_tags": {
                "environment": "non-production",
                "managed_by": "cloudformation",
                "production": "false",
                "service": "scanalyze-platform-authority",
                "work_package": "GUG-376",
            },
            "principal_id": "01234567-89ab-cdef-0123-456789abcdef",
            "role_arn": (
                "arn:aws:iam::042360977644:role/aws-reserved/"
                "sso.amazonaws.com/"
                "AWSReservedSSO_ScanalyzeAuthorityBootstrapPlan_"
                "0123456789abcdef"
            ),
            "role_name": (
                "AWSReservedSSO_ScanalyzeAuthorityBootstrapPlan_"
                "0123456789abcdef"
            ),
            "saml_provider_arn": (
                "arn:aws:iam::042360977644:saml-provider/"
                "AWSSSO_synthetic_DO_NOT_DELETE"
            ),
            "identity_center_kms_mode": (
                "CUSTOMER_MANAGED_KEY"
                if identity_center_kms_key_arn is not None
                else "AWS_OWNED_KMS_KEY"
            ),
            "identity_center_kms_key_arn": identity_center_kms_key_arn,
            "invocation_authority_graph_digest": "sha256:" + "d" * 64,
            "change_set_name": (
                "scanalyze-platform-authority-bootstrap-20300101000000"
            ),
            "ledger_table_name": (
                "scanalyze-platform-authority-plan-policy-repair-ledger"
            ),
            "ledger_kms_key_arn": (
                "arn:aws:kms:us-east-1:042360977644:key/"
                "01234567-89ab-cdef-0123-456789abcdef"
            ),
            "expected_artifact_code_sha256": (
                "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
            ),
            "expected_code_signing_config_arn": (
                "arn:aws:lambda:us-east-1:042360977644:"
                "code-signing-config:csc-0123456789abcdefg"
            ),
            "expected_signing_profile_version_arn": (
                "arn:aws:signer:us-east-1:042360977644:"
                "/signing-profiles/ScanalyzePlanRepair/0123456789"
            ),
            "not_before": "2026-08-30T01:00:00Z",
            "not_after": "2026-08-30T01:15:00Z",
            "plan_function_version": "1",
            "repair_function_version": "2",
            "reconcile_function_version": "3",
            "expected_boto3_version": "1.40.1",
            "expected_botocore_version": "1.40.1",
        }
    )


def _environment(
    *, identity_center_kms_key_arn: str | None = None
) -> tuple[dict[str, str], Mapping[str, Any]]:
    binding = _binding(
        identity_center_kms_key_arn=identity_center_kms_key_arn
    )
    intent = build_private_intent(binding, repo_root=REPO_ROOT)
    env = {
        "SOURCE_COMMIT": binding.source_commit,
        "SOURCE_BUNDLE_DIGEST": binding.source_bundle_digest,
        "REPAIR_ID": binding.repair_id,
        "PRINCIPAL_ID": binding.principal_id,
        "IDENTITY_STORE_ID": binding.identity_store_id,
        "IDENTITY_CENTER_INSTANCE_ARN": binding.instance_arn,
        "PLAN_PERMISSION_SET_ARN": binding.permission_set_arn,
        "EXPECTED_PERMISSION_SET_DESCRIPTION": (
            binding.permission_set_description
        ),
        "REPAIR_INVOKER_PERMISSION_SET_ARN": (
            binding.repair_invoker_permission_set_arn
        ),
        "CURRENT_POLICY_DIGEST": str(intent["predecessor_policy_digest"]),
        "DESIRED_POLICY_DIGEST": str(intent["target_policy_digest"]),
        "EXPECTED_PLAN_PERMISSION_SET_TAGS_JSON": json.dumps(
            dict(binding.permission_set_tags), sort_keys=True
        ),
        "BOOTSTRAP_CHANGE_SET_NAME": binding.change_set_name,
        "REPAIR_LEDGER_TABLE_NAME": binding.ledger_table_name,
        "REPAIR_LEDGER_KMS_KEY_ARN": binding.ledger_kms_key_arn,
        "EXPECTED_ARTIFACT_CODE_SHA256": (
            binding.expected_artifact_code_sha256
        ),
        "EXPECTED_CODE_SIGNING_CONFIG_ARN": (
            binding.expected_code_signing_config_arn
        ),
        "EXPECTED_SIGNING_PROFILE_VERSION_ARN": (
            binding.expected_signing_profile_version_arn
        ),
        "REPAIR_NOT_BEFORE": "2026-08-30T01:00:00Z",
        "REPAIR_NOT_AFTER": "2026-08-30T01:15:00Z",
        "PLAN_SAML_PROVIDER_ARN": binding.saml_provider_arn,
        "IDENTITY_CENTER_KMS_MODE": binding.identity_center_kms_mode,
        "IDENTITY_CENTER_KMS_KEY_ARN": (
            binding.identity_center_kms_key_arn or ""
        ),
        "EXPECTED_BOTO3_VERSION": binding.expected_boto3_version,
        "EXPECTED_BOTOCORE_VERSION": binding.expected_botocore_version,
    }
    env["IMMU_CONFIG_DIGEST"] = (
        immutable_configuration_digest_from_environment(env)
    )
    lock = {
        "record_type": runtime.RUNTIME_LOCK_TYPE,
        "schema_version": 1,
        "source_commit": binding.source_commit,
        "source_bundle_digest": binding.source_bundle_digest,
        "expected_boto3_version": binding.expected_boto3_version,
        "expected_botocore_version": binding.expected_botocore_version,
    }
    return env, lock


class _Boto:
    __version__ = "1.40.1"

    def __init__(self) -> None:
        self.clients_created = 0

    def client(self, *_args: Any, **_kwargs: Any) -> Any:
        self.clients_created += 1
        raise AssertionError("invalid static input must not create an SDK client")


class _Botocore:
    __version__ = "1.40.1"


class _Config:
    def __init__(self, **_kwargs: Any) -> None:
        pass


class _Context:
    @staticmethod
    def get_remaining_time_in_millis() -> int:
        return 600_000


@pytest.mark.parametrize(
    ("field", "value", "code"),
    [
        (
            "IDENTITY_CENTER_INSTANCE_ARN",
            "not-an-arn",
            "IMMUTABLE_CONFIGURATION_INVALID",
        ),
        (
            "CURRENT_POLICY_DIGEST",
            "sha256:" + "0" * 64,
            "IMMUTABLE_CONFIGURATION_DIGEST_MISMATCH",
        ),
        (
            "REPAIR_NOT_AFTER",
            "2026-08-30T01:16:00Z",
            "IMMUTABLE_CONFIGURATION_INVALID",
        ),
        (
            "EXPECTED_PLAN_PERMISSION_SET_TAGS_JSON",
            '{"bad key":"value"}',
            "IMMUTABLE_CONFIGURATION_INVALID",
        ),
        (
            "EXPECTED_PLAN_PERMISSION_SET_TAGS_JSON",
            '{"managed_by":"cloudformation","managed_by":"foreign"}',
            "IMMUTABLE_CONFIGURATION_INVALID",
        ),
    ],
)
def test_static_bindings_fail_before_any_sdk_client(
    field: str, value: str, code: str
) -> None:
    env, lock = _environment()
    env[field] = value
    boto = _Boto()
    with pytest.raises(PlanPermissionRepairError) as captured:
        runtime.build_runtime(
            mode="plan",
            env=env,
            context=_Context(),
            boto3_module=boto,
            botocore_module=_Botocore(),
            config_type=_Config,
            repo_root=REPO_ROOT,
            runtime_lock=lock,
            now=lambda: NOW,
        )
    assert captured.value.code == code
    assert boto.clients_created == 0


def test_environment_budget_fails_before_any_sdk_client() -> None:
    env, lock = _environment()
    env["EXPECTED_PERMISSION_SET_DESCRIPTION"] = "x" * 2500
    env["EXPECTED_PLAN_PERMISSION_SET_TAGS_JSON"] = "x" * 2500
    boto = _Boto()

    with pytest.raises(PlanPermissionRepairError) as captured:
        runtime.build_runtime(
            mode="plan",
            env=env,
            context=_Context(),
            boto3_module=boto,
            botocore_module=_Botocore(),
            config_type=_Config,
            repo_root=REPO_ROOT,
            runtime_lock=lock,
            now=lambda: NOW,
        )

    assert captured.value.code == "LAMBDA_ENVIRONMENT_BUDGET_EXCEEDED"
    assert boto.clients_created == 0


@pytest.mark.parametrize(
    "key_arn",
    (
        "arn:aws:kms:us-east-1:839393571433:key/"
        "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
        "arn:aws:kms:us-east-1:839393571433:key/"
        "mrk-0123456789abcdef0123456789abcdef",
    ),
)
def test_static_environment_preserves_canonical_customer_managed_key(
    key_arn: str,
) -> None:
    env, _ = _environment(identity_center_kms_key_arn=key_arn)

    seed = runtime._static_seed(env)  # noqa: SLF001
    runtime._validate_static_seed(seed, repo_root=REPO_ROOT)  # noqa: SLF001

    assert seed["identity_center_kms_mode"] == "CUSTOMER_MANAGED_KEY"
    assert seed["identity_center_kms_key_arn"] == key_arn
    intent = build_private_intent(
        _binding(identity_center_kms_key_arn=key_arn),
        repo_root=REPO_ROOT,
    )
    assert intent["schema_version"] == 2
    assert intent["identity_center_kms_key_arn"] == key_arn


def test_static_environment_preserves_unobserved_without_a_key() -> None:
    env, _ = _environment()
    env["IDENTITY_CENTER_KMS_MODE"] = "NOT_OBSERVED"
    env["IMMU_CONFIG_DIGEST"] = (
        immutable_configuration_digest_from_environment(env)
    )

    seed = runtime._static_seed(env)  # noqa: SLF001
    runtime._validate_static_seed(seed, repo_root=REPO_ROOT)  # noqa: SLF001

    assert seed["identity_center_kms_mode"] == "NOT_OBSERVED"
    assert seed["identity_center_kms_key_arn"] is None


def _instance_readback_adapter(
    response: Mapping[str, Any],
) -> tuple[runtime.AwsIdentityCenterAdapter, list[Mapping[str, Any]]]:
    calls: list[Mapping[str, Any]] = []

    class ReadOnlyIdentityCenter:
        @staticmethod
        def describe_instance(**request: Any) -> Mapping[str, Any]:
            calls.append(request)
            return response

    adapter = runtime.AwsIdentityCenterAdapter(
        sso_admin=ReadOnlyIdentityCenter(),
        identitystore=object(),
        authority_iam=object(),
        graph_supplier=lambda _stage, _seed: "sha256:" + "d" * 64,
        expected_description="Synthetic reviewed Plan policy",
        expected_plan_tags={"work_package": "GUG-376"},
        source_commit="a" * 40,
        remaining_time_ms=lambda: 600_000,
    )
    return adapter, calls


def _instance_response(intent: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "InstanceArn": intent["instance_arn"],
        "IdentityStoreId": intent["identity_store_id"],
        "OwnerAccountId": runtime.MANAGEMENT_ACCOUNT_ID,
        "Status": "ACTIVE",
    }


def test_instance_readback_accepts_only_absence_for_unobserved_seed() -> None:
    intent = build_private_intent(_binding(), repo_root=REPO_ROOT)
    intent["identity_center_kms_mode"] = "NOT_OBSERVED"
    adapter, calls = _instance_readback_adapter(_instance_response(intent))

    adapter._instance(intent)  # noqa: SLF001

    assert calls == [{"InstanceArn": intent["instance_arn"]}]
    assert intent["identity_center_kms_mode"] == "NOT_OBSERVED"
    assert intent["identity_center_kms_key_arn"] is None


@pytest.mark.parametrize(
    "details",
    (
        None,
        {},
        [],
        "invalid",
        {"KeyType": "AWS_OWNED_KMS_KEY"},
        {"EncryptionStatus": "ENABLED"},
        {"KeyType": "NOT_OBSERVED", "EncryptionStatus": "ENABLED"},
        {"KeyType": "AWS_OWNED_KMS_KEY", "EncryptionStatus": "UPDATING"},
        {"KeyType": "AWS_OWNED_KMS_KEY", "EncryptionStatus": "UPDATE_FAILED"},
        {
            "KeyType": "CUSTOMER_MANAGED_KEY",
            "EncryptionStatus": "ENABLED",
            "KmsKeyArn": "",
        },
    ),
)
def test_instance_readback_rejects_present_invalid_details_before_other_calls(
    details: Any,
) -> None:
    intent = build_private_intent(_binding(), repo_root=REPO_ROOT)
    intent["identity_center_kms_mode"] = "NOT_OBSERVED"
    response = _instance_response(intent)
    response["EncryptionConfigurationDetails"] = details
    adapter, calls = _instance_readback_adapter(response)

    with pytest.raises(PlanPermissionRepairError) as exc_info:
        adapter._capture(intent)  # noqa: SLF001
    assert exc_info.value.code == "KMS_READBACK_MALFORMED"
    assert len(calls) == 1


@pytest.mark.parametrize(
    ("kms_mode", "key_arn"),
    (
        ("AWS_OWNED_KMS_KEY", None),
        (
            "CUSTOMER_MANAGED_KEY",
            "arn:aws:kms:us-east-1:839393571433:key/"
            "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
        ),
    ),
)
@pytest.mark.parametrize("observed_after_materialization", (False, True))
def test_instance_readback_does_not_upgrade_or_downgrade_encryption_binding(
    kms_mode: str,
    key_arn: str | None,
    observed_after_materialization: bool,
) -> None:
    intent = build_private_intent(_binding(), repo_root=REPO_ROOT)
    response = _instance_response(intent)
    if observed_after_materialization:
        intent["identity_center_kms_mode"] = "NOT_OBSERVED"
        response["EncryptionConfigurationDetails"] = {
            "KeyType": kms_mode,
            "KmsKeyArn": key_arn,
            "EncryptionStatus": "ENABLED",
        }
    else:
        intent["identity_center_kms_mode"] = kms_mode
        intent["identity_center_kms_key_arn"] = key_arn
    adapter, calls = _instance_readback_adapter(response)

    with pytest.raises(PlanPermissionRepairError) as exc_info:
        adapter._capture(intent)  # noqa: SLF001
    assert exc_info.value.code == "KMS_READBACK_MISMATCH"
    assert len(calls) == 1


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("OwnerAccountId", runtime.AUTHORITY_ACCOUNT_ID),
        ("InstanceArn", "different-instance"),
        ("IdentityStoreId", "different-store"),
        ("Status", "CREATE_IN_PROGRESS"),
    ),
)
def test_unobserved_instance_readback_retains_identity_and_active_checks(
    field: str,
    value: str,
) -> None:
    intent = build_private_intent(_binding(), repo_root=REPO_ROOT)
    intent["identity_center_kms_mode"] = "NOT_OBSERVED"
    response = _instance_response(intent)
    response[field] = value
    adapter, calls = _instance_readback_adapter(response)

    with pytest.raises(PlanPermissionRepairError) as exc_info:
        adapter._capture(intent)  # noqa: SLF001
    assert exc_info.value.code == "INSTANCE_READBACK_MISMATCH"
    assert len(calls) == 1


def test_dynamo_cas_conditions_bind_every_expected_ledger_field() -> None:
    intent = build_private_intent(_binding(), repo_root=REPO_ROOT)
    expected = build_plan_ledger(
        intent, state_digest="sha256:" + "e" * 64, planned_at=NOW
    )
    replacement = transition_ledger(
        expected,
        expected_status="PLAN_VERIFIED",
        new_status="CLAIMED",
        stage="BEFORE_FIRST_EFFECT",
        effects_attempted=0,
        effects_completed=0,
        state_digest="sha256:" + "e" * 64,
        updated_at=NOW,
        claimed_at=NOW,
    )

    class Client:
        kwargs: dict[str, Any] | None = None

        def update_item(self, **kwargs: Any) -> Mapping[str, Any]:
            self.kwargs = kwargs
            return {"Attributes": runtime.DynamoLedger._encode(replacement)}

    client = Client()
    runtime.DynamoLedger(client, "exact-ledger").compare_and_swap(
        repair_id=str(expected["repair_id"]),
        expected_ledger_digest=str(expected["ledger_digest"]),
        expected_ledger=expected,
        replacement=replacement,
    )
    assert client.kwargs is not None
    names = client.kwargs["ExpressionAttributeNames"]
    condition = client.kwargs["ConditionExpression"]
    assert set(expected) <= set(names.values())
    assert condition.count(" = ") == len(expected)


def _terminal_ledger(intent: Mapping[str, Any]) -> dict[str, Any]:
    state_digest = "sha256:" + "e" * 64
    ledger = build_plan_ledger(
        intent, state_digest=state_digest, planned_at=NOW
    )
    for expected, new, stage, attempted, completed, claimed in (
        (
            "PLAN_VERIFIED",
            "CLAIMED",
            "BEFORE_FIRST_EFFECT",
            0,
            0,
            NOW,
        ),
        (
            "CLAIMED",
            "ATTEMPTING_1",
            "BEFORE_PUT_INLINE_POLICY",
            0,
            0,
            None,
        ),
        (
            "ATTEMPTING_1",
            "COMPLETED_1",
            "AFTER_PUT_INLINE_POLICY",
            1,
            1,
            None,
        ),
        (
            "COMPLETED_1",
            "ATTEMPTING_2",
            "BEFORE_PROVISION_PERMISSION_SET",
            1,
            1,
            None,
        ),
        (
            "ATTEMPTING_2",
            "COMPLETED_2",
            "AFTER_PROVISION_PERMISSION_SET",
            2,
            2,
            None,
        ),
        (
            "COMPLETED_2",
            "REPAIR_VERIFIED",
            "FINAL_READBACK_VERIFIED",
            2,
            2,
            None,
        ),
    ):
        ledger = transition_ledger(
            ledger,
            expected_status=expected,
            new_status=new,
            stage=stage,
            effects_attempted=attempted,
            effects_completed=completed,
            state_digest=state_digest,
            updated_at=NOW,
            claimed_at=claimed,
        )
    return ledger


def _uncertain_ledger(intent: Mapping[str, Any]) -> dict[str, Any]:
    state_digest = "sha256:" + "e" * 64
    ledger = build_plan_ledger(
        intent, state_digest=state_digest, planned_at=NOW
    )
    for expected, new, stage, attempted, completed, claimed in (
        (
            "PLAN_VERIFIED",
            "CLAIMED",
            "BEFORE_FIRST_EFFECT",
            0,
            0,
            NOW,
        ),
        (
            "CLAIMED",
            "ATTEMPTING_1",
            "BEFORE_PUT_INLINE_POLICY",
            0,
            0,
            None,
        ),
        (
            "ATTEMPTING_1",
            "UNCERTAIN_RECONCILE_ONLY",
            "UNCERTAIN_PUT_INLINE_POLICY",
            1,
            0,
            None,
        ),
    ):
        ledger = transition_ledger(
            ledger,
            expected_status=expected,
            new_status=new,
            stage=stage,
            effects_attempted=attempted,
            effects_completed=completed,
            state_digest=state_digest,
            updated_at=NOW,
            claimed_at=claimed,
        )
    return ledger


def test_dynamo_reconcile_attestation_is_conditional_and_strongly_read() -> None:
    intent = build_private_intent(_binding(), repo_root=REPO_ROOT)
    ledger = _terminal_ledger(intent)
    attestation = build_reconcile_attestation(
        intent,
        ledger,
        observed_state_digest=str(ledger["state_digest"]),
        reconciled_at=NOW,
    )

    class Client:
        put_kwargs: dict[str, Any] | None = None
        get_kwargs: dict[str, Any] | None = None

        def put_item(self, **kwargs: Any) -> Mapping[str, Any]:
            self.put_kwargs = kwargs
            return {}

        def get_item(self, **kwargs: Any) -> Mapping[str, Any]:
            self.get_kwargs = kwargs
            return {"Item": runtime.DynamoLedger._encode(attestation)}

    client = Client()
    adapter = runtime.DynamoLedger(client, "exact-ledger")
    adapter.put_reconcile_attestation(attestation)
    observed = adapter.read_reconcile_attestation(str(intent["repair_id"]))

    assert observed == attestation
    assert client.put_kwargs is not None
    assert client.put_kwargs["ConditionExpression"] == (
        "attribute_not_exists(repair_id)"
    )
    assert client.get_kwargs is not None
    assert client.get_kwargs["ConsistentRead"] is True
    assert client.get_kwargs["Key"]["repair_id"]["S"] == (
        str(intent["repair_id"]) + "#reconcile-v1"
    )


def test_dynamo_reconcile_attempt_is_conditional_and_strongly_read() -> None:
    intent = build_private_intent(_binding(), repo_root=REPO_ROOT)
    ledger = _uncertain_ledger(intent)
    attempt = build_reconcile_attempt(
        intent,
        ledger,
        claimed_at=NOW,
    )

    class Client:
        put_kwargs: dict[str, Any] | None = None
        get_kwargs: dict[str, Any] | None = None

        def put_item(self, **kwargs: Any) -> Mapping[str, Any]:
            self.put_kwargs = kwargs
            return {}

        def get_item(self, **kwargs: Any) -> Mapping[str, Any]:
            self.get_kwargs = kwargs
            return {"Item": runtime.DynamoLedger._encode(attempt)}

    client = Client()
    adapter = runtime.DynamoLedger(client, "exact-ledger")
    adapter.put_reconcile_attempt(attempt)
    observed = adapter.read_reconcile_attempt(str(intent["repair_id"]))

    assert observed == attempt
    assert client.put_kwargs is not None
    assert client.put_kwargs["ConditionExpression"] == (
        "attribute_not_exists(repair_id)"
    )
    assert client.get_kwargs is not None
    assert client.get_kwargs["ConsistentRead"] is True
    assert client.get_kwargs["Key"]["repair_id"]["S"] == (
        str(intent["repair_id"]) + "#reconcile-attempt-v1"
    )


def test_handler_rebinds_runtime_factory_after_test_isolation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from tooling import platform_authority_plan_permission_repair as core

    core.install_runtime_factory(None)

    def fail_before_provider(*_args: Any, **_kwargs: Any) -> Any:
        raise PlanPermissionRepairError("SYNTHETIC_BLOCK", "blocked")

    monkeypatch.setattr(runtime, "_runtime_factory", fail_before_provider)
    environment, _ = _environment()
    for key, value in environment.items():
        monkeypatch.setenv(key, value)
    monkeypatch.setenv("AWS_LAMBDA_FUNCTION_VERSION", "1")
    context = type(
        "Context",
        (),
        {
            "invoked_function_arn": (
                "arn:aws:lambda:us-east-1:042360977644:function:"
                "scanalyze-platform-authority-plan-policy-plan:plan-v1"
            ),
            "get_remaining_time_in_millis": lambda self: 300_000,
        },
    )()
    try:
        result, code = runtime._capture_handler("plan", {}, context)
        assert result is None
        assert code == "SYNTHETIC_BLOCK"
    finally:
        core.install_runtime_factory(None)
