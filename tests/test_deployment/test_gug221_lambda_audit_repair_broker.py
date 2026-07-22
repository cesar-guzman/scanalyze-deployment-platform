from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
import json
import sys

import pytest


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tooling"))

from platform_authority_lambda_audit_repair_broker import (  # noqa: E402
    Assignment,
    BrokerConfig,
    BrokerContractError,
    CollectorRole,
    LiveSnapshot,
    build_private_intent,
    build_public_receipt,
    canonical_digest,
    validate_empty_event,
    validate_invocation,
    validate_snapshot,
)


NOW = datetime(2026, 7, 21, 20, 0, tzinfo=timezone.utc)
POLICY = {"Version": "2012-10-17", "Statement": []}
POLICY_DIGEST = canonical_digest(POLICY)
INVOKER_POLICY = {"Version": "2012-10-17", "Statement": [{"Effect": "Deny", "Action": "*", "Resource": "*"}]}
INVOKER_POLICY_DIGEST = canonical_digest(INVOKER_POLICY)
PRINCIPAL_ID = "1234567890-11111111-2222-3333-4444-555555555555"
INSTANCE_ARN = "arn:aws:sso:::instance/ssoins-1234567890abcdef"
PERMISSION_SET_ARN = (
    "arn:aws:sso:::permissionSet/ssoins-1234567890abcdef/ps-fedcba0987654321"
)
INVOKER_PERMISSION_SET_ARN = (
    "arn:aws:sso:::permissionSet/ssoins-1234567890abcdef/ps-0123456789abcdef"
)
SAML_PROVIDER_ARN = (
    "arn:aws:iam::042360977644:saml-provider/"
    "AWSSSO_1234567890abcdef_DO_NOT_DELETE"
)
TAGS = {"scanalyze:control": "lambda-audit", "scanalyze:managed-by": "gug-221"}
ARTIFACT_CODE_SHA256 = "A" * 43 + "="
CODE_SIGNING_CONFIG_ARN = (
    "arn:aws:lambda:us-east-1:042360977644:"
    "code-signing-config:csc-1234567890abcdef0"
)
LEDGER_KMS_KEY_ARN = (
    "arn:aws:kms:us-east-1:042360977644:key/"
    "11111111-2222-3333-4444-555555555555"
)
SIGNING_PROFILE_VERSION_ARN = (
    "arn:aws:signer:us-east-1:042360977644:"
    "/signing-profiles/ScanalyzeGug221/ABCDEFGHIJ"
)


def env_for(mode: str = "repair", *, kms_mode: str = "AWS_OWNED_KMS_KEY") -> dict[str, str]:
    qualifiers = {"repair": "repair-v1", "plan": "plan-v1", "reconcile": "reconcile-v1"}
    version = "42" if mode == "repair" else "43"
    result = {
        "FUNCTION_MODE": mode,
        "FUNCTION_QUALIFIER": qualifiers[mode],
        "SOURCE_COMMIT": "a" * 40,
        "REPAIR_ID": "gug221-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "PRINCIPAL_ID": PRINCIPAL_ID,
        "IDENTITY_STORE_ID": "d-1234567890",
        "IDENTITY_CENTER_INSTANCE_ARN": INSTANCE_ARN,
        "COLLECTOR_PERMISSION_SET_ARN": PERMISSION_SET_ARN,
        "REPAIR_INVOKER_PERMISSION_SET_ARN": INVOKER_PERMISSION_SET_ARN,
        "COLLECTOR_POLICY_DIGEST": POLICY_DIGEST,
        "REPAIR_INVOKER_POLICY_DIGEST": INVOKER_POLICY_DIGEST,
        "ORIGINAL_GUG220_LEDGER_DIGEST": "c" * 64,
        "EXPECTED_PERMISSION_SET_TAGS_JSON": json.dumps(TAGS),
        "REPAIR_LEDGER_TABLE_NAME": (
            "scanalyze-platform-authority-gug221-repair-ledger"
        ),
        "REPAIR_LEDGER_KMS_KEY_ARN": LEDGER_KMS_KEY_ARN,
        "EXPECTED_ARTIFACT_CODE_SHA256": ARTIFACT_CODE_SHA256,
        "EXPECTED_CODE_SIGNING_CONFIG_ARN": CODE_SIGNING_CONFIG_ARN,
        "EXPECTED_SIGNING_PROFILE_VERSION_ARN": SIGNING_PROFILE_VERSION_ARN,
        "REPAIR_NOT_BEFORE": "2026-07-21T19:55:00Z",
        "REPAIR_NOT_AFTER": "2026-07-21T20:10:00Z",
        "AWS_LAMBDA_FUNCTION_VERSION": version,
        "EXPECTED_BOTO3_VERSION": "1.40.1",
        "EXPECTED_BOTOCORE_VERSION": "1.40.1",
        "REPAIR_FUNCTION_VERSION": "42",
        "PLAN_FUNCTION_VERSION": "43",
        "COLLECTOR_SAML_PROVIDER_ARN": SAML_PROVIDER_ARN,
        "IDENTITY_CENTER_KMS_MODE": kms_mode,
    }
    if kms_mode == "CUSTOMER_MANAGED_KEY":
        result["IDENTITY_CENTER_KMS_KEY_ARN"] = (
            "arn:aws:kms:us-east-1:839393571433:key/"
            "11111111-2222-3333-4444-555555555555"
        )
    return result


def config_for(mode: str = "repair", *, kms_mode: str = "AWS_OWNED_KMS_KEY") -> BrokerConfig:
    return BrokerConfig.from_env(env_for(mode, kms_mode=kms_mode))


def role_for(config: BrokerConfig, **changes: object) -> CollectorRole:
    values: dict[str, object] = {
        "role_name": "AWSReservedSSO_ScanalyzeAuthorityLambdaAudit_0123456789abcdef",
        "saml_provider_arn": config.collector_saml_provider_arn,
        "saml_audience": "https://signin.aws.amazon.com/saml",
        "inline_policy_name": "AwsSSOInlinePolicy",
        "inline_policy_digest": config.collector_policy_digest,
        "attached_managed_policy_arns": (),
        "extra_inline_policy_names": (),
        "permissions_boundary_arn": None,
    }
    values.update(changes)
    return CollectorRole(**values)  # type: ignore[arg-type]


def snapshot_for(config: BrokerConfig, stage: str = "initial", **changes: object) -> LiveSnapshot:
    values: dict[str, object] = {
        "instance_arn": config.instance_arn,
        "identity_store_id": config.identity_store_id,
        "kms_mode": config.identity_center_kms_mode,
        "kms_key_arn": config.identity_center_kms_key_arn,
        "permission_set_arn": config.collector_permission_set_arn,
        "permission_set_name": config.collector_permission_set_name,
        "permission_set_description": (
            "GUG-219 read-only account-wide Lambda invocation-authority inventory"
        ),
        "session_duration": "PT1H",
        "relay_state": None,
        "permission_set_tags": config.expected_permission_set_tags,
        "inline_policy_digest": None,
        "managed_policy_arns": (),
        "customer_managed_policy_references": (),
        "permissions_boundary_present": False,
        "assignments": (),
        "provisioned_account_ids": (),
        "collector_roles": (),
    }
    if stage in {"policy", "assignment", "final"}:
        values["inline_policy_digest"] = config.collector_policy_digest
    if stage in {"assignment", "final"}:
        values["assignments"] = (Assignment("USER", config.principal_id),)
    if stage == "final":
        values["provisioned_account_ids"] = (config.authority_account_id,)
        values["collector_roles"] = (role_for(config),)
    values.update(changes)
    return LiveSnapshot(**values)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "event",
    [None, [], "{}", {"mode": "repair"}, {"PrincipalId": PRINCIPAL_ID}, {"Account": "7644"}],
)
def test_authoritative_event_is_exactly_empty(event: object) -> None:
    with pytest.raises(BrokerContractError, match="exactly an empty JSON object"):
        validate_empty_event(event)
    validate_empty_event({})


def test_mode_override_ignores_spoofed_environment_mode() -> None:
    env = env_for("plan")
    env["FUNCTION_MODE"] = "repair"
    env["FUNCTION_QUALIFIER"] = "repair-v1"
    config = BrokerConfig.from_env(
        env,
        mode_override="plan",
        qualifier_override="plan-v1",
    )
    assert config.mode == "plan"
    assert config.function_qualifier == "plan-v1"


def test_repair_intent_digest_is_shared_by_plan_repair_and_reconcile() -> None:
    digests = {
        canonical_digest(build_private_intent(config_for(mode)))
        for mode in ("plan", "repair", "reconcile")
    }
    assert len(digests) == 1


@pytest.mark.parametrize(
    ("field", "value", "code"),
    [
        ("EXPECTED_BOTO3_VERSION", None, "MISSING_CONFIG"),
        ("EXPECTED_BOTOCORE_VERSION", "latest", "INVALID_SDK_VERSION"),
        ("EXPECTED_BOTO3_VERSION", "01.40.1", "INVALID_SDK_VERSION"),
    ],
)
def test_runtime_sdk_version_configuration_is_required_and_exact(
    field: str, value: str | None, code: str
) -> None:
    env = env_for()
    if value is None:
        env.pop(field)
    else:
        env[field] = value
    with pytest.raises(BrokerContractError) as captured:
        BrokerConfig.from_env(env)
    assert captured.value.code == code


def test_repair_derives_its_version_and_plan_can_provider_derive_repair_version() -> None:
    repair_env = env_for("repair")
    repair_env.pop("REPAIR_FUNCTION_VERSION")
    repair = BrokerConfig.from_env(repair_env)
    assert repair.repair_function_version == repair.function_version == "42"

    plan_env = env_for("plan")
    plan_env.pop("REPAIR_FUNCTION_VERSION")
    plan = BrokerConfig.from_env(plan_env)
    assert plan.repair_function_version == "PROVIDER_DERIVED"


def test_aws_owned_and_customer_managed_kms_modes_are_exact() -> None:
    assert config_for(kms_mode="AWS_OWNED_KMS_KEY").identity_center_kms_key_arn is None
    assert config_for(kms_mode="CUSTOMER_MANAGED_KEY").identity_center_kms_key_arn

    invalid = env_for(kms_mode="AWS_OWNED_KMS_KEY")
    invalid["IDENTITY_CENTER_KMS_KEY_ARN"] = (
        "arn:aws:kms:us-east-1:839393571433:key/"
        "11111111-2222-3333-4444-555555555555"
    )
    with pytest.raises(BrokerContractError, match="cannot carry"):
        BrokerConfig.from_env(invalid)


@pytest.mark.parametrize(
    ("mode", "function_name", "role_name"),
    [
        ("repair", "scanalyze-authority-lambda-audit-repair", "ScanalyzeLambdaAuditRepairExecution"),
        ("plan", "scanalyze-authority-lambda-audit-plan", "ScanalyzeLambdaAuditRepairPlan"),
        ("reconcile", "scanalyze-authority-lambda-audit-reconcile", "ScanalyzeLambdaAuditRepairReconcile"),
    ],
)
def test_function_role_and_alias_bindings_are_mode_specific(
    mode: str, function_name: str, role_name: str
) -> None:
    config = config_for(mode)
    validate_invocation(
        config,
        f"arn:aws:lambda:us-east-1:042360977644:function:{function_name}:{config.function_qualifier}",
        f"arn:aws:sts::042360977644:assumed-role/{role_name}/runtime-session",
    )


def test_crossed_function_or_execution_role_is_rejected() -> None:
    config = config_for("repair")
    with pytest.raises(BrokerContractError):
        validate_invocation(
            config,
            "arn:aws:lambda:us-east-1:042360977644:function:"
            "scanalyze-authority-lambda-audit-reconcile:repair-v1",
            "arn:aws:sts::042360977644:assumed-role/"
            "ScanalyzeLambdaAuditRepairExecution/runtime-session",
        )
    with pytest.raises(BrokerContractError):
        validate_invocation(
            config,
            "arn:aws:lambda:us-east-1:042360977644:function:"
            "scanalyze-authority-lambda-audit-repair:repair-v1",
            "arn:aws:sts::042360977644:assumed-role/"
            "ScanalyzeLambdaAuditRepairReconcile/runtime-session",
        )


def test_stage_contract_accepts_only_exact_state_vector() -> None:
    config = config_for()
    validate_snapshot(config, snapshot_for(config), "BEFORE_PUT_INLINE_POLICY")
    validate_snapshot(config, snapshot_for(config, "policy"), "BEFORE_CREATE_ACCOUNT_ASSIGNMENT")
    validate_snapshot(config, snapshot_for(config, "assignment"), "BEFORE_PROVISION_PERMISSION_SET")
    validate_snapshot(config, snapshot_for(config, "final"), "FINAL")


def test_group_foreign_principal_and_policy_attachments_fail_closed() -> None:
    config = config_for()
    for snapshot in (
        snapshot_for(config, assignments=(Assignment("GROUP", config.principal_id),)),
        snapshot_for(
            config,
            assignments=(Assignment("USER", "abcdef1234-aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"),),
        ),
        snapshot_for(config, managed_policy_arns=("arn:aws:iam::aws:policy/ReadOnlyAccess",)),
        snapshot_for(config, permissions_boundary_present=True),
        snapshot_for(config, provisioned_account_ids=("999999999999",)),
        snapshot_for(config, permission_set_description="foreign"),
        snapshot_for(config, session_duration="PT8H"),
        snapshot_for(config, relay_state="https://example.invalid"),
    ):
        with pytest.raises(BrokerContractError):
            validate_snapshot(config, snapshot, "BEFORE_PUT_INLINE_POLICY")


def test_collector_role_policy_trust_and_boundary_are_exact() -> None:
    config = config_for()
    for role in (
        role_for(config, inline_policy_digest="0" * 64),
        role_for(config, saml_provider_arn=SAML_PROVIDER_ARN.replace("1234", "9999")),
        role_for(config, attached_managed_policy_arns=("arn:aws:iam::aws:policy/ReadOnlyAccess",)),
        role_for(config, permissions_boundary_arn="arn:aws:iam::042360977644:policy/foreign"),
    ):
        with pytest.raises(BrokerContractError):
            validate_snapshot(
                config,
                snapshot_for(config, "final", collector_roles=(role,)),
                "FINAL",
            )


def test_public_receipt_contains_only_sanitized_bindings() -> None:
    config = config_for()
    receipt = build_public_receipt(
        config=config,
        status="REPAIR_VERIFIED",
        intent_digest="1" * 64,
        ledger_digest="2" * 64,
        state_digest="3" * 64,
        effects_attempted=3,
        effects_completed=3,
        mutation_attribution="PROVEN_BY_DURABLE_LEDGER",
        required_next_action="NONE",
        generated_at=NOW,
    )
    serialized = json.dumps(receipt)
    assert config.repair_id not in serialized
    assert config.principal_id not in serialized
    assert config.instance_arn not in serialized
    assert config.collector_permission_set_arn not in serialized
    assert config.collector_saml_provider_arn not in serialized
    assert receipt["authority_account_suffix"] == "7644"
    assert receipt["management_account_suffix"] == "1433"
    assert receipt["production_status"] == "NO-GO"
    assert set(receipt) == {
        "schema_version",
        "record_type",
        "mode",
        "status",
        "repair_id_digest",
        "source_commit",
        "function_version",
        "function_qualifier",
        "region",
        "authority_account_suffix",
        "management_account_suffix",
        "intent_digest",
        "ledger_digest",
        "state_digest",
        "effects_attempted",
        "effects_completed",
        "mutation_attribution",
        "required_next_action",
        "generated_at",
        "production_status",
    }


def test_repair_and_read_modes_select_distinct_exact_management_roles() -> None:
    assert config_for("repair").service_role_arn.endswith(
        "/ScanalyzeLambdaAuditRepairMutationServiceRole"
    )
    assert config_for("plan").service_role_arn.endswith(
        "/ScanalyzeLambdaAuditRepairReadbackServiceRole"
    )
    assert config_for("reconcile").service_role_arn.endswith(
        "/ScanalyzeLambdaAuditRepairReadbackServiceRole"
    )


def test_public_receipt_rejects_free_form_next_action() -> None:
    with pytest.raises(BrokerContractError, match="next action"):
        build_public_receipt(
            config=config_for(),
            status="BLOCKED",
            intent_digest="1" * 64,
            ledger_digest=None,
            state_digest="3" * 64,
            effects_attempted=0,
            effects_completed=0,
            mutation_attribution="UNPROVEN",
            required_next_action="DO_SOMETHING_UNREVIEWED",
            generated_at=NOW,
        )
