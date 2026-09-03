from __future__ import annotations

from copy import deepcopy
from dataclasses import replace
from datetime import UTC, datetime, timedelta
import hashlib
import json
from pathlib import Path
from typing import Any, Mapping

import pytest

from tooling.platform_authority_plan_permission_repair import (
    Assignment,
    FUNCTION_NAMES,
    FUNCTION_QUALIFIERS,
    INTENT_RECORD_TYPE_V1,
    INTENT_RECORD_TYPE_V2,
    LAMBDA_ENTRY_MINIMUM_REMAINING_MS,
    MUTATION_WINDOW_MIN_REMAINING_SECONDS,
    OperationResult,
    PRIVATE_INTENT_FIELDS,
    PRIVATE_LEDGER_ACTIVE_FIELDS,
    PRIVATE_LEDGER_PLAN_FIELDS,
    PRIVATE_RECONCILE_ATTEMPT_FIELDS,
    PRIVATE_RECONCILE_ATTESTATION_FIELDS,
    RECEIPT_RECORD_TYPE_V2,
    PUBLIC_RECEIPT_FIELDS,
    PlanPermissionRepair,
    PlanPermissionRepairError,
    PlanPermissionSnapshot,
    RepairBinding,
    REPAIR_START_MIN_WINDOW_REMAINING_SECONDS,
    RoleSnapshot,
    build_plan_ledger,
    build_private_intent,
    build_reconcile_attestation,
    digest_value,
    immutable_configuration_digest_from_intent,
    install_runtime_factory,
    parse_timestamp,
    plan_handler,
    render_predecessor_policy,
    render_target_policy,
    transition_ledger,
    validate_private_intent,
    validate_private_ledger,
    validate_reconcile_attempt,
    validate_reconcile_attestation,
    validate_public_receipt,
    validate_runtime_environment,
    validate_snapshot,
    validate_versioned_lambda_contract,
)


REPO_ROOT = Path(__file__).resolve().parents[2]
NOW = datetime(2026, 8, 30, 1, 3, tzinfo=UTC)


def _binding_record() -> dict[str, Any]:
    return {
        "source_commit": "a" * 40,
        "repair_id": "gug376-plan-permission-repair-" + "b" * 64,
        "source_bundle_digest": "sha256:" + "c" * 64,
        "instance_arn": "arn:aws:sso:::instance/ssoins-0123456789ABCDEF",
        "identity_store_id": "d-0123456789",
        "permission_set_arn": (
            "arn:aws:sso:::permissionSet/ssoins-0123456789ABCDEF/"
            "ps-0123456789ABCDEF"
        ),
        "repair_invoker_permission_set_arn": (
            "arn:aws:sso:::permissionSet/ssoins-0123456789ABCDEF/"
            "ps-fedcba9876543210"
        ),
        "permission_set_description": (
            "Synthetic reviewed bootstrap Plan permission set"
        ),
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
        "identity_center_kms_mode": "AWS_OWNED_KMS_KEY",
        "identity_center_kms_key_arn": None,
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


@pytest.fixture
def intent() -> dict[str, Any]:
    return build_private_intent(
        RepairBinding.from_mapping(_binding_record()), repo_root=REPO_ROOT
    )


def _reseal(value: Mapping[str, Any], digest_field: str) -> dict[str, Any]:
    resealed = deepcopy(dict(value))
    resealed.pop(digest_field, None)
    resealed[digest_field] = digest_value(resealed)
    return resealed


def _snapshot(
    intent: Mapping[str, Any],
    *,
    permission_policy: Mapping[str, Any],
    role_policy: Mapping[str, Any],
) -> PlanPermissionSnapshot:
    return PlanPermissionSnapshot(
        instance_arn=str(intent["instance_arn"]),
        identity_store_id=str(intent["identity_store_id"]),
        identity_center_kms_mode=str(intent["identity_center_kms_mode"]),
        identity_center_kms_key_arn=intent["identity_center_kms_key_arn"],
        permission_set_arn=str(intent["permission_set_arn"]),
        permission_set_name=str(intent["permission_set_name"]),
        permission_set_description=str(intent["permission_set_description"]),
        session_duration=str(intent["session_duration"]),
        relay_state=None,
        permission_set_tags=tuple(
            sorted(dict(intent["permission_set_tags"]).items())
        ),
        inline_policy=deepcopy(dict(permission_policy)),
        managed_policy_arns=(),
        customer_managed_policy_references=(),
        permissions_boundary_present=False,
        assignments=(Assignment("USER", str(intent["principal_id"])),),
        provisioned_account_ids=("042360977644",),
        pending_operation_count=0,
        role=RoleSnapshot(
            role_arn=str(intent["role_arn"]),
            role_name=str(intent["role_name"]),
            saml_provider_arn=str(intent["saml_provider_arn"]),
            saml_audience="https://signin.aws.amazon.com/saml",
            inline_policy_name="AwsSSOInlinePolicy",
            inline_policy=deepcopy(dict(role_policy)),
        ),
        invocation_authority_graph_digest=str(
            intent["invocation_authority_graph_digest"]
        ),
    )


class MemoryLedger:
    def __init__(self, timeline: list[str]) -> None:
        self.item: dict[str, Any] | None = None
        self.attestation: dict[str, Any] | None = None
        self.reconcile_attempt: dict[str, Any] | None = None
        self.timeline = timeline

    def put_if_absent(self, ledger: Mapping[str, Any]) -> None:
        if self.item is not None:
            raise RuntimeError("conditional write failed")
        self.item = deepcopy(dict(ledger))
        self.timeline.append("ledger:PLAN_VERIFIED")

    def read(self, repair_id: str) -> Mapping[str, Any] | None:
        if self.item is None or self.item["repair_id"] != repair_id:
            return None
        return deepcopy(self.item)

    def compare_and_swap(
        self,
        *,
        repair_id: str,
        expected_ledger_digest: str,
        expected_ledger: Mapping[str, Any],
        replacement: Mapping[str, Any],
    ) -> None:
        if (
            self.item is None
            or self.item["repair_id"] != repair_id
            or self.item["ledger_digest"] != expected_ledger_digest
            or self.item != dict(expected_ledger)
        ):
            raise RuntimeError("conditional update failed")
        self.item = deepcopy(dict(replacement))
        self.timeline.append("ledger:" + str(replacement["status"]))

    def put_reconcile_attestation(
        self, attestation: Mapping[str, Any]
    ) -> None:
        if self.attestation is not None:
            raise RuntimeError("conditional attestation write failed")
        self.attestation = deepcopy(dict(attestation))
        self.timeline.append("ledger:RECONCILE_ATTESTED")

    def read_reconcile_attestation(
        self, repair_id: str
    ) -> Mapping[str, Any] | None:
        if (
            self.attestation is None
            or self.attestation["base_repair_id"] != repair_id
        ):
            return None
        return deepcopy(self.attestation)

    def put_reconcile_attempt(self, attempt: Mapping[str, Any]) -> None:
        if self.reconcile_attempt is not None:
            raise RuntimeError("conditional reconcile attempt write failed")
        self.reconcile_attempt = deepcopy(dict(attempt))
        self.timeline.append("ledger:RECONCILE_ATTEMPT_CLAIMED")

    def read_reconcile_attempt(
        self, repair_id: str
    ) -> Mapping[str, Any] | None:
        if (
            self.reconcile_attempt is None
            or self.reconcile_attempt["base_repair_id"] != repair_id
        ):
            return None
        return deepcopy(self.reconcile_attempt)


class FailUncertainSealLedger(MemoryLedger):
    def compare_and_swap(
        self,
        *,
        repair_id: str,
        expected_ledger_digest: str,
        expected_ledger: Mapping[str, Any],
        replacement: Mapping[str, Any],
    ) -> None:
        if replacement["status"] == "UNCERTAIN_RECONCILE_ONLY":
            raise RuntimeError("synthetic uncertainty seal failure")
        super().compare_and_swap(
            repair_id=repair_id,
            expected_ledger_digest=expected_ledger_digest,
            expected_ledger=expected_ledger,
            replacement=replacement,
        )


class AmbiguousAttestationLedger(MemoryLedger):
    def put_reconcile_attestation(
        self, attestation: Mapping[str, Any]
    ) -> None:
        super().put_reconcile_attestation(attestation)
        raise RuntimeError("synthetic ambiguous attestation response")


class MissingAttestationLedger(MemoryLedger):
    def put_reconcile_attestation(
        self, attestation: Mapping[str, Any]
    ) -> None:
        del attestation
        raise RuntimeError("synthetic absent attestation response")


class AmbiguousReconcileAttemptLedger(MemoryLedger):
    def put_reconcile_attempt(self, attempt: Mapping[str, Any]) -> None:
        super().put_reconcile_attempt(attempt)
        raise RuntimeError("synthetic ambiguous reconcile attempt response")


class MissingReconcileAttemptLedger(MemoryLedger):
    def put_reconcile_attempt(self, attempt: Mapping[str, Any]) -> None:
        del attempt
        raise RuntimeError("synthetic absent reconcile attempt response")


class RacingReconcileAttemptLedger(MemoryLedger):
    def put_reconcile_attempt(self, attempt: Mapping[str, Any]) -> None:
        self.reconcile_attempt = deepcopy(dict(attempt))
        raise PlanPermissionRepairError(
            "REPLAY_BLOCKED", "synthetic concurrent reconcile winner"
        )


class MemoryProvider:
    def __init__(
        self,
        intent: Mapping[str, Any],
        timeline: list[str],
        *,
        fail_put: bool = False,
        provision_statuses: tuple[str, ...] = ("SUCCEEDED",),
    ) -> None:
        self.intent = dict(intent)
        self.timeline = timeline
        self.target = render_target_policy(str(intent["change_set_name"]))
        self.predecessor = render_predecessor_policy(self.target)
        self.permission_policy = deepcopy(self.predecessor)
        self.role_policy = deepcopy(self.predecessor)
        self.fail_put = fail_put
        self.put_calls = 0
        self.provision_calls = 0
        self.provision_statuses = list(provision_statuses)

    def snapshot(self, intent: Mapping[str, Any]) -> PlanPermissionSnapshot:
        assert intent["intent_digest"] == self.intent["intent_digest"]
        self.timeline.append("provider:snapshot")
        return _snapshot(
            intent,
            permission_policy=self.permission_policy,
            role_policy=self.role_policy,
        )

    def put_inline_policy(
        self, intent: Mapping[str, Any], policy_json: str
    ) -> None:
        self.timeline.append("provider:put")
        self.put_calls += 1
        if self.fail_put:
            raise RuntimeError("ambiguous provider response")
        assert json.loads(policy_json) == self.target
        self.permission_policy = deepcopy(self.target)

    def provision_permission_set(
        self, intent: Mapping[str, Any]
    ) -> OperationResult:
        self.timeline.append("provider:provision")
        self.provision_calls += 1
        status = self.provision_statuses.pop(0)
        if status == "SUCCEEDED":
            self.role_policy = deepcopy(self.target)
        return OperationResult("synthetic-private-request", status)

    def describe_provisioning(
        self, intent: Mapping[str, Any], request_id: str
    ) -> str:
        assert request_id == "synthetic-private-request"
        self.timeline.append("provider:describe")
        status = self.provision_statuses.pop(0)
        if status == "SUCCEEDED":
            self.role_policy = deepcopy(self.target)
        return status


def _install_uncertain_ledger(
    ledger: MemoryLedger,
    *,
    stage: str,
    effects_attempted: int,
    effects_completed: int,
) -> dict[str, Any]:
    assert ledger.item is not None
    uncertain = dict(ledger.item)
    uncertain.update(
        {
            "status": "UNCERTAIN_RECONCILE_ONLY",
            "stage": stage,
            "effects_attempted": effects_attempted,
            "effects_completed": effects_completed,
        }
    )
    uncertain = _reseal(uncertain, "ledger_digest")
    validate_private_ledger(uncertain)
    ledger.item = uncertain
    return uncertain


def test_policy_repair_is_exactly_one_added_statement() -> None:
    target = render_target_policy(_binding_record()["change_set_name"])
    predecessor = render_predecessor_policy(target)
    target_sids = [item["Sid"] for item in target["Statement"]]
    predecessor_sids = [item["Sid"] for item in predecessor["Statement"]]
    assert target_sids.count("ListOnlyExactBootstrapChangeSets") == 1
    assert "ListOnlyExactBootstrapChangeSets" not in predecessor_sids
    assert len(target_sids) == len(predecessor_sids) + 1


def test_private_intent_is_source_rendered_and_sealed(
    intent: dict[str, Any],
) -> None:
    validate_private_intent(intent)
    assert intent["schema_version"] == 2
    assert intent["record_type"] == INTENT_RECORD_TYPE_V2
    changed = deepcopy(intent)
    changed["authorized_mutations"].append("sso:CreatePermissionSet")
    with pytest.raises(PlanPermissionRepairError) as exc_info:
        validate_private_intent(changed)
    assert exc_info.value.code == "DIGEST_MISMATCH"


def test_private_intent_rejects_resealed_extra_field(
    intent: dict[str, Any],
) -> None:
    changed = deepcopy(intent)
    changed["operator_profile"] = "private-profile-value"
    changed = _reseal(changed, "intent_digest")
    with pytest.raises(PlanPermissionRepairError) as exc_info:
        validate_private_intent(changed)
    assert exc_info.value.code == "INTENT_FIELDS_INVALID"
    assert set(intent) == PRIVATE_INTENT_FIELDS


def test_private_intent_v1_reader_remains_exactly_compatible() -> None:
    fixture_path = (
        REPO_ROOT
        / "fixtures/valid/"
        "platform-authority-plan-permission-repair-intent-v1-synthetic.json"
    )
    raw = fixture_path.read_bytes()
    assert hashlib.sha256(raw).hexdigest() == (
        "8e189b20d04b814446e87423298abcfb70aba50c7df203d4cee18ad280ef0a40"
    )
    legacy = json.loads(raw)

    validate_private_intent(legacy)
    assert set(legacy) == PRIVATE_INTENT_FIELDS
    assert legacy["schema_version"] == 1
    assert legacy["record_type"] == INTENT_RECORD_TYPE_V1
    with pytest.raises(PlanPermissionRepairError) as active:
        PlanPermissionRepair(
            intent=legacy,
            provider=MemoryProvider(legacy, []),
            ledger=MemoryLedger([]),
            now=lambda: NOW,
        )
    assert active.value.code == "ACTIVE_INTENT_VERSION_REQUIRED"


def test_private_intent_v1_reader_does_not_backport_mrk_semantics() -> None:
    legacy = json.loads(
        (
            REPO_ROOT
            / "fixtures/valid/"
            "platform-authority-plan-permission-repair-intent-v1-synthetic.json"
        ).read_text(encoding="utf-8")
    )
    legacy.update(
        {
            "identity_center_kms_mode": "CUSTOMER_MANAGED_KEY",
            "identity_center_kms_key_arn": (
                "arn:aws:kms:us-east-1:839393571433:key/"
                "mrk-0123456789abcdef0123456789abcdef"
            ),
        }
    )
    legacy = _reseal(legacy, "intent_digest")

    with pytest.raises(PlanPermissionRepairError) as exc_info:
        validate_private_intent(legacy)
    assert exc_info.value.code == "INVALID_KMS_BINDING"


@pytest.mark.parametrize(
    "key_arn",
    (
        "arn:aws:kms:us-east-1:839393571433:key/"
        "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
        "arn:aws:kms:us-east-1:839393571433:key/"
        "mrk-0123456789abcdef0123456789abcdef",
    ),
)
def test_private_intent_v2_accepts_canonical_customer_managed_key_and_env(
    key_arn: str,
) -> None:
    record = _binding_record()
    record.update(
        {
            "identity_center_kms_mode": "CUSTOMER_MANAGED_KEY",
            "identity_center_kms_key_arn": key_arn,
        }
    )
    candidate = build_private_intent(
        RepairBinding.from_mapping(record), repo_root=REPO_ROOT
    )

    validate_private_intent(candidate)
    assert candidate["schema_version"] == 2
    assert candidate["record_type"] == INTENT_RECORD_TYPE_V2
    assert candidate["identity_center_kms_key_arn"] == key_arn

    env = {
        "SOURCE_COMMIT": candidate["source_commit"],
        "SOURCE_BUNDLE_DIGEST": candidate["source_bundle_digest"],
        "REPAIR_ID": candidate["repair_id"],
        "PRINCIPAL_ID": candidate["principal_id"],
        "IDENTITY_STORE_ID": candidate["identity_store_id"],
        "IDENTITY_CENTER_INSTANCE_ARN": candidate["instance_arn"],
        "PLAN_PERMISSION_SET_ARN": candidate["permission_set_arn"],
        "EXPECTED_PERMISSION_SET_DESCRIPTION": candidate[
            "permission_set_description"
        ],
        "REPAIR_INVOKER_PERMISSION_SET_ARN": candidate[
            "repair_invoker_permission_set_arn"
        ],
        "CURRENT_POLICY_DIGEST": candidate["predecessor_policy_digest"],
        "DESIRED_POLICY_DIGEST": candidate["target_policy_digest"],
        "EXPECTED_PLAN_PERMISSION_SET_TAGS_JSON": json.dumps(
            candidate["permission_set_tags"],
            sort_keys=True,
            separators=(",", ":"),
        ),
        "BOOTSTRAP_CHANGE_SET_NAME": candidate["change_set_name"],
        "REPAIR_LEDGER_TABLE_NAME": candidate["ledger_table_name"],
        "REPAIR_LEDGER_KMS_KEY_ARN": candidate["ledger_kms_key_arn"],
        "EXPECTED_ARTIFACT_CODE_SHA256": candidate[
            "expected_artifact_code_sha256"
        ],
        "EXPECTED_CODE_SIGNING_CONFIG_ARN": candidate[
            "expected_code_signing_config_arn"
        ],
        "EXPECTED_SIGNING_PROFILE_VERSION_ARN": candidate[
            "expected_signing_profile_version_arn"
        ],
        "REPAIR_NOT_BEFORE": candidate["not_before"],
        "REPAIR_NOT_AFTER": candidate["not_after"],
        "PLAN_SAML_PROVIDER_ARN": candidate["saml_provider_arn"],
        "IDENTITY_CENTER_KMS_MODE": candidate["identity_center_kms_mode"],
        "IDENTITY_CENTER_KMS_KEY_ARN": key_arn,
        "EXPECTED_BOTO3_VERSION": candidate["expected_boto3_version"],
        "EXPECTED_BOTOCORE_VERSION": candidate["expected_botocore_version"],
        "AWS_LAMBDA_FUNCTION_VERSION": candidate["function_versions"]["plan"],
    }
    env["IMMU_CONFIG_DIGEST"] = immutable_configuration_digest_from_intent(
        candidate
    )
    validate_runtime_environment(candidate, mode="plan", env=env)


@pytest.mark.parametrize(
    "key_arn",
    (
        "arn:aws:kms:us-east-1:839393571433:alias/identity-center",
        "arn:aws-cn:kms:us-east-1:839393571433:key/"
        "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
        "arn:aws:kms:us-west-2:839393571433:key/"
        "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
        "arn:aws:kms:us-east-1:000000000000:key/"
        "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
        "arn:aws:kms:us-east-1:839393571433:key/"
        "AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE",
        "arn:aws:kms:us-east-1:839393571433:key/"
        "mrk-0123456789abcdef0123456789abcdeF",
        "arn:aws:kms:us-east-1:839393571433:key/mrk-0123",
    ),
)
def test_new_binding_rejects_noncanonical_identity_center_key(
    key_arn: str,
) -> None:
    record = _binding_record()
    record.update(
        {
            "identity_center_kms_mode": "CUSTOMER_MANAGED_KEY",
            "identity_center_kms_key_arn": key_arn,
        }
    )
    with pytest.raises(PlanPermissionRepairError) as exc_info:
        RepairBinding.from_mapping(record)
    assert exc_info.value.code == "INVALID_KMS_BINDING"


def test_private_ledger_rejects_resealed_extra_fields_and_bool_counters(
    intent: dict[str, Any],
) -> None:
    ledger = build_plan_ledger(
        intent,
        state_digest="sha256:" + "e" * 64,
        planned_at=NOW,
    )
    assert set(ledger) == PRIVATE_LEDGER_PLAN_FIELDS

    extra = deepcopy(ledger)
    extra["operator_profile"] = "private-profile-value"
    extra = _reseal(extra, "ledger_digest")
    with pytest.raises(PlanPermissionRepairError) as extra_exc:
        validate_private_ledger(extra)
    assert extra_exc.value.code == "LEDGER_FIELDS_INVALID"

    bool_counters = deepcopy(ledger)
    bool_counters["effects_attempted"] = False
    bool_counters["effects_completed"] = False
    bool_counters = _reseal(bool_counters, "ledger_digest")
    with pytest.raises(PlanPermissionRepairError) as bool_exc:
        validate_private_ledger(bool_counters)
    assert bool_exc.value.code == "IMPOSSIBLE_LEDGER_PROGRESS"


def test_snapshot_requires_the_exact_predecessor_and_no_foreign_authority(
    intent: dict[str, Any],
) -> None:
    target = render_target_policy(str(intent["change_set_name"]))
    predecessor = render_predecessor_policy(target)
    snapshot = _snapshot(
        intent,
        permission_policy=predecessor,
        role_policy=predecessor,
    )
    validate_snapshot(intent, snapshot, "BEFORE_PUT_INLINE_POLICY")
    drifted = replace(
        snapshot,
        managed_policy_arns=("arn:aws:iam::aws:policy/ReadOnlyAccess",),
    )
    with pytest.raises(PlanPermissionRepairError) as exc_info:
        validate_snapshot(intent, drifted, "BEFORE_PUT_INLINE_POLICY")
    assert exc_info.value.code == "FOREIGN_AUTHORITY"


def test_complete_two_effect_state_machine_is_at_most_once(
    intent: dict[str, Any],
) -> None:
    timeline: list[str] = []
    provider = MemoryProvider(intent, timeline)
    ledger = MemoryLedger(timeline)
    runtime = PlanPermissionRepair(
        intent=intent,
        provider=provider,
        ledger=ledger,
        now=lambda: NOW,
        sleep=lambda _: None,
    )

    plan_receipt = runtime.plan()
    repair_receipt = runtime.repair()
    reconcile_receipt = runtime.reconcile()

    for receipt in (plan_receipt, repair_receipt, reconcile_receipt):
        assert receipt["schema_version"] == 2
        assert receipt["record_type"] == RECEIPT_RECORD_TYPE_V2
    assert plan_receipt["status"] == "PLAN_VERIFIED"
    assert repair_receipt["status"] == "REPAIR_VERIFIED"
    assert repair_receipt["effects_attempted"] == 2
    assert repair_receipt["effects_completed"] == 2
    assert reconcile_receipt["status"] == "RECONCILE_VERIFIED"
    assert provider.put_calls == 1
    assert provider.provision_calls == 1
    assert timeline.index("ledger:ATTEMPTING_1") < timeline.index("provider:put")
    assert timeline.index("ledger:ATTEMPTING_2") < timeline.index(
        "provider:provision"
    )
    assert ledger.item is not None
    assert set(ledger.item) == PRIVATE_LEDGER_ACTIVE_FIELDS
    assert ledger.reconcile_attempt is not None
    assert set(ledger.reconcile_attempt) == PRIVATE_RECONCILE_ATTEMPT_FIELDS
    assert ledger.attestation is not None
    assert set(ledger.attestation) == PRIVATE_RECONCILE_ATTESTATION_FIELDS
    assert ledger.attestation["repair_ledger_digest"] == (
        ledger.item["ledger_digest"]
    )
    assert timeline.index("ledger:REPAIR_VERIFIED") < timeline.index(
        "ledger:RECONCILE_ATTEMPT_CLAIMED"
    ) < timeline.index(
        "provider:snapshot",
        timeline.index("ledger:RECONCILE_ATTEMPT_CLAIMED"),
    ) < timeline.index(
        "ledger:RECONCILE_ATTESTED"
    )
    validate_private_ledger(ledger.item)
    validate_reconcile_attempt(
        ledger.reconcile_attempt, intent=intent, ledger=ledger.item
    )
    validate_reconcile_attestation(
        ledger.attestation, intent=intent, ledger=ledger.item
    )
    validate_public_receipt(plan_receipt)
    validate_public_receipt(repair_receipt)
    validate_public_receipt(reconcile_receipt)


def test_reconcile_attestation_response_loss_is_recovered_only_in_first_invoke(
    intent: dict[str, Any],
) -> None:
    timeline: list[str] = []
    provider = MemoryProvider(intent, timeline)
    ledger = MemoryLedger(timeline)
    runtime = PlanPermissionRepair(
        intent=intent,
        provider=provider,
        ledger=ledger,
        now=lambda: NOW,
        sleep=lambda _: None,
    )
    runtime.plan()
    runtime.repair()
    first = runtime.reconcile()
    snapshot_count = timeline.count("provider:snapshot")

    assert first["schema_version"] == 2
    assert first["record_type"] == RECEIPT_RECORD_TYPE_V2
    with pytest.raises(PlanPermissionRepairError) as replay:
        runtime.reconcile()
    assert replay.value.code == "REPLAY_BLOCKED"
    assert timeline.count("provider:snapshot") == snapshot_count
    assert ledger.reconcile_attempt is not None
    assert timeline.count("ledger:RECONCILE_ATTESTED") == 1


def test_concurrent_success_reconcile_loser_stops_before_snapshot(
    intent: dict[str, Any],
) -> None:
    timeline: list[str] = []
    provider = MemoryProvider(intent, timeline)
    ledger = RacingReconcileAttemptLedger(timeline)
    runtime = PlanPermissionRepair(
        intent=intent,
        provider=provider,
        ledger=ledger,
        now=lambda: NOW,
        sleep=lambda _: None,
    )
    runtime.plan()
    runtime.repair()
    snapshot_count = timeline.count("provider:snapshot")

    with pytest.raises(PlanPermissionRepairError) as replay:
        runtime.reconcile()

    assert replay.value.code == "REPLAY_BLOCKED"
    assert timeline.count("provider:snapshot") == snapshot_count
    assert ledger.reconcile_attempt is not None
    assert ledger.attestation is None


@pytest.mark.parametrize(
    ("stage", "effects_attempted", "effects_completed"),
    [
        ("UNCERTAIN_PUT_INLINE_POLICY", 1, 0),
        ("UNCERTAIN_PUT_INLINE_POLICY_LEDGER_COMMIT", 1, 1),
        ("UNCERTAIN_PROVISION_PERMISSION_SET", 2, 1),
        ("UNCERTAIN_PROVISION_PERMISSION_SET_LEDGER_COMMIT", 2, 2),
        ("UNCERTAIN_FINAL_READBACK", 2, 2),
    ],
)
def test_reconcile_final_exact_uncertainty_never_creates_closeout_attestation(
    intent: dict[str, Any],
    stage: str,
    effects_attempted: int,
    effects_completed: int,
) -> None:
    timeline: list[str] = []
    provider = MemoryProvider(intent, timeline)
    ledger = MemoryLedger(timeline)
    runtime = PlanPermissionRepair(
        intent=intent,
        provider=provider,
        ledger=ledger,
        now=lambda: NOW,
        sleep=lambda _: None,
    )
    runtime.plan()
    runtime.repair()
    uncertain = _install_uncertain_ledger(
        ledger,
        stage=stage,
        effects_attempted=effects_attempted,
        effects_completed=effects_completed,
    )

    first = runtime.reconcile()
    snapshot_count = timeline.count("provider:snapshot")
    with pytest.raises(PlanPermissionRepairError) as replay:
        runtime.reconcile()
    assert first["status"] == "UNCERTAIN_RECONCILE_ONLY"
    assert first["required_next_action"] == "REVIEW_BLOCKER"
    assert replay.value.code == "REPLAY_BLOCKED"
    assert timeline.count("provider:snapshot") == snapshot_count
    assert ledger.attestation is None
    assert ledger.reconcile_attempt is not None
    assert set(ledger.reconcile_attempt) == PRIVATE_RECONCILE_ATTEMPT_FIELDS
    validate_reconcile_attempt(
        ledger.reconcile_attempt,
        intent=intent,
        ledger=uncertain,
    )
    non_integer_progress = deepcopy(ledger.reconcile_attempt)
    non_integer_progress["effects_attempted"] = True
    non_integer_progress = _reseal(non_integer_progress, "attempt_digest")
    with pytest.raises(PlanPermissionRepairError) as invalid_attempt:
        validate_reconcile_attempt(non_integer_progress)
    assert invalid_attempt.value.code == "RECONCILE_ATTEMPT_OVERCLAIM"
    reconcile_snapshot_index = max(
        index
        for index, event in enumerate(timeline)
        if event == "provider:snapshot"
    )
    assert (
        timeline.index("ledger:RECONCILE_ATTEMPT_CLAIMED")
        < reconcile_snapshot_index
    )
    assert timeline.count("ledger:RECONCILE_ATTESTED") == 0

    with pytest.raises(PlanPermissionRepairError) as blocked:
        build_reconcile_attestation(
            intent,
            uncertain,
            observed_state_digest=provider.snapshot(intent).digest(),
            reconciled_at=NOW,
        )
    assert blocked.value.code == "RECONCILE_ATTESTATION_BINDING_MISMATCH"

    repeated = deepcopy(first)
    repeated["required_next_action"] = "INVOKE_RECONCILE_ALIAS"
    repeated = _reseal(repeated, "receipt_digest")
    with pytest.raises(PlanPermissionRepairError) as overclaim:
        validate_public_receipt(repeated)
    assert overclaim.value.code == "PUBLIC_OVERCLAIM"


def test_uncertain_reconcile_attempt_accepts_only_exact_ambiguous_readback(
    intent: dict[str, Any],
) -> None:
    timeline: list[str] = []
    provider = MemoryProvider(intent, timeline)
    ledger = AmbiguousReconcileAttemptLedger(timeline)
    runtime = PlanPermissionRepair(
        intent=intent,
        provider=provider,
        ledger=ledger,
        now=lambda: NOW,
        sleep=lambda _: None,
    )
    runtime.plan()
    runtime.repair()
    uncertain = _install_uncertain_ledger(
        ledger,
        stage="UNCERTAIN_FINAL_READBACK",
        effects_attempted=2,
        effects_completed=2,
    )

    receipt = runtime.reconcile()

    assert receipt["status"] == "UNCERTAIN_RECONCILE_ONLY"
    assert ledger.reconcile_attempt is not None
    validate_reconcile_attempt(
        ledger.reconcile_attempt,
        intent=intent,
        ledger=uncertain,
    )


def test_uncertain_reconcile_stops_before_snapshot_when_claim_is_unproven(
    intent: dict[str, Any],
) -> None:
    timeline: list[str] = []
    provider = MemoryProvider(intent, timeline)
    ledger = MissingReconcileAttemptLedger(timeline)
    runtime = PlanPermissionRepair(
        intent=intent,
        provider=provider,
        ledger=ledger,
        now=lambda: NOW,
        sleep=lambda _: None,
    )
    runtime.plan()
    runtime.repair()
    _install_uncertain_ledger(
        ledger,
        stage="UNCERTAIN_FINAL_READBACK",
        effects_attempted=2,
        effects_completed=2,
    )
    snapshot_count = timeline.count("provider:snapshot")

    with pytest.raises(PlanPermissionRepairError) as unproven:
        runtime.reconcile()

    assert unproven.value.code == "RECONCILE_ATTEMPT_UNPROVEN"
    assert timeline.count("provider:snapshot") == snapshot_count


def test_reconcile_attestation_accepts_only_exact_ambiguous_readback(
    intent: dict[str, Any],
) -> None:
    timeline: list[str] = []
    ledger = AmbiguousAttestationLedger(timeline)
    runtime = PlanPermissionRepair(
        intent=intent,
        provider=MemoryProvider(intent, timeline),
        ledger=ledger,
        now=lambda: NOW,
        sleep=lambda _: None,
    )
    runtime.plan()
    runtime.repair()

    assert runtime.reconcile()["status"] == "RECONCILE_VERIFIED"
    assert ledger.attestation is not None


def test_reconcile_attestation_fails_when_write_cannot_be_proven(
    intent: dict[str, Any],
) -> None:
    timeline: list[str] = []
    ledger = MissingAttestationLedger(timeline)
    runtime = PlanPermissionRepair(
        intent=intent,
        provider=MemoryProvider(intent, timeline),
        ledger=ledger,
        now=lambda: NOW,
        sleep=lambda _: None,
    )
    runtime.plan()
    runtime.repair()

    with pytest.raises(PlanPermissionRepairError) as unproven:
        runtime.reconcile()

    assert unproven.value.code == "RECONCILE_ATTESTATION_UNPROVEN"


def test_reconcile_attestation_rejects_nonterminal_or_tampered_evidence(
    intent: dict[str, Any],
) -> None:
    plan = build_plan_ledger(
        intent,
        state_digest="sha256:" + "e" * 64,
        planned_at=NOW,
    )
    with pytest.raises(PlanPermissionRepairError) as nonterminal:
        build_reconcile_attestation(
            intent,
            plan,
            observed_state_digest=str(plan["state_digest"]),
            reconciled_at=NOW,
        )
    assert nonterminal.value.code == (
        "RECONCILE_ATTESTATION_BINDING_MISMATCH"
    )

    timeline: list[str] = []
    ledger = MemoryLedger(timeline)
    runtime = PlanPermissionRepair(
        intent=intent,
        provider=MemoryProvider(intent, timeline),
        ledger=ledger,
        now=lambda: NOW,
        sleep=lambda _: None,
    )
    runtime.plan()
    runtime.repair()
    runtime.reconcile()
    assert ledger.attestation is not None
    tampered = deepcopy(ledger.attestation)
    tampered["observed_state_digest"] = "sha256:" + "f" * 64
    tampered = _reseal(tampered, "attestation_digest")
    with pytest.raises(PlanPermissionRepairError) as mismatch:
        validate_reconcile_attestation(
            tampered,
            intent=intent,
            ledger=ledger.item,
        )
    assert mismatch.value.code == (
        "RECONCILE_ATTESTATION_BINDING_MISMATCH"
    )


def test_ambiguous_first_effect_is_terminal_and_never_retried(
    intent: dict[str, Any],
) -> None:
    timeline: list[str] = []
    provider = MemoryProvider(intent, timeline, fail_put=True)
    ledger = MemoryLedger(timeline)
    runtime = PlanPermissionRepair(
        intent=intent,
        provider=provider,
        ledger=ledger,
        now=lambda: NOW,
        sleep=lambda _: None,
    )
    runtime.plan()
    receipt = runtime.repair()
    assert receipt["status"] == "UNCERTAIN_RECONCILE_ONLY"
    assert receipt["effects_attempted"] == 1
    assert receipt["effects_completed"] == 0
    assert provider.put_calls == 1
    assert ledger.item is not None
    assert ledger.item["stage"] == "UNCERTAIN_PUT_INLINE_POLICY"
    with pytest.raises(PlanPermissionRepairError) as exc_info:
        runtime.repair()
    assert exc_info.value.code == "REPLAY_BLOCKED"
    assert provider.put_calls == 1


def test_uncertain_effect_without_durable_seal_emits_no_invalid_receipt(
    intent: dict[str, Any],
) -> None:
    timeline: list[str] = []
    provider = MemoryProvider(intent, timeline, fail_put=True)
    ledger = FailUncertainSealLedger(timeline)
    runtime = PlanPermissionRepair(
        intent=intent,
        provider=provider,
        ledger=ledger,
        now=lambda: NOW,
        sleep=lambda _: None,
    )
    runtime.plan()

    with pytest.raises(PlanPermissionRepairError) as exc_info:
        runtime.repair()

    assert exc_info.value.code == "UNCERTAINTY_LEDGER_UNPROVEN"
    assert provider.put_calls == 1
    assert ledger.item is not None
    assert ledger.item["status"] == "ATTEMPTING_1"

    with pytest.raises(PlanPermissionRepairError) as replay_exc_info:
        runtime.repair()
    assert replay_exc_info.value.code == "REPLAY_BLOCKED"
    assert provider.put_calls == 1


def test_async_provisioning_is_bounded_and_reaches_final_readback(
    intent: dict[str, Any],
) -> None:
    timeline: list[str] = []
    provider = MemoryProvider(
        intent,
        timeline,
        provision_statuses=("IN_PROGRESS", "SUCCEEDED"),
    )
    ledger = MemoryLedger(timeline)
    runtime = PlanPermissionRepair(
        intent=intent,
        provider=provider,
        ledger=ledger,
        now=lambda: NOW,
        sleep=lambda _: None,
        maximum_poll_attempts=2,
    )
    runtime.plan()
    assert runtime.repair()["status"] == "REPAIR_VERIFIED"
    assert timeline.count("provider:describe") == 1


def test_uncertain_ledger_cannot_transition_back_into_repair(
    intent: dict[str, Any],
) -> None:
    timeline: list[str] = []
    provider = MemoryProvider(intent, timeline, fail_put=True)
    ledger = MemoryLedger(timeline)
    runtime = PlanPermissionRepair(
        intent=intent,
        provider=provider,
        ledger=ledger,
        now=lambda: NOW,
        sleep=lambda _: None,
    )
    runtime.plan()
    runtime.repair()
    assert ledger.item is not None
    with pytest.raises(PlanPermissionRepairError) as exc_info:
        transition_ledger(
            ledger.item,
            expected_status="UNCERTAIN_RECONCILE_ONLY",
            new_status="CLAIMED",
            stage="BEFORE_FIRST_EFFECT",
            effects_attempted=0,
            effects_completed=0,
            state_digest=ledger.item["state_digest"],
            updated_at=NOW,
        )
    assert exc_info.value.code == "REPLAY_BLOCKED"


def _ledger_at_attempting_1(intent: Mapping[str, Any]) -> dict[str, Any]:
    ledger = build_plan_ledger(
        intent,
        state_digest="sha256:" + "e" * 64,
        planned_at=NOW,
    )
    ledger = transition_ledger(
        ledger,
        expected_status="PLAN_VERIFIED",
        new_status="CLAIMED",
        stage="BEFORE_FIRST_EFFECT",
        effects_attempted=0,
        effects_completed=0,
        state_digest=ledger["state_digest"],
        updated_at=NOW + timedelta(seconds=1),
        claimed_at=NOW + timedelta(seconds=1),
    )
    return transition_ledger(
        ledger,
        expected_status="CLAIMED",
        new_status="ATTEMPTING_1",
        stage="BEFORE_PUT_INLINE_POLICY",
        effects_attempted=0,
        effects_completed=0,
        state_digest=ledger["state_digest"],
        updated_at=NOW + timedelta(seconds=2),
    )


@pytest.mark.parametrize(
    ("stage", "attempted", "completed"),
    (
        ("UNCERTAIN_PUT_INLINE_POLICY", 1, 0),
        ("UNCERTAIN_PUT_INLINE_POLICY_LEDGER_COMMIT", 1, 1),
    ),
)
def test_ledger_transition_graph_accepts_exact_first_effect_uncertainty_edges(
    intent: dict[str, Any],
    stage: str,
    attempted: int,
    completed: int,
) -> None:
    ledger = _ledger_at_attempting_1(intent)
    transitioned = transition_ledger(
        ledger,
        expected_status="ATTEMPTING_1",
        new_status="UNCERTAIN_RECONCILE_ONLY",
        stage=stage,
        effects_attempted=attempted,
        effects_completed=completed,
        state_digest=ledger["state_digest"],
        updated_at=NOW + timedelta(seconds=3),
    )
    assert transitioned["status"] == "UNCERTAIN_RECONCILE_ONLY"
    assert transitioned["stage"] == stage


def test_ledger_transition_graph_rejects_state_skips_without_mutating_input(
    intent: dict[str, Any],
) -> None:
    ledger = build_plan_ledger(
        intent,
        state_digest="sha256:" + "e" * 64,
        planned_at=NOW,
    )
    original = deepcopy(ledger)
    with pytest.raises(PlanPermissionRepairError) as exc_info:
        transition_ledger(
            ledger,
            expected_status="PLAN_VERIFIED",
            new_status="REPAIR_VERIFIED",
            stage="FINAL_READBACK_VERIFIED",
            effects_attempted=2,
            effects_completed=2,
            state_digest=ledger["state_digest"],
            updated_at=NOW + timedelta(seconds=1),
        )
    assert exc_info.value.code == "INVALID_LEDGER_TRANSITION"
    assert ledger == original


def test_ledger_transition_graph_rejects_cross_effect_uncertainty_stage(
    intent: dict[str, Any],
) -> None:
    ledger = _ledger_at_attempting_1(intent)
    with pytest.raises(PlanPermissionRepairError) as exc_info:
        transition_ledger(
            ledger,
            expected_status="ATTEMPTING_1",
            new_status="UNCERTAIN_RECONCILE_ONLY",
            stage="UNCERTAIN_PROVISION_PERMISSION_SET",
            effects_attempted=2,
            effects_completed=1,
            state_digest=ledger["state_digest"],
            updated_at=NOW + timedelta(seconds=3),
        )
    assert exc_info.value.code == "INVALID_LEDGER_TRANSITION"


def test_ledger_transition_graph_enforces_claim_and_monotonic_time(
    intent: dict[str, Any],
) -> None:
    plan = build_plan_ledger(
        intent,
        state_digest="sha256:" + "e" * 64,
        planned_at=NOW,
    )
    with pytest.raises(PlanPermissionRepairError) as missing_claim:
        transition_ledger(
            plan,
            expected_status="PLAN_VERIFIED",
            new_status="CLAIMED",
            stage="BEFORE_FIRST_EFFECT",
            effects_attempted=0,
            effects_completed=0,
            state_digest=plan["state_digest"],
            updated_at=NOW + timedelta(seconds=1),
        )
    assert missing_claim.value.code == "INVALID_LEDGER_TRANSITION"

    attempting = _ledger_at_attempting_1(intent)
    with pytest.raises(PlanPermissionRepairError) as repeated_claim:
        transition_ledger(
            attempting,
            expected_status="ATTEMPTING_1",
            new_status="COMPLETED_1",
            stage="AFTER_PUT_INLINE_POLICY",
            effects_attempted=1,
            effects_completed=1,
            state_digest=attempting["state_digest"],
            updated_at=NOW + timedelta(seconds=3),
            claimed_at=NOW + timedelta(seconds=1),
        )
    assert repeated_claim.value.code == "INVALID_LEDGER_TRANSITION"

    claimed = transition_ledger(
        plan,
        expected_status="PLAN_VERIFIED",
        new_status="CLAIMED",
        stage="BEFORE_FIRST_EFFECT",
        effects_attempted=0,
        effects_completed=0,
        state_digest=plan["state_digest"],
        updated_at=NOW + timedelta(seconds=2),
        claimed_at=NOW + timedelta(seconds=1),
    )
    with pytest.raises(PlanPermissionRepairError) as regressive_time:
        transition_ledger(
            claimed,
            expected_status="CLAIMED",
            new_status="ATTEMPTING_1",
            stage="BEFORE_PUT_INLINE_POLICY",
            effects_attempted=0,
            effects_completed=0,
            state_digest=claimed["state_digest"],
            updated_at=NOW + timedelta(seconds=1),
        )
    assert regressive_time.value.code == "INVALID_LEDGER_TRANSITION"


def test_public_receipt_validator_rejects_resealed_extra_fields(
    intent: dict[str, Any],
) -> None:
    timeline: list[str] = []
    runtime = PlanPermissionRepair(
        intent=intent,
        provider=MemoryProvider(intent, timeline),
        ledger=MemoryLedger(timeline),
        now=lambda: NOW,
        sleep=lambda _: None,
    )
    receipt = runtime.plan()
    assert set(receipt) == PUBLIC_RECEIPT_FIELDS
    receipt["operator_profile"] = "private-profile-value"
    receipt.pop("receipt_digest")
    receipt["receipt_digest"] = digest_value(receipt)

    with pytest.raises(PlanPermissionRepairError) as exc_info:
        validate_public_receipt(receipt)

    assert exc_info.value.code == "RECEIPT_FIELDS_INVALID"


def test_public_receipt_validator_matches_version_and_reconcile_schema(
    intent: dict[str, Any],
) -> None:
    timeline: list[str] = []
    runtime = PlanPermissionRepair(
        intent=intent,
        provider=MemoryProvider(intent, timeline),
        ledger=MemoryLedger(timeline),
        now=lambda: NOW,
        sleep=lambda _: None,
    )
    receipt = runtime.plan()

    invalid_version = deepcopy(receipt)
    invalid_version["function_version"] = "not-a-version"
    invalid_version = _reseal(invalid_version, "receipt_digest")
    with pytest.raises(PlanPermissionRepairError) as version_exc:
        validate_public_receipt(invalid_version)
    assert version_exc.value.code == "UNPUBLISHED_FUNCTION"

    invalid_reconcile = deepcopy(receipt)
    invalid_reconcile.update(
        {
            "mode": "reconcile",
            "status": "RECONCILE_VERIFIED",
            "function_version": "3",
            "function_qualifier": "reconcile-v1",
            "effects_attempted": 2,
            "effects_completed": 1,
            "required_next_action": "NONE",
        }
    )
    invalid_reconcile = _reseal(invalid_reconcile, "receipt_digest")
    with pytest.raises(PlanPermissionRepairError) as reconcile_exc:
        validate_public_receipt(invalid_reconcile)
    assert reconcile_exc.value.code == "PUBLIC_OVERCLAIM"


@pytest.mark.parametrize(
    ("attempted", "completed"),
    ((0, 0), (0, 2), (1, 2), (2, 0)),
)
def test_public_receipt_validator_rejects_nonledger_uncertainty_progress(
    intent: dict[str, Any],
    attempted: int,
    completed: int,
) -> None:
    timeline: list[str] = []
    runtime = PlanPermissionRepair(
        intent=intent,
        provider=MemoryProvider(intent, timeline),
        ledger=MemoryLedger(timeline),
        now=lambda: NOW,
        sleep=lambda _: None,
    )
    receipt = runtime.plan()
    receipt.update(
        {
            "mode": "repair",
            "status": "UNCERTAIN_RECONCILE_ONLY",
            "function_version": intent["function_versions"]["repair"],
            "function_qualifier": "repair-v1",
            "effects_attempted": attempted,
            "effects_completed": completed,
            "required_next_action": "INVOKE_RECONCILE_ALIAS",
        }
    )
    receipt = _reseal(receipt, "receipt_digest")

    with pytest.raises(PlanPermissionRepairError) as exc_info:
        validate_public_receipt(receipt)

    assert exc_info.value.code == "IMPOSSIBLE_RECEIPT_PROGRESS"


def test_repair_requires_immutable_window_reserve_before_provider_or_claim(
    intent: dict[str, Any],
) -> None:
    timeline: list[str] = []
    provider = MemoryProvider(intent, timeline)
    ledger = MemoryLedger(timeline)
    PlanPermissionRepair(
        intent=intent,
        provider=provider,
        ledger=ledger,
        now=lambda: NOW,
        sleep=lambda _: None,
    ).plan()
    timeline_before = list(timeline)
    late = datetime(2026, 8, 30, 1, 4, 1, tzinfo=UTC)
    assert (
        parse_timestamp(intent["not_after"], "not_after") - late
    ).total_seconds() == REPAIR_START_MIN_WINDOW_REMAINING_SECONDS - 1

    with pytest.raises(PlanPermissionRepairError) as exc_info:
        PlanPermissionRepair(
            intent=intent,
            provider=provider,
            ledger=ledger,
            now=lambda: late,
            sleep=lambda _: None,
        ).repair()

    assert exc_info.value.code == "WINDOW_BUDGET_INSUFFICIENT"
    assert timeline == timeline_before
    assert ledger.item is not None
    assert ledger.item["status"] == "PLAN_VERIFIED"
    assert provider.put_calls == 0


def test_repair_requires_more_than_mutation_window_reserve_before_dispatch(
    intent: dict[str, Any],
) -> None:
    timeline: list[str] = []
    provider = MemoryProvider(intent, timeline)
    ledger = MemoryLedger(timeline)
    PlanPermissionRepair(
        intent=intent,
        provider=provider,
        ledger=ledger,
        now=lambda: NOW,
        sleep=lambda _: None,
    ).plan()
    late = datetime(2026, 8, 30, 1, 13, 45, tzinfo=UTC)
    assert (
        parse_timestamp(intent["not_after"], "not_after") - late
    ).total_seconds() == MUTATION_WINDOW_MIN_REMAINING_SECONDS
    moments = iter((NOW, NOW, NOW, late))
    runtime = PlanPermissionRepair(
        intent=intent,
        provider=provider,
        ledger=ledger,
        now=lambda: next(moments),
        sleep=lambda _: None,
    )

    with pytest.raises(PlanPermissionRepairError) as exc_info:
        runtime.repair()

    assert exc_info.value.code == "WINDOW_BUDGET_INSUFFICIENT"
    assert provider.put_calls == 0
    assert provider.provision_calls == 0
    assert ledger.item is not None
    assert ledger.item["status"] == "CLAIMED"


class _Context:
    def __init__(self, arn: str, remaining_ms: object = 120_000) -> None:
        self.invoked_function_arn = arn
        self.remaining_ms = remaining_ms

    def get_remaining_time_in_millis(self) -> object:
        return self.remaining_ms


def test_versioned_lambda_contract_rejects_payload_and_wrong_alias() -> None:
    context = _Context(
        "arn:aws:lambda:us-east-1:042360977644:function:"
        + FUNCTION_NAMES["plan"]
        + ":"
        + FUNCTION_QUALIFIERS["plan"]
    )
    with pytest.raises(PlanPermissionRepairError) as exc_info:
        validate_versioned_lambda_contract(
            mode="plan",
            event={"permission_set_arn": "caller-selected"},
            context=context,
            env={"AWS_LAMBDA_FUNCTION_VERSION": "1"},
        )
    assert exc_info.value.code == "NON_EMPTY_EVENT"

    wrong = _Context(context.invoked_function_arn.removesuffix("plan-v1") + "1")
    with pytest.raises(PlanPermissionRepairError) as exc_info:
        validate_versioned_lambda_contract(
            mode="plan",
            event={},
            context=wrong,
            env={"AWS_LAMBDA_FUNCTION_VERSION": "1"},
        )
    assert exc_info.value.code == "FUNCTION_BINDING_MISMATCH"


@pytest.mark.parametrize(
    "mode", ("plan", "repair", "reconcile")
)
def test_versioned_lambda_contract_enforces_mode_entry_budget(mode: str) -> None:
    threshold = LAMBDA_ENTRY_MINIMUM_REMAINING_MS[mode]
    arn = (
        "arn:aws:lambda:us-east-1:042360977644:function:"
        + FUNCTION_NAMES[mode]
        + ":"
        + FUNCTION_QUALIFIERS[mode]
    )
    env = {"AWS_LAMBDA_FUNCTION_VERSION": "1"}
    if mode == "repair":
        env["PLAN_FUNCTION_VERSION"] = "1"
    if mode == "reconcile":
        env["REPAIR_FUNCTION_VERSION"] = "2"

    with pytest.raises(PlanPermissionRepairError) as exc_info:
        validate_versioned_lambda_contract(
            mode=mode,
            event={},
            context=_Context(arn, threshold),
            env=env,
        )
    assert exc_info.value.code == "FUNCTION_BUDGET_INSUFFICIENT"

    validate_versioned_lambda_contract(
        mode=mode,
        event={},
        context=_Context(arn, threshold + 1),
        env=env,
    )


@pytest.mark.parametrize("remaining_ms", (True, 1.5, -1))
def test_versioned_lambda_contract_rejects_invalid_or_exhausted_budget(
    remaining_ms: object,
) -> None:
    arn = (
        "arn:aws:lambda:us-east-1:042360977644:function:"
        + FUNCTION_NAMES["plan"]
        + ":plan-v1"
    )
    expected_code = (
        "FUNCTION_CONTEXT_MISSING"
        if type(remaining_ms) is not int
        else "FUNCTION_BUDGET_INSUFFICIENT"
    )
    with pytest.raises(PlanPermissionRepairError) as exc_info:
        validate_versioned_lambda_contract(
            mode="plan",
            event={},
            context=_Context(arn, remaining_ms),
            env={"AWS_LAMBDA_FUNCTION_VERSION": "1"},
        )
    assert exc_info.value.code == expected_code


def test_lambda_handler_fails_closed_without_reviewed_ports(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from tests.test_deployment.test_gug376_plan_permission_repair_aws import (
        _environment,
    )

    install_runtime_factory(None)
    environment, _ = _environment()
    for key, value in environment.items():
        monkeypatch.setenv(key, value)
    monkeypatch.setenv("AWS_LAMBDA_FUNCTION_VERSION", "1")
    context = _Context(
        "arn:aws:lambda:us-east-1:042360977644:function:"
        + FUNCTION_NAMES["plan"]
        + ":plan-v1"
    )
    with pytest.raises(PlanPermissionRepairError) as exc_info:
        plan_handler({}, context)
    assert exc_info.value.code == "RUNTIME_PORTS_NOT_BOUND"
