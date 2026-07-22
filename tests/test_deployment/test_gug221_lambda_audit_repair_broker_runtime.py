from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
import json
import sys
from typing import Any, Mapping

import pytest
from jsonschema import Draft202012Validator


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tooling"))

from platform_authority_lambda_audit_repair_broker import (  # noqa: E402
    Assignment,
    BrokerLiveSnapshot,
    BrokerConfig,
    BrokerContractError,
    CollectorRole,
    LiveSnapshot,
    RepairInvokerSnapshot,
    build_private_ledger_claim,
    canonical_digest,
)
import platform_authority_lambda_audit_repair_broker_runtime as runtime  # noqa: E402
import platform_authority_lambda_audit_repair_iam_verifier as iam_verifier  # noqa: E402


NOW = datetime(2026, 7, 21, 19, 59, tzinfo=timezone.utc)
POLICY = {"Version": "2012-10-17", "Statement": []}
POLICY_DIGEST = canonical_digest(POLICY)
INVOKER_POLICY = {
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Deny", "Action": "*", "Resource": "*"}],
}
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
    result = {
        "FUNCTION_MODE": "spoofed-and-ignored",
        "FUNCTION_QUALIFIER": "spoofed-and-ignored",
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
        "EXPECTED_PERMISSION_SET_TAGS_JSON": json.dumps(
            {"scanalyze:control": "lambda-audit", "scanalyze:managed-by": "gug-221"}
        ),
        "REPAIR_LEDGER_TABLE_NAME": (
            "scanalyze-platform-authority-gug221-repair-ledger"
        ),
        "REPAIR_LEDGER_KMS_KEY_ARN": LEDGER_KMS_KEY_ARN,
        "EXPECTED_ARTIFACT_CODE_SHA256": ARTIFACT_CODE_SHA256,
        "EXPECTED_CODE_SIGNING_CONFIG_ARN": CODE_SIGNING_CONFIG_ARN,
        "EXPECTED_SIGNING_PROFILE_VERSION_ARN": SIGNING_PROFILE_VERSION_ARN,
        "REPAIR_NOT_BEFORE": "2026-07-21T19:55:00Z",
        "REPAIR_NOT_AFTER": "2026-07-21T20:10:00Z",
        "AWS_LAMBDA_FUNCTION_VERSION": "42" if mode == "repair" else "43",
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
    result["_MODE"] = mode
    result["_QUALIFIER"] = qualifiers[mode]
    return result


def config_for(mode: str = "repair", *, kms_mode: str = "AWS_OWNED_KMS_KEY") -> BrokerConfig:
    env = env_for(mode, kms_mode=kms_mode)
    return BrokerConfig.from_env(
        {key: value for key, value in env.items() if not key.startswith("_")},
        mode_override=env["_MODE"],
        qualifier_override=env["_QUALIFIER"],
    )


def write_runtime_lock(
    repo_root: Path, config: BrokerConfig, **changes: object
) -> None:
    value = runtime.expected_runtime_lock(config)
    value.update(changes)
    (repo_root / runtime.RUNTIME_LOCK_RELATIVE_PATH).write_text(
        json.dumps(value, sort_keys=True), encoding="utf-8"
    )


def collector_role(config: BrokerConfig) -> CollectorRole:
    return CollectorRole(
        role_name="AWSReservedSSO_ScanalyzeAuthorityLambdaAudit_0123456789abcdef",
        saml_provider_arn=config.collector_saml_provider_arn,
        saml_audience="https://signin.aws.amazon.com/saml",
        inline_policy_name="AwsSSOInlinePolicy",
        inline_policy_digest=config.collector_policy_digest,
    )


def invoker_role(config: BrokerConfig, **changes: object) -> CollectorRole:
    values: dict[str, object] = {
        "role_name": "AWSReservedSSO_ScanalyzeLambdaAuditRepair_0123456789abcdef",
        "saml_provider_arn": config.collector_saml_provider_arn,
        "saml_audience": "https://signin.aws.amazon.com/saml",
        "inline_policy_name": "AwsSSOInlinePolicy",
        "inline_policy_digest": config.repair_invoker_policy_digest,
        "attached_managed_policy_arns": (),
        "extra_inline_policy_names": (),
        "permissions_boundary_arn": None,
    }
    values.update(changes)
    return CollectorRole(**values)  # type: ignore[arg-type]


def snapshot(config: BrokerConfig, step: int) -> LiveSnapshot:
    return LiveSnapshot(
        instance_arn=config.instance_arn,
        identity_store_id=config.identity_store_id,
        kms_mode=config.identity_center_kms_mode,
        kms_key_arn=config.identity_center_kms_key_arn,
        permission_set_arn=config.collector_permission_set_arn,
        permission_set_name=config.collector_permission_set_name,
        permission_set_description=(
            "GUG-219 read-only account-wide Lambda invocation-authority inventory"
        ),
        session_duration="PT1H",
        relay_state=None,
        permission_set_tags=config.expected_permission_set_tags,
        inline_policy_digest=config.collector_policy_digest if step >= 1 else None,
        managed_policy_arns=(),
        customer_managed_policy_references=(),
        permissions_boundary_present=False,
        assignments=(Assignment("USER", config.principal_id),) if step >= 2 else (),
        provisioned_account_ids=(config.authority_account_id,) if step >= 3 else (),
        collector_roles=(collector_role(config),) if step >= 3 else (),
    )


def invoker_snapshot(config: BrokerConfig, **changes: object) -> RepairInvokerSnapshot:
    values: dict[str, object] = {
        "permission_set_arn": config.repair_invoker_permission_set_arn,
        "permission_set_name": "ScanalyzeLambdaAuditRepair",
        "permission_set_description": (
            "GUG-221 invoke-only private repair PEP boundary"
        ),
        "session_duration": "PT1H",
        "relay_state": None,
        "permission_set_tags": config.expected_repair_invoker_tags,
        "inline_policy_digest": config.repair_invoker_policy_digest,
        "managed_policy_arns": (),
        "customer_managed_policy_references": (),
        "permissions_boundary_present": False,
        "assignments": (Assignment("USER", config.principal_id),),
        "provisioned_account_ids": (config.authority_account_id,),
        "invoker_roles": (invoker_role(config),),
    }
    values.update(changes)
    return RepairInvokerSnapshot(**values)  # type: ignore[arg-type]


def local_snapshot(
    config: BrokerConfig, **changes: object
) -> runtime.LocalControlPlaneSnapshot:
    reconcile_version = config.function_version if config.mode == "reconcile" else "43"
    values: dict[str, object] = {
        "repair_function_version": config.repair_function_version,
        "plan_function_version": config.plan_function_version,
        "reconcile_function_version": reconcile_version,
        "artifact_code_sha256": config.expected_artifact_code_sha256,
        "code_signing_config_arn": config.expected_code_signing_config_arn,
        "signing_profile_version_arn": (
            config.expected_signing_profile_version_arn
        ),
        "ledger_table_arn": (
            "arn:aws:dynamodb:us-east-1:042360977644:"
            f"table/{config.ledger_table_name}"
        ),
        "ledger_kms_key_arn": config.repair_ledger_kms_key_arn,
        "lambda_controls_digest": "1" * 64,
        "ledger_controls_digest": "2" * 64,
        "kms_controls_digest": "3" * 64,
    }
    values.update(changes)
    return runtime.LocalControlPlaneSnapshot(**values)  # type: ignore[arg-type]


def iam_snapshot(config: BrokerConfig) -> iam_verifier.IamEffectiveSnapshot:
    specs = iam_verifier.expected_role_specs(config, repo_root=ROOT)
    roles = tuple(
        iam_verifier.IamRoleSnapshot(
            account_id=spec.account_id,
            role_name=spec.role_name,
            path=spec.path,
            arn=spec.arn,
            max_session_duration=iam_verifier.MAX_SESSION_DURATION_SECONDS,
            trust_policy_digest=spec.trust_policy_digest,
            inline_policy_name=spec.inline_policy_name,
            inline_policy_digest=spec.inline_policy_digest,
            attached_managed_policy_arns=(),
            permissions_boundary_arn=None,
        )
        for spec in specs
    )
    return iam_verifier.IamEffectiveSnapshot(
        authority_roles=roles[:4],
        management_roles=roles[4:],
    )


def invocation_authority_snapshot(
    *, authority_graph_digest: str = "4" * 64
) -> runtime.VerifiedRepairInvocationAuthority:
    return runtime.VerifiedRepairInvocationAuthority(
        binding_digest="5" * 64,
        collector_principal_digest="6" * 64,
        plan_snapshot_digest="7" * 64,
        repair_snapshot_digest="8" * 64,
        reconcile_snapshot_digest="9" * 64,
        authority_graph_digest=authority_graph_digest,
        expected_edge_count=3,
        verified_at="2026-07-21T20:00:00Z",
        expires_at="2026-07-21T20:05:00Z",
    )


def verified_state_digest(config: BrokerConfig) -> str:
    return runtime.VerifiedBrokerLiveSnapshot(
        identity=BrokerLiveSnapshot(
            invoker=invoker_snapshot(config),
            collector=snapshot(config, 0),
        ),
        local=local_snapshot(config),
        iam=iam_snapshot(config),
        invocation_authority=invocation_authority_snapshot(),
    ).digest()


def plan_claim(
    config: BrokerConfig, *, state_digest: str | None = None
) -> dict[str, Any]:
    return build_private_ledger_claim(
        config_for("plan", kms_mode=config.identity_center_kms_mode),
        NOW,
        state_digest or verified_state_digest(config),
    )


class FakeLocalControlPlane:
    def __init__(
        self,
        config: BrokerConfig,
        timeline: list[str],
        *,
        override: runtime.LocalControlPlaneSnapshot | None = None,
        fail_on_call: int | None = None,
    ) -> None:
        self.config = config
        self.timeline = timeline
        self.override = override
        self.fail_on_call = fail_on_call
        self.calls = 0

    def snapshot(self, config: BrokerConfig) -> runtime.LocalControlPlaneSnapshot:
        assert config == self.config
        self.calls += 1
        self.timeline.append(f"local:snapshot:{self.calls}")
        if self.fail_on_call == self.calls:
            raise BrokerContractError(
                "LOCAL_CONTROL_PLANE_MISMATCH", "synthetic local drift"
            )
        return self.override or local_snapshot(config)


class FakeIamEffective:
    def __init__(
        self,
        config: BrokerConfig,
        timeline: list[str],
        *,
        override: iam_verifier.IamEffectiveSnapshot | None = None,
        fail_on_call: int | None = None,
    ) -> None:
        self.config = config
        self.timeline = timeline
        self.override = override
        self.fail_on_call = fail_on_call
        self.calls = 0

    def snapshot(self, config: BrokerConfig) -> iam_verifier.IamEffectiveSnapshot:
        assert config == self.config
        self.calls += 1
        self.timeline.append(f"iam:snapshot:{self.calls}")
        if self.fail_on_call == self.calls:
            raise BrokerContractError(
                "IAM_EFFECTIVE_STATE_MISMATCH", "synthetic IAM drift"
            )
        return self.override or iam_snapshot(config)


class FakeInvocationAuthority:
    def __init__(
        self,
        timeline: list[str],
        *,
        fail_on_call: int | None = None,
        drift_on_call: int | None = None,
    ) -> None:
        self.timeline = timeline
        self.fail_on_call = fail_on_call
        self.drift_on_call = drift_on_call
        self.calls = 0

    def snapshot(
        self, config: BrokerConfig, invoker: RepairInvokerSnapshot
    ) -> runtime.VerifiedRepairInvocationAuthority:
        del config, invoker
        self.calls += 1
        self.timeline.append(f"invocation-authority:snapshot:{self.calls}")
        if self.fail_on_call == self.calls:
            raise runtime.AuthorityInventoryError("SYNTHETIC_AUTHORITY_FAILURE")
        digest = "a" * 64 if self.drift_on_call == self.calls else "4" * 64
        return invocation_authority_snapshot(authority_graph_digest=digest)


class MemoryLedger:
    def __init__(self, timeline: list[str], *, race: bool = False) -> None:
        self.timeline = timeline
        self.item: dict[str, Any] | None = None
        self.race = race
        self.transition_calls: list[dict[str, Any]] = []

    def claim(self, claim: Mapping[str, Any]) -> None:
        self.timeline.append("ledger:claim")
        if self.race or self.item is not None:
            raise BrokerContractError("REPLAY_BLOCKED", "already consumed")
        self.item = dict(claim)

    def read(self, repair_id: str) -> Mapping[str, Any] | None:
        self.timeline.append("ledger:read")
        if self.item is None or self.item.get("repair_id") != repair_id:
            return None
        return dict(self.item)

    def transition(self, **kwargs: Any) -> None:
        self.timeline.append(f"ledger:{kwargs['new_status']}")
        if self.item is None:
            raise BrokerContractError("LEDGER_MISSING", "missing")
        if dict(self.item) != dict(kwargs["expected_ledger"]):
            raise BrokerContractError("LEDGER_CAS_MISMATCH", "expected ledger differs")
        if self.item["status"] != kwargs["expected_status"]:
            raise BrokerContractError("LEDGER_CAS_MISMATCH", "status differs")
        if self.item["intent_digest"] != kwargs["intent_digest"]:
            raise BrokerContractError("LEDGER_CAS_MISMATCH", "intent differs")
        if self.race and kwargs["new_status"] == "CLAIMED":
            raise BrokerContractError("LEDGER_CAS_MISMATCH", "synthetic concurrent consume")
        self.item.update(
            {
                "status": kwargs["new_status"],
                "stage": kwargs["stage"],
                "effects_attempted": kwargs["effects_attempted"],
                "effects_completed": kwargs["effects_completed"],
                "state_digest": kwargs["state_digest"],
                "updated_at": runtime.utc_timestamp(kwargs["updated_at"]),
            }
        )
        if kwargs.get("claimed_at") is not None:
            self.item["claimed_at"] = runtime.utc_timestamp(kwargs["claimed_at"])
        self.transition_calls.append(dict(kwargs))


class FakeIdentity:
    def __init__(
        self,
        config: BrokerConfig,
        timeline: list[str],
        *,
        ambiguous_effect: str | None = None,
        initial_override: LiveSnapshot | None = None,
        invoker_override: RepairInvokerSnapshot | None = None,
    ) -> None:
        self.config = config
        self.timeline = timeline
        self.step = 0
        self.ambiguous_effect = ambiguous_effect
        self.initial_override = initial_override
        self.invoker_override = invoker_override
        self.mutation_calls: list[str] = []

    def snapshot(
        self,
        config: BrokerConfig,
        policy: Mapping[str, Any],
        repair_invoker_policy: Mapping[str, Any],
    ) -> BrokerLiveSnapshot:
        assert config == self.config
        assert canonical_digest(policy) == config.collector_policy_digest
        assert canonical_digest(repair_invoker_policy) == config.repair_invoker_policy_digest
        self.timeline.append(f"provider:snapshot:{self.step}")
        collector = (
            self.initial_override
            if self.step == 0 and self.initial_override is not None
            else snapshot(config, self.step)
        )
        return BrokerLiveSnapshot(
            invoker=self.invoker_override or invoker_snapshot(config),
            collector=collector,
        )

    def _mutate(self, name: str, next_step: int) -> None:
        self.timeline.append(f"provider:{name}")
        self.mutation_calls.append(name)
        if self.ambiguous_effect == name:
            raise runtime.ProviderResponseAmbiguous("synthetic timeout")
        self.step = next_step

    def put_inline_policy(self, config: BrokerConfig, policy_json: str) -> None:
        assert json.loads(policy_json) == POLICY
        self._mutate("put", 1)

    def create_account_assignment(self, config: BrokerConfig) -> runtime.OperationResult:
        self._mutate("assign", 2)
        return runtime.OperationResult("assignment-request", "SUCCEEDED")

    def describe_account_assignment(self, request_id: str) -> str:
        self.timeline.append("provider:describe-assignment")
        return "SUCCEEDED"

    def provision_permission_set(self, config: BrokerConfig) -> runtime.OperationResult:
        self._mutate("provision", 3)
        return runtime.OperationResult("provision-request", "SUCCEEDED")

    def describe_provisioning(self, request_id: str) -> str:
        self.timeline.append("provider:describe-provision")
        return "SUCCEEDED"


def broker(
    config: BrokerConfig,
    identity: FakeIdentity,
    ledger: MemoryLedger,
    *,
    now: Any = lambda: NOW,
    remaining_time_ms: Any = lambda: 600_000,
    local_control_plane: FakeLocalControlPlane | None = None,
    iam_effective: FakeIamEffective | None = None,
    invocation_authority: FakeInvocationAuthority | None = None,
    seed_plan: bool = True,
) -> runtime.RepairBroker:
    if config.mode == "repair":
        function = "scanalyze-authority-lambda-audit-repair"
        role = "ScanalyzeLambdaAuditRepairExecution"
        if seed_plan and ledger.item is None:
            ledger.item = plan_claim(config)
    elif config.mode == "plan":
        function = "scanalyze-authority-lambda-audit-plan"
        role = "ScanalyzeLambdaAuditRepairPlan"
    else:
        function = "scanalyze-authority-lambda-audit-reconcile"
        role = "ScanalyzeLambdaAuditRepairReconcile"
    return runtime.RepairBroker(
        config=config,
        identity=identity,
        local_control_plane=(
            local_control_plane
            or FakeLocalControlPlane(config, identity.timeline)
        ),
        iam_effective=(
            iam_effective or FakeIamEffective(config, identity.timeline)
        ),
        invocation_authority=(
            invocation_authority or FakeInvocationAuthority(identity.timeline)
        ),
        ledger=ledger,
        collector_policy=POLICY,
        repair_invoker_policy=INVOKER_POLICY,
        invoked_function_arn=(
            f"arn:aws:lambda:us-east-1:042360977644:function:{function}:"
            f"{config.function_qualifier}"
        ),
        caller_arn=(
            f"arn:aws:sts::042360977644:assumed-role/{role}/runtime-session"
        ),
        now=now,
        sleep=lambda _: None,
        remaining_time_ms=remaining_time_ms,
        repo_root=ROOT,
    )


def test_repair_claims_before_first_effect_and_uses_exact_order() -> None:
    config = config_for()
    timeline: list[str] = []
    identity = FakeIdentity(config, timeline)
    ledger = MemoryLedger(timeline)

    receipt = broker(config, identity, ledger).run({})

    assert receipt["status"] == "REPAIR_VERIFIED"
    assert receipt["effects_attempted"] == 3
    assert receipt["effects_completed"] == 3
    assert receipt["mutation_attribution"] == "PROVEN_BY_DURABLE_LEDGER"
    assert identity.mutation_calls == ["put", "assign", "provision"]
    assert timeline.index("ledger:CLAIMED") < timeline.index("provider:put")
    assert timeline.index("ledger:ATTEMPTING_1") < timeline.index("provider:put")
    assert timeline.index("ledger:ATTEMPTING_2") < timeline.index("provider:assign")
    assert timeline.index("ledger:ATTEMPTING_3") < timeline.index("provider:provision")


def test_repair_uses_five_complete_snapshots() -> None:
    config = config_for()
    timeline: list[str] = []
    identity = FakeIdentity(config, timeline)
    ledger = MemoryLedger(timeline)
    authority = FakeInvocationAuthority(timeline)

    receipt = broker(
        config,
        identity,
        ledger,
        invocation_authority=authority,
    ).run({})

    assert receipt["status"] == "REPAIR_VERIFIED"
    assert authority.calls == 5
    assert sum(item.startswith("provider:snapshot:") for item in timeline) == 5


def test_repair_without_durable_plan_fails_before_any_effect() -> None:
    config = config_for()
    timeline: list[str] = []
    identity = FakeIdentity(config, timeline)
    ledger = MemoryLedger(timeline)

    with pytest.raises(BrokerContractError) as captured:
        broker(config, identity, ledger, seed_plan=False).run({})

    assert captured.value.code == "PLAN_REQUIRED"
    assert ledger.item is None
    assert identity.mutation_calls == []


def test_unverified_invocation_authority_blocks_before_ledger_or_effect() -> None:
    config = config_for()
    timeline: list[str] = []
    identity = FakeIdentity(config, timeline)
    ledger = MemoryLedger(timeline)
    authority = FakeInvocationAuthority(timeline, fail_on_call=1)

    with pytest.raises(BrokerContractError) as captured:
        broker(
            config,
            identity,
            ledger,
            invocation_authority=authority,
            seed_plan=False,
        ).run({})

    assert captured.value.code == "INVOCATION_AUTHORITY_UNVERIFIED"
    assert ledger.item is None
    assert identity.mutation_calls == []


def test_invocation_authority_drift_blocks_before_first_effect() -> None:
    config = config_for()
    timeline: list[str] = []
    identity = FakeIdentity(config, timeline)
    ledger = MemoryLedger(timeline)
    authority = FakeInvocationAuthority(timeline, drift_on_call=2)

    receipt = broker(
        config,
        identity,
        ledger,
        invocation_authority=authority,
    ).run({})

    assert receipt["status"] == "BLOCKED"
    assert receipt["effects_attempted"] == 0
    assert identity.mutation_calls == []
    assert ledger.item and ledger.item["status"] == "ATTEMPTING_1"


def test_local_control_plane_drift_blocks_before_ledger_claim_or_effect() -> None:
    config = config_for()
    timeline: list[str] = []
    identity = FakeIdentity(config, timeline)
    ledger = MemoryLedger(timeline)
    local = FakeLocalControlPlane(
        config,
        timeline,
        override=local_snapshot(config, artifact_code_sha256="B" * 43 + "="),
    )

    with pytest.raises(BrokerContractError) as captured:
        broker(
            config,
            identity,
            ledger,
            local_control_plane=local,
            seed_plan=False,
        ).run({})

    assert captured.value.code == "LOCAL_CONTROL_PLANE_MISMATCH"
    assert ledger.item is None
    assert identity.mutation_calls == []


def test_effective_iam_drift_blocks_before_ledger_claim_or_effect() -> None:
    config = config_for()
    timeline: list[str] = []
    identity = FakeIdentity(config, timeline)
    ledger = MemoryLedger(timeline)
    expected = iam_snapshot(config)
    bad_authority = (
        replace(expected.authority_roles[0], max_session_duration=7200),
        *expected.authority_roles[1:],
    )
    iam = FakeIamEffective(
        config,
        timeline,
        override=iam_verifier.IamEffectiveSnapshot(
            authority_roles=bad_authority,
            management_roles=expected.management_roles,
        ),
    )

    with pytest.raises(BrokerContractError) as captured:
        broker(config, identity, ledger, iam_effective=iam, seed_plan=False).run({})

    assert captured.value.code == "AUTHORITY_IAM_SNAPSHOT_MISMATCH"
    assert ledger.item is None
    assert identity.mutation_calls == []


@pytest.mark.parametrize("boundary", ["local", "iam"])
def test_final_control_plane_drift_never_returns_repair_verified(
    boundary: str,
) -> None:
    config = config_for()
    timeline: list[str] = []
    identity = FakeIdentity(config, timeline)
    ledger = MemoryLedger(timeline)
    local = FakeLocalControlPlane(
        config,
        timeline,
        fail_on_call=5 if boundary == "local" else None,
    )
    iam = FakeIamEffective(
        config,
        timeline,
        fail_on_call=5 if boundary == "iam" else None,
    )

    receipt = broker(
        config,
        identity,
        ledger,
        local_control_plane=local,
        iam_effective=iam,
    ).run({})

    assert receipt["status"] == "UNCERTAIN_RECONCILE_ONLY"
    assert receipt["required_next_action"] == "INVOKE_RECONCILE_ALIAS"
    assert receipt["effects_attempted"] == 3
    assert receipt["effects_completed"] == 3
    assert ledger.item is not None
    assert ledger.item["stage"] == "UNCERTAIN_FINAL_READBACK"


@pytest.mark.parametrize("payload", [{"mode": "repair"}, {"PrincipalId": PRINCIPAL_ID}, {"policy": POLICY}])
def test_request_cannot_select_mode_principal_or_policy(payload: dict[str, Any]) -> None:
    config = config_for()
    timeline: list[str] = []
    identity = FakeIdentity(config, timeline)
    ledger = MemoryLedger(timeline)
    with pytest.raises(BrokerContractError):
        broker(config, identity, ledger, seed_plan=False).run(payload)
    assert identity.mutation_calls == []
    assert ledger.item is None


@pytest.mark.parametrize(
    "bad_state",
    [
        lambda config: LiveSnapshot(
            **{**snapshot(config, 0).__dict__, "assignments": (Assignment("GROUP", config.principal_id),)}
        ),
        lambda config: LiveSnapshot(
            **{
                **snapshot(config, 0).__dict__,
                "assignments": (
                    Assignment("USER", "abcdef1234-aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"),
                ),
            }
        ),
        lambda config: LiveSnapshot(
            **{
                **snapshot(config, 0).__dict__,
                "managed_policy_arns": ("arn:aws:iam::aws:policy/ReadOnlyAccess",),
            }
        ),
    ],
)
def test_foreign_principal_group_or_policy_is_blocked_before_cas(bad_state: Any) -> None:
    config = config_for()
    timeline: list[str] = []
    identity = FakeIdentity(config, timeline, initial_override=bad_state(config))
    ledger = MemoryLedger(timeline)
    with pytest.raises(BrokerContractError):
        broker(config, identity, ledger, seed_plan=False).run({})
    assert ledger.item is None
    assert identity.mutation_calls == []


@pytest.mark.parametrize(
    "changes",
    [
        {"permission_set_name": "ForeignRepair"},
        {"permission_set_description": "foreign"},
        {"session_duration": "PT8H"},
        {"relay_state": "https://example.invalid"},
        {"permission_set_tags": (("managed_by", "manual"),)},
        {"inline_policy_digest": "0" * 64},
        {"managed_policy_arns": ("arn:aws:iam::aws:policy/ReadOnlyAccess",)},
        {"permissions_boundary_present": True},
        {"assignments": (Assignment("GROUP", PRINCIPAL_ID),)},
        {"provisioned_account_ids": ("999999999999",)},
        {"invoker_roles": ()},
        {
            "invoker_roles": (
                invoker_role(config_for()),
                invoker_role(
                    config_for(),
                    role_name=(
                        "AWSReservedSSO_ScanalyzeLambdaAuditRepair_"
                        "fedcba9876543210"
                    ),
                ),
            )
        },
        {
            "invoker_roles": (
                invoker_role(config_for(), inline_policy_digest="0" * 64),
            )
        },
        {
            "invoker_roles": (
                invoker_role(
                    config_for(),
                    attached_managed_policy_arns=(
                        "arn:aws:iam::aws:policy/ReadOnlyAccess",
                    ),
                ),
            )
        },
        {
            "invoker_roles": (
                invoker_role(
                    config_for(),
                    permissions_boundary_arn="arn:aws:iam::042360977644:policy/foreign",
                ),
            )
        },
        {
            "invoker_roles": (
                invoker_role(
                    config_for(),
                    saml_audience="https://example.invalid",
                ),
            )
        },
    ],
)
def test_repair_invoker_permission_set_drift_blocks_before_cas(
    changes: dict[str, object]
) -> None:
    config = config_for()
    timeline: list[str] = []
    identity = FakeIdentity(
        config,
        timeline,
        invoker_override=invoker_snapshot(config, **changes),
    )
    ledger = MemoryLedger(timeline)
    with pytest.raises(BrokerContractError):
        broker(config, identity, ledger, seed_plan=False).run({})
    assert ledger.item is None
    assert identity.mutation_calls == []


def test_bundled_repair_invoker_policy_digest_is_authoritative() -> None:
    config = config_for()
    timeline: list[str] = []
    with pytest.raises(BrokerContractError, match="bundled repair invoker policy"):
        runtime.RepairBroker(
            config=config,
            identity=FakeIdentity(config, timeline),
            local_control_plane=FakeLocalControlPlane(config, timeline),
            iam_effective=FakeIamEffective(config, timeline),
            invocation_authority=FakeInvocationAuthority(timeline),
            ledger=MemoryLedger(timeline),
            collector_policy=POLICY,
            repair_invoker_policy={"Version": "2012-10-17", "Statement": []},
            invoked_function_arn=(
                "arn:aws:lambda:us-east-1:042360977644:function:"
                "scanalyze-authority-lambda-audit-repair:repair-v1"
            ),
            caller_arn=(
                "arn:aws:sts::042360977644:assumed-role/"
                "ScanalyzeLambdaAuditRepairExecution/runtime-session"
            ),
            now=lambda: NOW,
            repo_root=ROOT,
        )


def test_bundled_collector_policy_is_rendered_before_digest_and_submission() -> None:
    policy = runtime.load_bundled_collector_policy(ROOT)
    serialized = json.dumps(policy, sort_keys=True, separators=(",", ":"))

    assert "${" not in serialized
    assert "arn:aws:lambda:*:042360977644:function:*" in serialized
    assert (
        "arn:aws:lambda:us-east-1:042360977644:function:"
        "scanalyze-platform-authority-gug215-retirement"
    ) in serialized

    env = env_for()
    env["COLLECTOR_POLICY_DIGEST"] = canonical_digest(policy)
    config = BrokerConfig.from_env(
        {key: value for key, value in env.items() if not key.startswith("_")},
        mode_override=env["_MODE"],
        qualifier_override=env["_QUALIFIER"],
    )
    assert runtime._assert_policy_binding(config, policy) == serialized


def test_runtime_sdk_versions_match_exact_reviewed_values() -> None:
    config = config_for()

    class Boto3:
        __version__ = "1.40.1"

    class Botocore:
        __version__ = "1.40.1"

    runtime.validate_runtime_sdk_versions(
        config,
        boto3_module=Boto3,
        botocore_module=Botocore,
    )


@pytest.mark.parametrize(
    ("boto3_version", "botocore_version", "code"),
    [
        ("1.40.2", "1.40.1", "BOTO3_VERSION_MISMATCH"),
        (None, "1.40.1", "BOTO3_VERSION_MISMATCH"),
        ("1.40.1", "1.40.2", "BOTOCORE_VERSION_MISMATCH"),
        ("1.40.1", None, "BOTOCORE_VERSION_MISMATCH"),
    ],
)
def test_runtime_sdk_drift_blocks_before_any_aws_client(
    tmp_path: Path,
    boto3_version: str | None,
    botocore_version: str | None,
    code: str,
) -> None:
    class Boto3:
        def client(self, *_args: Any, **_kwargs: Any) -> Any:
            raise AssertionError("AWS client must not be constructed")

    class Botocore:
        pass

    if boto3_version is not None:
        Boto3.__version__ = boto3_version
    if botocore_version is not None:
        Botocore.__version__ = botocore_version

    write_runtime_lock(tmp_path, config_for())

    with pytest.raises(BrokerContractError) as captured:
        runtime.build_runtime(
            env={key: value for key, value in env_for().items() if not key.startswith("_")},
            invoked_function_arn=(
                "arn:aws:lambda:us-east-1:042360977644:function:"
                "scanalyze-authority-lambda-audit-repair:repair-v1"
            ),
            boto3_module=Boto3(),
            botocore_module=Botocore(),
            botocore_config=object(),
            mode="repair",
            qualifier="repair-v1",
            repo_root=tmp_path,
        )
    assert captured.value.code == code


@pytest.mark.parametrize(
    ("lock_state", "code"),
    [
        ("missing", "RUNTIME_LOCK_UNAVAILABLE"),
        ("source-drift", "RUNTIME_LOCK_MISMATCH"),
        ("unexpected-field", "RUNTIME_LOCK_MISMATCH"),
        ("duplicate-key", "RUNTIME_LOCK_INVALID"),
    ],
)
def test_runtime_lock_blocks_before_any_aws_client(
    tmp_path: Path, lock_state: str, code: str
) -> None:
    config = config_for()

    class Boto3:
        __version__ = "1.40.1"

        def client(self, *_args: Any, **_kwargs: Any) -> Any:
            raise AssertionError("AWS client must not be constructed")

    class Botocore:
        __version__ = "1.40.1"

    if lock_state == "source-drift":
        write_runtime_lock(tmp_path, config, source_commit="b" * 40)
    elif lock_state == "unexpected-field":
        write_runtime_lock(tmp_path, config, unexpected="authority")
    elif lock_state == "duplicate-key":
        (tmp_path / runtime.RUNTIME_LOCK_RELATIVE_PATH).write_text(
            '{"schema_version":1,"schema_version":1}', encoding="utf-8"
        )

    with pytest.raises(BrokerContractError) as captured:
        runtime.build_runtime(
            env={key: value for key, value in env_for().items() if not key.startswith("_")},
            invoked_function_arn=(
                "arn:aws:lambda:us-east-1:042360977644:function:"
                "scanalyze-authority-lambda-audit-repair:repair-v1"
            ),
            boto3_module=Boto3(),
            botocore_module=Botocore(),
            botocore_config=object(),
            mode="repair",
            qualifier="repair-v1",
            repo_root=tmp_path,
        )
    assert captured.value.code == code


def test_sdk_clients_use_bounded_timeouts_and_one_attempt() -> None:
    class Config:
        def __init__(self, **kwargs: Any) -> None:
            self.kwargs = kwargs

    factory = runtime.BotoSessionFactory(object(), Config)
    assert factory.client_config.kwargs == {
        "region_name": "us-east-1",
        "retries": {"mode": "standard", "total_max_attempts": 1},
        "connect_timeout": runtime.SDK_CONNECT_TIMEOUT_SECONDS,
        "read_timeout": runtime.SDK_READ_TIMEOUT_SECONDS,
    }
    sdk_timeout_ms = (
        runtime.SDK_CONNECT_TIMEOUT_SECONDS + runtime.SDK_READ_TIMEOUT_SECONDS
    ) * 1_000
    assert runtime.LAMBDA_MUTATION_DISPATCH_MIN_REMAINING_MS > sdk_timeout_ms
    assert runtime.LAMBDA_POLLING_RESERVE_MS > sdk_timeout_ms
    assert runtime.FUNCTION_TIMEOUT_SECONDS == {
        "plan": 300,
        "repair": 600,
        "reconcile": 300,
    }
    assert runtime.FUNCTION_MEMORY_SIZE_MB == 1024
    assert runtime.INVENTORY_PROVIDER_CALL_RESERVE_MS == 60_000
    assert runtime.LAMBDA_POLLING_RESERVE_MS == 60_000
    assert runtime.LAMBDA_MUTATION_DISPATCH_MIN_REMAINING_MS == 75_000
    assert runtime.REPAIR_CLAIM_MIN_REMAINING_MS == 480_000
    assert runtime.MUTATION_WINDOW_MIN_REMAINING_SECONDS == 75
    assert runtime.REPAIR_START_MIN_WINDOW_REMAINING_SECONDS == 660


def test_inventory_provider_call_budget_is_enforced_before_every_call() -> None:
    class Client:
        marker = "preserved"

        def __init__(self) -> None:
            self.calls = 0

        def list_functions(self) -> dict[str, list[object]]:
            self.calls += 1
            return {"Functions": []}

    client = Client()
    blocked = runtime._BudgetGuardedClient(
        client,
        lambda: runtime.INVENTORY_PROVIDER_CALL_RESERVE_MS,
    )
    assert blocked.marker == "preserved"
    with pytest.raises(runtime.AuthorityInventoryError) as captured:
        blocked.list_functions()
    assert str(captured.value) == "LAMBDA_BUDGET_INSUFFICIENT"
    assert client.calls == 0

    allowed = runtime._BudgetGuardedClient(
        client,
        lambda: runtime.INVENTORY_PROVIDER_CALL_RESERVE_MS + 1,
    )
    assert allowed.list_functions() == {"Functions": []}
    assert client.calls == 1


def test_durable_cas_race_blocks_every_effect() -> None:
    config = config_for()
    timeline: list[str] = []
    identity = FakeIdentity(config, timeline)
    ledger = MemoryLedger(timeline, race=True)
    receipt = broker(config, identity, ledger).run({})
    assert receipt["status"] == "UNCERTAIN_RECONCILE_ONLY"
    assert receipt["required_next_action"] == "INVOKE_RECONCILE_ALIAS"
    assert identity.mutation_calls == []


def test_ambiguous_attempting_cas_does_not_attribute_or_dispatch_sso() -> None:
    config = config_for()
    timeline: list[str] = []

    class AmbiguousTransitionLedger(MemoryLedger):
        def transition(self, **kwargs: Any) -> None:
            if kwargs["new_status"] == "ATTEMPTING_1":
                raise runtime.ProviderResponseAmbiguous("synthetic CAS timeout")
            super().transition(**kwargs)

    ledger = AmbiguousTransitionLedger(timeline)
    identity = FakeIdentity(config, timeline)
    receipt = broker(config, identity, ledger).run({})
    assert receipt["status"] == "BLOCKED"
    assert receipt["mutation_attribution"] == "UNPROVEN"
    assert receipt["effects_attempted"] == 0
    assert receipt["effects_completed"] == 0
    assert identity.mutation_calls == []


def test_deterministic_precondition_drift_after_first_effect_is_blocked_not_uncertain() -> None:
    config = config_for()
    timeline: list[str] = []

    class DriftAfterPut(FakeIdentity):
        def snapshot(
            self,
            config: BrokerConfig,
            policy: Mapping[str, Any],
            repair_invoker_policy: Mapping[str, Any],
        ) -> BrokerLiveSnapshot:
            observed = super().snapshot(config, policy, repair_invoker_policy)
            if self.step == 1:
                return BrokerLiveSnapshot(
                    invoker=observed.invoker,
                    collector=LiveSnapshot(
                        **{
                            **observed.collector.__dict__,
                            "managed_policy_arns": (
                                "arn:aws:iam::aws:policy/ReadOnlyAccess",
                            ),
                        }
                    ),
                )
            return observed

    identity = DriftAfterPut(config, timeline)
    ledger = MemoryLedger(timeline)
    receipt = broker(config, identity, ledger).run({})
    assert receipt["status"] == "BLOCKED"
    assert receipt["effects_attempted"] == 1
    assert receipt["effects_completed"] == 1
    assert receipt["mutation_attribution"] == "PROVEN_BY_DURABLE_LEDGER"
    assert identity.mutation_calls == ["put"]


@pytest.mark.parametrize("claim_visible", [False, True])
def test_ambiguous_durable_plan_never_dispatches_provider_effect(claim_visible: bool) -> None:
    config = config_for("plan")
    timeline: list[str] = []

    class AmbiguousLedger(MemoryLedger):
        def claim(self, claim: Mapping[str, Any]) -> None:
            self.timeline.append("ledger:claim-ambiguous")
            if claim_visible:
                self.item = dict(claim)
            raise runtime.ProviderResponseAmbiguous("synthetic timeout")

    ledger = AmbiguousLedger(timeline)
    identity = FakeIdentity(config, timeline)
    if claim_visible:
        receipt = broker(config, identity, ledger).run({})
        assert receipt["status"] == "PLAN_VERIFIED"
        assert receipt["required_next_action"] == "INVOKE_REPAIR_ALIAS"
        assert receipt["mutation_attribution"] == "PROVEN_BY_DURABLE_LEDGER"
    else:
        with pytest.raises(BrokerContractError) as captured:
            broker(config, identity, ledger).run({})
        assert captured.value.code == "LEDGER_MISSING"
    assert identity.mutation_calls == []


@pytest.mark.parametrize("effect", ["put", "assign", "provision"])
def test_ambiguous_provider_response_is_permanent_and_never_retried(effect: str) -> None:
    config = config_for()
    timeline: list[str] = []
    identity = FakeIdentity(config, timeline, ambiguous_effect=effect)
    ledger = MemoryLedger(timeline)
    receipt = broker(config, identity, ledger).run({})
    assert receipt["status"] == "UNCERTAIN_RECONCILE_ONLY"
    assert receipt["required_next_action"] == "INVOKE_RECONCILE_ALIAS"
    assert identity.mutation_calls.count(effect) == 1
    assert ledger.item and ledger.item["status"] == "UNCERTAIN_RECONCILE_ONLY"

    second_identity = FakeIdentity(config, timeline)
    with pytest.raises(BrokerContractError, match="already consumed"):
        broker(config, second_identity, ledger).run({})
    assert second_identity.mutation_calls == []


def test_reconcile_is_read_only_and_counts_come_only_from_ledger() -> None:
    repair_config = config_for("repair")
    reconcile_config = config_for("reconcile")
    timeline: list[str] = []
    ledger = MemoryLedger(timeline)
    claim = plan_claim(repair_config)
    ledger.item = dict(claim)
    ledger.item.update(
        {
            "status": "REPAIR_VERIFIED",
            "stage": "FINAL_READBACK_VERIFIED",
            "effects_attempted": 3,
            "effects_completed": 3,
            "state_digest": "9" * 64,
            "claimed_at": "2026-07-21T20:00:00Z",
            "updated_at": "2026-07-21T20:00:00Z",
        }
    )
    identity = FakeIdentity(reconcile_config, timeline)
    identity.step = 3
    receipt = broker(reconcile_config, identity, ledger).run({})
    assert receipt["status"] == "RECONCILE_VERIFIED"
    assert receipt["effects_attempted"] == 3
    assert receipt["effects_completed"] == 3
    assert receipt["mutation_attribution"] == "PROVEN_BY_DURABLE_LEDGER"
    assert identity.mutation_calls == []
    assert ledger.transition_calls == []


@pytest.mark.parametrize(
    ("status", "stage", "attempted", "completed"),
    [
        ("CLAIMED", "BEFORE_FIRST_EFFECT", 0, 0),
        ("COMPLETED_1", "AFTER_PUT_INLINE_POLICY", 1, 1),
        ("COMPLETED_2", "AFTER_CREATE_ACCOUNT_ASSIGNMENT", 3, 1),
    ],
)
def test_reconcile_never_attributes_final_state_to_incomplete_or_impossible_ledger(
    status: str, stage: str, attempted: int, completed: int
) -> None:
    repair_config = config_for("repair")
    reconcile_config = config_for("reconcile")
    timeline: list[str] = []
    ledger = MemoryLedger(timeline)
    ledger.item = dict(plan_claim(repair_config))
    ledger.item.update(
        {
            "status": status,
            "stage": stage,
            "effects_attempted": attempted,
            "effects_completed": completed,
            "state_digest": "9" * 64,
            "claimed_at": "2026-07-21T20:00:00Z",
            "updated_at": "2026-07-21T20:00:00Z",
        }
    )
    identity = FakeIdentity(reconcile_config, timeline)
    identity.step = 3
    receipt = broker(reconcile_config, identity, ledger).run({})
    assert receipt["status"] == "BLOCKED"
    assert receipt["mutation_attribution"] == "UNPROVEN"
    assert receipt["required_next_action"] == "REVIEW_BLOCKER"
    assert identity.mutation_calls == []


def test_reconcile_can_verify_final_state_after_third_effect_uncertainty() -> None:
    repair_config = config_for("repair")
    reconcile_config = config_for("reconcile")
    timeline: list[str] = []
    ledger = MemoryLedger(timeline)
    ledger.item = dict(plan_claim(repair_config))
    ledger.item.update(
        {
            "status": "UNCERTAIN_RECONCILE_ONLY",
            "stage": "UNCERTAIN_PROVISION_PERMISSION_SET",
            "effects_attempted": 3,
            "effects_completed": 2,
            "state_digest": "9" * 64,
            "claimed_at": "2026-07-21T20:00:00Z",
            "updated_at": "2026-07-21T20:00:00Z",
        }
    )
    identity = FakeIdentity(reconcile_config, timeline)
    identity.step = 3
    receipt = broker(reconcile_config, identity, ledger).run({})
    assert receipt["status"] == "RECONCILE_VERIFIED"
    assert receipt["mutation_attribution"] == "PROVEN_BY_DURABLE_LEDGER"


@pytest.mark.parametrize(
    ("field", "weakened"),
    [
        ("provider_immutable", False),
        ("claim_condition", "attribute_exists(repair_id)"),
        ("mutation_retry_attempted", True),
        ("production_authorized", True),
    ],
)
def test_reconcile_rejects_weakened_durable_ledger_constants(
    field: str, weakened: object
) -> None:
    repair_config = config_for("repair")
    reconcile_config = config_for("reconcile")
    timeline: list[str] = []
    ledger = MemoryLedger(timeline)
    ledger.item = dict(plan_claim(repair_config))
    ledger.item[field] = weakened
    identity = FakeIdentity(reconcile_config, timeline)
    identity.step = 3
    receipt = broker(reconcile_config, identity, ledger).run({})
    assert receipt["status"] == "BLOCKED"
    assert receipt["ledger_digest"] is None
    assert receipt["mutation_attribution"] == "UNPROVEN"
    assert identity.mutation_calls == []
    assert ledger.transition_calls == []


def test_plan_is_read_only_and_requires_unconsumed_repair_id() -> None:
    config = config_for("plan")
    timeline: list[str] = []
    ledger = MemoryLedger(timeline)
    identity = FakeIdentity(config, timeline)
    receipt = broker(config, identity, ledger).run({})
    assert receipt["status"] == "PLAN_VERIFIED"
    assert receipt["mutation_attribution"] == "PROVEN_BY_DURABLE_LEDGER"
    assert receipt["required_next_action"] == "INVOKE_REPAIR_ALIAS"
    assert ledger.item and ledger.item["status"] == "PLAN_VERIFIED"
    assert identity.mutation_calls == []
    assert ledger.transition_calls == []


def test_time_drift_before_effect_consumes_ledger_without_mutation() -> None:
    config = config_for()
    timeline: list[str] = []
    identity = FakeIdentity(config, timeline)
    ledger = MemoryLedger(timeline)
    values = [NOW, NOW, NOW + timedelta(minutes=20)]

    def drifting_clock() -> datetime:
        return values.pop(0) if values else NOW + timedelta(minutes=20)

    receipt = broker(config, identity, ledger, now=drifting_clock).run({})
    assert receipt["status"] == "BLOCKED"
    assert receipt["mutation_attribution"] == "UNPROVEN"
    assert receipt["effects_attempted"] == 0
    assert identity.mutation_calls == []
    assert ledger.item and ledger.item["status"] == "CLAIMED"


def test_initial_snapshot_crossing_window_never_claims_or_mutates() -> None:
    config = config_for()
    timeline: list[str] = []
    identity = FakeIdentity(config, timeline)
    ledger = MemoryLedger(timeline)
    values = [NOW, NOW + timedelta(minutes=20)]

    def crossing_clock() -> datetime:
        return values.pop(0) if values else NOW + timedelta(minutes=20)

    with pytest.raises(BrokerContractError) as captured:
        broker(config, identity, ledger, now=crossing_clock).run({})
    assert captured.value.code == "WINDOW_CLOSED"
    assert ledger.item and ledger.item["status"] == "PLAN_VERIFIED"
    assert identity.mutation_calls == []


def test_repair_requires_full_window_before_consuming_durable_plan() -> None:
    config = config_for()
    timeline: list[str] = []
    identity = FakeIdentity(config, timeline)
    ledger = MemoryLedger(timeline)
    authority = FakeInvocationAuthority(timeline)
    late = config.not_after - timedelta(
        seconds=runtime.REPAIR_START_MIN_WINDOW_REMAINING_SECONDS - 1
    )

    with pytest.raises(BrokerContractError) as captured:
        broker(
            config,
            identity,
            ledger,
            invocation_authority=authority,
            now=lambda: late,
        ).run({})

    assert captured.value.code == "REPAIR_WINDOW_INSUFFICIENT"
    assert ledger.item and ledger.item["status"] == "PLAN_VERIFIED"
    assert authority.calls == 0
    assert identity.mutation_calls == []
    assert not any(item.startswith("provider:snapshot:") for item in timeline)


def test_initial_inventory_budget_exhaustion_does_not_consume_durable_plan() -> None:
    config = config_for()
    timeline: list[str] = []
    identity = FakeIdentity(config, timeline)
    ledger = MemoryLedger(timeline)

    with pytest.raises(BrokerContractError) as captured:
        broker(
            config,
            identity,
            ledger,
            remaining_time_ms=lambda: runtime.REPAIR_CLAIM_MIN_REMAINING_MS,
        ).run({})

    assert captured.value.code == "LAMBDA_BUDGET_INSUFFICIENT"
    assert ledger.item and ledger.item["status"] == "PLAN_VERIFIED"
    assert identity.mutation_calls == []
    assert sum(item.startswith("provider:snapshot:") for item in timeline) == 1


def test_post_cas_snapshot_crossing_window_never_dispatches_provider() -> None:
    config = config_for()
    timeline: list[str] = []
    identity = FakeIdentity(config, timeline)
    ledger = MemoryLedger(timeline)
    values = [NOW] * 6 + [NOW + timedelta(minutes=20)]

    def crossing_clock() -> datetime:
        return values.pop(0) if values else NOW + timedelta(minutes=20)

    receipt = broker(config, identity, ledger, now=crossing_clock).run({})
    assert receipt["status"] == "BLOCKED"
    assert receipt["effects_attempted"] == 0
    assert receipt["effects_completed"] == 0
    assert identity.mutation_calls == []


def test_low_lambda_budget_before_cas_never_dispatches_provider() -> None:
    config = config_for()
    timeline: list[str] = []
    identity = FakeIdentity(config, timeline)
    ledger = MemoryLedger(timeline)
    budgets = iter(
        [
            runtime.REPAIR_CLAIM_MIN_REMAINING_MS + 1,
            runtime.LAMBDA_MUTATION_DISPATCH_MIN_REMAINING_MS,
        ]
    )
    receipt = broker(
        config,
        identity,
        ledger,
        remaining_time_ms=lambda: next(budgets),
    ).run({})
    assert receipt["status"] == "BLOCKED"
    assert identity.mutation_calls == []
    assert ledger.item and ledger.item["status"] == "CLAIMED"


def test_lambda_budget_crossing_after_cas_never_dispatches_provider() -> None:
    config = config_for()
    timeline: list[str] = []
    identity = FakeIdentity(config, timeline)
    ledger = MemoryLedger(timeline)
    budgets = iter(
        [
            runtime.REPAIR_CLAIM_MIN_REMAINING_MS + 1,
            90_000,
            runtime.LAMBDA_MUTATION_DISPATCH_MIN_REMAINING_MS,
        ]
    )
    receipt = broker(
        config,
        identity,
        ledger,
        remaining_time_ms=lambda: next(budgets),
    ).run({})
    assert receipt["status"] == "BLOCKED"
    assert identity.mutation_calls == []
    assert ledger.item and ledger.item["status"] == "ATTEMPTING_1"


def test_near_window_before_cas_never_dispatches_provider() -> None:
    config = config_for()
    timeline: list[str] = []
    identity = FakeIdentity(config, timeline)
    ledger = MemoryLedger(timeline)
    near_window = config.not_after - timedelta(
        seconds=runtime.MUTATION_WINDOW_MIN_REMAINING_SECONDS
    )
    values = [NOW, NOW, NOW, near_window]

    def near_window_clock() -> datetime:
        return values.pop(0) if values else near_window

    receipt = broker(
        config,
        identity,
        ledger,
        now=near_window_clock,
    ).run({})
    assert receipt["status"] == "BLOCKED"
    assert identity.mutation_calls == []
    assert ledger.item and ledger.item["status"] == "CLAIMED"


def test_sdk_timeout_after_one_dispatch_persists_uncertain() -> None:
    config = config_for()
    timeline: list[str] = []
    identity = FakeIdentity(config, timeline, ambiguous_effect="put")
    ledger = MemoryLedger(timeline)
    receipt = broker(config, identity, ledger).run({})
    assert receipt["status"] == "UNCERTAIN_RECONCILE_ONLY"
    assert identity.mutation_calls == ["put"]
    assert ledger.item and ledger.item["status"] == "UNCERTAIN_RECONCILE_ONLY"


def test_async_status_polling_reserves_lambda_timeout_and_never_retries_mutation() -> None:
    config = config_for()
    timeline: list[str] = []
    active = broker(
        config,
        FakeIdentity(config, timeline),
        MemoryLedger(timeline),
        remaining_time_ms=lambda: 14_999,
    )
    describe_calls: list[str] = []

    def describe(request_id: str) -> str:
        describe_calls.append(request_id)
        return "IN_PROGRESS"

    with pytest.raises(runtime.ProviderResponseAmbiguous, match="Lambda timeout"):
        active._wait(runtime.OperationResult("request-id", "IN_PROGRESS"), describe)
    assert describe_calls == []


def test_async_status_polling_can_observe_success_without_mutation_retry() -> None:
    config = config_for()
    timeline: list[str] = []
    active = broker(config, FakeIdentity(config, timeline), MemoryLedger(timeline))
    statuses = iter(["IN_PROGRESS", "SUCCEEDED"])
    describe_calls: list[str] = []

    def describe(request_id: str) -> str:
        describe_calls.append(request_id)
        return next(statuses)

    active._wait(runtime.OperationResult("request-id", "IN_PROGRESS"), describe)
    assert describe_calls == ["request-id", "request-id"]


@pytest.mark.parametrize("kms_mode", ["AWS_OWNED_KMS_KEY", "CUSTOMER_MANAGED_KEY"])
def test_runtime_accepts_both_exact_kms_modes(kms_mode: str) -> None:
    config = config_for("plan", kms_mode=kms_mode)
    timeline: list[str] = []
    identity = FakeIdentity(config, timeline)
    receipt = broker(config, identity, MemoryLedger(timeline)).run({})
    assert receipt["status"] == "PLAN_VERIFIED"


def test_kms_mode_drift_fails_closed() -> None:
    config = config_for("plan", kms_mode="CUSTOMER_MANAGED_KEY")
    wrong = LiveSnapshot(
        **{**snapshot(config, 0).__dict__, "kms_mode": "AWS_OWNED_KMS_KEY", "kms_key_arn": None}
    )
    timeline: list[str] = []
    with pytest.raises(BrokerContractError, match="KMS mode"):
        broker(
            config,
            FakeIdentity(config, timeline, initial_override=wrong),
            MemoryLedger(timeline),
        ).run({})


def test_dedicated_handlers_fix_mode_and_alias(monkeypatch: pytest.MonkeyPatch) -> None:
    observed: list[tuple[str, str]] = []

    def fake(mode: str, qualifier: str, event: Any, context: Any) -> dict[str, str]:
        observed.append((mode, qualifier))
        return {"mode": mode}

    monkeypatch.setattr(runtime, "_mode_handler", fake)

    assert runtime.plan_handler({}, object()) == {"mode": "plan"}
    assert runtime.repair_handler({}, object()) == {"mode": "repair"}
    assert runtime.reconcile_handler({}, object()) == {"mode": "reconcile"}
    assert observed == [
        ("plan", "plan-v1"),
        ("repair", "repair-v1"),
        ("reconcile", "reconcile-v1"),
    ]


def test_exact_client_context_proves_only_synchronous_transport() -> None:
    client_context = type(
        "ClientContext", (), {"custom": dict(runtime.SYNC_CLIENT_CONTEXT_CUSTOM)}
    )()
    context = type("Context", (), {"client_context": client_context})()
    runtime._validate_synchronous_transport(context)


@pytest.mark.parametrize(
    "custom",
    [
        None,
        {},
        {"scanalyze_transport": "Event", "scanalyze_work_package": "GUG-221"},
        {
            "scanalyze_transport": "REQUEST_RESPONSE",
            "scanalyze_work_package": "GUG-221",
            "principal_id": PRINCIPAL_ID,
        },
    ],
)
def test_missing_async_spoofed_or_expanded_client_context_fails_closed(
    custom: object,
) -> None:
    client_context = type("ClientContext", (), {"custom": custom})()
    context = type("Context", (), {"client_context": client_context})()
    with pytest.raises(BrokerContractError) as captured:
        runtime._validate_synchronous_transport(context)
    assert captured.value.code == "SYNCHRONOUS_TRANSPORT_UNPROVEN"


def test_transport_marker_is_required_before_runtime_or_provider_access(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    build_calls: list[object] = []

    def forbidden_build(**kwargs: Any) -> object:
        build_calls.append(kwargs)
        raise AssertionError("runtime must not be built")

    monkeypatch.setattr(runtime, "build_runtime", forbidden_build)
    context = type(
        "Context",
        (),
        {
            "invoked_function_arn": (
                "arn:aws:lambda:us-east-1:042360977644:function:"
                "scanalyze-authority-lambda-audit-repair:repair-v1"
            )
        },
    )()
    with pytest.raises(runtime.PublicBrokerFailure) as captured:
        runtime.repair_handler({}, context)
    assert str(captured.value) == (
        "GUG221_BROKER_BLOCKED:SYNCHRONOUS_TRANSPORT_UNPROVEN"
    )
    assert captured.value.__cause__ is None
    assert captured.value.__context__ is None
    assert build_calls == []


def test_provider_failure_is_sanitized_without_exception_chaining(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sentinel = (
        "arn:aws:sso:::permissionSet/ssoins-sensitive/ps-sensitive "
        "request-id-sensitive"
    )

    class SensitiveProviderFailure(RuntimeError):
        pass

    def fail(*args: Any, **kwargs: Any) -> dict[str, Any]:
        raise SensitiveProviderFailure(sentinel)

    monkeypatch.setattr(runtime, "_mode_handler_impl", fail)
    with pytest.raises(runtime.PublicBrokerFailure) as captured:
        runtime._mode_handler("repair", "repair-v1", {}, object())
    assert str(captured.value) == "GUG221_BROKER_BLOCKED:PROVIDER_FAILURE"
    assert sentinel not in str(captured.value)
    assert captured.value.__cause__ is None
    assert captured.value.__context__ is None


def test_runtime_exposes_only_three_dedicated_handlers() -> None:
    assert callable(runtime.plan_handler)
    assert callable(runtime.repair_handler)
    assert callable(runtime.reconcile_handler)
    assert not hasattr(runtime, "read_handler")
    assert not hasattr(runtime, "lambda_handler")


class ConditionalFailure(Exception):
    response = {"Error": {"Code": "ConditionalCheckFailedException"}}


def test_dynamodb_claim_uses_provider_cas_and_race_is_replay() -> None:
    class Client:
        def __init__(self) -> None:
            self.kwargs: dict[str, Any] | None = None

        def put_item(self, **kwargs: Any) -> None:
            self.kwargs = kwargs

    client = Client()
    ledger = runtime.DynamoLedger(client, "exact-table")
    claim = plan_claim(config_for())
    ledger.claim(claim)
    assert client.kwargs is not None
    assert client.kwargs["ConditionExpression"] == "attribute_not_exists(repair_id)"
    assert client.kwargs["Item"]["repair_id"] == {
        "S": "gug221-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    }

    class RaceClient:
        def put_item(self, **kwargs: Any) -> None:
            raise ConditionalFailure()

    with pytest.raises(BrokerContractError) as captured:
        runtime.DynamoLedger(RaceClient(), "exact-table").claim(claim)
    assert captured.value.code == "REPLAY_BLOCKED"


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("schema_version", 2),
        ("record_type", "foreign"),
        ("authority_account_id", "999999999999"),
        ("management_account_id", "999999999999"),
        ("region", "us-west-2"),
        ("claimed_at", "not-a-timestamp"),
        ("ledger_digest", "0" * 64),
    ],
)
def test_ledger_readback_recomputes_claim_digest_and_all_immutable_bindings(
    field: str, value: object
) -> None:
    config = config_for()
    ledger = dict(plan_claim(config))
    ledger[field] = value
    with pytest.raises(BrokerContractError) as captured:
        runtime._ledger_matches(
            ledger,
            config=config,
            intent_digest=canonical_digest(runtime.build_private_intent(config)),
            ledger_digest=str(ledger["ledger_digest"]),
        )
    assert captured.value.code == "LEDGER_BINDING_MISMATCH"


@pytest.mark.parametrize(
    ("updated_at", "state_digest"),
    [
        (None, "9" * 64),
        ("2026-07-21T19:59:59Z", "9" * 64),
        ("2026-07-21T20:00:00Z", "bad"),
    ],
)
def test_advanced_ledger_requires_ordered_timestamp_and_exact_state_digest(
    updated_at: str | None, state_digest: str
) -> None:
    config = config_for()
    ledger = dict(plan_claim(config))
    ledger.update(
        {
            "status": "ATTEMPTING_1",
            "stage": "BEFORE_PUT_INLINE_POLICY",
            "effects_attempted": 0,
            "effects_completed": 0,
            "state_digest": state_digest,
        }
    )
    if updated_at is not None:
        ledger["updated_at"] = updated_at
    with pytest.raises(BrokerContractError) as captured:
        runtime._ledger_matches(
            ledger,
            config=config,
            intent_digest=canonical_digest(runtime.build_private_intent(config)),
            ledger_digest=str(ledger["ledger_digest"]),
        )
    assert captured.value.code == "LEDGER_BINDING_MISMATCH"


def test_malformed_ledger_progress_never_reaches_first_sso_effect() -> None:
    config = config_for()
    timeline: list[str] = []

    class TamperedLedger(MemoryLedger):
        def read(self, repair_id: str) -> Mapping[str, Any] | None:
            value = super().read(repair_id)
            if value is not None and value.get("status") == "CLAIMED":
                assert self.item is not None
                self.item["effects_attempted"] = 3
                value = dict(self.item)
            return value

    ledger = TamperedLedger(timeline)
    identity = FakeIdentity(config, timeline)
    with pytest.raises(BrokerContractError) as captured:
        broker(config, identity, ledger).run({})
    assert captured.value.code == "LEDGER_PROGRESS_INVALID"
    assert identity.mutation_calls == []


def test_dynamodb_transition_cas_binds_full_expected_ledger_state() -> None:
    config = config_for()
    expected = plan_claim(config)

    class Client:
        def __init__(self) -> None:
            self.kwargs: dict[str, Any] | None = None

        def update_item(self, **kwargs: Any) -> None:
            self.kwargs = kwargs

    client = Client()
    ledger = runtime.DynamoLedger(client, "exact-table")
    ledger.transition(
        repair_id=config.repair_id,
        intent_digest=str(expected["intent_digest"]),
        ledger_digest=str(expected["ledger_digest"]),
        expected_ledger=expected,
        expected_status="PLAN_VERIFIED",
        new_status="CLAIMED",
        stage="BEFORE_FIRST_EFFECT",
        effects_attempted=0,
        effects_completed=0,
        state_digest="9" * 64,
        updated_at=NOW,
        claimed_at=NOW,
    )
    assert client.kwargs is not None
    condition = client.kwargs["ConditionExpression"]
    for binding in (
        "#schema",
        "#record",
        "#source",
        "#original",
        "#authority",
        "#management",
        "#region",
        "#stage",
        "#attempted",
        "#completed",
        "#plan_version",
        "#repair_version",
        "#repair_not_before",
        "#repair_not_after",
        "#planned_state",
        "#planned",
        "#claimed",
        "#immutable",
        "#claim_condition",
        "#retry",
        "#production",
        "attribute_not_exists(#updated)",
        "attribute_not_exists(#claimed)",
        "#state = :expected_state",
    ):
        assert binding in condition


def test_aws_adapter_emits_only_three_exact_identity_center_mutations() -> None:
    config = config_for()

    class Sso:
        def __init__(self) -> None:
            self.calls: list[tuple[str, dict[str, Any]]] = []

        def put_inline_policy_to_permission_set(self, **kwargs: Any) -> None:
            self.calls.append(("put", kwargs))

        def create_account_assignment(self, **kwargs: Any) -> dict[str, Any]:
            self.calls.append(("assign", kwargs))
            return {
                "AccountAssignmentCreationStatus": {
                    "RequestId": "request-assignment",
                    "Status": "SUCCEEDED",
                }
            }

        def provision_permission_set(self, **kwargs: Any) -> dict[str, Any]:
            self.calls.append(("provision", kwargs))
            return {
                "PermissionSetProvisioningStatus": {
                    "RequestId": "request-provision",
                    "Status": "SUCCEEDED",
                }
            }

    sso = Sso()
    adapter = runtime.AwsIdentityCenterAdapter(
        config=config,
        sso_admin=sso,
        identitystore=object(),
        authority_iam=object(),
    )
    adapter.put_inline_policy(config, json.dumps(POLICY))
    adapter.create_account_assignment(config)
    adapter.provision_permission_set(config)
    assert [name for name, _ in sso.calls] == ["put", "assign", "provision"]
    assert sso.calls[0][1] == {
        "InstanceArn": config.instance_arn,
        "PermissionSetArn": config.collector_permission_set_arn,
        "InlinePolicy": json.dumps(POLICY),
    }
    assert sso.calls[1][1] == {
        "InstanceArn": config.instance_arn,
        "TargetId": "042360977644",
        "TargetType": "AWS_ACCOUNT",
        "PermissionSetArn": config.collector_permission_set_arn,
        "PrincipalType": "USER",
        "PrincipalId": config.principal_id,
    }
    assert sso.calls[2][1] == {
        "InstanceArn": config.instance_arn,
        "PermissionSetArn": config.collector_permission_set_arn,
        "TargetId": "042360977644",
        "TargetType": "AWS_ACCOUNT",
    }


def test_exact_saml_trust_rejects_extra_statement_or_action() -> None:
    exact = {
        "Version": "2012-10-17",
        "Statement": {
            "Effect": "Allow",
            "Principal": {"Federated": SAML_PROVIDER_ARN},
            "Action": ["sts:AssumeRoleWithSAML", "sts:TagSession"],
            "Condition": {
                "StringEquals": {"SAML:aud": "https://signin.aws.amazon.com/saml"}
            },
        },
    }
    assert runtime._parse_exact_saml_trust(exact, SAML_PROVIDER_ARN) == (
        SAML_PROVIDER_ARN,
        "https://signin.aws.amazon.com/saml",
    )
    expanded = dict(exact)
    expanded["Statement"] = [
        exact["Statement"],
        {"Effect": "Allow", "Action": "sts:AssumeRole", "Principal": {"AWS": "*"}},
    ]
    with pytest.raises(BrokerContractError):
        runtime._parse_exact_saml_trust(expanded, SAML_PROVIDER_ARN)
    missing_tag_session = dict(exact)
    missing_tag_session["Statement"] = dict(exact["Statement"])
    missing_tag_session["Statement"]["Action"] = "sts:AssumeRoleWithSAML"
    with pytest.raises(BrokerContractError):
        runtime._parse_exact_saml_trust(missing_tag_session, SAML_PROVIDER_ARN)


def exact_saml_trust() -> dict[str, Any]:
    return {
        "Version": "2012-10-17",
        "Statement": {
            "Effect": "Allow",
            "Principal": {"Federated": SAML_PROVIDER_ARN},
            "Action": ["sts:AssumeRoleWithSAML", "sts:TagSession"],
            "Condition": {
                "StringEquals": {
                    "SAML:aud": "https://signin.aws.amazon.com/saml"
                }
            },
        },
    }


def test_iam_marker_pagination_cannot_hide_foreign_role_on_second_page() -> None:
    config = config_for("plan")

    class Iam:
        def list_roles(self, **kwargs: Any) -> dict[str, Any]:
            if "Marker" not in kwargs:
                return {
                    "Roles": [
                        {
                            "RoleName": "unrelated",
                            "Path": "/service/",
                            "Arn": "arn:aws:iam::042360977644:role/service/unrelated",
                        }
                    ],
                    "IsTruncated": True,
                    "Marker": "page-2",
                }
            assert kwargs["Marker"] == "page-2"
            return {
                "Roles": [
                    {
                        "RoleName": (
                            "AWSReservedSSO_ScanalyzeAuthorityLambdaAudit_"
                            "0123456789abcdef"
                        ),
                        "Path": "/aws-reserved/sso.amazonaws.com/",
                        "Arn": (
                            "arn:aws:iam::042360977644:role/aws-reserved/"
                            "sso.amazonaws.com/AWSReservedSSO_"
                            "ScanalyzeAuthorityLambdaAudit_0123456789abcdef"
                        ),
                    }
                ],
                "IsTruncated": False,
            }

        def get_role(self, **kwargs: Any) -> dict[str, Any]:
            return {
                "Role": {
                    "RoleName": kwargs["RoleName"],
                    "Path": "/aws-reserved/sso.amazonaws.com/",
                    "Arn": (
                        "arn:aws:iam::042360977644:role/aws-reserved/"
                        "sso.amazonaws.com/AWSReservedSSO_"
                        "ScanalyzeAuthorityLambdaAudit_0123456789abcdef"
                    ),
                    "AssumeRolePolicyDocument": {
                        **exact_saml_trust(),
                        "Statement": {
                            **exact_saml_trust()["Statement"],
                            "Principal": {
                                "Federated": "arn:aws:iam::042360977644:saml-provider/foreign"
                            },
                        },
                    },
                }
            }

    adapter = runtime.AwsIdentityCenterAdapter(
        config=config,
        sso_admin=object(),
        identitystore=object(),
        authority_iam=Iam(),
    )
    with pytest.raises(BrokerContractError) as captured:
        adapter._collector_roles(config, POLICY)
    assert captured.value.code == "SAML_TRUST_MISMATCH"


def test_iam_marker_pagination_cannot_hide_attached_policy_on_second_page() -> None:
    config = config_for("plan")
    role_name = "AWSReservedSSO_ScanalyzeAuthorityLambdaAudit_0123456789abcdef"

    class Iam:
        def list_roles(self, **kwargs: Any) -> dict[str, Any]:
            return {
                "Roles": [
                    {
                        "RoleName": role_name,
                        "Path": "/aws-reserved/sso.amazonaws.com/",
                        "Arn": (
                            "arn:aws:iam::042360977644:role/aws-reserved/"
                            f"sso.amazonaws.com/{role_name}"
                        ),
                    }
                ],
                "IsTruncated": False,
            }

        def get_role(self, **kwargs: Any) -> dict[str, Any]:
            return {
                "Role": {
                    "RoleName": role_name,
                    "Path": "/aws-reserved/sso.amazonaws.com/",
                    "Arn": (
                        "arn:aws:iam::042360977644:role/aws-reserved/"
                        f"sso.amazonaws.com/{role_name}"
                    ),
                    "AssumeRolePolicyDocument": exact_saml_trust(),
                }
            }

        def list_attached_role_policies(self, **kwargs: Any) -> dict[str, Any]:
            if "Marker" not in kwargs:
                return {
                    "AttachedPolicies": [],
                    "IsTruncated": True,
                    "Marker": "attached-2",
                }
            return {
                "AttachedPolicies": [
                    {
                        "PolicyName": "Foreign",
                        "PolicyArn": "arn:aws:iam::aws:policy/ReadOnlyAccess",
                    }
                ],
                "IsTruncated": False,
            }

        def list_role_policies(self, **kwargs: Any) -> dict[str, Any]:
            return {
                "PolicyNames": ["AwsSSOInlinePolicy"],
                "IsTruncated": False,
            }

        def get_role_policy(self, **kwargs: Any) -> dict[str, Any]:
            return {
                "RoleName": role_name,
                "PolicyName": "AwsSSOInlinePolicy",
                "PolicyDocument": POLICY,
            }

    adapter = runtime.AwsIdentityCenterAdapter(
        config=config,
        sso_admin=object(),
        identitystore=object(),
        authority_iam=Iam(),
    )
    roles = adapter._collector_roles(config, POLICY)
    assert roles[0].attached_managed_policy_arns == (
        "arn:aws:iam::aws:policy/ReadOnlyAccess",
    )


def test_adapter_reads_exact_local_repair_invoker_role_and_policy() -> None:
    config = config_for("plan")
    role_name = "AWSReservedSSO_ScanalyzeLambdaAuditRepair_0123456789abcdef"

    class Iam:
        def list_roles(self, **kwargs: Any) -> dict[str, Any]:
            return {
                "Roles": [
                    {
                        "RoleName": role_name,
                        "Path": "/aws-reserved/sso.amazonaws.com/",
                        "Arn": (
                            "arn:aws:iam::042360977644:role/aws-reserved/"
                            f"sso.amazonaws.com/{role_name}"
                        ),
                    }
                ],
                "IsTruncated": False,
            }

        def get_role(self, **kwargs: Any) -> dict[str, Any]:
            return {
                "Role": {
                    "RoleName": role_name,
                    "Path": "/aws-reserved/sso.amazonaws.com/",
                    "Arn": (
                        "arn:aws:iam::042360977644:role/aws-reserved/"
                        f"sso.amazonaws.com/{role_name}"
                    ),
                    "AssumeRolePolicyDocument": exact_saml_trust(),
                }
            }

        def list_attached_role_policies(self, **kwargs: Any) -> dict[str, Any]:
            return {"AttachedPolicies": [], "IsTruncated": False}

        def list_role_policies(self, **kwargs: Any) -> dict[str, Any]:
            return {
                "PolicyNames": ["AwsSSOInlinePolicy"],
                "IsTruncated": False,
            }

        def get_role_policy(self, **kwargs: Any) -> dict[str, Any]:
            return {
                "RoleName": role_name,
                "PolicyName": "AwsSSOInlinePolicy",
                "PolicyDocument": INVOKER_POLICY,
            }

    adapter = runtime.AwsIdentityCenterAdapter(
        config=config,
        sso_admin=object(),
        identitystore=object(),
        authority_iam=Iam(),
    )
    roles = adapter._repair_invoker_roles(config, INVOKER_POLICY)
    assert roles == (invoker_role(config),)


@pytest.mark.parametrize("drift_source", ["list", "get"])
def test_permission_set_role_requires_exact_root_path_and_arn(
    drift_source: str,
) -> None:
    config = config_for("plan")
    role_name = "AWSReservedSSO_ScanalyzeLambdaAuditRepair_0123456789abcdef"
    exact_path = "/aws-reserved/sso.amazonaws.com/"
    exact_arn = (
        "arn:aws:iam::042360977644:role/aws-reserved/"
        f"sso.amazonaws.com/{role_name}"
    )
    drift_path = "/aws-reserved/sso.amazonaws.com/us-west-2/"
    drift_arn = (
        "arn:aws:iam::042360977644:role/aws-reserved/"
        f"sso.amazonaws.com/us-west-2/{role_name}"
    )

    class Iam:
        def list_roles(self, **kwargs: Any) -> dict[str, Any]:
            return {
                "Roles": [
                    {
                        "RoleName": role_name,
                        "Path": drift_path if drift_source == "list" else exact_path,
                        "Arn": drift_arn if drift_source == "list" else exact_arn,
                    }
                ],
                "IsTruncated": False,
            }

        def get_role(self, **kwargs: Any) -> dict[str, Any]:
            return {
                "Role": {
                    "RoleName": role_name,
                    "Path": drift_path if drift_source == "get" else exact_path,
                    "Arn": drift_arn if drift_source == "get" else exact_arn,
                    "AssumeRolePolicyDocument": exact_saml_trust(),
                }
            }

    adapter = runtime.AwsIdentityCenterAdapter(
        config=config,
        sso_admin=object(),
        identitystore=object(),
        authority_iam=Iam(),
    )
    with pytest.raises(BrokerContractError) as captured:
        adapter._repair_invoker_roles(config, INVOKER_POLICY)
    assert captured.value.code in {"ROLE_BINDING_MISMATCH", "ROLE_READBACK_MALFORMED"}


@pytest.mark.parametrize(
    ("changes", "code"),
    [
        ({"OwnerAccountId": None}, "INSTANCE_OWNER_MISMATCH"),
        ({"OwnerAccountId": "999999999999"}, "INSTANCE_OWNER_MISMATCH"),
        ({"Status": "CREATE_IN_PROGRESS"}, "INSTANCE_STATUS_MISMATCH"),
        ({"Status": "CREATE_FAILED"}, "INSTANCE_STATUS_MISMATCH"),
        ({"EncryptionConfigurationDetails": None}, "KMS_READBACK_MALFORMED"),
        (
            {
                "EncryptionConfigurationDetails": {
                    "KeyType": "AWS_OWNED_KMS_KEY",
                    "EncryptionStatus": "UPDATE_IN_PROGRESS",
                }
            },
            "KMS_NOT_ENABLED",
        ),
    ],
)
def test_instance_readback_fails_closed_for_missing_or_transitional_binding(
    changes: dict[str, Any], code: str
) -> None:
    config = config_for("plan")
    response = {
        "InstanceArn": config.instance_arn,
        "IdentityStoreId": config.identity_store_id,
        "OwnerAccountId": "839393571433",
        "Status": "ACTIVE",
        "EncryptionConfigurationDetails": {
            "KeyType": "AWS_OWNED_KMS_KEY",
            "EncryptionStatus": "ENABLED",
        },
    }
    response.update(changes)

    class Sso:
        def describe_instance(self, **kwargs: Any) -> dict[str, Any]:
            return dict(response)

    adapter = runtime.AwsIdentityCenterAdapter(
        config=config,
        sso_admin=Sso(),
        identitystore=object(),
        authority_iam=object(),
    )
    with pytest.raises(BrokerContractError) as captured:
        adapter._instance_binding(config)
    assert captured.value.code == code


@pytest.mark.parametrize("kms_mode", ["AWS_OWNED_KMS_KEY", "CUSTOMER_MANAGED_KEY"])
def test_instance_readback_accepts_only_exact_active_kms_binding(kms_mode: str) -> None:
    config = config_for("plan", kms_mode=kms_mode)
    details: dict[str, Any] = {
        "KeyType": kms_mode,
        "EncryptionStatus": "ENABLED",
    }
    if config.identity_center_kms_key_arn is not None:
        details["KmsKeyArn"] = config.identity_center_kms_key_arn

    class Sso:
        def describe_instance(self, **kwargs: Any) -> dict[str, Any]:
            return {
                "InstanceArn": config.instance_arn,
                "IdentityStoreId": config.identity_store_id,
                "OwnerAccountId": "839393571433",
                "Status": "ACTIVE",
                "EncryptionConfigurationDetails": details,
            }

    adapter = runtime.AwsIdentityCenterAdapter(
        config=config,
        sso_admin=Sso(),
        identitystore=object(),
        authority_iam=object(),
    )
    assert adapter._instance_binding(config) == (
        kms_mode,
        config.identity_center_kms_key_arn,
    )


@pytest.mark.parametrize(
    ("method_name", "response", "code"),
    [
        (
            "list_tags_for_resource",
            {"Tags": [{"Key": "managed_by"}]},
            "TAG_LIST_MALFORMED",
        ),
        (
            "list_managed_policies_in_permission_set",
            {"AttachedManagedPolicies": [{"Arn": "arn:aws:iam::aws:policy/ReadOnlyAccess"}]},
            "MANAGED_POLICY_LIST_MALFORMED",
        ),
        (
            "list_customer_managed_policy_references_in_permission_set",
            {"CustomerManagedPolicyReferences": [{"Name": "Foreign", "Path": 7}]},
            "CUSTOMER_POLICY_LIST_MALFORMED",
        ),
        (
            "list_account_assignments",
            {
                "AccountAssignments": [
                    {
                        "PermissionSetArn": PERMISSION_SET_ARN,
                        "PrincipalType": "USER",
                        "PrincipalId": PRINCIPAL_ID,
                    }
                ]
            },
            "ASSIGNMENT_LIST_MALFORMED",
        ),
        (
            "list_accounts_for_provisioned_permission_set",
            {"AccountIds": ["foreign"]},
            "ACCOUNT_LIST_MALFORMED",
        ),
        (
            "list_account_assignment_creation_status",
            {
                "AccountAssignmentsCreationStatus": [
                    {
                        "RequestId": "pending-create",
                        "Status": "IN_PROGRESS",
                        "PermissionSetArn": PERMISSION_SET_ARN,
                        "TargetId": "042360977644",
                        "TargetType": "AWS_ACCOUNT",
                        "PrincipalType": "USER",
                        "PrincipalId": PRINCIPAL_ID,
                    }
                ]
            },
            "PERMISSION_SET_OPERATION_IN_PROGRESS",
        ),
        (
            "list_account_assignment_deletion_status",
            {
                "AccountAssignmentsDeletionStatus": [
                    {
                        "RequestId": "pending-delete",
                        "Status": "IN_PROGRESS",
                        "PermissionSetArn": PERMISSION_SET_ARN,
                        "TargetId": "042360977644",
                        "TargetType": "AWS_ACCOUNT",
                        "PrincipalType": "USER",
                        "PrincipalId": PRINCIPAL_ID,
                    }
                ]
            },
            "PERMISSION_SET_OPERATION_IN_PROGRESS",
        ),
        (
            "list_permission_set_provisioning_status",
            {
                "PermissionSetsProvisioningStatus": [
                    {
                        "RequestId": "pending-provision",
                        "Status": "IN_PROGRESS",
                        "PermissionSetArn": PERMISSION_SET_ARN,
                        "AccountId": "042360977644",
                    }
                ]
            },
            "PERMISSION_SET_OPERATION_IN_PROGRESS",
        ),
    ],
)
def test_permission_set_inventory_rejects_malformed_provider_items(
    method_name: str, response: dict[str, Any], code: str
) -> None:
    config = config_for("plan")

    class Sso:
        def describe_permission_set(self, **kwargs: Any) -> dict[str, Any]:
            return {
                "PermissionSet": {
                    "PermissionSetArn": PERMISSION_SET_ARN,
                    "Name": "ScanalyzeAuthorityLambdaAudit",
                    "Description": (
                        "GUG-219 read-only account-wide Lambda invocation-authority inventory"
                    ),
                    "SessionDuration": "PT1H",
                }
            }

        def list_tags_for_resource(self, **kwargs: Any) -> dict[str, Any]:
            return {"Tags": []}

        def list_account_assignment_creation_status(
            self, **kwargs: Any
        ) -> dict[str, Any]:
            return {"AccountAssignmentsCreationStatus": []}

        def list_account_assignment_deletion_status(
            self, **kwargs: Any
        ) -> dict[str, Any]:
            return {"AccountAssignmentsDeletionStatus": []}

        def list_permission_set_provisioning_status(
            self, **kwargs: Any
        ) -> dict[str, Any]:
            return {"PermissionSetsProvisioningStatus": []}

        def describe_account_assignment_creation_status(
            self, **kwargs: Any
        ) -> dict[str, Any]:
            item = response["AccountAssignmentsCreationStatus"][0]
            return {"AccountAssignmentCreationStatus": item}

        def describe_account_assignment_deletion_status(
            self, **kwargs: Any
        ) -> dict[str, Any]:
            item = response["AccountAssignmentsDeletionStatus"][0]
            return {"AccountAssignmentDeletionStatus": item}

        def describe_permission_set_provisioning_status(
            self, **kwargs: Any
        ) -> dict[str, Any]:
            item = response["PermissionSetsProvisioningStatus"][0]
            return {"PermissionSetProvisioningStatus": item}

        def get_inline_policy_for_permission_set(self, **kwargs: Any) -> dict[str, Any]:
            return {"InlinePolicy": POLICY}

        def list_managed_policies_in_permission_set(self, **kwargs: Any) -> dict[str, Any]:
            return {"AttachedManagedPolicies": []}

        def list_customer_managed_policy_references_in_permission_set(
            self, **kwargs: Any
        ) -> dict[str, Any]:
            return {"CustomerManagedPolicyReferences": []}

        def get_permissions_boundary_for_permission_set(
            self, **kwargs: Any
        ) -> dict[str, Any]:
            return {}

        def list_account_assignments(self, **kwargs: Any) -> dict[str, Any]:
            return {
                "AccountAssignments": [
                    {
                        "AccountId": "042360977644",
                        "PermissionSetArn": PERMISSION_SET_ARN,
                        "PrincipalType": "USER",
                        "PrincipalId": PRINCIPAL_ID,
                    }
                ]
            }

        def list_accounts_for_provisioned_permission_set(
            self, **kwargs: Any
        ) -> dict[str, Any]:
            return {"AccountIds": ["042360977644"]}

    sso = Sso()
    setattr(sso, method_name, lambda **kwargs: response)
    adapter = runtime.AwsIdentityCenterAdapter(
        config=config,
        sso_admin=sso,
        identitystore=object(),
        authority_iam=object(),
    )
    with pytest.raises(BrokerContractError) as captured:
        adapter._permission_set_inventory(config, PERMISSION_SET_ARN)
    assert captured.value.code == code


@pytest.mark.parametrize(
    ("requested_arn", "returned_arn"),
    [
        (PERMISSION_SET_ARN, INVOKER_PERMISSION_SET_ARN),
        (INVOKER_PERMISSION_SET_ARN, PERMISSION_SET_ARN),
    ],
)
def test_permission_set_readback_is_bound_to_exact_requested_arn(
    requested_arn: str, returned_arn: str
) -> None:
    config = config_for("plan")

    class Sso:
        def describe_permission_set(self, **kwargs: Any) -> dict[str, Any]:
            assert kwargs["PermissionSetArn"] == requested_arn
            return {"PermissionSet": {"PermissionSetArn": returned_arn}}

    adapter = runtime.AwsIdentityCenterAdapter(
        config=config,
        sso_admin=Sso(),
        identitystore=object(),
        authority_iam=object(),
    )
    with pytest.raises(BrokerContractError) as captured:
        adapter._permission_set_inventory(config, requested_arn)
    assert captured.value.code == "PERMISSION_SET_MALFORMED"


def test_iam_role_inventory_rejects_malformed_items_instead_of_filtering() -> None:
    config = config_for("plan")

    class Iam:
        def list_roles(self, **kwargs: Any) -> dict[str, Any]:
            return {
                "Roles": [{"RoleName": 7, "Path": None, "Arn": None}],
                "IsTruncated": False,
            }

    adapter = runtime.AwsIdentityCenterAdapter(
        config=config,
        sso_admin=object(),
        identitystore=object(),
        authority_iam=Iam(),
    )
    with pytest.raises(BrokerContractError) as captured:
        adapter._collector_roles(config, POLICY)
    assert captured.value.code == "ROLE_LIST_MALFORMED"


def test_permission_set_inventory_enumerates_every_account_without_latest_filter() -> None:
    config = config_for("plan")
    foreign_account = "999999999999"

    class Sso:
        def __init__(self) -> None:
            self.accounts_kwargs: dict[str, Any] | None = None

        def describe_permission_set(self, **kwargs: Any) -> dict[str, Any]:
            return {
                "PermissionSet": {
                    "PermissionSetArn": PERMISSION_SET_ARN,
                    "Name": "synthetic",
                }
            }

        def list_account_assignment_creation_status(self, **kwargs: Any) -> dict[str, Any]:
            return {"AccountAssignmentsCreationStatus": []}

        def list_account_assignment_deletion_status(self, **kwargs: Any) -> dict[str, Any]:
            return {"AccountAssignmentsDeletionStatus": []}

        def list_permission_set_provisioning_status(self, **kwargs: Any) -> dict[str, Any]:
            return {"PermissionSetsProvisioningStatus": []}

        def list_tags_for_resource(self, **kwargs: Any) -> dict[str, Any]:
            return {"Tags": []}

        def get_inline_policy_for_permission_set(self, **kwargs: Any) -> dict[str, Any]:
            return {"InlinePolicy": POLICY}

        def list_managed_policies_in_permission_set(self, **kwargs: Any) -> dict[str, Any]:
            return {"AttachedManagedPolicies": []}

        def list_customer_managed_policy_references_in_permission_set(
            self, **kwargs: Any
        ) -> dict[str, Any]:
            return {"CustomerManagedPolicyReferences": []}

        def get_permissions_boundary_for_permission_set(self, **kwargs: Any) -> dict[str, Any]:
            return {}

        def list_accounts_for_provisioned_permission_set(
            self, **kwargs: Any
        ) -> dict[str, Any]:
            self.accounts_kwargs = dict(kwargs)
            return {"AccountIds": ["042360977644", foreign_account]}

        def list_account_assignments(self, **kwargs: Any) -> dict[str, Any]:
            return {
                "AccountAssignments": [
                    {
                        "AccountId": kwargs["AccountId"],
                        "PermissionSetArn": kwargs["PermissionSetArn"],
                        "PrincipalType": "USER",
                        "PrincipalId": PRINCIPAL_ID,
                    }
                ]
            }

    sso = Sso()
    adapter = runtime.AwsIdentityCenterAdapter(
        config=config,
        sso_admin=sso,
        identitystore=object(),
        authority_iam=object(),
    )
    inventory = adapter._permission_set_inventory(config, PERMISSION_SET_ARN)
    assert sso.accounts_kwargs is not None
    assert "ProvisioningStatus" not in sso.accounts_kwargs
    assert {item.target_account_id for item in inventory["assignments"]} == {
        "042360977644",
        foreign_account,
    }
    with pytest.raises(BrokerContractError) as captured:
        runtime.validate_snapshot(
            config,
            LiveSnapshot(
                **{
                    **snapshot(config, 0).__dict__,
                    "assignments": inventory["assignments"],
                    "provisioned_account_ids": inventory["accounts"],
                }
            ),
            "BEFORE_PUT_INLINE_POLICY",
        )
    assert captured.value.code == "FOREIGN_TARGET"


def test_botocore_clients_disable_retries() -> None:
    class Config:
        def __init__(self, **kwargs: Any) -> None:
            self.kwargs = kwargs

    class Boto:
        def client(self, service: str, **kwargs: Any) -> tuple[str, dict[str, Any]]:
            return service, kwargs

    factory = runtime.BotoSessionFactory(Boto(), Config)
    assert factory.client_config.kwargs["retries"] == {
        "mode": "standard",
        "total_max_attempts": 1,
    }


def test_assume_role_uses_exact_attributable_source_identity() -> None:
    config = config_for()

    class Config:
        def __init__(self, **kwargs: Any) -> None:
            self.kwargs = kwargs

    class Sts:
        def __init__(self) -> None:
            self.kwargs: dict[str, Any] | None = None

        def assume_role(self, **kwargs: Any) -> dict[str, Any]:
            self.kwargs = kwargs
            session_name = kwargs["RoleSessionName"]
            role_name = kwargs["RoleArn"].rsplit("/", 1)[-1]
            return {
                "AssumedRoleUser": {
                    "Arn": (
                        "arn:aws:sts::839393571433:assumed-role/"
                        f"{role_name}/{session_name}"
                    )
                },
                "Credentials": {
                    "AccessKeyId": "synthetic",
                    "SecretAccessKey": "synthetic",
                    "SessionToken": "synthetic",
                },
            }

    class Boto:
        def __init__(self) -> None:
            self.sts = Sts()

        def client(self, service: str, **kwargs: Any) -> Any:
            return self.sts if service == "sts" and "aws_access_key_id" not in kwargs else object()

    boto = Boto()
    factory = runtime.BotoSessionFactory(boto, Config)
    factory.assumed_clients(config.service_role_arn, config.repair_id)
    assert boto.sts.kwargs is not None
    assert boto.sts.kwargs["SourceIdentity"] == boto.sts.kwargs["RoleSessionName"]
    assert boto.sts.kwargs["SourceIdentity"].startswith("gug221-")


def test_invocation_inventory_uses_only_exact_inspector_role() -> None:
    config = config_for()

    class Config:
        def __init__(self, **kwargs: Any) -> None:
            self.kwargs = kwargs

    class Sts:
        def __init__(self) -> None:
            self.kwargs: dict[str, Any] | None = None

        def assume_role(self, **kwargs: Any) -> dict[str, Any]:
            self.kwargs = kwargs
            session = kwargs["RoleSessionName"]
            return {
                "AssumedRoleUser": {
                    "Arn": (
                        "arn:aws:sts::042360977644:assumed-role/"
                        f"{runtime.INVOCATION_INSPECTOR_ROLE_NAME}/{session}"
                    )
                },
                "Credentials": {
                    "AccessKeyId": "synthetic",
                    "SecretAccessKey": "synthetic",
                    "SessionToken": "synthetic",
                },
            }

    class Boto:
        def __init__(self) -> None:
            self.sts = Sts()
            self.calls: list[tuple[str, dict[str, Any]]] = []

        def client(self, service: str, **kwargs: Any) -> Any:
            self.calls.append((service, dict(kwargs)))
            if service == "sts" and "aws_access_key_id" not in kwargs:
                return self.sts
            return object()

    boto = Boto()
    factory = runtime.BotoSessionFactory(boto, Config)
    adapter, principal_digest = factory.authority_inventory_adapter(
        role_arn=runtime.INVOCATION_INSPECTOR_ROLE_ARN,
        repair_id=config.repair_id,
        clock=lambda: NOW,
    )

    assert isinstance(adapter, runtime.AwsReadOnlyInventoryAdapter)
    assert principal_digest == runtime.digest_text(
        "arn:aws:sts::042360977644:assumed-role/"
        f"{runtime.INVOCATION_INSPECTOR_ROLE_NAME}"
    )
    assert boto.sts.kwargs is not None
    assert boto.sts.kwargs["RoleArn"] == runtime.INVOCATION_INSPECTOR_ROLE_ARN
    assert boto.sts.kwargs["SourceIdentity"] == boto.sts.kwargs["RoleSessionName"]
    assert {service for service, _ in boto.calls} >= {
        "sts",
        "ec2",
        "lambda",
        "iam",
    }


def test_invocation_inventory_rejects_any_inspector_role_substitution() -> None:
    class Config:
        def __init__(self, **kwargs: Any) -> None:
            self.kwargs = kwargs

    class Boto:
        def client(self, *_args: Any, **_kwargs: Any) -> Any:
            raise AssertionError("AWS client must not be constructed")

    factory = runtime.BotoSessionFactory(Boto(), Config)
    with pytest.raises(BrokerContractError) as captured:
        factory.authority_inventory_adapter(
            role_arn="arn:aws:iam::042360977644:role/Admin",
            repair_id=config_for().repair_id,
            clock=lambda: NOW,
        )
    assert captured.value.code == "INSPECTOR_ROLE_MISMATCH"


def test_generated_private_and_public_records_match_repository_schemas() -> None:
    config = config_for()
    timeline: list[str] = []
    identity = FakeIdentity(config, timeline)
    ledger = MemoryLedger(timeline)
    records = {
        "intent": runtime.build_private_intent(config),
        "ledger": plan_claim(config),
        "receipt": broker(config, identity, ledger).run({}),
    }
    for kind, record in records.items():
        schema = json.loads(
            (
                ROOT
                / "schemas"
                / f"platform-authority-lambda-audit-repair-broker-{kind}.v1.schema.json"
            ).read_text(encoding="utf-8")
        )
        Draft202012Validator(schema).validate(record)
