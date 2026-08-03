"""Causal GUG-274 regressions for the normal bootstrap trust boundary."""
from __future__ import annotations

import argparse
import copy
import csv
from datetime import UTC, datetime, timedelta
import base64
import hashlib
from importlib import metadata
import io
import json
import os
from pathlib import Path
import py_compile
import subprocess
import sys
import threading
from typing import Any, Mapping

import pytest
import yaml
from yaml.constructor import ConstructorError

import tooling.platform_authority_bootstrap_artifact_authority as authority_module
import tooling.platform_authority_bootstrap_artifact_package as artifact_package_module
import tooling.platform_authority_bootstrap_signed_artifact as signed_artifact_module
from tooling.platform_authority_bootstrap import (
    PUBLIC_ACCESS_BLOCK,
    BootstrapAuthorizationError,
    BootstrapBinding,
    render_bootstrap_iam_policy,
)
from tooling.platform_authority_bootstrap_artifact_authority import (
    APPROVAL_AUTHORITY_FUNCTION,
    APPLY_EXECUTOR_FUNCTION,
    BROKER_FUNCTION_VERSION,
    LEDGER_TABLE_NAME,
    PLAN_AUTHORITY_FUNCTION,
    ArtifactAuthorityStore,
    Boto3BootstrapApplyEffects,
    BootstrapArtifactAuthorityBroker,
    BootstrapArtifactAuthorityError,
    BootstrapArtifactAuthorityRuntimeConfig,
    BootstrapArtifactAuthorityUncertainError,
    DynamoDbArtifactAuthorityStore,
    LambdaBootstrapArtifactAuthorityClient,
    broker_function_arn,
    build_bootstrap_approval_v2,
    build_bootstrap_plan_v2,
    prevalidate_bootstrap_apply_v2,
    render_bootstrap_apply_iam_policy,
    render_bootstrap_approval_iam_policy,
    trust_root_id,
    validate_authority_ledger,
    validate_bootstrap_approval_v2,
    validate_bootstrap_plan_v2,
)
from tooling.platform_authority_bootstrap_artifact_package import (
    BootstrapArtifactPackageError,
    EXPECTED_BOTO3_VERSION,
    EXPECTED_BOTOCORE_VERSION,
    PACKAGE_PATHS,
    PROVENANCE_PATHS,
    SDK_DISTRIBUTION_LOCKS,
    SOURCE_PATHS,
    _build_bootstrap_artifact_package,
    build_bootstrap_artifact_package,
    resolve_trusted_executable,
    validate_bootstrap_artifact_package,
)
from tooling.platform_authority_bootstrap_identity_proof import (
    AuthorizationCodeGrant,
    BootstrapIdentityProofBinding,
    BootstrapIdentityProofError,
    BootstrapIdentityProofReceipt,
    BootstrapIdentityProofVerifier,
    validate_identity_proof_receipt,
)
from tooling.platform_authority_bootstrap_signed_artifact import (
    AUTHORITY_ACCOUNT_ID as SIGNING_AUTHORITY_ACCOUNT_ID,
    EVIDENCE_STATUS as SIGNED_ARTIFACT_EVIDENCE_STATUS,
    EXPECTED_VERIFIER_PROFILE,
    SIGNING_PLATFORM,
    BootstrapSignedArtifactError,
    _build_signed_artifact_receipt,
    build_signed_artifact_receipt_from_aws,
    load_signing_trust_root_contract,
    refresh_signed_artifact_receipt_read_only,
    signing_trust_root_contract_digest,
    validate_signed_artifact_receipt,
    validate_signing_trust_root_contract,
    verify_reviewed_source_release,
    write_signed_artifact_receipt,
)
from tooling.platform_authority_lambda_audit_repair_signed_artifact import (
    GITHUB_ACTIONS_APP_ID,
    REQUIRED_GITHUB_CHECKS,
)


REPO_ROOT = Path(__file__).resolve().parents[2]
AUTHORITY_ACCOUNT_ID = "111122223333"
REGION = "us-east-1"
CHANGE_SET_NAME = "scanalyze-platform-authority-bootstrap-20300101000000"
ORIGINAL_CHANGE_SET_ID = (
    "arn:aws:cloudformation:us-east-1:111122223333:changeSet/"
    f"{CHANGE_SET_NAME}/00000000-0000-4000-8000-000000000000"
)
SUBSTITUTED_CHANGE_SET_ID = (
    "arn:aws:cloudformation:us-east-1:111122223333:changeSet/"
    f"{CHANGE_SET_NAME}/11111111-1111-4111-8111-111111111111"
)
PLAN_ARN = (
    "arn:aws:sts::111122223333:assumed-role/"
    "AWSReservedSSO_ScanalyzeAuthorityBootstrapPlan_0123456789abcdef/initiator"
)
APPROVER_ARN = (
    "arn:aws:sts::111122223333:assumed-role/"
    "AWSReservedSSO_ScanalyzeAuthorityBootApprove_fedcba9876543210/reviewer"
)
PLAN_USER_ID = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
SECOND_PARTY_USER_ID = "11111111-2222-4333-8444-555555555555"
TEMPLATE_BODY = "synthetic exact original template"
TEMPLATE_SHA256 = hashlib.sha256(TEMPLATE_BODY.encode()).hexdigest()
NOW = datetime(2030, 1, 1, tzinfo=UTC)
SIGNING_NOW = datetime.now(UTC).replace(microsecond=0)


class _CloudFormationLoader(yaml.SafeLoader):
    def construct_mapping(self, node: yaml.Node, deep: bool = False) -> Any:
        mapping: dict[Any, Any] = {}
        for key_node, value_node in node.value:
            key = self.construct_object(key_node, deep=deep)
            if key in mapping:
                raise ConstructorError(
                    "while constructing a mapping",
                    node.start_mark,
                    f"duplicate key {key!r}",
                    key_node.start_mark,
                )
            mapping[key] = self.construct_object(value_node, deep=deep)
        return mapping


def _construct_intrinsic(
    loader: yaml.SafeLoader, tag_suffix: str, node: yaml.Node
) -> Any:
    if isinstance(node, yaml.ScalarNode):
        value = loader.construct_scalar(node)
    elif isinstance(node, yaml.SequenceNode):
        value = loader.construct_sequence(node)
    else:
        value = loader.construct_mapping(node)
    return {tag_suffix: value}


_CloudFormationLoader.add_multi_constructor("!", _construct_intrinsic)


def _binding() -> BootstrapBinding:
    return BootstrapBinding(
        authority_account_id=AUTHORITY_ACCOUNT_ID,
        region=REGION,
        stack_name="scanalyze-platform-authority-state-backend",
        state_bucket_name="scanalyze-platform-authority-111122223333-us-east-1-state",
        state_key="platform-authority/terraform.tfstate",
        destination_account_ids=("444455556666", "777788889999"),
    )


def _identity_binding(
    *, plan_user_id: str = PLAN_USER_ID, second_party_user_id: str = SECOND_PARTY_USER_ID
) -> BootstrapIdentityProofBinding:
    prefix = f"arn:aws:iam::{AUTHORITY_ACCOUNT_ID}:role/"
    return BootstrapIdentityProofBinding(
        authority_account_id=AUTHORITY_ACCOUNT_ID,
        region=REGION,
        identity_center_application_arn=(
            "arn:aws:sso::111122223333:application/"
            "ssoins-1234567890abcdef/apl-1234567890abcdef"
        ),
        identity_center_instance_arn=(
            "arn:aws:sso:::instance/ssoins-1234567890abcdef"
        ),
        identity_store_arn=(
            "arn:aws:identitystore::111122223333:identitystore/d-1234567890"
        ),
        redirect_uri="http://127.0.0.1:49152/callback",
        plan_user_id=plan_user_id,
        second_party_user_id=second_party_user_id,
        plan_execution_role_arn=prefix + "ScanalyzeGug274BootstrapPlanAuthority",
        approval_execution_role_arn=(
            prefix + "ScanalyzeGug274BootstrapApprovalAuthority"
        ),
        apply_execution_role_arn=prefix + "ScanalyzeGug274BootstrapApplyExecutor",
        plan_proof_role_arn=prefix + "ScanalyzeGug274BootstrapPlanIdentityProof",
        approval_proof_role_arn=(
            prefix + "ScanalyzeGug274BootstrapApprovalIdentityProof"
        ),
        apply_proof_role_arn=prefix + "ScanalyzeGug274BootstrapApplyIdentityProof",
    )


def _resource_changes() -> tuple[dict[str, str], ...]:
    return (
        {
            "action": "Add",
            "logical_resource_id": "StateKmsKey",
            "resource_type": "AWS::KMS::Key",
        },
        {
            "action": "Add",
            "logical_resource_id": "StateBucket",
            "resource_type": "AWS::S3::Bucket",
        },
        {
            "action": "Add",
            "logical_resource_id": "StateBucketPolicy",
            "resource_type": "AWS::S3::BucketPolicy",
        },
    )


def _plan(
    now: datetime = NOW,
    *,
    change_set_id: str = ORIGINAL_CHANGE_SET_ID,
    nonce: str = "1" * 64,
) -> dict[str, Any]:
    return build_bootstrap_plan_v2(
        binding=_binding(),
        caller_account_id=AUTHORITY_ACCOUNT_ID,
        caller_arn=PLAN_ARN,
        template_sha256=TEMPLATE_SHA256,
        change_set_id=change_set_id,
        change_set_type="CREATE",
        resource_changes=_resource_changes(),
        account_public_access_block_before=None,
        created_at=now - timedelta(minutes=5),
        expires_at=now + timedelta(minutes=55),
        initiator_id="operator-1001",
        artifact_nonce=nonce,
    )


def _approval(plan: Mapping[str, Any], now: datetime = NOW) -> dict[str, Any]:
    return build_bootstrap_approval_v2(
        plan=plan,
        binding=_binding(),
        approver_id="reviewer-2002",
        approver_arn=APPROVER_ARN,
        approved_at=now - timedelta(minutes=1),
        expires_at=now + timedelta(minutes=30),
        approval_nonce="2" * 64,
    )


def _sha(label: str) -> str:
    return "sha256:" + hashlib.sha256(label.encode()).hexdigest()


def _proof(operation: str, identity_binding: BootstrapIdentityProofBinding) -> dict[str, Any]:
    role_kind = {
        "plan": "plan_author",
        "approval": "independent_approver",
        "apply": "apply_verifier",
    }[operation]
    plan_digest = _sha("real-plan-user")
    second_digest = _sha("real-second-party-user")
    expected, peer = (
        (plan_digest, second_digest)
        if operation == "plan"
        else (second_digest, plan_digest)
    )
    return BootstrapIdentityProofReceipt(
        operation=operation,
        role_kind=role_kind,
        identity_binding_digest=identity_binding.binding_digest,
        expected_user_id_digest=expected,
        peer_user_id_digest=peer,
        broker_execution_role_arn_digest=_sha(f"execution:{operation}"),
        proof_role_arn_digest=_sha(f"proof-role:{operation}"),
        proof_session_arn_digest=_sha(f"proof-session:{operation}"),
        managed_policy_version="v12",
        managed_policy_digest=_sha("managed-policy"),
        required_action="sts:SetContext",
        proof_expires_at="2030-01-01T00:15:00Z",
    ).to_dict()


class FakeProofVerifier:
    def __init__(self, events: list[str] | None = None) -> None:
        self.events = events if events is not None else []
        self.calls: list[tuple[str, object]] = []
        self.fail = False

    def verify(
        self,
        *,
        operation: str,
        identity_grant: object,
        binding: BootstrapIdentityProofBinding,
        now: datetime,
    ) -> Mapping[str, Any]:
        self.events.append(f"proof:{operation}")
        self.calls.append((operation, identity_grant))
        if self.fail:
            raise BootstrapIdentityProofError("synthetic proof denied")
        return _proof(operation, binding)


class FakeStore(ArtifactAuthorityStore):
    def __init__(self, events: list[str] | None = None) -> None:
        self.events = events if events is not None else []
        self.record: dict[str, Any] | None = None
        self.fail_create = False
        self.fail_cas = False

    def get(self, authority_record_id: str) -> Mapping[str, Any] | None:
        self.events.append("store:get")
        if self.record is None or self.record["authority_record_id"] != authority_record_id:
            return None
        return copy.deepcopy(self.record)

    def create(self, record: Mapping[str, Any]) -> None:
        self.events.append("store:create")
        if self.fail_create or self.record is not None:
            raise RuntimeError("synthetic ambiguous create")
        self.record = copy.deepcopy(dict(record))

    def compare_and_swap(
        self, before: Mapping[str, Any], after: Mapping[str, Any]
    ) -> None:
        self.events.append("store:cas")
        if self.fail_cas or self.record != dict(before):
            raise RuntimeError("synthetic ambiguous cas")
        self.record = copy.deepcopy(dict(after))


class FakeEffects:
    def __init__(self, events: list[str]) -> None:
        self.events = events
        self.calls = 0

    def execute(
        self, *, plan: Mapping[str, Any], approval: Mapping[str, Any]
    ) -> None:
        self.events.append("effects:execute")
        self.calls += 1


class FakeEffectsFactory:
    def __init__(self, events: list[str]) -> None:
        self.events = events
        self.effects = FakeEffects(events)
        self.calls = 0

    def __call__(self) -> FakeEffects:
        self.events.append("effects:construct")
        self.calls += 1
        return self.effects


def _broker(
    *,
    store: FakeStore | None = None,
    events: list[str] | None = None,
    now: datetime = NOW,
    with_effects: bool = True,
) -> tuple[BootstrapArtifactAuthorityBroker, FakeStore, FakeProofVerifier, FakeEffectsFactory]:
    event_log = events if events is not None else []
    state = store if store is not None else FakeStore(event_log)
    verifier = FakeProofVerifier(event_log)
    factory = FakeEffectsFactory(event_log)
    broker = BootstrapArtifactAuthorityBroker(
        binding=_binding(),
        identity_binding=_identity_binding(),
        identity_verifier=verifier,
        store=state,
        now=lambda: now,
        effects_factory=factory if with_effects else None,
    )
    return broker, state, verifier, factory


def _anchor_approved(
    *, events: list[str] | None = None
) -> tuple[dict[str, Any], dict[str, Any], BootstrapArtifactAuthorityBroker, FakeStore, FakeEffectsFactory]:
    plan = _plan()
    approval = _approval(plan)
    broker, store, _, factory = _broker(events=events)
    broker.anchor_plan(plan, "plan-grant")
    broker.approve_plan(plan, approval, "approval-grant")
    return plan, approval, broker, store, factory


def test_complete_redigested_same_name_different_uuid_pair_fails_at_external_root() -> None:
    """Causal RED: local consistency passes; the immutable anchor rejects it."""

    _, _, broker, _, factory = _anchor_approved()
    attacker_plan = _plan(change_set_id=SUBSTITUTED_CHANGE_SET_ID)
    attacker_approval = _approval(attacker_plan)
    local = prevalidate_bootstrap_apply_v2(
        plan=attacker_plan,
        approval=attacker_approval,
        binding=_binding(),
        current_template_sha256=attacker_plan["template_sha256"],
        now=NOW,
    )
    assert local.name == CHANGE_SET_NAME
    assert local.uuid == "11111111-1111-4111-8111-111111111111"

    with pytest.raises(BootstrapArtifactAuthorityError, match="anchor"):
        broker.claim_and_execute(attacker_plan, attacker_approval, "apply-grant")
    assert factory.calls == 0
    assert factory.effects.calls == 0


def test_real_person_separation_is_runtime_owned_not_role_arn_claimed() -> None:
    with pytest.raises(BootstrapIdentityProofError, match="distinct Identity Store users"):
        _identity_binding(second_party_user_id=PLAN_USER_ID.upper())

    binding = _identity_binding()
    assert binding.proof_target("plan")[1] == PLAN_USER_ID
    assert binding.proof_target("approval")[1] == SECOND_PARTY_USER_ID
    assert binding.proof_target("apply")[1] == SECOND_PARTY_USER_ID
    assert binding.proof_target("approval")[4] != binding.proof_target("apply")[4]


def test_identity_proof_uses_one_exact_context_and_clears_secret_responses() -> None:
    binding = _identity_binding()
    token_response: dict[str, Any] = {
        "accessToken": "raw-access-token",
        "tokenType": "Bearer",
        "expiresIn": 300,
        "scope": ["sts:identity_context"],
        "awsAdditionalDetails": {"identityContext": "raw-context-assertion"},
    }

    class Oidc:
        calls: list[dict[str, Any]] = []

        def create_token_with_iam(self, **kwargs: Any) -> Mapping[str, Any]:
            self.calls.append(kwargs)
            return token_response

    sts_response: dict[str, Any] = {}

    class Sts:
        calls: list[dict[str, Any]] = []

        def assume_role(self, **kwargs: Any) -> Mapping[str, Any]:
            self.calls.append(kwargs)
            session = kwargs["RoleSessionName"]
            role = kwargs["RoleArn"].rsplit("/", 1)[-1]
            sts_response.update(
                {
                    "AssumedRoleUser": {
                        "Arn": (
                            f"arn:aws:sts::{AUTHORITY_ACCOUNT_ID}:assumed-role/"
                            f"{role}/{session}"
                        )
                    },
                    "Credentials": {
                        "AccessKeyId": "raw-access-key",
                        "SecretAccessKey": "raw-secret-key",
                        "SessionToken": "raw-session-token",
                        "Expiration": NOW + timedelta(minutes=15),
                    },
                }
            )
            return sts_response

    oidc, sts = Oidc(), Sts()
    grant: dict[str, Any] = {
        "schema_version": "1",
        "record_type": "platform_authority_bootstrap_identity_grant",
        "authorization_code": "one-shot-code",
        "code_verifier": "v" * 43,
    }
    receipt = BootstrapIdentityProofVerifier(
        oidc_client=oidc, sts_client=sts, clock=lambda: NOW
    ).verify(operation="plan", identity_grant=grant, binding=binding, now=NOW)

    assert grant == {}
    assert token_response == {}
    assert sts_response == {}
    assert oidc.calls[0]["scope"] == ["sts:identity_context"]
    contexts = sts.calls[0]["ProvidedContexts"]
    assert contexts == [
        {
            "ProviderArn": "arn:aws:iam::aws:contextProvider/IdentityCenter",
            "ContextAssertion": "raw-context-assertion",
        }
    ]
    assert sts.calls[0]["RoleArn"] == binding.plan_proof_role_arn
    serialized = json.dumps(receipt)
    for raw_secret in (
        "one-shot-code",
        "raw-access-token",
        "raw-context-assertion",
        "raw-access-key",
        "raw-secret-key",
        "raw-session-token",
        PLAN_USER_ID,
        SECOND_PARTY_USER_ID,
    ):
        assert raw_secret not in serialized
    validate_identity_proof_receipt(receipt, operation="plan", now=NOW)


def test_authorization_code_grant_is_closed_duplicate_safe_and_one_shot() -> None:
    with pytest.raises(BootstrapIdentityProofError, match="invalid"):
        AuthorizationCodeGrant.from_json(
            '{"schema_version":"1","schema_version":"1",'
            '"record_type":"platform_authority_bootstrap_identity_grant",'
            '"authorization_code":"12345678","code_verifier":"'
            + "v" * 43
            + '"}'
        )
    grant = AuthorizationCodeGrant.from_json(
        json.dumps(
            {
                "schema_version": "1",
                "record_type": "platform_authority_bootstrap_identity_grant",
                "authorization_code": "12345678",
                "code_verifier": "v" * 43,
            }
        )
    )
    assert grant.consume_once() == ("12345678", "v" * 43)
    with pytest.raises(BootstrapIdentityProofError, match="replayed"):
        grant.consume_once()


def test_apply_order_is_proof_then_cas_then_client_factory_then_effect() -> None:
    events: list[str] = []
    plan, approval, broker, store, factory = _anchor_approved(events=events)
    events.clear()
    receipt = broker.claim_and_execute(plan, approval, "apply-grant")
    assert events == [
        "proof:apply",
        "store:get",
        "store:cas",
        "effects:construct",
        "effects:execute",
    ]
    assert receipt["state"] == "CLAIMED"
    assert receipt["version"] == 3
    assert store.record is not None and store.record["attempt_count"] == 1
    assert factory.calls == factory.effects.calls == 1


def test_proof_and_cas_failures_receive_no_provider_effect_client() -> None:
    plan, approval, broker, store, factory = _anchor_approved()
    verifier = broker.identity_verifier
    assert isinstance(verifier, FakeProofVerifier)
    verifier.fail = True
    with pytest.raises(BootstrapIdentityProofError):
        broker.claim_and_execute(plan, approval, "apply-grant")
    assert store.record is not None and store.record["state"] == "APPROVED"
    assert factory.calls == 0

    verifier.fail = False
    store.fail_cas = True
    with pytest.raises(BootstrapArtifactAuthorityUncertainError, match="uncertain"):
        broker.claim_and_execute(plan, approval, "apply-grant")
    assert store.record is not None and store.record["state"] == "APPROVED"
    assert factory.calls == 0


def test_replay_and_competing_apply_execute_at_most_once() -> None:
    plan, approval, first, store, first_factory = _anchor_approved()
    second, _, _, second_factory = _broker(store=store)
    first.claim_and_execute(plan, approval, "first-apply-grant")
    with pytest.raises(BootstrapArtifactAuthorityError, match="consumed"):
        second.claim_and_execute(plan, approval, "second-apply-grant")
    assert first_factory.effects.calls == 1
    assert second_factory.calls == 0


def test_ambiguous_create_approval_and_claim_never_create_authority() -> None:
    plan = _plan()
    broker, store, _, factory = _broker()
    store.fail_create = True
    with pytest.raises(BootstrapArtifactAuthorityUncertainError):
        broker.anchor_plan(plan, "plan-grant")
    assert store.record is None and factory.calls == 0

    broker, store, _, factory = _broker()
    store_record_plan = _plan()
    broker.anchor_plan(store_record_plan, "plan-grant")
    store.fail_cas = True
    with pytest.raises(BootstrapArtifactAuthorityUncertainError):
        broker.approve_plan(store_record_plan, _approval(store_record_plan), "approval-grant")
    assert store.record is not None and store.record["state"] == "PLAN_ANCHORED"
    assert factory.calls == 0


class FakeCloudFormation:
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, Any]]] = []
        self.describe_count = 0
        self.tamper_describe_at: int | None = None
        self.template_body = TEMPLATE_BODY
        self.raise_execute = False
        self.parameter_retention_days = "365"
        self.role_arn: str | None = None

    def describe_stacks(self, **kwargs: Any) -> Mapping[str, Any]:
        self.calls.append(("describe_stacks", kwargs))
        return {
            "Stacks": [
                {
                    "StackName": _binding().stack_name,
                    "StackStatus": "REVIEW_IN_PROGRESS",
                    "StackId": (
                        "arn:aws:cloudformation:us-east-1:111122223333:stack/"
                        "scanalyze-platform-authority-state-backend/"
                        "00000000-0000-4000-8000-000000000000"
                    ),
                    "NotificationARNs": [],
                }
            ]
        }

    def list_stack_resources(self, **kwargs: Any) -> Mapping[str, Any]:
        self.calls.append(("list_stack_resources", kwargs))
        return {"StackResourceSummaries": []}

    def describe_change_set(self, **kwargs: Any) -> Mapping[str, Any]:
        self.calls.append(("describe_change_set", kwargs))
        self.describe_count += 1
        change_set_id = (
            SUBSTITUTED_CHANGE_SET_ID
            if self.tamper_describe_at == self.describe_count
            else ORIGINAL_CHANGE_SET_ID
        )
        response: dict[str, Any] = {
            "ChangeSetId": change_set_id,
            "ChangeSetName": CHANGE_SET_NAME,
            "StackName": _binding().stack_name,
            "ChangeSetType": "CREATE",
            "Status": "CREATE_COMPLETE",
            "ExecutionStatus": "AVAILABLE",
            "Capabilities": [],
            "NotificationARNs": [],
            "IncludeNestedStacks": False,
            "ImportExistingResources": False,
            "OnStackFailure": "ROLLBACK",
            "Parameters": [
                {
                    "ParameterKey": "AuthorityAccountId",
                    "ParameterValue": AUTHORITY_ACCOUNT_ID,
                },
                {
                    "ParameterKey": "NoncurrentVersionRetentionDays",
                    "ParameterValue": self.parameter_retention_days,
                },
                {
                    "ParameterKey": "StateKey",
                    "ParameterValue": _binding().state_key,
                },
            ],
            "Tags": [
                {"Key": "managed_by", "Value": "cloudformation"},
                {"Key": "service", "Value": "scanalyze-platform-authority"},
                {"Key": "work_package", "Value": "GUG-206"},
            ],
            "Changes": [
                {
                    "ResourceChange": {
                        "Action": change["action"],
                        "LogicalResourceId": change["logical_resource_id"],
                        "ResourceType": change["resource_type"],
                        "Replacement": change["replacement"],
                    }
                }
                for change in _plan()["planned_resource_changes"]
            ],
        }
        if self.role_arn is not None:
            response["RoleARN"] = self.role_arn
        return response

    def get_template(self, **kwargs: Any) -> Mapping[str, Any]:
        self.calls.append(("get_template", kwargs))
        return {"TemplateBody": self.template_body}

    def execute_change_set(self, **kwargs: Any) -> Mapping[str, Any]:
        self.calls.append(("execute_change_set", kwargs))
        if self.raise_execute:
            raise TimeoutError("synthetic ambiguous execute")
        return {}


class FakeS3Control:
    def __init__(self, order: list[str] | None = None) -> None:
        self.calls: list[dict[str, Any]] = []
        self.order = order

    def put_public_access_block(self, **kwargs: Any) -> Mapping[str, Any]:
        self.calls.append(kwargs)
        if self.order is not None:
            self.order.append("put_public_access_block")
        return {}


def _effects(
    cloudformation: FakeCloudFormation,
    s3control: FakeS3Control,
    *,
    now: Any = lambda: NOW,
) -> Boto3BootstrapApplyEffects:
    return Boto3BootstrapApplyEffects(
        binding=_binding(),
        expected_change_set_name=CHANGE_SET_NAME,
        cloudformation_client=cloudformation,
        s3control_client=s3control,
        now=now,
    )


def test_service_effects_preserve_gug210_full_arn_original_and_bare_execute() -> None:
    cloudformation, s3control = FakeCloudFormation(), FakeS3Control()
    plan = _plan()
    _effects(cloudformation, s3control).execute(plan=plan, approval=_approval(plan))

    describes = [args for name, args in cloudformation.calls if name == "describe_change_set"]
    templates = [args for name, args in cloudformation.calls if name == "get_template"]
    executes = [args for name, args in cloudformation.calls if name == "execute_change_set"]
    assert len(describes) == len(templates) == 2
    assert all(call["ChangeSetName"] == ORIGINAL_CHANGE_SET_ID for call in describes)
    assert all(
        call["ChangeSetName"] == ORIGINAL_CHANGE_SET_ID
        and call["TemplateStage"] == "Original"
        for call in templates
    )
    assert executes == [
        {
            "ChangeSetName": CHANGE_SET_NAME,
            "StackName": _binding().stack_name,
            "DisableRollback": False,
        }
    ]
    assert s3control.calls == [
        {
            "AccountId": AUTHORITY_ACCOUNT_ID,
            "PublicAccessBlockConfiguration": PUBLIC_ACCESS_BLOCK,
        }
    ]


@pytest.mark.parametrize("tamper", ["retention", "role_arn", "deployment_mode"])
def test_noncanonical_change_set_authority_blocks_every_effect(tamper: str) -> None:
    cloudformation, s3control = FakeCloudFormation(), FakeS3Control()
    if tamper == "retention":
        cloudformation.parameter_retention_days = "90"
    elif tamper == "role_arn":
        cloudformation.role_arn = (
            "arn:aws:iam::111122223333:role/foreign-cloudformation-service-role"
        )
    else:
        original = cloudformation.describe_change_set

        def with_deployment_mode(**kwargs: Any) -> Mapping[str, Any]:
            response = dict(original(**kwargs))
            response["DeploymentMode"] = "REVERT_DRIFT"
            return response

        cloudformation.describe_change_set = with_deployment_mode  # type: ignore[method-assign]
    plan = _plan()

    with pytest.raises(BootstrapArtifactAuthorityError, match="canonical"):
        _effects(cloudformation, s3control).execute(
            plan=plan, approval=_approval(plan)
        )

    assert s3control.calls == []
    assert not any(name == "execute_change_set" for name, _ in cloudformation.calls)


def test_final_uuid_readback_and_freshness_block_execute_after_pab() -> None:
    cloudformation, s3control = FakeCloudFormation(), FakeS3Control()
    cloudformation.tamper_describe_at = 2
    plan = _plan()
    with pytest.raises(BootstrapArtifactAuthorityError, match="differs"):
        _effects(cloudformation, s3control).execute(plan=plan, approval=_approval(plan))
    assert len(s3control.calls) == 1
    assert not any(name == "execute_change_set" for name, _ in cloudformation.calls)

    cloudformation, s3control = FakeCloudFormation(), FakeS3Control()
    moments = iter((NOW, NOW + timedelta(hours=1)))
    with pytest.raises(BootstrapArtifactAuthorityError, match="expired"):
        _effects(cloudformation, s3control, now=lambda: next(moments)).execute(
            plan=plan, approval=_approval(plan)
        )
    assert len(s3control.calls) == 1
    assert not any(name == "execute_change_set" for name, _ in cloudformation.calls)


@pytest.mark.parametrize("tamper", ["template", "inventory"])
def test_initial_template_or_inventory_mismatch_blocks_every_effect(tamper: str) -> None:
    cloudformation, s3control = FakeCloudFormation(), FakeS3Control()
    if tamper == "template":
        cloudformation.template_body = "rewritten template"
    else:
        original = cloudformation.describe_change_set

        def changed(**kwargs: Any) -> Mapping[str, Any]:
            response = dict(original(**kwargs))
            changes = copy.deepcopy(response["Changes"])
            changes[0]["ResourceChange"]["LogicalResourceId"] = "SubstitutedKey"
            response["Changes"] = changes
            return response

        cloudformation.describe_change_set = changed  # type: ignore[method-assign]
    plan = _plan()
    with pytest.raises(BootstrapArtifactAuthorityError):
        _effects(cloudformation, s3control).execute(plan=plan, approval=_approval(plan))
    assert s3control.calls == []
    assert not any(name == "execute_change_set" for name, _ in cloudformation.calls)


def test_execute_ambiguity_is_one_call_and_reconcile_only() -> None:
    cloudformation, s3control = FakeCloudFormation(), FakeS3Control()
    cloudformation.raise_execute = True
    plan = _plan()
    with pytest.raises(BootstrapArtifactAuthorityUncertainError, match="reconcile only"):
        _effects(cloudformation, s3control).execute(plan=plan, approval=_approval(plan))
    assert len([1 for name, _ in cloudformation.calls if name == "execute_change_set"]) == 1


@pytest.mark.parametrize(
    ("artifact", "field", "value"),
    [
        ("plan", "trust_root_generation", True),
        ("plan", "native_lockfile_enabled", 1),
        ("approval", "native_lockfile_enabled", 1),
        ("ledger", "version", True),
        ("ledger", "attempt_count", False),
    ],
)
def test_bool_integer_type_confusion_is_rejected(
    artifact: str, field: str, value: object
) -> None:
    plan = _plan()
    approval = _approval(plan)
    broker, store, _, _ = _broker()
    broker.anchor_plan(plan, "plan-grant")
    broker.approve_plan(plan, approval, "approval-grant")
    if artifact == "plan":
        candidate = copy.deepcopy(plan)
        candidate[field] = value
        with pytest.raises(BootstrapArtifactAuthorityError):
            validate_bootstrap_plan_v2(plan=candidate, binding=_binding())
    elif artifact == "approval":
        candidate = copy.deepcopy(approval)
        candidate[field] = value
        with pytest.raises(BootstrapArtifactAuthorityError):
            validate_bootstrap_approval_v2(
                plan=plan, approval=candidate, binding=_binding()
            )
    else:
        assert store.record is not None
        candidate = copy.deepcopy(store.record)
        candidate[field] = value
        with pytest.raises(BootstrapArtifactAuthorityError):
            validate_authority_ledger(record=candidate, binding=_binding())


def test_ledger_state_machine_requires_exact_proof_shape() -> None:
    plan, approval, broker, store, _ = _anchor_approved()
    assert store.record is not None
    impossible = copy.deepcopy(store.record)
    impossible["state"] = "CLAIMED"
    impossible["version"] = 3
    impossible["attempt_count"] = 1
    impossible["claimed_at"] = impossible["updated_at"]
    impossible["ledger_digest"] = authority_module._ledger_digest(impossible)
    with pytest.raises(BootstrapArtifactAuthorityError, match="Apply identity proof"):
        validate_authority_ledger(record=impossible, binding=_binding())
    broker.claim_and_execute(plan, approval, "apply-grant")
    assert store.record is not None
    spliced = copy.deepcopy(store.record)
    spliced["apply_identity_proof"] = spliced["approval_identity_proof"]
    with pytest.raises(BootstrapArtifactAuthorityError):
        validate_authority_ledger(record=spliced, binding=_binding())


class FakeLambda:
    def __init__(self, *, fail: bool = False) -> None:
        self.fail = fail
        self.calls: list[dict[str, Any]] = []

    def invoke(self, **kwargs: Any) -> Mapping[str, Any]:
        self.calls.append(kwargs)
        if self.fail:
            raise TimeoutError("synthetic provider secret")
        payload = json.loads(kwargs["Payload"])
        function = kwargs["FunctionName"]
        if function.endswith(f":{APPROVAL_AUTHORITY_FUNCTION}:1"):
            state, version = "APPROVED", 2
        elif function.endswith(f":{APPLY_EXECUTOR_FUNCTION}:1"):
            state, version = "CLAIMED", 3
        else:
            state, version = "PLAN_ANCHORED", 1
        plan = payload["plan"]
        approval = payload.get("approval")
        receipt: dict[str, Any] = {
            "schema_version": "1",
            "record_type": "platform_authority_bootstrap_authority_receipt",
            "domain_separator": (
                "scanalyze.platform-authority.bootstrap.authority-receipt.v1"
            ),
            "trust_root_id": plan["trust_root_id"],
            "trust_root_generation": 1,
            "authority_record_id": plan["authority_record_id"],
            "plan_artifact_digest": plan["plan_artifact_digest"],
            "approval_artifact_digest": (
                approval["approval_artifact_digest"]
                if isinstance(approval, Mapping)
                else None
            ),
            "identity_binding_digest": _sha("binding"),
            "plan_identity_proof_digest": _sha("plan-proof"),
            "approval_identity_proof_digest": (
                _sha("approval-proof") if version >= 2 else None
            ),
            "apply_identity_proof_digest": _sha("apply-proof") if version == 3 else None,
            "state": state,
            "version": version,
            "ledger_digest": _sha("ledger"),
        }
        receipt["receipt_digest"] = authority_module._domain_digest(
            receipt["domain_separator"], receipt
        )
        return {
            "StatusCode": 200,
            "Payload": io.BytesIO(json.dumps(receipt).encode()),
        }


def test_lambda_adapter_targets_only_exact_versions_and_clears_grants() -> None:
    fake = FakeLambda()
    client = LambdaBootstrapArtifactAuthorityClient(
        binding=_binding(), lambda_client=fake
    )
    plan = _plan()
    approval = _approval(plan)
    client.anchor_plan(plan, "plan-secret")
    client.approve_plan(plan, approval, "approval-secret")
    client.claim_and_execute(plan, approval, "apply-secret")
    assert [call["FunctionName"] for call in fake.calls] == [
        broker_function_arn(_binding(), PLAN_AUTHORITY_FUNCTION),
        broker_function_arn(_binding(), APPROVAL_AUTHORITY_FUNCTION),
        broker_function_arn(_binding(), APPLY_EXECUTOR_FUNCTION),
    ]
    assert all(call["FunctionName"].endswith(f":{BROKER_FUNCTION_VERSION}") for call in fake.calls)


def test_lambda_and_handler_provider_errors_are_sanitized(monkeypatch: pytest.MonkeyPatch) -> None:
    client = LambdaBootstrapArtifactAuthorityClient(
        binding=_binding(), lambda_client=FakeLambda(fail=True)
    )
    with pytest.raises(BootstrapArtifactAuthorityUncertainError) as captured:
        client.anchor_plan(_plan(), "raw-grant")
    assert "synthetic provider secret" not in str(captured.value)
    assert captured.value.__cause__ is None

    def fail(event: object, context: object) -> Mapping[str, Any]:
        raise RuntimeError("raw-provider-response-and-arn")

    monkeypatch.setattr(authority_module, "_handle_plan_anchor", fail)
    with pytest.raises(BootstrapArtifactAuthorityError) as handled:
        authority_module.plan_anchor_handler({}, object())
    assert str(handled.value) == "BOOTSTRAP_ARTIFACT_AUTHORITY_RUNTIME_UNAVAILABLE"
    assert handled.value.__cause__ is None


class FakeDynamoDb:
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, Any]]] = []

    def put_item(self, **kwargs: Any) -> Mapping[str, Any]:
        self.calls.append(("put", kwargs))
        return {}

    def update_item(self, **kwargs: Any) -> Mapping[str, Any]:
        self.calls.append(("update", kwargs))
        return {}


def test_dynamodb_store_uses_exact_table_create_only_and_digest_cas() -> None:
    plan = _plan()
    broker, state, _, _ = _broker()
    broker.anchor_plan(plan, "plan-grant")
    assert state.record is not None
    fake = FakeDynamoDb()
    store = DynamoDbArtifactAuthorityStore(binding=_binding(), dynamodb_client=fake)
    store.create(state.record)
    assert fake.calls[0][1]["TableName"] == LEDGER_TABLE_NAME
    assert fake.calls[0][1]["ConditionExpression"] == (
        "attribute_not_exists(trust_root_id) AND "
        "attribute_not_exists(authority_record_id)"
    )
    before = copy.deepcopy(state.record)
    approval = _approval(plan)
    broker.approve_plan(plan, approval, "approval-grant")
    assert state.record is not None
    store.compare_and_swap(before, state.record)
    request = fake.calls[1][1]
    assert request["Key"]["trust_root_id"] == {"S": trust_root_id(_binding())}
    assert request["ExpressionAttributeValues"][":expected_ledger_digest"] == {
        "S": before["ledger_digest"]
    }


def _allowed_actions(policy: Mapping[str, Any]) -> set[str]:
    return {
        action
        for statement in policy["Statement"]
        if statement.get("Effect") == "Allow"
        for action in (
            statement.get("Action")
            if isinstance(statement.get("Action"), list)
            else [statement.get("Action")]
        )
        if isinstance(action, str)
    }


def test_human_roles_are_disjoint_fail_closed_and_apply_has_no_effect_authority() -> None:
    policy_root = REPO_ROOT / "policies/iam"
    plan_template = json.loads(
        (policy_root / "platform-authority-bootstrap-plan-role.json").read_text()
    )
    approval_template = json.loads(
        (policy_root / "platform-authority-bootstrap-approval-role.json").read_text()
    )
    apply_template = json.loads(
        (policy_root / "platform-authority-bootstrap-apply-role.json").read_text()
    )
    plan = render_bootstrap_iam_policy(
        policy_template=plan_template,
        binding=_binding(),
        change_set_name=CHANGE_SET_NAME,
    )
    approval = render_bootstrap_approval_iam_policy(
        policy_template=approval_template, binding=_binding()
    )
    apply = render_bootstrap_apply_iam_policy(
        policy_template=apply_template, binding=_binding()
    )
    assert broker_function_arn(_binding(), PLAN_AUTHORITY_FUNCTION) in json.dumps(plan)
    assert broker_function_arn(_binding(), APPROVAL_AUTHORITY_FUNCTION) in json.dumps(approval)
    assert broker_function_arn(_binding(), APPLY_EXECUTOR_FUNCTION) in json.dumps(apply)
    apply_allows = _allowed_actions(apply)
    assert "lambda:InvokeFunction" in apply_allows
    assert not any(
        action.startswith(("cloudformation:Execute", "dynamodb:", "iam:", "kms:Create", "kms:Put", "s3:Put"))
        for action in apply_allows
    )
    deny_all = next(
        statement
        for statement in apply["Statement"]
        if statement["Sid"] == "DenyEveryNonReadOrBrokerAction"
    )
    assert deny_all["Effect"] == "Deny" and "NotAction" in deny_all


def test_apply_policy_cannot_self_justify_an_added_assume_role_allow() -> None:
    template = json.loads(
        (
            REPO_ROOT
            / "policies/iam/platform-authority-bootstrap-apply-role.json"
        ).read_text()
    )
    template["Statement"].insert(
        -1,
        {
            "Sid": "EscalateThroughArbitraryRole",
            "Effect": "Allow",
            "Action": "sts:AssumeRole",
            "Resource": "*",
        },
    )
    deny_all = next(
        statement
        for statement in template["Statement"]
        if statement["Sid"] == "DenyEveryNonReadOrBrokerAction"
    )
    deny_all["NotAction"].append("sts:AssumeRole")

    with pytest.raises(BootstrapArtifactAuthorityError, match="exact read-only"):
        render_bootstrap_apply_iam_policy(
            policy_template=template, binding=_binding()
        )


def test_approval_policy_rejects_conditions_that_neutralize_every_deny() -> None:
    template = json.loads(
        (
            REPO_ROOT
            / "policies/iam/platform-authority-bootstrap-approval-role.json"
        ).read_text()
    )
    for statement in template["Statement"]:
        if statement["Effect"] == "Deny":
            statement["Condition"] = {
                "StringEquals": {"aws:PrincipalTag/never": "true"}
            }

    with pytest.raises(
        BootstrapArtifactAuthorityError,
        match="fail-closed boundary is not exact",
    ):
        render_bootstrap_approval_iam_policy(
            policy_template=template, binding=_binding()
        )


def test_cfn_declares_exact_identity_cas_executor_and_supply_chain_boundaries() -> None:
    path = REPO_ROOT / "bootstrap/cfn-platform-authority-bootstrap-artifact-authority.yaml"
    text = path.read_text()
    template = yaml.load(text, Loader=_CloudFormationLoader)
    resources = template["Resources"]
    parameters = template["Parameters"]
    signing_contract = json.loads(
        (
            REPO_ROOT
            / "bootstrap/platform-authority-bootstrap-artifact-signing-trust-root.json"
        ).read_text()
    )
    assert signing_contract["configuration_status"] == "NOT_CONFIGURED"
    assert signing_contract["profile_version_id"] is None
    assert signing_contract["profile_version_arn"] is None
    assert parameters["AuthoritySigningProfileName"]["AllowedValues"] == [
        "scanalyze_gug274_bootstrap_artifact_authority"
    ]
    assert parameters["AuthoritySigningTrustRootConfigured"] == {
        "Type": "String",
        "Default": "false",
        "AllowedValues": ["false"],
        "Description": parameters["AuthoritySigningTrustRootConfigured"][
            "Description"
        ],
    }
    activation_assertion = template["Rules"][
        "ReviewedSignerTrustRootMustBeConfigured"
    ]["Assertions"][0]
    assert activation_assertion["Assert"] == {
        "Equals": [
            {"Ref": "AuthoritySigningTrustRootConfigured"},
            "true",
        ]
    }
    signing = resources["AuthorityCodeSigningConfig"]["Properties"]
    assert signing["CodeSigningPolicies"]["UntrustedArtifactOnDeployment"] == "Enforce"
    assert "IfExists" not in text
    assert "apply-claim" not in text

    for role_name in (
        "PlanAuthorityExecutionRole",
        "ApprovalAuthorityExecutionRole",
        "ApplyExecutorExecutionRole",
    ):
        trust = resources[role_name]["Properties"]["AssumeRolePolicyDocument"]
        assert trust == {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "lambda.amazonaws.com"},
                    "Action": "sts:AssumeRole",
                }
            ],
        }

    table_policy = resources["ArtifactAuthorityTable"]["Properties"][
        "ResourcePolicy"
    ]["PolicyDocument"]["Statement"]
    assert all(statement["Effect"] == "Deny" for statement in table_policy)
    assert {statement["Sid"] for statement in table_policy} == {
        "DenyAnyForeignTrustRootKey",
        "DenyInsecureArtifactAuthorityTransport",
        "DenyPlanCreatesOutsideExactPlanAuthority",
        "DenyReadsOutsideExactApprovalAndApplyAuthorities",
        "DenyTransitionsOutsideExactApprovalAndApplyAuthorities",
        "DenyUnsupportedArtifactAuthorityOperations",
    }
    for role_name, exact_function_name in (
        (
            "PlanAuthorityExecutionRole",
            "scanalyze-platform-authority-bootstrap-plan-authority",
        ),
        (
            "ApprovalAuthorityExecutionRole",
            "scanalyze-platform-authority-bootstrap-approval-authority",
        ),
        (
            "ApplyExecutorExecutionRole",
            "scanalyze-platform-authority-bootstrap-apply-executor",
        ),
    ):
        role_statements = resources[role_name]["Properties"]["Policies"][0][
            "PolicyDocument"
        ]["Statement"]
        ledger_allows = [
            statement
            for statement in role_statements
            if statement["Effect"] == "Allow"
            and any(
                action.startswith("dynamodb:")
                for action in (
                    [statement["Action"]]
                    if isinstance(statement["Action"], str)
                    else statement["Action"]
                )
            )
        ]
        assert len(ledger_allows) == 1
        source_function = ledger_allows[0]["Condition"]["ArnEquals"][
            "lambda:SourceFunctionArn"
        ]["Sub"]
        assert source_function.endswith(":function:" + exact_function_name)

    for proof_role, user_parameter, execution_role in (
        ("PlanIdentityProofRole", "PlanIdentityStoreUserId", "ScanalyzeGug274BootstrapPlanAuthority"),
        ("ApprovalIdentityProofRole", "SecondPartyIdentityStoreUserId", "ScanalyzeGug274BootstrapApprovalAuthority"),
        ("ApplyIdentityProofRole", "SecondPartyIdentityStoreUserId", "ScanalyzeGug274BootstrapApplyExecutor"),
    ):
        statements = resources[proof_role]["Properties"]["AssumeRolePolicyDocument"]["Statement"]
        context = next(statement for statement in statements if statement["Action"] == "sts:SetContext")
        condition = context["Condition"]
        assert condition["ForAllValues:ArnEquals"] == {
            "sts:RequestContextProviders": [
                "arn:aws:iam::aws:contextProvider/IdentityCenter"
            ]
        }
        assert condition["StringEquals"] == {
            "sts:RequestContext/identitystore:UserId": {"Ref": user_parameter}
        }
        assert set(condition["ArnEquals"]) == {
            "aws:PrincipalArn",
            "sts:RequestContext/identitystore:IdentityStoreArn",
            "sts:RequestContext/identitycenter:InstanceArn",
            "sts:RequestContext/identitycenter:ApplicationArn",
        }
        assert condition["ArnEquals"]["aws:PrincipalArn"]["Sub"].endswith(
            execution_role
        )
        assert condition["ArnEquals"][
            "sts:RequestContext/identitystore:IdentityStoreArn"
        ] == {"Ref": "IdentityStoreArn"}
        assert condition["ArnEquals"][
            "sts:RequestContext/identitycenter:InstanceArn"
        ] == {"Ref": "IdentityCenterInstanceArn"}
        assert condition["ArnEquals"][
            "sts:RequestContext/identitycenter:ApplicationArn"
        ] == {"Ref": "IdentityCenterApplicationArn"}
        assert condition["Null"] == {
            "sts:RequestContextProviders": "false",
            "sts:RequestContext/identitystore:UserId": "false",
            "sts:RequestContext/identitystore:IdentityStoreArn": "false",
            "sts:RequestContext/identitycenter:InstanceArn": "false",
            "sts:RequestContext/identitycenter:ApplicationArn": "false",
        }

    apply_statements = resources["ApplyExecutorExecutionRole"]["Properties"]["Policies"][0]["PolicyDocument"]["Statement"]
    by_sid = {statement["Sid"]: statement for statement in apply_statements}
    assert "cloudformation:ExecuteChangeSet" in by_sid["ReadAndExecuteExactBootstrapChangeSet"]["Action"]
    assert "s3:GetEncryptionConfiguration" in by_sid["ReadExactStateBucketViaCloudFormation"]["Action"]
    assert "kms:DescribeKey" in by_sid["ReadTaggedStateKeyViaCloudFormation"]["Action"]
    tagged_alias = by_sid["BindAliasOnlyToTaggedStateKeyViaCloudFormation"]
    assert set(tagged_alias["Condition"]["StringEquals"]) == {
        "aws:ResourceTag/service",
        "aws:ResourceTag/data_class",
        "aws:ResourceTag/account_id",
        "aws:ResourceTag/region",
    }

    for version in ("PlanAuthorityVersion", "ApprovalAuthorityVersion", "ApplyExecutorVersion"):
        assert resources[version]["Properties"]["CodeSha256"] == {
            "Ref": "SignedAuthorityArtifactCodeSha256"
        }
    expected_runtime_provenance = {
        "GUG274_SOURCE_COMMIT": {"Ref": "SourceCommit"},
        "GUG274_EXPECTED_BOTO3_VERSION": {"Ref": "ExpectedBoto3Version"},
        "GUG274_EXPECTED_BOTOCORE_VERSION": {"Ref": "ExpectedBotocoreVersion"},
    }
    for function in (
        "PlanAuthorityFunction",
        "ApprovalAuthorityFunction",
        "ApplyExecutorFunction",
    ):
        properties = resources[function]["Properties"]
        assert properties["CodeSigningConfigArn"] == {
            "Ref": "AuthorityCodeSigningConfig"
        }
        environment = properties["Environment"]["Variables"]
        for name, expected in expected_runtime_provenance.items():
            assert environment[name] == expected
        assert {
            "Key": "signing_receipt_digest",
            "Value": {"Ref": "AuthoritySigningReceiptDigest"},
        } in properties["Tags"]
        assert {
            "Key": "signing_trust_root_digest",
            "Value": {"Ref": "AuthoritySigningTrustRootContractDigest"},
        } in properties["Tags"]
    assert template["Outputs"]["AuthoritySigningReceiptDigest"]["Value"] == {
        "Ref": "AuthoritySigningReceiptDigest"
    }
    assert template["Outputs"]["SignedAuthorityArtifactCodeSha256"]["Value"] == {
        "Ref": "SignedAuthorityArtifactCodeSha256"
    }
    assert template["Outputs"]["AuthoritySigningTrustRootContractDigest"][
        "Value"
    ] == {"Ref": "AuthoritySigningTrustRootContractDigest"}
    assert template["Outputs"]["ApplyExecutorPublishedVersion"]["Value"] == {
        "GetAtt": "ApplyExecutorVersion.Version"
    }
    assert template["Outputs"]["ProductionAuthorized"]["Value"] == "false"


def test_identity_application_actor_policy_is_exact_service_only() -> None:
    policy = json.loads(
        (
            REPO_ROOT
            / "policies/iam/platform-authority-bootstrap-artifact-identity-application-actor-policy.json"
        ).read_text()
    )
    allows = [statement for statement in policy["Statement"] if statement["Effect"] == "Allow"]
    assert len(allows) == 1
    assert allows[0]["Action"] == "sso-oauth:CreateTokenWithIAM"
    assert allows[0]["Resource"] == "*"
    principals = allows[0]["Principal"]["AWS"]
    assert len(principals) == 3
    assert all("ScanalyzeGug274Bootstrap" in principal for principal in principals)


def test_package_is_reproducible_closed_and_tamper_evident() -> None:
    committed_sources = {
        path: (REPO_ROOT / path).read_bytes() for path in SOURCE_PATHS
    }
    first = _build_bootstrap_artifact_package(
        source_root=REPO_ROOT,
        source_commit="a" * 40,
        expected_boto3_version="1.42.57",
        expected_botocore_version="1.42.97",
        committed_sources=committed_sources,
    )
    second = _build_bootstrap_artifact_package(
        source_root=REPO_ROOT,
        source_commit="a" * 40,
        expected_boto3_version="1.42.57",
        expected_botocore_version="1.42.97",
        committed_sources=committed_sources,
    )
    assert first.archive == second.archive
    assert first.manifest == second.manifest
    assert [entry["path"] for entry in first.manifest["entries"]] == [
        path.as_posix() for path in PACKAGE_PATHS
    ]
    assert first.manifest["signing_contract"] == {
        "profile_name": "scanalyze_gug274_bootstrap_artifact_authority",
        "trust_root_contract_path": (
            "bootstrap/platform-authority-bootstrap-artifact-signing-trust-root.json"
        ),
        "trust_root_configuration_status": "NOT_CONFIGURED",
        "immutable_profile_version_required": True,
        "untrusted_artifact_on_deployment": "Enforce",
        "signed_s3_object_version_required": True,
        "signed_artifact_receipt_required": True,
        "signed_lambda_code_sha256_from_receipt_required": True,
        "trusted_read_only_refresh_required": True,
        "unsigned_archive_is_not_deployable": True,
    }
    assert first.manifest["activation_contract"] == {
        "all_three_functions_same_signed_code_sha256": True,
        "all_three_published_versions_must_equal": 1,
        "signed_artifact_evidence_observed": False,
        "deployment_evidence_observed": False,
        "live_identity_proof_observed": False,
    }
    with pytest.raises(BootstrapArtifactPackageError):
        validate_bootstrap_artifact_package(
            manifest=dict(first.manifest),
            archive=first.archive + b"tamper",
            expected_source_commit="a" * 40,
        )


@pytest.mark.parametrize(
    "script_name",
    [
        "platform-authority-bootstrap.py",
        "platform-authority-bootstrap-artifact-package.py",
        "platform-authority-bootstrap-signed-artifact.py",
    ],
)
def test_artifact_clis_require_isolated_python_before_repo_imports(
    tmp_path: Path, script_name: str
) -> None:
    hostile = tmp_path / "hostile"
    tooling = hostile / "tooling"
    tooling.mkdir(parents=True)
    marker = tmp_path / "hostile-imported"
    (tooling / "__init__.py").write_text(
        f"from pathlib import Path\nPath({str(marker)!r}).write_text('bad')\n"
    )
    environment = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "LANG": "C",
        "LC_ALL": "C",
        "PYTHONPATH": str(hostile),
    }
    blocked = subprocess.run(
        [
            sys.executable,
            str(REPO_ROOT / "scripts/deployment" / script_name),
            "--help",
        ],
        cwd=REPO_ROOT,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )
    assert blocked.returncode == 2
    assert "ISOLATED_PYTHON_REQUIRED" in blocked.stderr
    assert not marker.exists()

    environment.pop("PYTHONPATH", None)
    environment.pop("PYTHONHOME", None)
    site_enabled = subprocess.run(
        [
            sys.executable,
            "-I",
            str(REPO_ROOT / "scripts/deployment" / script_name),
            "--help",
        ],
        cwd=REPO_ROOT,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )
    assert site_enabled.returncode == 2
    assert "ISOLATED_PYTHON_REQUIRED" in site_enabled.stderr

    bytecode_prefix_enabled = subprocess.run(
        [
            sys.executable,
            "-I",
            "-S",
            "-X",
            f"pycache_prefix={tmp_path / 'untrusted-pycache'}",
            str(REPO_ROOT / "scripts/deployment" / script_name),
            "--help",
        ],
        cwd=REPO_ROOT,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )
    assert bytecode_prefix_enabled.returncode == 2
    assert "ISOLATED_PYTHON_REQUIRED" in bytecode_prefix_enabled.stderr

    isolated = subprocess.run(
        [
            sys.executable,
            "-I",
            "-S",
            str(REPO_ROOT / "scripts/deployment" / script_name),
            "--help",
        ],
        cwd=REPO_ROOT,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )
    assert isolated.returncode == 0, isolated.stderr


def test_source_only_repository_importer_ignores_unchecked_bytecode(
    tmp_path: Path,
) -> None:
    source_root = tmp_path / "reviewed-source"
    tooling_root = source_root / "tooling"
    tooling_root.mkdir(parents=True)
    (tooling_root / "__init__.py").write_text("", encoding="utf-8")
    probe_source = tooling_root / "probe.py"
    marker = tmp_path / "unchecked-bytecode-executed"
    probe_source.write_text(
        "from pathlib import Path\n"
        f"Path({str(marker)!r}).write_text('bad')\n"
        "VALUE = 'bytecode'\n",
        encoding="utf-8",
    )
    py_compile.compile(
        str(probe_source),
        doraise=True,
        invalidation_mode=py_compile.PycInvalidationMode.UNCHECKED_HASH,
    )
    probe_source.write_text("VALUE = 'source'\n", encoding="utf-8")

    unprotected = subprocess.run(
        [
            sys.executable,
            "-I",
            "-S",
            "-c",
            (
                "import sys; "
                f"sys.path.insert(0, {str(source_root)!r}); "
                "import tooling.probe; "
                "assert tooling.probe.VALUE == 'bytecode'"
            ),
        ],
        cwd=tmp_path,
        env={"PATH": os.environ.get("PATH", "/usr/bin:/bin")},
        capture_output=True,
        text=True,
        check=False,
    )
    assert unprotected.returncode == 0, unprotected.stderr
    assert marker.exists()
    marker.unlink()

    boundary = (
        REPO_ROOT / "tooling/platform_authority_source_only_import.py"
    )
    protected_code = "\n".join(
        (
            "from pathlib import Path",
            f"boundary = Path({str(boundary)!r})",
            "namespace = {'__file__': str(boundary), '__name__': '_source_boundary'}",
            "exec(compile(boundary.read_bytes(), str(boundary), 'exec'), namespace)",
            f"namespace['install_repository_source_only_importer'](Path({str(source_root)!r}))",
            "import tooling.probe",
            "assert tooling.probe.VALUE == 'source'",
        )
    )
    protected = subprocess.run(
        [sys.executable, "-I", "-S", "-c", protected_code],
        cwd=tmp_path,
        env={"PATH": os.environ.get("PATH", "/usr/bin:/bin")},
        capture_output=True,
        text=True,
        check=False,
    )
    assert protected.returncode == 0, protected.stderr
    assert not marker.exists()


def _materialize_locked_sdk_runtime(runtime_site: Path) -> None:
    for distribution_name, contract in SDK_DISTRIBUTION_LOCKS.items():
        distribution = metadata.distribution(distribution_name)
        distribution_root = Path(distribution.locate_file("")).resolve()
        record_path = Path(distribution._path) / "RECORD"
        rows = [
            row
            for row in csv.reader(
                record_path.read_text(encoding="utf-8").splitlines()
            )
            if "__pycache__" not in Path(row[0]).parts
            and not row[0].endswith((".pyc", ".pyo"))
        ]
        record_relative = record_path.relative_to(distribution_root).as_posix()
        ignored_install_paths = frozenset(contract.get("ignored_install_paths", ()))
        for row in rows:
            if row[0] in ignored_install_paths:
                continue
            source = (distribution_root / row[0]).resolve(strict=True)
            destination = Path(os.path.abspath(runtime_site / row[0]))
            missing_directories: list[Path] = []
            parent = destination.parent
            while not parent.exists():
                missing_directories.append(parent)
                parent = parent.parent
            for directory in reversed(missing_directories):
                directory.mkdir(mode=0o700)
            if not destination.exists():
                if row[0] == record_relative:
                    with destination.open("w", encoding="utf-8", newline="") as stream:
                        writer = csv.writer(stream, lineterminator="\n")
                        writer.writerows(rows)
                else:
                    destination.write_bytes(source.read_bytes())
                destination.chmod(0o600)


def _isolated_sdk_probe_code(
    *, runtime_site: Path, source_root: Path, success_expected: bool
) -> str:
    lines = [
        "from pathlib import Path",
        "import sys",
        f"runtime_site = {str(runtime_site)!r}",
        "runtime_root = Path(runtime_site).parent",
        "isolated = tuple(path for path in sys.path if 'site-packages' not in Path(path).parts)",
        f"sys.path.insert(0, {str(REPO_ROOT)!r})",
        "from tooling.platform_authority_bootstrap_artifact_package import BootstrapArtifactPackageError, import_reviewed_aws_sdk",
        f"source_root = Path({str(source_root)!r})",
    ]
    if success_expected:
        lines.extend(
            (
                "boto3, botocore, _ = import_reviewed_aws_sdk(source_root=source_root, isolated_import_paths=isolated, sdk_runtime_root=runtime_root)",
                "assert boto3.__version__ == '1.42.57'",
                "assert botocore.__version__ == '1.42.97'",
            )
        )
    else:
        lines.extend(
            (
                "try:",
                "    import_reviewed_aws_sdk(source_root=source_root, isolated_import_paths=isolated, sdk_runtime_root=runtime_root)",
                "except BootstrapArtifactPackageError as exc:",
                "    print(str(exc))",
                "else:",
                "    raise AssertionError('tampered SDK accepted')",
            )
        )
    return "\n".join(lines)


def test_reviewed_sdk_import_never_executes_repository_shadow(tmp_path: Path) -> None:
    hostile_root = tmp_path / "hostile-source"
    marker = tmp_path / "shadow-executed"
    for shadow_name in ("boto3.py", "botocore/__init__.py"):
        shadow = hostile_root / shadow_name
        shadow.parent.mkdir(parents=True, exist_ok=True)
        shadow.write_text(
            f"from pathlib import Path\nPath({str(marker)!r}).write_text('bad')\n",
            encoding="utf-8",
        )

    runtime_site = (
        tmp_path / "reviewed-runtime/lib/python3.11/site-packages"
    )
    _materialize_locked_sdk_runtime(runtime_site)
    code = _isolated_sdk_probe_code(
        runtime_site=runtime_site,
        source_root=hostile_root,
        success_expected=True,
    )
    environment = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "LANG": "C",
        "LC_ALL": "C",
    }
    result = subprocess.run(
        [sys.executable, "-I", "-S", "-c", code],
        cwd=tmp_path,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert not marker.exists()


def test_reviewed_sdk_rejects_pth_and_unreviewed_site_content_before_import(
    tmp_path: Path,
) -> None:
    runtime_site = tmp_path / "reviewed-runtime/lib/python3.11/site-packages"
    _materialize_locked_sdk_runtime(runtime_site)
    marker = tmp_path / "pth-executed"
    hostile_pth = runtime_site / "hostile.pth"
    hostile_pth.write_text(
        f"import pathlib; pathlib.Path({str(marker)!r}).write_text('bad')\n",
        encoding="utf-8",
    )
    hostile_pth.chmod(0o600)
    source_root = tmp_path / "source"
    source_root.mkdir()
    result = subprocess.run(
        [
            sys.executable,
            "-I",
            "-S",
            "-c",
            _isolated_sdk_probe_code(
                runtime_site=runtime_site,
                source_root=source_root,
                success_expected=False,
            ),
        ],
        cwd=tmp_path,
        env={
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "LANG": "C",
            "LC_ALL": "C",
        },
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert "SDK_RUNTIME_SITE_NOT_CLOSED" in result.stdout
    assert not marker.exists()


def test_reviewed_sdk_rejects_group_writable_runtime_before_import(
    tmp_path: Path,
) -> None:
    runtime_site = tmp_path / "reviewed-runtime/lib/python3.11/site-packages"
    _materialize_locked_sdk_runtime(runtime_site)
    session_path = runtime_site / "boto3/session.py"
    session_bytes = session_path.read_bytes()
    session_path.unlink()
    session_path.write_bytes(session_bytes)
    session_path.chmod(session_path.stat().st_mode | 0o020)
    source_root = tmp_path / "source"
    source_root.mkdir()
    result = subprocess.run(
        [
            sys.executable,
            "-I",
            "-S",
            "-c",
            _isolated_sdk_probe_code(
                runtime_site=runtime_site,
                source_root=source_root,
                success_expected=False,
            ),
        ],
        cwd=tmp_path,
        env={
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "LANG": "C",
            "LC_ALL": "C",
        },
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert "SDK_RUNTIME_PATH_UNSAFE" in result.stdout


@pytest.mark.parametrize("redigest_record", (False, True))
def test_reviewed_sdk_authenticates_complete_tree_before_import(
    tmp_path: Path, redigest_record: bool
) -> None:
    runtime_site = tmp_path / "reviewed-runtime/lib/python3.11/site-packages"
    _materialize_locked_sdk_runtime(runtime_site)
    marker = tmp_path / "tampered-session-executed"
    session_path = runtime_site / "boto3/session.py"
    session_path.unlink()
    malicious = (
        "from pathlib import Path\n"
        f"Path({str(marker)!r}).write_text('bad')\n"
        "class Session: pass\n"
    ).encode()
    session_path.write_bytes(malicious)
    session_path.chmod(0o600)
    expected_error = "SDK_DISTRIBUTION_FILE_MISMATCH"
    if redigest_record:
        record_path = runtime_site / "boto3-1.42.57.dist-info/RECORD"
        rows = list(csv.reader(record_path.read_text(encoding="utf-8").splitlines()))
        for row in rows:
            if row[0] == "boto3/session.py":
                row[1] = "sha256=" + base64.urlsafe_b64encode(
                    hashlib.sha256(malicious).digest()
                ).decode("ascii").rstrip("=")
                row[2] = str(len(malicious))
                break
        record_path.unlink()
        with record_path.open("w", encoding="utf-8", newline="") as stream:
            writer = csv.writer(stream, lineterminator="\n")
            writer.writerows(rows)
        record_path.chmod(0o600)
        expected_error = "SDK_DISTRIBUTION_RECORD_MISMATCH"
    source_root = tmp_path / "source"
    source_root.mkdir()
    result = subprocess.run(
        [
            sys.executable,
            "-I",
            "-S",
            "-c",
            _isolated_sdk_probe_code(
                runtime_site=runtime_site,
                source_root=source_root,
                success_expected=False,
            ),
        ],
        cwd=tmp_path,
        env={"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "LANG": "C", "LC_ALL": "C"},
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert expected_error in result.stdout
    assert not marker.exists()


def test_reviewed_sdk_rejects_repository_local_virtualenv_before_import(
    tmp_path: Path,
) -> None:
    source_root = tmp_path / "source"
    runtime_site = source_root / ".venv/lib/python3.11/site-packages"
    _materialize_locked_sdk_runtime(runtime_site)
    result = subprocess.run(
        [
            sys.executable,
            "-I",
            "-S",
            "-c",
            _isolated_sdk_probe_code(
                runtime_site=runtime_site,
                source_root=source_root,
                success_expected=False,
            ),
        ],
        cwd=REPO_ROOT,
        env={"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "LANG": "C", "LC_ALL": "C"},
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert "SDK_RUNTIME_INSIDE_SOURCE_ROOT" in result.stdout


def test_reviewed_sdk_import_rejects_preloaded_module(tmp_path: Path) -> None:
    runtime_site = tmp_path / "reviewed-runtime/lib/python3.11/site-packages"
    _materialize_locked_sdk_runtime(runtime_site)
    code = "\n".join(
        (
            "from importlib.machinery import ModuleSpec",
            "from pathlib import Path",
            "from types import ModuleType",
            "import sys",
            "isolated = tuple(sys.path)",
            f"runtime_root = Path({str(runtime_site.parent)!r})",
            f"sys.path.insert(0, {str(REPO_ROOT)!r})",
            "from tooling.platform_authority_bootstrap_artifact_package import BootstrapArtifactPackageError, import_reviewed_aws_sdk",
            "fake = ModuleType('boto3')",
            "fake.__file__ = '/tmp/untrusted-boto3.py'",
            "fake.__spec__ = ModuleSpec('boto3', loader=None, origin=fake.__file__)",
            "sys.modules['boto3'] = fake",
            "try:",
            f"    import_reviewed_aws_sdk(source_root=Path({str(REPO_ROOT)!r}), isolated_import_paths=isolated, sdk_runtime_root=runtime_root)",
            "except BootstrapArtifactPackageError as exc:",
            "    assert str(exc) == 'SDK_MODULE_PRELOADED_FORBIDDEN'",
            "else:",
            "    raise AssertionError('preloaded SDK accepted')",
        )
    )
    result = subprocess.run(
        [sys.executable, "-I", "-S", "-c", code],
        cwd=REPO_ROOT,
        env={"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "LANG": "C", "LC_ALL": "C"},
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr


def test_plan_authenticates_sdk_authority_before_cloudformation_client(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import importlib.util

    script_path = REPO_ROOT / "scripts/deployment/platform-authority-bootstrap.py"
    spec = importlib.util.spec_from_file_location(
        "gug274_bootstrap_sdk_order", script_path
    )
    assert spec is not None and spec.loader is not None
    cli = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(cli)

    def unavailable_authority(_: BootstrapBinding) -> None:
        raise BootstrapAuthorizationError("artifact authority provider is unavailable")

    class ForbiddenAwsCli:
        def __init__(self, **_: Any) -> None:
            raise AssertionError("CloudFormation client constructed before SDK authentication")

    monkeypatch.setattr(cli, "_artifact_authority_client", unavailable_authority)
    monkeypatch.setattr(cli, "AwsCli", ForbiddenAwsCli)
    monkeypatch.setattr(cli, "_require_sso_environment", lambda _: None)
    args = argparse.Namespace(
        allow_change_set_write=True,
        plan_out=tmp_path / "plan.json",
        authority_account_id=AUTHORITY_ACCOUNT_ID,
        region=REGION,
        destination_account_id=("444455556666",),
        initiator_id="operator-1001",
        change_set_name=CHANGE_SET_NAME,
    )
    with pytest.raises(
        BootstrapAuthorizationError, match="artifact authority provider is unavailable"
    ):
        cli._cmd_plan(args)


def test_reviewed_non_root_executable_rejects_group_writable_ancestor(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    executable_parent = tmp_path / "reviewed-bin"
    executable_parent.mkdir(mode=0o700)
    executable = executable_parent / "gh"
    executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    executable.chmod(0o700)
    digest = hashlib.sha256(executable.read_bytes()).hexdigest()
    monkeypatch.setitem(
        artifact_package_module.TRUSTED_EXECUTABLE_CANDIDATES,
        "gh",
        (executable,),
    )
    monkeypatch.setitem(
        artifact_package_module.REVIEWED_NON_ROOT_EXECUTABLE_SHA256,
        "gh",
        frozenset({digest}),
    )
    executable_parent.chmod(0o770)

    with pytest.raises(
        BootstrapArtifactPackageError,
        match="TRUSTED_GH_EXECUTABLE_UNAVAILABLE",
    ):
        resolve_trusted_executable(name="gh", source_root=REPO_ROOT)


def test_public_package_builder_rejects_caller_selected_sdk_versions_before_git(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def forbidden_git(*_: object, **__: object) -> None:
        raise AssertionError("Git must not run for an unreviewed SDK version")

    monkeypatch.setattr(artifact_package_module.subprocess, "run", forbidden_git)
    with pytest.raises(
        BootstrapArtifactPackageError, match="SDK_RUNTIME_VERSION_UNREVIEWED"
    ):
        build_bootstrap_artifact_package(
            source_root=REPO_ROOT,
            source_commit="a" * 40,
            expected_boto3_version="1.42.58",
            expected_botocore_version=EXPECTED_BOTOCORE_VERSION,
        )


def test_package_provenance_ignores_hostile_path_git_and_rejects_untracked_shadow(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source_root = tmp_path / "source"
    for relative_path in (*SOURCE_PATHS, *PROVENANCE_PATHS):
        target = source_root / relative_path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes((REPO_ROOT / relative_path).read_bytes())
    trusted_git = resolve_trusted_executable(name="git", source_root=source_root)
    subprocess.run([str(trusted_git), "init", "-q"], cwd=source_root, check=True)
    subprocess.run([str(trusted_git), "add", "--", "."], cwd=source_root, check=True)
    subprocess.run(
        [
            str(trusted_git),
            "-c",
            "user.name=Synthetic Test",
            "-c",
            "user.email=synthetic@example.invalid",
            "commit",
            "-qm",
            "synthetic source",
        ],
        cwd=source_root,
        check=True,
    )
    source_commit = subprocess.run(
        [str(trusted_git), "rev-parse", "HEAD"],
        cwd=source_root,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    hostile_bin = tmp_path / "hostile-bin"
    hostile_bin.mkdir()
    marker = tmp_path / "hostile-git-executed"
    fake_git = hostile_bin / "git"
    fake_git.write_text(
        f"#!/bin/sh\nprintf bad > {str(marker)!r}\nexit 99\n",
        encoding="utf-8",
    )
    fake_git.chmod(0o700)
    monkeypatch.setenv("PATH", str(hostile_bin))
    built = build_bootstrap_artifact_package(
        source_root=source_root,
        source_commit=source_commit,
        expected_boto3_version=EXPECTED_BOTO3_VERSION,
        expected_botocore_version=EXPECTED_BOTOCORE_VERSION,
    )
    assert built.manifest["source_commit"] == source_commit
    assert not marker.exists()

    (source_root / "boto3.py").write_text("raise RuntimeError('shadow')\n")
    with pytest.raises(BootstrapArtifactPackageError, match="SOURCE_TREE_DIRTY"):
        build_bootstrap_artifact_package(
            source_root=source_root,
            source_commit=source_commit,
            expected_boto3_version=EXPECTED_BOTO3_VERSION,
            expected_botocore_version=EXPECTED_BOTOCORE_VERSION,
        )


def test_source_review_ignores_hostile_path_gh(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    hostile_bin = tmp_path / "hostile-bin"
    hostile_bin.mkdir()
    marker = tmp_path / "hostile-gh-executed"
    fake_gh = hostile_bin / "gh"
    fake_gh.write_text(
        f"#!/bin/sh\nprintf bad > {str(marker)!r}\nexit 99\n",
        encoding="utf-8",
    )
    fake_gh.chmod(0o700)
    monkeypatch.setenv("PATH", str(hostile_bin))
    reviewed_bin = tmp_path / "reviewed-bin"
    reviewed_bin.mkdir(mode=0o700)
    reviewed_gh = reviewed_bin / "gh"
    reviewed_gh.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    reviewed_gh.chmod(0o700)
    reviewed_digest = hashlib.sha256(reviewed_gh.read_bytes()).hexdigest()
    monkeypatch.setitem(
        artifact_package_module.TRUSTED_EXECUTABLE_CANDIDATES,
        "gh",
        (reviewed_gh,),
    )
    monkeypatch.setitem(
        artifact_package_module.REVIEWED_NON_ROOT_EXECUTABLE_SHA256,
        "gh",
        frozenset({reviewed_digest}),
    )
    captured: dict[str, Any] = {}

    def fake_verify(**kwargs: Any) -> Mapping[str, Any]:
        captured.update(kwargs)
        return {"evidence_status": "synthetic"}

    monkeypatch.setattr(signed_artifact_module, "verify_github_merged_release", fake_verify)
    result = verify_reviewed_source_release(
        source_root=REPO_ROOT, source_commit="a" * 40
    )
    assert result == {"evidence_status": "synthetic"}
    assert Path(captured["gh_executable"]).resolve() != fake_gh.resolve()
    assert str(hostile_bin) not in captured["command_environment"]["PATH"].split(os.pathsep)
    assert not marker.exists()


def _unsigned_authority_package(
    *, boto3_version: str = "1.42.57"
) -> Any:
    committed_sources = {
        path: (REPO_ROOT / path).read_bytes() for path in SOURCE_PATHS
    }
    return _build_bootstrap_artifact_package(
        source_root=REPO_ROOT,
        source_commit="a" * 40,
        expected_boto3_version=boto3_version,
        expected_botocore_version="1.42.97",
        committed_sources=committed_sources,
    )


def _synthetic_signed_archive(unsigned_archive: bytes) -> bytes:
    return unsigned_archive + b"SYNTHETIC-AWS-SIGNER-METADATA"


def _signing_job(
    *,
    owner: str = SIGNING_AUTHORITY_ACCOUNT_ID,
    profile_name: str = "scanalyze_gug274_bootstrap_artifact_authority",
    profile_version: str = "ABCDEFGHIJ",
    expires_at: str = "2031-01-01T00:00:00Z",
) -> dict[str, Any]:
    job_id = "11111111-2222-4333-8444-555555555555"
    return {
        "status": "Succeeded",
        "jobOwner": owner,
        "jobInvoker": owner,
        "platformId": SIGNING_PLATFORM,
        "profileName": profile_name,
        "profileVersion": profile_version,
        "jobId": job_id,
        "signatureExpiresAt": expires_at,
        "source": {
            "s3": {
                "bucketName": "scanalyze-gug274-artifacts-7644",
                "key": (
                    "scanalyze/platform-authority/gug-274/unsigned/"
                    + ("a" * 40)
                    + "/scanalyze-gug274-bootstrap-artifact-authority.zip"
                ),
                "version": "UnsignedVersion1",
            }
        },
        "signedObject": {
            "s3": {
                "bucketName": "scanalyze-gug274-artifacts-7644",
                "key": (
                    "scanalyze/platform-authority/gug-274/signed/"
                    f"{job_id}.zip"
                ),
            }
        },
    }


def _signed_object_head(signed_archive: bytes) -> dict[str, Any]:
    job_id = "11111111-2222-4333-8444-555555555555"
    return {
        "bucket": "scanalyze-gug274-artifacts-7644",
        "key": f"scanalyze/platform-authority/gug-274/signed/{job_id}.zip",
        "version_id": "SignedVersion1",
        "content_length": len(signed_archive),
        "checksum_sha256": base64.b64encode(
            hashlib.sha256(signed_archive).digest()
        ).decode("ascii"),
    }


def _signing_verifier_identity() -> dict[str, str]:
    return {
        "Account": SIGNING_AUTHORITY_ACCOUNT_ID,
        "Arn": (
            f"arn:aws:sts::{SIGNING_AUTHORITY_ACCOUNT_ID}:assumed-role/"
            "AWSReservedSSO_AWSReadOnlyAccess_0123456789abcdef/"
            "synthetic@example.invalid"
        ),
    }


def _configured_signing_trust_root(
    *, profile_version_id: str = "ABCDEFGHIJ"
) -> dict[str, Any]:
    return {
        "artifact_type": (
            "scanalyze.platform_authority."
            "bootstrap_artifact_signing_trust_root.v1"
        ),
        "schema_version": 1,
        "work_package": "GUG-274",
        "trust_root_generation": 1,
        "partition": "aws",
        "authority_account_id": SIGNING_AUTHORITY_ACCOUNT_ID,
        "region": "us-east-1",
        "profile_name": "scanalyze_gug274_bootstrap_artifact_authority",
        "profile_version_id": profile_version_id,
        "profile_version_arn": (
            f"arn:aws:signer:us-east-1:{SIGNING_AUTHORITY_ACCOUNT_ID}:"
            "/signing-profiles/"
            "scanalyze_gug274_bootstrap_artifact_authority/"
            f"{profile_version_id}"
        ),
        "signing_platform": SIGNING_PLATFORM,
        "code_signing_policy": "Enforce",
        "configuration_status": "CONFIGURED_REVIEWED",
        "activation_authorized": False,
        "production_status": "NO-GO",
    }


def _signed_source_review() -> dict[str, Any]:
    return {
        "repository": "cesar-guzman/scanalyze-deployment-platform",
        "branch": "main",
        "source_commit": "a" * 40,
        "source_tree": "b" * 40,
        "pull_request_number": 274,
        "pull_request_head_commit": "c" * 40,
        "pull_request_head_tree": "b" * 40,
        "merged_at": "2026-08-02T00:00:00Z",
        "required_checks": [
            {
                "name": name,
                "conclusion": "success",
                "app_id": GITHUB_ACTIONS_APP_ID,
                "app_slug": "github-actions",
            }
            for name in REQUIRED_GITHUB_CHECKS
        ],
        "branch_protection_strict": True,
        "evidence_status": "MERGED_MAIN_REQUIRED_CHECKS_VERIFIED",
    }


def _signed_artifact_receipt() -> dict[str, Any]:
    unsigned = _unsigned_authority_package()
    signed = _synthetic_signed_archive(unsigned.archive)
    return dict(
        _build_signed_artifact_receipt(
            unsigned_manifest=unsigned.manifest,
            downloaded_unsigned_archive=unsigned.archive,
            downloaded_signed_archive=signed,
            signing_job=_signing_job(),
            signed_object_head=_signed_object_head(signed),
            signing_trust_root=_configured_signing_trust_root(),
            source_review=_signed_source_review(),
            verifier_identity=_signing_verifier_identity(),
            verifier_profile=EXPECTED_VERIFIER_PROFILE,
            now=SIGNING_NOW,
        )
    )


def test_repository_signing_trust_root_is_deliberately_not_configured() -> None:
    contract = load_signing_trust_root_contract(
        source_root=REPO_ROOT, require_configured=False
    )
    validate_signing_trust_root_contract(contract, require_configured=False)
    assert contract["configuration_status"] == "NOT_CONFIGURED"
    assert signing_trust_root_contract_digest(contract).startswith("sha256:")
    with pytest.raises(
        BootstrapSignedArtifactError,
        match="SIGNING_TRUST_ROOT_NOT_CONFIGURED",
    ):
        load_signing_trust_root_contract(
            source_root=REPO_ROOT, require_configured=True
        )


def test_unconfigured_signer_contract_stops_before_any_provider_read() -> None:
    class NoProviderRead:
        def __getattr__(self, _name: str) -> Any:
            raise AssertionError("provider read must not occur")

    with pytest.raises(
        BootstrapSignedArtifactError,
        match="SIGNING_TRUST_ROOT_NOT_CONFIGURED",
    ):
        build_signed_artifact_receipt_from_aws(
            source_root=REPO_ROOT,
            source_commit="a" * 40,
            expected_boto3_version="1.42.57",
            expected_botocore_version="1.42.97",
            profile_name=EXPECTED_VERIFIER_PROFILE,
            job_id="11111111-2222-4333-8444-555555555555",
            sts_client=NoProviderRead(),
            signer_client=NoProviderRead(),
            s3_client=NoProviderRead(),
            now=SIGNING_NOW,
        )


def test_signed_artifact_receipt_binds_only_signer_destination_bytes_to_cfn() -> None:
    unsigned = _unsigned_authority_package()
    signed = _synthetic_signed_archive(unsigned.archive)
    receipt = _signed_artifact_receipt()
    validate_signed_artifact_receipt(receipt)
    parameters = {
        item["ParameterKey"]: item["ParameterValue"]
        for item in receipt["cloudformation_parameters"]
    }
    expected_signed_code_sha = base64.b64encode(
        hashlib.sha256(signed).digest()
    ).decode("ascii")
    assert parameters["SignedAuthorityArtifactCodeSha256"] == expected_signed_code_sha
    assert (
        parameters["SignedAuthorityArtifactCodeSha256"]
        != unsigned.manifest["unsigned_archive_code_sha256"]
    )
    assert parameters["AuthoritySigningReceiptDigest"] == receipt["receipt_digest"]
    assert parameters["AuthoritySigningTrustRootContractDigest"] == receipt[
        "trust_root"
    ]["contract_digest"]
    assert parameters["AuthoritySigningProfileVersionId"] == "ABCDEFGHIJ"
    assert receipt["evidence_status"] == SIGNED_ARTIFACT_EVIDENCE_STATUS
    assert receipt["production_status"] == "NO-GO"


def test_signed_receipt_expires_and_must_be_refreshed_from_providers() -> None:
    receipt = _signed_artifact_receipt()
    with pytest.raises(BootstrapSignedArtifactError, match="SIGNATURE_EXPIRED"):
        validate_signed_artifact_receipt(
            receipt, now=SIGNING_NOW + timedelta(minutes=16)
        )


def test_self_redigested_receipt_fails_fresh_provider_comparison(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fresh = _signed_artifact_receipt()
    forged = copy.deepcopy(fresh)
    forged["signed_artifact"]["version"] = "AttackerSelectedVersion"
    payload = signed_artifact_module._receipt_payload(forged)
    forged["receipt_digest"] = signed_artifact_module._receipt_digest(payload)
    forged["cloudformation_parameters"] = (
        signed_artifact_module._cloudformation_parameters(
            payload=payload, receipt_digest=forged["receipt_digest"]
        )
    )
    validate_signed_artifact_receipt(forged, now=SIGNING_NOW)
    monkeypatch.setattr(
        signed_artifact_module,
        "build_signed_artifact_receipt_from_aws",
        lambda **_kwargs: fresh,
    )
    with pytest.raises(
        BootstrapSignedArtifactError,
        match="SIGNED_RECEIPT_PROVIDER_READBACK_DRIFT",
    ):
        refresh_signed_artifact_receipt_read_only(
            source_root=REPO_ROOT,
            local_receipt=forged,
            sts_client=object(),
            signer_client=object(),
            s3_client=object(),
            now=SIGNING_NOW,
        )


def test_receipt_refresh_rejects_local_sdk_version_authority_before_provider_reads() -> None:
    forged = copy.deepcopy(_signed_artifact_receipt())
    forged["expected_sdk_versions"]["boto3"] = "1.42.58"
    payload = signed_artifact_module._receipt_payload(forged)
    forged["receipt_digest"] = signed_artifact_module._receipt_digest(payload)
    forged["cloudformation_parameters"] = (
        signed_artifact_module._cloudformation_parameters(
            payload=payload, receipt_digest=forged["receipt_digest"]
        )
    )
    validate_signed_artifact_receipt(forged, now=SIGNING_NOW)

    class NoProviderReads:
        def __getattr__(self, name: str) -> Any:
            raise AssertionError(f"provider read attempted: {name}")

    provider = NoProviderReads()
    with pytest.raises(
        BootstrapSignedArtifactError, match="SDK_RUNTIME_VERSION_UNREVIEWED"
    ):
        refresh_signed_artifact_receipt_read_only(
            source_root=REPO_ROOT,
            local_receipt=forged,
            sts_client=provider,
            signer_client=provider,
            s3_client=provider,
            now=SIGNING_NOW,
        )


def test_unsigned_code_sha_cannot_be_substituted_into_signed_cfn_projection() -> None:
    unsigned = _unsigned_authority_package()
    receipt = _signed_artifact_receipt()
    code_parameter = next(
        item
        for item in receipt["cloudformation_parameters"]
        if item["ParameterKey"] == "SignedAuthorityArtifactCodeSha256"
    )
    code_parameter["ParameterValue"] = unsigned.manifest[
        "unsigned_archive_code_sha256"
    ]
    with pytest.raises(
        BootstrapSignedArtifactError, match="CFN_PARAMETER_BINDING_DRIFT"
    ):
        validate_signed_artifact_receipt(receipt)


@pytest.mark.parametrize(
    ("job", "error"),
    [
        (
            _signing_job(owner="999900001111"),
            "SIGNING_JOB_NOT_EXACT",
        ),
        (
            _signing_job(profile_name="caller_selected_profile"),
            "SIGNING_JOB_NOT_EXACT",
        ),
        (
            _signing_job(profile_version="KLMNOPQRST"),
            "SIGNING_JOB_NOT_EXACT",
        ),
        (
            _signing_job(expires_at="2020-01-01T00:00:00Z"),
            "SIGNATURE_EXPIRED",
        ),
    ],
)
def test_signed_artifact_receipt_rejects_foreign_or_expired_signer_authority(
    job: Mapping[str, Any], error: str
) -> None:
    unsigned = _unsigned_authority_package()
    signed = _synthetic_signed_archive(unsigned.archive)
    with pytest.raises(BootstrapSignedArtifactError, match=error):
        _build_signed_artifact_receipt(
            unsigned_manifest=unsigned.manifest,
            downloaded_unsigned_archive=unsigned.archive,
            downloaded_signed_archive=signed,
            signing_job=job,
            signed_object_head=_signed_object_head(signed),
            signing_trust_root=_configured_signing_trust_root(),
            source_review=_signed_source_review(),
            verifier_identity=_signing_verifier_identity(),
            verifier_profile=EXPECTED_VERIFIER_PROFILE,
            now=SIGNING_NOW,
        )


def test_signed_artifact_receipt_rejects_source_entry_substitution() -> None:
    reviewed = _unsigned_authority_package()
    substituted = _unsigned_authority_package(boto3_version="1.42.58")
    signed = _synthetic_signed_archive(substituted.archive)
    with pytest.raises(
        BootstrapSignedArtifactError, match="SIGNED_ARCHIVE_SOURCE_ENTRY_DRIFT"
    ):
        _build_signed_artifact_receipt(
            unsigned_manifest=reviewed.manifest,
            downloaded_unsigned_archive=reviewed.archive,
            downloaded_signed_archive=signed,
            signing_job=_signing_job(),
            signed_object_head=_signed_object_head(signed),
            signing_trust_root=_configured_signing_trust_root(),
            source_review=_signed_source_review(),
            verifier_identity=_signing_verifier_identity(),
            verifier_profile=EXPECTED_VERIFIER_PROFILE,
            now=SIGNING_NOW,
        )


def test_signed_artifact_receipt_is_write_once_private_and_outside_repo(
    tmp_path: Path,
) -> None:
    receipt = _signed_artifact_receipt()
    output = tmp_path / "receipt.json"
    write_signed_artifact_receipt(
        receipt=receipt, output_path=output, source_root=REPO_ROOT
    )
    assert output.stat().st_mode & 0o777 == 0o600
    with pytest.raises(
        BootstrapSignedArtifactError, match="SIGNED_RECEIPT_OUTPUT_EXISTS"
    ):
        write_signed_artifact_receipt(
            receipt=receipt, output_path=output, source_root=REPO_ROOT
        )


@pytest.mark.parametrize("provenance_path", PROVENANCE_PATHS)
def test_public_package_builder_rejects_assume_unchanged_provenance_drift(
    tmp_path: Path, provenance_path: Path
) -> None:
    source_root = tmp_path / "source"
    for relative_path in (*SOURCE_PATHS, *PROVENANCE_PATHS):
        target = source_root / relative_path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes((REPO_ROOT / relative_path).read_bytes())
    subprocess.run(["git", "init", "-q"], cwd=source_root, check=True)
    subprocess.run(["git", "add", "--", "."], cwd=source_root, check=True)
    subprocess.run(
        [
            "git",
            "-c",
            "user.name=Synthetic Test",
            "-c",
            "user.email=synthetic@example.invalid",
            "commit",
            "-qm",
            "synthetic provenance",
        ],
        cwd=source_root,
        check=True,
    )
    source_commit = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=source_root,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    subprocess.run(
        ["git", "update-index", "--assume-unchanged", provenance_path.as_posix()],
        cwd=source_root,
        check=True,
    )
    with (source_root / provenance_path).open("ab") as stream:
        stream.write(b"\n# hidden provenance drift\n")
    status = subprocess.run(
        ["git", "status", "--porcelain=v1", "--untracked-files=no"],
        cwd=source_root,
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    assert status == ""

    with pytest.raises(
        BootstrapArtifactPackageError, match="PACKAGE_SOURCE_COMMIT_DRIFT"
    ):
        build_bootstrap_artifact_package(
            source_root=source_root,
            source_commit=source_commit,
            expected_boto3_version="1.42.57",
            expected_botocore_version="1.42.97",
        )


def test_public_package_builder_rejects_replacement_ref_substitution(
    tmp_path: Path,
) -> None:
    source_root = tmp_path / "source"
    for relative_path in (*SOURCE_PATHS, *PROVENANCE_PATHS):
        target = source_root / relative_path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes((REPO_ROOT / relative_path).read_bytes())
    subprocess.run(["git", "init", "-q"], cwd=source_root, check=True)
    subprocess.run(["git", "add", "--", "."], cwd=source_root, check=True)
    commit_command = [
        "git",
        "-c",
        "user.name=Synthetic Test",
        "-c",
        "user.email=synthetic@example.invalid",
        "commit",
        "-qm",
    ]
    subprocess.run(
        [*commit_command, "reviewed source"], cwd=source_root, check=True
    )
    reviewed_commit = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=source_root,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()

    operational_script = PROVENANCE_PATHS[1]
    malicious_bytes = (source_root / operational_script).read_bytes() + (
        b"\n# replacement-ref payload\n"
    )
    (source_root / operational_script).write_bytes(malicious_bytes)
    subprocess.run(["git", "add", "--", operational_script.as_posix()], cwd=source_root, check=True)
    subprocess.run(
        [*commit_command, "substituted source"], cwd=source_root, check=True
    )
    substituted_commit = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=source_root,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    subprocess.run(
        ["git", "checkout", "-q", reviewed_commit], cwd=source_root, check=True
    )
    subprocess.run(
        ["git", "replace", reviewed_commit, substituted_commit],
        cwd=source_root,
        check=True,
    )
    subprocess.run(
        ["git", "read-tree", "--reset", "-u", substituted_commit],
        cwd=source_root,
        check=True,
    )
    status = subprocess.run(
        ["git", "status", "--porcelain=v1", "--untracked-files=no"],
        cwd=source_root,
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    assert status == ""
    assert subprocess.run(
        ["git", "show", f"{reviewed_commit}:{operational_script.as_posix()}"],
        cwd=source_root,
        check=True,
        capture_output=True,
    ).stdout == malicious_bytes

    with pytest.raises(
        BootstrapArtifactPackageError, match="SOURCE_REPLACEMENT_FORBIDDEN"
    ):
        build_bootstrap_artifact_package(
            source_root=source_root,
            source_commit=reviewed_commit,
            expected_boto3_version="1.42.57",
            expected_botocore_version="1.42.97",
        )


def test_provider_endpoint_and_config_overrides_fail_closed() -> None:
    for environment in (
        {"AWS_ENDPOINT_URL": "http://127.0.0.1:9999"},
        {"AWS_ENDPOINT_URL_LAMBDA": "http://127.0.0.1:9999"},
        {"AWS_CONFIG_FILE": "/tmp/attacker-config"},
        {"AWS_CA_BUNDLE": "/tmp/attacker-ca"},
        {"AWS_DATA_PATH": "/tmp/attacker-models"},
    ):
        with pytest.raises(BootstrapArtifactAuthorityError, match="override"):
            authority_module._reject_provider_overrides(environment)


def _runtime_environment() -> dict[str, str]:
    identity = _identity_binding()
    return {
        "GUG274_AUTHORITY_ACCOUNT_ID": AUTHORITY_ACCOUNT_ID,
        "GUG274_AUTHORITY_REGION": REGION,
        "GUG274_DESTINATION_ACCOUNT_IDS": "444455556666,777788889999",
        "GUG274_CHANGE_SET_NAME": CHANGE_SET_NAME,
        "GUG274_IDENTITY_CENTER_APPLICATION_ARN": (
            identity.identity_center_application_arn
        ),
        "GUG274_IDENTITY_CENTER_INSTANCE_ARN": identity.identity_center_instance_arn,
        "GUG274_IDENTITY_STORE_ARN": identity.identity_store_arn,
        "GUG274_IDENTITY_REDIRECT_URI": identity.redirect_uri,
        "GUG274_PLAN_IDENTITY_STORE_USER_ID": identity.plan_user_id,
        "GUG274_SECOND_PARTY_IDENTITY_STORE_USER_ID": identity.second_party_user_id,
        "GUG274_SOURCE_COMMIT": "a" * 40,
        "GUG274_EXPECTED_BOTO3_VERSION": "1.42.57",
        "GUG274_EXPECTED_BOTOCORE_VERSION": "1.42.97",
    }


def test_runtime_configuration_and_package_lock_are_exact(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    config = BootstrapArtifactAuthorityRuntimeConfig.from_environment(
        _runtime_environment()
    )
    assert config.source_commit == "a" * 40
    assert config.expected_boto3_version == "1.42.57"
    assert config.expected_botocore_version == "1.42.97"

    package_root = tmp_path / "package"
    tooling_root = package_root / "tooling"
    tooling_root.mkdir(parents=True)
    monkeypatch.setattr(
        authority_module, "__file__", str(tooling_root / "authority.py")
    )
    lock_path = package_root / "gug274_runtime_lock.json"
    exact_lock = {
        "record_type": (
            "scanalyze.platform_authority."
            "bootstrap_artifact_authority_runtime_lock.v1"
        ),
        "schema_version": 1,
        "work_package": "GUG-274",
        "trust_root_generation": 1,
        "source_commit": "a" * 40,
        "expected_boto3_version": "1.42.57",
        "expected_botocore_version": "1.42.97",
    }
    lock_path.write_text(json.dumps(exact_lock), encoding="utf-8")
    authority_module._validate_runtime_lock(config)

    lock_path.write_text(
        json.dumps({**exact_lock, "source_commit": "b" * 40}), encoding="utf-8"
    )
    with pytest.raises(BootstrapArtifactAuthorityError, match="lock is invalid"):
        authority_module._validate_runtime_lock(config)
    lock_path.unlink()
    with pytest.raises(BootstrapArtifactAuthorityError, match="lock is unavailable"):
        authority_module._validate_runtime_lock(config)


def test_cli_identity_grant_accepts_pipe_only_and_never_regular_file(tmp_path: Path) -> None:
    import importlib.util

    script_path = REPO_ROOT / "scripts/deployment/platform-authority-bootstrap.py"
    spec = importlib.util.spec_from_file_location("gug274_bootstrap_cli", script_path)
    assert spec is not None and spec.loader is not None
    cli = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(cli)
    payload = json.dumps(
        {
            "schema_version": "1",
            "record_type": "platform_authority_bootstrap_identity_grant",
            "authorization_code": "one-shot-code",
            "code_verifier": "v" * 43,
        }
    )
    read_fd, write_fd = os.pipe()
    try:
        os.write(write_fd, payload.encode())
        os.close(write_fd)
        write_fd = -1
        assert json.loads(cli._read_identity_grant_json(read_fd))["authorization_code"] == "one-shot-code"
    finally:
        if write_fd >= 0:
            os.close(write_fd)
        try:
            os.close(read_fd)
        except OSError:
            pass

    regular = tmp_path / "grant.json"
    regular.write_text(payload)
    descriptor = os.open(regular, os.O_RDONLY)
    try:
        with pytest.raises(BootstrapAuthorizationError, match="pipe or socket"):
            cli._read_identity_grant_json(descriptor)
    finally:
        os.close(descriptor)


def test_normal_cli_ignores_hostile_path_aws(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import importlib.util

    script_path = REPO_ROOT / "scripts/deployment/platform-authority-bootstrap.py"
    spec = importlib.util.spec_from_file_location("gug274_bootstrap_path_test", script_path)
    assert spec is not None and spec.loader is not None
    cli = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(cli)
    hostile_bin = tmp_path / "hostile-bin"
    hostile_bin.mkdir()
    marker = tmp_path / "hostile-aws-executed"
    fake_aws = hostile_bin / "aws"
    fake_aws.write_text(
        f"#!/bin/sh\nprintf bad > {str(marker)!r}\nexit 99\n",
        encoding="utf-8",
    )
    fake_aws.chmod(0o700)
    monkeypatch.setenv("PATH", str(hostile_bin))
    captured: list[str] = []

    def fake_run(command: list[str], **_: Any) -> subprocess.CompletedProcess[str]:
        captured.extend(command)
        return subprocess.CompletedProcess(command, 0, stdout="{}", stderr="")

    monkeypatch.setattr(cli.subprocess, "run", fake_run)
    cli.AwsCli(region=REGION).run("sts", "get-caller-identity")
    assert Path(captured[0]).is_absolute()
    assert Path(captured[0]).resolve() != fake_aws.resolve()
    assert not marker.exists()


def test_active_v1_artifacts_and_caller_selected_coordinates_have_no_fallback() -> None:
    with pytest.raises(BootstrapArtifactAuthorityError, match="Plan v2"):
        prevalidate_bootstrap_apply_v2(
            plan={"schema_version": "1"},
            approval={"schema_version": "1"},
            binding=_binding(),
            current_template_sha256="sha256:" + "a" * 64,
            now=NOW,
        )
    for function in (
        PLAN_AUTHORITY_FUNCTION,
        APPROVAL_AUTHORITY_FUNCTION,
        APPLY_EXECUTOR_FUNCTION,
    ):
        assert broker_function_arn(_binding(), function).endswith(":1")
    with pytest.raises(BootstrapArtifactAuthorityError, match="canonical"):
        broker_function_arn(_binding(), "caller-selected-latest")


def test_synthetic_fixtures_validate_under_runtime_contract() -> None:
    fixture_root = REPO_ROOT / "fixtures/valid"
    plan = json.loads(
        (fixture_root / "platform-authority-bootstrap-plan-v2-synthetic.json").read_text()
    )
    approval = json.loads(
        (fixture_root / "platform-authority-bootstrap-approval-v2-synthetic.json").read_text()
    )
    ledger = json.loads(
        (fixture_root / "platform-authority-bootstrap-artifact-authority-v1-synthetic.json").read_text()
    )
    validate_bootstrap_plan_v2(plan=plan, binding=_binding())
    validate_bootstrap_approval_v2(plan=plan, approval=approval, binding=_binding())
    validate_authority_ledger(record=ledger, binding=_binding())
