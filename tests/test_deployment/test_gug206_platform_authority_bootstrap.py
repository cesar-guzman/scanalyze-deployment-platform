"""GUG-206 dedicated platform-authority bootstrap security contracts."""
from __future__ import annotations

import argparse
import copy
import hashlib
import importlib.util
import json
import os
import stat
import subprocess
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

import tooling.platform_authority_bootstrap as bootstrap_contract
from tooling.platform_authority_bootstrap import (
    BootstrapAuthorizationError,
    BootstrapBinding,
    authorize_bootstrap_apply,
    build_bootstrap_approval,
    build_bootstrap_plan,
    build_bootstrap_verification,
    render_backend_config,
    render_bootstrap_iam_policy,
)


REPO_ROOT = Path(__file__).resolve().parents[2]
TEMPLATE = REPO_ROOT / "bootstrap/cfn-platform-authority-state-backend.yaml"
PLAN_POLICY = REPO_ROOT / "policies/iam/platform-authority-bootstrap-plan-role.json"
APPLY_POLICY = REPO_ROOT / "policies/iam/platform-authority-bootstrap-apply-role.json"
SCHEMA_DIR = REPO_ROOT / "schemas"
SYNTHETIC_AUTHORITY = "111122223333"
SYNTHETIC_DESTINATIONS = ("444455556666", "777788889999")
SYNTHETIC_BUCKET = "scanalyze-platform-authority-111122223333-us-east-1-state"
SYNTHETIC_CHANGE_SET_NAME = "scanalyze-platform-authority-bootstrap-20300101000000"


def _canonical_digest(document: dict) -> str:
    payload = json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return "sha256:" + hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _redigest(document: dict, field: str) -> None:
    document[field] = _canonical_digest(
        {key: value for key, value in document.items() if key != field}
    )


def _binding(**overrides: object) -> BootstrapBinding:
    values: dict[str, object] = {
        "authority_account_id": SYNTHETIC_AUTHORITY,
        "region": "us-east-1",
        "stack_name": "scanalyze-platform-authority-state-backend",
        "state_bucket_name": SYNTHETIC_BUCKET,
        "state_key": "platform-authority/terraform.tfstate",
        "destination_account_ids": SYNTHETIC_DESTINATIONS,
    }
    values.update(overrides)
    return BootstrapBinding(**values)  # type: ignore[arg-type]


def _plan(now: datetime | None = None) -> dict:
    current = now or datetime(2030, 1, 1, tzinfo=UTC)
    return build_bootstrap_plan(
        binding=_binding(),
        caller_account_id=SYNTHETIC_AUTHORITY,
        caller_arn="arn:aws:sts::111122223333:assumed-role/SyntheticBootstrap/session",
        template_sha256="a" * 64,
        change_set_id=(
            "arn:aws:cloudformation:us-east-1:111122223333:changeSet/"
            f"{SYNTHETIC_CHANGE_SET_NAME}/00000000-0000-4000-8000-000000000000"
        ),
        change_set_type="CREATE",
        resource_changes=(
            {"action": "Add", "logical_resource_id": "StateKmsKey", "resource_type": "AWS::KMS::Key"},
            {"action": "Add", "logical_resource_id": "StateBucket", "resource_type": "AWS::S3::Bucket"},
            {"action": "Add", "logical_resource_id": "StateBucketPolicy", "resource_type": "AWS::S3::BucketPolicy"},
        ),
        account_public_access_block_before=None,
        created_at=current,
        expires_at=current + timedelta(hours=1),
        initiator_id="operator-1001",
    )


def _load_bootstrap_cli(module_name: str):
    spec = importlib.util.spec_from_file_location(
        module_name,
        REPO_ROOT / "scripts/deployment/platform-authority-bootstrap.py",
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _live_plan_and_approval(now: datetime | None = None) -> tuple[dict, dict]:
    current = now or datetime.now(tz=UTC).replace(microsecond=0)
    plan = build_bootstrap_plan(
        binding=_binding(),
        caller_account_id=SYNTHETIC_AUTHORITY,
        caller_arn=(
            "arn:aws:sts::111122223333:assumed-role/"
            "AWSReservedSSO_ScanalyzeAuthorityBootstrapPlan_"
            "0123456789abcdef/synthetic.initiator"
        ),
        template_sha256=hashlib.sha256(TEMPLATE.read_bytes()).hexdigest(),
        change_set_id=str(_plan()["change_set_id"]),
        change_set_type="CREATE",
        resource_changes=(
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
        ),
        account_public_access_block_before=None,
        created_at=current - timedelta(minutes=5),
        expires_at=current + timedelta(minutes=55),
        initiator_id="operator-1001",
    )
    approval = build_bootstrap_approval(
        plan=plan,
        initiator_id="operator-1001",
        approver_id="reviewer-2002",
        approver_arn=(
            "arn:aws:sts::111122223333:assumed-role/"
            "AWSReservedSSO_ScanalyzeAuthorityBootstrapApply_"
            "fedcba9876543210/synthetic.reviewer"
        ),
        approved_at=current - timedelta(minutes=1),
        expires_at=current + timedelta(minutes=30),
    )
    return plan, approval


def _live_change_set_response(plan: dict) -> dict:
    return {
        "ChangeSetId": plan["change_set_id"],
        "ChangeSetName": SYNTHETIC_CHANGE_SET_NAME,
        "StackName": "scanalyze-platform-authority-state-backend",
        "Status": "CREATE_COMPLETE",
        "ExecutionStatus": "AVAILABLE",
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
            for change in plan["planned_resource_changes"]
        ],
    }


def _run_apply_until_execute(
    *,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    module_name: str,
    ambiguous_execute: bool = False,
    expire_before_execute: bool = False,
    substitute_uuid_on_final_readback: bool = False,
    wrong_approved_principal: bool = False,
) -> tuple[object, list[tuple[str, str, tuple[str, ...]]], dict]:
    module = _load_bootstrap_cli(module_name)
    plan, approval = _live_plan_and_approval()
    plan_path = tmp_path / "plan.json"
    approval_path = tmp_path / "approval.json"
    plan_path.write_text(json.dumps(plan), encoding="utf-8")
    approval_path.write_text(json.dumps(approval), encoding="utf-8")
    calls: list[tuple[str, str, tuple[str, ...]]] = []
    describe_count = 0

    class StopAfterExecute(Exception):
        pass

    class FakeClient:
        region = "us-east-1"

        def run(self, service: str, operation: str, *args: str) -> dict:
            nonlocal describe_count
            calls.append((service, operation, args))
            if (service, operation) == ("sts", "get-caller-identity"):
                return {
                    "Account": SYNTHETIC_AUTHORITY,
                    "Arn": (
                        "arn:aws:sts::111122223333:assumed-role/"
                        "AWSReservedSSO_ScanalyzeAuthorityBootstrapApply_"
                        "fedcba9876543210/"
                        + (
                            "foreign.reviewer"
                            if wrong_approved_principal
                            else "synthetic.reviewer"
                        )
                    ),
                }
            if (service, operation) == ("cloudformation", "list-stack-resources"):
                return {"StackResourceSummaries": []}
            if (service, operation) == ("cloudformation", "describe-change-set"):
                describe_count += 1
                response = _live_change_set_response(plan)
                if substitute_uuid_on_final_readback and describe_count == 2:
                    response["ChangeSetId"] = str(response["ChangeSetId"]).replace(
                        "00000000-0000-4000-8000-000000000000",
                        "11111111-1111-4111-8111-111111111111",
                    )
                return response
            if (service, operation) == ("s3control", "put-public-access-block"):
                return {}
            if (service, operation) == ("cloudformation", "execute-change-set"):
                if ambiguous_execute:
                    raise module.AwsCliError("AWS CLI request failed")
                raise StopAfterExecute
            raise AssertionError(f"unexpected AWS call: {service} {operation} {args}")

        def run_allow_missing(
            self,
            service: str,
            operation: str,
            *args: str,
            missing_markers: tuple[str, ...],
        ) -> dict:
            del missing_markers
            calls.append((service, operation, args))
            if (service, operation) != ("cloudformation", "describe-stacks"):
                raise AssertionError(f"unexpected AWS call: {service} {operation} {args}")
            return {
                "Stacks": [
                    {
                        "StackName": "scanalyze-platform-authority-state-backend",
                        "StackId": (
                            "arn:aws:cloudformation:us-east-1:111122223333:stack/"
                            "scanalyze-platform-authority-state-backend/"
                            "00000000-0000-4000-8000-000000000000"
                        ),
                        "StackStatus": "REVIEW_IN_PROGRESS",
                        "NotificationARNs": [],
                    }
                ]
            }

    client = FakeClient()
    monkeypatch.setattr(module, "AwsCli", lambda *, region: client)
    if expire_before_execute:
        valid_now = datetime.fromisoformat(
            str(approval["approved_at"]).replace("Z", "+00:00")
        ) + timedelta(seconds=1)
        expired_now = datetime.fromisoformat(
            str(approval["expires_at"]).replace("Z", "+00:00")
        )
        authorization_times = iter((valid_now, valid_now, expired_now))
        monkeypatch.setattr(module, "_now", lambda: next(authorization_times))
    monkeypatch.setenv("AWS_PROFILE", "synthetic-sso-profile")
    monkeypatch.setenv("AWS_REGION", "us-east-1")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")
    for name in module.FORBIDDEN_CREDENTIAL_ENV:
        monkeypatch.delenv(name, raising=False)
    args = argparse.Namespace(
        authority_account_id=SYNTHETIC_AUTHORITY,
        region="us-east-1",
        destination_account_id=list(SYNTHETIC_DESTINATIONS),
        plan=plan_path,
        approval=approval_path,
        verification_out=tmp_path / "verification.json",
        backend_config_out=tmp_path / "backend.hcl",
        allow_bootstrap_apply=True,
    )
    if expire_before_execute:
        with pytest.raises(
            BootstrapAuthorizationError,
            match="bootstrap approval is expired or not yet valid",
        ):
            module._cmd_apply(args)
    elif wrong_approved_principal:
        with pytest.raises(
            BootstrapAuthorizationError,
            match="current AWS principal is not the approved executor",
        ):
            module._cmd_apply(args)
    elif substitute_uuid_on_final_readback:
        with pytest.raises(BootstrapAuthorizationError, match="identity differs"):
            module._cmd_apply(args)
    else:
        expected_error = module.AwsCliError if ambiguous_execute else StopAfterExecute
        with pytest.raises(expected_error):
            module._cmd_apply(args)
    return module, calls, plan


def test_binding_accepts_only_exact_dedicated_authority_boundary() -> None:
    binding = _binding()
    binding.authorize_identity(
        caller_account_id=SYNTHETIC_AUTHORITY,
        caller_region="us-east-1",
    )

    with pytest.raises(BootstrapAuthorizationError, match="caller account"):
        binding.authorize_identity(caller_account_id="999900001111", caller_region="us-east-1")
    with pytest.raises(BootstrapAuthorizationError, match="caller region"):
        binding.authorize_identity(caller_account_id=SYNTHETIC_AUTHORITY, caller_region="us-west-2")
    with pytest.raises(BootstrapAuthorizationError, match="destination account"):
        _binding(destination_account_ids=(SYNTHETIC_AUTHORITY,))
    with pytest.raises(BootstrapAuthorizationError, match="unique"):
        _binding(destination_account_ids=(SYNTHETIC_DESTINATIONS[0], SYNTHETIC_DESTINATIONS[0]))


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("authority_account_id", "000000000000"),
        ("authority_account_id", "1111"),
        ("region", "global"),
        ("stack_name", "arbitrary-stack"),
        ("state_bucket_name", "request-supplied-prefix"),
        ("state_key", "customer-a/terraform.tfstate"),
        ("destination_account_ids", ()),
    ],
)
def test_binding_rejects_missing_malformed_or_request_selected_authority(field: str, value: object) -> None:
    with pytest.raises(BootstrapAuthorizationError):
        _binding(**{field: value})


def test_plan_binds_exact_change_set_template_identity_and_account_control() -> None:
    plan = _plan()

    assert plan["record_type"] == "platform_authority_bootstrap_plan"
    assert plan["authority_account_id"] == SYNTHETIC_AUTHORITY
    assert plan["region"] == "us-east-1"
    assert plan["state_key"] == "platform-authority/terraform.tfstate"
    assert plan["native_lockfile_enabled"] is True
    assert plan["account_public_access_block_after"] == {
        "BlockPublicAcls": True,
        "BlockPublicPolicy": True,
        "IgnorePublicAcls": True,
        "RestrictPublicBuckets": True,
    }
    assert plan["template_sha256"] == "sha256:" + "a" * 64
    assert plan["record_digest"] == _canonical_digest(
        {key: value for key, value in plan.items() if key != "record_digest"}
    )
    assert {change["resource_type"] for change in plan["planned_resource_changes"]} == {
        "AWS::KMS::Key",
        "AWS::S3::Bucket",
        "AWS::S3::BucketPolicy",
    }


def test_apply_requires_distinct_current_plan_bound_approval() -> None:
    now = datetime(2030, 1, 1, 0, 10, tzinfo=UTC)
    plan = _plan(now=now - timedelta(minutes=10))
    approval = build_bootstrap_approval(
        plan=plan,
        initiator_id="operator-1001",
        approver_id="reviewer-2002",
        approver_arn="arn:aws:sts::111122223333:assumed-role/SyntheticBootstrap/reviewer-2002",
        approved_at=now - timedelta(minutes=1),
        expires_at=now + timedelta(minutes=30),
    )

    authorize_bootstrap_apply(
        plan=plan,
        approval=approval,
        binding=_binding(),
        caller_account_id=SYNTHETIC_AUTHORITY,
        caller_region="us-east-1",
        caller_arn="arn:aws:sts::111122223333:assumed-role/SyntheticBootstrap/reviewer-2002",
        current_template_sha256="a" * 64,
        now=now,
    )

    with pytest.raises(BootstrapAuthorizationError, match="independent"):
        build_bootstrap_approval(
            plan=plan,
            initiator_id="operator-1001",
            approver_id="operator-1001",
            approver_arn="arn:aws:sts::111122223333:assumed-role/SyntheticBootstrap/session",
            approved_at=now - timedelta(minutes=1),
            expires_at=now + timedelta(minutes=30),
        )

    tampered = copy.deepcopy(plan)
    tampered["state_key"] = "foreign/terraform.tfstate"
    with pytest.raises(BootstrapAuthorizationError, match="plan digest"):
        authorize_bootstrap_apply(
            plan=tampered,
            approval=approval,
            binding=_binding(),
            caller_account_id=SYNTHETIC_AUTHORITY,
            caller_region="us-east-1",
            caller_arn="arn:aws:sts::111122223333:assumed-role/SyntheticBootstrap/reviewer-2002",
            current_template_sha256="a" * 64,
            now=now,
        )

    with pytest.raises(BootstrapAuthorizationError, match="template digest"):
        authorize_bootstrap_apply(
            plan=plan,
            approval=approval,
            binding=_binding(),
            caller_account_id=SYNTHETIC_AUTHORITY,
            caller_region="us-east-1",
            caller_arn="arn:aws:sts::111122223333:assumed-role/SyntheticBootstrap/reviewer-2002",
            current_template_sha256="b" * 64,
            now=now,
        )

    with pytest.raises(BootstrapAuthorizationError, match="expired"):
        authorize_bootstrap_apply(
            plan=plan,
            approval=approval,
            binding=_binding(),
            caller_account_id=SYNTHETIC_AUTHORITY,
            caller_region="us-east-1",
            caller_arn="arn:aws:sts::111122223333:assumed-role/SyntheticBootstrap/reviewer-2002",
            current_template_sha256="a" * 64,
            now=now + timedelta(hours=2),
        )


def test_backend_config_is_native_lockfile_and_contains_no_legacy_lock_table() -> None:
    config = render_backend_config(
        binding=_binding(),
        kms_key_arn="arn:aws:kms:us-east-1:111122223333:key/00000000-0000-4000-8000-000000000000",
    )

    assert 'bucket              = "scanalyze-platform-authority-111122223333-us-east-1-state"' in config
    assert 'key                 = "platform-authority/terraform.tfstate"' in config
    assert 'region              = "us-east-1"' in config
    assert "encrypt             = true" in config
    assert "use_lockfile        = true" in config
    assert "dynamodb" not in config.lower()


def test_verification_fails_closed_unless_every_backend_control_is_true() -> None:
    plan = _plan()
    controls = {
        "account_public_access_blocked": True,
        "bucket_public_access_blocked": True,
        "bucket_owner_enforced": True,
        "bucket_versioning_enabled": True,
        "default_encryption": "aws:kms",
        "bucket_key_enabled": True,
        "kms_rotation_enabled": True,
        "native_lockfile_enabled": True,
    }
    record = build_bootstrap_verification(
        plan=plan,
        binding=_binding(),
        caller_arn="arn:aws:sts::111122223333:assumed-role/SyntheticBootstrap/reviewer-2002",
        stack_status="CREATE_COMPLETE",
        state_bucket_name=SYNTHETIC_BUCKET,
        state_key="platform-authority/terraform.tfstate",
        state_kms_key_arn=(
            "arn:aws:kms:us-east-1:111122223333:key/"
            "00000000-0000-4000-8000-000000000000"
        ),
        controls=controls,
        verified_at=datetime(2030, 1, 1, 0, 30, tzinfo=UTC),
    )
    assert record["verification_digest"] == _canonical_digest(
        {key: value for key, value in record.items() if key != "verification_digest"}
    )

    unsafe = dict(controls)
    unsafe["account_public_access_blocked"] = False
    with pytest.raises(BootstrapAuthorizationError, match="control"):
        build_bootstrap_verification(
            plan=plan,
            binding=_binding(),
            caller_arn="arn:aws:sts::111122223333:assumed-role/SyntheticBootstrap/reviewer-2002",
            stack_status="CREATE_COMPLETE",
            state_bucket_name=SYNTHETIC_BUCKET,
            state_key="platform-authority/terraform.tfstate",
            state_kms_key_arn=(
                "arn:aws:kms:us-east-1:111122223333:key/"
                "00000000-0000-4000-8000-000000000000"
            ),
            controls=unsafe,
            verified_at=datetime(2030, 1, 1, 0, 30, tzinfo=UTC),
        )


def test_cloudformation_template_is_retained_encrypted_and_account_bound() -> None:
    text = TEMPLATE.read_text(encoding="utf-8")

    assert "AuthorityAccountId" in text
    assert "AuthorityAccountMustMatch" in text
    assert "AWS::AccountId" in text
    assert "platform-authority/terraform.tfstate" in text
    assert "AWS::KMS::Key" in text
    assert "EnableKeyRotation: true" in text
    assert "BypassPolicyLockoutSafetyCheck: false" in text
    assert "DeletionPolicy: Retain" in text
    assert "UpdateReplacePolicy: Retain" in text
    assert "BucketKeyEnabled: true" in text
    assert "BlockPublicAcls: true" in text
    assert "ObjectOwnership: BucketOwnerEnforced" in text
    assert "DenyInsecureTransport" in text
    assert "DenyWrongKmsKey" in text
    assert "DenyCrossAccountAccess" in text
    assert "use_lockfile        = true" in text
    assert "AWS::DynamoDB::Table" not in text
    assert "production" not in text.lower()


def _allowed_actions(policy: dict) -> set[str]:
    return {
        action
        for statement in policy["Statement"]
        if statement["Effect"] == "Allow"
        for action in (
            [statement["Action"]] if isinstance(statement["Action"], str) else statement["Action"]
        )
    }


def test_bootstrap_policies_enforce_disjoint_plan_and_apply_authority() -> None:
    plan_policy = json.loads(PLAN_POLICY.read_text(encoding="utf-8"))
    apply_policy = json.loads(APPLY_POLICY.read_text(encoding="utf-8"))
    plan_actions = _allowed_actions(plan_policy)
    apply_actions = _allowed_actions(apply_policy)

    assert "cloudformation:CreateChangeSet" in plan_actions
    assert "cloudformation:DeleteChangeSet" not in plan_actions
    assert "cloudformation:ExecuteChangeSet" not in plan_actions
    assert "s3:PutAccountPublicAccessBlock" not in plan_actions
    assert "kms:CreateKey" not in plan_actions

    assert "cloudformation:ExecuteChangeSet" in apply_actions
    assert "s3:PutAccountPublicAccessBlock" in apply_actions
    assert "kms:CreateKey" in apply_actions
    assert "cloudformation:CreateChangeSet" not in apply_actions
    assert "cloudformation:DeleteChangeSet" not in apply_actions

    statements = {
        statement["Sid"]: statement
        for policy in (plan_policy, apply_policy)
        for statement in policy["Statement"]
    }
    stack_arn = (
        "arn:${aws_partition}:cloudformation:${region}:${authority_account_id}:"
        "stack/scanalyze-platform-authority-state-backend/*"
    )
    expected_tags = {
        "aws:RequestTag/managed_by": "cloudformation",
        "aws:RequestTag/service": "scanalyze-platform-authority",
        "aws:RequestTag/work_package": "GUG-206",
    }
    create_statement = statements["CreateOnlyExactBootstrapChangeSet"]
    assert create_statement["Action"] == "cloudformation:CreateChangeSet"
    assert create_statement["Resource"] == stack_arn
    assert create_statement["Condition"] == {
        "StringEquals": {
            "cloudformation:ChangeSetName": "${change_set_name}",
            **expected_tags,
        },
        "ForAllValues:StringEquals": {
            "aws:TagKeys": ["managed_by", "service", "work_package"]
        },
    }
    plan_statements = {
        statement["Sid"]: statement for statement in plan_policy["Statement"]
    }
    retirement_deny = plan_statements["DenyDirectRetirementEffects"]
    assert retirement_deny["Effect"] == "Deny"
    assert "cloudformation:DeleteChangeSet" in retirement_deny["Action"]
    assert retirement_deny["Resource"] == "*"
    tag_statement = statements["TagOnlyExactBootstrapChangeSetAtCreate"]
    assert tag_statement["Action"] == "cloudformation:TagResource"
    assert tag_statement["Condition"] == {
        "StringEquals": {
            "cloudformation:CreateAction": "CreateChangeSet",
            **expected_tags,
        },
        "ForAllValues:StringEquals": {
            "aws:TagKeys": ["managed_by", "service", "work_package"]
        },
    }
    execute_statement = statements["ExecuteExactBootstrapChangeSet"]
    assert execute_statement["Action"] == "cloudformation:ExecuteChangeSet"
    assert execute_statement["Resource"] == stack_arn
    assert execute_statement["Condition"] == {
        "StringEquals": {"cloudformation:ChangeSetName": "${change_set_name}"}
    }
    for statement in (create_statement, execute_statement):
        assert ":changeSet/" not in json.dumps(statement["Resource"])

    for policy in (plan_policy, apply_policy):
        serialized = json.dumps(policy)
        assert "cloudformation:DeleteStack" not in _allowed_actions(policy)
        assert '"Action": "*"' not in serialized
        assert "AdministratorAccess" not in serialized
        for forbidden in (
            "iam:CreateUser",
            "iam:CreateAccessKey",
            "iam:PassRole",
            "organizations:*",
            "ecs:",
            "ec2:RunInstances",
            "cognito-idp:",
        ):
            assert forbidden not in serialized

    alias_statements = {
        statement["Sid"]: statement
        for statement in apply_policy["Statement"]
        if "kms:CreateAlias" in (
            [statement["Action"]] if isinstance(statement["Action"], str) else statement["Action"]
        )
    }
    exact_alias_statement = alias_statements[
        "ManageExactStateKeyAliasViaCloudFormation"
    ]
    assert exact_alias_statement["Resource"] == (
        "arn:${aws_partition}:kms:${region}:${authority_account_id}:"
        "alias/scanalyze-platform-authority-state"
    )
    assert "Condition" not in exact_alias_statement
    assert alias_statements["BindAliasOnlyToTaggedStateKeyViaCloudFormation"]["Resource"] == (
        "arn:${aws_partition}:kms:${region}:${authority_account_id}:key/*"
    )
    key_alias_statement = alias_statements[
        "BindAliasOnlyToTaggedStateKeyViaCloudFormation"
    ]
    assert set(key_alias_statement["Action"]) == {
        "kms:CreateAlias",
        "kms:DeleteAlias",
        "kms:UpdateAlias",
    }
    assert key_alias_statement["Condition"]["StringEquals"] == {
        "aws:ResourceTag/service": "scanalyze-platform-authority",
        "aws:ResourceTag/data_class": "control-metadata",
        "aws:ResourceTag/account_id": "${authority_account_id}",
        "aws:ResourceTag/region": "${region}",
    }
    assert key_alias_statement["Condition"]["ForAnyValue:StringEquals"] == {
        "aws:CalledVia": ["cloudformation.amazonaws.com"]
    }
    assert "kms:RequestAlias" not in json.dumps(alias_statements)

    direct_mutation_exception = {"s3:PutAccountPublicAccessBlock"}
    backend_mutations = {
        action
        for statement in apply_policy["Statement"]
        for action in (
            [statement["Action"]]
            if isinstance(statement["Action"], str)
            else statement["Action"]
        )
        if action.startswith(
            (
                "s3:Put",
                "s3:Create",
                "kms:Put",
                "kms:Create",
                "kms:Update",
                "kms:Delete",
                "kms:Enable",
                "kms:Tag",
            )
        )
        and action not in direct_mutation_exception
    }
    assert backend_mutations
    for statement in apply_policy["Statement"]:
        actions = (
            [statement["Action"]]
            if isinstance(statement["Action"], str)
            else statement["Action"]
        )
        if backend_mutations.intersection(actions):
            if statement["Sid"] == "ManageExactStateKeyAliasViaCloudFormation":
                assert "Condition" not in statement
                continue
            assert statement["Condition"]["ForAnyValue:StringEquals"]["aws:CalledVia"] == [
                "cloudformation.amazonaws.com"
            ]

    account_public_access = next(
        statement
        for statement in apply_policy["Statement"]
        if statement["Sid"] == "ManageAccountPublicAccessBlock"
    )
    assert account_public_access["Action"] == [
        "s3:GetAccountPublicAccessBlock",
        "s3:PutAccountPublicAccessBlock",
    ]
    assert account_public_access["Resource"] == "*"


def test_policy_renderer_binds_account_bucket_and_exact_change_set() -> None:
    plan_template = json.loads(PLAN_POLICY.read_text(encoding="utf-8"))
    apply_template = json.loads(APPLY_POLICY.read_text(encoding="utf-8"))
    plan_policy = render_bootstrap_iam_policy(
        policy_template=plan_template,
        binding=_binding(),
        change_set_name=SYNTHETIC_CHANGE_SET_NAME,
    )
    apply_policy = render_bootstrap_iam_policy(
        policy_template=apply_template,
        binding=_binding(),
        change_set_id=str(_plan()["change_set_id"]),
    )

    assert "${" not in json.dumps(plan_policy)
    assert "${" not in json.dumps(apply_policy)
    execute = next(
        statement
        for statement in apply_policy["Statement"]
        if statement["Sid"] == "ExecuteExactBootstrapChangeSet"
    )
    assert execute["Resource"] == (
        "arn:aws:cloudformation:us-east-1:111122223333:"
        "stack/scanalyze-platform-authority-state-backend/*"
    )
    assert execute["Condition"] == {
        "StringEquals": {"cloudformation:ChangeSetName": SYNTHETIC_CHANGE_SET_NAME}
    }

    with pytest.raises(BootstrapAuthorizationError, match="unbound placeholder"):
        render_bootstrap_iam_policy(
            policy_template=plan_template,
            binding=_binding(),
        )
    with pytest.raises(BootstrapAuthorizationError, match="name does not match"):
        render_bootstrap_iam_policy(
            policy_template=apply_template,
            binding=_binding(),
            change_set_name="scanalyze-platform-authority-bootstrap-20300101000001",
            change_set_id=str(_plan()["change_set_id"]),
        )
    with pytest.raises(BootstrapAuthorizationError, match="name is invalid"):
        render_bootstrap_iam_policy(
            policy_template=plan_template,
            binding=_binding(),
            change_set_name="request-selected-name",
        )
    with pytest.raises(BootstrapAuthorizationError, match="does not match"):
        render_bootstrap_iam_policy(
            policy_template=apply_template,
            binding=_binding(),
            change_set_id=(
                "arn:aws:cloudformation:us-east-1:999900001111:changeSet/"
                "scanalyze-bootstrap-20300101/00000000-0000-4000-8000-000000000000"
            ),
        )

    unsupported = copy.deepcopy(plan_template)
    create_statement = next(
        statement
        for statement in unsupported["Statement"]
        if statement["Sid"] == "CreateOnlyExactBootstrapChangeSet"
    )
    create_statement["Resource"] = (
        "arn:${aws_partition}:cloudformation:${region}:${authority_account_id}:"
        "changeSet/${change_set_name}/*"
    )
    with pytest.raises(BootstrapAuthorizationError, match="exact stack resource"):
        render_bootstrap_iam_policy(
            policy_template=unsupported,
            binding=_binding(),
            change_set_name=SYNTHETIC_CHANGE_SET_NAME,
        )

    wildcard = copy.deepcopy(plan_template)
    wildcard["Statement"].append(
        {
            "Sid": "ForbiddenWildcard",
            "Effect": "Allow",
            "Action": "cloudformation:*",
            "Resource": "*",
        }
    )
    with pytest.raises(BootstrapAuthorizationError, match="wildcard CloudFormation"):
        render_bootstrap_iam_policy(
            policy_template=wildcard,
            binding=_binding(),
            change_set_name=SYNTHETIC_CHANGE_SET_NAME,
        )

    unexpected = copy.deepcopy(plan_template)
    unexpected["Statement"].append(
        {
            "Sid": "ForbiddenMutation",
            "Effect": "Allow",
            "Action": "cloudformation:UpdateStack",
            "Resource": "*",
        }
    )
    with pytest.raises(BootstrapAuthorizationError, match="unexpected CloudFormation"):
        render_bootstrap_iam_policy(
            policy_template=unexpected,
            binding=_binding(),
            change_set_name=SYNTHETIC_CHANGE_SET_NAME,
        )


def test_change_set_identity_from_arn_returns_exact_typed_binding() -> None:
    change_set_id = str(_plan()["change_set_id"])
    parser = getattr(bootstrap_contract, "change_set_identity_from_arn")
    identity = parser(change_set_id, binding=_binding())

    assert identity.full_arn == change_set_id
    assert identity.name == SYNTHETIC_CHANGE_SET_NAME
    assert identity.uuid == "00000000-0000-4000-8000-000000000000"
    assert identity.partition == "aws"
    assert identity.region == "us-east-1"
    assert identity.account_id == SYNTHETIC_AUTHORITY
    assert _plan()["change_set_id"] == change_set_id


@pytest.mark.parametrize(
    "change_set_id",
    [
        "not-an-arn",
        SYNTHETIC_CHANGE_SET_NAME,
        (
            "arn:aws-cn:cloudformation:us-east-1:111122223333:changeSet/"
            f"{SYNTHETIC_CHANGE_SET_NAME}/00000000-0000-4000-8000-000000000000"
        ),
        (
            "arn:aws:cloudformation:us-west-2:111122223333:changeSet/"
            f"{SYNTHETIC_CHANGE_SET_NAME}/00000000-0000-4000-8000-000000000000"
        ),
        (
            "arn:aws:cloudformation:us-east-1:999900001111:changeSet/"
            f"{SYNTHETIC_CHANGE_SET_NAME}/00000000-0000-4000-8000-000000000000"
        ),
        (
            "arn:aws:cloudformation:us-east-1:111122223333:changeSet/"
            "request-selected-name/00000000-0000-4000-8000-000000000000"
        ),
        (
            "arn:aws:cloudformation:us-east-1:111122223333:changeSet/"
            f"{SYNTHETIC_CHANGE_SET_NAME}/not-a-uuid"
        ),
        (
            "arn:aws:cloudformation:us-east-1:111122223333:changeSet/"
            f"{SYNTHETIC_CHANGE_SET_NAME}/00000000-0000-0000-0000-000000000000"
        ),
        (
            "arn:aws:cloudformation:us-east-1:111122223333:changeSet/"
            f"{SYNTHETIC_CHANGE_SET_NAME}/00000000-0000-4000-8000-000000000000/extra"
        ),
        (
            "arn:aws:cloudformation:us-east-1:111122223333:changeSet/"
            f"{SYNTHETIC_CHANGE_SET_NAME}/"
        ),
        (
            "arn:aws:cloudformation:us-east-1:111122223333:changeSet/"
            "00000000-0000-4000-8000-000000000000"
        ),
        (
            "arn:aws:cloudformation:us-east-1:111122223333:changeSet//"
            "00000000-0000-4000-8000-000000000000"
        ),
        (
            " arn:aws:cloudformation:us-east-1:111122223333:changeSet/"
            f"{SYNTHETIC_CHANGE_SET_NAME}/00000000-0000-4000-8000-000000000000"
        ),
        (
            "arn:aws:cloudformation:us-east-1:111122223333:changeSet/"
            "scanalyze-platform-authority-bootstrap-%3230303030313031303030303030/"
            "00000000-0000-4000-8000-000000000000"
        ),
        (
            "arn:aws:cloudformation:us-east-1:111122223333:changeSet/"
            "SCANALYZE-PLATFORM-AUTHORITY-BOOTSTRAP-20300101000000/"
            "00000000-0000-4000-8000-000000000000"
        ),
    ],
    ids=(
        "malformed",
        "bare-name",
        "partition",
        "region",
        "account",
        "name-pattern",
        "uuid",
        "uuid-version-variant",
        "extra-path",
        "missing-id",
        "missing-name",
        "empty-name",
        "whitespace",
        "encoded-name",
        "case-variant",
    ),
)
def test_change_set_identity_from_arn_rejects_foreign_or_ambiguous_values(
    change_set_id: str,
) -> None:
    parser = getattr(bootstrap_contract, "change_set_identity_from_arn")

    with pytest.raises(BootstrapAuthorizationError, match="Change Set ARN"):
        parser(change_set_id, binding=_binding())


def test_apply_mutation_request_matches_the_policy_bound_bare_name(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _, calls, plan = _run_apply_until_execute(
        monkeypatch=monkeypatch,
        tmp_path=tmp_path,
        module_name="gug210_apply_request_parity",
    )
    execute_calls = [
        args
        for service, operation, args in calls
        if (service, operation) == ("cloudformation", "execute-change-set")
    ]
    assert len(execute_calls) == 1
    execute_args = execute_calls[0]
    execute_name = execute_args[execute_args.index("--change-set-name") + 1]
    stack_name = execute_args[execute_args.index("--stack-name") + 1]
    policy = render_bootstrap_iam_policy(
        policy_template=json.loads(APPLY_POLICY.read_text(encoding="utf-8")),
        binding=_binding(),
        change_set_id=str(plan["change_set_id"]),
    )
    execute_statement = next(
        statement
        for statement in policy["Statement"]
        if statement["Sid"] == "ExecuteExactBootstrapChangeSet"
    )
    policy_name = execute_statement["Condition"]["StringEquals"][
        "cloudformation:ChangeSetName"
    ]

    assert execute_name == policy_name == SYNTHETIC_CHANGE_SET_NAME
    assert execute_name != plan["change_set_id"]
    assert stack_name == _binding().stack_name


def test_apply_repeats_full_arn_readback_after_other_mutation(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _, calls, plan = _run_apply_until_execute(
        monkeypatch=monkeypatch,
        tmp_path=tmp_path,
        module_name="gug210_apply_final_readback",
    )
    describe_indexes = [
        index
        for index, (service, operation, args) in enumerate(calls)
        if (service, operation) == ("cloudformation", "describe-change-set")
        and plan["change_set_id"] in args
    ]
    public_block_index = next(
        index
        for index, (service, operation, _) in enumerate(calls)
        if (service, operation) == ("s3control", "put-public-access-block")
    )
    execute_index = next(
        index
        for index, (service, operation, _) in enumerate(calls)
        if (service, operation) == ("cloudformation", "execute-change-set")
    )

    assert len(describe_indexes) == 2
    assert describe_indexes[0] < public_block_index < describe_indexes[1] < execute_index
    cloudformation_before_execute = [
        index
        for index, (service, _, _) in enumerate(calls[:execute_index])
        if service == "cloudformation"
    ]
    assert cloudformation_before_execute[-1] == describe_indexes[-1]


def test_apply_rejects_same_name_different_uuid_on_final_readback(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _, calls, _ = _run_apply_until_execute(
        monkeypatch=monkeypatch,
        tmp_path=tmp_path,
        module_name="gug210_apply_final_uuid_substitution",
        substitute_uuid_on_final_readback=True,
    )

    assert sum(
        (service, operation) == ("cloudformation", "describe-change-set")
        for service, operation, _ in calls
    ) == 2
    assert not any(
        (service, operation) == ("cloudformation", "execute-change-set")
        for service, operation, _ in calls
    )


def test_apply_rechecks_approval_expiry_immediately_before_execute(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _, calls, _ = _run_apply_until_execute(
        monkeypatch=monkeypatch,
        tmp_path=tmp_path,
        module_name="gug210_apply_expired_before_execute",
        expire_before_execute=True,
    )

    assert not any(
        (service, operation) == ("cloudformation", "execute-change-set")
        for service, operation, _ in calls
    )


def test_apply_rejects_unapproved_live_principal_before_mutation(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _, calls, _ = _run_apply_until_execute(
        monkeypatch=monkeypatch,
        tmp_path=tmp_path,
        module_name="gug210_apply_unapproved_live_principal",
        wrong_approved_principal=True,
    )

    assert not any(
        (service, operation)
        in {
            ("s3control", "put-public-access-block"),
            ("cloudformation", "execute-change-set"),
        }
        for service, operation, _ in calls
    )


def test_apply_does_not_retry_after_ambiguous_execute_result(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _, calls, _ = _run_apply_until_execute(
        monkeypatch=monkeypatch,
        tmp_path=tmp_path,
        module_name="gug210_apply_ambiguous_execute",
        ambiguous_execute=True,
    )
    execute_indexes = [
        index
        for index, (service, operation, _) in enumerate(calls)
        if (service, operation) == ("cloudformation", "execute-change-set")
    ]

    assert execute_indexes == [len(calls) - 1]


def test_invalid_plan_change_set_id_fails_before_any_aws_call() -> None:
    module = _load_bootstrap_cli("gug210_invalid_arn_pre_aws")
    plan = _plan()
    plan["change_set_id"] = SYNTHETIC_CHANGE_SET_NAME

    class ZeroCallClient:
        def run(self, *_: str) -> dict:
            raise AssertionError("invalid Change Set evidence reached AWS")

    with pytest.raises(BootstrapAuthorizationError, match="Change Set ARN"):
        module._describe_exact_change_set(ZeroCallClient(), _binding(), plan)


@pytest.mark.parametrize(
    ("mutation", "expected_error"),
    (
        ("malformed-arn", "Change Set ARN"),
        ("plan-digest", "bootstrap plan digest mismatch"),
        ("approval-digest", "bootstrap approval digest mismatch"),
        ("approval-binding", "bootstrap approval binding mismatch"),
        ("approval-expired", "bootstrap approval is expired or not yet valid"),
        ("approval-not-yet-valid", "bootstrap approval is expired or not yet valid"),
        ("approval-decision", "bootstrap approval decision is not approved"),
        ("plan-record-type", "bootstrap plan record contract is invalid"),
        ("operator-type-confusion", "bootstrap plan record contract is invalid"),
        ("wrong-stack", "bootstrap plan binding mismatch: stack_name"),
        ("expired", "bootstrap plan is expired"),
        ("duplicate-json", "duplicate operational JSON key"),
        ("duplicate-approval-json", "duplicate operational JSON key"),
    ),
)
def test_apply_prevalidates_local_evidence_before_creating_aws_client(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    mutation: str,
    expected_error: str,
) -> None:
    module = _load_bootstrap_cli(f"gug210_local_prevalidation_{mutation}")
    current = datetime.now(tz=UTC).replace(microsecond=0)
    plan, approval = _live_plan_and_approval(
        now=(
            current - timedelta(hours=3)
            if mutation == "expired"
            else current
        )
    )
    if mutation == "malformed-arn":
        plan["change_set_id"] = SYNTHETIC_CHANGE_SET_NAME
        _redigest(plan, "record_digest")
        approval["plan_record_digest"] = plan["record_digest"]
        approval["change_set_id"] = plan["change_set_id"]
        _redigest(approval, "approval_digest")
    elif mutation == "plan-digest":
        plan["state_key"] = "tampered/terraform.tfstate"
    elif mutation == "approval-digest":
        approval["approver_id"] = "reviewer-3003"
    elif mutation == "approval-binding":
        approval["change_set_id"] = str(approval["change_set_id"]).replace(
            "00000000-0000-4000-8000-000000000000",
            "11111111-1111-4111-8111-111111111111",
        )
        _redigest(approval, "approval_digest")
    elif mutation == "approval-expired":
        approval["approved_at"] = (current - timedelta(minutes=2)).isoformat().replace(
            "+00:00", "Z"
        )
        approval["expires_at"] = (current - timedelta(minutes=1)).isoformat().replace(
            "+00:00", "Z"
        )
        _redigest(approval, "approval_digest")
    elif mutation == "approval-not-yet-valid":
        approval["approved_at"] = (current + timedelta(minutes=1)).isoformat().replace(
            "+00:00", "Z"
        )
        approval["expires_at"] = (current + timedelta(minutes=10)).isoformat().replace(
            "+00:00", "Z"
        )
        _redigest(approval, "approval_digest")
    elif mutation == "approval-decision":
        approval["decision"] = "DENIED"
        _redigest(approval, "approval_digest")
    elif mutation == "plan-record-type":
        plan["record_type"] = "self_consistent_but_foreign_plan"
        _redigest(plan, "record_digest")
        approval["plan_record_digest"] = plan["record_digest"]
        _redigest(approval, "approval_digest")
    elif mutation == "operator-type-confusion":
        plan["initiator_id"] = 123
        _redigest(plan, "record_digest")
        approval["plan_record_digest"] = plan["record_digest"]
        approval["initiator_id"] = 123
        approval["approver_id"] = "123"
        _redigest(approval, "approval_digest")
    elif mutation == "wrong-stack":
        plan["stack_name"] = "foreign-stack"
        _redigest(plan, "record_digest")
        approval["plan_record_digest"] = plan["record_digest"]
        _redigest(approval, "approval_digest")

    plan_path = tmp_path / "plan.json"
    approval_path = tmp_path / "approval.json"
    if mutation == "duplicate-json":
        plan_path.write_text(
            '{"record_digest":"first","record_digest":"second"}',
            encoding="utf-8",
        )
    else:
        plan_path.write_text(json.dumps(plan), encoding="utf-8")
    if mutation == "duplicate-approval-json":
        approval_path.write_text(
            '{"approval_digest":"first","approval_digest":"second"}',
            encoding="utf-8",
        )
    else:
        approval_path.write_text(json.dumps(approval), encoding="utf-8")
    aws_client_constructions = 0

    def forbidden_aws_client(*, region: str) -> object:
        del region
        nonlocal aws_client_constructions
        aws_client_constructions += 1
        raise AssertionError("locally invalid evidence constructed an AWS client")

    monkeypatch.setattr(module, "AwsCli", forbidden_aws_client)
    monkeypatch.setenv("AWS_PROFILE", "synthetic-sso-profile")
    monkeypatch.setenv("AWS_REGION", "us-east-1")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")
    for name in module.FORBIDDEN_CREDENTIAL_ENV:
        monkeypatch.delenv(name, raising=False)
    args = argparse.Namespace(
        authority_account_id=SYNTHETIC_AUTHORITY,
        region="us-east-1",
        destination_account_id=list(SYNTHETIC_DESTINATIONS),
        plan=plan_path,
        approval=approval_path,
        verification_out=tmp_path / "verification.json",
        backend_config_out=tmp_path / "backend.hcl",
        allow_bootstrap_apply=True,
    )

    with pytest.raises(BootstrapAuthorizationError, match=expected_error):
        module._cmd_apply(args)
    assert aws_client_constructions == 0


def test_aws_cli_disables_provider_retries_for_one_shot_requests(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _load_bootstrap_cli("gug210_single_attempt_aws_cli")
    captured_environment: dict[str, str] = {}

    def fake_run(*_: object, **kwargs: object) -> subprocess.CompletedProcess[str]:
        captured_environment.update(kwargs["env"])  # type: ignore[arg-type]
        return subprocess.CompletedProcess(args=[], returncode=0, stdout="{}", stderr="")

    monkeypatch.setattr(module.subprocess, "run", fake_run)
    monkeypatch.setenv("AWS_MAX_ATTEMPTS", "9")

    module.AwsCli(region="us-east-1").run("cloudformation", "execute-change-set")

    assert captured_environment["AWS_MAX_ATTEMPTS"] == "1"


def test_private_output_is_exclusive_non_symlink_and_mode_0600(tmp_path: Path) -> None:
    module = _load_bootstrap_cli("gug210_private_output_contract")
    preexisting = tmp_path / "preexisting.json"
    preexisting.write_text("preserve", encoding="utf-8")
    with pytest.raises(BootstrapAuthorizationError, match="must not already exist"):
        module._write_private(preexisting, "replacement")
    assert preexisting.read_text(encoding="utf-8") == "preserve"

    symlink_target = tmp_path / "symlink-target.json"
    symlink_output = tmp_path / "symlink-output.json"
    symlink_output.symlink_to(symlink_target)
    with pytest.raises(BootstrapAuthorizationError, match="must not already exist"):
        module._write_private(symlink_output, "must-not-be-written")
    assert symlink_output.is_symlink()
    assert not symlink_target.exists()

    private_output = tmp_path / "private.json"
    module._write_private(private_output, "synthetic")
    assert private_output.read_text(encoding="utf-8") == "synthetic"
    assert stat.S_IMODE(private_output.stat().st_mode) == 0o600


def test_apply_rejects_parent_symlink_output_alias_before_creating_client(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    module = _load_bootstrap_cli("gug210_parent_symlink_output_alias")
    real_parent = tmp_path / "private-evidence"
    real_parent.mkdir(mode=0o700)
    first_alias = tmp_path / "first-alias"
    second_alias = tmp_path / "second-alias"
    first_alias.symlink_to(real_parent, target_is_directory=True)
    second_alias.symlink_to(real_parent, target_is_directory=True)
    aws_client_constructions = 0

    def forbidden_aws_client(*, region: str) -> object:
        del region
        nonlocal aws_client_constructions
        aws_client_constructions += 1
        raise AssertionError("symlinked output path constructed an AWS client")

    monkeypatch.setattr(module, "AwsCli", forbidden_aws_client)
    args = argparse.Namespace(
        authority_account_id=SYNTHETIC_AUTHORITY,
        region="us-east-1",
        destination_account_id=list(SYNTHETIC_DESTINATIONS),
        plan=tmp_path / "must-not-be-read-plan.json",
        approval=tmp_path / "must-not-be-read-approval.json",
        verification_out=first_alias / "shared-output",
        backend_config_out=second_alias / "shared-output",
        allow_bootstrap_apply=True,
    )

    with pytest.raises(BootstrapAuthorizationError, match="must not contain symlinks"):
        module._cmd_apply(args)
    assert aws_client_constructions == 0
    assert not (real_parent / "shared-output").exists()


def test_live_cli_requires_explicit_write_flags_sso_and_private_external_outputs() -> None:
    cli = (REPO_ROOT / "scripts/deployment/platform-authority-bootstrap.py").read_text(
        encoding="utf-8"
    )

    assert "AWS_PROFILE" in cli
    assert "FORBIDDEN_CREDENTIAL_ENV" in cli
    assert "SSO_ASSUMED_ROLE_ARN" in cli
    assert 'PLAN_PERMISSION_SET = "ScanalyzeAuthorityBootstrapPlan"' in cli
    assert 'APPLY_PERMISSION_SET = "ScanalyzeAuthorityBootstrapApply"' in cli
    assert "AWS_PERMISSION_SET_NAME" in cli
    assert "_validate_permission_set_name(permission_set)" in cli
    assert "render-plan-policy" in cli
    assert "render-apply-policy" in cli
    assert "--change-set-name" in cli
    assert "--allow-change-set-write" in cli
    assert "--allow-bootstrap-apply" in cli
    assert "--allow-cancel-unexecuted" in cli
    assert "NORMAL_CANCEL_RETIRED" in cli
    assert "--no-disable-rollback" in cli
    assert "operational output must be outside the repository" in cli
    assert "os.O_EXCL" in cli
    assert "0o600" in cli
    assert "cloudformation\",\n        \"execute-change-set" in cli
    assert "put-public-access-block" in cli
    assert "delete-change-set" not in cli
    assert "delete-stack" not in cli
    assert "delete-bucket" not in cli
    assert "--profile" not in cli


def test_legacy_normal_cancel_fails_locally_without_reaching_aws(
    tmp_path: Path,
) -> None:
    marker = tmp_path / "aws-was-called"
    fake_aws = tmp_path / "aws"
    fake_aws.write_text(
        "#!/bin/sh\nprintf called > \"$AWS_CALL_MARKER\"\nprintf '{}\\n'\n",
        encoding="utf-8",
    )
    fake_aws.chmod(0o700)
    plan = _plan()
    plan_path = tmp_path / "must-not-be-read-plan.json"
    env = {
        **os.environ,
        "AWS_PROFILE": "synthetic-sso-profile",
        "AWS_REGION": "us-east-1",
        "AWS_DEFAULT_REGION": "us-east-1",
        "AWS_CALL_MARKER": str(marker),
        "AWS_EC2_METADATA_DISABLED": "true",
        "PATH": str(tmp_path),
    }
    for name in (
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "AWS_SESSION_TOKEN",
        "AWS_WEB_IDENTITY_TOKEN_FILE",
        "AWS_ROLE_ARN",
    ):
        env.pop(name, None)
    result = subprocess.run(
        [
            sys.executable,
            str(REPO_ROOT / "scripts/deployment/platform-authority-bootstrap.py"),
            "cancel",
            "--authority-account-id",
            SYNTHETIC_AUTHORITY,
            "--region",
            "us-east-1",
            "--destination-account-id",
            SYNTHETIC_DESTINATIONS[0],
            "--plan",
            str(plan_path),
            "--allow-cancel-unexecuted",
        ],
        check=False,
        capture_output=True,
        text=True,
        env=env,
    )
    output = result.stdout + result.stderr

    assert result.returncode == 1
    assert (
        "NORMAL_CANCEL_RETIRED: use the separately reviewed GUG-215 retirement process"
        in output
    )
    assert not marker.exists()
    assert not plan_path.exists()
    for sensitive in (
        SYNTHETIC_AUTHORITY,
        SYNTHETIC_CHANGE_SET_NAME,
        str(plan["change_set_id"]),
        "00000000-0000-4000-8000-000000000000",
        "synthetic-sso-profile",
        "record_digest",
    ):
        assert sensitive not in output


def test_recovery_plan_accepts_only_an_empty_review_stack(monkeypatch: pytest.MonkeyPatch) -> None:
    spec = importlib.util.spec_from_file_location(
        "gug206_platform_authority_bootstrap_cli",
        REPO_ROOT / "scripts/deployment/platform-authority-bootstrap.py",
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    class FakeClient:
        region = "us-east-1"

        def __init__(
            self,
            resources: list[dict[str, str]],
            caller_arn: str = (
                "arn:aws:sts::111122223333:assumed-role/"
                "AWSReservedSSO_AdministratorAccess_0123456789abcdef/synthetic.user"
            ),
        ) -> None:
            self.resources = resources
            self.caller_arn = caller_arn

        def run(self, service: str, operation: str, *args: str) -> dict:
            if (service, operation) == ("sts", "get-caller-identity"):
                return {
                    "Account": SYNTHETIC_AUTHORITY,
                    "Arn": self.caller_arn,
                }
            if (service, operation) == ("cloudformation", "list-stack-resources"):
                return {"StackResourceSummaries": self.resources}
            if (service, operation) == ("cloudformation", "validate-template"):
                return {}
            raise AssertionError(f"unexpected AWS call: {service} {operation} {args}")

        def run_allow_missing(
            self,
            service: str,
            operation: str,
            *args: str,
            missing_markers: tuple[str, ...],
        ) -> dict | None:
            del args, missing_markers
            if (service, operation) == ("cloudformation", "describe-stacks"):
                return {
                    "Stacks": [
                        {
                            "StackName": "scanalyze-platform-authority-state-backend",
                            "StackId": (
                                "arn:aws:cloudformation:us-east-1:111122223333:stack/"
                                "scanalyze-platform-authority-state-backend/"
                                "00000000-0000-4000-8000-000000000000"
                            ),
                            "StackStatus": "REVIEW_IN_PROGRESS",
                            "NotificationARNs": [],
                        }
                    ]
                }
            if (service, operation) == ("s3control", "get-public-access-block"):
                return None
            raise AssertionError(f"unexpected AWS call: {service} {operation}")

    monkeypatch.setenv("AWS_PROFILE", "synthetic-sso-profile")
    monkeypatch.setenv("AWS_REGION", "us-east-1")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")
    for name in module.FORBIDDEN_CREDENTIAL_ENV:
        monkeypatch.delenv(name, raising=False)

    module._preflight(FakeClient([]), _binding(), allow_empty_review_stack=True)

    with pytest.raises(BootstrapAuthorizationError, match="Identity Center"):
        module._preflight(
            FakeClient(
                [],
                caller_arn=(
                    "arn:aws:sts::111122223333:"
                    "assumed-role/NonSsoBootstrap/session"
                ),
            ),
            _binding(),
            allow_empty_review_stack=True,
        )

    plan_caller = (
        "arn:aws:sts::111122223333:assumed-role/"
        "AWSReservedSSO_ScanalyzeAuthorityBootstrapPlan_"
        "0123456789abcdef/synthetic.user"
    )
    module._require_permission_set(plan_caller, module.PLAN_PERMISSION_SET)
    with pytest.raises(BootstrapAuthorizationError, match="BootstrapApply"):
        module._require_permission_set(plan_caller, module.APPLY_PERMISSION_SET)
    with pytest.raises(BootstrapAuthorizationError, match="BootstrapPlan"):
        module._require_permission_set(
            plan_caller.replace("BootstrapPlan_", "BootstrapPlan_Elevated_"),
            module.PLAN_PERMISSION_SET,
        )

    with pytest.raises(BootstrapAuthorizationError, match="resource inventory"):
        module._preflight(
            FakeClient([{"LogicalResourceId": "ForeignResource"}]),
            _binding(),
            allow_empty_review_stack=True,
        )


def test_live_change_set_pep_revalidates_identity_tags_and_inventory() -> None:
    spec = importlib.util.spec_from_file_location(
        "gug210_platform_authority_bootstrap_cli",
        REPO_ROOT / "scripts/deployment/platform-authority-bootstrap.py",
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    plan = _plan()
    change_set_id = str(plan["change_set_id"])
    response = {
        "ChangeSetId": change_set_id,
        "ChangeSetName": SYNTHETIC_CHANGE_SET_NAME,
        "StackName": "scanalyze-platform-authority-state-backend",
        "Status": "CREATE_COMPLETE",
        "ExecutionStatus": "AVAILABLE",
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
            for change in plan["planned_resource_changes"]
        ],
    }

    class FakeClient:
        def __init__(self, result: dict[str, object]) -> None:
            self.result = result

        def run(self, service: str, operation: str, *args: str) -> dict[str, object]:
            assert (service, operation) == ("cloudformation", "describe-change-set")
            assert change_set_id in args
            return self.result

    assert module._describe_exact_change_set(FakeClient(response), _binding(), plan) == response

    for field, value in (
        ("ChangeSetId", change_set_id.replace(SYNTHETIC_CHANGE_SET_NAME, "foreign")),
        (
            "ChangeSetId",
            change_set_id.replace(
                "00000000-0000-4000-8000-000000000000",
                "11111111-1111-4111-8111-111111111111",
            ),
        ),
        ("ChangeSetName", "foreign"),
        ("StackName", "foreign"),
    ):
        tampered = copy.deepcopy(response)
        tampered[field] = value
        with pytest.raises(BootstrapAuthorizationError, match="identity differs"):
            module._describe_exact_change_set(FakeClient(tampered), _binding(), plan)

    tampered_tags = copy.deepcopy(response)
    tampered_tags["Tags"][2]["Value"] = "FOREIGN"  # type: ignore[index]
    with pytest.raises(BootstrapAuthorizationError, match="tags differ"):
        module._describe_exact_change_set(FakeClient(tampered_tags), _binding(), plan)

    tampered_changes = copy.deepcopy(response)
    tampered_changes["Changes"][0]["ResourceChange"]["Action"] = "Remove"  # type: ignore[index]
    with pytest.raises(BootstrapAuthorizationError, match="live change set differs"):
        module._describe_exact_change_set(FakeClient(tampered_changes), _binding(), plan)


def test_plan_reads_original_template_by_full_change_set_arn() -> None:
    module = _load_bootstrap_cli("gug210_plan_template_readback")
    plan = _plan()
    change_set_id = str(plan["change_set_id"])
    calls: list[tuple[str, str, tuple[str, ...]]] = []

    class FakeClient:
        def __init__(self, template_body: object) -> None:
            self.template_body = template_body

        def run(self, service: str, operation: str, *args: str) -> dict[str, object]:
            calls.append((service, operation, args))
            return {"TemplateBody": self.template_body}

    template_body = TEMPLATE.read_text(encoding="utf-8")
    digest = module._read_exact_change_set_template(
        FakeClient(template_body),
        _binding(),
        change_set_id,
    )

    assert digest == hashlib.sha256(template_body.encode("utf-8")).hexdigest()
    assert calls == [
        (
            "cloudformation",
            "get-template",
            (
                "--change-set-name",
                change_set_id,
                "--stack-name",
                _binding().stack_name,
                "--template-stage",
                "Original",
            ),
        )
    ]

    for invalid_body in (None, {"Resources": {}}, template_body + "\n"):
        with pytest.raises(BootstrapAuthorizationError, match="template differs"):
            module._read_exact_change_set_template(
                FakeClient(invalid_body),
                _binding(),
                change_set_id,
            )


def test_plan_command_persists_only_the_exact_original_template_digest(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    module = _load_bootstrap_cli("gug210_plan_command_template_binding")
    now = datetime(2030, 1, 1, tzinfo=UTC)
    source_plan = _plan(now)
    change_set_id = str(source_plan["change_set_id"])
    response = _live_change_set_response(source_plan)
    template_body = TEMPLATE.read_text(encoding="utf-8")
    calls: list[tuple[str, str, tuple[str, ...]]] = []

    class FakeClient:
        def __init__(self, *, region: str) -> None:
            assert region == "us-east-1"
            self.template_body: object = template_body

        def run(self, service: str, operation: str, *args: str) -> dict[str, object]:
            calls.append((service, operation, args))
            if (service, operation) == ("cloudformation", "create-change-set"):
                return {"Id": change_set_id}
            if (service, operation) == ("cloudformation", "describe-change-set"):
                return response
            if (service, operation) == ("cloudformation", "get-template"):
                return {"TemplateBody": self.template_body}
            raise AssertionError(f"unexpected AWS call: {service} {operation} {args}")

        def wait(self, service: str, waiter: str, *args: str) -> None:
            calls.append((service, waiter, args))

    client = FakeClient(region="us-east-1")
    monkeypatch.setattr(module, "AwsCli", lambda *, region: client)
    monkeypatch.setattr(
        module,
        "_preflight",
        lambda client, binding, *, allow_empty_review_stack: (
            SYNTHETIC_AUTHORITY,
            (
                "arn:aws:sts::111122223333:assumed-role/"
                "AWSReservedSSO_ScanalyzeAuthorityBootstrapPlan_"
                "0123456789abcdef/synthetic.initiator"
            ),
            None,
            False,
        ),
    )
    monkeypatch.setattr(module, "_stack", lambda client, stack_name: None)
    monkeypatch.setattr(module, "_now", lambda: now)

    def plan_args(plan_out: Path) -> argparse.Namespace:
        return argparse.Namespace(
            authority_account_id=SYNTHETIC_AUTHORITY,
            region="us-east-1",
            destination_account_id=list(SYNTHETIC_DESTINATIONS),
            initiator_id="operator-1001",
            change_set_name=SYNTHETIC_CHANGE_SET_NAME,
            plan_out=plan_out,
            allow_change_set_write=True,
        )

    plan_out = tmp_path / "plan.json"
    module._cmd_plan(plan_args(plan_out))
    persisted = json.loads(plan_out.read_text(encoding="utf-8"))
    expected_digest = hashlib.sha256(template_body.encode("utf-8")).hexdigest()
    assert persisted["template_sha256"] == f"sha256:{expected_digest}"
    assert calls[-1] == (
        "cloudformation",
        "get-template",
        (
            "--change-set-name",
            change_set_id,
            "--stack-name",
            _binding().stack_name,
            "--template-stage",
            "Original",
        ),
    )

    calls.clear()
    client.template_body = template_body + "\n"
    rejected_out = tmp_path / "rejected-plan.json"
    with pytest.raises(BootstrapAuthorizationError, match="template differs"):
        module._cmd_plan(plan_args(rejected_out))
    assert not rejected_out.exists()
    assert calls[-1][:2] == ("cloudformation", "get-template")


def test_live_cli_rejects_invalid_evidence_paths_before_any_aws_call(tmp_path: Path) -> None:
    marker = tmp_path / "aws-was-called"
    fake_aws = tmp_path / "aws"
    fake_aws.write_text(
        "#!/bin/sh\nprintf called > \"$AWS_CALL_MARKER\"\nexit 99\n",
        encoding="utf-8",
    )
    fake_aws.chmod(0o700)
    env = {
        **os.environ,
        "AWS_PROFILE": "synthetic-sso-profile",
        "AWS_REGION": "us-east-1",
        "AWS_CALL_MARKER": str(marker),
        "PATH": str(tmp_path),
    }
    result = subprocess.run(
        [
            sys.executable,
            str(REPO_ROOT / "scripts/deployment/platform-authority-bootstrap.py"),
            "plan",
            "--authority-account-id",
            SYNTHETIC_AUTHORITY,
            "--region",
            "us-east-1",
            "--destination-account-id",
            SYNTHETIC_DESTINATIONS[0],
            "--initiator-id",
            "operator-1001",
            "--change-set-name",
            SYNTHETIC_CHANGE_SET_NAME,
            "--plan-out",
            str(REPO_ROOT / "forbidden-operational-output.json"),
            "--allow-change-set-write",
        ],
        check=False,
        capture_output=True,
        text=True,
        env=env,
    )

    assert result.returncode != 0
    assert "operational output must be outside the repository" in result.stderr
    assert not marker.exists()


def test_schemas_docs_and_offline_gate_are_registered() -> None:
    expected = {
        "platform-authority-bootstrap-plan.v1.schema.json",
        "platform-authority-bootstrap-approval.v1.schema.json",
        "platform-authority-bootstrap-verification.v1.schema.json",
    }
    assert expected <= {path.name for path in SCHEMA_DIR.iterdir()}

    makefile = (REPO_ROOT / "Makefile").read_text(encoding="utf-8")
    assert "platform-authority-bootstrap-check" in makefile
    assert "test_gug206_platform_authority_bootstrap.py" in makefile

    for relative in (
        "ADR/ADR-034-dedicated-platform-authority-account-bootstrap.md",
        "docs/deployment/platform-authority-account-bootstrap.md",
        "docs/operations/platform-authority-bootstrap-recovery.md",
        "docs/security/gug-206-threat-model-delta.md",
        "_NotebookLM_Brain/23_GUG206_Platform_Authority_Account_Bootstrap.md",
    ):
        assert (REPO_ROOT / relative).is_file()


def test_gug207_kms_alias_authorization_evidence_is_registered() -> None:
    required_documents = (
        REPO_ROOT / "ADR/ADR-035-kms-alias-authorization-boundary.md",
        REPO_ROOT / "docs/security/gug-207-kms-alias-authorization-threat-model-delta.md",
        REPO_ROOT / "_NotebookLM_Brain/24_GUG207_KMS_Alias_Authorization.md",
    )
    for document in required_documents:
        assert document.is_file(), document
        content = document.read_text(encoding="utf-8")
        assert "kms:RequestAlias" in content
        assert "aws:CalledVia" in content
        assert "Production" in content and "NO-GO" in content

    deployment_guide = (
        REPO_ROOT / "docs/deployment/platform-authority-account-bootstrap.md"
    ).read_text(encoding="utf-8")
    recovery_guide = (
        REPO_ROOT / "docs/operations/platform-authority-bootstrap-recovery.md"
    ).read_text(encoding="utf-8")
    notebook_index = (
        REPO_ROOT / "_NotebookLM_Brain/00_INDEX_AND_SOURCE_MAP.md"
    ).read_text(encoding="utf-8")
    assert "KMS alias authorization boundary" in deployment_guide
    assert "Alias authorization failure" in recovery_guide
    assert "24 — GUG-207 KMS Alias Authorization" in notebook_index


def test_gug210_change_set_iam_binding_evidence_is_registered() -> None:
    required_documents = (
        REPO_ROOT / "ADR/ADR-038-cloudformation-changeset-iam-binding.md",
        REPO_ROOT / "docs/security/gug-210-changeset-iam-binding-threat-model-delta.md",
        REPO_ROOT / "_NotebookLM_Brain/27_GUG210_ChangeSet_IAM_Binding.md",
    )
    for document in required_documents:
        assert document.is_file(), document
        content = document.read_text(encoding="utf-8")
        assert "cloudformation:ChangeSetName" in content
        assert "Change Set ARN" in content
        assert "Production" in content and "NO-GO" in content

    deployment_guide = (
        REPO_ROOT / "docs/deployment/platform-authority-account-bootstrap.md"
    ).read_text(encoding="utf-8")
    recovery_guide = (
        REPO_ROOT / "docs/operations/platform-authority-bootstrap-recovery.md"
    ).read_text(encoding="utf-8")
    notebook_index = (
        REPO_ROOT / "_NotebookLM_Brain/00_INDEX_AND_SOURCE_MAP.md"
    ).read_text(encoding="utf-8")
    assert "GUG-210 supported Change Set IAM binding" in deployment_guide
    assert "Change Set IAM binding failure" in recovery_guide
    assert "GUG-215 is the sole retirement authority" in recovery_guide
    assert "Before execution, remove the unexecuted Change Set" not in recovery_guide
    assert "27 — GUG-210 Change Set IAM Binding" in notebook_index
