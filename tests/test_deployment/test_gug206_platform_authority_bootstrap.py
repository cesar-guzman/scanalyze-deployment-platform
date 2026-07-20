"""GUG-206 dedicated platform-authority bootstrap security contracts."""
from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import os
import subprocess
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

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
    assert "--no-disable-rollback" in cli
    assert "operational output must be outside the repository" in cli
    assert "os.O_EXCL" in cli
    assert "0o600" in cli
    assert "cloudformation\",\n        \"execute-change-set" in cli
    assert "put-public-access-block" in cli
    assert "review stack is not empty; cancel is forbidden" in cli
    assert "delete-stack" not in cli
    assert "no stack or resources deleted" in cli
    assert "delete-bucket" not in cli
    assert "--profile" not in cli


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
    assert "27 — GUG-210 Change Set IAM Binding" in notebook_index
