"""Static least-privilege checks for the dedicated GUG-93 role templates."""

from __future__ import annotations

import json
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parent.parent
POLICY_DIR = REPO_ROOT / "policies" / "iam"
GLOBAL_IAM_PATH = REPO_ROOT / "modules" / "global" / "iam.tf"

DESTRUCTIVE_IDENTITY_ACTIONS = {
    "cloudwatch:DeleteAlarms",
    "cognito-idp:DeleteGroup",
    "cognito-idp:DeleteResourceServer",
    "cognito-idp:DeleteUserPool",
    "cognito-idp:DeleteUserPoolClient",
    "cognito-idp:DeleteUserPoolDomain",
    "dynamodb:DeleteTable",
    "iam:DeletePolicy",
    "iam:DeleteRole",
    "iam:DeleteRolePolicy",
    "kms:DeleteAlias",
    "kms:DisableKey",
    "kms:ScheduleKeyDeletion",
    "lambda:DeleteAlias",
    "lambda:DeleteFunction",
    "lambda:RemovePermission",
    "logs:DeleteLogGroup",
    "logs:DeleteMetricFilter",
    "logs:DeleteRetentionPolicy",
    "secretsmanager:DeleteSecret",
    "sqs:DeleteQueue",
    "sqs:PurgeQueue",
}

CLOUDWATCH_ALARM_MANAGEMENT_ACTIONS = {
    "cloudwatch:ListTagsForResource",
    "cloudwatch:PutMetricAlarm",
    "cloudwatch:TagResource",
    "cloudwatch:UntagResource",
}


def _load(name: str) -> dict:
    return json.loads((POLICY_DIR / name).read_text(encoding="utf-8"))


def _actions(statement: dict) -> set[str]:
    value = statement["Action"]
    return {value} if isinstance(value, str) else set(value)


def test_identity_apply_role_never_uses_wildcard_actions() -> None:
    policy = _load("identity-control-plane-apply-role.json")

    for statement in policy["Statement"]:
        if statement["Effect"] == "Deny":
            continue
        actions = _actions(statement)
        assert "*" not in actions
        assert all(not action.endswith(":*") for action in actions)


def test_identity_apply_role_has_only_reviewed_wildcard_resource_exceptions() -> None:
    policy = _load("identity-control-plane-apply-role.json")
    wildcard_sids = {
        statement["Sid"]
        for statement in policy["Statement"]
        if statement.get("Resource") == "*"
    }

    assert wildcard_sids == {
        "CreateTaggedUserPool",
        "CreateTaggedIdentityEncryptionKey",
        "DescribeIdentityMonitoring",
        "DenyIdentityDestructionOutsideReviewedDecommission",
        "DenyPrivilegeEscalationAndHumanAdministration",
    }

    allow_statements = {
        statement["Sid"]: statement
        for statement in policy["Statement"]
        if statement["Effect"] == "Allow"
    }
    assert "Condition" in allow_statements["CreateTaggedUserPool"]
    assert "Condition" in allow_statements["CreateTaggedIdentityEncryptionKey"]


def test_identity_role_templates_are_partition_portable() -> None:
    for name in (
        "identity-control-plane-plan-role.json",
        "identity-control-plane-apply-role.json",
    ):
        serialized = json.dumps(_load(name), sort_keys=True)
        assert "arn:aws:" not in serialized
        assert "arn:${aws_partition}:" in serialized


def test_identity_apply_role_cannot_administer_users_or_export_secrets() -> None:
    policy = _load("identity-control-plane-apply-role.json")
    allowed = set().union(
        *(
            _actions(statement)
            for statement in policy["Statement"]
            if statement["Effect"] == "Allow"
        )
    )

    assert "cognito-idp:AdminCreateUser" not in allowed
    assert "cognito-idp:AdminSetUserPassword" not in allowed
    assert "secretsmanager:GetSecretValue" not in allowed
    assert "secretsmanager:PutSecretValue" not in allowed
    assert "iam:AttachRolePolicy" not in allowed


def test_identity_apply_role_denies_destructive_decommission_actions() -> None:
    policy = _load("identity-control-plane-apply-role.json")
    allowed = set().union(
        *(
            _actions(statement)
            for statement in policy["Statement"]
            if statement["Effect"] == "Allow"
        )
    )
    explicit_denies = set().union(
        *(
            _actions(statement)
            for statement in policy["Statement"]
            if statement["Effect"] == "Deny"
        )
    )

    assert allowed.isdisjoint(DESTRUCTIVE_IDENTITY_ACTIONS)
    assert DESTRUCTIVE_IDENTITY_ACTIONS <= explicit_denies
    # Terraform's S3 lock cleanup is the only reviewed delete operation in the
    # regular apply role and is bound to the exact .tflock object.
    delete_object_statements = [
        statement
        for statement in policy["Statement"]
        if "s3:DeleteObject" in _actions(statement)
    ]
    assert len(delete_object_statements) == 1
    assert delete_object_statements[0]["Resource"].endswith("terraform.tfstate.tflock")


def test_identity_apply_role_can_reconcile_tags_on_exact_alarm_family() -> None:
    policy = _load("identity-control-plane-apply-role.json")
    statement = next(
        item for item in policy["Statement"] if item["Sid"] == "ManageIdentityAlarms"
    )

    assert statement["Effect"] == "Allow"
    assert _actions(statement) == CLOUDWATCH_ALARM_MANAGEMENT_ACTIONS
    assert statement["Resource"] == (
        "arn:${aws_partition}:cloudwatch:${region}:${account_id}:"
        "alarm:${deployment_id}-identity-*"
    )

    destructive_deny = next(
        item
        for item in policy["Statement"]
        if item["Sid"] == "DenyIdentityDestructionOutsideReviewedDecommission"
    )
    assert destructive_deny["Effect"] == "Deny"
    assert destructive_deny["Resource"] == "*"
    assert "cloudwatch:DeleteAlarms" in _actions(destructive_deny)


def test_orchestrator_and_break_glass_treat_identity_roles_explicitly() -> None:
    orchestrator = json.dumps(_load("orchestrator-role.json"), sort_keys=True)
    break_glass = json.dumps(_load("break-glass-role.json"), sort_keys=True)

    for role in (
        "ScanalyzeCustomer-Identity-Plan",
        "ScanalyzeCustomer-Identity-Apply",
    ):
        assert role in orchestrator
        assert role in break_glass


def test_identity_runtime_boundary_allows_required_secret_cmk_operations() -> None:
    """The boundary must not silently remove permissions required by escrow.

    Secrets Manager requires GenerateDataKey and Decrypt when CreateSecret uses
    a customer-managed KMS key. The execution role is narrower, but the global
    boundary must still admit the complete reviewed intersection.
    """

    source = GLOBAL_IAM_PATH.read_text(encoding="utf-8")
    statement = source.split('Sid    = "TaggedIdentityEncryptionOnly"', 1)[1]
    statement = statement.split("},", 1)[0]

    assert '"kms:Decrypt"' in statement
    assert '"kms:Encrypt"' in statement
    assert '"kms:GenerateDataKey"' in statement
