"""Structural least-privilege tests for the GUG-365 child-role boundaries.

These tests are offline. They prove that the GUG-363 CloudFormation template
cannot create or mutate child IAM roles and that each precreated role remains
capped by a class-specific managed permissions boundary.
"""

from __future__ import annotations

from fnmatch import fnmatchcase
import json
from pathlib import Path
import re
from typing import Any, Iterable, Mapping

import yaml


ROOT = Path(__file__).resolve().parents[2]
TEMPLATE_PATH = (
    ROOT
    / "bootstrap"
    / "cfn-platform-authority-change-set-retirement-ledger.yaml"
)
POLICY_ROOT = ROOT / "policies" / "iam"
POLICY_PATH = "/scanalyze/platform-authority/"
IAM_MANAGED_POLICY_CHARACTER_LIMIT = 6_144

ROLE_CLASSES = {"broker", "classifier-invoker", "approver-invoker", "proof"}
POLICY_FILES = {
    role_class: (
        POLICY_ROOT
        / f"platform-authority-gug365-{role_class}-boundary.json"
    )
    for role_class in ROLE_CLASSES
}
PLAN_BOUND_PLACEHOLDERS = {
    "broker": {
        "authority_account_id",
        "aws_partition",
        "broker_function_arn",
        "change_set_name",
        "identity_center_application_arn",
        "region",
        "retirement_id",
    },
    "classifier-invoker": {"classifier_function_arn"},
    "approver-invoker": {
        "approver_reconcile_function_arn",
        "approver_retire_function_arn",
    },
    "proof": set(),
}
PRIVILEGE_ESCALATION_ACTIONS = {
    "cloudformation:CreateStack",
    "cloudformation:ExecuteChangeSet",
    "iam:AttachRolePolicy",
    "iam:CreatePolicyVersion",
    "iam:CreateRole",
    "iam:PassRole",
    "iam:PutRolePolicy",
    "kms:PutKeyPolicy",
    "lambda:UpdateFunctionCode",
    "s3:PutObject",
    "sts:AssumeRoleWithSAML",
}
SYNTHETIC_RENDER_VALUES = {
    "aws_partition": "aws",
    "region": "us-east-1",
    "authority_account_id": "111122223333",
    "change_set_name": "scanalyze-platform-authority-bootstrap-20300101000500",
    "retirement_id": "gug215#sha256:" + "1" * 64,
    "identity_center_application_arn": (
        "arn:aws:sso::111122223333:application/"
        "ssoins-A1B2C3D4E5F6G7H8/apl-Z9Y8X7W6V5U4T3S2"
    ),
    "broker_function_arn": (
        "arn:aws:lambda:us-east-1:111122223333:function:"
        "scanalyze-platform-authority-gug215-retirement"
    ),
    "classifier_function_arn": (
        "arn:aws:lambda:us-east-1:111122223333:function:"
        "scanalyze-platform-authority-gug215-retirement:single-classify"
    ),
    "approver_retire_function_arn": (
        "arn:aws:lambda:us-east-1:111122223333:function:"
        "scanalyze-platform-authority-gug215-retirement:single-retire"
    ),
    "approver_reconcile_function_arn": (
        "arn:aws:lambda:us-east-1:111122223333:function:"
        "scanalyze-platform-authority-gug215-retirement:single-reconcile"
    ),
}


class _CloudFormationLoader(yaml.SafeLoader):
    pass


def _construct_intrinsic(
    loader: yaml.SafeLoader,
    tag_suffix: str,
    node: yaml.Node,
) -> object:
    if isinstance(node, yaml.ScalarNode):
        value: object = loader.construct_scalar(node)
    elif isinstance(node, yaml.SequenceNode):
        value = loader.construct_sequence(node, deep=True)
    else:
        value = loader.construct_mapping(node, deep=True)
    return {tag_suffix: value}


_CloudFormationLoader.add_multi_constructor("!", _construct_intrinsic)


def _template() -> Mapping[str, Any]:
    value = yaml.load(
        TEMPLATE_PATH.read_text(encoding="utf-8"),
        Loader=_CloudFormationLoader,
    )
    assert isinstance(value, Mapping)
    return value


def _policies() -> dict[str, Mapping[str, Any]]:
    return {
        role_class: json.loads(path.read_text(encoding="utf-8"))
        for role_class, path in POLICY_FILES.items()
    }


def _items(value: str | Iterable[str]) -> tuple[str, ...]:
    if isinstance(value, str):
        return (value,)
    return tuple(value)


def _effect_actions(policy: Mapping[str, Any], effect: str) -> set[str]:
    actions: set[str] = set()
    for statement in policy["Statement"]:
        if statement["Effect"] == effect:
            actions.update(_items(statement["Action"]))
    return actions


def _action_matches(pattern: str, action: str) -> bool:
    return fnmatchcase(action.lower(), pattern.lower())


def _resource_matches(pattern: str, resource: str) -> bool:
    return fnmatchcase(resource, pattern)


def _boundary_allows(
    policy: Mapping[str, Any],
    *,
    action: str,
    resource: str,
    context: Mapping[str, str] | None = None,
) -> bool:
    """Evaluate the action/resource cap; conditions can only narrow this result."""

    denied = False
    allowed = False
    request_context = {} if context is None else context
    for statement in policy["Statement"]:
        actions = _items(statement["Action"])
        resources = _items(statement["Resource"])
        matches = any(_action_matches(item, action) for item in actions) and any(
            _resource_matches(item, resource) for item in resources
        )
        source_function = (
            statement.get("Condition", {})
            .get("ArnEquals", {})
            .get("lambda:SourceFunctionArn")
        )
        if source_function is not None:
            matches = matches and (
                request_context.get("lambda:SourceFunctionArn")
                == source_function
            )
        if matches and statement["Effect"] == "Deny":
            denied = True
        if matches and statement["Effect"] == "Allow":
            allowed = True
    return allowed and not denied


def test_cloudformation_graph_has_no_child_iam_or_dynamodb_mutation() -> None:
    resources = _template()["Resources"]
    assert len(resources) == 26
    assert not {
        value["Type"]
        for value in resources.values()
    }.intersection(
        {"AWS::IAM::Role", "AWS::DynamoDB::Table", "AWS::Lambda::Function"}
    )
    source = TEMPLATE_PATH.read_text(encoding="utf-8")
    assert "ResourcePolicy:" not in source
    assert "dynamodb:PutResourcePolicy" not in source
    assert "PermissionsBoundary:" not in source
    assert "!GetAtt RetirementBrokerExecutionRole" not in source
    assert "!GetAtt ClassifierInvokerRole" not in source
    assert "!GetAtt ApproverInvokerRole" not in source
    assert "!Ref ChangeSetRetirementLedger" not in source
    assert "AWS::Lambda::Function" not in source
    assert source.count(
        "Principal: !Sub arn:${AWS::Partition}:iam::${AuthorityAccountId}:"
        "role/ScanalyzeGug215ClassifierInvoker"
    ) == 4
    assert source.count(
        "Principal: !Sub arn:${AWS::Partition}:iam::${AuthorityAccountId}:"
        "role/ScanalyzeGug215ApproverInvoker"
    ) == 8


def test_class_specific_boundaries_have_no_authority_union() -> None:
    policies = _policies()

    for boundary in policies.values():
        assert "NotAction" not in json.dumps(boundary)
        assert "NotResource" not in json.dumps(boundary)
        assert "*" not in _effect_actions(boundary, "Allow")

    classifier_resources = {
        resource
        for statement in policies["classifier-invoker"]["Statement"]
        if statement["Effect"] == "Allow"
        for resource in _items(statement["Resource"])
    }
    approver_resources = {
        resource
        for statement in policies["approver-invoker"]["Statement"]
        if statement["Effect"] == "Allow"
        for resource in _items(statement["Resource"])
    }
    assert classifier_resources == {"${classifier_function_arn}"}
    assert approver_resources == {
        "${approver_retire_function_arn}",
        "${approver_reconcile_function_arn}",
    }
    assert classifier_resources.isdisjoint(approver_resources)
    assert _effect_actions(policies["proof"], "Allow") == set()


def test_malicious_action_wildcard_cannot_escape_any_boundary() -> None:
    malicious_inline = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "*",
                "Resource": "*",
            }
        ],
    }
    assert _action_matches(
        malicious_inline["Statement"][0]["Action"],
        "iam:CreateRole",
    )

    for role_class, boundary in _policies().items():
        for action in PRIVILEGE_ESCALATION_ACTIONS:
            assert not _boundary_allows(
                boundary,
                action=action,
                resource="*",
            ), f"{role_class} boundary leaked {action}"


def test_broker_boundary_requires_exact_lambda_source_on_every_allow() -> None:
    boundary = _policies()["broker"]
    expected_source = "${broker_function_arn}"
    for statement in boundary["Statement"]:
        if statement["Effect"] == "Allow":
            assert statement["Condition"]["ArnEquals"] == {
                "lambda:SourceFunctionArn": expected_source
            }

    delete_statement = next(
        statement
        for statement in boundary["Statement"]
        if statement["Sid"] == "DeleteOnlyExactRecoveryChangeSet"
    )
    exact_stack = str(delete_statement["Resource"])
    assert not _boundary_allows(
        boundary,
        action="cloudformation:DeleteChangeSet",
        resource=exact_stack,
        context={},
    )
    assert not _boundary_allows(
        boundary,
        action="cloudformation:DeleteChangeSet",
        resource=exact_stack,
        context={"lambda:SourceFunctionArn": "arn:aws:lambda:foreign"},
    )


def test_boundary_templates_use_only_plan_bindings_and_fit_iam_limit() -> None:
    placeholder_pattern = re.compile(r"\$\{([a-z0-9_]+)\}")
    for role_class, policy in _policies().items():
        serialized = json.dumps(policy, sort_keys=True, separators=(",", ":"))
        placeholders = set(placeholder_pattern.findall(serialized))
        assert placeholders == PLAN_BOUND_PLACEHOLDERS[role_class]
        rendered = serialized
        for placeholder in placeholders:
            rendered = rendered.replace(
                "${" + placeholder + "}",
                SYNTHETIC_RENDER_VALUES[placeholder],
            )
        assert "${" not in rendered
        assert len(rendered) <= IAM_MANAGED_POLICY_CHARACTER_LIMIT

        for statement in policy["Statement"]:
            if statement["Effect"] != "Allow":
                continue
            if statement["Resource"] == "*":
                assert set(_items(statement["Action"])) <= {
                    "kms:DescribeKey",
                    "s3:GetAccountPublicAccessBlock",
                }
