"""The additive supplement narrows new grants, not unrelated existing grants."""

from __future__ import annotations

import ast
import json
from pathlib import Path
import re
from typing import Any

import pytest


REPO_ROOT = Path(__file__).resolve().parents[2]
TEMPLATE_PATH = (
    REPO_ROOT
    / "policies/iam/platform-authority-plan-seed-management-read-supplement.json"
)
SNAPSHOT_PATH = (
    REPO_ROOT
    / "tooling/platform_authority_plan_permission_repair_plan_seed_snapshot.py"
)
EXPECTED_ACTIONS = {
    "identitystore:DescribeUser",
    "sso:DescribeAccountAssignmentCreationStatus",
    "sso:DescribeAccountAssignmentDeletionStatus",
    "sso:DescribeInstance",
    "sso:DescribePermissionSet",
    "sso:DescribePermissionSetProvisioningStatus",
    "sso:GetInlinePolicyForPermissionSet",
    "sso:GetPermissionsBoundaryForPermissionSet",
    "sso:ListAccountAssignmentCreationStatus",
    "sso:ListAccountAssignmentDeletionStatus",
    "sso:ListAccountAssignments",
    "sso:ListAccountsForProvisionedPermissionSet",
    "sso:ListCustomerManagedPolicyReferencesInPermissionSet",
    "sso:ListInstances",
    "sso:ListManagedPoliciesInPermissionSet",
    "sso:ListPermissionSetProvisioningStatus",
    "sso:ListPermissionSets",
    "sso:ListTagsForResource",
}
EXPECTED_CONDITIONS = {
    "StringEquals": {
        "aws:PrincipalAccount": "${management_account_id}",
        "aws:RequestedRegion": "${region}",
    },
    "DateGreaterThanEquals": {"aws:CurrentTime": "${not_before}"},
    "DateLessThan": {"aws:CurrentTime": "${not_after}"},
}


def _policy() -> dict[str, Any]:
    return json.loads(TEMPLATE_PATH.read_text(encoding="utf-8"))


def _actions(statement: dict[str, Any]) -> list[str]:
    value = statement["Action"]
    return [value] if isinstance(value, str) else value


def _statement(action: str) -> dict[str, Any]:
    matches = [item for item in _policy()["Statement"] if action in _actions(item)]
    assert len(matches) == 1
    return matches[0]


def test_exact_read_operation_set_without_duplicate_grants() -> None:
    policy = _policy()
    assert set(policy) == {"Version", "Statement"}
    assert policy["Version"] == "2012-10-17"
    assert len(policy["Statement"]) == 8
    assert len({item["Sid"] for item in policy["Statement"]}) == 8
    actions = [action for item in policy["Statement"] for action in _actions(item)]
    assert set(actions) == EXPECTED_ACTIONS
    assert len(actions) == len(EXPECTED_ACTIONS) == 18


def test_covers_the_snapshot_producer_management_read_calls() -> None:
    """Track literal calls and all six dynamically dispatched status reads."""
    source = ast.parse(SNAPSHOT_PATH.read_text(encoding="utf-8"))
    functions = {
        node.name: node
        for node in source.body
        if isinstance(node, ast.FunctionDef)
    }
    methods: set[str] = set()
    for name in ("_describe_instance", "_permission_set"):
        for node in ast.walk(functions[name]):
            if not isinstance(node, ast.Call):
                continue
            if isinstance(node.func, ast.Name) and node.func.id == "_paginate_token":
                method = node.args[2]
            elif isinstance(node.func, ast.Attribute) and node.func.attr == "call":
                method = node.args[0]
            else:
                continue
            assert isinstance(method, ast.Constant) and isinstance(method.value, str)
            methods.add(method.value)
    for node in ast.walk(functions["_pending_operations"]):
        if not isinstance(node, ast.Assign):
            continue
        if not any(isinstance(t, ast.Name) and t.id == "specifications" for t in node.targets):
            continue
        for specification in ast.literal_eval(node.value):
            methods.update((specification[0], specification[2]))
    actions = {
        ("identitystore:" if method == "describe_user" else "sso:")
        + "".join(part.capitalize() for part in method.split("_"))
        for method in methods
    }
    assert actions == EXPECTED_ACTIONS


@pytest.mark.parametrize("index", range(8))
def test_every_grant_is_additive_and_account_region_time_bounded(index: int) -> None:
    statement = _policy()["Statement"][index]
    assert set(statement) == {"Sid", "Effect", "Action", "Resource", "Condition"}
    assert statement["Effect"] == "Allow"
    assert statement["Condition"] == EXPECTED_CONDITIONS
    assert all("*" not in action and "?" not in action for action in _actions(statement))


def test_no_shared_account_deny_or_implicit_allowlist_boundary() -> None:
    # Attaching this supplement must not deny other existing shared-role grants.
    for statement in _policy()["Statement"]:
        assert statement["Effect"] != "Deny"
        assert "NotAction" not in statement
        assert "NotResource" not in statement
        assert "Principal" not in statement
        assert "NotPrincipal" not in statement


def test_only_service_discovery_has_a_global_resource() -> None:
    global_actions = {
        action
        for item in _policy()["Statement"]
        if item["Resource"] == "*"
        for action in _actions(item)
    }
    assert global_actions == {"sso:ListInstances"}
    wildcard_resources = []
    for item in _policy()["Statement"]:
        value = item["Resource"]
        resources = [value] if isinstance(value, str) else value
        for resource in resources:
            assert "?" not in resource
            if "*" in resource:
                wildcard_resources.append((_actions(item), resource))
    assert wildcard_resources == [
        (["sso:ListInstances"], "*"),
        (
            ["sso:DescribePermissionSet"],
            "arn:aws:sso:::permissionSet/${identity_center_instance_id}/*",
        ),
    ]


@pytest.mark.parametrize("action", ["sso:DescribeInstance", "sso:ListPermissionSets"])
def test_instance_discovery_is_bound_to_the_exact_instance(action: str) -> None:
    assert _statement(action)["Resource"] == "${identity_center_instance_arn}"


def test_candidate_description_covers_required_instance_and_candidate_types() -> None:
    assert _statement("sso:DescribePermissionSet")["Resource"] == [
        "${identity_center_instance_arn}",
        "arn:aws:sso:::permissionSet/${identity_center_instance_id}/*",
    ]


@pytest.mark.parametrize(
    "action",
    [
        "sso:GetInlinePolicyForPermissionSet",
        "sso:GetPermissionsBoundaryForPermissionSet",
        "sso:ListAccountsForProvisionedPermissionSet",
        "sso:ListCustomerManagedPolicyReferencesInPermissionSet",
        "sso:ListManagedPoliciesInPermissionSet",
    ],
)
def test_policy_contents_require_exact_plan_and_instance_resources(action: str) -> None:
    assert _statement(action)["Resource"] == [
        "${identity_center_instance_arn}",
        "${plan_permission_set_arn}",
    ]


def test_tags_are_limited_to_the_selected_plan_permission_set() -> None:
    assert _statement("sso:ListTagsForResource")["Resource"] == "${plan_permission_set_arn}"


def test_assignments_include_all_three_required_resource_types() -> None:
    assert _statement("sso:ListAccountAssignments")["Resource"] == [
        "arn:aws:sso:::account/${authority_account_id}",
        "${identity_center_instance_arn}",
        "${plan_permission_set_arn}",
    ]


@pytest.mark.parametrize(
    "action",
    [
        "sso:DescribeAccountAssignmentCreationStatus",
        "sso:DescribeAccountAssignmentDeletionStatus",
        "sso:DescribePermissionSetProvisioningStatus",
        "sso:ListAccountAssignmentCreationStatus",
        "sso:ListAccountAssignmentDeletionStatus",
        "sso:ListPermissionSetProvisioningStatus",
    ],
)
def test_pending_operation_reads_are_bound_to_exact_instance(action: str) -> None:
    assert _statement(action)["Resource"] == "${identity_center_instance_arn}"


def test_user_read_requires_both_exact_identity_store_and_user_resources() -> None:
    # AWS Identity Store SAR requires both resource types for DescribeUser.
    assert _statement("identitystore:DescribeUser")["Resource"] == [
        "${identity_store_arn}",
        "${principal_user_arn}",
    ]


def test_private_bindings_remain_explicit_unfilled_template_parameters() -> None:
    serialized = TEMPLATE_PATH.read_text(encoding="utf-8")
    assert set(re.findall(r"\$\{([a-z_]+)\}", serialized)) == {
        "management_account_id",
        "authority_account_id",
        "region",
        "not_before",
        "not_after",
        "identity_center_instance_arn",
        "identity_center_instance_id",
        "plan_permission_set_arn",
        "identity_store_arn",
        "principal_user_arn",
    }
    assert re.search(r"(?<![0-9])[0-9]{12}(?![0-9])", serialized) is None
