from __future__ import annotations

import json
from hashlib import sha256
from pathlib import Path

from tooling.platform_authority_gug365_upstream_inventory import (
    READ_ONLY_ACTION_ALLOWLIST,
)


ROOT = Path(__file__).resolve().parents[2]
POLICY_PATHS = (
    ROOT
    / "policies/iam/platform-authority-gug376-authority-inventory-read-only.json",
    ROOT
    / "policies/iam/platform-authority-gug376-identity-center-inventory-read-only.json",
)

WRITE_VERBS = (
    "Add",
    "Attach",
    "Cancel",
    "Create",
    "Delete",
    "Detach",
    "Disable",
    "Enable",
    "Execute",
    "Invoke",
    "Provision",
    "Put",
    "Remove",
    "Revoke",
    "Start",
    "Tag",
    "Untag",
    "Update",
)

EXPECTED_AUTHORITY_POLICY_SHA256 = (
    "7e0de088559d9c13d28e446cc97d246e58eafe45c71d2e261893dc0ce235ddf0"
)
EXPECTED_IDENTITY_POLICY_SHA256 = (
    "6de56114672327b7fa39e65d00aa01d84abad2eec19c41990a13852dc083371d"
)


def _load(path: Path) -> dict[str, object]:
    return json.loads(path.read_text(encoding="utf-8"))


def _actions(statement: dict[str, object], key: str) -> list[str]:
    value = statement.get(key, [])
    return [value] if isinstance(value, str) else list(value)


def test_inventory_policies_are_read_only_closed_and_time_bounded() -> None:
    for path in POLICY_PATHS:
        policy = _load(path)
        statements = policy["Statement"]
        allow_actions = {
            action
            for statement in statements
            if statement["Effect"] == "Allow"
            for action in _actions(statement, "Action")
        }
        deny_not_action = next(
            statement
            for statement in statements
            if statement["Sid"] == "DenyEveryUnreviewedAction"
        )
        assert allow_actions == set(_actions(deny_not_action, "NotAction"))
        assert "sts:GetCallerIdentity" in allow_actions
        assert not any(
            action.split(":", 1)[1].startswith(WRITE_VERBS)
            for action in allow_actions
        )
        assert {
            statement["Sid"] for statement in statements
        } >= {
            "ConfirmOnlyTheCurrentCaller",
            "DenyAllActionsBeforeAbsoluteStart",
            "DenyAllActionsAtAbsoluteExpiry",
            "DenyEveryUnreviewedAction",
        }


def test_inventory_policy_bytes_are_review_bound() -> None:
    assert sha256(POLICY_PATHS[0].read_bytes()).hexdigest() == (
        EXPECTED_AUTHORITY_POLICY_SHA256
    )


def test_inventory_code_allowlist_matches_both_reviewed_policies_exactly() -> None:
    policy_actions = {
        action
        for path in POLICY_PATHS
        for statement in _load(path)["Statement"]
        if statement["Effect"] == "Allow"
        for action in _actions(statement, "Action")
    }

    assert policy_actions == set(READ_ONLY_ACTION_ALLOWLIST)
    assert sha256(POLICY_PATHS[1].read_bytes()).hexdigest() == (
        EXPECTED_IDENTITY_POLICY_SHA256
    )


def test_authority_inventory_has_exact_required_surfaces() -> None:
    policy = _load(POLICY_PATHS[0])
    allowed = {
        action
        for statement in policy["Statement"]
        if statement["Effect"] == "Allow"
        for action in _actions(statement, "Action")
    }
    assert {
        "kms:GetKeyPolicy",
        "lambda:GetRuntimeManagementConfig",
        "s3:ListBucketVersions",
        "signer:DescribeSigningJob",
        "signer:GetSigningProfile",
        "signer:ListSigningJobs",
    }.issubset(allowed)
    assert "s3:GetObjectVersionAttributes" not in allowed


def test_authority_decrypt_is_bound_to_exact_s3_bucket_context() -> None:
    policy = _load(POLICY_PATHS[0])
    decrypt = next(
        statement
        for statement in policy["Statement"]
        if statement["Sid"] == "DecryptOnlyThroughExactArtifactBucket"
    )

    assert decrypt["Effect"] == "Allow"
    assert decrypt["Action"] == "kms:Decrypt"
    assert decrypt["Resource"] == "${artifact_kms_key_arn}"
    assert decrypt["Condition"]["StringEquals"] == {
        "aws:RequestedRegion": "us-east-1",
        "kms:EncryptionContext:aws:s3:arn": "${artifact_bucket_arn}",
        "kms:ViaService": "s3.us-east-1.amazonaws.com",
    }
    assert decrypt["Condition"]["DateGreaterThanEquals"] == {
        "aws:CurrentTime": "${inventory_not_before}"
    }
    assert decrypt["Condition"]["DateLessThan"] == {
        "aws:CurrentTime": "${inventory_not_after}"
    }


def test_identity_center_inventory_has_exact_required_surfaces() -> None:
    policy = _load(POLICY_PATHS[1])
    allowed = {
        action
        for statement in policy["Statement"]
        if statement["Effect"] == "Allow"
        for action in _actions(statement, "Action")
    }
    assert {
        "identitystore:DescribeUser",
        "sso:DescribeApplication",
        "sso:GetInlinePolicyForPermissionSet",
        "sso:ListAccountAssignments",
        "sso:ListApplicationAssignments",
        "sso:ListPermissionSetProvisioningStatus",
    }.issubset(allowed)
    assert "sso:ListUsers" not in allowed
