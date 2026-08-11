"""Pure, fail-closed GUG-357 Identity Center audit preparation contracts.

This module renders and validates a temporary, strictly read-only permission
policy and produces a sanitized preparation intent.  It has no AWS client, no
subprocess entrypoint, and no create, assign, provision, or revoke operation.
Live materialization and revocation require separate owner authorizations.
"""
from __future__ import annotations

import hashlib
import json
import re
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Mapping

from tooling.platform_authority_lambda_invocation_authority import (
    canonical_digest,
    digest_text,
)


MANAGEMENT_ACCOUNT_ID_DIGEST = (
    "sha256:717e8c0d35281f6d8781b8fdb14210c0abd1c2d945f1f281dcd1f26dc44f4679"
)
AUTHORITY_ACCOUNT_ID_DIGEST = (
    "sha256:9eea494bbe2b8bfff5b8ec4fe55e95ed4dc0b956977a550a5b057be80cc0ec86"
)
IDENTITY_CENTER_REGION = "us-east-1"
ISSUE_ID = "GUG-357"
PERMISSION_SET_NAME = "ScanalyzeGug357IdentityAudit"
PERMISSION_SET_DESCRIPTION = (
    "GUG-357 temporary read-only IAM Identity Center audit; no approval or "
    "execution duty"
)
SESSION_DURATION = "PT1H"
INTENT_TTL = timedelta(minutes=15)
MAX_AUDIT_TTL = timedelta(hours=4)
POLICY_TEMPLATE_PATH = Path(
    "policies/iam/platform-authority-gug357-identity-center-audit-role.json"
)
CLASSIFIER_PERMISSION_SET_NAME = "ScanalyzeAuthorityRetireClass"
APPROVER_PERMISSION_SET_NAME = "ScanalyzeAuthorityRetireApprove"
BASE_TAGS = {
    "managed_by": "scanalyze",
    "work_package": ISSUE_ID,
    "purpose": "identity-center-read-only-audit",
    "lifecycle": "temporary",
    "production": "NO-GO",
}

ALLOWED_ACTIONS = frozenset(
    {
        "identitystore:DescribeUser",
        "sso:DescribeAccountAssignmentCreationStatus",
        "sso:DescribeAccountAssignmentDeletionStatus",
        "sso:DescribeApplication",
        "sso:DescribeInstance",
        "sso:DescribePermissionSet",
        "sso:DescribePermissionSetProvisioningStatus",
        "sso:GetApplicationAccessScope",
        "sso:GetApplicationAssignmentConfiguration",
        "sso:GetApplicationAuthenticationMethod",
        "sso:GetApplicationGrant",
        "sso:GetInlinePolicyForPermissionSet",
        "sso:GetPermissionsBoundaryForPermissionSet",
        "sso:ListAccountAssignmentCreationStatus",
        "sso:ListAccountAssignmentDeletionStatus",
        "sso:ListAccountAssignments",
        "sso:ListAccountsForProvisionedPermissionSet",
        "sso:ListApplicationAccessScopes",
        "sso:ListApplicationAssignments",
        "sso:ListApplicationAuthenticationMethods",
        "sso:ListApplicationGrants",
        "sso:ListCustomerManagedPolicyReferencesInPermissionSet",
        "sso:ListInstances",
        "sso:ListManagedPoliciesInPermissionSet",
        "sso:ListPermissionSetProvisioningStatus",
        "sso:ListPermissionSets",
        "sso:ListTagsForResource",
        "sts:GetCallerIdentity",
    }
)
DUAL_AUTH_COMPATIBILITY_EXEMPTIONS = frozenset(
    {
        "sso-directory:DescribeUser",
        "sso-directory:DescribeUsers",
        "sso:DescribePermissionsPolicies",
        "sso:GetApplicationInstance",
        "sso:GetManagedApplicationInstance",
        "sso:GetPermissionSet",
        "sso:GetPermissionsPolicy",
        "sso:GetSharedSsoConfiguration",
        "sso:ListApplicationInstances",
        "sso:ListDirectoryAssociations",
        "sso:ListProfileAssociations",
    }
)
CLOSED_BOUNDARY_ACTIONS = ALLOWED_ACTIONS | DUAL_AUTH_COMPATIBILITY_EXEMPTIONS
EXPECTED_STATEMENT_SIDS = frozenset(
    {
        "ConfirmOnlyTheCurrentCaller",
        "DiscoverSingleIdentityCenterInstance",
        "ReadExactInstanceAndRuntimePermissionSets",
        "ReadExactResourceTags",
        "ReadExactAuthorityAccountAssignments",
        "ReadExactPendingIdentityCenterOperations",
        "ReadExactIdentityContextApplication",
        "ReadOnlyTheTwoApprovedRuntimeUsers",
        "DenyIdentityReadsOutsideHomeRegion",
        "DenyAllActionsBeforeAbsoluteStart",
        "DenyAllActionsAtAbsoluteExpiry",
        "DenyEveryUnreviewedAction",
    }
)
WILDCARD_ALLOW_SIDS = frozenset(
    {"ConfirmOnlyTheCurrentCaller", "DiscoverSingleIdentityCenterInstance"}
)
EXPECTED_ALLOW_ACTIONS_BY_SID = {
    "ConfirmOnlyTheCurrentCaller": frozenset({"sts:GetCallerIdentity"}),
    "DiscoverSingleIdentityCenterInstance": frozenset({"sso:ListInstances"}),
    "ReadExactInstanceAndRuntimePermissionSets": frozenset(
        {
            "sso:DescribeInstance",
            "sso:DescribePermissionSet",
            "sso:GetInlinePolicyForPermissionSet",
            "sso:GetPermissionsBoundaryForPermissionSet",
            "sso:ListAccountsForProvisionedPermissionSet",
            "sso:ListCustomerManagedPolicyReferencesInPermissionSet",
            "sso:ListManagedPoliciesInPermissionSet",
            "sso:ListPermissionSets",
        }
    ),
    "ReadExactResourceTags": frozenset({"sso:ListTagsForResource"}),
    "ReadExactAuthorityAccountAssignments": frozenset(
        {"sso:ListAccountAssignments"}
    ),
    "ReadExactPendingIdentityCenterOperations": frozenset(
        {
            "sso:DescribeAccountAssignmentCreationStatus",
            "sso:DescribeAccountAssignmentDeletionStatus",
            "sso:DescribePermissionSetProvisioningStatus",
            "sso:ListAccountAssignmentCreationStatus",
            "sso:ListAccountAssignmentDeletionStatus",
            "sso:ListPermissionSetProvisioningStatus",
        }
    ),
    "ReadExactIdentityContextApplication": frozenset(
        {
            "sso:DescribeApplication",
            "sso:GetApplicationAccessScope",
            "sso:GetApplicationAssignmentConfiguration",
            "sso:GetApplicationAuthenticationMethod",
            "sso:GetApplicationGrant",
            "sso:ListApplicationAccessScopes",
            "sso:ListApplicationAssignments",
            "sso:ListApplicationAuthenticationMethods",
            "sso:ListApplicationGrants",
        }
    ),
    "ReadOnlyTheTwoApprovedRuntimeUsers": frozenset(
        {"identitystore:DescribeUser"}
    ),
}

_COMMIT = re.compile(r"[a-f0-9]{40}")
_DIGEST = re.compile(r"sha256:[a-f0-9]{64}")
_ACCOUNT_ID = re.compile(r"[0-9]{12}")
_ACCOUNT_ARN = re.compile(r"arn:aws:sso:::account/(?P<account>[0-9]{12})")
_INSTANCE_ARN = re.compile(
    r"arn:aws:sso:::instance/(?P<instance>ssoins-[A-Za-z0-9.-]{16})"
)
_PERMISSION_SET_ARN = re.compile(
    r"arn:aws:sso:::permissionSet/(?P<instance>ssoins-[A-Za-z0-9.-]{16})/"
    r"ps-[A-Za-z0-9-]{16}"
)
_IDENTITY_STORE_ID_PATTERN = (
    r"(?:d-[0-9a-f]{10}|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-"
    r"[0-9a-f]{4}-[0-9a-f]{12})"
)
_USER_ID_PATTERN = (
    r"(?:[0-9a-f]{10}-)?[A-Fa-f0-9]{8}-[A-Fa-f0-9]{4}-"
    r"[A-Fa-f0-9]{4}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{12}"
)
_APPLICATION_ARN = re.compile(
    r"arn:aws:sso::(?P<account>[0-9]{12}):application/"
    r"(?P<instance>ssoins-[A-Za-z0-9.-]{16})/apl-[A-Za-z0-9]{16}"
)
_IDENTITY_STORE_ARN = re.compile(
    r"arn:aws:identitystore::(?P<account>[0-9]{12}):identitystore/"
    rf"(?P<store>{_IDENTITY_STORE_ID_PATTERN})"
)
_USER_ARN = re.compile(
    rf"arn:aws:identitystore:::user/(?P<user>{_USER_ID_PATTERN})"
)
_USER_ID = re.compile(_USER_ID_PATTERN)
_PLACEHOLDER = re.compile(r"\$\{[a-z0-9_]+\}")
_WRITE_VERB = re.compile(
    r":(?:Create|Delete|Update|Put|Attach|Detach|Provision|Tag|Untag|Associate|"
    r"Disassociate|Start|Stop|Enable|Disable|Import|CreateTokenWithIAM)"
)


class IdentityCenterAuditPreparationError(ValueError):
    """Stable, sanitized GUG-357 preparation validation error."""


def _fail(code: str) -> None:
    raise IdentityCenterAuditPreparationError(code)


def _timestamp(value: datetime, *, code: str = "TIMESTAMP_INVALID") -> str:
    if not isinstance(value, datetime) or value.tzinfo is None:
        _fail(code)
    return (
        value.astimezone(UTC)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def _parse_timestamp(value: object, *, code: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        _fail(code)
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        _fail(code)
    if parsed.tzinfo is None:
        _fail(code)
    return parsed.astimezone(UTC)


def _byte_digest(path: Path) -> str:
    try:
        return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError:
        _fail("POLICY_TEMPLATE_UNAVAILABLE")
    raise AssertionError("unreachable")


def _validate_audit_window(*, started_at: datetime, not_after: datetime) -> tuple[str, str]:
    started = _parse_timestamp(
        _timestamp(started_at, code="AUDIT_WINDOW_INVALID"),
        code="AUDIT_WINDOW_INVALID",
    )
    expires = _parse_timestamp(
        _timestamp(not_after, code="AUDIT_WINDOW_INVALID"),
        code="AUDIT_WINDOW_INVALID",
    )
    if not started < expires or expires - started > MAX_AUDIT_TTL:
        _fail("AUDIT_WINDOW_INVALID")
    return _timestamp(started), _timestamp(expires)


def _load_policy_template(repo_root: Path) -> dict[str, Any]:
    path = Path(repo_root).resolve() / POLICY_TEMPLATE_PATH
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        _fail("POLICY_TEMPLATE_UNAVAILABLE")
    if not isinstance(value, dict):
        _fail("POLICY_TEMPLATE_INVALID")
    return value


def _replace_placeholders(value: Any, replacements: Mapping[str, str]) -> Any:
    if isinstance(value, dict):
        return {
            str(key): _replace_placeholders(item, replacements)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [_replace_placeholders(item, replacements) for item in value]
    if isinstance(value, str):
        rendered = value
        for placeholder, replacement in replacements.items():
            rendered = rendered.replace("${" + placeholder + "}", replacement)
        return rendered
    return value


def _action_set(value: object) -> set[str]:
    if isinstance(value, str):
        return {value}
    if isinstance(value, list) and all(isinstance(item, str) for item in value):
        return set(value)
    _fail("POLICY_ACTION_SHAPE_INVALID")
    raise AssertionError("unreachable")


def _resource_set(value: object) -> set[str]:
    if isinstance(value, str):
        return {value}
    if isinstance(value, list) and all(isinstance(item, str) for item in value):
        return set(value)
    _fail("POLICY_RESOURCE_SHAPE_INVALID")
    raise AssertionError("unreachable")


def _validate_account_id(*, value: str, expected_digest: str, code: str) -> None:
    if (
        not isinstance(value, str)
        or _ACCOUNT_ID.fullmatch(value) is None
        or digest_text(value) != expected_digest
    ):
        _fail(code)


def render_audit_policy(
    *,
    repo_root: Path,
    audit_started_at: datetime,
    audit_not_after: datetime,
    management_account_id: str,
    authority_account_id: str,
    identity_center_instance_arn: str,
    runtime_classifier_permission_set_arn: str,
    runtime_approver_permission_set_arn: str,
    identity_center_application_arn: str,
    identity_store_arn: str,
    runtime_classifier_user_arn: str,
    runtime_approver_user_arn: str,
) -> dict[str, Any]:
    """Render one exact, bounded read-only policy from private identifiers."""

    _, expiry = _validate_audit_window(
        started_at=audit_started_at,
        not_after=audit_not_after,
    )
    _validate_account_id(
        value=management_account_id,
        expected_digest=MANAGEMENT_ACCOUNT_ID_DIGEST,
        code="MANAGEMENT_ACCOUNT_BINDING_INVALID",
    )
    _validate_account_id(
        value=authority_account_id,
        expected_digest=AUTHORITY_ACCOUNT_ID_DIGEST,
        code="AUTHORITY_ACCOUNT_BINDING_INVALID",
    )
    instance_match = _INSTANCE_ARN.fullmatch(identity_center_instance_arn)
    classifier_match = _PERMISSION_SET_ARN.fullmatch(
        runtime_classifier_permission_set_arn
    )
    approver_match = _PERMISSION_SET_ARN.fullmatch(
        runtime_approver_permission_set_arn
    )
    application_match = _APPLICATION_ARN.fullmatch(identity_center_application_arn)
    if instance_match is None:
        _fail("IDENTITY_CENTER_INSTANCE_ARN_INVALID")
    if classifier_match is None or approver_match is None:
        _fail("RUNTIME_PERMISSION_SET_ARN_INVALID")
    instance_id = instance_match.group("instance")
    if (
        classifier_match.group("instance") != instance_id
        or approver_match.group("instance") != instance_id
        or runtime_classifier_permission_set_arn == runtime_approver_permission_set_arn
    ):
        _fail("RUNTIME_PERMISSION_SET_BINDING_INVALID")
    if (
        application_match is None
        or application_match.group("instance") != instance_id
        or application_match.group("account") != management_account_id
    ):
        _fail("IDENTITY_CENTER_APPLICATION_BINDING_INVALID")
    identity_store_match = _IDENTITY_STORE_ARN.fullmatch(identity_store_arn)
    if (
        identity_store_match is None
        or identity_store_match.group("account") != management_account_id
    ):
        _fail("IDENTITY_STORE_ARN_INVALID")
    if (
        _USER_ARN.fullmatch(runtime_classifier_user_arn) is None
        or _USER_ARN.fullmatch(runtime_approver_user_arn) is None
        or runtime_classifier_user_arn == runtime_approver_user_arn
    ):
        _fail("RUNTIME_USER_BINDING_INVALID")
    replacements = {
        "audit_not_before": _timestamp(audit_started_at),
        "audit_not_after": expiry,
        "management_account_id": management_account_id,
        "authority_account_id": authority_account_id,
        "identity_center_instance_arn": identity_center_instance_arn,
        "runtime_classifier_permission_set_arn": runtime_classifier_permission_set_arn,
        "runtime_approver_permission_set_arn": runtime_approver_permission_set_arn,
        "identity_center_application_arn": identity_center_application_arn,
        "identity_store_arn": identity_store_arn,
        "runtime_classifier_user_arn": runtime_classifier_user_arn,
        "runtime_approver_user_arn": runtime_approver_user_arn,
    }
    policy = _replace_placeholders(_load_policy_template(repo_root), replacements)
    serialized = json.dumps(policy, sort_keys=True, separators=(",", ":"))
    if _PLACEHOLDER.search(serialized):
        _fail("POLICY_PLACEHOLDER_UNRESOLVED")
    return validate_audit_policy(
        policy,
        audit_started_at=audit_started_at,
        audit_not_after=audit_not_after,
    )


def validate_audit_policy(
    value: Mapping[str, Any],
    *,
    audit_started_at: datetime,
    audit_not_after: datetime,
) -> dict[str, Any]:
    """Prove exact allow-list, scopes, expiry, and closed-session boundary."""

    start, expiry = _validate_audit_window(
        started_at=audit_started_at,
        not_after=audit_not_after,
    )
    if not isinstance(value, Mapping) or set(value) != {"Version", "Statement"}:
        _fail("POLICY_SHAPE_INVALID")
    if value.get("Version") != "2012-10-17":
        _fail("POLICY_VERSION_INVALID")
    statements = value.get("Statement")
    if not isinstance(statements, list) or not statements:
        _fail("POLICY_STATEMENTS_INVALID")
    if not all(isinstance(item, Mapping) for item in statements):
        _fail("POLICY_STATEMENTS_INVALID")
    by_sid = {str(item.get("Sid")): item for item in statements}
    if len(by_sid) != len(statements) or set(by_sid) != EXPECTED_STATEMENT_SIDS:
        _fail("POLICY_STATEMENT_SET_INVALID")

    allowed: set[str] = set()
    for statement in statements:
        if "Principal" in statement:
            _fail("POLICY_AUTHORITY_EXPANSION")
        effect = statement.get("Effect")
        sid = str(statement.get("Sid"))
        if effect == "Allow":
            if set(statement) != {"Sid", "Effect", "Action", "Resource", "Condition"}:
                _fail("POLICY_AUTHORITY_EXPANSION")
            actions = _action_set(statement.get("Action"))
            expected_statement_actions = EXPECTED_ALLOW_ACTIONS_BY_SID.get(sid)
            if (
                expected_statement_actions is None
                or actions != set(expected_statement_actions)
            ):
                _fail("POLICY_ACTION_SCOPE_INVALID")
            allowed.update(actions)
            if any(_WRITE_VERB.search(action) for action in actions):
                _fail("POLICY_WRITE_ACTION_PRESENT")
            resource = statement.get("Resource")
            if resource == "*" and sid not in WILDCARD_ALLOW_SIDS:
                _fail("POLICY_WILDCARD_RESOURCE_INVALID")
            if resource != "*" and sid in WILDCARD_ALLOW_SIDS:
                _fail("POLICY_WILDCARD_RESOURCE_INVALID")
            if resource != "*" and any(
                "*" in item for item in _resource_set(resource)
            ):
                _fail("POLICY_WILDCARD_RESOURCE_INVALID")
            condition = statement.get("Condition")
            if (
                not isinstance(condition, Mapping)
                or condition.get("DateGreaterThanEquals")
                != {"aws:CurrentTime": start}
                or condition.get("DateLessThan") != {"aws:CurrentTime": expiry}
            ):
                _fail("POLICY_EXPIRY_GUARD_INVALID")
        elif effect == "Deny":
            expected_keys = (
                {"Sid", "Effect", "NotAction", "Resource"}
                if sid == "DenyEveryUnreviewedAction"
                else {"Sid", "Effect", "Action", "Resource", "Condition"}
            )
            if set(statement) != expected_keys:
                _fail("POLICY_DENY_SHAPE_INVALID")
        else:
            _fail("POLICY_EFFECT_INVALID")
    if allowed != set(ALLOWED_ACTIONS):
        _fail("POLICY_ALLOWLIST_INVALID")

    if (
        by_sid["ConfirmOnlyTheCurrentCaller"].get("Action")
        != "sts:GetCallerIdentity"
        or by_sid["ConfirmOnlyTheCurrentCaller"].get("Condition")
        != {
            "DateGreaterThanEquals": {"aws:CurrentTime": start},
            "DateLessThan": {"aws:CurrentTime": expiry},
        }
        or by_sid["DiscoverSingleIdentityCenterInstance"].get("Action")
        != "sso:ListInstances"
        or by_sid["DiscoverSingleIdentityCenterInstance"].get("Condition")
        != {
            "StringEquals": {"aws:RequestedRegion": IDENTITY_CENTER_REGION},
            "DateGreaterThanEquals": {"aws:CurrentTime": start},
            "DateLessThan": {"aws:CurrentTime": expiry},
        }
    ):
        _fail("POLICY_DISCOVERY_SCOPE_INVALID")

    permission_statement = by_sid["ReadExactInstanceAndRuntimePermissionSets"]
    permission_resources = _resource_set(permission_statement.get("Resource"))
    instance_resources = {
        item for item in permission_resources if _INSTANCE_ARN.fullmatch(item)
    }
    permission_set_resources = {
        item for item in permission_resources if _PERMISSION_SET_ARN.fullmatch(item)
    }
    if (
        len(instance_resources) != 1
        or len(permission_set_resources) != 2
        or permission_resources != instance_resources | permission_set_resources
    ):
        _fail("POLICY_PERMISSION_SET_RESOURCES_INVALID")
    instance_arn = next(iter(instance_resources))
    instance_match = _INSTANCE_ARN.fullmatch(instance_arn)
    if instance_match is None:
        _fail("POLICY_PERMISSION_SET_RESOURCES_INVALID")
    instance_id = instance_match.group("instance")
    for item in permission_set_resources:
        permission_set_match = _PERMISSION_SET_ARN.fullmatch(item)
        if (
            permission_set_match is None
            or permission_set_match.group("instance") != instance_id
        ):
            _fail("POLICY_PERMISSION_SET_RESOURCES_INVALID")
    regional_condition = {
        "StringEquals": {
            "aws:RequestedRegion": IDENTITY_CENTER_REGION,
            "sso:PrimaryRegion": IDENTITY_CENTER_REGION,
        },
        "DateGreaterThanEquals": {"aws:CurrentTime": start},
        "DateLessThan": {"aws:CurrentTime": expiry},
    }
    if permission_statement.get("Condition") != regional_condition:
        _fail("POLICY_PERMISSION_SET_CONDITION_INVALID")

    tag_statement = by_sid["ReadExactResourceTags"]
    if (
        _resource_set(tag_statement.get("Resource")) != permission_resources
        or tag_statement.get("Action") != "sso:ListTagsForResource"
        or tag_statement.get("Condition")
        != {
            "StringEquals": {"aws:RequestedRegion": IDENTITY_CENTER_REGION},
            "DateGreaterThanEquals": {"aws:CurrentTime": start},
            "DateLessThan": {"aws:CurrentTime": expiry},
        }
    ):
        _fail("POLICY_TAG_READ_SCOPE_INVALID")

    assignment_statement = by_sid["ReadExactAuthorityAccountAssignments"]
    assignment_resources = _resource_set(assignment_statement.get("Resource"))
    account_resources = {
        item for item in assignment_resources if _ACCOUNT_ARN.fullmatch(item)
    }
    if (
        assignment_statement.get("Action") != "sso:ListAccountAssignments"
        or len(account_resources) != 1
        or assignment_resources != permission_resources | account_resources
        or assignment_statement.get("Condition") != regional_condition
    ):
        _fail("POLICY_ASSIGNMENT_SCOPE_INVALID")
    authority_account_match = _ACCOUNT_ARN.fullmatch(next(iter(account_resources)))
    if authority_account_match is None:
        _fail("POLICY_ASSIGNMENT_SCOPE_INVALID")
    _validate_account_id(
        value=authority_account_match.group("account"),
        expected_digest=AUTHORITY_ACCOUNT_ID_DIGEST,
        code="POLICY_ASSIGNMENT_SCOPE_INVALID",
    )
    pending_statement = by_sid["ReadExactPendingIdentityCenterOperations"]
    if (
        pending_statement.get("Resource") != instance_arn
        or pending_statement.get("Condition") != regional_condition
    ):
        _fail("POLICY_PENDING_OPERATION_SCOPE_INVALID")

    application_statement = by_sid["ReadExactIdentityContextApplication"]
    application_resource = application_statement.get("Resource")
    application_match = (
        _APPLICATION_ARN.fullmatch(application_resource)
        if isinstance(application_resource, str)
        else None
    )
    application_account = (
        application_match.group("account") if application_match is not None else ""
    )
    _validate_account_id(
        value=application_account,
        expected_digest=MANAGEMENT_ACCOUNT_ID_DIGEST,
        code="POLICY_APPLICATION_SCOPE_INVALID",
    )
    if (
        application_match is None
        or application_match.group("instance") != instance_id
        or application_statement.get("Condition")
        != {
            "StringEquals": {
                "aws:RequestedRegion": IDENTITY_CENTER_REGION,
                "sso:PrimaryRegion": IDENTITY_CENTER_REGION,
                "sso:ApplicationAccount": application_account,
            },
            "DateGreaterThanEquals": {"aws:CurrentTime": start},
            "DateLessThan": {"aws:CurrentTime": expiry},
        }
    ):
        _fail("POLICY_APPLICATION_SCOPE_INVALID")

    user_statement = by_sid["ReadOnlyTheTwoApprovedRuntimeUsers"]
    user_resources = _resource_set(user_statement.get("Resource"))
    store_resources = {
        item for item in user_resources if _IDENTITY_STORE_ARN.fullmatch(item)
    }
    exact_users = {item for item in user_resources if _USER_ARN.fullmatch(item)}
    if (
        len(store_resources) != 1
        or len(exact_users) != 2
        or user_resources != store_resources | exact_users
        or user_statement.get("Condition")
        != {
            "StringEquals": {
                "aws:RequestedRegion": IDENTITY_CENTER_REGION,
                "identitystore:PrimaryRegion": IDENTITY_CENTER_REGION,
            },
            "DateGreaterThanEquals": {"aws:CurrentTime": start},
            "DateLessThan": {"aws:CurrentTime": expiry},
        }
    ):
        _fail("POLICY_RUNTIME_USER_SCOPE_INVALID")
    identity_store_arn = next(iter(store_resources))
    identity_store_match = _IDENTITY_STORE_ARN.fullmatch(identity_store_arn)
    if (
        identity_store_match is None
        or identity_store_match.group("account") != application_account
    ):
        _fail("POLICY_RUNTIME_USER_SCOPE_INVALID")

    closed = by_sid["DenyEveryUnreviewedAction"]
    if (
        closed.get("Effect") != "Deny"
        or _action_set(closed.get("NotAction")) != set(CLOSED_BOUNDARY_ACTIONS)
        or closed.get("Resource") != "*"
    ):
        _fail("POLICY_CLOSED_BOUNDARY_INVALID")
    start_deny = by_sid["DenyAllActionsBeforeAbsoluteStart"]
    if (
        start_deny.get("Effect") != "Deny"
        or start_deny.get("Action") != "*"
        or start_deny.get("Resource") != "*"
        or start_deny.get("Condition")
        != {"DateLessThan": {"aws:CurrentTime": start}}
    ):
        _fail("POLICY_START_DENY_INVALID")
    expiry_deny = by_sid["DenyAllActionsAtAbsoluteExpiry"]
    if (
        expiry_deny.get("Effect") != "Deny"
        or expiry_deny.get("Action") != "*"
        or expiry_deny.get("Resource") != "*"
        or expiry_deny.get("Condition")
        != {"DateGreaterThanEquals": {"aws:CurrentTime": expiry}}
    ):
        _fail("POLICY_EXPIRY_DENY_INVALID")
    region_deny = by_sid["DenyIdentityReadsOutsideHomeRegion"]
    expected_region_deny_actions = {"identitystore:*", "sso-directory:*", "sso:*"}
    if (
        region_deny.get("Effect") != "Deny"
        or _action_set(region_deny.get("Action"))
        != expected_region_deny_actions
        or region_deny.get("Resource") != "*"
        or region_deny.get("Condition")
        != {
            "StringNotEquals": {
                "aws:RequestedRegion": IDENTITY_CENTER_REGION,
            }
        }
    ):
        _fail("POLICY_REGION_DENY_INVALID")
    serialized = json.dumps(value, sort_keys=True, separators=(",", ":"))
    non_whitespace_bytes = len(re.sub(r"\s", "", serialized).encode("utf-8"))
    if len(serialized.encode("utf-8")) > 32768 or non_whitespace_bytes > 10240:
        _fail("POLICY_INLINE_SIZE_LIMIT_EXCEEDED")
    if _PLACEHOLDER.search(serialized):
        _fail("POLICY_PLACEHOLDER_UNRESOLVED")
    return json.loads(serialized)


def build_audit_preparation_intent(
    *,
    repo_root: Path,
    base_main_commit: str,
    created_at: datetime,
    audit_not_after: datetime,
    auditor_user_id: str,
    management_account_id: str,
    authority_account_id: str,
    identity_center_instance_arn: str,
    runtime_classifier_permission_set_arn: str,
    runtime_approver_permission_set_arn: str,
    identity_center_application_arn: str,
    identity_store_arn: str,
    runtime_classifier_user_arn: str,
    runtime_approver_user_arn: str,
) -> dict[str, Any]:
    """Build a digest-only intent for later independent review."""

    if not isinstance(base_main_commit, str) or _COMMIT.fullmatch(base_main_commit) is None:
        _fail("BASE_MAIN_COMMIT_INVALID")
    if not isinstance(auditor_user_id, str) or _USER_ID.fullmatch(auditor_user_id) is None:
        _fail("AUDITOR_USER_ID_INVALID")
    runtime_user_matches = (
        _USER_ARN.fullmatch(runtime_classifier_user_arn),
        _USER_ARN.fullmatch(runtime_approver_user_arn),
    )
    if any(match is None for match in runtime_user_matches) or auditor_user_id in {
        match.group("user") for match in runtime_user_matches if match is not None
    }:
        _fail("AUDITOR_USER_BINDING_INVALID")
    runtime_classifier_user_id = runtime_user_matches[0].group("user")
    runtime_approver_user_id = runtime_user_matches[1].group("user")
    started, audit_expiry = _validate_audit_window(
        started_at=created_at,
        not_after=audit_not_after,
    )
    root = Path(repo_root).resolve()
    policy = render_audit_policy(
        repo_root=root,
        audit_started_at=created_at,
        audit_not_after=audit_not_after,
        management_account_id=management_account_id,
        authority_account_id=authority_account_id,
        identity_center_instance_arn=identity_center_instance_arn,
        runtime_classifier_permission_set_arn=runtime_classifier_permission_set_arn,
        runtime_approver_permission_set_arn=runtime_approver_permission_set_arn,
        identity_center_application_arn=identity_center_application_arn,
        identity_store_arn=identity_store_arn,
        runtime_classifier_user_arn=runtime_classifier_user_arn,
        runtime_approver_user_arn=runtime_approver_user_arn,
    )
    exact_tags = dict(BASE_TAGS)
    exact_tags["expires_at"] = audit_expiry
    auditor_user_id_digest = digest_text(auditor_user_id)
    allowed_audit_operators = {
        "auditor_user_id_digests": [auditor_user_id_digest]
    }
    compact_policy = json.dumps(policy, sort_keys=True, separators=(",", ":"))
    intent: dict[str, Any] = {
        "schema_version": "1",
        "record_type": "platform_authority_gug357_identity_center_audit_intent",
        "issue_id": ISSUE_ID,
        "operation": "PREPARE_IDENTITY_CENTER_READ_ONLY_AUDIT_PERMISSION_SET",
        "environment": "management-control-plane",
        "production": False,
        "base_main_commit": base_main_commit,
        "management_account_id_digest": digest_text(management_account_id),
        "authority_account_id_digest": digest_text(authority_account_id),
        "target_region": IDENTITY_CENTER_REGION,
        "identity_center_instance_arn_digest": digest_text(
            identity_center_instance_arn
        ),
        "identity_store_arn_digest": digest_text(identity_store_arn),
        "identity_center_application_arn_digest": digest_text(
            identity_center_application_arn
        ),
        "runtime_classifier_permission_set_arn_digest": digest_text(
            runtime_classifier_permission_set_arn
        ),
        "runtime_approver_permission_set_arn_digest": digest_text(
            runtime_approver_permission_set_arn
        ),
        "runtime_classifier_user_arn_digest": digest_text(
            runtime_classifier_user_arn
        ),
        "runtime_approver_user_arn_digest": digest_text(
            runtime_approver_user_arn
        ),
        "runtime_classifier_user_id_digest": digest_text(
            runtime_classifier_user_id
        ),
        "runtime_approver_user_id_digest": digest_text(runtime_approver_user_id),
        "auditor_user_id_digest": auditor_user_id_digest,
        "allowed_operator_set_digest": canonical_digest(allowed_audit_operators),
        "classifier_permission_set_name": CLASSIFIER_PERMISSION_SET_NAME,
        "approver_permission_set_name": APPROVER_PERMISSION_SET_NAME,
        "permission_set_name": PERMISSION_SET_NAME,
        "permission_set_description": PERMISSION_SET_DESCRIPTION,
        "session_duration": SESSION_DURATION,
        "expected_tags": exact_tags,
        "expected_tags_digest": canonical_digest(exact_tags),
        "policy_template_sha256": _byte_digest(root / POLICY_TEMPLATE_PATH),
        "rendered_policy_digest": canonical_digest(policy),
        "rendered_policy_non_whitespace_bytes": len(
            re.sub(r"\s", "", compact_policy).encode("utf-8")
        ),
        "managed_policy_arns": [],
        "customer_managed_policy_references": [],
        "permissions_boundary_present": False,
        "relay_state_present": False,
        "session_source": "DIRECT_SSO_PERMISSION_SET",
        "identity_enhanced_session_authorized": False,
        "provided_contexts_authorized": False,
        "role_chaining_authorized": False,
        "additional_identity_policies_authorized": False,
        "exclusive_permission_set_policy_required": True,
        "principal_type": "USER",
        "direct_assignment_count": 1,
        "provisioned_account_count": 1,
        "assignment_target_account_id_digest": digest_text(management_account_id),
        "auditor_counts_as_gug357_approver": False,
        "auditor_counts_as_gug357_executor": False,
        "approver_executor_contract_status": "NOT_DEFINED",
        "two_human_separation": "NOT_PROVEN",
        "materialization_authorized": False,
        "revocation_authorized": False,
        "cloudformation_authorized": False,
        "broker_invocation_authorized": False,
        "production_authorized": False,
        "aws_mutations": [],
        "revocation_required_after_future_materialization": True,
        "created_at": started,
        "expires_at": _timestamp(created_at + INTENT_TTL),
        "audit_not_before": started,
        "audit_not_after": audit_expiry,
    }
    intent["intent_digest"] = canonical_digest(intent)
    return validate_audit_preparation_intent(intent, repo_root=root)


def validate_audit_preparation_intent(
    value: Mapping[str, Any], *, repo_root: Path
) -> dict[str, Any]:
    """Validate the public, sanitized preparation artifact."""

    expected_fields = {
        "schema_version",
        "record_type",
        "issue_id",
        "operation",
        "environment",
        "production",
        "base_main_commit",
        "management_account_id_digest",
        "authority_account_id_digest",
        "target_region",
        "identity_center_instance_arn_digest",
        "identity_store_arn_digest",
        "identity_center_application_arn_digest",
        "runtime_classifier_permission_set_arn_digest",
        "runtime_approver_permission_set_arn_digest",
        "runtime_classifier_user_arn_digest",
        "runtime_approver_user_arn_digest",
        "runtime_classifier_user_id_digest",
        "runtime_approver_user_id_digest",
        "auditor_user_id_digest",
        "allowed_operator_set_digest",
        "classifier_permission_set_name",
        "approver_permission_set_name",
        "permission_set_name",
        "permission_set_description",
        "session_duration",
        "expected_tags",
        "expected_tags_digest",
        "policy_template_sha256",
        "rendered_policy_digest",
        "rendered_policy_non_whitespace_bytes",
        "managed_policy_arns",
        "customer_managed_policy_references",
        "permissions_boundary_present",
        "relay_state_present",
        "session_source",
        "identity_enhanced_session_authorized",
        "provided_contexts_authorized",
        "role_chaining_authorized",
        "additional_identity_policies_authorized",
        "exclusive_permission_set_policy_required",
        "principal_type",
        "direct_assignment_count",
        "provisioned_account_count",
        "assignment_target_account_id_digest",
        "auditor_counts_as_gug357_approver",
        "auditor_counts_as_gug357_executor",
        "approver_executor_contract_status",
        "two_human_separation",
        "materialization_authorized",
        "revocation_authorized",
        "cloudformation_authorized",
        "broker_invocation_authorized",
        "production_authorized",
        "aws_mutations",
        "revocation_required_after_future_materialization",
        "created_at",
        "expires_at",
        "audit_not_before",
        "audit_not_after",
        "intent_digest",
    }
    if not isinstance(value, Mapping) or set(value) != expected_fields:
        _fail("INTENT_SHAPE_INVALID")
    exact = {
        "schema_version": "1",
        "record_type": "platform_authority_gug357_identity_center_audit_intent",
        "issue_id": ISSUE_ID,
        "operation": "PREPARE_IDENTITY_CENTER_READ_ONLY_AUDIT_PERMISSION_SET",
        "environment": "management-control-plane",
        "production": False,
        "management_account_id_digest": MANAGEMENT_ACCOUNT_ID_DIGEST,
        "authority_account_id_digest": AUTHORITY_ACCOUNT_ID_DIGEST,
        "target_region": IDENTITY_CENTER_REGION,
        "classifier_permission_set_name": CLASSIFIER_PERMISSION_SET_NAME,
        "approver_permission_set_name": APPROVER_PERMISSION_SET_NAME,
        "permission_set_name": PERMISSION_SET_NAME,
        "permission_set_description": PERMISSION_SET_DESCRIPTION,
        "session_duration": SESSION_DURATION,
        "managed_policy_arns": [],
        "customer_managed_policy_references": [],
        "permissions_boundary_present": False,
        "relay_state_present": False,
        "session_source": "DIRECT_SSO_PERMISSION_SET",
        "identity_enhanced_session_authorized": False,
        "provided_contexts_authorized": False,
        "role_chaining_authorized": False,
        "additional_identity_policies_authorized": False,
        "exclusive_permission_set_policy_required": True,
        "principal_type": "USER",
        "direct_assignment_count": 1,
        "provisioned_account_count": 1,
        "assignment_target_account_id_digest": MANAGEMENT_ACCOUNT_ID_DIGEST,
        "auditor_counts_as_gug357_approver": False,
        "auditor_counts_as_gug357_executor": False,
        "approver_executor_contract_status": "NOT_DEFINED",
        "two_human_separation": "NOT_PROVEN",
        "materialization_authorized": False,
        "revocation_authorized": False,
        "cloudformation_authorized": False,
        "broker_invocation_authorized": False,
        "production_authorized": False,
        "aws_mutations": [],
        "revocation_required_after_future_materialization": True,
    }
    if any(
        type(value.get(key)) is not type(item) or value.get(key) != item
        for key, item in exact.items()
    ):
        _fail("INTENT_AUTHORITY_EXPANSION")
    if not isinstance(value.get("base_main_commit"), str) or _COMMIT.fullmatch(
        str(value["base_main_commit"])
    ) is None:
        _fail("BASE_MAIN_COMMIT_INVALID")
    for field in (
        "identity_center_instance_arn_digest",
        "identity_store_arn_digest",
        "identity_center_application_arn_digest",
        "runtime_classifier_permission_set_arn_digest",
        "runtime_approver_permission_set_arn_digest",
        "runtime_classifier_user_arn_digest",
        "runtime_approver_user_arn_digest",
        "runtime_classifier_user_id_digest",
        "runtime_approver_user_id_digest",
        "auditor_user_id_digest",
        "allowed_operator_set_digest",
        "expected_tags_digest",
        "policy_template_sha256",
        "rendered_policy_digest",
        "intent_digest",
    ):
        item = value.get(field)
        if not isinstance(item, str) or _DIGEST.fullmatch(item) is None:
            _fail("INTENT_DIGEST_INVALID")
    if (
        value["runtime_classifier_permission_set_arn_digest"]
        == value["runtime_approver_permission_set_arn_digest"]
        or value["runtime_classifier_user_arn_digest"]
        == value["runtime_approver_user_arn_digest"]
        or len(
            {
                value["runtime_classifier_user_id_digest"],
                value["runtime_approver_user_id_digest"],
                value["auditor_user_id_digest"],
            }
        )
        != 3
    ):
        _fail("INTENT_OPERATOR_BINDING_INVALID")
    expected_operator_set_digest = canonical_digest(
        {"auditor_user_id_digests": [value["auditor_user_id_digest"]]}
    )
    if value.get("allowed_operator_set_digest") != expected_operator_set_digest:
        _fail("INTENT_OPERATOR_SET_INVALID")
    created = _parse_timestamp(value.get("created_at"), code="INTENT_TIMESTAMP_INVALID")
    expires = _parse_timestamp(value.get("expires_at"), code="INTENT_TIMESTAMP_INVALID")
    audit_expiry = _parse_timestamp(
        value.get("audit_not_after"), code="INTENT_TIMESTAMP_INVALID"
    )
    audit_start = _parse_timestamp(
        value.get("audit_not_before"), code="INTENT_TIMESTAMP_INVALID"
    )
    if (
        not created < expires
        or expires - created != INTENT_TTL
        or audit_start != created
        or not audit_start < audit_expiry
        or audit_expiry - audit_start > MAX_AUDIT_TTL
    ):
        _fail("INTENT_TIMESTAMP_INVALID")
    expected_tags = dict(BASE_TAGS)
    expected_tags["expires_at"] = value["audit_not_after"]
    if (
        value.get("expected_tags") != expected_tags
        or value.get("expected_tags_digest") != canonical_digest(expected_tags)
    ):
        _fail("INTENT_TAGS_INVALID")
    if value.get("policy_template_sha256") != _byte_digest(
        Path(repo_root).resolve() / POLICY_TEMPLATE_PATH
    ):
        _fail("INTENT_POLICY_TEMPLATE_MISMATCH")
    size = value.get("rendered_policy_non_whitespace_bytes")
    if not isinstance(size, int) or isinstance(size, bool) or not 0 < size <= 10240:
        _fail("INTENT_POLICY_SIZE_INVALID")
    calculated = canonical_digest(
        {key: item for key, item in value.items() if key != "intent_digest"}
    )
    if value.get("intent_digest") != calculated:
        _fail("INTENT_DIGEST_MISMATCH")
    return json.loads(json.dumps(value, sort_keys=True, separators=(",", ":")))
