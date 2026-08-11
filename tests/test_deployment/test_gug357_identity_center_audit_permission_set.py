"""Offline contract tests for the GUG-357 Identity Center audit package."""
from __future__ import annotations

import ast
import copy
import hashlib
import json
import re
from datetime import UTC, datetime, timedelta
from pathlib import Path

import jsonschema
import pytest

import tooling.platform_authority_gug357_identity_center_audit as audit_contract
from tooling.platform_authority_gug357_identity_center_audit import (
    ALLOWED_ACTIONS,
    BASE_TAGS,
    CLOSED_BOUNDARY_ACTIONS,
    DUAL_AUTH_COMPATIBILITY_EXEMPTIONS,
    INTENT_TTL,
    MAX_AUDIT_TTL,
    PERMISSION_SET_NAME,
    POLICY_TEMPLATE_PATH,
    SESSION_DURATION,
    WILDCARD_ALLOW_SIDS,
    IdentityCenterAuditPreparationError,
    build_audit_preparation_intent,
    render_audit_policy,
    validate_audit_policy,
    validate_audit_preparation_intent,
)
from tooling.validate_policy import validate_policy


ROOT = Path(__file__).resolve().parents[2]
SCHEMA_PATH = (
    ROOT
    / "schemas/platform-authority-gug357-identity-center-audit-intent.v1.schema.json"
)
MODULE_PATH = ROOT / "tooling/platform_authority_gug357_identity_center_audit.py"
STARTED_AT = datetime(2026, 8, 11, 0, 0, tzinfo=UTC)
NOT_AFTER = STARTED_AT + timedelta(hours=2)
BASE_MAIN_COMMIT = "fa6be9e1dd9598fce15826779cfdc382d8b46bd4"
MANAGEMENT_ACCOUNT_ID = "111122223333"
AUTHORITY_ACCOUNT_ID = "444455556666"
PRODUCTION_MANAGEMENT_ACCOUNT_ID_DIGEST = audit_contract.MANAGEMENT_ACCOUNT_ID_DIGEST
PRODUCTION_AUTHORITY_ACCOUNT_ID_DIGEST = audit_contract.AUTHORITY_ACCOUNT_ID_DIGEST
INSTANCE_ARN = "arn:aws:sso:::instance/ssoins-0123456789abcdef"
CLASSIFIER_PERMISSION_SET_ARN = (
    "arn:aws:sso:::permissionSet/ssoins-0123456789abcdef/ps-0123456789abcdef"
)
APPROVER_PERMISSION_SET_ARN = (
    "arn:aws:sso:::permissionSet/ssoins-0123456789abcdef/ps-fedcba9876543210"
)
APPLICATION_ARN = (
    f"arn:aws:sso::{MANAGEMENT_ACCOUNT_ID}:application/"
    "ssoins-0123456789abcdef/apl-0123456789abcdef"
)
IDENTITY_STORE_ARN = (
    f"arn:aws:identitystore::{MANAGEMENT_ACCOUNT_ID}:identitystore/d-0123456789"
)
CLASSIFIER_USER_ID = "0123456789-01234567-89ab-cdef-0123-456789abcdef"
APPROVER_USER_ID = "fedcba9876-fedcba98-7654-3210-fedc-ba9876543210"
AUDITOR_USER_ID = "aaaaaaaaaa-aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
CLASSIFIER_USER_ARN = f"arn:aws:identitystore:::user/{CLASSIFIER_USER_ID}"
APPROVER_USER_ARN = f"arn:aws:identitystore:::user/{APPROVER_USER_ID}"


def _digest(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()


def _schema_for_synthetic_accounts() -> dict:
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    schema["properties"]["management_account_id_digest"]["const"] = _digest(
        MANAGEMENT_ACCOUNT_ID
    )
    schema["properties"]["authority_account_id_digest"]["const"] = _digest(
        AUTHORITY_ACCOUNT_ID
    )
    schema["properties"]["assignment_target_account_id_digest"]["const"] = (
        _digest(MANAGEMENT_ACCOUNT_ID)
    )
    return schema


def _recalculate_intent_checksum(value: dict) -> None:
    value["intent_digest"] = audit_contract.canonical_digest(
        {key: item for key, item in value.items() if key != "intent_digest"}
    )


@pytest.fixture(autouse=True)
def _use_synthetic_account_bindings(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        audit_contract, "MANAGEMENT_ACCOUNT_ID_DIGEST", _digest(MANAGEMENT_ACCOUNT_ID)
    )
    monkeypatch.setattr(
        audit_contract, "AUTHORITY_ACCOUNT_ID_DIGEST", _digest(AUTHORITY_ACCOUNT_ID)
    )


def _render(**overrides: object) -> dict:
    values = {
        "repo_root": ROOT,
        "audit_started_at": STARTED_AT,
        "audit_not_after": NOT_AFTER,
        "management_account_id": MANAGEMENT_ACCOUNT_ID,
        "authority_account_id": AUTHORITY_ACCOUNT_ID,
        "identity_center_instance_arn": INSTANCE_ARN,
        "runtime_classifier_permission_set_arn": CLASSIFIER_PERMISSION_SET_ARN,
        "runtime_approver_permission_set_arn": APPROVER_PERMISSION_SET_ARN,
        "identity_center_application_arn": APPLICATION_ARN,
        "identity_store_arn": IDENTITY_STORE_ARN,
        "runtime_classifier_user_arn": CLASSIFIER_USER_ARN,
        "runtime_approver_user_arn": APPROVER_USER_ARN,
    }
    values.update(overrides)
    return render_audit_policy(**values)


def _intent(**overrides: object) -> dict:
    values = {
        "repo_root": ROOT,
        "base_main_commit": BASE_MAIN_COMMIT,
        "created_at": STARTED_AT,
        "audit_not_after": NOT_AFTER,
        "auditor_user_id": AUDITOR_USER_ID,
        "management_account_id": MANAGEMENT_ACCOUNT_ID,
        "authority_account_id": AUTHORITY_ACCOUNT_ID,
        "identity_center_instance_arn": INSTANCE_ARN,
        "runtime_classifier_permission_set_arn": CLASSIFIER_PERMISSION_SET_ARN,
        "runtime_approver_permission_set_arn": APPROVER_PERMISSION_SET_ARN,
        "identity_center_application_arn": APPLICATION_ARN,
        "identity_store_arn": IDENTITY_STORE_ARN,
        "runtime_classifier_user_arn": CLASSIFIER_USER_ARN,
        "runtime_approver_user_arn": APPROVER_USER_ARN,
    }
    values.update(overrides)
    return build_audit_preparation_intent(**values)


def _actions(statement: dict, key: str = "Action") -> set[str]:
    value = statement[key]
    return {value} if isinstance(value, str) else set(value)


def test_renders_exact_read_only_policy_with_closed_expiry_boundary() -> None:
    policy = _render()
    statements = {item["Sid"]: item for item in policy["Statement"]}
    allowed = set().union(
        *(
            _actions(item)
            for item in policy["Statement"]
            if item["Effect"] == "Allow"
        )
    )

    assert allowed == set(ALLOWED_ACTIONS)
    assert _actions(
        statements["DenyEveryUnreviewedAction"], "NotAction"
    ) == set(CLOSED_BOUNDARY_ACTIONS)
    assert set(DUAL_AUTH_COMPATIBILITY_EXEMPTIONS).isdisjoint(allowed)
    assert statements["DenyAllActionsBeforeAbsoluteStart"]["Condition"] == {
        "DateLessThan": {"aws:CurrentTime": "2026-08-11T00:00:00Z"}
    }
    assert statements["DenyAllActionsAtAbsoluteExpiry"]["Condition"] == {
        "DateGreaterThanEquals": {"aws:CurrentTime": "2026-08-11T02:00:00Z"}
    }
    assert statements["DenyIdentityReadsOutsideHomeRegion"]["Condition"] == {
        "StringNotEquals": {"aws:RequestedRegion": "us-east-1"}
    }
    assert not any(
        re.search(
            r":(?:Create|Delete|Update|Put|Attach|Detach|Provision|Tag|Untag|"
            r"Associate|Disassociate|Start|Stop|Enable|Disable|Import)",
            action,
        )
        for action in allowed
    )


def test_wildcard_resources_are_only_unavoidable_sts_and_instance_discovery() -> None:
    policy = _render()
    wildcard_allow_sids = {
        statement["Sid"]
        for statement in policy["Statement"]
        if statement["Effect"] == "Allow" and statement["Resource"] == "*"
    }
    assert wildcard_allow_sids == set(WILDCARD_ALLOW_SIDS)
    for statement in policy["Statement"]:
        if statement["Effect"] == "Allow":
            assert statement["Condition"]["DateGreaterThanEquals"] == {
                "aws:CurrentTime": "2026-08-11T00:00:00Z"
            }
            assert statement["Condition"]["DateLessThan"] == {
                "aws:CurrentTime": "2026-08-11T02:00:00Z"
            }


def test_authority_is_limited_to_identity_reads_and_caller_confirmation() -> None:
    policy = _render()
    allowed = set().union(
        *(
            _actions(item)
            for item in policy["Statement"]
            if item["Effect"] == "Allow"
        )
    )
    assert allowed == set(ALLOWED_ACTIONS)
    assert all(
        action == "sts:GetCallerIdentity"
        or action.startswith("sso:")
        or action.startswith("identitystore:")
        for action in allowed
    )
    assert not any(action.startswith("kms:") for action in allowed)


def test_tag_read_uses_only_documented_global_region_and_expiry_conditions() -> None:
    statements = {item["Sid"]: item for item in _render()["Statement"]}
    assert statements["ReadExactResourceTags"]["Condition"] == {
        "StringEquals": {"aws:RequestedRegion": "us-east-1"},
        "DateGreaterThanEquals": {"aws:CurrentTime": "2026-08-11T00:00:00Z"},
        "DateLessThan": {"aws:CurrentTime": "2026-08-11T02:00:00Z"},
    }


def test_accepts_both_documented_identity_store_id_forms() -> None:
    legacy_store_arn = (
        f"arn:aws:identitystore::{MANAGEMENT_ACCOUNT_ID}:identitystore/"
        "01234567-89ab-cdef-0123-456789abcdef"
    )
    policy = _render(identity_store_arn=legacy_store_arn)
    statement = next(
        item
        for item in policy["Statement"]
        if item["Sid"] == "ReadOnlyTheTwoApprovedRuntimeUsers"
    )
    assert legacy_store_arn in statement["Resource"]
    unprefixed_user_id = "12345678-90ab-cdef-0123-456789abcdef"
    assert _intent(auditor_user_id=unprefixed_user_id)[
        "auditor_user_id_digest"
    ] == _digest(unprefixed_user_id)


def test_policy_is_valid_iam_json_and_below_permission_set_inline_limit() -> None:
    template = json.loads((ROOT / POLICY_TEMPLATE_PATH).read_text(encoding="utf-8"))
    policy = _render()
    assert validate_policy(template, POLICY_TEMPLATE_PATH.name) == []
    assert validate_policy(policy, "rendered-gug357-audit-policy.json") == []
    compact = json.dumps(policy, sort_keys=True, separators=(",", ":"))
    assert len(re.sub(r"\s", "", compact).encode("utf-8")) <= 10240
    assert len(compact.encode("utf-8")) <= 32768
    assert "${" not in compact


def test_builds_sanitized_checksum_bound_repository_only_intent() -> None:
    intent = _intent()
    schema = _schema_for_synthetic_accounts()
    jsonschema.Draft202012Validator(
        schema, format_checker=jsonschema.FormatChecker()
    ).validate(intent)
    serialized = json.dumps(intent, sort_keys=True)

    for private_value in (
        MANAGEMENT_ACCOUNT_ID,
        AUTHORITY_ACCOUNT_ID,
        INSTANCE_ARN,
        CLASSIFIER_PERMISSION_SET_ARN,
        APPROVER_PERMISSION_SET_ARN,
        APPLICATION_ARN,
        IDENTITY_STORE_ARN,
        CLASSIFIER_USER_ID,
        APPROVER_USER_ID,
        AUDITOR_USER_ID,
    ):
        assert private_value not in serialized
    assert intent["permission_set_name"] == PERMISSION_SET_NAME
    assert len(PERMISSION_SET_NAME) <= 32
    assert intent["session_duration"] == SESSION_DURATION == "PT1H"
    assert INTENT_TTL == timedelta(minutes=15)
    assert MAX_AUDIT_TTL == timedelta(hours=4)
    assert intent["expected_tags"] == {
        **BASE_TAGS,
        "expires_at": "2026-08-11T02:00:00Z",
    }
    assert intent["principal_type"] == "USER"
    assert intent["session_source"] == "DIRECT_SSO_PERMISSION_SET"
    assert intent["identity_enhanced_session_authorized"] is False
    assert intent["provided_contexts_authorized"] is False
    assert intent["role_chaining_authorized"] is False
    assert intent["additional_identity_policies_authorized"] is False
    assert intent["exclusive_permission_set_policy_required"] is True
    assert intent["direct_assignment_count"] == 1
    assert intent["provisioned_account_count"] == 1
    assert intent["allowed_operator_set_digest"] == audit_contract.canonical_digest(
        {"auditor_user_id_digests": [_digest(AUDITOR_USER_ID)]}
    )
    assert intent["aws_mutations"] == []
    assert intent["materialization_authorized"] is False
    assert intent["revocation_authorized"] is False
    assert intent["two_human_separation"] == "NOT_PROVEN"
    assert intent["approver_executor_contract_status"] == "NOT_DEFINED"
    assert intent["audit_not_before"] == "2026-08-11T00:00:00Z"


def test_public_schema_pins_reviewed_account_digests() -> None:
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    assert schema["properties"]["management_account_id_digest"]["const"] == (
        PRODUCTION_MANAGEMENT_ACCOUNT_ID_DIGEST
    )
    assert schema["properties"]["authority_account_id_digest"]["const"] == (
        PRODUCTION_AUTHORITY_ACCOUNT_ID_DIGEST
    )
    assert schema["properties"]["assignment_target_account_id_digest"][
        "const"
    ] == PRODUCTION_MANAGEMENT_ACCOUNT_ID_DIGEST

    foreign = _intent()
    foreign_digest = _digest("999900001111")
    foreign["management_account_id_digest"] = foreign_digest
    foreign["authority_account_id_digest"] = foreign_digest
    foreign["assignment_target_account_id_digest"] = foreign_digest
    _recalculate_intent_checksum(foreign)
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.Draft202012Validator(schema).validate(foreign)


@pytest.mark.parametrize(
    ("overrides", "error"),
    [
        (
            {"audit_not_after": STARTED_AT + timedelta(hours=4, seconds=1)},
            "AUDIT_WINDOW_INVALID",
        ),
        (
            {"runtime_approver_user_arn": CLASSIFIER_USER_ARN},
            "RUNTIME_USER_BINDING_INVALID",
        ),
        (
            {"auditor_user_id": CLASSIFIER_USER_ID},
            "AUDITOR_USER_BINDING_INVALID",
        ),
        (
            {"auditor_user_id": "not-a-valid-identity-store-user-id"},
            "AUDITOR_USER_ID_INVALID",
        ),
        (
            {
                "runtime_approver_permission_set_arn": (
                    "arn:aws:sso:::permissionSet/ssoins-fedcba9876543210/"
                    "ps-fedcba9876543210"
                )
            },
            "RUNTIME_PERMISSION_SET_BINDING_INVALID",
        ),
        (
            {
                "identity_center_application_arn": (
                    f"arn:aws:sso::{MANAGEMENT_ACCOUNT_ID}:application/"
                    "ssoins-fedcba9876543210/apl-0123456789abcdef"
                )
            },
            "IDENTITY_CENTER_APPLICATION_BINDING_INVALID",
        ),
        (
            {"management_account_id": "999900001111"},
            "MANAGEMENT_ACCOUNT_BINDING_INVALID",
        ),
        (
            {"authority_account_id": "999900002222"},
            "AUTHORITY_ACCOUNT_BINDING_INVALID",
        ),
    ],
)
def test_rejects_expanded_or_ambiguous_private_bindings(
    overrides: dict[str, object], error: str
) -> None:
    with pytest.raises(IdentityCenterAuditPreparationError, match=f"^{error}$"):
        _intent(**overrides)


def test_rejects_policy_action_expansion_or_missing_expiry() -> None:
    policy = _render()
    expanded = copy.deepcopy(policy)
    expanded["Statement"][0]["Action"] = [
        "sts:GetCallerIdentity",
        "sso:CreatePermissionSet",
    ]
    with pytest.raises(
        IdentityCenterAuditPreparationError,
        match=(
            "^(POLICY_ACTION_SCOPE_INVALID|POLICY_WRITE_ACTION_PRESENT|"
            "POLICY_ALLOWLIST_INVALID)$"
        ),
    ):
        validate_audit_policy(
            expanded,
            audit_started_at=STARTED_AT,
            audit_not_after=NOT_AFTER,
        )

    unbounded = copy.deepcopy(policy)
    del unbounded["Statement"][0]["Condition"]["DateLessThan"]
    with pytest.raises(
        IdentityCenterAuditPreparationError, match="^POLICY_EXPIRY_GUARD_INVALID$"
    ):
        validate_audit_policy(
            unbounded,
            audit_started_at=STARTED_AT,
            audit_not_after=NOT_AFTER,
        )

    early = copy.deepcopy(policy)
    del early["Statement"][0]["Condition"]["DateGreaterThanEquals"]
    with pytest.raises(
        IdentityCenterAuditPreparationError, match="^POLICY_EXPIRY_GUARD_INVALID$"
    ):
        validate_audit_policy(
            early,
            audit_started_at=STARTED_AT,
            audit_not_after=NOT_AFTER,
        )

    wildcarded = copy.deepcopy(policy)
    wildcarded["Statement"][2]["Resource"][0] = "arn:aws:sso:::instance/*"
    with pytest.raises(
        IdentityCenterAuditPreparationError,
        match="^POLICY_WILDCARD_RESOURCE_INVALID$",
    ):
        validate_audit_policy(
            wildcarded,
            audit_started_at=STARTED_AT,
            audit_not_after=NOT_AFTER,
        )

    foreign_assignment = copy.deepcopy(policy)
    for statement in foreign_assignment["Statement"]:
        if statement["Sid"] == "ReadExactAuthorityAccountAssignments":
            statement["Resource"][-1] = (
                f"arn:aws:sso:::account/{MANAGEMENT_ACCOUNT_ID}"
            )
    with pytest.raises(
        IdentityCenterAuditPreparationError,
        match="^POLICY_ASSIGNMENT_SCOPE_INVALID$",
    ):
        validate_audit_policy(
            foreign_assignment,
            audit_started_at=STARTED_AT,
            audit_not_after=NOT_AFTER,
        )

    inactive_closed_boundary = copy.deepcopy(policy)
    for statement in inactive_closed_boundary["Statement"]:
        if statement["Sid"] == "DenyEveryUnreviewedAction":
            statement["Condition"] = {
                "DateLessThan": {"aws:CurrentTime": "2000-01-01T00:00:00Z"}
            }
    with pytest.raises(
        IdentityCenterAuditPreparationError,
        match="^POLICY_DENY_SHAPE_INVALID$",
    ):
        validate_audit_policy(
            inactive_closed_boundary,
            audit_started_at=STARTED_AT,
            audit_not_after=NOT_AFTER,
        )

    reallocated_actions = copy.deepcopy(policy)
    statements = {item["Sid"]: item for item in reallocated_actions["Statement"]}
    statements["ReadExactPendingIdentityCenterOperations"]["Action"].remove(
        "sso:DescribePermissionSetProvisioningStatus"
    )
    statements["ReadExactPendingIdentityCenterOperations"]["Action"].append(
        "sso:DescribeApplication"
    )
    statements["ReadExactIdentityContextApplication"]["Action"].remove(
        "sso:DescribeApplication"
    )
    statements["ReadExactIdentityContextApplication"]["Action"].append(
        "sso:DescribePermissionSetProvisioningStatus"
    )
    with pytest.raises(
        IdentityCenterAuditPreparationError,
        match="^POLICY_ACTION_SCOPE_INVALID$",
    ):
        validate_audit_policy(
            reallocated_actions,
            audit_started_at=STARTED_AT,
            audit_not_after=NOT_AFTER,
        )


def test_rejects_tampered_intent_digest_and_authority_flags() -> None:
    intent = _intent()
    tampered = dict(intent)
    tampered["materialization_authorized"] = True
    with pytest.raises(
        IdentityCenterAuditPreparationError, match="^INTENT_AUTHORITY_EXPANSION$"
    ):
        validate_audit_preparation_intent(tampered, repo_root=ROOT)

    type_confused = dict(intent)
    type_confused["materialization_authorized"] = 0
    type_confused["exclusive_permission_set_policy_required"] = 1
    type_confused["direct_assignment_count"] = True
    _recalculate_intent_checksum(type_confused)
    with pytest.raises(
        IdentityCenterAuditPreparationError, match="^INTENT_AUTHORITY_EXPANSION$"
    ):
        validate_audit_preparation_intent(type_confused, repo_root=ROOT)

    tampered = dict(intent)
    tampered["intent_digest"] = "sha256:" + "0" * 64
    with pytest.raises(
        IdentityCenterAuditPreparationError, match="^INTENT_DIGEST_MISMATCH$"
    ):
        validate_audit_preparation_intent(tampered, repo_root=ROOT)

    tampered = dict(intent)
    tampered["runtime_approver_permission_set_arn_digest"] = tampered[
        "runtime_classifier_permission_set_arn_digest"
    ]
    _recalculate_intent_checksum(tampered)
    with pytest.raises(
        IdentityCenterAuditPreparationError,
        match="^INTENT_OPERATOR_BINDING_INVALID$",
    ):
        validate_audit_preparation_intent(tampered, repo_root=ROOT)

    tampered = dict(intent)
    tampered["runtime_approver_user_id_digest"] = tampered["auditor_user_id_digest"]
    _recalculate_intent_checksum(tampered)
    with pytest.raises(
        IdentityCenterAuditPreparationError,
        match="^INTENT_OPERATOR_BINDING_INVALID$",
    ):
        validate_audit_preparation_intent(tampered, repo_root=ROOT)

    tampered = dict(intent)
    tampered["allowed_operator_set_digest"] = "sha256:" + "1" * 64
    _recalculate_intent_checksum(tampered)
    with pytest.raises(
        IdentityCenterAuditPreparationError,
        match="^INTENT_OPERATOR_SET_INVALID$",
    ):
        validate_audit_preparation_intent(tampered, repo_root=ROOT)


def test_module_has_no_cloud_network_or_process_execution_capability() -> None:
    tree = ast.parse(MODULE_PATH.read_text(encoding="utf-8"))
    forbidden_modules = {"boto3", "botocore", "subprocess", "socket", "urllib", "requests"}
    imported_roots: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported_roots.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported_roots.add(node.module.split(".")[0])
    assert imported_roots.isdisjoint(forbidden_modules)
    assert not any(
        isinstance(node, ast.If)
        and isinstance(node.test, ast.Compare)
        and any(
            isinstance(item, ast.Constant) and item.value == "__main__"
            for item in ast.walk(node.test)
        )
        for node in ast.walk(tree)
    )
