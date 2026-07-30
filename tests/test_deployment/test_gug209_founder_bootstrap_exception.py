"""Fail-closed contract tests for the bounded GUG-209 founder exception.

The exception is intentionally not an alternate approval path.  It is a
separate, exact, non-production recovery control which records the absence of
an independent approver and can never be consumed more than once.
"""
from __future__ import annotations

import copy
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from tooling.founder_bootstrap_exception import (
    FOUNDER_AUTHORITY_ACCOUNT_ID,
    FOUNDER_REGION,
    FOUNDER_APPLY_PERMISSION_SET,
    FOUNDER_PLAN_PERMISSION_SET,
    model_founder_apply_transition,
    build_founder_bootstrap_exception,
    build_founder_execution_ledger,
    build_founder_revocation,
    model_founder_execution_outcome,
    render_founder_bootstrap_policy,
    validate_founder_bootstrap_exception,
)
from tooling.platform_authority_bootstrap import (
    PUBLIC_ACCESS_BLOCK,
    BootstrapAuthorizationError,
    BootstrapBinding,
    build_bootstrap_approval,
    build_bootstrap_plan,
    canonical_digest,
)


REPO_ROOT = Path(__file__).resolve().parents[2]
FOUNDER_OPERATOR_ID = "founder-operator"
FOUNDER_USER_ID = "11111111-2222-3333-4444-555555555555"
OTHER_USER_ID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
FOUNDER_PLAN_ARN = (
    "arn:aws:sts::042360977644:assumed-role/"
    "AWSReservedSSO_ScanalyzeFounderBootstrapPlan_0123456789ABCDEF/founder-plan"
)
FOUNDER_APPLY_ARN = (
    "arn:aws:sts::042360977644:assumed-role/"
    "AWSReservedSSO_ScanalyzeFounderBootstrapApply_0123456789ABCDEF/founder-apply"
)
EXCEPTION_ID = "fbe-gug209-20300101"
BASE = datetime(2030, 1, 1, 0, 0, tzinfo=UTC)


def _binding() -> BootstrapBinding:
    return BootstrapBinding(
        authority_account_id=FOUNDER_AUTHORITY_ACCOUNT_ID,
        region=FOUNDER_REGION,
        stack_name="scanalyze-platform-authority-state-backend",
        state_bucket_name=(
            "scanalyze-platform-authority-042360977644-us-east-1-state"
        ),
        state_key="platform-authority/terraform.tfstate",
        destination_account_ids=("111122223333",),
    )


def _times() -> dict[str, datetime]:
    revoked = BASE
    quarantine = revoked + timedelta(hours=12)
    return {
        "standard_plan_access_revoked_at": revoked,
        "standard_plan_session_quarantine_until": quarantine,
        "founder_plan_not_before": quarantine,
        "founder_plan_expires_at": quarantine + timedelta(minutes=15),
        "founder_apply_not_before": quarantine + timedelta(minutes=20),
        "founder_apply_expires_at": quarantine + timedelta(minutes=30),
        "plan_created_at": quarantine + timedelta(minutes=2),
        "exception_created_at": quarantine + timedelta(minutes=3),
    }


def _plan() -> dict:
    times = _times()
    return build_bootstrap_plan(
        binding=_binding(),
        caller_account_id=FOUNDER_AUTHORITY_ACCOUNT_ID,
        caller_arn=FOUNDER_PLAN_ARN,
        template_sha256="a" * 64,
        change_set_id=(
            "arn:aws:cloudformation:us-east-1:042360977644:changeSet/"
            f"scanalyze-founder-bootstrap-{EXCEPTION_ID}/"
            "00000000-0000-4000-8000-000000000000"
        ),
        change_set_type="CREATE",
        resource_changes=(
            {
                "action": "Add",
                "logical_resource_id": "StateKmsKey",
                "resource_type": "AWS::KMS::Key",
            },
            {
                "action": "Add",
                "logical_resource_id": "StateKmsAlias",
                "resource_type": "AWS::KMS::Alias",
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
        account_public_access_block_before=PUBLIC_ACCESS_BLOCK,
        created_at=times["plan_created_at"],
        expires_at=times["plan_created_at"] + timedelta(hours=1),
        initiator_id=FOUNDER_OPERATOR_ID,
    )


def _exception(**overrides: object) -> dict:
    times = _times()
    values: dict[str, object] = {
        "plan": _plan(),
        "exception_id": EXCEPTION_ID,
        "operator_id": FOUNDER_OPERATOR_ID,
        "operator_identity_store_user_id": FOUNDER_USER_ID,
        "founder_plan_principal_arn": FOUNDER_PLAN_ARN,
        "founder_apply_principal_arn": FOUNDER_APPLY_ARN,
        "risk_acceptance_id": "gug-209-founder-single-operator",
        "created_at": times["exception_created_at"],
        "standard_plan_access_revoked_at": times["standard_plan_access_revoked_at"],
        "standard_plan_session_quarantine_until": times[
            "standard_plan_session_quarantine_until"
        ],
        "founder_plan_not_before": times["founder_plan_not_before"],
        "founder_plan_expires_at": times["founder_plan_expires_at"],
        "founder_apply_not_before": times["founder_apply_not_before"],
        "founder_apply_expires_at": times["founder_apply_expires_at"],
    }
    values.update(overrides)
    return build_founder_bootstrap_exception(**values)  # type: ignore[arg-type]


def _redigest(record: dict, field: str) -> dict:
    changed = copy.deepcopy(record)
    changed[field] = canonical_digest({key: value for key, value in changed.items() if key != field})
    return changed


def _actions(policy: dict) -> set[str]:
    result: set[str] = set()
    for statement in policy["Statement"]:
        if statement["Effect"] != "Allow":
            continue
        actions = statement["Action"]
        result.update(actions if isinstance(actions, list) else [actions])
    return result


def _statements_by_sid(policy: dict) -> dict[str, dict]:
    return {statement["Sid"]: statement for statement in policy["Statement"]}


def test_valid_exception_is_exactly_bound_and_explicitly_not_independent() -> None:
    exception = _exception()

    validate_founder_bootstrap_exception(exception)
    assert exception["authority_account_id"] == FOUNDER_AUTHORITY_ACCOUNT_ID
    assert exception["region"] == FOUNDER_REGION
    assert exception["environment"] == "non-production"
    assert exception["approval_mode"] == "SINGLE_OPERATOR_FOUNDER_EXCEPTION"
    assert exception["independent_approval_present"] is False
    assert exception["approver_id"] is None
    assert exception["single_execution"] is True
    assert exception["live_execution_status"] == "BLOCKED_DURABLE_LEDGER_REQUIRED"
    assert exception["operator_subject_digest"] == canonical_digest(
        {"identity_store_user_id": FOUNDER_USER_ID}
    )
    assert {change["logical_resource_id"] for change in exception["planned_resource_changes"]} == {
        "StateKmsKey",
        "StateKmsAlias",
        "StateBucket",
        "StateBucketPolicy",
    }


def test_normal_bootstrap_flow_still_rejects_self_approval() -> None:
    plan = _plan()
    with pytest.raises(BootstrapAuthorizationError, match="independent"):
        build_bootstrap_approval(
            plan=plan,
            initiator_id=FOUNDER_OPERATOR_ID,
            approver_id=FOUNDER_OPERATOR_ID,
            approver_arn=FOUNDER_APPLY_ARN,
            approved_at=_times()["plan_created_at"] + timedelta(minutes=1),
            expires_at=_times()["plan_created_at"] + timedelta(minutes=30),
        )


@pytest.mark.parametrize(
    ("field", "value", "match"),
    [
        ("authority_account_id", "042360977645", "authority account"),
        ("region", "us-west-2", "authority region"),
        ("account_public_access_block_before", None, "pre-hardened"),
    ],
)
def test_exception_rejects_foreign_or_unhardened_plan(
    field: str, value: object, match: str
) -> None:
    plan = _plan()
    plan[field] = value
    plan = _redigest(plan, "record_digest")
    with pytest.raises(BootstrapAuthorizationError, match=match):
        _exception(plan=plan)


def test_exception_rejects_nonexact_change_inventory_and_temporal_overlap() -> None:
    plan = _plan()
    plan["planned_resource_changes"] = plan["planned_resource_changes"][:-1]
    plan = _redigest(plan, "record_digest")
    with pytest.raises(BootstrapAuthorizationError, match="exactly four"):
        _exception(plan=plan)

    times = _times()
    with pytest.raises(BootstrapAuthorizationError, match="quarantine"):
        _exception(
            standard_plan_session_quarantine_until=(
                times["standard_plan_access_revoked_at"] + timedelta(hours=11, minutes=59)
            )
        )
    with pytest.raises(BootstrapAuthorizationError, match="non-overlap"):
        _exception(founder_apply_not_before=times["founder_plan_expires_at"])


def test_exception_rejects_malformed_or_ambiguous_authorization_claims() -> None:
    exception = _exception()
    tampered = copy.deepcopy(exception)
    tampered["independent_approval_present"] = True
    tampered = _redigest(tampered, "exception_digest")
    with pytest.raises(BootstrapAuthorizationError, match="independent approval"):
        validate_founder_bootstrap_exception(tampered)

    tampered = copy.deepcopy(exception)
    tampered["approver_id"] = "invented-reviewer"
    tampered = _redigest(tampered, "exception_digest")
    with pytest.raises(BootstrapAuthorizationError, match="approver"):
        validate_founder_bootstrap_exception(tampered)

    tampered = copy.deepcopy(exception)
    tampered["unexpected_authority"] = "allow"
    tampered = _redigest(tampered, "exception_digest")
    with pytest.raises(BootstrapAuthorizationError, match="unexpected fields"):
        validate_founder_bootstrap_exception(tampered)

    tampered = copy.deepcopy(exception)
    tampered["live_execution_status"] = "LIVE_EXECUTION_ALLOWED"
    tampered = _redigest(tampered, "exception_digest")
    with pytest.raises(BootstrapAuthorizationError, match="live execution"):
        validate_founder_bootstrap_exception(tampered)


def test_offline_apply_model_requires_exact_operator_window_and_rejects_consumed_model() -> None:
    exception = _exception()
    ledger = build_founder_execution_ledger(
        exception=exception,
        created_at=_times()["founder_apply_not_before"] - timedelta(minutes=1),
    )

    with pytest.raises(BootstrapAuthorizationError, match="operator"):
        model_founder_apply_transition(
            exception=exception,
            plan=_plan(),
            ledger=ledger,
            caller_identity_store_user_id=OTHER_USER_ID,
            caller_arn=FOUNDER_APPLY_ARN,
            now=_times()["founder_apply_not_before"],
        )
    with pytest.raises(BootstrapAuthorizationError, match="not active"):
        model_founder_apply_transition(
            exception=exception,
            plan=_plan(),
            ledger=ledger,
            caller_identity_store_user_id=FOUNDER_USER_ID,
            caller_arn=FOUNDER_APPLY_ARN,
            now=_times()["founder_apply_not_before"] - timedelta(seconds=1),
        )

    consumed = model_founder_apply_transition(
        exception=exception,
        plan=_plan(),
        ledger=ledger,
        caller_identity_store_user_id=FOUNDER_USER_ID,
        caller_arn=FOUNDER_APPLY_ARN,
        now=_times()["founder_apply_not_before"],
    )
    assert consumed["state"] == "EXECUTION_ATTEMPTED"
    assert consumed["attempt_count"] == 1
    with pytest.raises(BootstrapAuthorizationError, match="already consumed"):
        model_founder_apply_transition(
            exception=exception,
            plan=_plan(),
            ledger=consumed,
            caller_identity_store_user_id=FOUNDER_USER_ID,
            caller_arn=FOUNDER_APPLY_ARN,
            now=_times()["founder_apply_not_before"] + timedelta(seconds=1),
        )


def test_rendered_policies_bind_time_identity_and_exact_change_set() -> None:
    exception = _exception()
    plan_policy = render_founder_bootstrap_policy(
        mode="plan",
        exception=exception,
        operator_identity_store_user_id=FOUNDER_USER_ID,
    )
    apply_policy = render_founder_bootstrap_policy(
        mode="apply",
        exception=exception,
        operator_identity_store_user_id=FOUNDER_USER_ID,
    )

    assert FOUNDER_PLAN_PERMISSION_SET == "ScanalyzeFounderBootstrapPlan"
    assert FOUNDER_APPLY_PERMISSION_SET == "ScanalyzeFounderBootstrapApply"
    assert len(FOUNDER_PLAN_PERMISSION_SET) <= 32
    assert len(FOUNDER_APPLY_PERMISSION_SET) <= 32
    assert "cloudformation:ExecuteChangeSet" not in _actions(plan_policy)
    assert "s3:PutAccountPublicAccessBlock" not in _actions(apply_policy)
    assert "kms:DeleteAlias" not in _actions(apply_policy)
    assert "kms:UpdateAlias" not in _actions(apply_policy)
    assert {
        "DenyBeforeFounderPlanWindow",
        "DenyAfterFounderPlanWindow",
        "DenyNonFounderPlanSubject",
        "DenyDirectAccountPublicAccessBlockMutation",
        "DenyOfflineOnlyFounderPlanMutations",
    } <= {statement["Sid"] for statement in plan_policy["Statement"]}
    assert {
        "DenyBeforeFounderApplyWindow",
        "DenyAfterFounderApplyWindow",
        "DenyNonFounderApplySubject",
        "DenyDirectAccountPublicAccessBlockMutation",
        "DenyFounderAliasRetargeting",
    } <= {statement["Sid"] for statement in apply_policy["Statement"]}
    stack_arn = (
        f"arn:aws:cloudformation:{FOUNDER_REGION}:{FOUNDER_AUTHORITY_ACCOUNT_ID}:"
        "stack/scanalyze-platform-authority-state-backend/*"
    )
    change_set_name = f"scanalyze-founder-bootstrap-{EXCEPTION_ID}"
    plan_statements = _statements_by_sid(plan_policy)
    apply_statements = _statements_by_sid(apply_policy)
    expected_tags = {
        "aws:RequestTag/managed_by": "cloudformation",
        "aws:RequestTag/service": "scanalyze-platform-authority",
        "aws:RequestTag/work_package": "GUG-206",
    }
    assert plan_statements["CreateOnlyExactExceptionBoundChangeSet"]["Resource"] == stack_arn
    assert plan_statements["CreateOnlyExactExceptionBoundChangeSet"]["Condition"] == {
        "StringEquals": {"cloudformation:ChangeSetName": change_set_name, **expected_tags},
        "ForAllValues:StringEquals": {"aws:TagKeys": ["managed_by", "service", "work_package"]},
    }
    assert plan_statements["DeleteOnlyExactExceptionBoundChangeSet"]["Resource"] == stack_arn
    assert plan_statements["DeleteOnlyExactExceptionBoundChangeSet"]["Condition"] == {
        "StringEquals": {"cloudformation:ChangeSetName": change_set_name}
    }
    assert plan_statements["TagOnlyExactExceptionBoundChangeSetAtCreate"]["Action"] == "cloudformation:TagResource"
    assert plan_statements["TagOnlyExactExceptionBoundChangeSetAtCreate"]["Resource"] == [
        stack_arn,
        f"arn:aws:cloudformation:{FOUNDER_REGION}:{FOUNDER_AUTHORITY_ACCOUNT_ID}:changeSet/{change_set_name}/*",
    ]
    assert plan_statements["TagOnlyExactExceptionBoundChangeSetAtCreate"]["Condition"] == {
        "StringEquals": {"cloudformation:CreateAction": "CreateChangeSet", **expected_tags},
        "ForAllValues:StringEquals": {"aws:TagKeys": ["managed_by", "service", "work_package"]},
    }
    assert set(plan_statements["DenyOfflineOnlyFounderPlanMutations"]["Action"]) == {
        "cloudformation:CreateChangeSet",
        "cloudformation:DeleteChangeSet",
        "cloudformation:TagResource",
        "cloudformation:UntagResource",
    }
    assert apply_statements["ExecuteOnlyExactFounderChangeSet"]["Resource"] == stack_arn
    assert apply_statements["ExecuteOnlyExactFounderChangeSet"]["Condition"] == {
        "StringEquals": {"cloudformation:ChangeSetName": change_set_name}
    }
    assert apply_statements["CreateExactStateKeyAliasViaCloudFormation"]["Action"] == "kms:CreateAlias"
    assert "Condition" not in apply_statements["CreateExactStateKeyAliasViaCloudFormation"]
    assert apply_statements["BindCreateAliasOnlyToTaggedStateKeyViaCloudFormation"]["Action"] == "kms:CreateAlias"
    assert apply_statements["BindCreateAliasOnlyToTaggedStateKeyViaCloudFormation"]["Condition"][
        "ForAnyValue:StringEquals"
    ] == {"aws:CalledVia": ["cloudformation.amazonaws.com"]}
    assert "cloudformation:ExecuteChangeSet" in apply_statements[
        "DenyOfflineOnlyFounderApplyMutations"
    ]["Action"]
    rendered = str(apply_policy)
    assert exception["change_set_id"] not in rendered
    assert change_set_name in rendered
    assert FOUNDER_USER_ID in rendered

    with pytest.raises(BootstrapAuthorizationError, match="operator subject"):
        render_founder_bootstrap_policy(
            mode="apply",
            exception=exception,
            operator_identity_store_user_id=OTHER_USER_ID,
        )


def test_revocation_never_allows_success_until_expired_and_structurally_verified() -> None:
    exception = _exception()
    ledger = model_founder_apply_transition(
        exception=exception,
        plan=_plan(),
        ledger=build_founder_execution_ledger(
            exception=exception,
            created_at=_times()["founder_apply_not_before"] - timedelta(minutes=1),
        ),
        caller_identity_store_user_id=FOUNDER_USER_ID,
        caller_arn=FOUNDER_APPLY_ARN,
        now=_times()["founder_apply_not_before"],
    )
    with pytest.raises(BootstrapAuthorizationError, match="expiry"):
        build_founder_revocation(
            exception=exception,
            checked_at=_times()["founder_apply_expires_at"] - timedelta(seconds=1),
            plan_assignment_absent=True,
            plan_membership_absent=True,
            apply_assignment_absent=True,
            apply_membership_absent=True,
            time_bound_deny_retained=True,
        )

    incomplete = build_founder_revocation(
        exception=exception,
        checked_at=_times()["founder_apply_expires_at"] + timedelta(minutes=1),
        plan_assignment_absent=True,
        plan_membership_absent=True,
        apply_assignment_absent=False,
        apply_membership_absent=True,
        time_bound_deny_retained=True,
    )
    assert incomplete["status"] == "REVOCATION_REQUIRED"
    with pytest.raises(BootstrapAuthorizationError, match="revocation"):
        model_founder_execution_outcome(
            ledger=ledger,
            outcome="SUCCEEDED",
            completed_at=_times()["founder_apply_expires_at"] + timedelta(minutes=1),
            revocation=incomplete,
        )

    revoked = build_founder_revocation(
        exception=exception,
        checked_at=_times()["founder_apply_expires_at"] + timedelta(minutes=1),
        plan_assignment_absent=True,
        plan_membership_absent=True,
        apply_assignment_absent=True,
        apply_membership_absent=True,
        time_bound_deny_retained=True,
    )
    completed = model_founder_execution_outcome(
        ledger=ledger,
        outcome="SUCCEEDED",
        completed_at=_times()["founder_apply_expires_at"] + timedelta(minutes=1),
        revocation=revoked,
    )
    assert revoked["status"] == "REVOKED"
    assert completed["state"] == "SUCCEEDED"


def test_founder_policy_templates_are_present_and_never_grant_apply_pab_write() -> None:
    plan_template = REPO_ROOT / "policies/iam/platform-authority-founder-bootstrap-plan-role.json"
    apply_template = REPO_ROOT / "policies/iam/platform-authority-founder-bootstrap-apply-role.json"
    assert plan_template.is_file()
    assert apply_template.is_file()
    apply_policy = json.loads(apply_template.read_text(encoding="utf-8"))
    assert "s3:PutAccountPublicAccessBlock" not in _actions(apply_policy)
    assert "kms:DeleteAlias" not in _actions(apply_policy)
    assert "kms:UpdateAlias" not in _actions(apply_policy)
    assert "DenyDirectAccountPublicAccessBlockMutation" in _statements_by_sid(apply_policy)
