"""Fail-closed contracts for the bounded single-operator founder exception.

This module intentionally does *not* relax the normal GUG-206 independent
approval path. It validates an offline model of a separately authorized,
one-time recovery boundary for an otherwise empty dedicated
platform-authority account. It has no AWS client and cannot authorize or
execute a Change Set. A future live PEP must persist an execution-ledger
transition with compare-and-swap semantics and re-read the exact Change Set,
template, and resource inventory before it performs any external effect.
"""
from __future__ import annotations

import json
import re
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Mapping, Sequence

from tooling.platform_authority_bootstrap import (
    PUBLIC_ACCESS_BLOCK,
    BootstrapAuthorizationError,
    canonical_digest,
)


REPO_ROOT = Path(__file__).resolve().parents[1]
FOUNDER_AUTHORITY_ACCOUNT_ID = "042360977644"
FOUNDER_REGION = "us-east-1"
FOUNDER_ENVIRONMENT = "non-production"
FOUNDER_APPROVAL_MODE = "SINGLE_OPERATOR_FOUNDER_EXCEPTION"
FOUNDER_EXCEPTION_REASON = "NO_SECOND_QUALIFIED_OPERATOR"
FOUNDER_PLAN_PERMISSION_SET = "ScanalyzeFounderBootstrapPlan"
FOUNDER_APPLY_PERMISSION_SET = "ScanalyzeFounderBootstrapApply"
FOUNDER_LIVE_EXECUTION_STATUS = "BLOCKED_DURABLE_LEDGER_REQUIRED"
FOUNDER_STACK_NAME = "scanalyze-platform-authority-state-backend"
FOUNDER_STATE_KEY = "platform-authority/terraform.tfstate"
FOUNDER_QUARANTINE = timedelta(hours=12)
FOUNDER_DENY_RETENTION = timedelta(hours=12)
MIN_PLAN_WINDOW = timedelta(minutes=5)
MAX_PLAN_WINDOW = timedelta(minutes=30)
MIN_APPLY_WINDOW = timedelta(minutes=5)
MAX_APPLY_WINDOW = timedelta(minutes=15)
MIN_PLAN_APPLY_GAP = timedelta(minutes=5)

FOUNDER_PLAN_OFFLINE_DENY_ACTIONS = frozenset(
    {
        "cloudformation:CreateChangeSet",
        "cloudformation:DeleteChangeSet",
        "cloudformation:TagResource",
        "cloudformation:UntagResource",
    }
)
FOUNDER_APPLY_OFFLINE_DENY_ACTIONS = frozenset(
    {
        "cloudformation:ExecuteChangeSet",
        "s3:CreateBucket",
        "s3:PutEncryptionConfiguration",
        "s3:PutBucketOwnershipControls",
        "s3:PutBucketPolicy",
        "s3:PutBucketPublicAccessBlock",
        "s3:PutBucketTagging",
        "s3:PutBucketVersioning",
        "s3:PutLifecycleConfiguration",
        "kms:CreateKey",
        "kms:EnableKeyRotation",
        "kms:PutKeyPolicy",
        "kms:TagResource",
        "kms:CreateAlias",
        "kms:DeleteAlias",
        "kms:UpdateAlias",
    }
)

ACCOUNT_ID = re.compile(r"^(?!000000000000$)[0-9]{12}$")
REGION = re.compile(r"^[a-z]{2}(?:-[a-z]+)+-[0-9]+$")
SHA256 = re.compile(r"^sha256:[a-f0-9]{64}$")
EXCEPTION_ID = re.compile(r"^[a-z][a-z0-9-]{7,63}$")
OPERATOR_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{2,127}$")
IDENTITY_STORE_USER_ID = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
)
CHANGE_SET_ARN = re.compile(
    r"^arn:(?P<partition>aws(?:-us-gov|-cn)?):cloudformation:"
    r"(?P<region>[a-z0-9-]+):(?P<account>[0-9]{12}):"
    r"changeSet/(?P<name>[A-Za-z][-A-Za-z0-9]*)/(?P<id>[0-9a-f-]{36})$"
)
UNBOUND_PLACEHOLDER = re.compile(r"\$\{[a-z_]+\}")

EXPECTED_PLAN_KEYS = frozenset(
    {
        "schema_version",
        "record_type",
        "authority_account_id",
        "region",
        "stack_name",
        "state_bucket_name",
        "state_key",
        "destination_account_ids",
        "native_lockfile_enabled",
        "template_sha256",
        "caller_principal_digest",
        "change_set_id",
        "change_set_type",
        "planned_resource_changes",
        "account_public_access_block_before",
        "account_public_access_block_after",
        "initiator_id",
        "created_at",
        "expires_at",
        "record_digest",
    }
)
EXPECTED_EXCEPTION_KEYS = frozenset(
    {
        "schema_version",
        "record_type",
        "exception_id",
        "approval_mode",
        "exception_reason",
        "independent_approval_present",
        "approver_id",
        "risk_acceptance_id",
        "risk_acceptance_digest",
        "authority_account_id",
        "region",
        "environment",
        "production",
        "operator_id",
        "operator_subject_digest",
        "founder_plan_principal_digest",
        "founder_apply_principal_digest",
        "plan_record_digest",
        "template_sha256",
        "change_set_id",
        "planned_resource_changes",
        "review_stack_status",
        "review_stack_resource_count",
        "change_set_status",
        "change_set_execution_status",
        "standard_plan_access_revoked_at",
        "standard_plan_session_quarantine_until",
        "founder_plan_not_before",
        "founder_plan_expires_at",
        "founder_apply_not_before",
        "founder_apply_expires_at",
        "automatic_deny_retain_until",
        "single_execution",
        "live_execution_status",
        "created_at",
        "exception_digest",
    }
)
EXPECTED_LEDGER_KEYS = frozenset(
    {
        "schema_version",
        "record_type",
        "exception_id",
        "exception_digest",
        "plan_record_digest",
        "authority_account_id",
        "region",
        "change_set_id",
        "live_execution_status",
        "attempt_count",
        "state",
        "execution_started_at",
        "outcome",
        "created_at",
        "updated_at",
        "ledger_digest",
    }
)
EXPECTED_REVOCATION_KEYS = frozenset(
    {
        "schema_version",
        "record_type",
        "exception_id",
        "exception_digest",
        "authority_account_id",
        "region",
        "automatic_deny_retain_until",
        "checked_at",
        "plan_assignment_absent",
        "plan_membership_absent",
        "apply_assignment_absent",
        "apply_membership_absent",
        "time_bound_deny_retained",
        "status",
        "revocation_digest",
    }
)

EXPECTED_RESOURCE_CHANGES = tuple(
    sorted(
        (
            {
                "action": "Add",
                "logical_resource_id": "StateKmsKey",
                "resource_type": "AWS::KMS::Key",
                "replacement": "False",
            },
            {
                "action": "Add",
                "logical_resource_id": "StateKmsAlias",
                "resource_type": "AWS::KMS::Alias",
                "replacement": "False",
            },
            {
                "action": "Add",
                "logical_resource_id": "StateBucket",
                "resource_type": "AWS::S3::Bucket",
                "replacement": "False",
            },
            {
                "action": "Add",
                "logical_resource_id": "StateBucketPolicy",
                "resource_type": "AWS::S3::BucketPolicy",
                "replacement": "False",
            },
        ),
        key=lambda item: item["logical_resource_id"],
    )
)


def _timestamp(value: datetime, label: str) -> str:
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise BootstrapAuthorizationError(f"{label} must be timezone-aware")
    return value.astimezone(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _parse_timestamp(value: object, label: str) -> datetime:
    if not isinstance(value, str):
        raise BootstrapAuthorizationError(f"{label} is missing")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise BootstrapAuthorizationError(f"{label} is invalid") from exc
    if parsed.tzinfo is None:
        raise BootstrapAuthorizationError(f"{label} must be timezone-aware")
    return parsed.astimezone(UTC)


def _require_exact_keys(document: Mapping[str, Any], expected: frozenset[str], label: str) -> None:
    actual = set(document)
    if actual != set(expected):
        missing = expected - actual
        unexpected = actual - expected
        if unexpected:
            raise BootstrapAuthorizationError(f"{label} has unexpected fields")
        if missing:
            raise BootstrapAuthorizationError(f"{label} is missing required fields")
        raise BootstrapAuthorizationError(f"{label} fields are invalid")


def _require_digest(document: Mapping[str, Any], field: str, label: str) -> None:
    value = document.get(field)
    if not isinstance(value, str) or SHA256.fullmatch(value) is None:
        raise BootstrapAuthorizationError(f"{label} digest is malformed")
    expected = canonical_digest({key: item for key, item in document.items() if key != field})
    if value != expected:
        raise BootstrapAuthorizationError(f"{label} digest mismatch")


def _require_digest_format(value: object, label: str) -> str:
    if not isinstance(value, str) or SHA256.fullmatch(value) is None:
        raise BootstrapAuthorizationError(f"{label} must be a SHA-256 digest")
    return value


def _require_operator_id(value: object, label: str) -> str:
    if not isinstance(value, str) or OPERATOR_ID.fullmatch(value) is None:
        raise BootstrapAuthorizationError(f"{label} is invalid")
    return value


def _require_exception_id(value: object) -> str:
    if not isinstance(value, str) or EXCEPTION_ID.fullmatch(value) is None:
        raise BootstrapAuthorizationError("founder exception ID is invalid")
    return value


def _require_identity_store_user_id(value: object) -> str:
    if not isinstance(value, str) or IDENTITY_STORE_USER_ID.fullmatch(value) is None:
        raise BootstrapAuthorizationError("founder operator identity subject is invalid")
    return value


def _require_founder_arn(value: object, *, permission_set: str, label: str) -> str:
    if not isinstance(value, str):
        raise BootstrapAuthorizationError(f"{label} is missing")
    expected = (
        rf"^arn:aws:sts::{FOUNDER_AUTHORITY_ACCOUNT_ID}:assumed-role/"
        rf"AWSReservedSSO_{re.escape(permission_set)}_[0-9A-Fa-f]{{16}}/"
        rf"[A-Za-z0-9+=,.@_-]{{2,64}}$"
    )
    if re.fullmatch(expected, value) is None:
        raise BootstrapAuthorizationError(f"{label} is not the exact founder SSO role")
    return value


def _require_exact_resource_changes(value: object) -> list[dict[str, str]]:
    if not isinstance(value, list):
        raise BootstrapAuthorizationError("founder change set resource inventory is invalid")
    normalized: list[dict[str, str]] = []
    for item in value:
        if not isinstance(item, Mapping):
            raise BootstrapAuthorizationError("founder change set resource inventory is invalid")
        if set(item) != {"action", "logical_resource_id", "resource_type", "replacement"}:
            raise BootstrapAuthorizationError("founder change set resource inventory is invalid")
        normalized.append(
            {
                "action": item.get("action"),  # type: ignore[arg-type]
                "logical_resource_id": item.get("logical_resource_id"),  # type: ignore[arg-type]
                "resource_type": item.get("resource_type"),  # type: ignore[arg-type]
                "replacement": item.get("replacement"),  # type: ignore[arg-type]
            }
        )
    if len(normalized) != 4 or tuple(sorted(normalized, key=lambda item: item["logical_resource_id"])) != EXPECTED_RESOURCE_CHANGES:
        raise BootstrapAuthorizationError("founder change set must contain exactly four canonical resources")
    return list(EXPECTED_RESOURCE_CHANGES)


def _change_set_parts(value: object, exception_id: str) -> dict[str, str]:
    if not isinstance(value, str):
        raise BootstrapAuthorizationError("founder Change Set ARN is missing")
    match = CHANGE_SET_ARN.fullmatch(value)
    if match is None:
        raise BootstrapAuthorizationError("founder Change Set ARN is malformed")
    if (
        match.group("partition") != "aws"
        or match.group("account") != FOUNDER_AUTHORITY_ACCOUNT_ID
        or match.group("region") != FOUNDER_REGION
    ):
        raise BootstrapAuthorizationError("founder Change Set ARN is outside the authority boundary")
    expected_name = f"scanalyze-founder-bootstrap-{exception_id}"
    if match.group("name") != expected_name:
        raise BootstrapAuthorizationError("founder Change Set name is not exception-bound")
    return {
        "partition": match.group("partition"),
        "region": match.group("region"),
        "account": match.group("account"),
        "name": match.group("name"),
        "id": match.group("id"),
    }


def _expected_bucket() -> str:
    return f"scanalyze-platform-authority-{FOUNDER_AUTHORITY_ACCOUNT_ID}-{FOUNDER_REGION}-state"


def _validate_founder_plan(
    plan: Mapping[str, Any],
    *,
    exception_id: str,
    operator_id: str,
    founder_plan_principal_arn: str | None = None,
    expected_plan_principal_digest: str | None = None,
    minimum_not_before: datetime | None = None,
    maximum_apply_expires_at: datetime | None = None,
) -> dict[str, Any]:
    _require_exact_keys(plan, EXPECTED_PLAN_KEYS, "founder source plan")
    _require_digest(plan, "record_digest", "founder source plan")
    if plan.get("schema_version") != "1" or plan.get("record_type") != "platform_authority_bootstrap_plan":
        raise BootstrapAuthorizationError("founder source plan type is invalid")
    if plan.get("authority_account_id") != FOUNDER_AUTHORITY_ACCOUNT_ID:
        raise BootstrapAuthorizationError("founder source plan authority account is invalid")
    if plan.get("region") != FOUNDER_REGION:
        raise BootstrapAuthorizationError("founder source plan authority region is invalid")
    if plan.get("stack_name") != FOUNDER_STACK_NAME:
        raise BootstrapAuthorizationError("founder source plan stack binding is invalid")
    if plan.get("state_bucket_name") != _expected_bucket() or plan.get("state_key") != FOUNDER_STATE_KEY:
        raise BootstrapAuthorizationError("founder source plan state binding is invalid")
    destinations = plan.get("destination_account_ids")
    if (
        not isinstance(destinations, list)
        or not destinations
        or any(not isinstance(item, str) or ACCOUNT_ID.fullmatch(item) is None for item in destinations)
        or FOUNDER_AUTHORITY_ACCOUNT_ID in destinations
        or len(set(destinations)) != len(destinations)
    ):
        raise BootstrapAuthorizationError("founder source plan destination binding is invalid")
    if plan.get("native_lockfile_enabled") is not True:
        raise BootstrapAuthorizationError("founder source plan native lockfile is missing")
    _require_digest_format(plan.get("template_sha256"), "founder template digest")
    if founder_plan_principal_arn is not None:
        expected_principal_digest = canonical_digest({"caller_arn": founder_plan_principal_arn})
    elif expected_plan_principal_digest is not None:
        expected_principal_digest = _require_digest_format(
            expected_plan_principal_digest, "founder Plan principal digest"
        )
    else:
        raise BootstrapAuthorizationError("founder source plan principal proof is missing")
    if plan.get("caller_principal_digest") != expected_principal_digest:
        raise BootstrapAuthorizationError("founder source plan principal is invalid")
    if plan.get("change_set_type") != "CREATE":
        raise BootstrapAuthorizationError("founder source plan must be a CREATE change set")
    _change_set_parts(plan.get("change_set_id"), exception_id)
    _require_exact_resource_changes(plan.get("planned_resource_changes"))
    if plan.get("account_public_access_block_before") != PUBLIC_ACCESS_BLOCK:
        raise BootstrapAuthorizationError("founder source plan requires pre-hardened account public access block")
    if plan.get("account_public_access_block_after") != PUBLIC_ACCESS_BLOCK:
        raise BootstrapAuthorizationError("founder source plan public access block transition is invalid")
    if plan.get("initiator_id") != operator_id:
        raise BootstrapAuthorizationError("founder source plan operator binding is invalid")
    created_at = _parse_timestamp(plan.get("created_at"), "founder source plan created_at")
    expires_at = _parse_timestamp(plan.get("expires_at"), "founder source plan expires_at")
    if not created_at < expires_at:
        raise BootstrapAuthorizationError("founder source plan lifetime is invalid")
    if minimum_not_before is not None and created_at < minimum_not_before:
        raise BootstrapAuthorizationError("founder source plan precedes the required quarantine")
    if maximum_apply_expires_at is not None and expires_at < maximum_apply_expires_at:
        raise BootstrapAuthorizationError("founder source plan expires before the apply window")
    return dict(plan)


def build_founder_bootstrap_exception(
    *,
    plan: Mapping[str, Any],
    exception_id: str,
    operator_id: str,
    operator_identity_store_user_id: str,
    founder_plan_principal_arn: str,
    founder_apply_principal_arn: str,
    risk_acceptance_id: str,
    created_at: datetime,
    standard_plan_access_revoked_at: datetime,
    standard_plan_session_quarantine_until: datetime,
    founder_plan_not_before: datetime,
    founder_plan_expires_at: datetime,
    founder_apply_not_before: datetime,
    founder_apply_expires_at: datetime,
    review_stack_status: str = "REVIEW_IN_PROGRESS",
    review_stack_resource_count: int = 0,
    change_set_status: str = "CREATE_COMPLETE",
    change_set_execution_status: str = "AVAILABLE",
) -> dict[str, Any]:
    """Build a separately auditable, fixed-boundary founder exception record."""
    exception_name = _require_exception_id(exception_id)
    operator = _require_operator_id(operator_id, "founder operator ID")
    subject = _require_identity_store_user_id(operator_identity_store_user_id)
    plan_arn = _require_founder_arn(
        founder_plan_principal_arn,
        permission_set=FOUNDER_PLAN_PERMISSION_SET,
        label="founder plan principal",
    )
    apply_arn = _require_founder_arn(
        founder_apply_principal_arn,
        permission_set=FOUNDER_APPLY_PERMISSION_SET,
        label="founder apply principal",
    )
    if plan_arn == apply_arn:
        raise BootstrapAuthorizationError("founder Plan and Apply principals must differ")
    if not isinstance(risk_acceptance_id, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{7,127}", risk_acceptance_id):
        raise BootstrapAuthorizationError("founder risk acceptance ID is invalid")
    created = _parse_timestamp(_timestamp(created_at, "exception created_at"), "exception created_at")
    revoked = _parse_timestamp(
        _timestamp(standard_plan_access_revoked_at, "standard Plan revoked_at"),
        "standard Plan revoked_at",
    )
    quarantine_until = _parse_timestamp(
        _timestamp(standard_plan_session_quarantine_until, "standard Plan quarantine_until"),
        "standard Plan quarantine_until",
    )
    plan_not_before = _parse_timestamp(
        _timestamp(founder_plan_not_before, "founder Plan not_before"),
        "founder Plan not_before",
    )
    plan_expires = _parse_timestamp(
        _timestamp(founder_plan_expires_at, "founder Plan expires_at"),
        "founder Plan expires_at",
    )
    apply_not_before = _parse_timestamp(
        _timestamp(founder_apply_not_before, "founder Apply not_before"),
        "founder Apply not_before",
    )
    apply_expires = _parse_timestamp(
        _timestamp(founder_apply_expires_at, "founder Apply expires_at"),
        "founder Apply expires_at",
    )
    if quarantine_until < revoked + FOUNDER_QUARANTINE:
        raise BootstrapAuthorizationError("standard Plan session quarantine is shorter than twelve hours")
    if plan_not_before < quarantine_until:
        raise BootstrapAuthorizationError("founder Plan window begins before the standard Plan quarantine")
    if not MIN_PLAN_WINDOW <= plan_expires - plan_not_before <= MAX_PLAN_WINDOW:
        raise BootstrapAuthorizationError("founder Plan window is outside the allowed duration")
    if not MIN_APPLY_WINDOW <= apply_expires - apply_not_before <= MAX_APPLY_WINDOW:
        raise BootstrapAuthorizationError("founder Apply window is outside the allowed duration")
    if apply_not_before - plan_expires < MIN_PLAN_APPLY_GAP:
        raise BootstrapAuthorizationError("founder Plan and Apply windows require a non-overlap gap")
    if review_stack_status != "REVIEW_IN_PROGRESS" or review_stack_resource_count != 0:
        raise BootstrapAuthorizationError("founder Change Set requires an empty review stack")
    if change_set_status != "CREATE_COMPLETE" or change_set_execution_status != "AVAILABLE":
        raise BootstrapAuthorizationError("founder Change Set is not executable")
    source_plan = _validate_founder_plan(
        plan,
        exception_id=exception_name,
        operator_id=operator,
        founder_plan_principal_arn=plan_arn,
        minimum_not_before=plan_not_before,
        maximum_apply_expires_at=apply_expires,
    )
    plan_created = _parse_timestamp(source_plan["created_at"], "founder source plan created_at")
    if not plan_not_before <= plan_created < plan_expires:
        raise BootstrapAuthorizationError("founder Change Set was not created in the Plan window")
    if not plan_created <= created < plan_expires:
        raise BootstrapAuthorizationError("founder exception was not recorded in the Plan window")
    record: dict[str, Any] = {
        "schema_version": "1",
        "record_type": "platform_authority_founder_bootstrap_exception",
        "exception_id": exception_name,
        "approval_mode": FOUNDER_APPROVAL_MODE,
        "exception_reason": FOUNDER_EXCEPTION_REASON,
        "independent_approval_present": False,
        "approver_id": None,
        "risk_acceptance_id": risk_acceptance_id,
        "risk_acceptance_digest": canonical_digest({"risk_acceptance_id": risk_acceptance_id}),
        "authority_account_id": FOUNDER_AUTHORITY_ACCOUNT_ID,
        "region": FOUNDER_REGION,
        "environment": FOUNDER_ENVIRONMENT,
        "production": False,
        "operator_id": operator,
        "operator_subject_digest": canonical_digest({"identity_store_user_id": subject}),
        "founder_plan_principal_digest": canonical_digest({"caller_arn": plan_arn}),
        "founder_apply_principal_digest": canonical_digest({"caller_arn": apply_arn}),
        "plan_record_digest": source_plan["record_digest"],
        "template_sha256": source_plan["template_sha256"],
        "change_set_id": source_plan["change_set_id"],
        "planned_resource_changes": list(EXPECTED_RESOURCE_CHANGES),
        "review_stack_status": review_stack_status,
        "review_stack_resource_count": review_stack_resource_count,
        "change_set_status": change_set_status,
        "change_set_execution_status": change_set_execution_status,
        "standard_plan_access_revoked_at": _timestamp(revoked, "standard Plan revoked_at"),
        "standard_plan_session_quarantine_until": _timestamp(
            quarantine_until, "standard Plan quarantine_until"
        ),
        "founder_plan_not_before": _timestamp(plan_not_before, "founder Plan not_before"),
        "founder_plan_expires_at": _timestamp(plan_expires, "founder Plan expires_at"),
        "founder_apply_not_before": _timestamp(apply_not_before, "founder Apply not_before"),
        "founder_apply_expires_at": _timestamp(apply_expires, "founder Apply expires_at"),
        "automatic_deny_retain_until": _timestamp(
            apply_expires + FOUNDER_DENY_RETENTION, "automatic deny retain_until"
        ),
        "single_execution": True,
        "live_execution_status": FOUNDER_LIVE_EXECUTION_STATUS,
        "created_at": _timestamp(created, "exception created_at"),
    }
    record["exception_digest"] = canonical_digest(record)
    return record


def validate_founder_bootstrap_exception(exception: Mapping[str, Any]) -> None:
    """Reject partial, legacy, ambiguous, or otherwise altered exceptions."""
    _require_exact_keys(exception, EXPECTED_EXCEPTION_KEYS, "founder exception")
    _require_digest(exception, "exception_digest", "founder exception")
    if exception.get("schema_version") != "1" or exception.get("record_type") != "platform_authority_founder_bootstrap_exception":
        raise BootstrapAuthorizationError("founder exception type is invalid")
    exception_id = _require_exception_id(exception.get("exception_id"))
    if exception.get("approval_mode") != FOUNDER_APPROVAL_MODE:
        raise BootstrapAuthorizationError("founder exception approval mode is invalid")
    if exception.get("exception_reason") != FOUNDER_EXCEPTION_REASON:
        raise BootstrapAuthorizationError("founder exception reason is invalid")
    if exception.get("independent_approval_present") is not False:
        raise BootstrapAuthorizationError("founder exception must explicitly record no independent approval")
    if exception.get("approver_id") is not None:
        raise BootstrapAuthorizationError("founder exception approver must be null")
    risk_acceptance_id = exception.get("risk_acceptance_id")
    if not isinstance(risk_acceptance_id, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{7,127}", risk_acceptance_id):
        raise BootstrapAuthorizationError("founder risk acceptance ID is invalid")
    if exception.get("risk_acceptance_digest") != canonical_digest({"risk_acceptance_id": risk_acceptance_id}):
        raise BootstrapAuthorizationError("founder risk acceptance digest is invalid")
    if exception.get("authority_account_id") != FOUNDER_AUTHORITY_ACCOUNT_ID:
        raise BootstrapAuthorizationError("founder exception authority account is invalid")
    if exception.get("region") != FOUNDER_REGION:
        raise BootstrapAuthorizationError("founder exception authority region is invalid")
    if exception.get("environment") != FOUNDER_ENVIRONMENT or exception.get("production") is not False:
        raise BootstrapAuthorizationError("founder exception must remain non-production")
    _require_operator_id(exception.get("operator_id"), "founder operator ID")
    _require_digest_format(exception.get("operator_subject_digest"), "founder operator subject digest")
    _require_digest_format(exception.get("founder_plan_principal_digest"), "founder Plan principal digest")
    _require_digest_format(exception.get("founder_apply_principal_digest"), "founder Apply principal digest")
    _require_digest_format(exception.get("plan_record_digest"), "founder source plan digest")
    _require_digest_format(exception.get("template_sha256"), "founder template digest")
    _change_set_parts(exception.get("change_set_id"), exception_id)
    _require_exact_resource_changes(exception.get("planned_resource_changes"))
    if exception.get("review_stack_status") != "REVIEW_IN_PROGRESS" or exception.get("review_stack_resource_count") != 0:
        raise BootstrapAuthorizationError("founder review stack is invalid")
    if exception.get("change_set_status") != "CREATE_COMPLETE" or exception.get("change_set_execution_status") != "AVAILABLE":
        raise BootstrapAuthorizationError("founder Change Set state is invalid")
    revoked = _parse_timestamp(exception.get("standard_plan_access_revoked_at"), "standard Plan revoked_at")
    quarantine = _parse_timestamp(
        exception.get("standard_plan_session_quarantine_until"), "standard Plan quarantine_until"
    )
    plan_not_before = _parse_timestamp(exception.get("founder_plan_not_before"), "founder Plan not_before")
    plan_expires = _parse_timestamp(exception.get("founder_plan_expires_at"), "founder Plan expires_at")
    apply_not_before = _parse_timestamp(exception.get("founder_apply_not_before"), "founder Apply not_before")
    apply_expires = _parse_timestamp(exception.get("founder_apply_expires_at"), "founder Apply expires_at")
    retention = _parse_timestamp(exception.get("automatic_deny_retain_until"), "founder deny retain_until")
    created = _parse_timestamp(exception.get("created_at"), "founder exception created_at")
    if quarantine < revoked + FOUNDER_QUARANTINE:
        raise BootstrapAuthorizationError("founder standard Plan quarantine is invalid")
    if plan_not_before < quarantine:
        raise BootstrapAuthorizationError("founder Plan begins before the required quarantine")
    if not MIN_PLAN_WINDOW <= plan_expires - plan_not_before <= MAX_PLAN_WINDOW:
        raise BootstrapAuthorizationError("founder Plan window is invalid")
    if not MIN_APPLY_WINDOW <= apply_expires - apply_not_before <= MAX_APPLY_WINDOW:
        raise BootstrapAuthorizationError("founder Apply window is invalid")
    if apply_not_before - plan_expires < MIN_PLAN_APPLY_GAP:
        raise BootstrapAuthorizationError("founder Plan and Apply windows are not safely non-overlapping")
    if retention != apply_expires + FOUNDER_DENY_RETENTION:
        raise BootstrapAuthorizationError("founder deny retention is invalid")
    if not plan_not_before <= created < plan_expires:
        raise BootstrapAuthorizationError("founder exception creation time is outside the Plan window")
    if exception.get("single_execution") is not True:
        raise BootstrapAuthorizationError("founder exception must be one-time")
    if exception.get("live_execution_status") != FOUNDER_LIVE_EXECUTION_STATUS:
        raise BootstrapAuthorizationError("founder live execution must remain blocked")


def build_founder_execution_ledger(
    *, exception: Mapping[str, Any], created_at: datetime
) -> dict[str, Any]:
    """Create an offline ledger model; it is not durable execution authority."""
    validate_founder_bootstrap_exception(exception)
    created = _parse_timestamp(_timestamp(created_at, "founder ledger created_at"), "founder ledger created_at")
    apply_not_before = _parse_timestamp(exception["founder_apply_not_before"], "founder Apply not_before")
    if created > apply_not_before:
        raise BootstrapAuthorizationError("founder execution ledger must be prepared before Apply opens")
    ledger: dict[str, Any] = {
        "schema_version": "1",
        "record_type": "platform_authority_founder_execution_ledger",
        "exception_id": exception["exception_id"],
        "exception_digest": exception["exception_digest"],
        "plan_record_digest": exception["plan_record_digest"],
        "authority_account_id": FOUNDER_AUTHORITY_ACCOUNT_ID,
        "region": FOUNDER_REGION,
        "change_set_id": exception["change_set_id"],
        "live_execution_status": FOUNDER_LIVE_EXECUTION_STATUS,
        "attempt_count": 0,
        "state": "PREPARED",
        "execution_started_at": None,
        "outcome": None,
        "created_at": _timestamp(created, "founder ledger created_at"),
        "updated_at": _timestamp(created, "founder ledger created_at"),
    }
    ledger["ledger_digest"] = canonical_digest(ledger)
    return ledger


def validate_founder_execution_ledger(ledger: Mapping[str, Any]) -> None:
    """Validate an offline ledger model; a live CAS adapter remains required."""
    _require_exact_keys(ledger, EXPECTED_LEDGER_KEYS, "founder execution ledger")
    _require_digest(ledger, "ledger_digest", "founder execution ledger")
    if ledger.get("schema_version") != "1" or ledger.get("record_type") != "platform_authority_founder_execution_ledger":
        raise BootstrapAuthorizationError("founder execution ledger type is invalid")
    _require_exception_id(ledger.get("exception_id"))
    for field in ("exception_digest", "plan_record_digest"):
        _require_digest_format(ledger.get(field), f"founder execution ledger {field}")
    if ledger.get("authority_account_id") != FOUNDER_AUTHORITY_ACCOUNT_ID or ledger.get("region") != FOUNDER_REGION:
        raise BootstrapAuthorizationError("founder execution ledger authority binding is invalid")
    _change_set_parts(ledger.get("change_set_id"), str(ledger.get("exception_id")))
    if ledger.get("live_execution_status") != FOUNDER_LIVE_EXECUTION_STATUS:
        raise BootstrapAuthorizationError("founder execution ledger must remain offline-only")
    attempt_count = ledger.get("attempt_count")
    state = ledger.get("state")
    started = ledger.get("execution_started_at")
    outcome = ledger.get("outcome")
    if state == "PREPARED":
        if attempt_count != 0 or started is not None or outcome is not None:
            raise BootstrapAuthorizationError("founder execution ledger prepared state is invalid")
    elif state == "EXECUTION_ATTEMPTED":
        if attempt_count != 1 or outcome is not None:
            raise BootstrapAuthorizationError("founder execution ledger attempted state is invalid")
        _parse_timestamp(started, "founder execution started_at")
    elif state in {"SUCCEEDED", "FAILED", "UNCERTAIN"}:
        if attempt_count != 1 or outcome != state:
            raise BootstrapAuthorizationError("founder execution ledger terminal state is invalid")
        _parse_timestamp(started, "founder execution started_at")
    else:
        raise BootstrapAuthorizationError("founder execution ledger state is invalid")
    created = _parse_timestamp(ledger.get("created_at"), "founder ledger created_at")
    updated = _parse_timestamp(ledger.get("updated_at"), "founder ledger updated_at")
    if updated < created:
        raise BootstrapAuthorizationError("founder execution ledger timestamps are invalid")


def model_founder_apply_transition(
    *,
    exception: Mapping[str, Any],
    plan: Mapping[str, Any],
    ledger: Mapping[str, Any],
    caller_identity_store_user_id: str,
    caller_arn: str,
    now: datetime,
) -> dict[str, Any]:
    """Model a would-be Apply transition; never authorize or execute AWS.

    A caller can copy an offline JSON record, so this pure function is solely a
    contract test for the future live PEP. A live PEP must replace this model
    with a durable compare-and-swap transition before `ExecuteChangeSet`.
    """
    validate_founder_bootstrap_exception(exception)
    validate_founder_execution_ledger(ledger)
    subject = _require_identity_store_user_id(caller_identity_store_user_id)
    current = _parse_timestamp(_timestamp(now, "founder model time"), "founder model time")
    _require_founder_arn(
        caller_arn,
        permission_set=FOUNDER_APPLY_PERMISSION_SET,
        label="founder apply caller",
    )
    _validate_founder_plan(
        plan,
        exception_id=str(exception["exception_id"]),
        operator_id=str(exception["operator_id"]),
        expected_plan_principal_digest=str(exception["founder_plan_principal_digest"]),
        minimum_not_before=_parse_timestamp(exception["founder_plan_not_before"], "founder Plan not_before"),
        maximum_apply_expires_at=_parse_timestamp(exception["founder_apply_expires_at"], "founder Apply expires_at"),
    )
    # _validate_founder_plan needs the original Plan ARN to prove the normal
    # plan digest.  Its public record retains only a digest, so compare that
    # digest explicitly rather than accepting a request-provided Plan ARN.
    if plan.get("record_digest") != exception.get("plan_record_digest"):
        raise BootstrapAuthorizationError("founder source plan digest does not match the exception")
    if plan.get("template_sha256") != exception.get("template_sha256"):
        raise BootstrapAuthorizationError("founder source template digest does not match the exception")
    if plan.get("change_set_id") != exception.get("change_set_id"):
        raise BootstrapAuthorizationError("founder source Change Set does not match the exception")
    if plan.get("caller_principal_digest") != exception.get("founder_plan_principal_digest"):
        raise BootstrapAuthorizationError("founder source Plan principal does not match the exception")
    if ledger.get("exception_id") != exception.get("exception_id") or ledger.get("exception_digest") != exception.get("exception_digest"):
        raise BootstrapAuthorizationError("founder execution ledger exception binding is invalid")
    for field in ("plan_record_digest", "authority_account_id", "region", "change_set_id"):
        if ledger.get(field) != exception.get(field):
            raise BootstrapAuthorizationError("founder execution ledger binding is invalid")
    if ledger.get("state") != "PREPARED" or ledger.get("attempt_count") != 0:
        raise BootstrapAuthorizationError("founder execution ledger is already consumed")
    if canonical_digest({"identity_store_user_id": subject}) != exception.get("operator_subject_digest"):
        raise BootstrapAuthorizationError("founder operator subject is not authorized")
    if canonical_digest({"caller_arn": caller_arn}) != exception.get("founder_apply_principal_digest"):
        raise BootstrapAuthorizationError("founder apply principal is not authorized")
    apply_not_before = _parse_timestamp(exception["founder_apply_not_before"], "founder Apply not_before")
    apply_expires = _parse_timestamp(exception["founder_apply_expires_at"], "founder Apply expires_at")
    if not apply_not_before <= current < apply_expires:
        raise BootstrapAuthorizationError("founder Apply window is not active")
    updated = dict(ledger)
    updated["attempt_count"] = 1
    updated["state"] = "EXECUTION_ATTEMPTED"
    updated["execution_started_at"] = _timestamp(current, "founder execution started_at")
    updated["updated_at"] = _timestamp(current, "founder model time")
    updated["ledger_digest"] = canonical_digest(
        {key: value for key, value in updated.items() if key != "ledger_digest"}
    )
    return updated


def build_founder_revocation(
    *,
    exception: Mapping[str, Any],
    checked_at: datetime,
    plan_assignment_absent: bool,
    plan_membership_absent: bool,
    apply_assignment_absent: bool,
    apply_membership_absent: bool,
    time_bound_deny_retained: bool,
) -> dict[str, Any]:
    """Record structural cleanup after AWS-side Apply expiry has elapsed."""
    validate_founder_bootstrap_exception(exception)
    checked = _parse_timestamp(_timestamp(checked_at, "founder revocation checked_at"), "founder revocation checked_at")
    apply_expires = _parse_timestamp(exception["founder_apply_expires_at"], "founder Apply expires_at")
    if checked < apply_expires:
        raise BootstrapAuthorizationError("founder revocation cannot be verified before Apply expiry")
    values = (
        plan_assignment_absent,
        plan_membership_absent,
        apply_assignment_absent,
        apply_membership_absent,
        time_bound_deny_retained,
    )
    if any(type(value) is not bool for value in values):
        raise BootstrapAuthorizationError("founder revocation evidence is malformed")
    status = "REVOKED" if all(values) else "REVOCATION_REQUIRED"
    record: dict[str, Any] = {
        "schema_version": "1",
        "record_type": "platform_authority_founder_bootstrap_revocation",
        "exception_id": exception["exception_id"],
        "exception_digest": exception["exception_digest"],
        "authority_account_id": FOUNDER_AUTHORITY_ACCOUNT_ID,
        "region": FOUNDER_REGION,
        "automatic_deny_retain_until": exception["automatic_deny_retain_until"],
        "checked_at": _timestamp(checked, "founder revocation checked_at"),
        "plan_assignment_absent": plan_assignment_absent,
        "plan_membership_absent": plan_membership_absent,
        "apply_assignment_absent": apply_assignment_absent,
        "apply_membership_absent": apply_membership_absent,
        "time_bound_deny_retained": time_bound_deny_retained,
        "status": status,
    }
    record["revocation_digest"] = canonical_digest(record)
    return record


def validate_founder_revocation(revocation: Mapping[str, Any]) -> None:
    """Validate a readback-based cleanup record without treating it as success."""
    _require_exact_keys(revocation, EXPECTED_REVOCATION_KEYS, "founder revocation")
    _require_digest(revocation, "revocation_digest", "founder revocation")
    if revocation.get("schema_version") != "1" or revocation.get("record_type") != "platform_authority_founder_bootstrap_revocation":
        raise BootstrapAuthorizationError("founder revocation type is invalid")
    _require_exception_id(revocation.get("exception_id"))
    _require_digest_format(revocation.get("exception_digest"), "founder revocation exception digest")
    if revocation.get("authority_account_id") != FOUNDER_AUTHORITY_ACCOUNT_ID or revocation.get("region") != FOUNDER_REGION:
        raise BootstrapAuthorizationError("founder revocation authority binding is invalid")
    _parse_timestamp(revocation.get("automatic_deny_retain_until"), "founder revocation retain_until")
    _parse_timestamp(revocation.get("checked_at"), "founder revocation checked_at")
    values = [
        revocation.get("plan_assignment_absent"),
        revocation.get("plan_membership_absent"),
        revocation.get("apply_assignment_absent"),
        revocation.get("apply_membership_absent"),
        revocation.get("time_bound_deny_retained"),
    ]
    if any(type(value) is not bool for value in values):
        raise BootstrapAuthorizationError("founder revocation evidence is malformed")
    expected = "REVOKED" if all(values) else "REVOCATION_REQUIRED"
    if revocation.get("status") != expected:
        raise BootstrapAuthorizationError("founder revocation status is invalid")


def model_founder_execution_outcome(
    *,
    ledger: Mapping[str, Any],
    outcome: str,
    completed_at: datetime,
    revocation: Mapping[str, Any],
) -> dict[str, Any]:
    """Model an outcome after cleanup; never attest that a live execution occurred."""
    validate_founder_execution_ledger(ledger)
    validate_founder_revocation(revocation)
    if ledger.get("state") != "EXECUTION_ATTEMPTED" or ledger.get("attempt_count") != 1:
        raise BootstrapAuthorizationError("founder execution ledger cannot be finalized")
    if outcome not in {"SUCCEEDED", "FAILED", "UNCERTAIN"}:
        raise BootstrapAuthorizationError("founder execution outcome is invalid")
    if (
        revocation.get("exception_id") != ledger.get("exception_id")
        or revocation.get("exception_digest") != ledger.get("exception_digest")
        or revocation.get("authority_account_id") != ledger.get("authority_account_id")
        or revocation.get("region") != ledger.get("region")
    ):
        raise BootstrapAuthorizationError("founder revocation does not match the execution ledger")
    if outcome == "SUCCEEDED" and revocation.get("status") != "REVOKED":
        raise BootstrapAuthorizationError("founder success requires verified revocation")
    completed = _parse_timestamp(_timestamp(completed_at, "founder execution completed_at"), "founder execution completed_at")
    started = _parse_timestamp(ledger.get("execution_started_at"), "founder execution started_at")
    if completed < started:
        raise BootstrapAuthorizationError("founder execution completion precedes the attempt")
    updated = dict(ledger)
    updated["state"] = outcome
    updated["outcome"] = outcome
    updated["updated_at"] = _timestamp(completed, "founder execution completed_at")
    updated["ledger_digest"] = canonical_digest(
        {key: value for key, value in updated.items() if key != "ledger_digest"}
    )
    return updated


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise BootstrapAuthorizationError("founder IAM policy template has duplicate keys")
        result[key] = value
    return result


def _render(value: Any, bindings: Mapping[str, str]) -> Any:
    if isinstance(value, str):
        rendered = value
        for name, replacement in bindings.items():
            rendered = rendered.replace(f"${{{name}}}", replacement)
        if UNBOUND_PLACEHOLDER.search(rendered):
            raise BootstrapAuthorizationError("founder IAM policy template has an unbound placeholder")
        return rendered
    if isinstance(value, list):
        return [_render(item, bindings) for item in value]
    if isinstance(value, dict):
        return {key: _render(item, bindings) for key, item in value.items()}
    return value


def _allow_actions(policy: Mapping[str, Any]) -> set[str]:
    actions: set[str] = set()
    for statement in policy.get("Statement", []):
        if not isinstance(statement, Mapping) or statement.get("Effect") != "Allow":
            continue
        raw_actions = statement.get("Action")
        items = raw_actions if isinstance(raw_actions, list) else [raw_actions]
        if not all(isinstance(item, str) for item in items):
            raise BootstrapAuthorizationError("founder IAM policy action is invalid")
        actions.update(items)
    return actions


def _statement_action_set(statement: Mapping[str, Any], label: str) -> set[str]:
    raw_actions = statement.get("Action")
    items = raw_actions if isinstance(raw_actions, list) else [raw_actions]
    if not items or not all(isinstance(item, str) for item in items):
        raise BootstrapAuthorizationError(f"{label} actions are invalid")
    return set(items)


def _validate_rendered_policy(
    *, mode: str, policy: Mapping[str, Any], exception: Mapping[str, Any], user_id: str
) -> None:
    if policy.get("Version") != "2012-10-17" or not isinstance(policy.get("Statement"), list):
        raise BootstrapAuthorizationError("rendered founder IAM policy is malformed")
    statements = policy["Statement"]
    if not statements or any(not isinstance(statement, Mapping) for statement in statements):
        raise BootstrapAuthorizationError("rendered founder IAM policy is malformed")
    sids = {statement.get("Sid") for statement in statements}
    prefix = "FounderPlan" if mode == "plan" else "FounderApply"
    required = {
        f"DenyBefore{prefix}Window",
        f"DenyAfter{prefix}Window",
        f"DenyNon{prefix}Subject",
        "DenyOutsideFounderAuthorityRegion",
        "DenyOfflineOnlyFounderPlanMutations"
        if mode == "plan"
        else "DenyOfflineOnlyFounderApplyMutations",
    }
    if not required <= sids:
        raise BootstrapAuthorizationError("rendered founder IAM policy lacks a required deny")
    before = exception["founder_plan_not_before"] if mode == "plan" else exception["founder_apply_not_before"]
    after = exception["founder_plan_expires_at"] if mode == "plan" else exception["founder_apply_expires_at"]
    by_sid = {statement.get("Sid"): statement for statement in statements}
    if by_sid[f"DenyBefore{prefix}Window"].get("Condition") != {"DateLessThan": {"aws:CurrentTime": before}}:
        raise BootstrapAuthorizationError("rendered founder IAM policy has an invalid start deny")
    if by_sid[f"DenyAfter{prefix}Window"].get("Condition") != {"DateGreaterThanEquals": {"aws:CurrentTime": after}}:
        raise BootstrapAuthorizationError("rendered founder IAM policy has an invalid expiry deny")
    if by_sid[f"DenyNon{prefix}Subject"].get("Condition") != {"StringNotEquals": {"identitystore:UserId": user_id}}:
        raise BootstrapAuthorizationError("rendered founder IAM policy has an invalid subject deny")
    actions = _allow_actions(policy)
    if "s3:PutAccountPublicAccessBlock" in actions:
        raise BootstrapAuthorizationError("founder IAM policy may not mutate account public access block")
    if mode == "plan" and "cloudformation:ExecuteChangeSet" in actions:
        raise BootstrapAuthorizationError("founder Plan policy may not execute a Change Set")
    if mode == "apply" and {"cloudformation:CreateChangeSet", "cloudformation:DeleteChangeSet"} & actions:
        raise BootstrapAuthorizationError("founder Apply policy may not manage Change Sets")
    if mode == "apply" and {"kms:DeleteAlias", "kms:UpdateAlias"} & actions:
        raise BootstrapAuthorizationError("founder Apply policy may not retarget or delete KMS aliases")
    parts = _change_set_parts(exception.get("change_set_id"), str(exception.get("exception_id")))
    stack_arn = (
        f"arn:aws:cloudformation:{FOUNDER_REGION}:{FOUNDER_AUTHORITY_ACCOUNT_ID}:"
        f"stack/{FOUNDER_STACK_NAME}/*"
    )
    change_set_condition = {"StringEquals": {"cloudformation:ChangeSetName": parts["name"]}}
    if mode == "plan":
        expected_tags = {
            "aws:RequestTag/managed_by": "cloudformation",
            "aws:RequestTag/service": "scanalyze-platform-authority",
            "aws:RequestTag/work_package": "GUG-206",
        }
        expected_tag_keys = {
            "ForAllValues:StringEquals": {
                "aws:TagKeys": ["managed_by", "service", "work_package"]
            }
        }
        create_statement = by_sid.get("CreateOnlyExactExceptionBoundChangeSet")
        delete_statement = by_sid.get("DeleteOnlyExactExceptionBoundChangeSet")
        tag_statement = by_sid.get("TagOnlyExactExceptionBoundChangeSetAtCreate")
        if not all(isinstance(statement, Mapping) for statement in (create_statement, delete_statement, tag_statement)):
            raise BootstrapAuthorizationError("rendered founder Plan policy lacks an exact Change Set statement")
        if create_statement.get("Resource") != stack_arn or create_statement.get("Action") != "cloudformation:CreateChangeSet":
            raise BootstrapAuthorizationError("rendered founder Plan policy has an invalid Change Set create resource")
        expected_create_condition = {
            "StringEquals": {"cloudformation:ChangeSetName": parts["name"], **expected_tags},
            **expected_tag_keys,
        }
        if create_statement.get("Condition") != expected_create_condition:
            raise BootstrapAuthorizationError("rendered founder Plan policy has an invalid Change Set create condition")
        if delete_statement.get("Resource") != stack_arn or delete_statement.get("Action") != "cloudformation:DeleteChangeSet":
            raise BootstrapAuthorizationError("rendered founder Plan policy has an invalid Change Set delete resource")
        if delete_statement.get("Condition") != change_set_condition:
            raise BootstrapAuthorizationError("rendered founder Plan policy has an invalid Change Set delete condition")
        expected_tag_resources = [
            stack_arn,
            f"arn:aws:cloudformation:{FOUNDER_REGION}:{FOUNDER_AUTHORITY_ACCOUNT_ID}:changeSet/{parts['name']}/*",
        ]
        expected_tag_condition = {
            "StringEquals": {
                "cloudformation:CreateAction": "CreateChangeSet",
                **expected_tags,
            },
            **expected_tag_keys,
        }
        if tag_statement.get("Action") != "cloudformation:TagResource" or tag_statement.get("Resource") != expected_tag_resources:
            raise BootstrapAuthorizationError("rendered founder Plan policy has an invalid Change Set tag resource")
        if tag_statement.get("Condition") != expected_tag_condition:
            raise BootstrapAuthorizationError("rendered founder Plan policy has an invalid Change Set tag condition")
        offline_deny = by_sid.get("DenyOfflineOnlyFounderPlanMutations")
        if (
            not isinstance(offline_deny, Mapping)
            or offline_deny.get("Effect") != "Deny"
            or offline_deny.get("Resource") != "*"
            or _statement_action_set(offline_deny, "founder Plan offline deny")
            != FOUNDER_PLAN_OFFLINE_DENY_ACTIONS
        ):
            raise BootstrapAuthorizationError("rendered founder Plan policy lacks the offline mutation deny")
    else:
        change_set_statement = by_sid.get("ExecuteOnlyExactFounderChangeSet")
        if not isinstance(change_set_statement, Mapping):
            raise BootstrapAuthorizationError("rendered founder Apply policy lacks the exact Change Set statement")
        if change_set_statement.get("Resource") != stack_arn:
            raise BootstrapAuthorizationError("rendered founder Apply policy has an invalid Change Set resource")
        if change_set_statement.get("Condition") != change_set_condition:
            raise BootstrapAuthorizationError("rendered founder Apply policy has an invalid Change Set condition")
        alias_statement = by_sid.get("CreateExactStateKeyAliasViaCloudFormation")
        key_statement = by_sid.get("BindCreateAliasOnlyToTaggedStateKeyViaCloudFormation")
        if not isinstance(alias_statement, Mapping) or alias_statement.get("Action") != "kms:CreateAlias":
            raise BootstrapAuthorizationError("rendered founder Apply policy has an invalid alias permission")
        if not isinstance(key_statement, Mapping) or key_statement.get("Action") != "kms:CreateAlias":
            raise BootstrapAuthorizationError("rendered founder Apply policy has an invalid alias key permission")
        key_condition = key_statement.get("Condition")
        if not isinstance(key_condition, Mapping):
            raise BootstrapAuthorizationError("rendered founder Apply policy lacks an alias key condition")
        key_called_via = key_condition.get("ForAnyValue:StringEquals")
        if key_called_via != {"aws:CalledVia": ["cloudformation.amazonaws.com"]}:
            raise BootstrapAuthorizationError("rendered founder Apply policy lacks CloudFormation-bound alias key permission")
        offline_deny = by_sid.get("DenyOfflineOnlyFounderApplyMutations")
        if (
            not isinstance(offline_deny, Mapping)
            or offline_deny.get("Effect") != "Deny"
            or offline_deny.get("Resource") != "*"
            or _statement_action_set(offline_deny, "founder Apply offline deny")
            != FOUNDER_APPLY_OFFLINE_DENY_ACTIONS
        ):
            raise BootstrapAuthorizationError("rendered founder Apply policy lacks the offline mutation deny")
    rendered = json.dumps(policy, sort_keys=True, separators=(",", ":"))
    if "${" in rendered:
        raise BootstrapAuthorizationError("rendered founder IAM policy still contains placeholders")


def render_founder_bootstrap_policy(
    *, mode: str, exception: Mapping[str, Any], operator_identity_store_user_id: str
) -> dict[str, Any]:
    """Render a temporary policy from a digest-validated exception only.

    The raw Identity Center subject is accepted only while rendering a private
    operational artifact.  It is never put into the exception, ledger, schema
    fixture, or public documentation.
    """
    if mode not in {"plan", "apply"}:
        raise BootstrapAuthorizationError("founder IAM policy mode is invalid")
    validate_founder_bootstrap_exception(exception)
    user_id = _require_identity_store_user_id(operator_identity_store_user_id)
    if canonical_digest({"identity_store_user_id": user_id}) != exception.get("operator_subject_digest"):
        raise BootstrapAuthorizationError("founder operator subject does not match the exception")
    parts = _change_set_parts(exception.get("change_set_id"), str(exception.get("exception_id")))
    path = REPO_ROOT / "policies" / "iam" / f"platform-authority-founder-bootstrap-{mode}-role.json"
    try:
        template = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_reject_duplicate_keys)
    except (OSError, json.JSONDecodeError) as exc:
        raise BootstrapAuthorizationError("founder IAM policy template is unavailable") from exc
    if not isinstance(template, dict):
        raise BootstrapAuthorizationError("founder IAM policy template is malformed")
    bindings = {
        "aws_partition": "aws",
        "authority_account_id": FOUNDER_AUTHORITY_ACCOUNT_ID,
        "region": FOUNDER_REGION,
        "state_bucket_name": _expected_bucket(),
        "change_set_name": parts["name"],
        "change_set_id": parts["id"],
        "exception_id": str(exception["exception_id"]),
        "founder_operator_user_id": user_id,
        "plan_not_before": str(exception["founder_plan_not_before"]),
        "plan_expires_at": str(exception["founder_plan_expires_at"]),
        "apply_not_before": str(exception["founder_apply_not_before"]),
        "apply_expires_at": str(exception["founder_apply_expires_at"]),
    }
    rendered = _render(template, bindings)
    if not isinstance(rendered, dict):
        raise BootstrapAuthorizationError("rendered founder IAM policy is malformed")
    _validate_rendered_policy(mode=mode, policy=rendered, exception=exception, user_id=user_id)
    return rendered
