"""Durable fail-closed PEP contracts for the one-shot founder bootstrap.

The management account may seed only the durable DynamoDB control plane and
the organization-level S3 public-access baseline.  Plan and Apply sessions run
inside the dedicated authority account and can consume exactly one conditional
ledger transition each.  This module never infers authority from profile
names, request data, local files, or a legacy/offline GUG-209 ledger.
"""
from __future__ import annotations

import json
import re
import subprocess
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Callable, Mapping, NoReturn, Sequence

from tooling.platform_authority_bootstrap import canonical_digest


REPO_ROOT = Path(__file__).resolve().parents[1]
MANAGEMENT_ACCOUNT_ID = "839393571433"
AUTHORITY_ACCOUNT_ID = "042360977644"
AUTHORITY_REGION = "us-east-1"
PEP_TABLE_NAME = "scanalyze-platform-authority-founder-executions"
PEP_STACK_SET_NAME = "scanalyze-platform-authority-founder-pep"
PEP_STACK_NAME = "StackSet-scanalyze-platform-authority-founder-pep"
FOUNDER_PLAN_PERMISSION_SET = "ScanalyzeFounderBootstrapPlan"
FOUNDER_APPLY_PERMISSION_SET = "ScanalyzeFounderBootstrapApply"
MANAGEMENT_SEED_PERMISSION_SET = "ScanalyzeFounderPepSeed"
MANAGEMENT_IDENTITY_ADMIN_PERMISSION_SET = "ScanalyzeFounderPepIdentityAdmin"
FOUNDER_APPROVAL_MODE = "SINGLE_OPERATOR_FOUNDER_EXCEPTION"
FOUNDER_EXCEPTION_REASON = "NO_SECOND_QUALIFIED_OPERATOR"
FOUNDER_ENVIRONMENT = "non-production"
FOUNDER_STACK_NAME = "scanalyze-platform-authority-state-backend"
FOUNDER_STATE_KEY = "platform-authority/terraform.tfstate"
PLAN_QUARANTINE = timedelta(hours=12)
MIN_PLAN_WINDOW = timedelta(minutes=5)
MAX_PLAN_WINDOW = timedelta(minutes=30)
MIN_APPLY_WINDOW = timedelta(minutes=5)
MAX_APPLY_WINDOW = timedelta(minutes=15)
MIN_PLAN_APPLY_GAP = timedelta(minutes=5)
DENY_RETENTION = timedelta(hours=12)

SHA256 = re.compile(r"^sha256:[a-f0-9]{64}$")
RAW_SHA256 = re.compile(r"^[a-f0-9]{64}$")
EXCEPTION_ID = re.compile(r"^[a-z][a-z0-9-]{7,63}$")
OPERATOR_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{2,127}$")
IDENTITY_STORE_USER_ID = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
)
CHANGE_SET_ARN = re.compile(
    r"^arn:aws:cloudformation:us-east-1:042360977644:"
    r"changeSet/(?P<name>[A-Za-z][-A-Za-z0-9]*)/(?P<id>[0-9a-f-]{36})$"
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

INTENT_KEYS = frozenset(
    {
        "schema_version",
        "record_type",
        "exception_id",
        "approval_mode",
        "exception_reason",
        "independent_approval_present",
        "approver_id",
        "environment",
        "production",
        "authority_account_id",
        "region",
        "operator_id",
        "operator_subject_digest",
        "plan_principal_digest",
        "apply_principal_digest",
        "risk_acceptance_id",
        "risk_acceptance_digest",
        "template_sha256",
        "change_set_name",
        "expected_resource_changes",
        "normal_plan_revoked_at",
        "plan_not_before",
        "plan_expires_at",
        "apply_not_before",
        "apply_expires_at",
        "deny_retain_until",
        "plan_attempt_limit",
        "apply_attempt_limit",
        "created_at",
        "intent_digest",
    }
)

LEDGER_KEYS = frozenset(
    {
        "schema_version",
        "record_type",
        "exception_id",
        "intent_digest",
        "authority_account_id",
        "region",
        "table_name",
        "version",
        "state",
        "plan_attempt_count",
        "apply_attempt_count",
        "change_set_id",
        "plan_record_digest",
        "exception_digest",
        "execution_started_at",
        "outcome",
        "revocation_digest",
        "created_at",
        "updated_at",
        "ledger_digest",
    }
)

REVOCATION_KEYS = frozenset(
    {
        "schema_version",
        "record_type",
        "exception_id",
        "intent_digest",
        "execution_ledger_digest",
        "authority_account_id",
        "region",
        "operator_subject_digest",
        "principal_type",
        "group_membership_used",
        "normal_plan_assignment_count",
        "founder_plan_assignment_count",
        "founder_apply_assignment_count",
        "founder_plan_permission_set",
        "founder_apply_permission_set",
        "founder_plan_policy_digest",
        "founder_apply_policy_digest",
        "founder_plan_deny_retained",
        "founder_apply_deny_retained",
        "deny_retain_until",
        "verified_at",
        "revocation_state",
        "revocation_digest",
    }
)


class FounderPepAuthorizationError(ValueError):
    """The live founder PEP could not prove the requested transition safe."""


def _timestamp(value: datetime, label: str) -> str:
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise FounderPepAuthorizationError(f"{label} must be timezone-aware")
    return value.astimezone(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _parse_timestamp(value: object, label: str) -> datetime:
    if not isinstance(value, str):
        raise FounderPepAuthorizationError(f"{label} is missing")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise FounderPepAuthorizationError(f"{label} is invalid") from exc
    if parsed.tzinfo is None:
        raise FounderPepAuthorizationError(f"{label} must be timezone-aware")
    return parsed.astimezone(UTC)


def _require_exact_keys(document: Mapping[str, Any], expected: frozenset[str], label: str) -> None:
    actual = set(document)
    if actual != set(expected):
        if actual - expected:
            raise FounderPepAuthorizationError(f"{label} has unexpected fields")
        raise FounderPepAuthorizationError(f"{label} is missing required fields")


def _require_digest(document: Mapping[str, Any], field: str, label: str) -> None:
    claimed = document.get(field)
    if not isinstance(claimed, str) or SHA256.fullmatch(claimed) is None:
        raise FounderPepAuthorizationError(f"{label} digest is malformed")
    expected = canonical_digest({key: value for key, value in document.items() if key != field})
    if claimed != expected:
        raise FounderPepAuthorizationError(f"{label} digest mismatch")


def _require_digest_value(value: object, label: str) -> str:
    if not isinstance(value, str) or SHA256.fullmatch(value) is None:
        raise FounderPepAuthorizationError(f"{label} must be a SHA-256 digest")
    return value


def _principal_arn(value: object, permission_set: str, label: str) -> str:
    if not isinstance(value, str):
        raise FounderPepAuthorizationError(f"{label} is missing")
    pattern = re.compile(
        rf"^arn:aws:sts::{AUTHORITY_ACCOUNT_ID}:assumed-role/"
        rf"AWSReservedSSO_{re.escape(permission_set)}_[0-9A-Fa-f]{{16}}/"
        rf"[A-Za-z0-9+=,.@_-]{{2,64}}$"
    )
    if pattern.fullmatch(value) is None:
        raise FounderPepAuthorizationError(f"{label} is not the exact founder SSO role")
    return value


def _change_set_id(value: object, exception_id: str) -> str:
    if not isinstance(value, str):
        raise FounderPepAuthorizationError("founder Change Set ID is missing")
    match = CHANGE_SET_ARN.fullmatch(value)
    if match is None or match.group("name") != f"scanalyze-founder-bootstrap-{exception_id}":
        raise FounderPepAuthorizationError("founder Change Set binding is invalid")
    return value


@dataclass(frozen=True, slots=True)
class FounderPepBinding:
    management_account_id: str = MANAGEMENT_ACCOUNT_ID
    authority_account_id: str = AUTHORITY_ACCOUNT_ID
    region: str = AUTHORITY_REGION
    table_name: str = PEP_TABLE_NAME

    def __post_init__(self) -> None:
        if self.management_account_id != MANAGEMENT_ACCOUNT_ID:
            raise FounderPepAuthorizationError("management account binding is invalid")
        if self.authority_account_id != AUTHORITY_ACCOUNT_ID:
            raise FounderPepAuthorizationError("authority account binding is invalid")
        if self.region != AUTHORITY_REGION:
            raise FounderPepAuthorizationError("authority region binding is invalid")
        if self.table_name != PEP_TABLE_NAME:
            raise FounderPepAuthorizationError("founder PEP table binding is invalid")

    @property
    def table_arn(self) -> str:
        return f"arn:aws:dynamodb:{self.region}:{self.authority_account_id}:table/{self.table_name}"


def build_founder_pep_intent(
    *,
    exception_id: str,
    operator_id: str,
    operator_identity_store_user_id: str,
    founder_plan_principal_arn: str,
    founder_apply_principal_arn: str,
    risk_acceptance_id: str,
    template_sha256: str,
    normal_plan_revoked_at: datetime,
    plan_not_before: datetime,
    plan_expires_at: datetime,
    apply_not_before: datetime,
    apply_expires_at: datetime,
    deny_retain_until: datetime,
    created_at: datetime,
) -> dict[str, Any]:
    if EXCEPTION_ID.fullmatch(exception_id) is None:
        raise FounderPepAuthorizationError("founder exception ID is invalid")
    if OPERATOR_ID.fullmatch(operator_id) is None:
        raise FounderPepAuthorizationError("founder operator ID is invalid")
    if IDENTITY_STORE_USER_ID.fullmatch(operator_identity_store_user_id) is None:
        raise FounderPepAuthorizationError("founder operator subject is invalid")
    plan_arn = _principal_arn(
        founder_plan_principal_arn, FOUNDER_PLAN_PERMISSION_SET, "founder Plan principal"
    )
    apply_arn = _principal_arn(
        founder_apply_principal_arn, FOUNDER_APPLY_PERMISSION_SET, "founder Apply principal"
    )
    if plan_arn == apply_arn:
        raise FounderPepAuthorizationError("founder Plan and Apply principals must differ")
    if not isinstance(risk_acceptance_id, str) or re.fullmatch(
        r"[A-Za-z0-9][A-Za-z0-9._:-]{7,127}", risk_acceptance_id
    ) is None:
        raise FounderPepAuthorizationError("founder risk acceptance ID is invalid")
    raw_template_digest = template_sha256.removeprefix("sha256:")
    if RAW_SHA256.fullmatch(raw_template_digest) is None:
        raise FounderPepAuthorizationError("founder template digest is invalid")

    revoked = _parse_timestamp(_timestamp(normal_plan_revoked_at, "normal Plan revoked_at"), "normal Plan revoked_at")
    plan_start = _parse_timestamp(_timestamp(plan_not_before, "Plan not_before"), "Plan not_before")
    plan_end = _parse_timestamp(_timestamp(plan_expires_at, "Plan expires_at"), "Plan expires_at")
    apply_start = _parse_timestamp(_timestamp(apply_not_before, "Apply not_before"), "Apply not_before")
    apply_end = _parse_timestamp(_timestamp(apply_expires_at, "Apply expires_at"), "Apply expires_at")
    retain_until = _parse_timestamp(_timestamp(deny_retain_until, "deny retain_until"), "deny retain_until")
    created = _parse_timestamp(_timestamp(created_at, "intent created_at"), "intent created_at")
    if plan_start < revoked + PLAN_QUARANTINE:
        raise FounderPepAuthorizationError("founder Plan begins before the twelve-hour quarantine")
    if not MIN_PLAN_WINDOW <= plan_end - plan_start <= MAX_PLAN_WINDOW:
        raise FounderPepAuthorizationError("founder Plan window is outside the allowed bounds")
    if apply_start - plan_end < MIN_PLAN_APPLY_GAP:
        raise FounderPepAuthorizationError("founder Plan/Apply gap is too short")
    if not MIN_APPLY_WINDOW <= apply_end - apply_start <= MAX_APPLY_WINDOW:
        raise FounderPepAuthorizationError("founder Apply window is outside the allowed bounds")
    if retain_until < apply_end + DENY_RETENTION:
        raise FounderPepAuthorizationError("founder deny retention is shorter than twelve hours")
    if created > plan_start:
        raise FounderPepAuthorizationError("founder intent must exist before the Plan window")

    document: dict[str, Any] = {
        "schema_version": "1",
        "record_type": "platform_authority_founder_pep_intent",
        "exception_id": exception_id,
        "approval_mode": FOUNDER_APPROVAL_MODE,
        "exception_reason": FOUNDER_EXCEPTION_REASON,
        "independent_approval_present": False,
        "approver_id": None,
        "environment": FOUNDER_ENVIRONMENT,
        "production": False,
        "authority_account_id": AUTHORITY_ACCOUNT_ID,
        "region": AUTHORITY_REGION,
        "operator_id": operator_id,
        "operator_subject_digest": canonical_digest(
            {"identity_store_user_id": operator_identity_store_user_id}
        ),
        "plan_principal_digest": canonical_digest({"caller_arn": plan_arn}),
        "apply_principal_digest": canonical_digest({"caller_arn": apply_arn}),
        "risk_acceptance_id": risk_acceptance_id,
        "risk_acceptance_digest": canonical_digest(
            {"risk_acceptance_id": risk_acceptance_id}
        ),
        "template_sha256": "sha256:" + raw_template_digest,
        "change_set_name": f"scanalyze-founder-bootstrap-{exception_id}",
        "expected_resource_changes": list(EXPECTED_RESOURCE_CHANGES),
        "normal_plan_revoked_at": _timestamp(revoked, "normal Plan revoked_at"),
        "plan_not_before": _timestamp(plan_start, "Plan not_before"),
        "plan_expires_at": _timestamp(plan_end, "Plan expires_at"),
        "apply_not_before": _timestamp(apply_start, "Apply not_before"),
        "apply_expires_at": _timestamp(apply_end, "Apply expires_at"),
        "deny_retain_until": _timestamp(retain_until, "deny retain_until"),
        "plan_attempt_limit": 1,
        "apply_attempt_limit": 1,
        "created_at": _timestamp(created, "intent created_at"),
    }
    document["intent_digest"] = canonical_digest(document)
    validate_founder_pep_intent(document)
    return document


def validate_founder_pep_intent(intent: Mapping[str, Any]) -> dict[str, Any]:
    _require_exact_keys(intent, INTENT_KEYS, "founder PEP intent")
    _require_digest(intent, "intent_digest", "founder PEP intent")
    if intent.get("schema_version") != "1" or intent.get("record_type") != "platform_authority_founder_pep_intent":
        raise FounderPepAuthorizationError("founder PEP intent type is invalid")
    if intent.get("authority_account_id") != AUTHORITY_ACCOUNT_ID or intent.get("region") != AUTHORITY_REGION:
        raise FounderPepAuthorizationError("founder PEP intent ownership is invalid")
    if (
        intent.get("approval_mode") != FOUNDER_APPROVAL_MODE
        or intent.get("exception_reason") != FOUNDER_EXCEPTION_REASON
        or intent.get("independent_approval_present") is not False
        or intent.get("approver_id") is not None
        or intent.get("environment") != FOUNDER_ENVIRONMENT
        or intent.get("production") is not False
    ):
        raise FounderPepAuthorizationError("founder PEP risk boundary is invalid")
    exception_id = intent.get("exception_id")
    if not isinstance(exception_id, str) or EXCEPTION_ID.fullmatch(exception_id) is None:
        raise FounderPepAuthorizationError("founder exception ID is invalid")
    if intent.get("change_set_name") != f"scanalyze-founder-bootstrap-{exception_id}":
        raise FounderPepAuthorizationError("founder Change Set name is invalid")
    if intent.get("expected_resource_changes") != list(EXPECTED_RESOURCE_CHANGES):
        raise FounderPepAuthorizationError("founder resource inventory is invalid")
    if intent.get("plan_attempt_limit") != 1 or intent.get("apply_attempt_limit") != 1:
        raise FounderPepAuthorizationError("founder attempt limits are invalid")
    for field in (
        "operator_subject_digest",
        "plan_principal_digest",
        "apply_principal_digest",
        "risk_acceptance_digest",
        "template_sha256",
    ):
        _require_digest_value(intent.get(field), field)
    if intent.get("plan_principal_digest") == intent.get("apply_principal_digest"):
        raise FounderPepAuthorizationError("founder principal digests must differ")
    revoked = _parse_timestamp(intent.get("normal_plan_revoked_at"), "normal Plan revoked_at")
    plan_start = _parse_timestamp(intent.get("plan_not_before"), "Plan not_before")
    plan_end = _parse_timestamp(intent.get("plan_expires_at"), "Plan expires_at")
    apply_start = _parse_timestamp(intent.get("apply_not_before"), "Apply not_before")
    apply_end = _parse_timestamp(intent.get("apply_expires_at"), "Apply expires_at")
    retain_until = _parse_timestamp(intent.get("deny_retain_until"), "deny retain_until")
    created = _parse_timestamp(intent.get("created_at"), "intent created_at")
    if plan_start < revoked + PLAN_QUARANTINE:
        raise FounderPepAuthorizationError("founder Plan begins before the twelve-hour quarantine")
    if not MIN_PLAN_WINDOW <= plan_end - plan_start <= MAX_PLAN_WINDOW:
        raise FounderPepAuthorizationError("founder Plan window is outside the allowed bounds")
    if apply_start - plan_end < MIN_PLAN_APPLY_GAP:
        raise FounderPepAuthorizationError("founder Plan/Apply gap is too short")
    if not MIN_APPLY_WINDOW <= apply_end - apply_start <= MAX_APPLY_WINDOW:
        raise FounderPepAuthorizationError("founder Apply window is outside the allowed bounds")
    if retain_until < apply_end + DENY_RETENTION:
        raise FounderPepAuthorizationError("founder deny retention is shorter than twelve hours")
    if created > plan_start:
        raise FounderPepAuthorizationError("founder intent was created after Plan start")
    return dict(intent)


def _with_ledger_digest(document: dict[str, Any]) -> dict[str, Any]:
    document["ledger_digest"] = canonical_digest(document)
    validate_founder_pep_ledger(document)
    return document


def build_founder_pep_ledger(*, intent: Mapping[str, Any], created_at: datetime) -> dict[str, Any]:
    source = validate_founder_pep_intent(intent)
    created = _timestamp(created_at, "ledger created_at")
    if _parse_timestamp(created, "ledger created_at") > _parse_timestamp(
        source["plan_not_before"], "Plan not_before"
    ):
        raise FounderPepAuthorizationError("founder ledger must exist before Plan start")
    document: dict[str, Any] = {
        "schema_version": "1",
        "record_type": "platform_authority_founder_pep_ledger",
        "exception_id": source["exception_id"],
        "intent_digest": source["intent_digest"],
        "authority_account_id": AUTHORITY_ACCOUNT_ID,
        "region": AUTHORITY_REGION,
        "table_name": PEP_TABLE_NAME,
        "version": 1,
        "state": "PREPARED",
        "plan_attempt_count": 0,
        "apply_attempt_count": 0,
        "change_set_id": None,
        "plan_record_digest": None,
        "exception_digest": None,
        "execution_started_at": None,
        "outcome": None,
        "revocation_digest": None,
        "created_at": created,
        "updated_at": created,
    }
    return _with_ledger_digest(document)


def validate_founder_pep_ledger(ledger: Mapping[str, Any]) -> dict[str, Any]:
    _require_exact_keys(ledger, LEDGER_KEYS, "founder PEP ledger")
    _require_digest(ledger, "ledger_digest", "founder PEP ledger")
    if ledger.get("schema_version") != "1" or ledger.get("record_type") != "platform_authority_founder_pep_ledger":
        raise FounderPepAuthorizationError("founder PEP ledger type is invalid")
    if (
        ledger.get("authority_account_id") != AUTHORITY_ACCOUNT_ID
        or ledger.get("region") != AUTHORITY_REGION
        or ledger.get("table_name") != PEP_TABLE_NAME
    ):
        raise FounderPepAuthorizationError("founder PEP ledger ownership is invalid")
    if not isinstance(ledger.get("version"), int) or ledger["version"] < 1:
        raise FounderPepAuthorizationError("founder PEP ledger version is invalid")
    plan_count = ledger.get("plan_attempt_count")
    apply_count = ledger.get("apply_attempt_count")
    if plan_count not in {0, 1} or apply_count not in {0, 1} or apply_count > plan_count:
        raise FounderPepAuthorizationError("founder PEP attempt counters are invalid")
    state = ledger.get("state")
    expected_counts = {
        "PREPARED": (0, 0),
        "PLAN_ATTEMPTED": (1, 0),
        "PLAN_REVIEWED": (1, 0),
        "APPLY_ATTEMPTED": (1, 1),
        "SUCCEEDED": (1, 1),
        "REVOKED": (1, 1),
        "FAILED": None,
        "UNCERTAIN": None,
    }
    if state not in expected_counts:
        raise FounderPepAuthorizationError("founder PEP ledger state is invalid")
    required_counts = expected_counts[state]
    if required_counts is not None and (plan_count, apply_count) != required_counts:
        raise FounderPepAuthorizationError("founder PEP state conflicts with attempt counters")
    expected_version = {
        "PREPARED": 1,
        "PLAN_ATTEMPTED": 2,
        "PLAN_REVIEWED": 3,
        "APPLY_ATTEMPTED": 4,
        "SUCCEEDED": 5,
        "REVOKED": 6,
    }.get(state)
    if state in {"FAILED", "UNCERTAIN"}:
        if (plan_count, apply_count) not in {(1, 0), (1, 1)}:
            raise FounderPepAuthorizationError("founder terminal state conflicts with attempt counters")
        expected_version = 3 if apply_count == 0 else 5
    if ledger["version"] != expected_version:
        raise FounderPepAuthorizationError("founder PEP state conflicts with ledger version")
    for field in ("intent_digest",):
        _require_digest_value(ledger.get(field), field)
    bound = state in {"PLAN_REVIEWED", "APPLY_ATTEMPTED", "SUCCEEDED", "REVOKED"} or (
        state in {"FAILED", "UNCERTAIN"} and apply_count == 1
    )
    if bound:
        _change_set_id(ledger.get("change_set_id"), str(ledger.get("exception_id")))
        _require_digest_value(ledger.get("plan_record_digest"), "plan record digest")
        _require_digest_value(ledger.get("exception_digest"), "exception digest")
    elif state in {"PREPARED", "PLAN_ATTEMPTED"}:
        if any(ledger.get(field) is not None for field in ("change_set_id", "plan_record_digest", "exception_digest")):
            raise FounderPepAuthorizationError("unreviewed founder ledger contains a Change Set binding")
    if apply_count == 1:
        _parse_timestamp(ledger.get("execution_started_at"), "Apply execution_started_at")
    elif ledger.get("execution_started_at") is not None:
        raise FounderPepAuthorizationError("founder ledger has an unexpected Apply start time")
    if state in {"SUCCEEDED", "FAILED", "UNCERTAIN"}:
        if ledger.get("outcome") != state:
            raise FounderPepAuthorizationError("founder terminal outcome is inconsistent")
    elif state == "REVOKED":
        if ledger.get("outcome") != "SUCCEEDED":
            raise FounderPepAuthorizationError("founder revocation requires successful execution")
        _require_digest_value(ledger.get("revocation_digest"), "revocation digest")
    elif ledger.get("outcome") is not None:
        raise FounderPepAuthorizationError("non-terminal founder ledger contains an outcome")
    if state != "REVOKED" and ledger.get("revocation_digest") is not None:
        raise FounderPepAuthorizationError("non-revoked founder ledger contains revocation evidence")
    created_at = _parse_timestamp(ledger.get("created_at"), "ledger created_at")
    updated_at = _parse_timestamp(ledger.get("updated_at"), "ledger updated_at")
    if updated_at < created_at:
        raise FounderPepAuthorizationError("founder ledger time moved before creation")
    return dict(ledger)


def build_founder_pep_revocation(
    *,
    intent: Mapping[str, Any],
    ledger: Mapping[str, Any],
    founder_plan_policy: Mapping[str, Any],
    founder_apply_policy: Mapping[str, Any],
    normal_plan_assignment_count: int,
    founder_plan_assignment_count: int,
    founder_apply_assignment_count: int,
    founder_plan_deny_retained: bool,
    founder_apply_deny_retained: bool,
    verified_at: datetime,
) -> dict[str, Any]:
    source, current = _authorize_intent_and_ledger(intent, ledger)
    if current["state"] != "SUCCEEDED" or current["outcome"] != "SUCCEEDED":
        raise FounderPepAuthorizationError("founder revocation requires successful execution")
    if any(
        value != 0
        for value in (
            normal_plan_assignment_count,
            founder_plan_assignment_count,
            founder_apply_assignment_count,
        )
    ):
        raise FounderPepAuthorizationError("founder assignment revocation is incomplete")
    if founder_plan_deny_retained is not True or founder_apply_deny_retained is not True:
        raise FounderPepAuthorizationError("founder AWS-side time denial is not retained")
    timestamp = _parse_timestamp(
        _timestamp(verified_at, "revocation verified_at"), "revocation verified_at"
    )
    started_at = _parse_timestamp(current["execution_started_at"], "Apply execution_started_at")
    apply_expires_at = _parse_timestamp(source["apply_expires_at"], "Apply expires_at")
    if not started_at <= timestamp < apply_expires_at:
        raise FounderPepAuthorizationError(
            "founder revocation must close after execution and before Apply session expiry"
        )
    for policy, mode in (
        (founder_plan_policy, "plan"),
        (founder_apply_policy, "apply"),
    ):
        serialized = json.dumps(policy, sort_keys=True)
        if (
            source[f"{mode}_expires_at"] not in serialized
            or source[f"{mode}_not_before"] not in serialized
            or "identitystore:UserId" not in serialized
        ):
            raise FounderPepAuthorizationError(
                f"founder {mode.title()} retained policy differs from the reviewed time denial"
            )
    receipt: dict[str, Any] = {
        "schema_version": "1",
        "record_type": "platform_authority_founder_pep_revocation",
        "exception_id": source["exception_id"],
        "intent_digest": source["intent_digest"],
        "execution_ledger_digest": current["ledger_digest"],
        "authority_account_id": AUTHORITY_ACCOUNT_ID,
        "region": AUTHORITY_REGION,
        "operator_subject_digest": source["operator_subject_digest"],
        "principal_type": "USER",
        "group_membership_used": False,
        "normal_plan_assignment_count": 0,
        "founder_plan_assignment_count": 0,
        "founder_apply_assignment_count": 0,
        "founder_plan_permission_set": FOUNDER_PLAN_PERMISSION_SET,
        "founder_apply_permission_set": FOUNDER_APPLY_PERMISSION_SET,
        "founder_plan_policy_digest": canonical_digest(dict(founder_plan_policy)),
        "founder_apply_policy_digest": canonical_digest(dict(founder_apply_policy)),
        "founder_plan_deny_retained": True,
        "founder_apply_deny_retained": True,
        "deny_retain_until": source["deny_retain_until"],
        "verified_at": _timestamp(timestamp, "revocation verified_at"),
        "revocation_state": "REVOKED_ASSIGNMENTS_DENY_RETAINED",
    }
    receipt["revocation_digest"] = canonical_digest(receipt)
    validate_founder_pep_revocation(receipt)
    return receipt


def validate_founder_pep_revocation(receipt: Mapping[str, Any]) -> dict[str, Any]:
    _require_exact_keys(receipt, REVOCATION_KEYS, "founder PEP revocation")
    _require_digest(receipt, "revocation_digest", "founder PEP revocation")
    if (
        receipt.get("schema_version") != "1"
        or receipt.get("record_type") != "platform_authority_founder_pep_revocation"
        or receipt.get("authority_account_id") != AUTHORITY_ACCOUNT_ID
        or receipt.get("region") != AUTHORITY_REGION
        or receipt.get("principal_type") != "USER"
        or receipt.get("group_membership_used") is not False
        or receipt.get("founder_plan_permission_set") != FOUNDER_PLAN_PERMISSION_SET
        or receipt.get("founder_apply_permission_set") != FOUNDER_APPLY_PERMISSION_SET
        or receipt.get("revocation_state") != "REVOKED_ASSIGNMENTS_DENY_RETAINED"
    ):
        raise FounderPepAuthorizationError("founder PEP revocation boundary is invalid")
    for field in (
        "intent_digest",
        "execution_ledger_digest",
        "operator_subject_digest",
        "founder_plan_policy_digest",
        "founder_apply_policy_digest",
    ):
        _require_digest_value(receipt.get(field), field)
    if any(
        receipt.get(field) != 0
        for field in (
            "normal_plan_assignment_count",
            "founder_plan_assignment_count",
            "founder_apply_assignment_count",
        )
    ):
        raise FounderPepAuthorizationError("founder PEP revocation assignment counts are invalid")
    if (
        receipt.get("founder_plan_deny_retained") is not True
        or receipt.get("founder_apply_deny_retained") is not True
    ):
        raise FounderPepAuthorizationError("founder PEP revocation deny retention is invalid")
    _parse_timestamp(receipt.get("deny_retain_until"), "deny retain_until")
    _parse_timestamp(receipt.get("verified_at"), "revocation verified_at")
    return dict(receipt)


def finalize_founder_revocation(
    *,
    intent: Mapping[str, Any],
    ledger: Mapping[str, Any],
    receipt: Mapping[str, Any],
    now: datetime,
) -> dict[str, Any]:
    source, current = _authorize_intent_and_ledger(intent, ledger)
    revocation = validate_founder_pep_revocation(receipt)
    if (
        current["state"] != "SUCCEEDED"
        or revocation["exception_id"] != source["exception_id"]
        or revocation["intent_digest"] != source["intent_digest"]
        or revocation["execution_ledger_digest"] != current["ledger_digest"]
    ):
        raise FounderPepAuthorizationError("founder revocation is not bound to execution")
    return _next_ledger(
        current,
        now=now,
        state="REVOKED",
        revocation_digest=revocation["revocation_digest"],
    )


def _authorize_intent_and_ledger(
    intent: Mapping[str, Any], ledger: Mapping[str, Any]
) -> tuple[dict[str, Any], dict[str, Any]]:
    source = validate_founder_pep_intent(intent)
    current = validate_founder_pep_ledger(ledger)
    if current["exception_id"] != source["exception_id"] or current["intent_digest"] != source["intent_digest"]:
        raise FounderPepAuthorizationError("founder PEP ledger is not bound to the intent")
    return source, current


def _next_ledger(current: Mapping[str, Any], *, now: datetime, **updates: Any) -> dict[str, Any]:
    timestamp = _parse_timestamp(_timestamp(now, "ledger updated_at"), "ledger updated_at")
    if timestamp < _parse_timestamp(current.get("updated_at"), "current ledger updated_at"):
        raise FounderPepAuthorizationError("founder ledger time must be monotonic")
    document = {key: value for key, value in current.items() if key != "ledger_digest"}
    document.update(updates)
    document["version"] = int(current["version"]) + 1
    document["updated_at"] = _timestamp(timestamp, "ledger updated_at")
    return _with_ledger_digest(document)


def _replace_ledger(
    store: "AwsCliFounderPepStore", *, before: Mapping[str, Any], after: Mapping[str, Any]
) -> None:
    store.replace_ledger(
        ledger=after,
        expected_version=before["version"],
        expected_digest=before["ledger_digest"],
        expected_state=before["state"],
        expected_plan_attempt_count=before["plan_attempt_count"],
        expected_apply_attempt_count=before["apply_attempt_count"],
    )


def _observed_digest(
    store: "AwsCliFounderPepStore", *, intent: Mapping[str, Any]
) -> str:
    observed = store.get_ledger(str(intent.get("exception_id", "")))
    _, validated = _authorize_intent_and_ledger(intent, observed)
    return str(validated["ledger_digest"])


def _persist_uncertain_after_effect(
    *,
    intent: Mapping[str, Any],
    store: "AwsCliFounderPepStore",
    claimed: Mapping[str, Any],
    now: datetime,
    phase: str,
    cause: Exception,
) -> NoReturn:
    uncertain = finalize_founder_outcome(
        intent=intent, ledger=claimed, outcome="UNCERTAIN", now=now
    )
    try:
        _replace_ledger(store, before=claimed, after=uncertain)
    except Exception as write_error:
        try:
            observed_digest = _observed_digest(store, intent=intent)
        except Exception as read_error:
            raise FounderPepAuthorizationError(
                f"founder {phase} terminal write is uncertain; retry is forbidden and reconciliation is required"
            ) from read_error
        if observed_digest == uncertain["ledger_digest"]:
            raise FounderPepAuthorizationError(
                f"founder {phase} effect is uncertain; retry is forbidden"
            ) from cause
        raise FounderPepAuthorizationError(
            f"founder {phase} terminal write is uncertain; retry is forbidden and reconciliation is required"
        ) from write_error
    raise FounderPepAuthorizationError(
        f"founder {phase} effect is uncertain; retry is forbidden"
    ) from cause


def _finalize_after_effect(
    *,
    intent: Mapping[str, Any],
    store: "AwsCliFounderPepStore",
    claimed: Mapping[str, Any],
    final: Mapping[str, Any],
    now: datetime,
    phase: str,
) -> dict[str, Any]:
    try:
        _replace_ledger(store, before=claimed, after=final)
        return dict(final)
    except Exception as write_error:
        try:
            observed_digest = _observed_digest(store, intent=intent)
        except Exception:
            raise FounderPepAuthorizationError(
                f"founder {phase} finalization is uncertain; retry is forbidden and reconciliation is required"
            ) from write_error
        if observed_digest == final["ledger_digest"]:
            return dict(final)
        if observed_digest == claimed["ledger_digest"]:
            _persist_uncertain_after_effect(
                intent=intent,
                store=store,
                claimed=claimed,
                now=now,
                phase=phase,
                cause=write_error,
            )
        raise FounderPepAuthorizationError(
            f"founder {phase} finalization conflicts with durable state; retry is forbidden and reconciliation is required"
        ) from write_error


def claim_founder_plan(
    *, intent: Mapping[str, Any], ledger: Mapping[str, Any], caller_arn: str, now: datetime
) -> dict[str, Any]:
    source, current = _authorize_intent_and_ledger(intent, ledger)
    expected = canonical_digest(
        {"caller_arn": _principal_arn(caller_arn, FOUNDER_PLAN_PERMISSION_SET, "founder Plan principal")}
    )
    if expected != source["plan_principal_digest"]:
        raise FounderPepAuthorizationError("founder Plan principal digest mismatch")
    timestamp = _parse_timestamp(_timestamp(now, "Plan attempt time"), "Plan attempt time")
    if not _parse_timestamp(source["plan_not_before"], "Plan not_before") <= timestamp < _parse_timestamp(
        source["plan_expires_at"], "Plan expires_at"
    ):
        raise FounderPepAuthorizationError("founder Plan attempt is outside its AWS window")
    if current["plan_attempt_count"] != 0:
        raise FounderPepAuthorizationError("founder Plan attempt was already consumed")
    if current["state"] != "PREPARED":
        raise FounderPepAuthorizationError("founder Plan transition is not allowed")
    return _next_ledger(
        current,
        now=timestamp,
        state="PLAN_ATTEMPTED",
        plan_attempt_count=1,
    )


def finalize_founder_plan(
    *,
    intent: Mapping[str, Any],
    ledger: Mapping[str, Any],
    change_set_id: str,
    plan_record_digest: str,
    exception_digest: str,
    now: datetime,
) -> dict[str, Any]:
    source, current = _authorize_intent_and_ledger(intent, ledger)
    if current["state"] != "PLAN_ATTEMPTED" or current["plan_attempt_count"] != 1:
        raise FounderPepAuthorizationError("founder Plan cannot be finalized")
    timestamp = _parse_timestamp(_timestamp(now, "Plan finalize time"), "Plan finalize time")
    if timestamp >= _parse_timestamp(source["plan_expires_at"], "Plan expires_at"):
        raise FounderPepAuthorizationError("founder Plan finalization is outside its AWS window")
    return _next_ledger(
        current,
        now=timestamp,
        state="PLAN_REVIEWED",
        change_set_id=_change_set_id(change_set_id, source["exception_id"]),
        plan_record_digest=_require_digest_value(plan_record_digest, "plan record digest"),
        exception_digest=_require_digest_value(exception_digest, "exception digest"),
    )


def claim_founder_apply(
    *,
    intent: Mapping[str, Any],
    ledger: Mapping[str, Any],
    caller_arn: str,
    change_set_id: str,
    now: datetime,
) -> dict[str, Any]:
    source, current = _authorize_intent_and_ledger(intent, ledger)
    expected = canonical_digest(
        {"caller_arn": _principal_arn(caller_arn, FOUNDER_APPLY_PERMISSION_SET, "founder Apply principal")}
    )
    if expected != source["apply_principal_digest"]:
        raise FounderPepAuthorizationError("founder Apply principal digest mismatch")
    timestamp = _parse_timestamp(_timestamp(now, "Apply attempt time"), "Apply attempt time")
    if not _parse_timestamp(source["apply_not_before"], "Apply not_before") <= timestamp < _parse_timestamp(
        source["apply_expires_at"], "Apply expires_at"
    ):
        raise FounderPepAuthorizationError("founder Apply attempt is outside its AWS window")
    if current["apply_attempt_count"] != 0:
        raise FounderPepAuthorizationError("founder Apply attempt was already consumed")
    if current["state"] != "PLAN_REVIEWED" or current["plan_attempt_count"] != 1:
        raise FounderPepAuthorizationError("founder Apply transition is not allowed")
    exact_id = _change_set_id(change_set_id, source["exception_id"])
    if exact_id != current["change_set_id"]:
        raise FounderPepAuthorizationError("founder Apply Change Set differs from reviewed Plan")
    return _next_ledger(
        current,
        now=timestamp,
        state="APPLY_ATTEMPTED",
        apply_attempt_count=1,
        execution_started_at=_timestamp(timestamp, "Apply execution_started_at"),
    )


def finalize_founder_outcome(
    *, intent: Mapping[str, Any], ledger: Mapping[str, Any], outcome: str, now: datetime
) -> dict[str, Any]:
    _, current = _authorize_intent_and_ledger(intent, ledger)
    if outcome not in {"SUCCEEDED", "FAILED", "UNCERTAIN"}:
        raise FounderPepAuthorizationError("founder execution outcome is invalid")
    if current["state"] not in {"PLAN_ATTEMPTED", "APPLY_ATTEMPTED"}:
        raise FounderPepAuthorizationError("founder execution outcome transition is not allowed")
    if outcome == "SUCCEEDED" and current["state"] != "APPLY_ATTEMPTED":
        raise FounderPepAuthorizationError("founder success requires an Apply attempt")
    return _next_ledger(current, now=now, state=outcome, outcome=outcome)


def run_founder_plan_once(
    *,
    intent: Mapping[str, Any],
    store: "AwsCliFounderPepStore",
    caller_arn: str,
    now: datetime,
    effect: Callable[[], Mapping[str, str]],
    clock: Callable[[], datetime] | None = None,
) -> dict[str, Any]:
    """Consume the durable Plan claim before the single external effect."""
    current = store.get_ledger(str(intent.get("exception_id", "")))
    claimed = claim_founder_plan(intent=intent, ledger=current, caller_arn=caller_arn, now=now)
    _replace_ledger(store, before=current, after=claimed)
    try:
        result = effect()
        completed_at = clock() if clock is not None else now
        reviewed = finalize_founder_plan(
            intent=intent,
            ledger=claimed,
            change_set_id=str(result.get("change_set_id", "")),
            plan_record_digest=str(result.get("plan_record_digest", "")),
            exception_digest=str(result.get("exception_digest", "")),
            now=completed_at,
        )
    except Exception as exc:
        completed_at = clock() if clock is not None else now
        _persist_uncertain_after_effect(
            intent=intent,
            store=store,
            claimed=claimed,
            now=completed_at,
            phase="Plan",
            cause=exc,
        )
    return _finalize_after_effect(
        intent=intent,
        store=store,
        claimed=claimed,
        final=reviewed,
        now=completed_at,
        phase="Plan",
    )


def run_founder_apply_once(
    *,
    intent: Mapping[str, Any],
    store: "AwsCliFounderPepStore",
    caller_arn: str,
    change_set_id: str,
    now: datetime,
    effect: Callable[[], None],
    clock: Callable[[], datetime] | None = None,
) -> dict[str, Any]:
    """Consume the durable Apply claim before the single external effect."""
    current = store.get_ledger(str(intent.get("exception_id", "")))
    claimed = claim_founder_apply(
        intent=intent,
        ledger=current,
        caller_arn=caller_arn,
        change_set_id=change_set_id,
        now=now,
    )
    _replace_ledger(store, before=current, after=claimed)
    try:
        effect()
        outcome = "SUCCEEDED"
    except Exception as exc:
        completed_at = clock() if clock is not None else now
        _persist_uncertain_after_effect(
            intent=intent,
            store=store,
            claimed=claimed,
            now=completed_at,
            phase="Apply",
            cause=exc,
        )
    completed_at = clock() if clock is not None else now
    terminal = finalize_founder_outcome(
        intent=intent, ledger=claimed, outcome=outcome, now=completed_at
    )
    return _finalize_after_effect(
        intent=intent,
        store=store,
        claimed=claimed,
        final=terminal,
        now=completed_at,
        phase="Apply",
    )


def _render(value: Any, bindings: Mapping[str, str]) -> Any:
    if isinstance(value, str):
        rendered = value
        for name, replacement in bindings.items():
            rendered = rendered.replace(f"${{{name}}}", replacement)
        if "${" in rendered:
            raise FounderPepAuthorizationError("live founder policy has an unbound placeholder")
        return rendered
    if isinstance(value, list):
        return [_render(item, bindings) for item in value]
    if isinstance(value, dict):
        return {key: _render(item, bindings) for key, item in value.items()}
    return value


def render_live_founder_policy(
    *, mode: str, intent: Mapping[str, Any], operator_identity_store_user_id: str
) -> dict[str, Any]:
    source = validate_founder_pep_intent(intent)
    if IDENTITY_STORE_USER_ID.fullmatch(operator_identity_store_user_id) is None:
        raise FounderPepAuthorizationError("founder operator subject is invalid")
    if canonical_digest({"identity_store_user_id": operator_identity_store_user_id}) != source["operator_subject_digest"]:
        raise FounderPepAuthorizationError("founder operator subject digest mismatch")
    if mode not in {"plan", "apply"}:
        raise FounderPepAuthorizationError("founder policy mode is invalid")
    template_name = f"platform-authority-founder-live-{mode}-role.json"
    try:
        template = json.loads((REPO_ROOT / "policies/iam" / template_name).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise FounderPepAuthorizationError("live founder policy template is invalid") from exc
    bindings = {
        "region": AUTHORITY_REGION,
        "authority_account_id": AUTHORITY_ACCOUNT_ID,
        "pep_table_name": PEP_TABLE_NAME,
        "exception_id": source["exception_id"],
        "change_set_name": source["change_set_name"],
        "state_bucket_name": f"scanalyze-platform-authority-{AUTHORITY_ACCOUNT_ID}-{AUTHORITY_REGION}-state",
        "founder_operator_user_id": operator_identity_store_user_id,
        "plan_not_before": source["plan_not_before"],
        "plan_expires_at": source["plan_expires_at"],
        "apply_not_before": source["apply_not_before"],
        "apply_expires_at": source["apply_expires_at"],
    }
    policy = _render(template, bindings)
    serialized = json.dumps(policy, sort_keys=True)
    if any(forbidden in serialized for forbidden in ("organizations:", "sso:", "sso-admin:", "iam:")):
        raise FounderPepAuthorizationError("live founder policy crosses its authority boundary")
    allowed_actions = {
        action
        for statement in policy.get("Statement", [])
        if isinstance(statement, Mapping) and statement.get("Effect") == "Allow"
        for action in (
            [statement.get("Action")]
            if isinstance(statement.get("Action"), str)
            else statement.get("Action", [])
        )
        if isinstance(action, str)
    }
    statements = policy.get("Statement")
    if not isinstance(statements, list):
        raise FounderPepAuthorizationError("live founder policy statements are invalid")

    def actions(statement: Mapping[str, Any]) -> set[str]:
        raw = statement.get("Action")
        if isinstance(raw, str):
            return {raw}
        if isinstance(raw, list) and all(isinstance(action, str) for action in raw):
            return set(raw)
        return set()

    metadata_actions = {
        "dynamodb:DescribeContinuousBackups",
        "dynamodb:DescribeTable",
    }
    metadata_statements = [
        statement
        for statement in statements
        if isinstance(statement, Mapping)
        and statement.get("Effect") == "Allow"
        and actions(statement).intersection(metadata_actions)
    ]
    exact_table_arn = (
        f"arn:aws:dynamodb:{AUTHORITY_REGION}:{AUTHORITY_ACCOUNT_ID}:"
        f"table/{PEP_TABLE_NAME}"
    )
    if (
        len(metadata_statements) != 1
        or actions(metadata_statements[0]) != metadata_actions
        or metadata_statements[0].get("Resource") != exact_table_arn
        or "Condition" in metadata_statements[0]
    ):
        raise FounderPepAuthorizationError(
            "live founder policy does not preserve exact table metadata readback"
        )

    list_change_sets = [
        statement
        for statement in statements
        if isinstance(statement, Mapping)
        and statement.get("Effect") == "Allow"
        and "cloudformation:ListChangeSets" in actions(statement)
    ]
    exact_stack_arn = (
        f"arn:aws:cloudformation:{AUTHORITY_REGION}:{AUTHORITY_ACCOUNT_ID}:"
        "stack/scanalyze-platform-authority-state-backend/*"
    )
    if mode == "plan":
        if (
            len(list_change_sets) != 1
            or actions(list_change_sets[0]) != {"cloudformation:ListChangeSets"}
            or list_change_sets[0].get("Resource") != exact_stack_arn
            or "Condition" in list_change_sets[0]
        ):
            raise FounderPepAuthorizationError(
                "founder Plan Change Set inventory is not stack-bound"
            )
    elif list_change_sets:
        raise FounderPepAuthorizationError(
            "founder Apply must not add Change Set inventory scope"
        )
    if "DenyOfflineOnly" in serialized or "s3:PutAccountPublicAccessBlock" in allowed_actions:
        raise FounderPepAuthorizationError("live founder policy contains a forbidden bypass")
    return policy


CommandRunner = Callable[[Sequence[str]], str]


def _default_runner(command: Sequence[str]) -> str:
    try:
        result = subprocess.run(list(command), check=True, capture_output=True, text=True)
    except (OSError, subprocess.CalledProcessError) as exc:
        raise FounderPepAuthorizationError("founder PEP durable-store operation failed") from exc
    return result.stdout


def _ddb_item(ledger: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "exception_id": {"S": str(ledger["exception_id"])},
        "version": {"N": str(ledger["version"])},
        "ledger_digest": {"S": str(ledger["ledger_digest"])},
        "state": {"S": str(ledger["state"])},
        "plan_attempt_count": {"N": str(ledger["plan_attempt_count"])},
        "apply_attempt_count": {"N": str(ledger["apply_attempt_count"])},
        "document": {"S": json.dumps(dict(ledger), sort_keys=True, separators=(",", ":"))},
    }


class AwsCliFounderPepStore:
    """Exact-table DynamoDB adapter with create-only and CAS writes."""

    def __init__(
        self,
        *,
        region: str,
        authority_account_id: str,
        table_name: str,
        runner: CommandRunner = _default_runner,
    ) -> None:
        FounderPepBinding(
            authority_account_id=authority_account_id,
            region=region,
            table_name=table_name,
        )
        self.region = region
        self.authority_account_id = authority_account_id
        self.table_name = table_name
        self._run = runner

    @staticmethod
    def _json(raw: str, label: str) -> dict[str, Any]:
        try:
            value = json.loads(raw or "{}")
        except json.JSONDecodeError as exc:
            raise FounderPepAuthorizationError(f"{label} returned malformed JSON") from exc
        if not isinstance(value, dict):
            raise FounderPepAuthorizationError(f"{label} returned an invalid response")
        return value

    def verify_table_controls(self) -> dict[str, bool]:
        response = self._json(
            self._run(
                (
                    "aws", "dynamodb", "describe-table", "--region", self.region,
                    "--table-name", self.table_name, "--output", "json",
                )
            ),
            "founder PEP table",
        )
        table = response.get("Table")
        if not isinstance(table, Mapping):
            raise FounderPepAuthorizationError("founder PEP table response is incomplete")
        table_arn = f"arn:aws:dynamodb:{self.region}:{self.authority_account_id}:table/{self.table_name}"
        key_schema = table.get("KeySchema")
        controls = {
            "active": table.get("TableStatus") == "ACTIVE",
            "exact_arn": table.get("TableArn") == table_arn,
            "exact_key": key_schema == [{"AttributeName": "exception_id", "KeyType": "HASH"}],
            "deletion_protected": table.get("DeletionProtectionEnabled") is True,
            "sse_enabled": (
                isinstance(table.get("SSEDescription"), Mapping)
                and table["SSEDescription"].get("Status") == "ENABLED"
            ),
        }
        backups = self._json(
            self._run(
                (
                    "aws", "dynamodb", "describe-continuous-backups", "--region", self.region,
                    "--table-name", self.table_name, "--output", "json",
                )
            ),
            "founder PEP backups",
        )
        pitr = backups.get("ContinuousBackupsDescription", {})
        pitr_detail = pitr.get("PointInTimeRecoveryDescription", {}) if isinstance(pitr, Mapping) else {}
        controls["pitr_enabled"] = (
            isinstance(pitr_detail, Mapping)
            and pitr_detail.get("PointInTimeRecoveryStatus") == "ENABLED"
        )
        if not all(controls.values()):
            raise FounderPepAuthorizationError("founder PEP table controls are incomplete")
        return controls

    def get_ledger(self, exception_id: str) -> dict[str, Any]:
        if EXCEPTION_ID.fullmatch(exception_id) is None:
            raise FounderPepAuthorizationError("founder exception ID is invalid")
        response = self._json(
            self._run(
                (
                    "aws", "dynamodb", "get-item", "--region", self.region,
                    "--table-name", self.table_name,
                    "--key", json.dumps({"exception_id": {"S": exception_id}}, sort_keys=True),
                    "--consistent-read", "--projection-expression", "document",
                    "--output", "json",
                )
            ),
            "founder PEP ledger read",
        )
        item = response.get("Item")
        document_value = item.get("document") if isinstance(item, Mapping) else None
        raw = document_value.get("S") if isinstance(document_value, Mapping) else None
        if not isinstance(raw, str):
            raise FounderPepAuthorizationError("founder PEP ledger is missing")
        try:
            document = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise FounderPepAuthorizationError("founder PEP ledger is malformed") from exc
        if not isinstance(document, dict):
            raise FounderPepAuthorizationError("founder PEP ledger is malformed")
        return validate_founder_pep_ledger(document)

    def create_ledger(self, ledger: Mapping[str, Any]) -> None:
        document = validate_founder_pep_ledger(ledger)
        if document["state"] != "PREPARED" or document["version"] != 1:
            raise FounderPepAuthorizationError("only a new PREPARED founder ledger may be created")
        self._run(
            (
                "aws",
                "dynamodb",
                "put-item",
                "--region",
                self.region,
                "--table-name",
                self.table_name,
                "--item",
                json.dumps(_ddb_item(document), sort_keys=True),
                "--condition-expression",
                "attribute_not_exists(exception_id)",
                "--return-consumed-capacity",
                "NONE",
                "--output",
                "json",
            )
        )

    def replace_ledger(
        self,
        *,
        ledger: Mapping[str, Any],
        expected_version: int,
        expected_digest: str,
        expected_state: str,
        expected_plan_attempt_count: int,
        expected_apply_attempt_count: int,
    ) -> None:
        document = validate_founder_pep_ledger(ledger)
        values = {
            ":expected_version": {"N": str(expected_version)},
            ":expected_digest": {"S": _require_digest_value(expected_digest, "expected ledger digest")},
            ":expected_state": {"S": expected_state},
            ":expected_plan": {"N": str(expected_plan_attempt_count)},
            ":expected_apply": {"N": str(expected_apply_attempt_count)},
        }
        names = {
            "#version": "version",
            "#digest": "ledger_digest",
            "#state": "state",
            "#plan": "plan_attempt_count",
            "#apply": "apply_attempt_count",
        }
        condition = (
            "#version = :expected_version AND #digest = :expected_digest AND "
            "#state = :expected_state AND #plan = :expected_plan AND #apply = :expected_apply"
        )
        self._run(
            (
                "aws",
                "dynamodb",
                "put-item",
                "--region",
                self.region,
                "--table-name",
                self.table_name,
                "--item",
                json.dumps(_ddb_item(document), sort_keys=True),
                "--condition-expression",
                condition,
                "--expression-attribute-names",
                json.dumps(names, sort_keys=True),
                "--expression-attribute-values",
                json.dumps(values, sort_keys=True),
                "--return-consumed-capacity",
                "NONE",
                "--output",
                "json",
            )
        )
