"""Bounded GUG-215 single-operator non-production authorization contract.

This module is deliberately offline and has no AWS client.  It turns an exact
owner authorization into a digest-only document that can later be pinned in a
versioned broker deployment.  The document never claims independent approval,
never authorizes deployment, and cannot select a target at request time.
"""
from __future__ import annotations

import hashlib
import json
import re
from datetime import UTC, datetime, timedelta
from typing import Any, Mapping


EXCEPTION_MODE = "SINGLE_OPERATOR_NONPROD_EXCEPTION"
NORMAL_MODE = "TWO_HUMAN"
CANONICAL_STACK_NAME = "scanalyze-platform-authority-state-backend"
ALLOWED_ACTION = "cloudformation:DeleteChangeSet"
LEDGER_ACTIONS = ("dynamodb:PutItem", "dynamodb:UpdateItem")
FORBIDDEN_ACTIONS = (
    "cloudformation:CreateChangeSet",
    "cloudformation:DeleteStack",
    "cloudformation:ExecuteChangeSet",
    "cloudformation:UpdateStack",
)
MAX_ACTIVATION_DELAY = timedelta(hours=1)
MAX_EFFECT_WINDOW = timedelta(minutes=15)

ACCOUNT_ID = re.compile(r"^(?!000000000000$)[0-9]{12}$")
REGION = re.compile(r"^[a-z]{2}(?:-[a-z]+)+-[0-9]+$")
RUNTIME_VERSION_ARN = re.compile(
    r"^arn:(?P<partition>aws(?:-[a-z]+)*):lambda:"
    r"(?P<region>[a-z]{2}(?:-[a-z]+)+-[0-9]+)::runtime:"
    r"[a-f0-9]{64}$"
)
DIGEST = re.compile(r"^sha256:[a-f0-9]{64}$")
RETIREMENT_ID = re.compile(r"^gug215#sha256:[a-f0-9]{64}$")
IDENTITY_STORE_USER_ID = re.compile(
    r"^(?:[0-9a-f]{10}-)?[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$",
    re.IGNORECASE,
)

EXCEPTION_KEYS = frozenset(
    {
        "schema_version",
        "record_type",
        "issue_id",
        "environment",
        "production",
        "authorization_mode",
        "two_human_status",
        "independent_approval_present",
        "single_execution",
        "deployment_authorized",
        "request_selectable",
        "allowed_action",
        "broker_ledger_actions",
        "forbidden_actions",
        "aws_effect_principal",
        "max_attempts",
        "authority_account_id_digest",
        "region",
        "stack_name",
        "retirement_id",
        "change_set_name_digest",
        "template_sha256",
        "resource_inventory_sha256",
        "identity_binding_digest",
        "broker_runtime_version_arn_digest",
        "broker_version_binding_sha256",
        "operator_identity_store_user_id_digest",
        "owner_authorization_sha256",
        "created_at",
        "not_before",
        "expires_at",
        "reconciliation_after_expiry",
        "revocation_required",
        "authorization_digest",
    }
)


class SingleOperatorExceptionError(ValueError):
    """A sanitized fail-closed exception-contract result."""

    def __init__(self, code: str) -> None:
        if re.fullmatch(r"[A-Z][A-Z0-9_]{2,79}", code) is None:
            code = "SINGLE_OPERATOR_EXCEPTION_INVALID"
        self.code = code
        super().__init__(code)


def canonical_digest(value: Mapping[str, Any]) -> str:
    payload = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def _timestamp(value: datetime) -> str:
    if value.tzinfo is None:
        raise SingleOperatorExceptionError("EXCEPTION_TIME_INVALID")
    return value.astimezone(UTC).replace(microsecond=0).isoformat().replace(
        "+00:00", "Z"
    )


def _parse_timestamp(value: object) -> datetime:
    if not isinstance(value, str):
        raise SingleOperatorExceptionError("EXCEPTION_TIME_INVALID")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise SingleOperatorExceptionError("EXCEPTION_TIME_INVALID") from None
    if parsed.tzinfo is None or parsed.microsecond != 0:
        raise SingleOperatorExceptionError("EXCEPTION_TIME_INVALID")
    return parsed.astimezone(UTC)


def _require_digest(value: object, code: str) -> str:
    if not isinstance(value, str) or DIGEST.fullmatch(value) is None:
        raise SingleOperatorExceptionError(code)
    return value


def build_single_operator_retirement_exception(
    *,
    authority_account_id: str,
    region: str,
    retirement_id: str,
    change_set_name_digest: str,
    template_sha256: str,
    resource_inventory_sha256: str,
    identity_binding_digest: str,
    broker_runtime_version_arn: str,
    broker_version_binding_sha256: str,
    operator_identity_store_user_id: str,
    owner_authorization_sha256: str,
    created_at: datetime,
    not_before: datetime,
    expires_at: datetime,
) -> dict[str, object]:
    """Build the public digest-only exception; raw identity stays process-local."""

    if ACCOUNT_ID.fullmatch(authority_account_id) is None:
        raise SingleOperatorExceptionError("ACCOUNT_BINDING_INVALID")
    if REGION.fullmatch(region) is None:
        raise SingleOperatorExceptionError("REGION_BINDING_INVALID")
    runtime_match = RUNTIME_VERSION_ARN.fullmatch(broker_runtime_version_arn)
    if runtime_match is None or runtime_match.group("region") != region:
        raise SingleOperatorExceptionError("RUNTIME_VERSION_BINDING_INVALID")
    if RETIREMENT_ID.fullmatch(retirement_id) is None:
        raise SingleOperatorExceptionError("RETIREMENT_ID_INVALID")
    if IDENTITY_STORE_USER_ID.fullmatch(operator_identity_store_user_id) is None:
        raise SingleOperatorExceptionError("IDENTITY_STORE_USER_INVALID")
    for value, code in (
        (change_set_name_digest, "CHANGE_SET_NAME_DIGEST_INVALID"),
        (template_sha256, "TEMPLATE_DIGEST_INVALID"),
        (resource_inventory_sha256, "RESOURCE_INVENTORY_DIGEST_INVALID"),
        (identity_binding_digest, "IDENTITY_BINDING_DIGEST_INVALID"),
        (broker_version_binding_sha256, "BROKER_VERSION_BINDING_DIGEST_INVALID"),
        (owner_authorization_sha256, "OWNER_AUTHORIZATION_DIGEST_INVALID"),
    ):
        _require_digest(value, code)

    record: dict[str, object] = {
        "schema_version": "1",
        "record_type": (
            "platform_authority_change_set_retirement_single_operator_exception"
        ),
        "issue_id": "GUG-215",
        "environment": "non-production",
        "production": False,
        "authorization_mode": EXCEPTION_MODE,
        "two_human_status": "NOT_PROVEN",
        "independent_approval_present": False,
        "single_execution": True,
        "deployment_authorized": False,
        "request_selectable": False,
        "allowed_action": ALLOWED_ACTION,
        "broker_ledger_actions": list(LEDGER_ACTIONS),
        "forbidden_actions": list(FORBIDDEN_ACTIONS),
        "aws_effect_principal": "BROKER_EXECUTION_ROLE",
        "max_attempts": 1,
        "authority_account_id_digest": canonical_digest(
            {"authority_account_id": authority_account_id}
        ),
        "region": region,
        "stack_name": CANONICAL_STACK_NAME,
        "retirement_id": retirement_id,
        "change_set_name_digest": change_set_name_digest,
        "template_sha256": template_sha256,
        "resource_inventory_sha256": resource_inventory_sha256,
        "identity_binding_digest": identity_binding_digest,
        "broker_runtime_version_arn_digest": canonical_digest(
            {"broker_runtime_version_arn": broker_runtime_version_arn}
        ),
        "broker_version_binding_sha256": broker_version_binding_sha256,
        "operator_identity_store_user_id_digest": canonical_digest(
            {"identity_store_user_id": operator_identity_store_user_id.lower()}
        ),
        "owner_authorization_sha256": owner_authorization_sha256,
        "created_at": _timestamp(created_at),
        "not_before": _timestamp(not_before),
        "expires_at": _timestamp(expires_at),
        "reconciliation_after_expiry": True,
        "revocation_required": True,
    }
    record["authorization_digest"] = canonical_digest(record)
    validate_single_operator_retirement_exception(record)
    return record


def validate_single_operator_retirement_exception(
    value: Mapping[str, object],
) -> None:
    """Validate exact scope and digest before the artifact can be pinned."""

    if set(value) != set(EXCEPTION_KEYS):
        raise SingleOperatorExceptionError("EXCEPTION_FIELDS_INVALID")
    authorization_digest = _require_digest(
        value.get("authorization_digest"), "AUTHORIZATION_DIGEST_INVALID"
    )
    expected_digest = canonical_digest(
        {key: item for key, item in value.items() if key != "authorization_digest"}
    )
    if authorization_digest != expected_digest:
        raise SingleOperatorExceptionError("AUTHORIZATION_DIGEST_MISMATCH")

    constants = {
        "schema_version": "1",
        "record_type": (
            "platform_authority_change_set_retirement_single_operator_exception"
        ),
        "issue_id": "GUG-215",
        "environment": "non-production",
        "request_selectable": False,
        "aws_effect_principal": "BROKER_EXECUTION_ROLE",
        "max_attempts": 1,
        "stack_name": CANONICAL_STACK_NAME,
        "reconciliation_after_expiry": True,
        "revocation_required": True,
    }
    if any(value.get(field) != expected for field, expected in constants.items()):
        raise SingleOperatorExceptionError("EXCEPTION_SCOPE_INVALID")
    if value.get("authorization_mode") != EXCEPTION_MODE:
        raise SingleOperatorExceptionError("EXCEPTION_MODE_INVALID")
    if value.get("two_human_status") != "NOT_PROVEN":
        raise SingleOperatorExceptionError("TWO_HUMAN_OVERCLAIM")
    if value.get("independent_approval_present") is not False:
        raise SingleOperatorExceptionError("INDEPENDENCE_OVERCLAIM")
    if value.get("production") is not False:
        raise SingleOperatorExceptionError("PRODUCTION_FORBIDDEN")
    if value.get("single_execution") is not True:
        raise SingleOperatorExceptionError("SINGLE_EXECUTION_REQUIRED")
    if value.get("deployment_authorized") is not False:
        raise SingleOperatorExceptionError("DEPLOYMENT_AUTHORITY_OVERCLAIM")
    if (
        value.get("allowed_action") != ALLOWED_ACTION
        or value.get("broker_ledger_actions") != list(LEDGER_ACTIONS)
        or value.get("forbidden_actions") != list(FORBIDDEN_ACTIONS)
    ):
        raise SingleOperatorExceptionError("ACTION_SCOPE_INVALID")

    region = value.get("region")
    retirement_id = value.get("retirement_id")
    if not isinstance(region, str) or REGION.fullmatch(region) is None:
        raise SingleOperatorExceptionError("REGION_BINDING_INVALID")
    if not isinstance(retirement_id, str) or RETIREMENT_ID.fullmatch(retirement_id) is None:
        raise SingleOperatorExceptionError("RETIREMENT_ID_INVALID")
    for field in (
        "authority_account_id_digest",
        "change_set_name_digest",
        "template_sha256",
        "resource_inventory_sha256",
        "identity_binding_digest",
        "broker_runtime_version_arn_digest",
        "broker_version_binding_sha256",
        "operator_identity_store_user_id_digest",
        "owner_authorization_sha256",
    ):
        _require_digest(value.get(field), f"{field.upper()}_INVALID")

    created = _parse_timestamp(value.get("created_at"))
    not_before = _parse_timestamp(value.get("not_before"))
    expires = _parse_timestamp(value.get("expires_at"))
    if (
        not_before < created
        or not_before - created > MAX_ACTIVATION_DELAY
        or expires <= not_before
        or expires - not_before > MAX_EFFECT_WINDOW
    ):
        raise SingleOperatorExceptionError("EXCEPTION_WINDOW_INVALID")


def require_exception_effect_window(
    value: Mapping[str, object],
    *,
    now: datetime,
) -> None:
    """Fail closed outside ``not_before <= now < expires_at``."""

    validate_single_operator_retirement_exception(value)
    if now.tzinfo is None:
        raise SingleOperatorExceptionError("CLOCK_INVALID")
    observed = now.astimezone(UTC)
    if not (
        _parse_timestamp(value.get("not_before"))
        <= observed
        < _parse_timestamp(value.get("expires_at"))
    ):
        raise SingleOperatorExceptionError("EXCEPTION_NOT_ACTIVE")
