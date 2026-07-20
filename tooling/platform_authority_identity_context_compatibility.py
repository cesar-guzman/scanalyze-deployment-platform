"""Fail-closed compatibility guard for Identity Center ProvidedContexts.

AWS STS automatically attaches ``AWSIAMIdentityCenterAllowListForIdentityContext``
to identity-enhanced role sessions. The current reviewed v12 document has an
explicit ``Deny`` with ``NotAction`` and does not exempt
``lambda:InvokeFunction``. This module models that IAM semantic before any
OAuth, STS, or broker effect.

Only public managed-policy metadata and sanitized decisions may leave this
module. It never accepts cached policy data as live evidence and never calls
AWS.
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping


AWS_IDENTITY_CONTEXT_POLICY_ARN = (
    "arn:aws:iam::aws:policy/AWSIAMIdentityCenterAllowListForIdentityContext"
)
BROKER_REQUIRED_ACTION = "lambda:InvokeFunction"
BLOCKED_ACTION_UNSUPPORTED = "BLOCKED_AWS_IDENTITY_CONTEXT_ACTION_UNSUPPORTED"
COMPATIBLE_REVIEWED_ACTION = "COMPATIBLE_REVIEWED_ACTION"
POLICY_SNAPSHOT_VERSION = "v12"
POLICY_SNAPSHOT_DIGEST = (
    "sha256:588e10587ff62c683615a9612b1f42ded9fccd03bd94810dc6760dad50665655"
)
POLICY_SNAPSHOT_PATH = (
    Path(__file__).resolve().parents[1]
    / "policies/iam/aws-managed-identity-context-allowlist-v12.snapshot.json"
)
ACTION = re.compile(r"^[a-z0-9-]+:[A-Za-z0-9*]+$")
DIGEST = re.compile(r"^sha256:[a-f0-9]{64}$")
TIMESTAMP = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")


class CompatibilityError(ValueError):
    """A sanitized fail-closed compatibility decision."""

    def __init__(self, code: str) -> None:
        self.code = code if re.fullmatch(r"[A-Z][A-Z0-9_]{2,79}", code) else "COMPATIBILITY_DENIED"
        super().__init__(self.code)


def canonical_digest(value: Mapping[str, Any]) -> str:
    encoded = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


@dataclass(frozen=True, slots=True)
class CompatibilityDecision:
    """A public decision containing no operator or session identifiers."""

    status: str
    policy_arn: str
    policy_version: str
    policy_digest: str
    required_action: str
    token_issued: bool = False
    sts_session_issued: bool = False
    broker_invocation_performed: bool = False

    def __post_init__(self) -> None:
        if self.status not in {BLOCKED_ACTION_UNSUPPORTED, COMPATIBLE_REVIEWED_ACTION}:
            raise CompatibilityError("COMPATIBILITY_STATUS_INVALID")
        if self.policy_arn != AWS_IDENTITY_CONTEXT_POLICY_ARN:
            raise CompatibilityError("POLICY_ARN_UNEXPECTED")
        if DIGEST.fullmatch(self.policy_digest) is None:
            raise CompatibilityError("POLICY_DIGEST_INVALID")
        if ACTION.fullmatch(self.required_action) is None:
            raise CompatibilityError("REQUIRED_ACTION_INVALID")
        if any(
            (
                self.token_issued,
                self.sts_session_issued,
                self.broker_invocation_performed,
            )
        ):
            raise CompatibilityError("COMPATIBILITY_RECEIPT_OVERCLAIM")

    def to_receipt(self, *, observed_at: str) -> dict[str, Any]:
        if TIMESTAMP.fullmatch(observed_at) is None:
            raise CompatibilityError("OBSERVATION_TIME_INVALID")
        receipt: dict[str, Any] = {
            "schema_version": "1",
            "record_type": "platform_authority_identity_context_compatibility",
            "environment": "non-production",
            "production": False,
            "managed_policy_arn": self.policy_arn,
            "managed_policy_version": self.policy_version,
            "managed_policy_digest": self.policy_digest,
            "required_action": self.required_action,
            "status": self.status,
            "token_issued": self.token_issued,
            "sts_session_issued": self.sts_session_issued,
            "broker_invocation_performed": self.broker_invocation_performed,
            "current_human_operator_count": 1,
            "independent_approver_available": False,
            "live_retirement_authorized": False,
            "observed_at": observed_at,
        }
        receipt["receipt_digest"] = canonical_digest(receipt)
        return receipt


def load_bundled_policy_snapshot() -> dict[str, Any]:
    try:
        value = json.loads(POLICY_SNAPSHOT_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise CompatibilityError("POLICY_SNAPSHOT_UNAVAILABLE") from None
    if not isinstance(value, dict):
        raise CompatibilityError("POLICY_DOCUMENT_MALFORMED")
    return value


def _validated_not_actions(document: Mapping[str, Any]) -> frozenset[str]:
    if set(document) != {"Version", "Statement"}:
        raise CompatibilityError("POLICY_DOCUMENT_MALFORMED")
    if document.get("Version") != "2012-10-17":
        raise CompatibilityError("POLICY_DOCUMENT_MALFORMED")
    statements = document.get("Statement")
    if not isinstance(statements, list) or len(statements) != 1:
        raise CompatibilityError("POLICY_DOCUMENT_MALFORMED")
    statement = statements[0]
    if not isinstance(statement, dict) or set(statement) != {
        "Sid",
        "Effect",
        "NotAction",
        "Resource",
    }:
        raise CompatibilityError("POLICY_DOCUMENT_MALFORMED")
    if (
        statement.get("Sid") != "TrustedIdentityPropagation"
        or statement.get("Effect") != "Deny"
        or statement.get("Resource") != "*"
    ):
        raise CompatibilityError("POLICY_DOCUMENT_MALFORMED")
    actions = statement.get("NotAction")
    if (
        not isinstance(actions, list)
        or not actions
        or not all(isinstance(action, str) and ACTION.fullmatch(action) for action in actions)
        or len(actions) != len(set(actions))
    ):
        raise CompatibilityError("POLICY_DOCUMENT_MALFORMED")
    return frozenset(actions)


def evaluate_identity_context_policy(
    document: Mapping[str, Any],
    *,
    policy_arn: str,
    default_version_id: str,
    required_action: str,
    reviewed_digest: str,
) -> CompatibilityDecision:
    if policy_arn != AWS_IDENTITY_CONTEXT_POLICY_ARN:
        raise CompatibilityError("POLICY_ARN_UNEXPECTED")
    if re.fullmatch(r"v[1-9][0-9]*", default_version_id) is None:
        raise CompatibilityError("POLICY_VERSION_UNEXPECTED")
    if ACTION.fullmatch(required_action) is None:
        raise CompatibilityError("REQUIRED_ACTION_INVALID")
    if DIGEST.fullmatch(reviewed_digest) is None:
        raise CompatibilityError("POLICY_DIGEST_INVALID")
    actual_digest = canonical_digest(document)
    if actual_digest != reviewed_digest:
        raise CompatibilityError("POLICY_DIGEST_UNREVIEWED")
    allowed_by_not_action = _validated_not_actions(document)
    status = (
        COMPATIBLE_REVIEWED_ACTION
        if required_action in allowed_by_not_action
        else BLOCKED_ACTION_UNSUPPORTED
    )
    return CompatibilityDecision(
        status=status,
        policy_arn=policy_arn,
        policy_version=default_version_id,
        policy_digest=actual_digest,
        required_action=required_action,
    )


def bundled_compatibility_decision() -> CompatibilityDecision:
    document = load_bundled_policy_snapshot()
    return evaluate_identity_context_policy(
        document,
        policy_arn=AWS_IDENTITY_CONTEXT_POLICY_ARN,
        default_version_id=POLICY_SNAPSHOT_VERSION,
        required_action=BROKER_REQUIRED_ACTION,
        reviewed_digest=POLICY_SNAPSHOT_DIGEST,
    )
