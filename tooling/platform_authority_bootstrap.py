"""Fail-closed contracts for the dedicated platform-authority bootstrap.

This module contains no AWS client and performs no side effects.  The live CLI
adapter must prove the current STS account and region, create a CloudFormation
change set, bind that exact change set into a short-lived plan record, require
independent approval, and call these functions again immediately before apply.
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Mapping, Sequence


ACCOUNT_ID = re.compile(r"^(?!000000000000$)[0-9]{12}$")
REGION = re.compile(r"^[a-z]{2}(?:-[a-z]+)+-[0-9]+$")
SHA256 = re.compile(r"^[a-f0-9]{64}$")
KMS_KEY_ARN = re.compile(
    r"^arn:(?P<partition>aws(?:-us-gov|-cn)?):kms:"
    r"(?P<region>[a-z0-9-]+):(?P<account>[0-9]{12}):"
    r"key/[0-9a-f-]{36}$"
)
CHANGE_SET_ARN = re.compile(
    r"^arn:(?P<partition>aws(?:-us-gov|-cn)?):cloudformation:"
    r"(?P<region>[a-z0-9-]+):(?P<account>[0-9]{12}):"
    r"changeSet/(?P<name>[A-Za-z][-A-Za-z0-9]*)/(?P<id>[0-9a-f-]{36})$"
)
POLICY_PLACEHOLDER = re.compile(r"\$\{(?P<name>[a-z_]+)\}")
CANONICAL_STACK_NAME = "scanalyze-platform-authority-state-backend"
CANONICAL_STATE_KEY = "platform-authority/terraform.tfstate"
PUBLIC_ACCESS_BLOCK = {
    "BlockPublicAcls": True,
    "BlockPublicPolicy": True,
    "IgnorePublicAcls": True,
    "RestrictPublicBuckets": True,
}
ALLOWED_CHANGE_SET_TYPES = frozenset({"CREATE", "UPDATE"})
ALLOWED_RESOURCE_TYPES = frozenset(
    {
        "AWS::KMS::Key",
        "AWS::KMS::Alias",
        "AWS::S3::Bucket",
        "AWS::S3::BucketPolicy",
    }
)
REQUIRED_RESOURCE_TYPES = frozenset(
    {"AWS::KMS::Key", "AWS::S3::Bucket", "AWS::S3::BucketPolicy"}
)


class BootstrapAuthorizationError(ValueError):
    """The platform-authority bootstrap could not be proven safe."""


def _aws_partition(region: str) -> str:
    if region.startswith("cn-"):
        return "aws-cn"
    if region.startswith("us-gov-"):
        return "aws-us-gov"
    return "aws"


def _render_policy_value(value: Any, bindings: Mapping[str, str]) -> Any:
    if isinstance(value, str):
        rendered = value
        for name, replacement in bindings.items():
            rendered = rendered.replace(f"${{{name}}}", replacement)
        if POLICY_PLACEHOLDER.search(rendered):
            raise BootstrapAuthorizationError("IAM policy contains an unbound placeholder")
        return rendered
    if isinstance(value, list):
        return [_render_policy_value(item, bindings) for item in value]
    if isinstance(value, dict):
        return {key: _render_policy_value(item, bindings) for key, item in value.items()}
    return value


def canonical_digest(document: Mapping[str, Any]) -> str:
    """Return a stable SHA-256 digest without leaking document contents."""
    payload = json.dumps(
        document,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )
    return "sha256:" + hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _timestamp(value: datetime, label: str) -> str:
    if value.tzinfo is None:
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


def _require_digest(document: Mapping[str, Any], field: str, label: str) -> None:
    claimed = document.get(field)
    expected = canonical_digest({key: value for key, value in document.items() if key != field})
    if claimed != expected:
        raise BootstrapAuthorizationError(f"{label} digest mismatch")


def _normalize_sha256(value: str, label: str) -> str:
    raw = value.removeprefix("sha256:")
    if not SHA256.fullmatch(raw):
        raise BootstrapAuthorizationError(f"{label} must be a lowercase SHA-256 digest")
    return "sha256:" + raw


@dataclass(frozen=True, slots=True)
class BootstrapBinding:
    """Immutable bootstrap ownership and location binding."""

    authority_account_id: str
    region: str
    stack_name: str
    state_bucket_name: str
    state_key: str
    destination_account_ids: tuple[str, ...]

    def __post_init__(self) -> None:
        destinations = tuple(self.destination_account_ids)
        object.__setattr__(self, "destination_account_ids", destinations)
        if not ACCOUNT_ID.fullmatch(self.authority_account_id):
            raise BootstrapAuthorizationError("authority account ID is malformed")
        if not REGION.fullmatch(self.region):
            raise BootstrapAuthorizationError("authority region is malformed")
        if self.stack_name != CANONICAL_STACK_NAME:
            raise BootstrapAuthorizationError("bootstrap stack name is not canonical")
        expected_bucket = (
            f"scanalyze-platform-authority-{self.authority_account_id}-{self.region}-state"
        )
        if self.state_bucket_name != expected_bucket:
            raise BootstrapAuthorizationError("state bucket name is not authority-derived")
        if self.state_key != CANONICAL_STATE_KEY:
            raise BootstrapAuthorizationError("state key is not canonical")
        if not destinations:
            raise BootstrapAuthorizationError("at least one destination account is required")
        if any(not ACCOUNT_ID.fullmatch(account_id) for account_id in destinations):
            raise BootstrapAuthorizationError("destination account ID is malformed")
        if len(set(destinations)) != len(destinations):
            raise BootstrapAuthorizationError("destination account IDs must be unique")
        if self.authority_account_id in destinations:
            raise BootstrapAuthorizationError(
                "authority account must differ from every destination account"
            )

    def authorize_identity(self, *, caller_account_id: str, caller_region: str) -> None:
        if caller_account_id != self.authority_account_id:
            raise BootstrapAuthorizationError("caller account does not match authority binding")
        if caller_region != self.region:
            raise BootstrapAuthorizationError("caller region does not match authority binding")

    def as_record(self) -> dict[str, Any]:
        return {
            "authority_account_id": self.authority_account_id,
            "region": self.region,
            "stack_name": self.stack_name,
            "state_bucket_name": self.state_bucket_name,
            "state_key": self.state_key,
            "destination_account_ids": list(self.destination_account_ids),
        }


def render_bootstrap_iam_policy(
    *,
    policy_template: Mapping[str, Any],
    binding: BootstrapBinding,
    change_set_id: str | None = None,
) -> dict[str, Any]:
    """Render a policy without accepting caller-selected authority fields."""
    bindings = {
        "aws_partition": _aws_partition(binding.region),
        "region": binding.region,
        "authority_account_id": binding.authority_account_id,
        "state_bucket_name": binding.state_bucket_name,
    }
    if change_set_id is not None:
        match = CHANGE_SET_ARN.fullmatch(change_set_id)
        if (
            match is None
            or match.group("partition") != bindings["aws_partition"]
            or match.group("region") != binding.region
            or match.group("account") != binding.authority_account_id
        ):
            raise BootstrapAuthorizationError("Change Set ARN does not match policy binding")
        bindings["change_set_name"] = match.group("name")
        bindings["change_set_id"] = match.group("id")
    rendered = _render_policy_value(dict(policy_template), bindings)
    if (
        not isinstance(rendered, dict)
        or rendered.get("Version") != "2012-10-17"
        or not isinstance(rendered.get("Statement"), list)
        or not rendered["Statement"]
    ):
        raise BootstrapAuthorizationError("rendered IAM policy is malformed")
    return rendered


def _normalize_resource_changes(
    changes: Sequence[Mapping[str, Any]], *, change_set_type: str
) -> list[dict[str, str]]:
    normalized: list[dict[str, str]] = []
    seen_logical_ids: set[str] = set()
    for change in changes:
        action = change.get("action")
        logical_id = change.get("logical_resource_id")
        resource_type = change.get("resource_type")
        replacement = change.get("replacement", "False")
        if action not in {"Add", "Modify"}:
            raise BootstrapAuthorizationError("bootstrap change set contains a destructive action")
        if change_set_type == "CREATE" and action != "Add":
            raise BootstrapAuthorizationError("CREATE bootstrap change set may only add resources")
        if replacement not in {"False", False, None}:
            raise BootstrapAuthorizationError("bootstrap change set may not replace resources")
        if not isinstance(logical_id, str) or not re.fullmatch(r"[A-Za-z0-9]{1,255}", logical_id):
            raise BootstrapAuthorizationError("bootstrap change set logical ID is invalid")
        if logical_id in seen_logical_ids:
            raise BootstrapAuthorizationError("bootstrap change set contains duplicate logical IDs")
        if resource_type not in ALLOWED_RESOURCE_TYPES:
            raise BootstrapAuthorizationError("bootstrap change set contains an unexpected resource type")
        seen_logical_ids.add(logical_id)
        normalized.append(
            {
                "action": str(action),
                "logical_resource_id": logical_id,
                "resource_type": str(resource_type),
                "replacement": "False",
            }
        )
    present_types = {change["resource_type"] for change in normalized}
    if not REQUIRED_RESOURCE_TYPES <= present_types:
        raise BootstrapAuthorizationError("bootstrap change set is missing required resources")
    return sorted(normalized, key=lambda item: item["logical_resource_id"])


def build_bootstrap_plan(
    *,
    binding: BootstrapBinding,
    caller_account_id: str,
    caller_arn: str,
    template_sha256: str,
    change_set_id: str,
    change_set_type: str,
    resource_changes: Sequence[Mapping[str, Any]],
    account_public_access_block_before: Mapping[str, Any] | None,
    created_at: datetime,
    expires_at: datetime,
    initiator_id: str,
) -> dict[str, Any]:
    """Build a short-lived exact bootstrap plan from a reviewed change set."""
    binding.authorize_identity(
        caller_account_id=caller_account_id,
        caller_region=binding.region,
    )
    if not isinstance(initiator_id, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{2,127}", initiator_id):
        raise BootstrapAuthorizationError("bootstrap initiator ID is invalid")
    if not isinstance(caller_arn, str) or f"::{binding.authority_account_id}:" not in caller_arn:
        raise BootstrapAuthorizationError("caller principal is not bound to authority account")
    match = CHANGE_SET_ARN.fullmatch(change_set_id)
    if not match or match.group("account") != binding.authority_account_id:
        raise BootstrapAuthorizationError("change set account binding mismatch")
    if match.group("partition") != _aws_partition(binding.region):
        raise BootstrapAuthorizationError("change set partition binding mismatch")
    if match.group("region") != binding.region:
        raise BootstrapAuthorizationError("change set region binding mismatch")
    if change_set_type not in ALLOWED_CHANGE_SET_TYPES:
        raise BootstrapAuthorizationError("bootstrap change set type is invalid")
    created = _parse_timestamp(_timestamp(created_at, "created_at"), "created_at")
    expires = _parse_timestamp(_timestamp(expires_at, "expires_at"), "expires_at")
    lifetime = (expires - created).total_seconds()
    if not 300 <= lifetime <= 7200:
        raise BootstrapAuthorizationError("bootstrap plan lifetime must be five minutes to two hours")
    before = None if account_public_access_block_before is None else dict(account_public_access_block_before)
    if before is not None and set(before) != set(PUBLIC_ACCESS_BLOCK):
        raise BootstrapAuthorizationError("existing account public-access block is ambiguous")
    plan: dict[str, Any] = {
        "schema_version": "1",
        "record_type": "platform_authority_bootstrap_plan",
        **binding.as_record(),
        "native_lockfile_enabled": True,
        "template_sha256": _normalize_sha256(template_sha256, "template digest"),
        "caller_principal_digest": canonical_digest({"caller_arn": caller_arn}),
        "change_set_id": change_set_id,
        "change_set_type": change_set_type,
        "planned_resource_changes": _normalize_resource_changes(
            resource_changes,
            change_set_type=change_set_type,
        ),
        "account_public_access_block_before": before,
        "account_public_access_block_after": dict(PUBLIC_ACCESS_BLOCK),
        "initiator_id": initiator_id,
        "created_at": _timestamp(created_at, "created_at"),
        "expires_at": _timestamp(expires_at, "expires_at"),
    }
    plan["record_digest"] = canonical_digest(plan)
    return plan


def build_bootstrap_approval(
    *,
    plan: Mapping[str, Any],
    initiator_id: str,
    approver_id: str,
    approver_arn: str,
    approved_at: datetime,
    expires_at: datetime,
) -> dict[str, Any]:
    """Build a plan-specific approval requiring a different human reviewer."""
    _require_digest(plan, "record_digest", "bootstrap plan")
    if plan.get("initiator_id") != initiator_id:
        raise BootstrapAuthorizationError("bootstrap approval initiator binding mismatch")
    if initiator_id == approver_id:
        raise BootstrapAuthorizationError("bootstrap apply requires an independent approver")
    if not isinstance(approver_id, str) or not re.fullmatch(
        r"[A-Za-z0-9][A-Za-z0-9._-]{2,127}", approver_id
    ):
        raise BootstrapAuthorizationError("bootstrap approver ID is invalid")
    if not isinstance(approver_arn, str) or f"::{plan.get('authority_account_id')}:" not in approver_arn:
        raise BootstrapAuthorizationError("approver principal is not bound to authority account")
    approver_principal_digest = canonical_digest({"caller_arn": approver_arn})
    if approver_principal_digest == plan.get("caller_principal_digest"):
        raise BootstrapAuthorizationError("bootstrap apply requires an independent AWS principal")
    approved = _parse_timestamp(_timestamp(approved_at, "approved_at"), "approved_at")
    approval_expires = _parse_timestamp(_timestamp(expires_at, "approval expires_at"), "approval expires_at")
    plan_created = _parse_timestamp(plan.get("created_at"), "plan created_at")
    plan_expires = _parse_timestamp(plan.get("expires_at"), "plan expires_at")
    if not plan_created <= approved < approval_expires <= plan_expires:
        raise BootstrapAuthorizationError("bootstrap approval lifetime exceeds plan lifetime")
    approval: dict[str, Any] = {
        "schema_version": "1",
        "record_type": "platform_authority_bootstrap_approval",
        "plan_record_digest": plan["record_digest"],
        "authority_account_id": plan["authority_account_id"],
        "region": plan["region"],
        "change_set_id": plan["change_set_id"],
        "initiator_id": initiator_id,
        "approver_id": approver_id,
        "initiator_principal_digest": plan["caller_principal_digest"],
        "approver_principal_digest": approver_principal_digest,
        "decision": "APPROVED",
        "approved_at": _timestamp(approved_at, "approved_at"),
        "expires_at": _timestamp(expires_at, "approval expires_at"),
    }
    approval["approval_digest"] = canonical_digest(approval)
    return approval


def authorize_bootstrap_apply(
    *,
    plan: Mapping[str, Any],
    approval: Mapping[str, Any],
    binding: BootstrapBinding,
    caller_account_id: str,
    caller_region: str,
    caller_arn: str,
    current_template_sha256: str,
    now: datetime,
) -> None:
    """Authorize execution of exactly one previously reviewed change set."""
    binding.authorize_identity(
        caller_account_id=caller_account_id,
        caller_region=caller_region,
    )
    _require_digest(plan, "record_digest", "bootstrap plan")
    _require_digest(approval, "approval_digest", "bootstrap approval")
    for field, expected in binding.as_record().items():
        if plan.get(field) != expected:
            raise BootstrapAuthorizationError(f"bootstrap plan binding mismatch: {field}")
    if plan.get("template_sha256") != _normalize_sha256(
        current_template_sha256, "template digest"
    ):
        raise BootstrapAuthorizationError("bootstrap template digest mismatch")
    if approval.get("plan_record_digest") != plan.get("record_digest"):
        raise BootstrapAuthorizationError("bootstrap approval plan binding mismatch")
    for field in ("authority_account_id", "region", "change_set_id", "initiator_id"):
        if approval.get(field) != plan.get(field):
            raise BootstrapAuthorizationError(f"bootstrap approval binding mismatch: {field}")
    if approval.get("approver_id") == plan.get("initiator_id"):
        raise BootstrapAuthorizationError("bootstrap apply requires an independent approver")
    if approval.get("initiator_principal_digest") != plan.get("caller_principal_digest"):
        raise BootstrapAuthorizationError("bootstrap approval initiator principal mismatch")
    if approval.get("approver_principal_digest") == plan.get("caller_principal_digest"):
        raise BootstrapAuthorizationError("bootstrap apply requires an independent AWS principal")
    current_principal_digest = canonical_digest({"caller_arn": caller_arn})
    if approval.get("approver_principal_digest") != current_principal_digest:
        raise BootstrapAuthorizationError("current AWS principal is not the approved executor")
    current = _parse_timestamp(_timestamp(now, "authorization time"), "authorization time")
    plan_created = _parse_timestamp(plan.get("created_at"), "plan created_at")
    plan_expires = _parse_timestamp(plan.get("expires_at"), "plan expires_at")
    approved = _parse_timestamp(approval.get("approved_at"), "approval approved_at")
    approval_expires = _parse_timestamp(approval.get("expires_at"), "approval expires_at")
    if current < plan_created or current >= plan_expires:
        raise BootstrapAuthorizationError("bootstrap plan is expired or not yet valid")
    if current < approved or current >= approval_expires:
        raise BootstrapAuthorizationError("bootstrap approval is expired or not yet valid")
    if not plan_created <= approved < approval_expires <= plan_expires:
        raise BootstrapAuthorizationError("bootstrap approval lifetime exceeds plan lifetime")


def render_backend_config(*, binding: BootstrapBinding, kms_key_arn: str) -> str:
    """Render the exact Terraform S3 backend binding after live verification."""
    match = KMS_KEY_ARN.fullmatch(kms_key_arn)
    if not match:
        raise BootstrapAuthorizationError("backend KMS key ARN is malformed")
    if match.group("account") != binding.authority_account_id:
        raise BootstrapAuthorizationError("backend KMS account binding mismatch")
    if match.group("region") != binding.region:
        raise BootstrapAuthorizationError("backend KMS region binding mismatch")
    return (
        f'bucket              = "{binding.state_bucket_name}"\n'
        f'key                 = "{binding.state_key}"\n'
        f'region              = "{binding.region}"\n'
        "encrypt             = true\n"
        "use_lockfile        = true\n"
        f'kms_key_id          = "{kms_key_arn}"\n'
        f'allowed_account_ids = ["{binding.authority_account_id}"]\n'
    )


def build_bootstrap_verification(
    *,
    plan: Mapping[str, Any],
    binding: BootstrapBinding,
    caller_arn: str,
    stack_status: str,
    state_bucket_name: str,
    state_key: str,
    state_kms_key_arn: str,
    controls: Mapping[str, Any],
    verified_at: datetime,
) -> dict[str, Any]:
    """Build success evidence only after every live backend control is proven."""
    _require_digest(plan, "record_digest", "bootstrap plan")
    for field, expected in binding.as_record().items():
        if plan.get(field) != expected:
            raise BootstrapAuthorizationError(f"bootstrap plan binding mismatch: {field}")
    if stack_status not in {"CREATE_COMPLETE", "UPDATE_COMPLETE"}:
        raise BootstrapAuthorizationError("bootstrap stack is not complete")
    if state_bucket_name != binding.state_bucket_name or state_key != binding.state_key:
        raise BootstrapAuthorizationError("verified backend location does not match binding")
    render_backend_config(binding=binding, kms_key_arn=state_kms_key_arn)
    if not isinstance(caller_arn, str) or f"::{binding.authority_account_id}:" not in caller_arn:
        raise BootstrapAuthorizationError("verifier principal is not bound to authority account")
    expected_controls = {
        "account_public_access_blocked": True,
        "bucket_public_access_blocked": True,
        "bucket_owner_enforced": True,
        "bucket_versioning_enabled": True,
        "default_encryption": "aws:kms",
        "bucket_key_enabled": True,
        "kms_rotation_enabled": True,
        "native_lockfile_enabled": True,
    }
    if dict(controls) != expected_controls:
        raise BootstrapAuthorizationError("bootstrap verification control mismatch")
    record: dict[str, Any] = {
        "schema_version": "1",
        "record_type": "platform_authority_bootstrap_verification",
        "plan_record_digest": plan["record_digest"],
        "authority_account_id": binding.authority_account_id,
        "region": binding.region,
        "stack_name": binding.stack_name,
        "stack_status": stack_status,
        "state_bucket_name": state_bucket_name,
        "state_key": state_key,
        "state_kms_key_arn": state_kms_key_arn,
        "controls": expected_controls,
        "verifier_principal_digest": canonical_digest({"caller_arn": caller_arn}),
        "verified_at": _timestamp(verified_at, "verified_at"),
    }
    record["verification_digest"] = canonical_digest(record)
    return record
