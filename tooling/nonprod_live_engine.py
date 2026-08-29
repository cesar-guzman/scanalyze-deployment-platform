"""Pure fail-closed authorization core for the GUG-125 non-production engine.

The module deliberately performs no AWS, Terraform, GitHub, or filesystem I/O.
Live adapters must read authoritative records, pass them through these checks,
and use the returned compare-and-swap conditions without weakening them.
"""
from __future__ import annotations

import copy
import os
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Mapping, Sequence

import jsonschema

from tooling.authorize_deployment_backend import (
    AuthorizationError,
    canonical_digest,
    load_json_strict,
)


REPO_ROOT = Path(__file__).resolve().parents[1]
SCHEMA_DIR = REPO_ROOT / "schemas"
DIGEST = re.compile(r"^sha256:[a-f0-9]{64}$")
NONPRODUCTION_ENVIRONMENTS = frozenset({"sandbox", "dev", "staging"})
TERRAFORM_LAYERS = frozenset(
    {
        "global",
        "network",
        "platform",
        "data-foundation",
        "cicd",
        "identity-control-plane",
        "services",
        "edge-identity",
        "edge",
        "addons",
    }
)
CREDENTIAL_ENVIRONMENT_NAMES = frozenset(
    {
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "AWS_SESSION_TOKEN",
        "AWS_PROFILE",
        "AWS_DEFAULT_PROFILE",
        "AWS_SHARED_CREDENTIALS_FILE",
        "AWS_CONFIG_FILE",
        "AWS_WEB_IDENTITY_TOKEN_FILE",
        "AWS_ROLE_ARN",
        "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI",
        "AWS_CONTAINER_CREDENTIALS_FULL_URI",
        "AWS_CONTAINER_AUTHORIZATION_TOKEN",
        "AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE",
    }
)
PLAN_BINDING_FIELDS = (
    "customer_id",
    "deployment_id",
    "account_id",
    "region",
    "environment",
    "execution_id",
    "change_id",
    "layer",
    "release_version",
    "release_digest",
    "release_policy_digest",
    "release_projection_digest",
    "plan_policy_digest",
    "github_environment",
    "github_deployment_identity_digest",
    "environment_configuration_digest",
    "expected_approver_user_id",
    "approval_authority_digest",
    "platform_authority_digest",
    "registry_record_digest",
    "account_ready_digest",
    "execution_lock_digest",
    "backend_binding_digest",
    "contract_resolution_digest",
    "toolchain_digest",
    "root_module_digest",
    "source_revision_digest",
    "state_status",
    "state_lineage",
    "state_serial",
)
STATE_BINDING_FIELDS = (
    "state_status",
    "state_lineage",
    "state_serial",
)
# These fields are safe to materialize before OIDC. Terraform state is not a
# transport input: the terminal Plan role reads and brackets it immediately
# before planning, then adds the exact state tuple to the durable saved plan.
MATERIALIZED_PLAN_BINDING_FIELDS = tuple(
    field for field in PLAN_BINDING_FIELDS if field not in STATE_BINDING_FIELDS
)
LEDGER_BINDING_FIELDS = (
    "customer_id",
    "deployment_id",
    "account_id",
    "region",
    "environment",
    "execution_id",
    "change_id",
    "layer",
)
ALLOWED_LEDGER_TRANSITIONS = {
    "PLANNED": frozenset({"APPROVED", "REJECTED", "EXPIRED"}),
    "APPROVED": frozenset({"APPLYING", "EXPIRED"}),
    "APPLYING": frozenset({"APPLIED", "UNCERTAIN", "FAILED"}),
    "APPLIED": frozenset({"HEALTHY", "FAILED_HEALTH"}),
    "UNCERTAIN": frozenset({"RECONCILED_APPLIED", "RECONCILIATION_REQUIRED"}),
    "RECONCILED_APPLIED": frozenset({"HEALTHY", "FAILED_HEALTH"}),
    "REJECTED": frozenset(),
    "EXPIRED": frozenset(),
    "FAILED": frozenset(),
    "FAILED_HEALTH": frozenset(),
    "RECONCILIATION_REQUIRED": frozenset(),
    "HEALTHY": frozenset(),
}
STALE_APPLYING_MIN_AGE_SECONDS = 3900


def derive_approval_authority_digest(
    *,
    github_environment: str,
    expected_approver_user_id: int,
    github_deployment_identity_digest: str,
    environment_configuration_digest: str,
) -> str:
    """Domain-separate stable reviewer authority across Plan and Apply runs."""
    if (
        not isinstance(github_environment, str)
        or not re.fullmatch(r"^[A-Za-z0-9][A-Za-z0-9._-]{2,127}$", github_environment)
        or isinstance(expected_approver_user_id, bool)
        or not isinstance(expected_approver_user_id, int)
        or expected_approver_user_id < 1
        or any(
            not isinstance(value, str) or not DIGEST.fullmatch(value)
            for value in (
                github_deployment_identity_digest,
                environment_configuration_digest,
            )
        )
    ):
        raise AuthorizationError("saved plan approval authority is invalid")
    return canonical_digest(
        {
            "schema_version": "1",
            "record_type": "nonprod_live_approval_authority",
            "github_environment": github_environment,
            "expected_approver_user_id": expected_approver_user_id,
            "github_deployment_identity_digest": github_deployment_identity_digest,
            "environment_configuration_digest": environment_configuration_digest,
        }
    )


def require_terminal_role_for_layer(*, layer: str, role: str, operation: str) -> None:
    """Reject a terminal role that is not canonical for the exact Terraform layer."""
    if layer not in TERRAFORM_LAYERS:
        raise AuthorizationError("saved plan layer is not a canonical Terraform layer")
    if operation not in {"plan", "apply"}:
        raise AuthorizationError("saved plan terminal operation is invalid")
    role_suffix = "Plan" if operation == "plan" else "Apply"
    if layer == "identity-control-plane":
        expected = f"ScanalyzeCustomer-Identity-{role_suffix}"
    else:
        expected = f"ScanalyzeCustomer-{role_suffix}"
    if role != expected:
        raise AuthorizationError("saved plan terminal role does not match the bound layer")


def _timestamp(value: datetime) -> str:
    if value.tzinfo is None:
        raise AuthorizationError("timestamp must be timezone-aware")
    return value.astimezone(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _parse_timestamp(value: str, label: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (AttributeError, ValueError) as exc:
        raise AuthorizationError(f"{label} timestamp is invalid") from exc
    if parsed.tzinfo is None:
        raise AuthorizationError(f"{label} timestamp must be timezone-aware")
    return parsed.astimezone(UTC)


def _validate_schema(document: Mapping[str, Any], filename: str, label: str) -> None:
    schema = load_json_strict(SCHEMA_DIR / filename)
    validator = jsonschema.Draft202012Validator(
        schema,
        format_checker=jsonschema.FormatChecker(),
    )
    errors = sorted(validator.iter_errors(document), key=lambda error: list(error.path))
    if errors:
        path = ".".join(str(part) for part in errors[0].absolute_path) or "(root)"
        raise AuthorizationError(f"{label} schema validation failed at {path}")


def _verify_digest(document: Mapping[str, Any], field: str, label: str) -> None:
    claimed = document.get(field)
    expected = canonical_digest({key: value for key, value in document.items() if key != field})
    if claimed != expected:
        raise AuthorizationError(f"{label} digest mismatch")


def _exact_plan_key(bindings: Mapping[str, Any]) -> str:
    return (
        f"plan-execution/{bindings['deployment_id']}/{bindings['change_id']}/"
        f"{bindings['layer']}/plan.tfplan"
    )


PLAN_SUMMARY_COUNT_FIELDS = (
    "add_count",
    "change_count",
    "read_count",
    "no_op_count",
    "destroy_count",
    "replace_count",
)
PLAN_SUMMARY_OUTPUT_COUNT_FIELDS = (
    "output_create_count",
    "output_update_count",
    "output_delete_count",
    "output_no_op_count",
)
COST_BINDING_FIELDS = (
    "cost_model_digest",
    "maximum_cost_usd_micros",
    "modeled_cost_upper_bound_usd_micros",
)
_TERRAFORM_ACTION_COUNTS = {
    ("create",): "add_count",
    ("update",): "change_count",
    ("read",): "read_count",
    ("no-op",): "no_op_count",
    ("delete",): "destroy_count",
    ("delete", "create"): "replace_count",
    ("create", "delete"): "replace_count",
}
_TERRAFORM_OUTPUT_ACTIONS = {
    ("create",),
    ("update",),
    ("delete",),
    ("no-op",),
}
_REVIEW_ACTIONS = {
    ("create",): "create",
    ("update",): "update",
    ("read",): "read",
    ("no-op",): "no-op",
    ("delete",): "delete",
    ("delete", "create"): "replace",
    ("create", "delete"): "replace",
}
TERRAFORM_IDENTIFIER = re.compile(r"^[A-Za-z_][A-Za-z0-9_-]{0,127}$")
MAX_REVIEWABLE_RESOURCE_CHANGES = 256
MAX_REVIEWABLE_OUTPUT_CHANGES = 128


def summarize_terraform_plan(plan: Mapping[str, Any]) -> dict[str, Any]:
    """Project raw ``terraform show -json`` output to a sanitized summary.

    The raw plan can contain sensitive values and must never be persisted with
    this summary. Unknown action sequences are rejected instead of being
    treated as harmless changes.
    """
    if not isinstance(plan, Mapping):
        raise AuthorizationError("Terraform plan JSON must be an object")
    format_version = plan.get("format_version")
    terraform_version = plan.get("terraform_version")
    resource_changes = plan.get("resource_changes")
    if (
        format_version != "1.2"
        or not isinstance(terraform_version, str)
        or not terraform_version
        or not isinstance(resource_changes, list)
    ):
        raise AuthorizationError("Terraform plan JSON is incomplete")
    if (
        not isinstance(plan.get("applyable"), bool)
        or plan.get("complete") is not True
        or plan.get("errored") is not False
    ):
        raise AuthorizationError("Terraform plan is not complete and successful")
    for field in (
        "resource_drift",
        "deferred_changes",
        "deferred_action_invocations",
        "action_invocations",
    ):
        value = plan.get(field, [])
        if not isinstance(value, list) or value:
            raise AuthorizationError(
                f"Terraform plan contains unsupported {field.replace('_', ' ')}"
            )
    output_changes = plan.get("output_changes", {})
    if not isinstance(output_changes, Mapping):
        raise AuthorizationError("Terraform output changes are malformed")
    output_counts = {field: 0 for field in PLAN_SUMMARY_OUTPUT_COUNT_FIELDS}
    output_actions: list[dict[str, str]] = []
    output_action_fields = {
        ("create",): "output_create_count",
        ("update",): "output_update_count",
        ("delete",): "output_delete_count",
        ("no-op",): "output_no_op_count",
    }
    for name, output_change in output_changes.items():
        if (
            not isinstance(name, str)
            or not TERRAFORM_IDENTIFIER.fullmatch(name)
            or not isinstance(output_change, Mapping)
        ):
            raise AuthorizationError("Terraform output change is malformed")
        actions = output_change.get("actions")
        if (
            not isinstance(actions, list)
            or not actions
            or not all(isinstance(action, str) for action in actions)
            or tuple(actions) not in _TERRAFORM_OUTPUT_ACTIONS
        ):
            raise AuthorizationError("Terraform output actions are unknown")
        output_counts[output_action_fields[tuple(actions)]] += 1
        output_action = _REVIEW_ACTIONS[tuple(actions)]
        if output_action != "no-op":
            output_actions.append({"output_name": name, "action": output_action})

    if len(output_actions) > MAX_REVIEWABLE_OUTPUT_CHANGES:
        raise AuthorizationError("Terraform plan exceeds the reviewable output-change limit")
    output_actions.sort(key=lambda item: item["output_name"])

    counts = {field: 0 for field in PLAN_SUMMARY_COUNT_FIELDS}
    addresses: set[str] = set()
    resource_actions: list[dict[str, str]] = []
    for resource_change in resource_changes:
        if not isinstance(resource_change, Mapping):
            raise AuthorizationError("Terraform resource change is malformed")
        address = resource_change.get("address")
        resource_type = resource_change.get("type")
        resource_name = resource_change.get("name")
        change = resource_change.get("change")
        if (
            not isinstance(address, str)
            or not address
            or len(address.encode("utf-8")) > 4096
            or address in addresses
            or not isinstance(resource_type, str)
            or not TERRAFORM_IDENTIFIER.fullmatch(resource_type)
            or not isinstance(resource_name, str)
            or not TERRAFORM_IDENTIFIER.fullmatch(resource_name)
            or not isinstance(change, Mapping)
            or resource_change.get("previous_address") is not None
            or resource_change.get("deposed") is not None
            or change.get("importing") is not None
        ):
            raise AuthorizationError("Terraform resource change is malformed")
        addresses.add(address)
        actions = change.get("actions")
        if (
            not isinstance(actions, list)
            or not actions
            or not all(isinstance(action, str) for action in actions)
        ):
            raise AuthorizationError("Terraform resource actions are malformed")
        count_field = _TERRAFORM_ACTION_COUNTS.get(tuple(actions))
        if count_field is None:
            raise AuthorizationError("Terraform resource actions are unknown")
        counts[count_field] += 1
        review_action = _REVIEW_ACTIONS[tuple(actions)]
        if review_action != "no-op":
            resource_actions.append(
                {
                    "resource_type": resource_type,
                    "resource_name": resource_name,
                    "action": review_action,
                    "address_digest": canonical_digest({"address": address}),
                }
            )

    if len(resource_actions) > MAX_REVIEWABLE_RESOURCE_CHANGES:
        raise AuthorizationError(
            "Terraform plan exceeds the reviewable resource-change limit"
        )
    resource_actions.sort(key=lambda item: item["address_digest"])

    has_material_change = any(
        counts[field] > 0
        for field in (
            "add_count",
            "change_count",
            "read_count",
            "destroy_count",
            "replace_count",
        )
    ) or any(
        output_counts[field] > 0
        for field in (
            "output_create_count",
            "output_update_count",
            "output_delete_count",
        )
    )
    if plan["applyable"] is not has_material_change:
        raise AuthorizationError("Terraform applyable flag contradicts plan changes")

    classification = classify_plan(
        add=counts["add_count"],
        change=counts["change_count"],
        read=counts["read_count"],
        destroy=counts["destroy_count"],
        replace=counts["replace_count"],
        output_create=output_counts["output_create_count"],
        output_update=output_counts["output_update_count"],
        output_delete=output_counts["output_delete_count"],
    )
    summary: dict[str, Any] = {
        **counts,
        **output_counts,
        "applyable": plan["applyable"],
        "resource_change_count": len(resource_changes),
        "resource_actions": resource_actions,
        "output_change_count": len(output_changes),
        "output_actions": output_actions,
        "classification": classification,
    }
    summary["summary_digest"] = canonical_digest(summary)
    return summary


def _validate_plan_summary(summary: Mapping[str, Any]) -> None:
    if not isinstance(summary, Mapping):
        raise AuthorizationError("saved plan summary is invalid")
    count_values = [summary.get(field) for field in PLAN_SUMMARY_COUNT_FIELDS]
    output_count_values = [
        summary.get(field) for field in PLAN_SUMMARY_OUTPUT_COUNT_FIELDS
    ]
    resource_count = summary.get("resource_change_count")
    output_count = summary.get("output_change_count")
    output_actions = summary.get("output_actions")
    resource_actions = summary.get("resource_actions")
    if (
        any(
            isinstance(value, bool) or not isinstance(value, int) or value < 0
            for value in count_values
        )
        or isinstance(resource_count, bool)
        or not isinstance(resource_count, int)
        or resource_count < 0
        or sum(count_values) != resource_count
        or not isinstance(resource_actions, list)
        or len(resource_actions) != resource_count - summary.get("no_op_count", 0)
        or len(resource_actions) > MAX_REVIEWABLE_RESOURCE_CHANGES
        or any(
            isinstance(value, bool) or not isinstance(value, int) or value < 0
            for value in output_count_values
        )
        or isinstance(output_count, bool)
        or not isinstance(output_count, int)
        or output_count < 0
        or sum(output_count_values) != output_count
        or not isinstance(output_actions, list)
        or len(output_actions)
        != output_count - summary.get("output_no_op_count", 0)
        or len(output_actions) > MAX_REVIEWABLE_OUTPUT_CHANGES
        or not isinstance(summary.get("applyable"), bool)
    ):
        raise AuthorizationError("saved plan summary counts are invalid")
    action_digests: set[str] = set()
    for item in resource_actions:
        if (
            not isinstance(item, Mapping)
            or set(item)
            != {"resource_type", "resource_name", "action", "address_digest"}
            or not isinstance(item.get("resource_type"), str)
            or not TERRAFORM_IDENTIFIER.fullmatch(item["resource_type"])
            or not isinstance(item.get("resource_name"), str)
            or not TERRAFORM_IDENTIFIER.fullmatch(item["resource_name"])
            or item.get("action") not in set(_REVIEW_ACTIONS.values())
            or not isinstance(item.get("address_digest"), str)
            or not DIGEST.fullmatch(item["address_digest"])
            or item["address_digest"] in action_digests
        ):
            raise AuthorizationError("saved plan resource action manifest is invalid")
        action_digests.add(item["address_digest"])
    if resource_actions != sorted(
        resource_actions, key=lambda item: item["address_digest"]
    ):
        raise AuthorizationError("saved plan resource action manifest is not canonical")
    output_names: set[str] = set()
    for item in output_actions:
        if (
            not isinstance(item, Mapping)
            or set(item) != {"output_name", "action"}
            or not isinstance(item.get("output_name"), str)
            or not TERRAFORM_IDENTIFIER.fullmatch(item["output_name"])
            or item.get("action") not in {"create", "update", "delete"}
            or item["output_name"] in output_names
        ):
            raise AuthorizationError("saved plan output action manifest is invalid")
        output_names.add(item["output_name"])
    if output_actions != sorted(output_actions, key=lambda item: item["output_name"]):
        raise AuthorizationError("saved plan output action manifest is not canonical")
    classification = classify_plan(
        add=summary["add_count"],
        change=summary["change_count"],
        read=summary["read_count"],
        destroy=summary["destroy_count"],
        replace=summary["replace_count"],
        output_create=summary["output_create_count"],
        output_update=summary["output_update_count"],
        output_delete=summary["output_delete_count"],
    )
    if summary.get("classification") != classification:
        raise AuthorizationError("saved plan summary classification mismatch")
    if summary["applyable"] is not (classification == "CHANGE"):
        raise AuthorizationError("saved plan summary applyable mismatch")
    expected_digest = canonical_digest(
        {key: value for key, value in summary.items() if key != "summary_digest"}
    )
    if summary.get("summary_digest") != expected_digest:
        raise AuthorizationError("saved plan summary digest mismatch")


def _validated_cost_binding(cost_binding: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(cost_binding, Mapping) or set(cost_binding) != set(
        COST_BINDING_FIELDS
    ):
        raise AuthorizationError("saved plan cost binding is incomplete")
    digest = cost_binding.get("cost_model_digest")
    maximum = cost_binding.get("maximum_cost_usd_micros")
    modeled = cost_binding.get("modeled_cost_upper_bound_usd_micros")
    if (
        not isinstance(digest, str)
        or not digest.startswith("sha256:")
        or len(digest) != 71
        or any(character not in "0123456789abcdef" for character in digest[7:])
        or isinstance(maximum, bool)
        or not isinstance(maximum, int)
        or isinstance(modeled, bool)
        or not isinstance(modeled, int)
        or maximum < 0
        or maximum > 100_000_000
        or modeled < 0
        or modeled > maximum
    ):
        raise AuthorizationError("saved plan cost binding is invalid")
    return {field: cost_binding[field] for field in COST_BINDING_FIELDS}


def validate_saved_plan_cost_binding(
    plan_record: Mapping[str, Any],
    expected_cost_binding: Mapping[str, Any],
) -> None:
    """Require apply to reuse the exact cost guard captured by Plan."""
    expected = _validated_cost_binding(expected_cost_binding)
    actual = plan_record.get("cost_binding")
    if not isinstance(actual, Mapping) or dict(actual) != expected:
        raise AuthorizationError("saved plan cost binding mismatch")


def build_saved_plan_record(
    *,
    bindings: Mapping[str, Any],
    plan_environment_anchor_digest: str,
    plan_sha256: str,
    plan_size_bytes: int,
    bucket: str,
    object_key: str,
    object_version_id: str,
    state_readback: Mapping[str, Any],
    plan_summary: Mapping[str, Any],
    cost_binding: Mapping[str, Any],
    created_at: datetime,
    expires_at: datetime,
) -> dict[str, Any]:
    """Build one immutable, target-bound saved-plan metadata record."""
    missing = [field for field in PLAN_BINDING_FIELDS if field not in bindings]
    if missing:
        raise AuthorizationError("saved plan binding is incomplete")
    if bindings["environment"] not in NONPRODUCTION_ENVIRONMENTS:
        raise AuthorizationError("saved plans are limited to non-production environments")
    if not isinstance(plan_environment_anchor_digest, str) or not DIGEST.fullmatch(
        plan_environment_anchor_digest
    ):
        raise AuthorizationError("saved plan Environment anchor is invalid")
    created = created_at.astimezone(UTC) if created_at.tzinfo else None
    expires = expires_at.astimezone(UTC) if expires_at.tzinfo else None
    if created is None or expires is None or expires <= created:
        raise AuthorizationError("saved plan lifetime is invalid")
    lifetime = (expires - created).total_seconds()
    if not 300 <= lifetime <= 86400:
        raise AuthorizationError("saved plan lifetime must be between five minutes and 24 hours")
    if object_key != _exact_plan_key(bindings):
        raise AuthorizationError("saved plan object key is not derived from trusted bindings")
    if bucket != f"scanalyze-{bindings['account_id']}-tf-plan":
        raise AuthorizationError("saved plan bucket is not the canonical plan bucket")
    _validate_plan_summary(plan_summary)
    validated_cost_binding = _validated_cost_binding(cost_binding)
    expected_state = {
        "status": bindings["state_status"],
        "lineage": bindings["state_lineage"],
        "serial": bindings["state_serial"],
    }
    if any(state_readback.get(field) != value for field, value in expected_state.items()):
        raise AuthorizationError("saved plan state readback binding mismatch")
    state_version_id = state_readback.get("object_version_id")
    state_sha256 = state_readback.get("sha256")
    state_size_bytes = state_readback.get("size_bytes")
    if bindings["state_status"] == "PRESENT":
        if (
            not isinstance(state_version_id, str)
            or not state_version_id
            or not isinstance(state_sha256, str)
            or not DIGEST.fullmatch(state_sha256)
            or isinstance(state_size_bytes, bool)
            or not isinstance(state_size_bytes, int)
            or state_size_bytes < 2
        ):
            raise AuthorizationError("saved plan state fingerprint is invalid")
    elif any(value is not None for value in (state_version_id, state_sha256, state_size_bytes)):
        raise AuthorizationError("absent state must not claim an object fingerprint")

    record: dict[str, Any] = {
        "schema_version": "1",
        "record_type": "saved_plan",
        **{field: bindings[field] for field in PLAN_BINDING_FIELDS},
        "plan_environment_anchor_digest": plan_environment_anchor_digest,
        "state_object_version_id": state_version_id,
        "state_sha256": state_sha256,
        "state_size_bytes": state_size_bytes,
        "plan_sha256": plan_sha256,
        "plan_size_bytes": plan_size_bytes,
        "plan_summary": dict(plan_summary),
        "cost_binding": validated_cost_binding,
        "storage": {
            "bucket": bucket,
            "object_key": object_key,
            "object_version_id": object_version_id,
        },
        "created_at": _timestamp(created_at),
        "expires_at": _timestamp(expires_at),
    }
    record["record_digest"] = canonical_digest(record)
    _validate_schema(record, "saved-plan.v1.schema.json", "saved plan")
    return record


def _validate_approval_record(
    approval: Mapping[str, Any],
    *,
    now: datetime,
) -> None:
    _validate_schema(approval, "saved-plan-approval.v1.schema.json", "saved plan approval")
    _verify_digest(approval, "approval_digest", "saved plan approval")
    if approval.get("workflow_run_attempt") != 1:
        raise AuthorizationError("saved plan approval requires workflow run attempt 1")
    if approval["initiator_user_id"] == approval["approver_user_id"]:
        raise AuthorizationError("saved plan approval requires an independent reviewer")
    if approval["approver_user_id"] != approval["expected_approver_user_id"]:
        raise AuthorizationError("saved plan approval reviewer authority mismatch")
    expected_authority_digest = derive_approval_authority_digest(
        github_environment=approval["github_environment"],
        expected_approver_user_id=approval["expected_approver_user_id"],
        github_deployment_identity_digest=approval[
            "github_deployment_identity_digest"
        ],
        environment_configuration_digest=approval[
            "environment_configuration_digest"
        ],
    )
    if approval["approval_authority_digest"] != expected_authority_digest:
        raise AuthorizationError("saved plan approval authority digest mismatch")
    current = now.astimezone(UTC) if now.tzinfo else None
    if current is None:
        raise AuthorizationError("approval verification time must be timezone-aware")
    window_started = _parse_timestamp(
        approval["approval_window_started_at"],
        "approval_window_started_at",
    )
    observed = _parse_timestamp(
        approval["approval_observed_at"],
        "approval_observed_at",
    )
    expires = _parse_timestamp(approval["expires_at"], "approval expires_at")
    if (
        approval.get("freshness_basis")
        != "WORKFLOW_RUN_CREATED_AT_CONSERVATIVE_BOUND"
        or not window_started <= observed < expires
        or (observed - window_started).total_seconds() > 900
        or (expires - observed).total_seconds() > 300
        or (expires - window_started).total_seconds() > 900
        or current < observed
        or current >= expires
    ):
        raise AuthorizationError("saved plan approval is not currently valid")


def validate_saved_plan_document(document: Mapping[str, Any]) -> None:
    """Validate an untrusted saved-plan document read from durable storage."""
    _validate_schema(document, "saved-plan.v1.schema.json", "saved plan")
    _verify_digest(document, "record_digest", "saved plan")
    _validate_plan_summary(document["plan_summary"])
    _validated_cost_binding(document["cost_binding"])


def build_saved_plan_reviewer_packet(
    plan_record: Mapping[str, Any],
) -> dict[str, Any]:
    """Project one saved plan into a sanitized, reviewable digest packet."""
    validate_saved_plan_document(plan_record)
    state_binding = {
        "status": plan_record["state_status"],
        "lineage": plan_record["state_lineage"],
        "serial": plan_record["state_serial"],
        "object_version_id": plan_record["state_object_version_id"],
        "sha256": plan_record["state_sha256"],
        "size_bytes": plan_record["state_size_bytes"],
    }
    packet: dict[str, Any] = {
        "schema_version": "1",
        "record_type": "saved_plan_reviewer_packet",
        **{field: plan_record[field] for field in LEDGER_BINDING_FIELDS},
        "release_digest": plan_record["release_digest"],
        "source_revision_digest": plan_record["source_revision_digest"],
        "plan_environment_anchor_digest": plan_record[
            "plan_environment_anchor_digest"
        ],
        "expected_approver_user_id": plan_record["expected_approver_user_id"],
        "approval_authority_digest": plan_record["approval_authority_digest"],
        "plan_record_digest": plan_record["record_digest"],
        "plan_sha256": plan_record["plan_sha256"],
        "plan_size_bytes": plan_record["plan_size_bytes"],
        "plan_summary": dict(plan_record["plan_summary"]),
        "cost_binding": dict(plan_record["cost_binding"]),
        "state_status": plan_record["state_status"],
        "state_binding_digest": canonical_digest({"state": state_binding}),
        "created_at": plan_record["created_at"],
        "expires_at": plan_record["expires_at"],
        "production_authorized": False,
    }
    packet["packet_digest"] = canonical_digest(packet)
    _validate_schema(
        packet,
        "saved-plan-reviewer-packet.v1.schema.json",
        "saved plan reviewer packet",
    )
    return packet


def validate_saved_plan_reviewer_packet_document(
    document: Mapping[str, Any],
) -> None:
    """Validate a sanitized reviewer packet before any public projection."""
    _validate_schema(
        document,
        "saved-plan-reviewer-packet.v1.schema.json",
        "saved plan reviewer packet",
    )
    _verify_digest(document, "packet_digest", "saved plan reviewer packet")
    _validate_plan_summary(document["plan_summary"])


def validate_saved_plan_approval_document(
    document: Mapping[str, Any],
    *,
    now: datetime,
) -> None:
    """Validate an untrusted, time-bound approval read from durable storage."""
    _validate_approval_record(document, now=now)


def validate_health_receipt_document(document: Mapping[str, Any]) -> None:
    """Validate an untrusted health receipt read from durable storage."""
    _validate_schema(document, "live-health-receipt.v1.schema.json", "health receipt")
    _verify_digest(document, "receipt_digest", "health receipt")


def validate_execution_ledger_document(document: Mapping[str, Any]) -> None:
    """Validate an untrusted execution ledger read from durable storage."""
    _validate_schema(
        document,
        "live-execution-ledger.v1.schema.json",
        "execution ledger",
    )
    _verify_digest(document, "ledger_digest", "execution ledger")
    publication_digest = document.get("contract_publication_receipt_digest")
    if document.get("status") == "HEALTHY":
        if (
            not isinstance(publication_digest, str)
            or not DIGEST.fullmatch(publication_digest)
            or not isinstance(document.get("outcome_receipt_digest"), str)
            or not DIGEST.fullmatch(document["outcome_receipt_digest"])
        ):
            raise AuthorizationError(
                "healthy ledger lacks exact post-apply evidence"
            )
    elif publication_digest is not None:
        raise AuthorizationError(
            "non-healthy ledger cannot claim contract publication evidence"
        )


def validate_reconciliation_receipt_document(document: Mapping[str, Any]) -> None:
    """Validate an untrusted reconciliation receipt read from durable storage."""
    _validate_schema(
        document,
        "live-reconciliation-receipt.v1.schema.json",
        "reconciliation receipt",
    )
    _verify_digest(document, "receipt_digest", "reconciliation receipt")


def validate_contract_publication_receipt(
    document: Mapping[str, Any],
    *,
    health_receipt: Mapping[str, Any],
) -> None:
    """Require exact producer-contract publication and immutable readback proof."""
    required = {
        "schema_version",
        "record_type",
        "status",
        "health_receipt_digest",
        "contract_digest",
        "readback_contract_digest",
        "publication_receipt_digest",
    }
    if not isinstance(document, Mapping) or set(document) != required:
        raise AuthorizationError("contract publication evidence is incomplete")
    expected_contract_digest = health_receipt.get("expected_contract_digest")
    body = {
        key: value
        for key, value in document.items()
        if key != "publication_receipt_digest"
    }
    if (
        document.get("schema_version") != "1"
        or document.get("record_type") != "live_contract_publication"
        or document.get("status") != "EXACT_READBACK_VERIFIED"
        or document.get("health_receipt_digest")
        != health_receipt.get("receipt_digest")
        or not isinstance(expected_contract_digest, str)
        or not DIGEST.fullmatch(expected_contract_digest)
        or document.get("contract_digest") != expected_contract_digest
        or document.get("readback_contract_digest") != expected_contract_digest
        or document.get("publication_receipt_digest") != canonical_digest(body)
    ):
        raise AuthorizationError("contract publication readback is not exact")


def _validate_plan_approval_binding(
    plan_record: Mapping[str, Any],
    approval: Mapping[str, Any],
) -> None:
    for field in LEDGER_BINDING_FIELDS:
        if approval.get(field) != plan_record.get(field):
            raise AuthorizationError(f"saved plan approval binding mismatch: {field}")
    if approval.get("plan_record_digest") != plan_record["record_digest"]:
        raise AuthorizationError("saved plan approval plan binding mismatch")
    reviewer_packet = build_saved_plan_reviewer_packet(plan_record)
    if approval.get("reviewer_packet_digest") != reviewer_packet["packet_digest"]:
        raise AuthorizationError("saved plan approval reviewer packet binding mismatch")
    if approval.get("github_environment") != plan_record["github_environment"]:
        raise AuthorizationError("saved plan approval Environment binding mismatch")
    if approval.get("environment_configuration_digest") != plan_record[
        "environment_configuration_digest"
    ]:
        raise AuthorizationError("saved plan approval configuration binding mismatch")
    if approval.get("github_deployment_identity_digest") != plan_record[
        "github_deployment_identity_digest"
    ]:
        raise AuthorizationError("saved plan approval identity binding mismatch")
    if approval.get("approval_authority_digest") != plan_record[
        "approval_authority_digest"
    ]:
        raise AuthorizationError("saved plan approval authority binding mismatch")
    if approval.get("expected_approver_user_id") != plan_record[
        "expected_approver_user_id"
    ]:
        raise AuthorizationError("saved plan approval reviewer binding mismatch")
    if approval.get("workflow_run_attempt") != 1:
        raise AuthorizationError("saved plan approval run attempt binding mismatch")
    window_started = _parse_timestamp(
        approval["approval_window_started_at"],
        "approval_window_started_at",
    )
    observed = _parse_timestamp(
        approval["approval_observed_at"],
        "approval_observed_at",
    )
    approval_expires = _parse_timestamp(approval["expires_at"], "approval expires_at")
    plan_created = _parse_timestamp(plan_record["created_at"], "created_at")
    plan_expires = _parse_timestamp(plan_record["expires_at"], "expires_at")
    if not plan_created <= window_started <= observed < approval_expires <= plan_expires:
        raise AuthorizationError("saved plan approval lifetime exceeds the plan lifetime")


def build_saved_plan_approval(
    *,
    plan_record: Mapping[str, Any],
    repository_owner_id: int,
    repository_id: int,
    workflow_ref: str,
    workflow_sha: str,
    workflow_run_id: int,
    workflow_run_attempt: int,
    github_environment: str,
    environment_configuration_digest: str,
    apply_environment_anchor_digest: str,
    initiator_user_id: int,
    expected_approver_user_id: int,
    approver_user_id: int,
    reviewer_packet_digest: str,
    approval_evidence_digest: str,
    approval_window_started_at: datetime,
    approval_observed_at: datetime,
    freshness_basis: str,
    expires_at: datetime,
) -> dict[str, Any]:
    """Build one plan-bound observation interval from GitHub API evidence."""
    _validate_schema(plan_record, "saved-plan.v1.schema.json", "saved plan")
    _verify_digest(plan_record, "record_digest", "saved plan")
    window_started = (
        approval_window_started_at.astimezone(UTC)
        if approval_window_started_at.tzinfo
        else None
    )
    observed = (
        approval_observed_at.astimezone(UTC)
        if approval_observed_at.tzinfo
        else None
    )
    expires = expires_at.astimezone(UTC) if expires_at.tzinfo else None
    plan_created = _parse_timestamp(plan_record["created_at"], "created_at")
    plan_expires = _parse_timestamp(plan_record["expires_at"], "expires_at")
    if window_started is None or observed is None or expires is None:
        raise AuthorizationError("saved plan approval timestamps must be timezone-aware")
    if (
        freshness_basis != "WORKFLOW_RUN_CREATED_AT_CONSERVATIVE_BOUND"
        or not isinstance(approval_evidence_digest, str)
        or not approval_evidence_digest.startswith("sha256:")
        or not plan_created <= window_started <= observed < expires <= plan_expires
        or (observed - window_started).total_seconds() > 900
        or (expires - observed).total_seconds() > 300
        or (expires - window_started).total_seconds() > 900
    ):
        raise AuthorizationError("saved plan approval lifetime exceeds the plan lifetime")
    if initiator_user_id == approver_user_id:
        raise AuthorizationError("saved plan approval requires an independent reviewer")
    if approver_user_id != expected_approver_user_id:
        raise AuthorizationError("saved plan approval reviewer authority mismatch")
    if workflow_run_attempt != 1:
        raise AuthorizationError("saved plan approval requires workflow run attempt 1")
    if github_environment != plan_record["github_environment"]:
        raise AuthorizationError("saved plan approval Environment binding mismatch")
    if environment_configuration_digest != plan_record["environment_configuration_digest"]:
        raise AuthorizationError("saved plan approval configuration binding mismatch")
    if not isinstance(apply_environment_anchor_digest, str) or not DIGEST.fullmatch(
        apply_environment_anchor_digest
    ):
        raise AuthorizationError("saved plan approval Environment anchor is invalid")
    authority_digest = derive_approval_authority_digest(
        github_environment=github_environment,
        expected_approver_user_id=expected_approver_user_id,
        github_deployment_identity_digest=plan_record[
            "github_deployment_identity_digest"
        ],
        environment_configuration_digest=environment_configuration_digest,
    )
    if authority_digest != plan_record["approval_authority_digest"]:
        raise AuthorizationError("saved plan approval authority binding mismatch")
    expected_packet_digest = build_saved_plan_reviewer_packet(plan_record)[
        "packet_digest"
    ]
    if reviewer_packet_digest != expected_packet_digest:
        raise AuthorizationError("saved plan approval reviewer packet binding mismatch")
    approval: dict[str, Any] = {
        "schema_version": "1",
        "record_type": "saved_plan_approval",
        **{field: plan_record[field] for field in LEDGER_BINDING_FIELDS},
        "plan_record_digest": plan_record["record_digest"],
        "repository_owner_id": repository_owner_id,
        "repository_id": repository_id,
        "workflow_ref": workflow_ref,
        "workflow_sha": workflow_sha,
        "workflow_run_id": workflow_run_id,
        "workflow_run_attempt": workflow_run_attempt,
        "github_environment": github_environment,
        "github_deployment_identity_digest": plan_record[
            "github_deployment_identity_digest"
        ],
        "environment_configuration_digest": environment_configuration_digest,
        "apply_environment_anchor_digest": apply_environment_anchor_digest,
        "approval_authority_digest": authority_digest,
        "initiator_user_id": initiator_user_id,
        "expected_approver_user_id": expected_approver_user_id,
        "approver_user_id": approver_user_id,
        "decision": "APPROVED",
        "reviewer_packet_digest": reviewer_packet_digest,
        "approval_evidence_digest": approval_evidence_digest,
        "approval_window_started_at": _timestamp(approval_window_started_at),
        "approval_observed_at": _timestamp(approval_observed_at),
        "freshness_basis": freshness_basis,
        "expires_at": _timestamp(expires_at),
    }
    approval["approval_digest"] = canonical_digest(approval)
    _validate_schema(approval, "saved-plan-approval.v1.schema.json", "saved plan approval")
    return approval


def build_initial_ledger(*, plan_record: Mapping[str, Any], at: datetime) -> dict[str, Any]:
    """Build the create-only ledger item for a newly stored plan."""
    _validate_schema(plan_record, "saved-plan.v1.schema.json", "saved plan")
    _verify_digest(plan_record, "record_digest", "saved plan")
    ledger: dict[str, Any] = {
        "schema_version": "1",
        "record_type": "live_execution_layer",
        **{field: plan_record[field] for field in LEDGER_BINDING_FIELDS},
        "status": "PLANNED",
        "ledger_version": 1,
        "plan_record_digest": plan_record["record_digest"],
        "plan_environment_anchor_digest": plan_record[
            "plan_environment_anchor_digest"
        ],
        "expected_approver_user_id": plan_record["expected_approver_user_id"],
        "approval_authority_digest": plan_record["approval_authority_digest"],
        "updated_at": _timestamp(at),
        "attempt_count": 0,
    }
    ledger["ledger_digest"] = canonical_digest(ledger)
    _validate_schema(ledger, "live-execution-ledger.v1.schema.json", "execution ledger")
    return ledger


def authorize_saved_plan_apply(
    *,
    plan_record: Mapping[str, Any],
    ledger: Mapping[str, Any],
    approval_record: Mapping[str, Any],
    expected_bindings: Mapping[str, Any],
    plan_readback: Mapping[str, Any],
    state_readback: Mapping[str, Any],
    now: datetime,
) -> dict[str, Any]:
    """Authorize one exact plan apply or raise a sanitized denial."""
    _validate_schema(plan_record, "saved-plan.v1.schema.json", "saved plan")
    _verify_digest(plan_record, "record_digest", "saved plan")
    _validate_schema(ledger, "live-execution-ledger.v1.schema.json", "execution ledger")
    _verify_digest(ledger, "ledger_digest", "execution ledger")

    current = now.astimezone(UTC) if now.tzinfo else None
    if current is None:
        raise AuthorizationError("authorization time must be timezone-aware")
    created = _parse_timestamp(plan_record["created_at"], "created_at")
    expires = _parse_timestamp(plan_record["expires_at"], "expires_at")
    if current < created:
        raise AuthorizationError("saved plan was created in the future")
    if current >= expires:
        raise AuthorizationError("saved plan is expired")
    _validate_approval_record(approval_record, now=now)

    for field in PLAN_BINDING_FIELDS:
        if expected_bindings.get(field) != plan_record.get(field):
            raise AuthorizationError(f"saved plan binding mismatch: {field}")
    for field in LEDGER_BINDING_FIELDS:
        if ledger.get(field) != plan_record.get(field):
            raise AuthorizationError(f"execution ledger binding mismatch: {field}")
    if ledger.get("plan_record_digest") != plan_record["record_digest"]:
        raise AuthorizationError("execution ledger plan binding mismatch")
    if ledger.get("approval_authority_digest") != plan_record[
        "approval_authority_digest"
    ]:
        raise AuthorizationError("execution ledger approval authority mismatch")
    if ledger.get("plan_environment_anchor_digest") != plan_record[
        "plan_environment_anchor_digest"
    ] or ledger.get("expected_approver_user_id") != plan_record[
        "expected_approver_user_id"
    ]:
        raise AuthorizationError("execution ledger Plan reviewer anchor mismatch")
    _validate_plan_approval_binding(plan_record, approval_record)
    if ledger.get("approval_digest") != approval_record["approval_digest"]:
        raise AuthorizationError("execution ledger approval binding mismatch")
    if ledger.get("status") != "APPROVED" or ledger.get("attempt_count") != 0:
        raise AuthorizationError("saved plan ledger must be APPROVED and unused")

    expected_readback = {
        "bucket": plan_record["storage"]["bucket"],
        "object_key": plan_record["storage"]["object_key"],
        "object_version_id": plan_record["storage"]["object_version_id"],
        "sha256": plan_record["plan_sha256"],
        "size_bytes": plan_record["plan_size_bytes"],
    }
    if dict(plan_readback) != expected_readback:
        raise AuthorizationError("saved plan readback does not match immutable metadata")
    if dict(state_readback) != {
        "status": plan_record["state_status"],
        "lineage": plan_record["state_lineage"],
        "serial": plan_record["state_serial"],
        "object_version_id": plan_record["state_object_version_id"],
        "sha256": plan_record["state_sha256"],
        "size_bytes": plan_record["state_size_bytes"],
    }:
        raise AuthorizationError("Terraform state changed after the saved plan was created")

    return {
        "allowed": True,
        "code": "EXACT_SAVED_PLAN_AUTHORIZED",
        "plan_record_digest": plan_record["record_digest"],
    }


def _validate_approval_ledger_binding(
    *,
    current: Mapping[str, Any],
    approval_record: Mapping[str, Any],
    at: datetime,
) -> None:
    """Validate one fresh approval against the immutable ledger authority."""
    _validate_approval_record(approval_record, now=at)
    for field in LEDGER_BINDING_FIELDS:
        if approval_record.get(field) != current.get(field):
            raise AuthorizationError(f"saved plan approval binding mismatch: {field}")
    if approval_record.get("plan_record_digest") != current["plan_record_digest"]:
        raise AuthorizationError("saved plan approval plan binding mismatch")
    if approval_record.get("approval_authority_digest") != current[
        "approval_authority_digest"
    ]:
        raise AuthorizationError("saved plan approval authority binding mismatch")
    if approval_record.get("expected_approver_user_id") != current[
        "expected_approver_user_id"
    ]:
        raise AuthorizationError("saved plan approval reviewer mismatch")


def prepare_pre_apply_reapproval(
    *,
    current: Mapping[str, Any],
    approval_record: Mapping[str, Any],
    expected_version: int,
    expected_digest: str,
    at: datetime,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """CAS-select fresh approval evidence without consuming an apply attempt.

    This is deliberately not a general ``APPROVED -> APPROVED`` transition.
    It only recovers a cancelled pre-apply run while the exact saved plan is
    still unused.  The append-only approval record is not authority until this
    CAS stores its digest in the ledger.
    """
    validate_execution_ledger_document(current)
    if current["ledger_version"] != expected_version:
        raise AuthorizationError("execution ledger version conflict")
    if current["ledger_digest"] != expected_digest:
        raise AuthorizationError("execution ledger digest conflict")
    if current.get("status") != "APPROVED" or current.get("attempt_count") != 0:
        raise AuthorizationError(
            "saved plan reapproval requires an APPROVED unused ledger"
        )
    _validate_approval_ledger_binding(
        current=current,
        approval_record=approval_record,
        at=at,
    )
    if current.get("approval_digest") == approval_record["approval_digest"]:
        raise AuthorizationError("saved plan reapproval must select new evidence")

    proposed = copy.deepcopy(dict(current))
    proposed["ledger_version"] += 1
    proposed["updated_at"] = _timestamp(at)
    proposed["approval_digest"] = approval_record["approval_digest"]
    proposed["ledger_digest"] = canonical_digest(
        {key: value for key, value in proposed.items() if key != "ledger_digest"}
    )
    validate_execution_ledger_document(proposed)
    condition = {
        "condition_expression": (
            "ledger_version = :expected_version AND ledger_digest = :expected_digest "
            "AND #status = :expected_status"
        ),
        "expression_attribute_names": {"#status": "status"},
        "expression_attribute_values": {
            ":expected_version": expected_version,
            ":expected_digest": expected_digest,
            ":expected_status": "APPROVED",
        },
    }
    return proposed, condition


def prepare_ledger_transition(
    *,
    current: Mapping[str, Any],
    next_status: str,
    expected_version: int,
    expected_digest: str,
    at: datetime,
    outcome_code: str | None = None,
    approval_record: Mapping[str, Any] | None = None,
    health_receipt: Mapping[str, Any] | None = None,
    contract_publication_receipt: Mapping[str, Any] | None = None,
    reconciliation_receipt: Mapping[str, Any] | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Prepare one compare-and-swap ledger transition for a storage adapter."""
    validate_execution_ledger_document(current)
    if current["ledger_version"] != expected_version:
        raise AuthorizationError("execution ledger version conflict")
    if current["ledger_digest"] != expected_digest:
        raise AuthorizationError("execution ledger digest conflict")
    old_status = current["status"]
    if next_status not in ALLOWED_LEDGER_TRANSITIONS.get(old_status, frozenset()):
        raise AuthorizationError(f"execution ledger transition is forbidden: {old_status}->{next_status}")

    evidence_digest: str | None = None
    if next_status == "APPROVED":
        if approval_record is None:
            raise AuthorizationError("saved plan approval evidence is required")
        _validate_approval_ledger_binding(
            current=current,
            approval_record=approval_record,
            at=at,
        )
    if next_status == "HEALTHY":
        if health_receipt is None:
            raise AuthorizationError("health receipt is required for a healthy transition")
        _validate_schema(health_receipt, "live-health-receipt.v1.schema.json", "health receipt")
        _verify_digest(health_receipt, "receipt_digest", "health receipt")
        for field in LEDGER_BINDING_FIELDS:
            if health_receipt.get(field) != current.get(field):
                raise AuthorizationError(f"health receipt binding mismatch: {field}")
        if health_receipt.get("status") != "PASSED":
            raise AuthorizationError("health receipt did not pass")
        if health_receipt.get("plan_record_digest") != current["plan_record_digest"]:
            raise AuthorizationError("health receipt plan binding mismatch")
        if health_receipt.get("source_ledger_digest") != current["ledger_digest"]:
            raise AuthorizationError("health receipt ledger binding mismatch")
        if health_receipt.get("source_ledger_version") != current["ledger_version"]:
            raise AuthorizationError("health receipt ledger version mismatch")
        if contract_publication_receipt is None:
            raise AuthorizationError(
                "contract publication evidence is required for a healthy transition"
            )
        validate_contract_publication_receipt(
            contract_publication_receipt,
            health_receipt=health_receipt,
        )
        evidence_digest = health_receipt["receipt_digest"]
    if next_status in {"RECONCILED_APPLIED", "RECONCILIATION_REQUIRED"}:
        if reconciliation_receipt is None:
            raise AuthorizationError("reconciliation receipt is required")
        _validate_schema(
            reconciliation_receipt,
            "live-reconciliation-receipt.v1.schema.json",
            "reconciliation receipt",
        )
        _verify_digest(reconciliation_receipt, "receipt_digest", "reconciliation receipt")
        for field in LEDGER_BINDING_FIELDS:
            if reconciliation_receipt.get(field) != current.get(field):
                raise AuthorizationError(f"reconciliation receipt binding mismatch: {field}")
        if reconciliation_receipt.get("decision") != next_status:
            raise AuthorizationError("reconciliation receipt decision mismatch")
        if reconciliation_receipt.get("plan_record_digest") != current["plan_record_digest"]:
            raise AuthorizationError("reconciliation receipt plan binding mismatch")
        if reconciliation_receipt.get("source_ledger_digest") != current["ledger_digest"]:
            raise AuthorizationError("reconciliation receipt ledger binding mismatch")
        if reconciliation_receipt.get("source_ledger_version") != current["ledger_version"]:
            raise AuthorizationError("reconciliation receipt ledger version mismatch")
        evidence_digest = reconciliation_receipt["receipt_digest"]

    proposed = copy.deepcopy(dict(current))
    proposed["status"] = next_status
    proposed["ledger_version"] += 1
    proposed["updated_at"] = _timestamp(at)
    proposed.pop("outcome_code", None)
    proposed.pop("outcome_receipt_digest", None)
    if next_status == "APPROVED" and approval_record is not None:
        proposed["approval_digest"] = approval_record["approval_digest"]
    if next_status == "APPLYING":
        if proposed["attempt_count"] != 0:
            raise AuthorizationError("saved plan apply attempt is already consumed")
        proposed["attempt_count"] = 1
    if outcome_code is not None:
        proposed["outcome_code"] = outcome_code
    if evidence_digest is not None:
        proposed["outcome_receipt_digest"] = evidence_digest
    if next_status == "HEALTHY" and contract_publication_receipt is not None:
        proposed["contract_publication_receipt_digest"] = (
            contract_publication_receipt["publication_receipt_digest"]
        )
    proposed["ledger_digest"] = canonical_digest(
        {key: value for key, value in proposed.items() if key != "ledger_digest"}
    )
    validate_execution_ledger_document(proposed)
    condition = {
        "condition_expression": (
            "ledger_version = :expected_version AND ledger_digest = :expected_digest "
            "AND #status = :expected_status"
        ),
        "expression_attribute_names": {"#status": "status"},
        "expression_attribute_values": {
            ":expected_version": expected_version,
            ":expected_digest": expected_digest,
            ":expected_status": old_status,
        },
    }
    return proposed, condition


def recover_stale_applying(
    *,
    current: Mapping[str, Any],
    now: datetime,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Consume no new attempt while moving an expired runner lease to UNCERTAIN."""
    _validate_schema(current, "live-execution-ledger.v1.schema.json", "execution ledger")
    _verify_digest(current, "ledger_digest", "execution ledger")
    current_time = now.astimezone(UTC) if now.tzinfo else None
    if current_time is None:
        raise AuthorizationError("stale apply recovery time must be timezone-aware")
    updated_at = _parse_timestamp(current["updated_at"], "updated_at")
    age_seconds = (current_time - updated_at).total_seconds()
    if (
        current.get("status") != "APPLYING"
        or current.get("attempt_count") != 1
        or age_seconds < STALE_APPLYING_MIN_AGE_SECONDS
    ):
        raise AuthorizationError("APPLYING execution is not safely stale")
    return prepare_ledger_transition(
        current=current,
        next_status="UNCERTAIN",
        expected_version=current["ledger_version"],
        expected_digest=current["ledger_digest"],
        at=current_time,
        outcome_code="RUNNER_LOST_AFTER_ATTEMPT",
    )


def _observed_present_state(
    state_readback: Mapping[str, Any],
) -> tuple[str, int]:
    lineage = state_readback.get("lineage")
    serial = state_readback.get("serial")
    if (
        state_readback.get("status") != "PRESENT"
        or not isinstance(lineage, str)
        or re.fullmatch(r"^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$", lineage) is None
        or isinstance(serial, bool)
        or not isinstance(serial, int)
        or serial < 0
    ):
        raise AuthorizationError("observed Terraform state is not a real present state")
    return lineage, serial


def _observed_present_state_fingerprint(
    state_readback: Mapping[str, Any],
) -> dict[str, Any]:
    """Validate one immutable, versioned post-apply state observation."""
    if set(state_readback) != {
        "status",
        "lineage",
        "serial",
        "object_version_id",
        "sha256",
        "size_bytes",
    }:
        raise AuthorizationError("observed Terraform state fingerprint is not exact")
    lineage, serial = _observed_present_state(state_readback)
    version_id = state_readback.get("object_version_id")
    state_sha256 = state_readback.get("sha256")
    size_bytes = state_readback.get("size_bytes")
    if (
        not isinstance(version_id, str)
        or not version_id
        or version_id == "null"
        or not isinstance(state_sha256, str)
        or not DIGEST.fullmatch(state_sha256)
        or isinstance(size_bytes, bool)
        or not isinstance(size_bytes, int)
        or size_bytes < 2
    ):
        raise AuthorizationError(
            "observed Terraform state lacks an immutable fingerprint"
        )
    return {
        "status": "PRESENT",
        "lineage": lineage,
        "serial": serial,
        "object_version_id": version_id,
        "sha256": state_sha256,
        "size_bytes": size_bytes,
    }


def _validated_state_bracket(
    *,
    state_before: Mapping[str, Any],
    state_after: Mapping[str, Any],
) -> dict[str, Any]:
    before = _observed_present_state_fingerprint(state_before)
    after = _observed_present_state_fingerprint(state_after)
    if before != after:
        raise AuthorizationError(
            "Terraform state changed during post-apply verification"
        )
    return before


def _speculative_plan_evidence(
    *,
    result: str,
    plan_summary: Mapping[str, Any] | None,
) -> str:
    if result not in {"NO_CHANGE", "CHANGE", "ERROR"}:
        raise AuthorizationError("speculative plan result is invalid")
    if result == "ERROR" and plan_summary is None:
        return canonical_digest(
            {
                "schema_version": "1",
                "record_type": "speculative_plan_summary",
                "result": result,
            }
        )
    if result == "ERROR":
        raise AuthorizationError(
            "failed speculative plan must not claim a structural summary"
        )
    if not isinstance(plan_summary, Mapping):
        raise AuthorizationError("speculative plan structural summary is required")
    _validate_plan_summary(plan_summary)
    if plan_summary.get("classification") != result:
        raise AuthorizationError(
            "speculative plan result contradicts its structural summary"
        )
    return str(plan_summary["summary_digest"])


def build_health_receipt(
    *,
    plan_record: Mapping[str, Any],
    ledger: Mapping[str, Any],
    state_readback: Mapping[str, Any] | None = None,
    state_before: Mapping[str, Any] | None = None,
    state_after: Mapping[str, Any] | None = None,
    speculative_plan_summary: Mapping[str, Any] | None = None,
    outputs_digest: str | None = None,
    output_count: int = 0,
    expected_contract_digest: str | None = None,
    checked_at: datetime,
    checks: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    """Build a sanitized health gate receipt bound to the exact execution."""
    _validate_schema(plan_record, "saved-plan.v1.schema.json", "saved plan")
    _verify_digest(plan_record, "record_digest", "saved plan")
    _validate_schema(ledger, "live-execution-ledger.v1.schema.json", "execution ledger")
    _verify_digest(ledger, "ledger_digest", "execution ledger")
    if ledger.get("status") not in {"APPLIED", "RECONCILED_APPLIED"}:
        raise AuthorizationError("health receipt requires an applied execution")
    for field in LEDGER_BINDING_FIELDS:
        if ledger.get(field) != plan_record.get(field):
            raise AuthorizationError(f"health receipt binding mismatch: {field}")
    if ledger.get("plan_record_digest") != plan_record["record_digest"]:
        raise AuthorizationError("health receipt plan binding mismatch")
    if state_readback is not None:
        if state_before is not None:
            raise AuthorizationError("health receipt state bracket is ambiguous")
        state_before = state_readback
    if state_before is None or state_after is None:
        raise AuthorizationError(
            "health receipt requires independent before and after state reads"
        )
    state = _validated_state_bracket(
        state_before=state_before,
        state_after=state_after,
    )
    state_lineage = state["lineage"]
    state_serial = state["serial"]
    if plan_record["state_status"] == "PRESENT":
        if state_lineage != plan_record["state_lineage"]:
            raise AuthorizationError("health receipt state lineage mismatch")
        classification = plan_record["plan_summary"]["classification"]
        if classification == "CHANGE" and state_serial <= plan_record["state_serial"]:
            raise AuthorizationError("health receipt requires state advancement")
        if classification == "NO_CHANGE" and state_serial != plan_record["state_serial"]:
            raise AuthorizationError("no-change health receipt state serial drifted")
    speculative_summary_digest = _speculative_plan_evidence(
        result="NO_CHANGE",
        plan_summary=speculative_plan_summary,
    )
    if (
        not isinstance(outputs_digest, str)
        or not DIGEST.fullmatch(outputs_digest)
        or isinstance(output_count, bool)
        or not isinstance(output_count, int)
        or output_count < 0
        or output_count > 128
        or not isinstance(expected_contract_digest, str)
        or not DIGEST.fullmatch(expected_contract_digest)
    ):
        raise AuthorizationError(
            "verified Terraform output or contract evidence is invalid"
        )
    if (
        not checks
        or any(not isinstance(check, Mapping) for check in checks)
        or len({check.get("name") for check in checks}) != len(checks)
    ):
        raise AuthorizationError("health checks must be non-empty and uniquely named")
    receipt: dict[str, Any] = {
        "schema_version": "1",
        "record_type": "live_health_receipt",
        **{field: plan_record[field] for field in LEDGER_BINDING_FIELDS},
        "plan_record_digest": plan_record["record_digest"],
        "source_ledger_digest": ledger["ledger_digest"],
        "source_ledger_version": ledger["ledger_version"],
        "release_digest": plan_record["release_digest"],
        "contract_resolution_digest": plan_record["contract_resolution_digest"],
        "state_lineage": state_lineage,
        "state_serial": state_serial,
        "state_object_version_id": state["object_version_id"],
        "state_sha256": state["sha256"],
        "state_size_bytes": state["size_bytes"],
        "state_bracket_digest": canonical_digest(
            {"state_before": state, "state_after": state}
        ),
        "speculative_plan_result": "NO_CHANGE",
        "speculative_plan_summary_digest": speculative_summary_digest,
        "outputs_digest": outputs_digest,
        "output_count": output_count,
        "expected_contract_digest": expected_contract_digest,
        "cloud_writes": False,
        "checked_at": _timestamp(checked_at),
        "status": "PASSED" if all(check.get("passed") is True for check in checks) else "FAILED",
        "checks": [dict(check) for check in checks],
    }
    receipt["receipt_digest"] = canonical_digest(receipt)
    _validate_schema(receipt, "live-health-receipt.v1.schema.json", "health receipt")
    return receipt


def build_reconciliation_receipt(
    *,
    plan_record: Mapping[str, Any],
    ledger: Mapping[str, Any],
    observed_state: Mapping[str, Any] | None = None,
    state_before: Mapping[str, Any] | None = None,
    state_after: Mapping[str, Any] | None = None,
    speculative_plan_result: str,
    speculative_plan_summary: Mapping[str, Any] | None = None,
    contract_verified: bool,
    checked_at: datetime,
) -> dict[str, Any]:
    """Classify an uncertain apply using read-only state, plan, and contract proof.

    A successful reconciliation is intentionally narrow: the state lineage is
    unchanged, its serial advanced, a fresh speculative plan is no-change, and
    the exact producer contract is readable and verified. Every other result
    requires a new reviewed forward-recovery plan.
    """
    _validate_schema(plan_record, "saved-plan.v1.schema.json", "saved plan")
    _verify_digest(plan_record, "record_digest", "saved plan")
    _validate_schema(ledger, "live-execution-ledger.v1.schema.json", "execution ledger")
    _verify_digest(ledger, "ledger_digest", "execution ledger")
    if ledger.get("status") != "UNCERTAIN":
        raise AuthorizationError("reconciliation requires an UNCERTAIN execution")
    for field in LEDGER_BINDING_FIELDS:
        if ledger.get(field) != plan_record.get(field):
            raise AuthorizationError(f"reconciliation binding mismatch: {field}")
    if ledger.get("plan_record_digest") != plan_record.get("record_digest"):
        raise AuthorizationError("reconciliation plan binding mismatch")
    if observed_state is not None:
        if state_before is not None:
            raise AuthorizationError("reconciliation state bracket is ambiguous")
        state_before = observed_state
    if state_before is None or state_after is None:
        raise AuthorizationError(
            "reconciliation requires independent before and after state reads"
        )
    state = _validated_state_bracket(
        state_before=state_before,
        state_after=state_after,
    )
    lineage = state["lineage"]
    serial = state["serial"]
    speculative_summary_digest = _speculative_plan_evidence(
        result=speculative_plan_result,
        plan_summary=speculative_plan_summary,
    )
    if plan_record["state_status"] == "PRESENT":
        lineage_matches = lineage == plan_record["state_lineage"]
        serial_advanced = serial > plan_record["state_serial"]
    else:
        lineage_matches = True
        serial_advanced = True
    reconciled = (
        lineage_matches
        and serial_advanced
        and speculative_plan_result == "NO_CHANGE"
        and contract_verified is True
    )
    receipt: dict[str, Any] = {
        "schema_version": "1",
        "record_type": "live_reconciliation_receipt",
        **{field: ledger[field] for field in LEDGER_BINDING_FIELDS},
        "plan_record_digest": plan_record["record_digest"],
        "source_ledger_digest": ledger["ledger_digest"],
        "source_ledger_version": ledger["ledger_version"],
        "observed_state_lineage_matches": lineage_matches,
        "observed_state_serial": serial,
        "state_object_version_id": state["object_version_id"],
        "state_sha256": state["sha256"],
        "state_size_bytes": state["size_bytes"],
        "state_bracket_digest": canonical_digest(
            {"state_before": state, "state_after": state}
        ),
        "speculative_plan_result": speculative_plan_result,
        "speculative_plan_summary_digest": speculative_summary_digest,
        "contract_verified": contract_verified,
        "decision": "RECONCILED_APPLIED" if reconciled else "RECONCILIATION_REQUIRED",
        "cloud_writes": False,
        "checked_at": _timestamp(checked_at),
    }
    receipt["receipt_digest"] = canonical_digest(receipt)
    _validate_schema(
        receipt,
        "live-reconciliation-receipt.v1.schema.json",
        "reconciliation receipt",
    )
    return receipt


def require_downstream_health(
    ledger: Mapping[str, Any],
    *,
    plan_record: Mapping[str, Any],
    expected_layer: str,
    health_receipt: Mapping[str, Any] | None = None,
) -> None:
    """Require an exact successful predecessor before a downstream stage."""
    _validate_schema(ledger, "live-execution-ledger.v1.schema.json", "execution ledger")
    _verify_digest(ledger, "ledger_digest", "execution ledger")
    _validate_schema(plan_record, "saved-plan.v1.schema.json", "saved plan")
    _verify_digest(plan_record, "record_digest", "saved plan")
    if ledger.get("status") != "HEALTHY":
        raise AuthorizationError("downstream execution requires a healthy predecessor")
    if ledger.get("layer") != expected_layer:
        raise AuthorizationError("downstream health predecessor layer mismatch")
    if health_receipt is None:
        raise AuthorizationError("downstream execution requires a health receipt")
    _validate_schema(health_receipt, "live-health-receipt.v1.schema.json", "health receipt")
    _verify_digest(health_receipt, "receipt_digest", "health receipt")
    if ledger.get("plan_record_digest") != plan_record["record_digest"]:
        raise AuthorizationError("downstream plan binding mismatch")
    if ledger.get("outcome_receipt_digest") != health_receipt["receipt_digest"]:
        raise AuthorizationError("downstream health evidence binding mismatch")
    for field in LEDGER_BINDING_FIELDS:
        if health_receipt.get(field) != ledger.get(field) or plan_record.get(field) != ledger.get(field):
            raise AuthorizationError(f"health receipt binding mismatch: {field}")
    if health_receipt.get("plan_record_digest") != plan_record["record_digest"]:
        raise AuthorizationError("health receipt plan binding mismatch")
    if health_receipt.get("source_ledger_version") != ledger["ledger_version"] - 1:
        raise AuthorizationError("health receipt ledger version mismatch")
    if (
        not isinstance(ledger.get("contract_publication_receipt_digest"), str)
        or not DIGEST.fullmatch(ledger["contract_publication_receipt_digest"])
    ):
        raise AuthorizationError(
            "downstream execution requires contract publication evidence"
        )
    if health_receipt.get("status") != "PASSED":
        raise AuthorizationError("downstream execution requires a passed health receipt")


def validate_dry_run_boundary(
    *,
    dry_run: bool,
    allow_live: bool,
    environment: Mapping[str, str] | None = None,
) -> None:
    """Prove dry-run has no ambient AWS credential surface."""
    if dry_run == allow_live:
        raise AuthorizationError("exactly one of dry_run or allow_live must be true")
    if not dry_run:
        return
    values = environment if environment is not None else os.environ
    if any(values.get(name) for name in CREDENTIAL_ENVIRONMENT_NAMES):
        raise AuthorizationError("AWS credential material is forbidden in dry-run mode")


def classify_plan(
    *,
    add: int,
    change: int,
    destroy: int,
    replace: int,
    read: int = 0,
    output_create: int = 0,
    output_update: int = 0,
    output_delete: int = 0,
) -> str:
    """Classify a sanitized Terraform plan summary without accepting destruction."""
    counts = (
        add,
        change,
        destroy,
        replace,
        read,
        output_create,
        output_update,
        output_delete,
    )
    if any(not isinstance(value, int) or value < 0 for value in counts):
        raise AuthorizationError("plan counts must be non-negative integers")
    if destroy or replace:
        raise AuthorizationError("destructive plan requires a separate reviewed recovery path")
    return (
        "NO_CHANGE"
        if not any((add, change, read, output_create, output_update, output_delete))
        else "CHANGE"
    )
