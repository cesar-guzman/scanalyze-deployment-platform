"""Pure fail-closed authorization core for the GUG-125 non-production engine.

The module deliberately performs no AWS, Terraform, GitHub, or filesystem I/O.
Live adapters must read authoritative records, pass them through these checks,
and use the returned compare-and-swap conditions without weakening them.
"""
from __future__ import annotations

import copy
import os
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
        "AWS_WEB_IDENTITY_TOKEN_FILE",
        "AWS_ROLE_ARN",
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
    "platform_authority_digest",
    "registry_record_digest",
    "account_ready_digest",
    "execution_lock_digest",
    "backend_binding_digest",
    "contract_resolution_digest",
    "toolchain_digest",
    "root_module_digest",
    "source_revision_digest",
    "state_lineage",
    "state_serial",
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


def build_saved_plan_record(
    *,
    bindings: Mapping[str, Any],
    plan_sha256: str,
    plan_size_bytes: int,
    bucket: str,
    object_key: str,
    object_version_id: str,
    created_at: datetime,
    expires_at: datetime,
) -> dict[str, Any]:
    """Build one immutable, target-bound saved-plan metadata record."""
    missing = [field for field in PLAN_BINDING_FIELDS if field not in bindings]
    if missing:
        raise AuthorizationError("saved plan binding is incomplete")
    if bindings["environment"] not in NONPRODUCTION_ENVIRONMENTS:
        raise AuthorizationError("saved plans are limited to non-production environments")
    created = created_at.astimezone(UTC) if created_at.tzinfo else None
    expires = expires_at.astimezone(UTC) if expires_at.tzinfo else None
    if created is None or expires is None or expires <= created:
        raise AuthorizationError("saved plan lifetime is invalid")
    lifetime = (expires - created).total_seconds()
    if not 300 <= lifetime <= 86400:
        raise AuthorizationError("saved plan lifetime must be between five minutes and 24 hours")
    if object_key != _exact_plan_key(bindings):
        raise AuthorizationError("saved plan object key is not derived from trusted bindings")

    record: dict[str, Any] = {
        "schema_version": "1",
        "record_type": "saved_plan",
        **{field: bindings[field] for field in PLAN_BINDING_FIELDS},
        "plan_sha256": plan_sha256,
        "plan_size_bytes": plan_size_bytes,
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
    if approval["initiator_user_id"] == approval["approver_user_id"]:
        raise AuthorizationError("saved plan approval requires an independent reviewer")
    current = now.astimezone(UTC) if now.tzinfo else None
    if current is None:
        raise AuthorizationError("approval verification time must be timezone-aware")
    approved = _parse_timestamp(approval["approved_at"], "approved_at")
    expires = _parse_timestamp(approval["expires_at"], "approval expires_at")
    if expires <= approved or current < approved or current >= expires:
        raise AuthorizationError("saved plan approval is not currently valid")


def _validate_plan_approval_binding(
    plan_record: Mapping[str, Any],
    approval: Mapping[str, Any],
) -> None:
    for field in LEDGER_BINDING_FIELDS:
        if approval.get(field) != plan_record.get(field):
            raise AuthorizationError(f"saved plan approval binding mismatch: {field}")
    if approval.get("plan_record_digest") != plan_record["record_digest"]:
        raise AuthorizationError("saved plan approval plan binding mismatch")
    if approval.get("github_environment") != plan_record["github_environment"]:
        raise AuthorizationError("saved plan approval Environment binding mismatch")
    if approval.get("environment_configuration_digest") != plan_record[
        "environment_configuration_digest"
    ]:
        raise AuthorizationError("saved plan approval configuration binding mismatch")
    approved = _parse_timestamp(approval["approved_at"], "approved_at")
    approval_expires = _parse_timestamp(approval["expires_at"], "approval expires_at")
    plan_created = _parse_timestamp(plan_record["created_at"], "created_at")
    plan_expires = _parse_timestamp(plan_record["expires_at"], "expires_at")
    if not plan_created <= approved < approval_expires <= plan_expires:
        raise AuthorizationError("saved plan approval lifetime exceeds the plan lifetime")


def build_saved_plan_approval(
    *,
    plan_record: Mapping[str, Any],
    repository_owner_id: int,
    repository_id: int,
    workflow_ref: str,
    workflow_sha: str,
    workflow_run_id: int,
    github_environment: str,
    environment_configuration_digest: str,
    initiator_user_id: int,
    approver_user_id: int,
    approved_at: datetime,
    expires_at: datetime,
) -> dict[str, Any]:
    """Build one plan-bound approval from immutable GitHub API evidence."""
    _validate_schema(plan_record, "saved-plan.v1.schema.json", "saved plan")
    _verify_digest(plan_record, "record_digest", "saved plan")
    approved = approved_at.astimezone(UTC) if approved_at.tzinfo else None
    expires = expires_at.astimezone(UTC) if expires_at.tzinfo else None
    plan_created = _parse_timestamp(plan_record["created_at"], "created_at")
    plan_expires = _parse_timestamp(plan_record["expires_at"], "expires_at")
    if approved is None or expires is None:
        raise AuthorizationError("saved plan approval timestamps must be timezone-aware")
    if not plan_created <= approved < expires <= plan_expires:
        raise AuthorizationError("saved plan approval lifetime exceeds the plan lifetime")
    if initiator_user_id == approver_user_id:
        raise AuthorizationError("saved plan approval requires an independent reviewer")
    if github_environment != plan_record["github_environment"]:
        raise AuthorizationError("saved plan approval Environment binding mismatch")
    if environment_configuration_digest != plan_record["environment_configuration_digest"]:
        raise AuthorizationError("saved plan approval configuration binding mismatch")
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
        "github_environment": github_environment,
        "environment_configuration_digest": environment_configuration_digest,
        "initiator_user_id": initiator_user_id,
        "approver_user_id": approver_user_id,
        "decision": "APPROVED",
        "approved_at": _timestamp(approved_at),
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
        "lineage": plan_record["state_lineage"],
        "serial": plan_record["state_serial"],
    }:
        raise AuthorizationError("Terraform state changed after the saved plan was created")

    return {
        "allowed": True,
        "code": "EXACT_SAVED_PLAN_AUTHORIZED",
        "plan_record_digest": plan_record["record_digest"],
    }


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
    reconciliation_receipt: Mapping[str, Any] | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Prepare one compare-and-swap ledger transition for a storage adapter."""
    _validate_schema(current, "live-execution-ledger.v1.schema.json", "execution ledger")
    _verify_digest(current, "ledger_digest", "execution ledger")
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
        _validate_approval_record(approval_record, now=at)
        for field in LEDGER_BINDING_FIELDS:
            if approval_record.get(field) != current.get(field):
                raise AuthorizationError(f"saved plan approval binding mismatch: {field}")
        if approval_record.get("plan_record_digest") != current["plan_record_digest"]:
            raise AuthorizationError("saved plan approval plan binding mismatch")
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
    proposed["ledger_digest"] = canonical_digest(
        {key: value for key, value in proposed.items() if key != "ledger_digest"}
    )
    _validate_schema(proposed, "live-execution-ledger.v1.schema.json", "execution ledger")
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


def build_health_receipt(
    *,
    plan_record: Mapping[str, Any],
    ledger: Mapping[str, Any],
    state_readback: Mapping[str, Any],
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
    if state_readback.get("lineage") != plan_record["state_lineage"]:
        raise AuthorizationError("health receipt state lineage mismatch")
    state_serial = state_readback.get("serial")
    if not isinstance(state_serial, int) or state_serial < plan_record["state_serial"]:
        raise AuthorizationError("health receipt state serial is invalid")
    if not checks or len({check.get("name") for check in checks}) != len(checks):
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
        "state_lineage": state_readback["lineage"],
        "state_serial": state_serial,
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
    observed_state: Mapping[str, Any],
    speculative_plan_result: str,
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
    if speculative_plan_result not in {"NO_CHANGE", "CHANGE", "ERROR"}:
        raise AuthorizationError("speculative reconciliation result is invalid")
    lineage_matches = observed_state.get("lineage") == plan_record["state_lineage"]
    serial = observed_state.get("serial")
    serial_advanced = isinstance(serial, int) and serial > plan_record["state_serial"]
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
        "observed_state_serial": serial if isinstance(serial, int) and serial >= 0 else 0,
        "speculative_plan_result": speculative_plan_result,
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


def classify_plan(*, add: int, change: int, destroy: int, replace: int) -> str:
    """Classify a sanitized Terraform plan summary without accepting destruction."""
    counts = (add, change, destroy, replace)
    if any(not isinstance(value, int) or value < 0 for value in counts):
        raise AuthorizationError("plan counts must be non-negative integers")
    if destroy or replace:
        raise AuthorizationError("destructive plan requires a separate reviewed recovery path")
    return "NO_CHANGE" if add == 0 and change == 0 else "CHANGE"
