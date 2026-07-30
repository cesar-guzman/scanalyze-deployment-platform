"""Fail-closed deployment registry transition and conditional-write model."""
from __future__ import annotations

from pathlib import Path
from typing import Any

import jsonschema

from tooling.authorize_deployment_backend import (
    AuthorizationError,
    canonical_digest,
    load_json_strict,
)


REPO_ROOT = Path(__file__).resolve().parents[1]
IMMUTABLE_FIELDS = frozenset(
    {
        "schema_version",
        "record_type",
        "customer_id",
        "deployment_id",
        "account_id",
        "region",
        "environment",
        "account_ready",
        "state_binding",
    }
)
ALLOWED_TRANSITIONS = {
    "REQUESTED": frozenset({"BASELINING"}),
    "BASELINING": frozenset({"READY"}),
    "READY": frozenset({"ACTIVE", "SUSPENDED", "OFFBOARDING"}),
    "ACTIVE": frozenset({"SUSPENDED", "OFFBOARDING"}),
    "SUSPENDED": frozenset({"ACTIVE", "OFFBOARDING"}),
    "OFFBOARDING": frozenset({"ARCHIVED"}),
    "ARCHIVED": frozenset(),
}


def _validate(record: dict[str, Any]) -> None:
    schema = load_json_strict(REPO_ROOT / "schemas/deployment-target.v1.schema.json")
    errors = list(jsonschema.Draft202012Validator(schema).iter_errors(record))
    if errors:
        raise AuthorizationError("deployment registry record schema validation failed")
    expected = canonical_digest(
        {key: value for key, value in record.items() if key != "record_digest"}
    )
    if record["record_digest"] != expected:
        raise AuthorizationError("deployment registry record digest mismatch")


def prepare_registry_create(record: dict[str, Any]) -> dict[str, Any]:
    """Return a create-only DynamoDB write contract."""
    _validate(record)
    if record["registry_version"] != 1:
        raise AuthorizationError("new deployment registry records must start at version one")
    return {
        "condition_expression": "attribute_not_exists(deployment_id)",
        "expression_attribute_names": {},
        "expression_attribute_values": {},
    }


def prepare_registry_update(
    *,
    current: dict[str, Any],
    proposed: dict[str, Any],
    expected_version: int,
    expected_digest: str,
) -> dict[str, Any]:
    """Validate one immutable, compare-and-swap registry transition."""
    _validate(current)
    _validate(proposed)
    if current["registry_version"] != expected_version:
        raise AuthorizationError("deployment registry version conflict")
    if current["record_digest"] != expected_digest:
        raise AuthorizationError("deployment registry digest conflict")
    if proposed["registry_version"] != current["registry_version"] + 1:
        raise AuthorizationError("deployment registry version must increment by one")
    for field in IMMUTABLE_FIELDS:
        if proposed[field] != current[field]:
            raise AuthorizationError(f"deployment registry field is immutable: {field}")
    old_status = current["status"]
    new_status = proposed["status"]
    if new_status not in ALLOWED_TRANSITIONS[old_status]:
        raise AuthorizationError(
            f"deployment registry status transition is forbidden: {old_status}->{new_status}"
        )
    return {
        "condition_expression": (
            "registry_version = :expected_version "
            "AND record_digest = :expected_digest "
            "AND customer_id = :customer_id "
            "AND account_id = :account_id "
            "AND #region = :region"
        ),
        "expression_attribute_names": {"#region": "region"},
        "expression_attribute_values": {
            ":expected_version": expected_version,
            ":expected_digest": expected_digest,
            ":customer_id": current["customer_id"],
            ":account_id": current["account_id"],
            ":region": current["region"],
        },
    }
