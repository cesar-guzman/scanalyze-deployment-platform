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
TARGET_SCHEMAS = {
    "1": "deployment-target.v1.schema.json",
    "2": "deployment-target.v2.schema.json",
}
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
    schema_name = TARGET_SCHEMAS.get(record.get("schema_version"))
    if schema_name is None:
        raise AuthorizationError("deployment registry schema version is unsupported")
    schema = load_json_strict(REPO_ROOT / "schemas" / schema_name)
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
    if (
        current.get("schema_version") == "1"
        and proposed.get("schema_version") == "2"
    ):
        migration_fields = set(IMMUTABLE_FIELDS) - {"schema_version"}
        for field in migration_fields:
            if proposed.get(field) != current.get(field):
                raise AuthorizationError(
                    f"deployment registry field is immutable: {field}"
                )
        if proposed.get("status") != current.get("status"):
            raise AuthorizationError(
                "deployment target v1 to v2 migration cannot change status"
            )
        return {
            "condition_expression": (
                "registry_version = :expected_version "
                "AND record_digest = :expected_digest "
                "AND schema_version = :expected_schema_version "
                "AND customer_id = :customer_id "
                "AND account_id = :account_id "
                "AND #region = :region"
            ),
            "expression_attribute_names": {"#region": "region"},
            "expression_attribute_values": {
                ":expected_version": expected_version,
                ":expected_digest": expected_digest,
                ":expected_schema_version": "1",
                ":customer_id": current["customer_id"],
                ":account_id": current["account_id"],
                ":region": current["region"],
            },
        }
    immutable_fields = set(IMMUTABLE_FIELDS)
    if current.get("schema_version") == "2":
        immutable_fields.add("runtime_origin")
    for field in immutable_fields:
        if proposed.get(field) != current.get(field):
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
