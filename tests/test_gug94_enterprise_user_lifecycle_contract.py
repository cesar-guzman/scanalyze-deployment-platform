"""GUG-94 closed schema and privacy contracts for enterprise user lifecycle."""
from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, FormatChecker, ValidationError


ROOT = Path(__file__).resolve().parents[1]
IDENTITY_STORAGE = ROOT / "modules" / "identity-control-plane" / "storage.tf"
LIFECYCLE_ADAPTERS = (
    ROOT
    / "backend"
    / "workers"
    / "scanalyze-ingest-api"
    / "app"
    / "user_lifecycle_adapters.py"
)
SCHEMAS = {
    name: ROOT / "schemas" / name
    for name in (
        "enterprise-membership.v1.schema.json",
        "lifecycle-operation.v1.schema.json",
        "lifecycle-approval-evidence.v1.schema.json",
        "lifecycle-audit-event.v1.schema.json",
    )
}
CUSTOMER_ID = "cust_01ARZ3NDEKTSV4RRFFQ69G5FAW"
DEPLOYMENT_ID = "dep_01ARZ3NDEKTSV4RRFFQ69G5FAV"
POLICY_DIGEST = "sha256:34a639992f6c2312176ac7dc12c361daa38201adea6af0c0b1765a17a14754f8"


VALID_MEMBERSHIP = {
    "schema_version": "enterprise-membership.v1",
    "membership_reference": "mbr_" + "1" * 32,
    "subject": "synthetic-subject-94",
    "customer_id": CUSTOMER_ID,
    "deployment_id": DEPLOYMENT_ID,
    "state": "active",
    "role_id": "document_operator",
    "membership_version": 3,
    "provider_user_reference": "ref_" + "2" * 24,
    "provider_principal_key": "synthetic-provider-principal",
    "created_at": "2026-07-13T12:00:00Z",
    "updated_at": "2026-07-13T12:01:00Z",
}

VALID_OPERATION = {
    "schema_version": "lifecycle-operation.v1",
    "operation_reference": "op_" + "3" * 32,
    "operation": "membership.suspend",
    "customer_id": CUSTOMER_ID,
    "deployment_id": DEPLOYMENT_ID,
    "actor_subject": "synthetic-admin-94",
    "idempotency_key": "idem_" + "4" * 32,
    "request_digest": "sha256:" + "5" * 64,
    "stage": "sessions_revoked",
    "evidence": {
        "membership_reference": "mbr_" + "1" * 32,
        "approval_reference": "apr_" + "6" * 32,
        "before_membership_version": "3",
        "after_membership_version": "4",
    },
    "created_at": "2026-07-13T12:00:00Z",
    "updated_at": "2026-07-13T12:01:00Z",
}

VALID_APPROVAL = {
    "schema_version": "lifecycle-approval-evidence.v1",
    "approval_reference": "apr_" + "6" * 32,
    "approver_subject": "independent-approver-94",
    "customer_id": CUSTOMER_ID,
    "deployment_id": DEPLOYMENT_ID,
    "operation": "membership.suspend",
    "target_reference": "mbr_" + "1" * 32,
    "request_digest": "sha256:" + "5" * 64,
    "state": "approved",
    "expires_at": "2026-07-13T12:05:00Z",
}

VALID_AUDIT = {
    "event_schema_version": "lifecycle-audit-event.v1",
    "timestamp": "2026-07-13T12:00:00Z",
    "decision_id": "ref_" + "7" * 24,
    "principal_type": "user",
    "principal_reference": "ref_" + "8" * 24,
    "customer_reference": "ref_" + "9" * 24,
    "deployment_reference": "ref_" + "a" * 24,
    "action": "membership.suspend",
    "resource_type": "authorization_administration",
    "decision": "allow",
    "reason_code": "security_review",
    "policy_version": "1.0.0",
    "policy_digest": POLICY_DIGEST,
    "assurance": "phishing_resistant_mfa",
    "correlation_reference": "ref_" + "b" * 24,
    "approval_references": ["apr_" + "6" * 32],
    "before_membership_version": "3",
    "after_membership_version": "4",
}


def _validator(name: str) -> Draft202012Validator:
    path = SCHEMAS[name]
    assert path.is_file()
    schema = json.loads(path.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema, format_checker=FormatChecker())


@pytest.mark.parametrize(
    ("schema_name", "record"),
    [
        ("enterprise-membership.v1.schema.json", VALID_MEMBERSHIP),
        ("lifecycle-operation.v1.schema.json", VALID_OPERATION),
        ("lifecycle-approval-evidence.v1.schema.json", VALID_APPROVAL),
        ("lifecycle-audit-event.v1.schema.json", VALID_AUDIT),
    ],
)
def test_lifecycle_contracts_are_closed_and_accept_valid_records(
    schema_name: str,
    record: dict,
) -> None:
    validator = _validator(schema_name)
    validator.validate(record)
    assert validator.schema["additionalProperties"] is False


@pytest.mark.parametrize("field", ["customer_id", "deployment_id", "subject"])
def test_membership_rejects_missing_ownership_or_subject(field: str) -> None:
    candidate = copy.deepcopy(VALID_MEMBERSHIP)
    candidate.pop(field)
    with pytest.raises(ValidationError):
        _validator("enterprise-membership.v1.schema.json").validate(candidate)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("customer_id", "legacy-customer"),
        ("deployment_id", "default"),
        ("state", "enabled"),
        ("role_id", "platform_admin"),
        ("membership_version", 0),
    ],
)
def test_membership_rejects_legacy_or_ambiguous_authority(
    field: str,
    value: object,
) -> None:
    with pytest.raises(ValidationError):
        _validator("enterprise-membership.v1.schema.json").validate(
            {**VALID_MEMBERSHIP, field: value}
        )


def test_invited_membership_requires_expiry_and_revoked_is_terminal_shape() -> None:
    invited = {**VALID_MEMBERSHIP, "state": "invited"}
    with pytest.raises(ValidationError):
        _validator("enterprise-membership.v1.schema.json").validate(invited)
    _validator("enterprise-membership.v1.schema.json").validate(
        {**invited, "invitation_expires_at": "2026-07-14T12:00:00Z"}
    )
    with pytest.raises(ValidationError):
        _validator("enterprise-membership.v1.schema.json").validate(
            {
                **VALID_MEMBERSHIP,
                "state": "revoked",
                "invitation_expires_at": "2026-07-14T12:00:00Z",
            }
        )


@pytest.mark.parametrize(
    "forbidden_field",
    [
        "tokens",
        "cookies",
        "secrets",
        "raw_claims",
        "invitation_secrets",
        "request_bodies",
        "pii_payloads",
        "object_keys",
        "presigned_urls",
    ],
)
def test_lifecycle_audit_rejects_sensitive_or_unreviewed_fields(
    forbidden_field: str,
) -> None:
    with pytest.raises(ValidationError):
        _validator("lifecycle-audit-event.v1.schema.json").validate(
            {**VALID_AUDIT, forbidden_field: "synthetic-secret"}
        )


def test_approval_cannot_change_operation_target_or_owner_shape() -> None:
    validator = _validator("lifecycle-approval-evidence.v1.schema.json")
    for field, value in (
        ("operation", "membership.delete"),
        ("target_reference", "raw-subject"),
        ("customer_id", "foreign-customer"),
        ("state", "pending"),
    ):
        with pytest.raises(ValidationError):
            validator.validate({**VALID_APPROVAL, field: value})


def test_operation_contract_never_stores_raw_request_payload_as_a_top_level_field() -> None:
    with pytest.raises(ValidationError):
        _validator("lifecycle-operation.v1.schema.json").validate(
            {**VALID_OPERATION, "request_body": {"email": "private@example.invalid"}}
        )


@pytest.mark.parametrize("field", ["tokens", "raw_claims", "request_body", "pii_payload"])
def test_operation_evidence_rejects_unreviewed_or_sensitive_fields(field: str) -> None:
    candidate = copy.deepcopy(VALID_OPERATION)
    candidate["evidence"][field] = "synthetic-sensitive-value"
    with pytest.raises(ValidationError):
        _validator("lifecycle-operation.v1.schema.json").validate(candidate)


def test_completed_operation_requires_durable_audit_receipt() -> None:
    candidate = {**copy.deepcopy(VALID_OPERATION), "stage": "completed"}
    with pytest.raises(ValidationError):
        _validator("lifecycle-operation.v1.schema.json").validate(candidate)
    candidate["evidence"]["audit_receipt_reference"] = "ref_" + "a" * 24
    _validator("lifecycle-operation.v1.schema.json").validate(candidate)


def test_membership_indexes_are_owner_bound_and_paginated_without_scan() -> None:
    storage = IDENTITY_STORAGE.read_text(encoding="utf-8")
    adapters = LIFECYCLE_ADAPTERS.read_text(encoding="utf-8")

    assert 'name            = "ownership-membership-reference-v1"' in storage
    assert 'hash_key        = "ownership_membership_key"' in storage
    assert 'name            = "ownership-state-v1"' in storage
    assert 'hash_key        = "ownership_state_key"' in storage
    assert 'range_key       = "membership_reference"' in storage
    assert ".scan(" not in adapters
    assert "ConsistentRead=True" in adapters
    assert '"ConsistentRead": True' in adapters


def test_admin_removal_uses_conditional_transaction_guard() -> None:
    adapters = LIFECYCLE_ADAPTERS.read_text(encoding="utf-8")

    assert "transact_write_items(" in adapters
    assert '"ConditionCheck"' in adapters
    assert "membership_version = :replacement_version" in adapters
    assert "membership_version = :expected_version" in adapters
