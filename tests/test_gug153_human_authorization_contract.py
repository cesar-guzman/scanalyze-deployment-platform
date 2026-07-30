"""GUG-153 provider-neutral human authorization contract tests."""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, ValidationError


ROOT = Path(__file__).resolve().parents[1]
CONTEXT_SCHEMA_PATH = ROOT / "schemas/human-authorization-context.v1.schema.json"
DECISION_SCHEMA_PATH = ROOT / "schemas/authorization-decision.v1.schema.json"
AUTHORITY_SCHEMA_PATH = (
    ROOT / "schemas/authorization-authority-state.v1.schema.json"
)
AUDIT_RECEIPT_SCHEMA_PATH = (
    ROOT / "schemas/authorization-audit-receipt.v1.schema.json"
)

POLICY_DIGEST = (
    "sha256:34a639992f6c2312176ac7dc12c361daa38201adea6af0c0b1765a17a14754f8"
)

VALID_MEMBERSHIP = {
    "schema_version": "human-authorization-context.v1",
    "authorization_path": "membership",
    "authorization_source": "pre_token_membership_v1",
    "subject": "00000000-0000-4000-8000-000000000153",
    "customer_id": "cust_01ARZ3NDEKTSV4RRFFQ69G5FAW",
    "deployment_id": "dep_01ARZ3NDEKTSV4RRFFQ69G5FAV",
    "membership_state": "active",
    "role_id": "document_operator",
    "membership_version": "membership-v7",
    "authz_schema_version": "enterprise-authorization.v1",
    "scope_catalog_version": "scanalyze.api.v1",
    "role_catalog_version": "enterprise-roles.v1",
    "policy_version": "1.0.0",
    "policy_digest": POLICY_DIGEST,
    "issued_at_epoch": 2_000_000_000,
    "authenticated_at_epoch": 1_999_999_970,
    "assurance": "phishing_resistant_mfa",
    "assurance_source": "authoritative_authentication_event_v1",
    "assurance_version": "phishing-resistant-mfa.v1",
    "authentication_event_reference": "ref_000000000000000000000153",
}

VALID_TEMPORARY_GRANT = {
    "schema_version": "human-authorization-context.v1",
    "authorization_path": "temporary_grant",
    "authorization_source": "authoritative_temporary_grant_store_v1",
    "subject": "00000000-0000-4000-8000-000000000153",
    "customer_id": "cust_01ARZ3NDEKTSV4RRFFQ69G5FAW",
    "deployment_id": "dep_01ARZ3NDEKTSV4RRFFQ69G5FAV",
    "temporary_grant_id": "grant-synthetic-153",
    "temporary_grant_type": "support",
    "temporary_grant_state": "active",
    "temporary_grant_version": "grant-v1",
    "case_reference": "ref_000000000000000000000161",
    "purpose_reference": "ref_000000000000000000000162",
    "approval_references": ["ref_000000000000000000000163"],
    "grant_issued_at_epoch": 1_999_999_000,
    "allowed_operation_ids": ["documents.read_metadata"],
    "allowed_data_classes": ["metadata"],
    "expires_at_epoch": 2_000_000_300,
    "authz_schema_version": "enterprise-authorization.v1",
    "scope_catalog_version": "scanalyze.api.v1",
    "role_catalog_version": "enterprise-roles.v1",
    "policy_version": "1.0.0",
    "policy_digest": POLICY_DIGEST,
    "issued_at_epoch": 2_000_000_000,
    "authenticated_at_epoch": 1_999_999_970,
    "assurance": "phishing_resistant_mfa",
    "assurance_source": "authoritative_authentication_event_v1",
    "assurance_version": "phishing-resistant-mfa.v1",
    "authentication_event_reference": "ref_000000000000000000000154",
}

VALID_MEMBERSHIP_AUTHORITY = {
    "schema_version": "authorization-authority-state.v1",
    "authorization_path": "membership",
    "authority_source": "authoritative_membership_store_v1",
    "subject": "00000000-0000-4000-8000-000000000153",
    "customer_id": "cust_01ARZ3NDEKTSV4RRFFQ69G5FAW",
    "deployment_id": "dep_01ARZ3NDEKTSV4RRFFQ69G5FAV",
    "membership_state": "active",
    "role_id": "document_operator",
    "membership_version": "membership-v7",
    "checked_at_epoch": 2_000_000_001,
}

VALID_TEMPORARY_GRANT_AUTHORITY = {
    "schema_version": "authorization-authority-state.v1",
    "authorization_path": "temporary_grant",
    "authority_source": "authoritative_temporary_grant_store_v1",
    "subject": "00000000-0000-4000-8000-000000000153",
    "customer_id": "cust_01ARZ3NDEKTSV4RRFFQ69G5FAW",
    "deployment_id": "dep_01ARZ3NDEKTSV4RRFFQ69G5FAV",
    "temporary_grant_id": "grant-synthetic-153",
    "temporary_grant_type": "support",
    "temporary_grant_state": "active",
    "temporary_grant_version": "grant-v1",
    "case_reference": "ref_000000000000000000000161",
    "purpose_reference": "ref_000000000000000000000162",
    "approval_references": ["ref_000000000000000000000163"],
    "grant_issued_at_epoch": 1_999_999_000,
    "allowed_operation_ids": ["documents.read_metadata"],
    "allowed_data_classes": ["metadata"],
    "expires_at_epoch": 2_000_000_300,
    "checked_at_epoch": 2_000_000_001,
}

VALID_AUDIT_RECEIPT = {
    "schema_version": "authorization-audit-receipt.v1",
    "decision_id": "decision-000000000153",
    "sink_source": "durable_authorization_audit_sink_v1",
    "sink_version": "1.0.0",
    "receipt_reference": "ref_000000000000000000000157",
    "acknowledged_at_epoch": 2_000_000_001,
}

VALID_DECISION = {
    "event_schema_version": "authorization-decision.v1",
    "timestamp": "2033-05-18T03:33:20Z",
    "decision_id": "decision-000000000153",
    "principal_type": "user",
    "principal_reference": "ref_000000000000000000000153",
    "customer_reference": "ref_000000000000000000000154",
    "deployment_reference": "ref_000000000000000000000155",
    "correlation_reference": "ref_000000000000000000000156",
    "authorization_path": "membership",
    "authorization_source": "pre_token_membership_v1",
    "membership_version": "membership-v7",
    "role_catalog_version": "enterprise-roles.v1",
    "action": "read",
    "operation": "documents.read_metadata",
    "resource_type": "documents",
    "decision": "allow",
    "reason_code": "explicit_allow",
    "policy_version": "1.0.0",
    "policy_digest": POLICY_DIGEST,
    "assurance": "phishing_resistant_mfa",
}


def _schema(path: Path) -> dict:
    assert path.is_file(), f"missing reviewed contract: {path.name}"
    value = json.loads(path.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(value)
    return value


def test_membership_snapshot_contract_is_closed_and_valid() -> None:
    schema = _schema(CONTEXT_SCHEMA_PATH)
    Draft202012Validator(schema).validate(VALID_MEMBERSHIP)
    assert schema["additionalProperties"] is False


@pytest.mark.parametrize(
    "field",
    [
        "schema_version",
        "authorization_path",
        "authorization_source",
        "subject",
        "customer_id",
        "deployment_id",
        "membership_version",
        "policy_digest",
        "issued_at_epoch",
    ],
)
def test_membership_snapshot_rejects_missing_authority(field: str) -> None:
    candidate = copy.deepcopy(VALID_MEMBERSHIP)
    candidate.pop(field)
    with pytest.raises(ValidationError):
        Draft202012Validator(_schema(CONTEXT_SCHEMA_PATH)).validate(candidate)


def test_membership_snapshot_rejects_conflicting_temporary_grant_path() -> None:
    candidate = {
        **VALID_MEMBERSHIP,
        "temporary_grant_id": "grant-synthetic-153",
        "temporary_grant_type": "support",
        "temporary_grant_state": "active",
        "temporary_grant_version": "grant-v1",
        "grant_issued_at_epoch": 1_999_999_000,
        "allowed_operation_ids": ["documents.read_metadata"],
        "allowed_data_classes": ["metadata"],
        "expires_at_epoch": 2_000_000_300,
    }
    with pytest.raises(ValidationError):
        Draft202012Validator(_schema(CONTEXT_SCHEMA_PATH)).validate(candidate)


def test_membership_snapshot_accepts_absent_assurance_bundle() -> None:
    candidate = copy.deepcopy(VALID_MEMBERSHIP)
    for field in (
        "assurance",
        "assurance_source",
        "assurance_version",
        "authentication_event_reference",
    ):
        candidate.pop(field)
    Draft202012Validator(_schema(CONTEXT_SCHEMA_PATH)).validate(candidate)


@pytest.mark.parametrize(
    "missing_field",
    [
        "assurance",
        "assurance_source",
        "assurance_version",
        "authentication_event_reference",
    ],
)
def test_assurance_provenance_is_all_or_nothing(missing_field: str) -> None:
    candidate = copy.deepcopy(VALID_MEMBERSHIP)
    candidate.pop(missing_field)
    with pytest.raises(ValidationError):
        Draft202012Validator(_schema(CONTEXT_SCHEMA_PATH)).validate(candidate)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("assurance", "software_mfa"),
        ("assurance_source", "request_claim"),
        ("assurance_version", "unreviewed.v2"),
        ("authentication_event_reference", "authentication-event-raw"),
    ],
)
def test_assurance_provenance_rejects_unknown_or_malformed_values(
    field: str,
    value: str,
) -> None:
    candidate = {**VALID_MEMBERSHIP, field: value}
    with pytest.raises(ValidationError):
        Draft202012Validator(_schema(CONTEXT_SCHEMA_PATH)).validate(candidate)


@pytest.mark.parametrize("grant_type", ["support", "break_glass"])
def test_temporary_grant_snapshot_has_exact_ttl_structure(grant_type: str) -> None:
    candidate = {**VALID_TEMPORARY_GRANT, "temporary_grant_type": grant_type}
    if grant_type == "break_glass":
        candidate.pop("case_reference")
        candidate["incident_reference"] = "ref_000000000000000000000164"
        candidate["approval_references"] = [
            "ref_000000000000000000000163",
            "ref_000000000000000000000165",
        ]
    Draft202012Validator(_schema(CONTEXT_SCHEMA_PATH)).validate(candidate)


@pytest.mark.parametrize(
    "field",
    [
        "schema_version",
        "temporary_grant_id",
        "temporary_grant_type",
        "temporary_grant_state",
        "temporary_grant_version",
        "purpose_reference",
        "approval_references",
        "grant_issued_at_epoch",
        "allowed_operation_ids",
        "allowed_data_classes",
        "expires_at_epoch",
    ],
)
def test_temporary_grant_snapshot_rejects_missing_authority(field: str) -> None:
    candidate = copy.deepcopy(VALID_TEMPORARY_GRANT)
    candidate.pop(field)
    with pytest.raises(ValidationError):
        Draft202012Validator(_schema(CONTEXT_SCHEMA_PATH)).validate(candidate)


def test_temporary_grant_snapshot_requires_complete_step_up_bundle() -> None:
    candidate = copy.deepcopy(VALID_TEMPORARY_GRANT)
    for field in (
        "assurance",
        "assurance_source",
        "assurance_version",
        "authentication_event_reference",
    ):
        candidate.pop(field)
    with pytest.raises(ValidationError):
        Draft202012Validator(_schema(CONTEXT_SCHEMA_PATH)).validate(candidate)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("grant_issued_at_epoch", "1999999000"),
        ("grant_issued_at_epoch", 0),
        ("expires_at_epoch", "2000000300"),
        ("expires_at_epoch", 0),
    ],
)
def test_temporary_grant_snapshot_rejects_malformed_ttl_structure(
    field: str,
    value: object,
) -> None:
    candidate = {**VALID_TEMPORARY_GRANT, field: value}
    with pytest.raises(ValidationError):
        Draft202012Validator(_schema(CONTEXT_SCHEMA_PATH)).validate(candidate)


@pytest.mark.parametrize("missing_field", ["case_reference", "approval_references"])
def test_support_grant_requires_case_and_customer_approval(
    missing_field: str,
) -> None:
    candidate = copy.deepcopy(VALID_TEMPORARY_GRANT)
    candidate.pop(missing_field)
    with pytest.raises(ValidationError):
        Draft202012Validator(_schema(CONTEXT_SCHEMA_PATH)).validate(candidate)


def test_break_glass_requires_incident_and_two_independent_approvals() -> None:
    candidate = copy.deepcopy(VALID_TEMPORARY_GRANT)
    candidate["temporary_grant_type"] = "break_glass"
    candidate.pop("case_reference")
    candidate["incident_reference"] = "ref_000000000000000000000164"
    candidate["approval_references"] = ["ref_000000000000000000000163"]
    with pytest.raises(ValidationError):
        Draft202012Validator(_schema(CONTEXT_SCHEMA_PATH)).validate(candidate)


def test_membership_snapshot_rejects_grant_issuance_evidence() -> None:
    candidate = {**VALID_MEMBERSHIP, "grant_issued_at_epoch": 1_999_999_000}
    with pytest.raises(ValidationError):
        Draft202012Validator(_schema(CONTEXT_SCHEMA_PATH)).validate(candidate)


def test_temporary_grant_snapshot_rejects_membership_authority() -> None:
    candidate = {
        **VALID_TEMPORARY_GRANT,
        "membership_state": "active",
        "role_id": "document_operator",
        "membership_version": "membership-v7",
    }
    with pytest.raises(ValidationError):
        Draft202012Validator(_schema(CONTEXT_SCHEMA_PATH)).validate(candidate)


@pytest.mark.parametrize(
    "candidate",
    [
        {**VALID_MEMBERSHIP, "schema_version": "human-authorization-context.v2"},
        {**VALID_MEMBERSHIP, "legacy_role": "admin"},
        {
            **VALID_TEMPORARY_GRANT,
            "authorization_source": "pre_token_membership_v1",
        },
    ],
)
def test_context_rejects_unknown_version_property_or_source(candidate: dict) -> None:
    with pytest.raises(ValidationError):
        Draft202012Validator(_schema(CONTEXT_SCHEMA_PATH)).validate(candidate)


@pytest.mark.parametrize(
    "candidate",
    [VALID_MEMBERSHIP_AUTHORITY, VALID_TEMPORARY_GRANT_AUTHORITY],
)
def test_authority_state_contract_accepts_exactly_one_path(candidate: dict) -> None:
    schema = _schema(AUTHORITY_SCHEMA_PATH)
    Draft202012Validator(schema).validate(candidate)
    assert schema["additionalProperties"] is False


@pytest.mark.parametrize(
    "field",
    [
        "schema_version",
        "authorization_path",
        "authority_source",
        "subject",
        "customer_id",
        "deployment_id",
        "checked_at_epoch",
    ],
)
def test_authority_state_rejects_missing_binding(field: str) -> None:
    candidate = copy.deepcopy(VALID_MEMBERSHIP_AUTHORITY)
    candidate.pop(field)
    with pytest.raises(ValidationError):
        Draft202012Validator(_schema(AUTHORITY_SCHEMA_PATH)).validate(candidate)


@pytest.mark.parametrize(
    "candidate",
    [
        {
            **VALID_MEMBERSHIP_AUTHORITY,
            "authority_source": "pre_token_membership_v1",
        },
        {
            **VALID_MEMBERSHIP_AUTHORITY,
            "temporary_grant_version": "grant-v1",
        },
        {
            **VALID_TEMPORARY_GRANT_AUTHORITY,
            "membership_version": "membership-v7",
        },
        {**VALID_MEMBERSHIP_AUTHORITY, "tenant_id": "legacy-tenant"},
        {
            **VALID_TEMPORARY_GRANT_AUTHORITY,
            "schema_version": "authorization-authority-state.v2",
        },
    ],
)
def test_authority_state_rejects_untrusted_ambiguous_or_unknown_evidence(
    candidate: dict,
) -> None:
    with pytest.raises(ValidationError):
        Draft202012Validator(_schema(AUTHORITY_SCHEMA_PATH)).validate(candidate)


def test_audit_receipt_contract_is_closed_and_bound_to_decision() -> None:
    schema = _schema(AUDIT_RECEIPT_SCHEMA_PATH)
    Draft202012Validator(schema).validate(VALID_AUDIT_RECEIPT)
    assert schema["additionalProperties"] is False


@pytest.mark.parametrize(
    "field",
    [
        "schema_version",
        "decision_id",
        "sink_source",
        "sink_version",
        "receipt_reference",
        "acknowledged_at_epoch",
    ],
)
def test_audit_receipt_rejects_missing_acknowledgement(field: str) -> None:
    candidate = copy.deepcopy(VALID_AUDIT_RECEIPT)
    candidate.pop(field)
    with pytest.raises(ValidationError):
        Draft202012Validator(_schema(AUDIT_RECEIPT_SCHEMA_PATH)).validate(candidate)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("schema_version", "authorization-audit-receipt.v2"),
        ("decision_id", "unknown-decision"),
        ("sink_source", "logger_v1"),
        ("sink_version", "2.0.0"),
        ("receipt_reference", "raw-receipt-id"),
        ("acknowledged_at_epoch", 0),
        ("unreviewed_sink_metadata", "value"),
    ],
)
def test_audit_receipt_rejects_unknown_or_malformed_evidence(
    field: str,
    value: object,
) -> None:
    candidate = {**VALID_AUDIT_RECEIPT, field: value}
    with pytest.raises(ValidationError):
        Draft202012Validator(_schema(AUDIT_RECEIPT_SCHEMA_PATH)).validate(candidate)


def test_authorization_decision_contract_is_closed_and_sanitized() -> None:
    schema = _schema(DECISION_SCHEMA_PATH)
    Draft202012Validator(schema).validate(VALID_DECISION)
    assert schema["additionalProperties"] is False


def test_temporary_grant_decision_carries_sanitized_approval_evidence() -> None:
    candidate = copy.deepcopy(VALID_DECISION)
    for field in ("membership_version", "role_catalog_version"):
        candidate.pop(field)
    candidate.update({
        "authorization_path": "temporary_grant",
        "authorization_source": "authoritative_temporary_grant_store_v1",
        "temporary_grant_type": "support",
        "temporary_grant_state": "active",
        "temporary_grant_version": "grant-v1",
        "grant_reference": "ref_000000000000000000000160",
        "case_reference": "ref_000000000000000000000161",
        "purpose_reference": "ref_000000000000000000000162",
        "approval_references": ["ref_000000000000000000000163"],
    })
    Draft202012Validator(_schema(DECISION_SCHEMA_PATH)).validate(candidate)


@pytest.mark.parametrize("field", ["authorization_path", "authorization_source"])
def test_allow_decision_requires_unambiguous_authorization_provenance(
    field: str,
) -> None:
    candidate = copy.deepcopy(VALID_DECISION)
    candidate.pop(field)
    with pytest.raises(ValidationError):
        Draft202012Validator(_schema(DECISION_SCHEMA_PATH)).validate(candidate)


def test_membership_allow_decision_rejects_temporary_grant_evidence() -> None:
    candidate = {
        **VALID_DECISION,
        "temporary_grant_type": "support",
        "temporary_grant_state": "active",
        "temporary_grant_version": "grant-v1",
        "grant_reference": "ref_000000000000000000000160",
        "case_reference": "ref_000000000000000000000161",
        "purpose_reference": "ref_000000000000000000000162",
        "approval_references": ["ref_000000000000000000000163"],
    }
    with pytest.raises(ValidationError):
        Draft202012Validator(_schema(DECISION_SCHEMA_PATH)).validate(candidate)


def test_m2m_allow_decision_requires_exact_binding_provenance() -> None:
    candidate = copy.deepcopy(VALID_DECISION)
    for field in ("membership_version", "role_catalog_version"):
        candidate.pop(field)
    candidate.update(
        {
            "principal_type": "m2m",
            "authorization_path": "m2m_binding",
            "authorization_source": "m2m_identity_binding_v1",
            "grant_version": "m2m_identity_binding_v1",
            "assurance": "validated_client_credentials_binding",
        }
    )
    Draft202012Validator(_schema(DECISION_SCHEMA_PATH)).validate(candidate)


def test_early_deny_decision_may_omit_unavailable_provenance() -> None:
    candidate = copy.deepcopy(VALID_DECISION)
    for field in (
        "authorization_path",
        "authorization_source",
        "membership_version",
        "role_catalog_version",
    ):
        candidate.pop(field)
    candidate.update({"decision": "deny", "reason_code": "missing_auth_context"})
    Draft202012Validator(_schema(DECISION_SCHEMA_PATH)).validate(candidate)


@pytest.mark.parametrize(
    "assurance",
    ["validated_client_credentials_binding"],
)
def test_membership_allow_rejects_nonhuman_assurance(assurance: str) -> None:
    candidate = {**VALID_DECISION, "assurance": assurance}
    with pytest.raises(ValidationError):
        Draft202012Validator(_schema(DECISION_SCHEMA_PATH)).validate(candidate)


@pytest.mark.parametrize("grant_type", ["support", "break_glass"])
@pytest.mark.parametrize("assurance", ["none", "validated_client_credentials_binding"])
def test_temporary_grant_allow_requires_phishing_resistant_assurance(
    grant_type: str,
    assurance: str,
) -> None:
    candidate = copy.deepcopy(VALID_DECISION)
    for field in ("membership_version", "role_catalog_version"):
        candidate.pop(field)
    candidate.update(
        {
            "authorization_path": "temporary_grant",
            "authorization_source": "authoritative_temporary_grant_store_v1",
            "temporary_grant_type": grant_type,
            "temporary_grant_state": "active",
            "temporary_grant_version": "grant-v1",
            "grant_reference": "ref_000000000000000000000160",
            "purpose_reference": "ref_000000000000000000000162",
            "approval_references": ["ref_000000000000000000000163"],
            "assurance": assurance,
        }
    )
    if grant_type == "support":
        candidate["case_reference"] = "ref_000000000000000000000161"
    else:
        candidate["incident_reference"] = "ref_000000000000000000000164"
        candidate["approval_references"] = [
            "ref_000000000000000000000163",
            "ref_000000000000000000000165",
        ]
    with pytest.raises(ValidationError):
        Draft202012Validator(_schema(DECISION_SCHEMA_PATH)).validate(candidate)


@pytest.mark.parametrize(
    "forbidden_field",
    [
        "token",
        "raw_claims",
        "email",
        "document_contents",
        "object_key",
        "presigned_url",
        "request_body",
    ],
)
def test_authorization_decision_rejects_sensitive_fields(
    forbidden_field: str,
) -> None:
    candidate = {**VALID_DECISION, forbidden_field: "synthetic-forbidden-value"}
    with pytest.raises(ValidationError):
        Draft202012Validator(_schema(DECISION_SCHEMA_PATH)).validate(candidate)
