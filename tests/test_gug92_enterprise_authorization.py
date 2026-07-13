"""GUG-92 conformance tests for portable enterprise authorization policy v1."""

from __future__ import annotations

import copy
import json
import re
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from tooling.validate_enterprise_authorization import (
    DuplicateKeyError,
    load_json_without_duplicates,
    validate_enterprise_authorization,
)
from tooling.validate_schema import find_schema_for_fixture, validate_fixture


ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = ROOT / "schemas/enterprise-authorization.v1.schema.json"
POLICY_PATH = ROOT / "policies/authorization/enterprise-authorization.v1.json"
VALID_FIXTURE = ROOT / "fixtures/valid/enterprise-authorization-v1-synthetic.json"
INVALID_FIXTURES = tuple(
    sorted((ROOT / "fixtures/invalid").glob("enterprise-authorization-v1-*.json"))
)
EXPECTED_INVALID_FIXTURE_ERRORS = {
    "enterprise-authorization-v1-default-allow.json": "default deny",
    "enterprise-authorization-v1-legacy-fallback.json": "unknown or missing",
    "enterprise-authorization-v1-missing-deployment-binding.json": "customer_id and deployment_id",
    "enterprise-authorization-v1-service-lifecycle.json": "excluded from human privileges",
    "enterprise-authorization-v1-standing-break-glass.json": "break-glass must forbid standing",
}
ADR_PATH = ROOT / "ADR/ADR-023-enterprise-authorization-and-user-lifecycle.md"
REFERENCE_PATH = ROOT / "docs/deployment/enterprise-authorization.md"
NOTEBOOK_PATH = ROOT / "_NotebookLM_Brain/12_GUG92_Enterprise_Authorization.md"

EXPECTED_ACTION_SCOPES = {
    "read": "scanalyze.api.v1/read",
    "write": "scanalyze.api.v1/write",
    "admin": "scanalyze.api.v1/admin",
}
EXPECTED_HUMAN_ROLES = {
    "customer_admin",
    "document_operator",
    "document_reviewer",
    "auditor",
}
SENSITIVE_OPERATIONS = {
    "results.read_full",
    "exports.execute",
    "artifacts.download",
}
FORBIDDEN_LITERAL_PATTERNS = (
    re.compile(r"\b\d{12}\b"),
    re.compile(r"\barn:(?:aws|aws-us-gov|aws-cn):"),
    re.compile(r"\b(?:us|eu|ap|sa|ca|me|af)-(?:gov-)?[a-z]+-\d\b"),
    re.compile(r"\b(?:cust|dep)_[0-9A-HJKMNP-TV-Z]{26}\b"),
    re.compile(r"\b[a-z]{2}-[a-z]+-\d_[A-Za-z0-9]+\b"),
)


def _load(path: Path) -> dict:
    return load_json_without_duplicates(path)


def _set_transition_approval(
    policy: dict, from_state: str, to_state: str, required: bool
) -> None:
    transition = next(
        item
        for item in policy["human_lifecycle"]["transitions"]
        if item["from"] == from_state and item["to"] == to_state
    )
    transition["approval_required"] = required


def _duplicate_invitation_activation_transition(policy: dict) -> None:
    policy["human_lifecycle"]["transitions"].append(
        {
            "from": "invited",
            "to": "active",
            "approval_required": False,
            "audit_required": True,
        }
    )


def _grant_operator_pii(policy: dict) -> None:
    policy["human_roles"][1]["permissions"][0]["data_classes"].append("pii")


def _extend_v1_resource_catalog(policy: dict) -> None:
    policy["resources"].append(
        {
            "id": "unreviewed_resource",
            "allowed_actions": ["read"],
            "ownership_required": True,
            "ownership_attributes": ["customer_id", "deployment_id"],
        }
    )
    policy["human_roles"][0]["permissions"].append(
        {
            "resource": "unreviewed_resource",
            "actions": ["read"],
            "data_classes": ["metadata"],
        }
    )


@pytest.fixture(scope="module")
def schema() -> dict:
    value = _load(SCHEMA_PATH)
    Draft202012Validator.check_schema(value)
    return value


@pytest.fixture(scope="module")
def policy(schema: dict) -> dict:
    value = _load(POLICY_PATH)
    Draft202012Validator(schema).validate(value)
    assert validate_enterprise_authorization(value) == []
    return value


def test_canonical_policy_and_synthetic_fixture_validate(schema: dict, policy: dict) -> None:
    fixture = _load(VALID_FIXTURE)
    Draft202012Validator(schema).validate(fixture)
    assert validate_enterprise_authorization(fixture) == []
    assert fixture == policy


def test_schema_closes_every_declared_object(schema: dict) -> None:
    def walk(node) -> None:
        if isinstance(node, dict):
            if node.get("type") == "object":
                assert node.get("additionalProperties") is False
            for value in node.values():
                walk(value)
        elif isinstance(node, list):
            for value in node:
                walk(value)

    walk(schema)


def test_json_loader_rejects_duplicate_keys(tmp_path: Path) -> None:
    duplicate = tmp_path / "duplicate.json"
    duplicate.write_text('{"effect":"deny","effect":"allow"}', encoding="utf-8")
    with pytest.raises(DuplicateKeyError):
        load_json_without_duplicates(duplicate)


def test_schema_mapper_selects_gug92_schema_for_every_fixture() -> None:
    assert (
        find_schema_for_fixture(VALID_FIXTURE.stem, ROOT / "schemas")
        == SCHEMA_PATH
    )
    assert INVALID_FIXTURES, "negative GUG-92 fixtures are required"
    for fixture in INVALID_FIXTURES:
        assert find_schema_for_fixture(fixture.stem, ROOT / "schemas") == SCHEMA_PATH


def test_negative_fixtures_fail_closed(schema: dict) -> None:
    for fixture in INVALID_FIXTURES:
        valid, message = validate_fixture(fixture, SCHEMA_PATH)
        assert not valid, f"{fixture.name} unexpectedly passed"
        assert message.startswith("FAIL:")
        semantic_errors = validate_enterprise_authorization(_load(fixture))
        expected = EXPECTED_INVALID_FIXTURE_ERRORS[fixture.name]
        assert any(expected in error for error in semantic_errors)


def test_each_negative_fixture_contains_only_its_named_mutation(policy: dict) -> None:
    for fixture in INVALID_FIXTURES:
        candidate = _load(fixture)
        if fixture.name.endswith("default-allow.json"):
            candidate["effect"] = policy["effect"]
        elif fixture.name.endswith("legacy-fallback.json"):
            candidate["migration"]["missing_contract_behavior"] = "deny"
        elif fixture.name.endswith("missing-deployment-binding.json"):
            candidate["abac"]["exact_match_attributes"] = [
                "customer_id",
                "deployment_id",
            ]
        elif fixture.name.endswith("service-lifecycle.json"):
            candidate["service_principals"][
                "lifecycle_administration_forbidden"
            ] = True
        elif fixture.name.endswith("standing-break-glass.json"):
            candidate["break_glass"]["standing_role"] = False
        else:  # pragma: no cover - the closed fixture set is asserted above
            pytest.fail(f"unreviewed negative fixture: {fixture.name}")
        assert candidate == policy


def test_policy_is_closed_default_deny_and_portable(policy: dict) -> None:
    assert policy["effect"] == "deny_unless_explicitly_allowed"
    assert policy["policy_integrity"] == {
        "digest_algorithm": "sha256",
        "canonicalization": "rfc8785_json_canonicalization",
        "digest_format": "sha256_lowercase_hex",
        "digest_value_pattern": "^sha256:[0-9a-f]{64}$",
        "digest_source": "reviewed_published_policy_artifact",
        "constant_time_comparison_required": True,
        "request_digest_is_non_authoritative": True,
    }
    assert policy["portability"]["provider_adapter_required"] is True
    assert policy["portability"]["embedded_authority"] == "forbidden"
    serialized = json.dumps(policy, sort_keys=True)
    assert "*" not in serialized
    for pattern in FORBIDDEN_LITERAL_PATTERNS:
        assert not pattern.search(serialized)


def test_action_scope_catalog_is_exact_and_disjoint(policy: dict) -> None:
    actual = {item["id"]: item["scope"] for item in policy["actions"]}
    assert actual == EXPECTED_ACTION_SCOPES
    assert len(set(actual.values())) == len(actual)


def test_human_role_catalog_is_closed_and_least_privilege(policy: dict) -> None:
    roles = {role["id"]: role for role in policy["human_roles"]}
    assert set(roles) == EXPECTED_HUMAN_ROLES
    assert all(role["principal_type"] == "user" for role in roles.values())

    operator_permissions = roles["document_operator"]["permissions"]
    reviewer_permissions = roles["document_reviewer"]["permissions"]
    auditor_permissions = roles["auditor"]["permissions"]
    assert all("admin" not in permission["actions"] for permission in operator_permissions)
    assert all("admin" not in permission["actions"] for permission in reviewer_permissions)
    assert all(permission["actions"] == ["read"] for permission in auditor_permissions)
    assert all(
        set(permission["data_classes"]) <= {"metadata", "masked", "aggregated"}
        for permission in auditor_permissions
    )


def test_identity_contract_versions_cover_humans_services_and_policy_digest(
    policy: dict,
) -> None:
    identity = policy["identity"]
    assert identity["principal_types"] == ["user", "m2m"]
    assert set(identity["required_context_fields"]) == {
        "subject",
        "principal_type",
        "customer_id",
        "deployment_id",
    }
    assert identity["user_authorization_paths"] == ["membership", "temporary_grant"]
    assert identity["exactly_one_user_authorization_path"] is True
    assert set(identity["membership_user_required_context_fields"]) == {
        "membership_state",
        "role_id",
    }
    assert identity["required_authorizing_membership_state"] == "active"
    assert set(identity["temporary_grant_user_required_context_fields"]) == {
        "temporary_grant_type",
        "temporary_grant_state",
    }
    assert identity["required_authorizing_temporary_grant_state"] == "active"
    assert set(identity["m2m_required_context_fields"]) == {
        "workload_id",
        "environment",
    }
    assert set(identity["required_version_fields"]) == {
        "authz_schema_version",
        "scope_catalog_version",
        "policy_version",
        "policy_digest",
    }
    assert set(identity["membership_user_required_version_fields"]) == {
        "role_catalog_version",
        "membership_version",
    }
    assert identity["temporary_grant_user_required_version_fields"] == [
        "temporary_grant_version"
    ]
    assert set(identity["m2m_required_version_fields"]) == {"grant_version"}


def test_role_assignment_forbids_aggregation_and_untrusted_sources(policy: dict) -> None:
    assignments = policy["role_assignments"]
    assert assignments == {
        "max_roles_per_membership": 1,
        "role_aggregation": "forbidden",
        "unknown_role_behavior": "deny",
        "conflicting_role_behavior": "deny",
        "role_source": "authoritative_membership_store",
        "self_assignment": False,
    }

    reviewer = next(
        role for role in policy["human_roles"] if role["id"] == "document_reviewer"
    )
    reviewer_actions = {
        permission["resource"]: permission["actions"]
        for permission in reviewer["permissions"]
    }
    assert reviewer_actions["reviews"] == ["read", "write"]
    assert all(
        actions == ["read"]
        for resource, actions in reviewer_actions.items()
        if resource != "reviews"
    )
    assert all(
        set(permission["data_classes"]) <= {"metadata", "masked", "aggregated"}
        for permission in reviewer["permissions"]
    )


def test_abac_requires_exact_customer_and_deployment_and_object_authz(policy: dict) -> None:
    abac = policy["abac"]
    assert abac["exact_match_attributes"] == ["customer_id", "deployment_id"]
    assert abac["object_authorization_required"] is True
    assert abac["role_never_overrides_ownership"] is True
    assert set(abac["deny_reasons"]) >= {
        "missing",
        "malformed",
        "unknown",
        "stale",
        "conflicting",
        "foreign",
        "legacy_only",
    }


def test_sensitive_operations_preserve_read_plus_admin_and_step_up(policy: dict) -> None:
    operations = {item["id"]: item for item in policy["sensitive_operations"]}
    assert set(operations) == SENSITIVE_OPERATIONS
    for operation in operations.values():
        assert operation["required_actions"] == ["read", "admin"]
        assert operation["user_step_up_required"] is True
        assert operation["user_required_assurance"] == "phishing_resistant_mfa"
        assert operation["user_max_auth_age_seconds"] == 300
        assert operation["m2m_required_assurance"] == (
            "validated_client_credentials_binding"
        )
        assert operation["m2m_fresh_grant_check"] is True
        assert operation["user_fresh_membership_check"] is True


def test_catalog_versions_are_exact_and_provider_neutral(policy: dict) -> None:
    assert policy["catalog_versions"] == {
        "authz_schema_version": "enterprise-authorization.v1",
        "scope_catalog_version": "scanalyze.api.v1",
        "role_catalog_version": "enterprise-roles.v1",
    }


def test_authentication_recovery_is_provider_managed_and_non_authoritative(
    policy: dict,
) -> None:
    authentication = policy["authentication_lifecycle"]
    assert authentication["provider_managed_credentials"] is True
    assert authentication["application_password_storage"] is False
    assert authentication["static_default_passwords_forbidden"] is True
    assert authentication["minimum_password_length_if_enabled"] == 14
    assert authentication["compromised_password_detection_required"] is True
    assert authentication["privileged_phishing_resistant_mfa_required"] is True
    assert authentication["password_reset_generic_response_required"] is True
    assert authentication["password_reset_changes_authorization"] is False
    assert authentication["password_reset_revokes_sessions"] is True
    assert authentication["password_reset_fresh_membership_reconciliation"] is True
    assert authentication["password_reset_audit_required"] is True
    assert authentication["recovery_secrets_logging_forbidden"] is True
    assert authentication["federation_mode"] == "future_reviewed_adapter_only"
    assert authentication["scim_mode"] == "future_reviewed_adapter_only"


def test_service_principals_cannot_inherit_human_lifecycle_or_break_glass(policy: dict) -> None:
    service = policy["service_principals"]
    assert service["human_roles_forbidden"] is True
    assert service["lifecycle_administration_forbidden"] is True
    assert service["break_glass_forbidden"] is True
    assert service["default_actions"] == []
    assert service["binding_attributes"] == [
        "workload_id",
        "customer_id",
        "deployment_id",
        "environment",
    ]


def test_lifecycle_is_versioned_revocable_and_terminal(policy: dict) -> None:
    lifecycle = policy["human_lifecycle"]
    assert lifecycle["states"] == [
        "invited",
        "active",
        "suspended",
        "expired",
        "revoked",
    ]
    assert lifecycle["terminal_states"] == ["expired", "revoked"]
    assert lifecycle["role_change_increments_membership_version"] is True
    assert lifecycle["suspension_increments_membership_version"] is True
    assert lifecycle["revocation_increments_membership_version"] is True
    assert lifecycle["sensitive_change_revokes_sessions"] is True
    assert lifecycle["conditional_update_required"] is True
    assert lifecycle["privileged_change_step_up_required"] is True
    assert lifecycle["privileged_change_assurance"] == "phishing_resistant_mfa"
    assert lifecycle["privileged_change_max_auth_age_seconds"] == 300
    assert lifecycle["fresh_membership_check"] is True
    assert lifecycle["reactivate_revoked_membership"] is False
    assert lifecycle["last_admin_removal_requires_approved_replacement"] is True


def test_bootstrap_support_and_break_glass_are_fail_closed(policy: dict) -> None:
    invitation = policy["invitation_activation"]
    assert invitation["self_signup"] is False
    assert invitation["binding_attributes"] == [
        "subject",
        "customer_id",
        "deployment_id",
    ]
    assert invitation["single_use"] is True
    assert invitation["max_ttl_seconds"] == 86400
    assert invitation["conditional_consume_required"] is True
    assert invitation["replay_behavior"] == "deny"
    assert invitation["conflicting_subject_behavior"] == "deny"
    assert invitation["required_assurance"] == "phishing_resistant_mfa"
    assert invitation["max_auth_age_seconds"] == 300

    bootstrap = policy["bootstrap"]
    assert bootstrap["self_signup"] is False
    assert bootstrap["subject_binding_required"] is True
    assert bootstrap["single_use"] is True
    assert bootstrap["conditional_consume_required"] is True
    assert bootstrap["replay_behavior"] == "deny"
    assert bootstrap["expiry_required"] is True
    assert bootstrap["dual_approval"] is True
    assert bootstrap["independent_approvers"] is True
    assert bootstrap["self_approval"] is False
    assert bootstrap["phishing_resistant_mfa"] is True
    assert bootstrap["max_ttl_seconds"] == 900
    assert bootstrap["max_auth_age_seconds"] == 300
    assert bootstrap["audited"] is True

    temporary = policy["temporary_grants"]
    assert temporary["authority_source"] == "authoritative_temporary_grant_store"
    assert temporary["principal_type"] == "user"
    assert temporary["grant_types"] == ["support", "break_glass"]
    assert temporary["canonical_auth_context_required"] is True
    assert temporary["exactly_one_authorization_path"] is True
    assert temporary["role_assignment_or_inheritance"] == "forbidden"
    assert temporary["subject_customer_deployment_binding_required"] is True
    assert temporary["active_state_and_version_required"] is True
    assert temporary["operation_allowlist_required"] is True
    assert temporary["operation_catalog_source"] == "temporary_grant_operation_catalog"
    assert temporary["operation_catalog_binds_resource_actions_and_data_class"] is True
    assert temporary["data_class_allowlist_required"] is True
    assert temporary["unmapped_operation_behavior"] == "deny"
    assert temporary["unmapped_or_missing_data_class_behavior"] == "deny"
    assert temporary["explicit_deny_precedence"] is True
    assert temporary["sensitive_operations_behavior"] == "deny"

    temporary_operations = {
        operation["id"]: operation
        for operation in policy["temporary_grant_operation_catalog"]
    }
    assert set(temporary_operations) == {
        "documents.read_metadata",
        "batches.read_metadata",
        "results.read_masked",
        "reviews.read_metadata",
        "deployment_configuration.read",
        "metrics.read",
        "audit_log.read",
    }
    assert all(
        operation["required_actions"] == ["read"]
        for operation in temporary_operations.values()
    )
    assert all(
        set(operation["data_classes"]) <= {"metadata", "masked", "aggregated"}
        for operation in temporary_operations.values()
    )

    support = policy["support_access"]
    assert support["standing_access"] is False
    assert support["service_principal_allowed"] is False
    assert support["subject_binding_required"] is True
    assert support["customer_approval_required"] is True
    assert support["expiry_required"] is True
    assert support["operation_allowlist_required"] is True
    assert support["lifecycle_administration_forbidden"] is True
    assert support["ownership_change_forbidden"] is True
    assert support["privileged_grant_minting_forbidden"] is True
    assert support["pii_access_default"] == "deny"
    assert support["sensitive_operations_behavior"] == "deny"
    assert support["max_ttl_seconds"] == 3600
    assert support["max_auth_age_seconds"] == 300
    assert support["required_assurance"] == "phishing_resistant_mfa"
    assert support["auto_revoke"] is True
    assert support["revoke_on_expiry"] is True
    assert support["revoke_on_case_closure"] is True
    assert support["fresh_grant_state_and_version_check"] is True

    break_glass = policy["break_glass"]
    assert break_glass["standing_role"] is False
    assert break_glass["service_principal_allowed"] is False
    assert break_glass["subject_binding_required"] is True
    assert break_glass["incident_required"] is True
    assert break_glass["dual_approval"] is True
    assert break_glass["independent_approvers"] is True
    assert break_glass["phishing_resistant_mfa"] is True
    assert break_glass["expiry_required"] is True
    assert break_glass["operation_allowlist_required"] is True
    assert break_glass["lifecycle_administration_forbidden"] is True
    assert break_glass["ownership_change_forbidden"] is True
    assert break_glass["privileged_grant_minting_forbidden"] is True
    assert break_glass["auto_revoke"] is True
    assert break_glass["activation_alert_required"] is True
    assert break_glass["use_alert_required"] is True
    assert break_glass["fresh_grant_state_and_version_check"] is True
    assert break_glass["post_event_review"] is True
    assert break_glass["sensitive_operations_behavior"] == "deny"
    assert break_glass["max_ttl_seconds"] == 900
    assert break_glass["max_auth_age_seconds"] == 300
    assert set(break_glass["default_forbidden_operations"]) == SENSITIVE_OPERATIONS

    audit = policy["audit"]
    assert audit["raw_identity_values_forbidden"] is True
    assert audit["append_only"] is True
    assert audit["integrity_protection_required"] is True
    assert audit["deployment_partitioning_required"] is True
    assert set(audit["membership_user_required_fields"]) == {
        "membership_version",
        "role_catalog_version",
    }
    assert set(audit["temporary_grant_user_required_fields"]) == {
        "temporary_grant_type",
        "temporary_grant_version",
        "temporary_grant_state",
        "grant_reference",
    }
    assert audit["m2m_required_fields"] == ["grant_version"]
    assert set(audit["lifecycle_change_required_fields"]) == {
        "approval_references",
        "before_membership_version",
        "after_membership_version",
    }
    assert set(audit["support_required_fields"]) == {
        "case_reference",
        "approval_references",
        "grant_reference",
    }
    assert set(audit["break_glass_required_fields"]) == {
        "incident_reference",
        "approval_references",
        "grant_reference",
    }
    assert set(audit["forbidden_fields"]) >= {
        "tokens",
        "cookies",
        "raw_claims",
        "invitation_secrets",
        "mfa_values",
        "request_bodies",
        "document_contents",
        "pii_payloads",
        "object_keys",
        "presigned_urls",
    }


@pytest.mark.parametrize(
    ("mutator", "expected"),
    (
        (lambda p: p.__setitem__("effect", "allow_unless_denied"), "default deny"),
        (
            lambda p: p["abac"].__setitem__("exact_match_attributes", ["customer_id"]),
            "customer_id and deployment_id",
        ),
        (
            lambda p: p["service_principals"].__setitem__(
                "lifecycle_administration_forbidden", False
            ),
            "service principals",
        ),
        (
            lambda p: p["human_lifecycle"].__setitem__(
                "sensitive_change_revokes_sessions", False
            ),
            "revoke sessions",
        ),
        (
            lambda p: p["break_glass"].__setitem__("standing_role", True),
            "break-glass",
        ),
        (
            lambda p: p["sensitive_operations"][0].__setitem__(
                "required_actions", ["admin"]
            ),
            "read and admin",
        ),
        (
            lambda p: p["identity"]["m2m_required_version_fields"].remove(
                "grant_version"
            ),
            "m2m authorization and grant versions",
        ),
        (
            lambda p: p["human_roles"][0]["permissions"][0].__setitem__(
                "resource", "unknown_resource"
            ),
            "declared resources",
        ),
        (
            lambda p: p["resources"][0].__setitem__(
                "ownership_attributes", ["customer_id"]
            ),
            "customer_id and deployment_id",
        ),
        (
            lambda p: p["support_access"].__setitem__("standing_access", True),
            "support access",
        ),
        (
            lambda p: p["migration"].__setitem__("accepted_versions", []),
            "explicit allowlist",
        ),
        (
            lambda p: p["actions"][0].__setitem__(
                "description", "Wildcard authority is not permitted: *"
            ),
            "wildcard authority",
        ),
        (
            lambda p: p["role_assignments"].__setitem__(
                "max_roles_per_membership", 2
            ),
            "role aggregation",
        ),
        (
            lambda p: p["human_lifecycle"].__setitem__(
                "privileged_change_step_up_required", False
            ),
            "privileged lifecycle changes",
        ),
        (
            lambda p: p["audit"].__setitem__(
                "raw_identity_values_forbidden", False
            ),
            "audit evidence",
        ),
        (
            lambda p: p["identity"].__setitem__(
                "required_authorizing_membership_state", "suspended"
            ),
            "only active human memberships",
        ),
        (
            lambda p: _set_transition_approval(p, "invited", "active", False),
            "transitions and approvals",
        ),
        (
            lambda p: _set_transition_approval(p, "active", "suspended", False),
            "transitions and approvals",
        ),
        (
            _duplicate_invitation_activation_transition,
            "transitions must be unique",
        ),
        (_grant_operator_pii, "permission and data-class catalogs"),
        (_extend_v1_resource_catalog, "resource catalog and action sets"),
        (
            lambda p: p["invitation_activation"].__setitem__(
                "conditional_consume_required", False
            ),
            "invitation activation",
        ),
        (
            lambda p: p["invitation_activation"].__setitem__(
                "replay_behavior", "allow"
            ),
            "invitation replay",
        ),
        (
            lambda p: p["support_access"].__setitem__(
                "max_ttl_seconds", 86400
            ),
            "support access requires bounded TTL",
        ),
        (
            lambda p: p["break_glass"].__setitem__(
                "sensitive_operations_behavior", "allow"
            ),
            "break-glass must deny sensitive operations",
        ),
        (
            lambda p: p["sensitive_operations"][0].__setitem__(
                "m2m_fresh_grant_check", False
            ),
            "fresh grants",
        ),
        (
            lambda p: p["policy_integrity"].__setitem__(
                "digest_algorithm", "sha1"
            ),
            "SHA-256",
        ),
        (
            lambda p: p["audit"]["support_required_fields"].remove(
                "approval_references"
            ),
            "support audit events",
        ),
        (
            lambda p: p["audit"]["required_events"].remove("break_glass_use"),
            "audit events must cover",
        ),
        (
            lambda p: p["audit"]["required_fields"].append(
                "authorization_header"
            ),
            "audit decisions must carry",
        ),
        (
            lambda p: p["audit"]["forbidden_fields"].append("decision_id"),
            "required and forbidden fields must be disjoint",
        ),
        (
            lambda p: p["catalog_versions"].__setitem__(
                "role_catalog_version", "enterprise-roles.v2"
            ),
            "catalog versions must remain exact",
        ),
        (
            lambda p: p["identity"]["required_version_fields"].__setitem__(
                3, "unreviewed_version"
            ),
            "common authorization and policy versions must be explicit",
        ),
        (
            lambda p: p["temporary_grants"].__setitem__(
                "unmapped_operation_behavior", "allow"
            ),
            "closed operation catalog",
        ),
        (
            lambda p: p["temporary_grant_operation_catalog"][0][
                "required_actions"
            ].__setitem__(0, "write"),
            "temporary grant operation catalog must remain exact and read-only",
        ),
    ),
)
def test_semantic_validator_rejects_security_regressions(
    policy: dict,
    mutator,
    expected: str,
) -> None:
    invalid = copy.deepcopy(policy)
    mutator(invalid)
    assert any(expected in error for error in validate_enterprise_authorization(invalid))


def test_documentation_closes_gug92_acceptance_contract() -> None:
    for path in (ADR_PATH, REFERENCE_PATH, NOTEBOOK_PATH):
        assert path.is_file(), f"missing GUG-92 artifact: {path}"

    adr = ADR_PATH.read_text(encoding="utf-8")
    reference = REFERENCE_PATH.read_text(encoding="utf-8")
    assert all(issue in adr for issue in ("GUG-93", "GUG-94", "GUG-95", "GUG-117", "GUG-153"))
    assert adr.count("sequenceDiagram") >= 3
    assert "Production: NO-GO" in adr
    assert "customer_id" in reference and "deployment_id" in reference
    assert all(
        resource in reference
        for resource in (
            "documents",
            "batches",
            "results",
            "reviews",
            "exports",
            "deployment_configuration",
            "metrics",
            "authorization_administration",
        )
    )
    assert "Password reset" in reference and "SCIM" in reference
    assert "Implemented" in reference and "Live validated" in reference
