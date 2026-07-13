#!/usr/bin/env python3
"""Fail-closed semantic validation for enterprise authorization policy v1.

The JSON Schema validates shape and closed vocabularies. This module validates
catalog integrity and cross-field security invariants without echoing policy or
identity values in error messages.
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any


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
EXPECTED_RESOURCES = {
    "documents": ["read", "write", "admin"],
    "batches": ["read", "write", "admin"],
    "employee_profiles": ["read", "write", "admin"],
    "results": ["read", "admin"],
    "reviews": ["read", "write", "admin"],
    "exports": ["read", "admin"],
    "deployment_configuration": ["read", "admin"],
    "metrics": ["read", "admin"],
    "authorization_administration": ["read", "admin"],
    "audit_log": ["read"],
}
EXPECTED_TEMPORARY_GRANT_OPERATIONS = {
    "documents.read_metadata": ("documents", ["read"], ["metadata"]),
    "batches.read_metadata": ("batches", ["read"], ["metadata"]),
    "results.read_masked": ("results", ["read"], ["metadata", "masked"]),
    "reviews.read_metadata": ("reviews", ["read"], ["metadata"]),
    "deployment_configuration.read": (
        "deployment_configuration",
        ["read"],
        ["metadata"],
    ),
    "metrics.read": ("metrics", ["read"], ["metadata", "aggregated"]),
    "audit_log.read": ("audit_log", ["read"], ["metadata"]),
}
EXPECTED_ROLE_PERMISSIONS = {
    "customer_admin": {
        "documents": (["read", "write", "admin"], ["metadata", "masked", "content", "pii"]),
        "batches": (["read", "write", "admin"], ["metadata", "masked", "content", "pii"]),
        "employee_profiles": (["read", "write", "admin"], ["metadata", "masked", "content", "pii"]),
        "results": (["read", "admin"], ["metadata", "masked", "content", "pii"]),
        "reviews": (["read", "write", "admin"], ["metadata", "masked", "content"]),
        "exports": (["read", "admin"], ["metadata", "content", "pii"]),
        "deployment_configuration": (["read", "admin"], ["metadata"]),
        "metrics": (["read", "admin"], ["metadata", "aggregated"]),
        "authorization_administration": (["read", "admin"], ["metadata"]),
        "audit_log": (["read"], ["metadata"]),
    },
    "document_operator": {
        "documents": (["read", "write"], ["metadata", "masked", "content"]),
        "batches": (["read", "write"], ["metadata", "masked", "content"]),
        "employee_profiles": (["read", "write"], ["metadata", "masked"]),
        "results": (["read"], ["metadata", "masked"]),
        "reviews": (["read"], ["metadata", "masked"]),
        "metrics": (["read"], ["metadata", "aggregated"]),
    },
    "document_reviewer": {
        "documents": (["read"], ["metadata", "masked"]),
        "batches": (["read"], ["metadata", "masked"]),
        "employee_profiles": (["read"], ["metadata", "masked"]),
        "results": (["read"], ["metadata", "masked"]),
        "reviews": (["read", "write"], ["metadata", "masked"]),
    },
    "auditor": {
        "audit_log": (["read"], ["metadata"]),
        "metrics": (["read"], ["metadata", "aggregated"]),
    },
}
EXPECTED_SENSITIVE_OPERATIONS = {
    "results.read_full",
    "exports.execute",
    "artifacts.download",
}
EXPECTED_STATES = ["invited", "active", "suspended", "expired", "revoked"]
EXPECTED_TERMINAL_STATES = ["expired", "revoked"]
EXPECTED_TRANSITIONS = {
    ("invited", "active"): True,
    ("invited", "expired"): False,
    ("invited", "revoked"): True,
    ("active", "suspended"): True,
    ("active", "revoked"): True,
    ("suspended", "active"): True,
    ("suspended", "revoked"): True,
}
EXPECTED_OWNERSHIP_ATTRIBUTES = ["customer_id", "deployment_id"]
EXPECTED_SERVICE_BINDING = [
    "workload_id",
    "customer_id",
    "deployment_id",
    "environment",
]
REQUIRED_DENY_REASONS = {
    "missing",
    "malformed",
    "unknown",
    "stale",
    "conflicting",
    "foreign",
    "legacy_only",
}
REQUIRED_AUDIT_EVENTS = {
    "bootstrap",
    "invitation",
    "activation",
    "role_change",
    "suspension",
    "revocation",
    "service_grant_change",
    "authorization_allow",
    "authorization_denial",
    "sensitive_access",
    "support_activation",
    "support_use",
    "break_glass_activation",
    "break_glass_use",
}
REQUIRED_AUDIT_FIELDS = {
    "event_schema_version",
    "timestamp",
    "decision_id",
    "principal_type",
    "principal_reference",
    "customer_reference",
    "deployment_reference",
    "action",
    "resource_type",
    "decision",
    "reason_code",
    "policy_version",
    "policy_digest",
    "assurance",
    "correlation_reference",
}
REQUIRED_MEMBERSHIP_USER_AUDIT_FIELDS = {
    "membership_version",
    "role_catalog_version",
}
REQUIRED_TEMPORARY_GRANT_USER_AUDIT_FIELDS = {
    "temporary_grant_type",
    "temporary_grant_version",
    "temporary_grant_state",
    "grant_reference",
}
REQUIRED_M2M_AUDIT_FIELDS = {"grant_version"}
REQUIRED_LIFECYCLE_AUDIT_FIELDS = {
    "approval_references",
    "before_membership_version",
    "after_membership_version",
}
REQUIRED_SUPPORT_AUDIT_FIELDS = {
    "case_reference",
    "approval_references",
    "grant_reference",
}
REQUIRED_BREAK_GLASS_AUDIT_FIELDS = {
    "incident_reference",
    "approval_references",
    "grant_reference",
}
REQUIRED_FORBIDDEN_AUDIT_FIELDS = {
    "tokens",
    "cookies",
    "secrets",
    "raw_claims",
    "invitation_secrets",
    "mfa_values",
    "request_bodies",
    "document_contents",
    "pii_payloads",
    "object_keys",
    "presigned_urls",
}
FORBIDDEN_PORTABILITY_PATTERNS = (
    re.compile(r"\b\d{12}\b"),
    re.compile(r"\barn:(?:aws|aws-us-gov|aws-cn):"),
    re.compile(r"\b(?:us|eu|ap|sa|ca|me|af)-(?:gov-)?[a-z]+-\d\b"),
    re.compile(r"\b(?:cust|dep)_[0-9A-HJKMNP-TV-Z]{26}\b"),
    re.compile(r"\b[a-z]{2}-[a-z]+-\d_[A-Za-z0-9]+\b"),
)


class DuplicateKeyError(ValueError):
    """Raised when JSON contains an ambiguous duplicate object key."""


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise DuplicateKeyError("duplicate JSON object key")
        result[key] = value
    return result


def load_json_without_duplicates(path: Path) -> dict[str, Any]:
    """Load one JSON object while rejecting duplicate keys fail closed."""
    value = json.loads(
        path.read_text(encoding="utf-8"), object_pairs_hook=_reject_duplicate_keys
    )
    if not isinstance(value, dict):
        raise ValueError("JSON root must be an object")
    return value


def _mapping(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _sequence(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _strings(value: Any) -> list[str]:
    return [item for item in _sequence(value) if isinstance(item, str)]


def _ids(items: Any) -> list[str]:
    return [
        item["id"]
        for item in _sequence(items)
        if isinstance(item, dict) and isinstance(item.get("id"), str)
    ]


def _require_true(
    section: dict[str, Any], fields: tuple[str, ...], message: str, errors: list[str]
) -> None:
    if any(section.get(field) is not True for field in fields):
        errors.append(message)


def _require_false(
    section: dict[str, Any], fields: tuple[str, ...], message: str, errors: list[str]
) -> None:
    if any(section.get(field) is not False for field in fields):
        errors.append(message)


def validate_enterprise_authorization(policy: dict[str, Any]) -> list[str]:
    """Return sanitized cross-field errors for an enterprise policy instance."""
    errors: list[str] = []
    if not isinstance(policy, dict):
        return ["policy must be an object"]

    if policy.get("effect") != "deny_unless_explicitly_allowed":
        errors.append("policy must enforce default deny")
    if policy.get("schema_version") != "enterprise-authorization.v1":
        errors.append("policy must use the supported authorization schema version")
    if _mapping(policy.get("catalog_versions")) != {
        "authz_schema_version": "enterprise-authorization.v1",
        "scope_catalog_version": "scanalyze.api.v1",
        "role_catalog_version": "enterprise-roles.v1",
    }:
        errors.append("authorization, scope, and role catalog versions must remain exact")

    integrity = _mapping(policy.get("policy_integrity"))
    if integrity.get("digest_algorithm") != "sha256" or integrity.get(
        "canonicalization"
    ) != "rfc8785_json_canonicalization":
        errors.append("policy digest must use SHA-256 over RFC 8785 canonical JSON")
    if (
        integrity.get("digest_format") != "sha256_lowercase_hex"
        or integrity.get("digest_value_pattern") != "^sha256:[0-9a-f]{64}$"
        or integrity.get("digest_source") != "reviewed_published_policy_artifact"
    ):
        errors.append("policy digest format and source must remain exact")
    _require_true(
        integrity,
        (
            "constant_time_comparison_required",
            "request_digest_is_non_authoritative",
        ),
        "policy digest comparison must be constant-time and request-independent",
        errors,
    )

    serialized = json.dumps(policy, sort_keys=True, separators=(",", ":"))
    if "*" in serialized:
        errors.append("policy must not contain wildcard authority")
    if any(pattern.search(serialized) for pattern in FORBIDDEN_PORTABILITY_PATTERNS):
        errors.append("policy must not embed account, region, provider, or tenant authority")

    portability = _mapping(policy.get("portability"))
    _require_true(
        portability,
        ("provider_adapter_required", "environment_neutral", "account_region_neutral"),
        "portable policy requires a provider adapter and neutral bindings",
        errors,
    )

    authentication = _mapping(policy.get("authentication_lifecycle"))
    _require_true(
        authentication,
        (
            "provider_managed_credentials",
            "static_default_passwords_forbidden",
            "compromised_password_detection_required",
            "privileged_phishing_resistant_mfa_required",
            "password_reset_generic_response_required",
            "password_reset_revokes_sessions",
            "password_reset_fresh_membership_reconciliation",
            "password_reset_audit_required",
            "recovery_secrets_logging_forbidden",
        ),
        "authentication lifecycle must use managed credentials and fail-closed recovery",
        errors,
    )
    _require_false(
        authentication,
        ("application_password_storage", "password_reset_changes_authorization"),
        "application credentials and password reset must never become authorization",
        errors,
    )
    if authentication.get("minimum_password_length_if_enabled") != 14:
        errors.append("password authentication must meet the portable minimum length")
    if authentication.get("federation_mode") != "future_reviewed_adapter_only" or (
        authentication.get("scim_mode") != "future_reviewed_adapter_only"
    ):
        errors.append("federation and SCIM remain future reviewed adapters")
    if portability.get("embedded_authority") != "forbidden":
        errors.append("portable policy must forbid embedded authority")
    trusted_sources = set(_strings(portability.get("trusted_authority_sources")))
    if trusted_sources != {
        "validated_auth_context",
        "authoritative_membership_store",
        "authoritative_temporary_grant_store",
        "stored_object_metadata",
    }:
        errors.append("authority sources must be closed and server validated")
    forbidden_sources = set(_strings(portability.get("forbidden_authority_sources")))
    if not {
        "request_headers",
        "query_parameters",
        "path_parameters",
        "payload_fields",
        "email_domains",
        "provider_group_names",
        "legacy_aliases",
        "request_object_keys",
    } <= forbidden_sources:
        errors.append("request and legacy identity sources must remain non-authoritative")

    identity = _mapping(policy.get("identity"))
    _require_true(
        identity,
        ("access_token_only", "id_tokens_forbidden"),
        "protected APIs must accept access tokens and reject ID tokens",
        errors,
    )
    if identity.get("principal_types") != ["user", "m2m"]:
        errors.append("principal types must remain closed and unambiguous")
    if any(
        identity.get(field) != "deny"
        for field in (
            "unknown_version_behavior",
            "stale_grant_behavior",
            "conflicting_claims_behavior",
        )
    ):
        errors.append("unknown, stale, or conflicting identity context must deny")
    if set(_strings(identity.get("required_context_fields"))) != {
        "subject",
        "principal_type",
        "customer_id",
        "deployment_id",
    }:
        errors.append("common identity context must bind subject, customer, and deployment")
    if identity.get("user_authorization_paths") != [
        "membership",
        "temporary_grant",
    ] or identity.get("exactly_one_user_authorization_path") is not True:
        errors.append("user authorization must select exactly one closed decision path")
    if set(_strings(identity.get("membership_user_required_context_fields"))) != {
        "membership_state",
        "role_id",
    }:
        errors.append("membership user context must bind active state and one role")
    if identity.get("required_authorizing_membership_state") != "active":
        errors.append("only active human memberships may authorize")
    if set(
        _strings(identity.get("temporary_grant_user_required_context_fields"))
    ) != {"temporary_grant_type", "temporary_grant_state"} or (
        identity.get("required_authorizing_temporary_grant_state") != "active"
    ):
        errors.append("temporary user grants must bind an active grant type and state")
    if set(_strings(identity.get("m2m_required_context_fields"))) != {
        "workload_id",
        "environment",
    }:
        errors.append("m2m context must bind workload and environment")
    if set(_strings(identity.get("required_version_fields"))) != {
        "authz_schema_version",
        "scope_catalog_version",
        "policy_version",
        "policy_digest",
    }:
        errors.append("common authorization and policy versions must be explicit")
    if set(_strings(identity.get("membership_user_required_version_fields"))) != {
        "role_catalog_version",
        "membership_version",
    }:
        errors.append("membership authorization versions must be explicit")
    if set(
        _strings(identity.get("temporary_grant_user_required_version_fields"))
    ) != {"temporary_grant_version"}:
        errors.append("temporary grant authorization version must be explicit")
    if set(_strings(identity.get("m2m_required_version_fields"))) != {
        "grant_version"
    }:
        errors.append("m2m authorization and grant versions must be explicit")
    if identity.get("membership_binding_attributes") != [
        "subject",
        "customer_id",
        "deployment_id",
        "membership_version",
    ]:
        errors.append("human membership must bind subject, customer, deployment, and version")

    actions = _sequence(policy.get("actions"))
    action_ids = _ids(actions)
    if len(action_ids) != len(set(action_ids)):
        errors.append("action identifiers must be unique")
    actual_scopes = {
        action.get("id"): action.get("scope")
        for action in actions
        if isinstance(action, dict)
    }
    if actual_scopes != EXPECTED_ACTION_SCOPES:
        errors.append("action and scope catalogs must remain exact and disjoint")

    resources = _sequence(policy.get("resources"))
    resource_ids = _ids(resources)
    if len(resource_ids) != len(set(resource_ids)):
        errors.append("resource identifiers must be unique")
    actual_resources = {
        resource.get("id"): _strings(resource.get("allowed_actions"))
        for resource in resources
        if isinstance(resource, dict)
    }
    if actual_resources != EXPECTED_RESOURCES:
        errors.append("resource catalog and action sets must remain exact for v1")
    for resource in resources:
        if not isinstance(resource, dict):
            continue
        if resource.get("ownership_required") is not True:
            errors.append("every protected resource must require object ownership")
        if resource.get("ownership_attributes") != EXPECTED_OWNERSHIP_ATTRIBUTES:
            errors.append("resource ownership must require customer_id and deployment_id")

    roles = _sequence(policy.get("human_roles"))
    role_ids = _ids(roles)
    if set(role_ids) != EXPECTED_HUMAN_ROLES or len(role_ids) != len(set(role_ids)):
        errors.append("human role catalog must be exact and unique")
    roles_by_id = {
        role.get("id"): role for role in roles if isinstance(role, dict)
    }
    for role in roles:
        if not isinstance(role, dict):
            continue
        if role.get("principal_type") != "user":
            errors.append("human roles may only be assigned to user principals")
        actual_permissions: dict[str, tuple[list[str], list[str]]] = {}
        for permission in _sequence(role.get("permissions")):
            if not isinstance(permission, dict):
                continue
            resource_id = permission.get("resource")
            if resource_id not in EXPECTED_RESOURCES:
                errors.append("role permissions must reference declared resources")
                continue
            if resource_id in actual_permissions:
                errors.append("role permissions must not duplicate resources")
            actual_permissions[resource_id] = (
                _strings(permission.get("actions")),
                _strings(permission.get("data_classes")),
            )
        if actual_permissions != EXPECTED_ROLE_PERMISSIONS.get(role.get("id"), {}):
            errors.append("role permission and data-class catalogs must remain exact for v1")

    role_assignments = _mapping(policy.get("role_assignments"))
    if role_assignments.get("max_roles_per_membership") != 1 or role_assignments.get(
        "role_aggregation"
    ) != "forbidden":
        errors.append("human role aggregation must be forbidden")
    if role_assignments.get("unknown_role_behavior") != "deny" or role_assignments.get(
        "conflicting_role_behavior"
    ) != "deny":
        errors.append("unknown or conflicting human roles must deny")
    if role_assignments.get("role_source") != "authoritative_membership_store":
        errors.append("human roles must come from the authoritative membership store")
    if role_assignments.get("self_assignment") is not False:
        errors.append("human role self-assignment must be forbidden")

    service = _mapping(policy.get("service_principals"))
    _require_true(
        service,
        (
            "one_binding_per_workload_boundary",
            "human_roles_forbidden",
            "human_impersonation_forbidden",
            "lifecycle_administration_forbidden",
            "break_glass_forbidden",
            "explicit_action_grant_required",
        ),
        "service principals must be explicitly bound and excluded from human privileges",
        errors,
    )
    if service.get("credential_flow") != "oauth2_client_credentials":
        errors.append("service principals must use the confidential client flow")
    if service.get("binding_attributes") != EXPECTED_SERVICE_BINDING:
        errors.append("service principals must bind workload, customer, deployment, and environment")
    if service.get("default_actions") != []:
        errors.append("service principals must have no default actions")

    abac = _mapping(policy.get("abac"))
    if abac.get("exact_match_attributes") != EXPECTED_OWNERSHIP_ATTRIBUTES:
        errors.append("ABAC must match customer_id and deployment_id exactly")
    _require_true(
        abac,
        (
            "object_authorization_required",
            "role_never_overrides_ownership",
            "request_identity_is_non_authoritative",
        ),
        "RBAC must not override object ownership or request authority boundaries",
        errors,
    )
    if set(_strings(abac.get("deny_reasons"))) != REQUIRED_DENY_REASONS:
        errors.append("all malformed, foreign, stale, conflicting, and legacy ownership must deny")

    operations = _sequence(policy.get("sensitive_operations"))
    operation_ids = _ids(operations)
    if set(operation_ids) != EXPECTED_SENSITIVE_OPERATIONS or len(operation_ids) != len(
        set(operation_ids)
    ):
        errors.append("sensitive operation catalog must be exact and unique")
    for operation in operations:
        if not isinstance(operation, dict):
            continue
        if operation.get("required_actions") != ["read", "admin"]:
            errors.append("sensitive operations must require read and admin")
        _require_true(
            operation,
            (
                "user_step_up_required",
                "m2m_fresh_grant_check",
                "user_fresh_membership_check",
                "audit_required",
            ),
            "sensitive operations require user step-up, fresh grants, and audit",
            errors,
        )

    temporary_operations = _sequence(policy.get("temporary_grant_operation_catalog"))
    actual_temporary_operations = {
        operation.get("id"): (
            operation.get("resource"),
            _strings(operation.get("required_actions")),
            _strings(operation.get("data_classes")),
        )
        for operation in temporary_operations
        if isinstance(operation, dict)
    }
    if actual_temporary_operations != EXPECTED_TEMPORARY_GRANT_OPERATIONS or (
        len(temporary_operations) != len(EXPECTED_TEMPORARY_GRANT_OPERATIONS)
    ):
        errors.append("temporary grant operation catalog must remain exact and read-only")
        if operation.get("user_required_assurance") != "phishing_resistant_mfa" or (
            operation.get("user_max_auth_age_seconds") != 300
        ):
            errors.append("sensitive user operations require recent phishing-resistant MFA")
        if (
            operation.get("m2m_required_assurance")
            != "validated_client_credentials_binding"
        ):
            errors.append("sensitive m2m operations require a validated workload binding")

    lifecycle = _mapping(policy.get("human_lifecycle"))
    if lifecycle.get("states") != EXPECTED_STATES:
        errors.append("human lifecycle states must remain exact")
    if lifecycle.get("terminal_states") != EXPECTED_TERMINAL_STATES:
        errors.append("expired and revoked memberships must remain terminal")
    transition_items = [
        transition
        for transition in _sequence(lifecycle.get("transitions"))
        if isinstance(transition, dict)
    ]
    transitions: dict[tuple[Any, Any], Any] = {}
    for transition in transition_items:
        key = (transition.get("from"), transition.get("to"))
        if key in transitions:
            errors.append("human lifecycle transitions must be unique")
        transitions[key] = transition.get("approval_required")
    if transitions != EXPECTED_TRANSITIONS or len(transition_items) != len(
        EXPECTED_TRANSITIONS
    ):
        errors.append("human lifecycle transitions and approvals must remain exact")
    if any(
        _mapping(transition).get("audit_required") is not True
        for transition in _sequence(lifecycle.get("transitions"))
    ):
        errors.append("every lifecycle transition must be audited")
    _require_true(
        lifecycle,
        (
            "role_change_increments_membership_version",
            "suspension_increments_membership_version",
            "revocation_increments_membership_version",
        ),
        "role, suspension, and revocation changes must increment membership version",
        errors,
    )
    if lifecycle.get("sensitive_change_revokes_sessions") is not True:
        errors.append("sensitive lifecycle changes must revoke sessions")
    _require_true(
        lifecycle,
        (
            "conditional_update_required",
            "privileged_change_step_up_required",
            "fresh_membership_check",
        ),
        "privileged lifecycle changes require conditional updates, step-up, and fresh membership",
        errors,
    )
    if lifecycle.get("privileged_change_assurance") != "phishing_resistant_mfa":
        errors.append("privileged lifecycle changes require phishing-resistant MFA")
    if lifecycle.get("privileged_change_max_auth_age_seconds") != 300:
        errors.append("privileged lifecycle changes require recent authentication")
    _require_false(
        lifecycle,
        ("reactivate_revoked_membership", "self_promotion_allowed"),
        "revoked membership reactivation and self-promotion must be forbidden",
        errors,
    )
    if lifecycle.get("last_admin_removal_requires_approved_replacement") is not True:
        errors.append("last administrator removal requires an approved replacement")

    invitation = _mapping(policy.get("invitation_activation"))
    _require_false(
        invitation,
        ("self_signup",),
        "invitation activation must forbid self-signup",
        errors,
    )
    _require_true(
        invitation,
        (
            "single_use",
            "expiry_required",
            "conditional_consume_required",
            "provider_membership_reconciliation_required",
            "audit_required",
            "secret_logging_forbidden",
        ),
        "invitation activation must be single-use, atomic, reconciled, and audited",
        errors,
    )
    if invitation.get("binding_attributes") != [
        "subject",
        "customer_id",
        "deployment_id",
    ]:
        errors.append("invitation activation must bind subject, customer, and deployment")
    if invitation.get("replay_behavior") != "deny" or invitation.get(
        "conflicting_subject_behavior"
    ) != "deny":
        errors.append("invitation replay and conflicting subjects must deny")
    if (
        invitation.get("required_assurance") != "phishing_resistant_mfa"
        or invitation.get("max_auth_age_seconds") != 300
        or invitation.get("max_ttl_seconds") != 86400
    ):
        errors.append("invitation activation requires bounded TTL and recent strong MFA")

    bootstrap = _mapping(policy.get("bootstrap"))
    _require_false(
        bootstrap,
        ("self_signup", "self_approval"),
        "bootstrap must forbid self-signup and self-approval",
        errors,
    )
    _require_true(
        bootstrap,
        (
            "single_use",
            "subject_binding_required",
            "conditional_consume_required",
            "time_bound",
            "expiry_required",
            "dual_approval",
            "independent_approvers",
            "phishing_resistant_mfa",
            "consumed_on_success",
            "audited",
        ),
        "bootstrap must be single-use, approved, time-bound, MFA-protected, and audited",
        errors,
    )
    if bootstrap.get("binding_attributes") != EXPECTED_OWNERSHIP_ATTRIBUTES:
        errors.append("bootstrap must bind customer_id and deployment_id exactly")
    if bootstrap.get("replay_behavior") != "deny":
        errors.append("bootstrap consumption must be atomic and deny replay")
    if bootstrap.get("max_ttl_seconds") != 900 or bootstrap.get(
        "max_auth_age_seconds"
    ) != 300:
        errors.append("bootstrap requires bounded TTL and recent authentication")

    temporary_grants = _mapping(policy.get("temporary_grants"))
    if temporary_grants.get("authority_source") != (
        "authoritative_temporary_grant_store"
    ) or temporary_grants.get("principal_type") != "user":
        errors.append("temporary grants require an authoritative human grant store")
    if temporary_grants.get("grant_types") != ["support", "break_glass"]:
        errors.append("temporary grant types must remain exact and ordered")
    _require_true(
        temporary_grants,
        (
            "canonical_auth_context_required",
            "exactly_one_authorization_path",
            "subject_customer_deployment_binding_required",
            "active_state_and_version_required",
            "operation_allowlist_required",
            "operation_catalog_binds_resource_actions_and_data_class",
            "data_class_allowlist_required",
            "explicit_deny_precedence",
        ),
        "temporary grants require a bound, current, deny-precedence decision path",
        errors,
    )
    if temporary_grants.get("operation_catalog_source") != (
        "temporary_grant_operation_catalog"
    ) or temporary_grants.get("unmapped_operation_behavior") != "deny":
        errors.append("temporary grant operations must use the closed operation catalog")
    if temporary_grants.get("unmapped_or_missing_data_class_behavior") != "deny":
        errors.append("temporary grants must deny unmapped or missing data classes")
    if temporary_grants.get("role_assignment_or_inheritance") != "forbidden" or any(
        temporary_grants.get(field) != "deny"
        for field in (
            "sensitive_operations_behavior",
            "unknown_or_conflicting_grant_behavior",
        )
    ):
        errors.append("temporary grants cannot bypass roles or explicit denials")

    support = _mapping(policy.get("support_access"))
    _require_false(
        support,
        ("standing_access", "service_principal_allowed"),
        "support access must never be standing or assigned to service principals",
        errors,
    )
    _require_true(
        support,
        (
            "subject_binding_required",
            "ticket_required",
            "customer_approval_required",
            "time_bound",
            "expiry_required",
            "operation_allowlist_required",
            "lifecycle_administration_forbidden",
            "ownership_change_forbidden",
            "privileged_grant_minting_forbidden",
            "auto_revoke",
            "revoke_on_expiry",
            "revoke_on_case_closure",
            "fresh_grant_state_and_version_check",
            "audited",
        ),
        "support access must be approved, ticketed, time-bound, revoked, and audited",
        errors,
    )
    if support.get("scope_attributes") != EXPECTED_OWNERSHIP_ATTRIBUTES:
        errors.append("support access must bind customer_id and deployment_id exactly")
    if support.get("pii_access_default") != "deny" or support.get(
        "export_access_default"
    ) != "deny":
        errors.append("support access must deny PII and export by default")
    if support.get("sensitive_operations_behavior") != "deny":
        errors.append("support access must deny sensitive operations in v1")
    if support.get("max_ttl_seconds") != 3600 or support.get(
        "max_auth_age_seconds"
    ) != 300:
        errors.append("support access requires bounded TTL and recent authentication")
    if support.get("required_assurance") != "phishing_resistant_mfa":
        errors.append("support access requires phishing-resistant MFA")

    break_glass = _mapping(policy.get("break_glass"))
    _require_false(
        break_glass,
        ("standing_role", "service_principal_allowed", "self_approval"),
        "break-glass must forbid standing, service, and self-approved access",
        errors,
    )
    _require_true(
        break_glass,
        (
            "subject_binding_required",
            "incident_required",
            "dual_approval",
            "independent_approvers",
            "phishing_resistant_mfa",
            "time_bound",
            "expiry_required",
            "operation_allowlist_required",
            "lifecycle_administration_forbidden",
            "ownership_change_forbidden",
            "privileged_grant_minting_forbidden",
            "auto_revoke",
            "activation_alert_required",
            "use_alert_required",
            "fresh_grant_state_and_version_check",
            "post_event_review",
            "audited",
        ),
        "break-glass must be incident-bound, approved, time-bound, revoked, and reviewed",
        errors,
    )
    if break_glass.get("scope_attributes") != EXPECTED_OWNERSHIP_ATTRIBUTES:
        errors.append("break-glass must bind customer_id and deployment_id exactly")
    if set(_strings(break_glass.get("default_forbidden_operations"))) != (
        EXPECTED_SENSITIVE_OPERATIONS
    ):
        errors.append("break-glass must deny sensitive data operations by default")
    if break_glass.get("sensitive_operations_behavior") != "deny":
        errors.append("break-glass must deny sensitive operations in v1")
    if break_glass.get("max_ttl_seconds") != 900 or break_glass.get(
        "max_auth_age_seconds"
    ) != 300:
        errors.append("break-glass requires bounded TTL and recent authentication")

    audit = _mapping(policy.get("audit"))
    if set(_strings(audit.get("required_events"))) != REQUIRED_AUDIT_EVENTS:
        errors.append("audit events must cover lifecycle, denial, support, and break-glass")
    if set(_strings(audit.get("required_fields"))) != REQUIRED_AUDIT_FIELDS:
        errors.append("audit decisions must carry versioned and attributable metadata")
    if set(_strings(audit.get("membership_user_required_fields"))) != (
        REQUIRED_MEMBERSHIP_USER_AUDIT_FIELDS
    ):
        errors.append("membership user audit events must carry role and membership versions")
    if set(_strings(audit.get("temporary_grant_user_required_fields"))) != (
        REQUIRED_TEMPORARY_GRANT_USER_AUDIT_FIELDS
    ):
        errors.append("temporary grant audit events must carry grant type, state, and version")
    if set(_strings(audit.get("m2m_required_fields"))) != REQUIRED_M2M_AUDIT_FIELDS:
        errors.append("m2m audit events must carry the grant version")
    if set(_strings(audit.get("lifecycle_change_required_fields"))) != (
        REQUIRED_LIFECYCLE_AUDIT_FIELDS
    ):
        errors.append("lifecycle audit events must carry approvals and version changes")
    if set(_strings(audit.get("support_required_fields"))) != (
        REQUIRED_SUPPORT_AUDIT_FIELDS
    ):
        errors.append("support audit events must carry case, approval, and grant references")
    if set(_strings(audit.get("break_glass_required_fields"))) != (
        REQUIRED_BREAK_GLASS_AUDIT_FIELDS
    ):
        errors.append("break-glass audit events must carry incident and approval evidence")
    if not REQUIRED_FORBIDDEN_AUDIT_FIELDS <= set(
        _strings(audit.get("forbidden_fields"))
    ):
        errors.append("audit records must exclude tokens, secrets, PII, keys, and URLs")
    required_audit_fields = set(_strings(audit.get("required_fields")))
    required_audit_fields.update(
        _strings(audit.get("membership_user_required_fields"))
    )
    required_audit_fields.update(
        _strings(audit.get("temporary_grant_user_required_fields"))
    )
    required_audit_fields.update(_strings(audit.get("m2m_required_fields")))
    required_audit_fields.update(
        _strings(audit.get("lifecycle_change_required_fields"))
    )
    required_audit_fields.update(_strings(audit.get("support_required_fields")))
    required_audit_fields.update(_strings(audit.get("break_glass_required_fields")))
    if required_audit_fields & set(_strings(audit.get("forbidden_fields"))):
        errors.append("audit required and forbidden fields must be disjoint")
    _require_true(
        audit,
        (
            "append_only",
            "integrity_protection_required",
            "deployment_partitioning_required",
            "deny_reason_codes_sanitized",
            "raw_identity_values_forbidden",
        ),
        "audit evidence must be append-only and sanitized",
        errors,
    )

    migration = _mapping(policy.get("migration"))
    if migration.get("mode") != "additive_versioned":
        errors.append("authorization migration must remain additive and versioned")
    if migration.get("accepted_versions") != ["enterprise-authorization.v1"]:
        errors.append("accepted authorization versions require an explicit allowlist")
    if migration.get("unknown_version_behavior") != "deny" or migration.get(
        "missing_contract_behavior"
    ) != "deny":
        errors.append("unknown or missing authorization contracts must deny")
    if migration.get("legacy_inference") != "forbidden":
        errors.append("legacy identity inference must remain forbidden")
    if migration.get("parallel_acceptance_requires_allowlist") is not True:
        errors.append("parallel authorization versions require an explicit allowlist")

    return errors


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Validate the Scanalyze enterprise authorization policy"
    )
    parser.add_argument("policy", type=Path, help="Path to the policy JSON")
    parser.add_argument(
        "--schema",
        type=Path,
        default=Path("schemas/enterprise-authorization.v1.schema.json"),
        help="Path to the policy JSON Schema",
    )
    args = parser.parse_args(argv)

    try:
        policy = load_json_without_duplicates(args.policy)
        schema = load_json_without_duplicates(args.schema)
    except (OSError, json.JSONDecodeError, DuplicateKeyError, ValueError):
        print("FAIL: authorization policy or schema could not be loaded")
        return 1

    try:
        from jsonschema import Draft202012Validator

        validator = Draft202012Validator(schema)
        if next(validator.iter_errors(policy), None) is not None:
            print("FAIL: authorization policy does not conform to its schema")
            return 1
    except ImportError:
        print("BLOCKED_TOOLING: jsonschema is required")
        return 1

    errors = validate_enterprise_authorization(policy)
    if errors:
        for error in errors:
            print(f"FAIL: {error}")
        return 1

    print("PASS: enterprise authorization policy v1")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
